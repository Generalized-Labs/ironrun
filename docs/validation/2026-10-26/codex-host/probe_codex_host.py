#!/usr/bin/env python3
"""Local, credential-free Codex host wiring probe. No actual model is queried."""
from pathlib import Path
import argparse
import hashlib
import http.server
import json
import os
import subprocess
import threading
import time

ROOT = Path('/workspace/ironrun-product-research/launch-20261026/codex-host')
REPO = Path('/workspace/ironrun-product-review')
GO = '/workspace/ironrun-product-tools/go/bin/go'
CODEX = '/opt/codex/bin/codex'

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def source_snapshot():
    paths=sorted(list(REPO.rglob('*.go'))+[REPO/'go.mod',REPO/'go.sum'])
    return {str(p.relative_to(REPO)):sha(p) for p in paths if p.is_file()}

def environment(home):
    env = dict(os.environ)
    env.update(HOME=str(home), CODEX_HOME=str(home/'codex'),
               XDG_CONFIG_HOME=str(home/'config'), XDG_CACHE_HOME=str(home/'cache'),
               XDG_STATE_HOME=str(home/'state'),
               PATH='/workspace/ironrun-product-tools/go/bin:/usr/local/bin:/usr/bin:/bin',
               GOPATH='/workspace/ironrun-product-tools/gopath',
               GOMODCACHE='/workspace/ironrun-product-tools/go-modules',
               GOCACHE='/workspace/ironrun-product-tools/go-cache',
               GOTMPDIR='/workspace/ironrun-product-tools/go-tmp',
               TMPDIR='/workspace/ironrun-product-tools/go-tmp',
               GOFLAGS='-buildvcs=false', GOPROXY='off', GOSUMDB='off',
               GOTOOLCHAIN='local', GITHUB_ACTIONS='false')
    return env

def run(argv, cwd, env, output, name, input=None, timeout=60):
    result = subprocess.run(argv, cwd=cwd, env=env, input=input, capture_output=True, timeout=timeout)
    (output/(name+'.stdout.txt')).write_bytes(result.stdout)
    (output/(name+'.stderr.txt')).write_bytes(result.stderr)
    record=dict(argv=argv, cwd=str(cwd), exit_code=result.returncode,
                stdout=name+'.stdout.txt', stderr=name+'.stderr.txt')
    (output/(name+'.result.json')).write_text(json.dumps(record,indent=2)+'\n')
    return result

class ModelHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
        self.wfile.write(json.dumps({'data':[{'id':'fixture-model','object':'model'}]}).encode())
    def do_POST(self):
        body=self.rfile.read(int(self.headers.get('Content-Length','0')))
        request=json.loads(body)
        state=self.server.state
        with state['lock']:
            n=len(state['requests'])
            state['requests'].append({'path':self.path, 'authorization_header_present': 'Authorization' in self.headers,
                                      'observed_monotonic_ns':time.monotonic_ns(),
                                      'body':request})
        if 'Authorization' in self.headers:
            self.send_error(400,'This fixture must not receive authentication'); return
        events=[]
        response={'id':f'resp_fixture_{n}', 'object':'response', 'created_at':int(time.time()),
                  'status':'in_progress', 'model':'fixture-model', 'output':[]}
        events.append(('response.created', {'type':'response.created','response':response}))
        tools=request.get('tools',[])
        if state.get('tool_action') and n==0:
            candidates=[]
            for tool in tools:
                if tool.get('type')=='namespace':
                    candidates.extend(dict(child,namespace=tool['name']) for child in tool.get('tools',[]) if child.get('name')=='run_sealed')
                elif 'run_sealed' in tool.get('name',''):
                    candidates.append(tool)
            if len(candidates)!=1:
                state['error']='Expected one Ironrun run_sealed tool; got '+str([t.get('name') for t in tools])
                text='FIXTURE_TOOL_DISCOVERY_FAILED'
                item={'id':f'msg_{n}','type':'message','role':'assistant','status':'completed',
                      'content':[{'type':'output_text','text':text,'annotations':[]}]}
            else:
                args=json.dumps({'argv':state['tool_action']})
                item={'id':f'fc_{n}','type':'function_call','call_id':f'call_fixture_{n}',
                      'name':candidates[0]['name'],'arguments':args,'status':'completed'}
                if candidates[0].get('namespace'):item['namespace']=candidates[0]['namespace']
                initial=dict(item,arguments='',status='in_progress')
                events.append(('response.output_item.added',{'type':'response.output_item.added','output_index':0,'item':initial}))
                events.append(('response.function_call_arguments.delta',{'type':'response.function_call_arguments.delta',
                    'item_id':item['id'],'output_index':0,'delta':args}))
                events.append(('response.function_call_arguments.done',{'type':'response.function_call_arguments.done',
                    'item_id':item['id'],'output_index':0,'arguments':args}))
        else:
            item={'id':f'msg_{n}','type':'message','role':'assistant','status':'completed',
                  'content':[{'type':'output_text','text':'LOCAL_FIXTURE_COMPLETE','annotations':[]}]}
            events.append(('response.output_item.added',{'type':'response.output_item.added','output_index':0,
                'item':dict(item,status='in_progress',content=[])}))
            events.append(('response.output_text.delta',{'type':'response.output_text.delta','item_id':item['id'],
                'output_index':0,'content_index':0,'delta':'LOCAL_FIXTURE_COMPLETE'}))
        events.append(('response.output_item.done',{'type':'response.output_item.done','output_index':0,'item':item}))
        completed=dict(response,status='completed',output=[item],usage={'input_tokens':1,'output_tokens':1,'total_tokens':2})
        events.append(('response.completed',{'type':'response.completed','response':completed}))
        self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Cache-Control','no-cache');self.end_headers()
        for name,payload in events:
            self.wfile.write(('event: '+name+'\ndata: '+json.dumps(payload)+'\n\n').encode());self.wfile.flush()

class CredentialHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        self.server.observed.append(self.headers.get('X-Ironrun-Fixture'))
        self.server.observed_times.append(time.monotonic_ns())
        self.send_response(200);self.send_header('Content-Type','text/plain');self.end_headers()
        self.wfile.write(('LOOPBACK_RESPONSE '+self.server.value+'\n').encode())

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--mode',choices=['provider','mcp'],default='provider');args=parser.parse_args()
    driver_sha256=sha(__file__)
    output=ROOT/(args.mode+'-'+str(time.time_ns()));output.mkdir(parents=True)
    home=output/'home';home.mkdir();(home/'codex').mkdir();project=output/'project';project.mkdir()
    env=environment(home)
    state={'requests':[],'lock':threading.Lock()}
    credential_server=None
    if args.mode=='mcp':
        source_before=source_snapshot()
        binaries=output/'bin';binaries.mkdir()
        native=output/'synthetic-native-store';native.mkdir()
        env.update(IRONRUN_HOME=str(home/'ironrun'),IRONRUN_TEST_NATIVE_STORE_DIR=str(native),
                   PATH=str(binaries)+':'+env['PATH'])
        ironrun=binaries/'ironrun';probe=binaries/'secret-tool'
        assert run([GO,'build','-o',str(ironrun),'./cmd/ironrun'],REPO,env,output,'build-ironrun').returncode==0
        assert run([GO,'build','-o',str(probe),'./mcp/testdata/workspaceprobe'],REPO,env,output,'build-probe').returncode==0
        assert run([GO,'version'],REPO,env,output,'go-version').returncode==0
        assert run([GO,'version','-m',str(ironrun)],REPO,env,output,'ironrun-build-info').returncode==0
        source_after=source_snapshot()
        assert source_before==source_after,'Go source changed while building diagnostic binaries'
        (output/'runtime-source-build.json').write_text(json.dumps({'before':source_before,'after':source_after,'unchanged':True},indent=2)+'\n')
        value='codex-local-fixture-token-'+('synthetic' * 4)
        credential_server=http.server.ThreadingHTTPServer(('127.0.0.1',0),CredentialHandler)
        credential_server.value=value;credential_server.observed=[];credential_server.observed_times=[]
        threading.Thread(target=credential_server.serve_forever,daemon=True).start()
        url=f'http://127.0.0.1:{credential_server.server_address[1]}/probe'
        state['tool_action']=[str(probe),'http',url]
        policy=project/'ironrun.yml'
        policy.write_text('version: "2"\ncommands:\n  - id: strict-loopback\n    argv: '+json.dumps(state['tool_action'])+'\n    secrets: [IRONRUN_E2E_TOKEN]\n    ttl: 5s\n')
        for label,cliargs,data in [('env-init',['env','init','dev'],None),
                 ('env-set',['env','set','dev','IRONRUN_E2E_TOKEN','--from-stdin','--unsafe'],(value+'\n').encode()),
                 ('doctor',['doctor'],None)]:
            assert run([str(ironrun),*cliargs],project,env,output,label,input=data).returncode==0,label
        (project/'AGENTS.md').write_text('Use only Ironrun MCP run_sealed for credentialed commands. Do not use direct shell tools or inspect secret files. This is a local synthetic integration fixture.\n')
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),ModelHandler);server.state=state
    threading.Thread(target=server.serve_forever,daemon=True).start()
    port=server.server_address[1]
    config=f'''model = "fixture-model"
model_provider = "fixture"
model_reasoning_effort = "low"
model_context_window = 32768
model_auto_compact_token_limit = 30000
approval_policy = "never"
sandbox_mode = "read-only"
[model_providers.fixture]
name = "Local credential-free scripted fixture"
base_url = "http://127.0.0.1:{port}/v1"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
request_max_retries = 0
stream_max_retries = 0
[projects."{project}"]
trust_level = "trusted"
'''
    (home/'codex/config.toml').write_text(config)
    if args.mode=='mcp':
        mcp=f'''\n[mcp_servers.ironrun]
command = {json.dumps(str(ironrun))}
args = ["mcp", "--policy", {json.dumps(str(policy))}]
cwd = {json.dumps(str(project))}
required = true
startup_timeout_sec = 20
tool_timeout_sec = 30
default_tools_approval_mode = "approve"
[mcp_servers.ironrun.env]
'''
        for key in ['HOME','IRONRUN_HOME','XDG_CONFIG_HOME','XDG_CACHE_HOME','XDG_STATE_HOME','PATH','IRONRUN_TEST_NATIVE_STORE_DIR']:
            mcp+=key+' = '+json.dumps(env[key])+'\n'
        with (home/'codex/config.toml').open('a') as f:f.write(mcp)
        approval={'request':None,'grant_exit':None,'error':None,'no_loopback_before_approval':False}
        def approve_pending():
            deadline=time.monotonic()+35
            while time.monotonic()<deadline:
                try:
                    access=json.loads((project/'.ironrun/access.json').read_text())
                    pending=[r for r in access.get('requests',[]) if r['kind']=='workspace' and r['status']=='pending']
                    if pending:
                        approval['request']=pending[0]
                        approval['pending_observed_monotonic_ns']=time.monotonic_ns()
                        time.sleep(.1)
                        if credential_server.observed:
                            approval['error']='Child reached loopback before Ironrun approval';return
                        approval['no_loopback_before_approval']=True
                        approval['grant_started_monotonic_ns']=time.monotonic_ns()
                        result=run([str(ironrun),'trust','grant',pending[0]['id'],'--ttl','1m'],project,env,output,'trust-grant')
                        approval['grant_exit']=result.returncode
                        approval['grant_finished_monotonic_ns']=time.monotonic_ns()
                        return
                except FileNotFoundError: pass
                except Exception as exc:approval['error']=str(exc);return
                time.sleep(.025)
        approver=threading.Thread(target=approve_pending,daemon=True);approver.start()
    version=run([CODEX,'--version'],project,env,output,'codex-version')
    argv=[CODEX,'--no-daemon','exec','--skip-git-repo-check','--ephemeral','--json','--color','never','-C',str(project),
          'This is a local integration fixture. Respond with LOCAL_FIXTURE_COMPLETE. Do not execute shell commands.']
    try:
        p=run(argv,project,env,output,'codex-exec',timeout=50)
        status=p.returncode
    except subprocess.TimeoutExpired as exc:
        (output/'codex-exec.timeout.json').write_text(json.dumps({'timeout_seconds':50})+'\n');status='timeout'
        if exc.stdout:(output/'codex-exec.stdout.txt').write_bytes(exc.stdout)
        if exc.stderr:(output/'codex-exec.stderr.txt').write_bytes(exc.stderr)
    server.shutdown()
    if credential_server:credential_server.shutdown()
    (output/'model-requests.json').write_text(json.dumps(state['requests'],indent=2)+'\n')
    summary={'mode':args.mode,'codex_exit':status,'model_requests':len(state['requests']),
             'driver_sha256':driver_sha256,'driver_unchanged':driver_sha256==sha(__file__),
             'codex_version_stdout':version.stdout.decode().strip(),'codex_sha256':sha(CODEX),
             'authenticated_request':any(r['authorization_header_present'] for r in state['requests']),
             'host_config_sha256':sha(home/'codex/config.toml'),
             'limits':'Scripted local model fixture, not a real model or human usability test.'}
    if args.mode=='mcp':
        approver.join(timeout=1)
        input_text=json.dumps([r['body'].get('input') for r in state['requests']])
        stdout=(output/'codex-exec.stdout.txt').read_text() if (output/'codex-exec.stdout.txt').exists() else ''
        summary.update(approval=approval,loopback_requests=len(credential_server.observed),
                       child_received_synthetic_value=credential_server.observed==[value],
                       synthetic_value_in_model_input=value in input_text,
                       synthetic_value_in_codex_stdout=value in stdout,
                       redacted_loopback_in_model_input='LOOPBACK_RESPONSE [REDACTED]' in input_text,
                       loopback_observed_monotonic_ns=credential_server.observed_times,
                       ironrun_sha256=sha(ironrun),probe_sha256=sha(probe),fixture_error=state.get('error'))
        (output/'runtime-source-sha256.json').write_text(json.dumps({str(p.relative_to(REPO)):sha(p) for p in [REPO/'mcp/server.go',REPO/'internal/execution/execution.go',REPO/'mcp/testdata/workspaceprobe/main.go']},indent=2)+'\n')
        summary['passed']=bool(status==0 and len(state['requests'])==2 and
             approval['grant_exit']==0 and approval['no_loopback_before_approval'] and
             credential_server.observed==[value] and
             value not in input_text and value not in stdout and
             'LOOPBACK_RESPONSE [REDACTED]' in input_text and not state.get('error'))
        summary['source_stable_since_build']=source_after==source_snapshot()
        summary['passed']=summary['passed'] and summary['source_stable_since_build'] and summary['driver_unchanged']
    (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({'output':str(output),**summary}))
    if args.mode=='mcp' and not summary['passed']:raise SystemExit(1)

if __name__=='__main__': main()
