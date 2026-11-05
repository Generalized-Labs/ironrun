"""Actual isolated Linux Secret Service -> Ironrun vault -> MCP approval probe.

Only synthetic test values and a brand new, password-protected collection are
used. No fake secret-tool adapter is present. Existing user/session stores are
never contacted. Run the outer process through dbus-run-session as below.
"""
from pathlib import Path
import datetime
import hashlib
import http.server
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time

OUT=Path(__file__).resolve().parent / 'final'
OUT.mkdir(exist_ok=True)
REPO=Path('/workspace/ironrun-product-review')
NATIVE=Path('/workspace/ironrun-product-tools/native-linux/extracted')
SYNTHETIC_VALUE='native-linux-synthetic-fixture-token-'+('testonly' * 5)
COLLECTION_PASSWORD=b'ironrun-synthetic-isolated-collection-password\n'

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def source_identity():
    names=subprocess.check_output(['git','ls-files','-z'],cwd=REPO).decode().split('\0')
    files={n:digest(REPO/n) for n in names if n and (n.endswith('.go') or n in ['go.mod','go.sum'])}
    merge=subprocess.check_output(['git','rev-parse','6e03c06'],cwd=REPO).decode().strip()
    merged_match=all(hashlib.sha256(subprocess.check_output(['git','show',merge+':'+n],cwd=REPO)).hexdigest()==h for n,h in files.items())
    assert merged_match,'Diagnostic source differs from merged runtime source'
    return {'local_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO).decode().strip(),'merged_commit':merge,'all_runtime_inputs_match_merged_commit':merged_match,'files':files}

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        self.server.requests.append({'credential_matches':self.headers.get('X-Ironrun-Fixture')==SYNTHETIC_VALUE,'observed_monotonic_ns':time.monotonic_ns()})
        self.send_response(200);self.end_headers()
        self.wfile.write(('LOOPBACK_RESPONSE '+SYNTHETIC_VALUE+'\n').encode())

class MCP:
    def __init__(self,argv,cwd):
        self.err=(OUT/'mcp.stderr.log').open('w')
        self.proc=subprocess.Popen(argv,cwd=cwd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.err,text=True,bufsize=1)
        self.q=queue.Queue();self.messages=[]
        def read():
            for line in self.proc.stdout:
                self.q.put(json.loads(line))
        self.thread=threading.Thread(target=read,daemon=True);self.thread.start()
    def send(self,item):
        self.proc.stdin.write(json.dumps(item)+'\n');self.proc.stdin.flush()
    def response(self,id,timeout=15):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            item=self.q.get(timeout=max(.01,deadline-time.monotonic()))
            self.messages.append(item)
            if item.get('id')==id:return item
        raise AssertionError('MCP response timed out')
    def call(self,id,name,args):
        self.send({'jsonrpc':'2.0','id':id,'method':'tools/call','params':{'name':name,'arguments':args}})
        return self.response(id)
    def close(self):
        if self.proc.poll()is None:
            self.proc.stdin.close()
            try:self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:self.proc.terminate();self.proc.wait(timeout=5)
        self.err.close()

def tool_text(response):
    result=response['result']
    return '\n'.join(x.get('text','')for x in result.get('content',[])if x.get('type')=='text'),result.get('isError',False)

def run_inner():
    started=datetime.datetime.now(datetime.timezone.utc).isoformat()
    before=source_identity();(OUT/'source-identity.json').write_text(json.dumps(before,indent=2)+'\n')
    assert shutil.which('secret-tool')==str(NATIVE/'usr/bin/secret-tool')
    assert 'IRONRUN_TEST_NATIVE_STORE_DIR'not in os.environ
    project=OUT/'e2e-project';project.mkdir(exist_ok=True)
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);server.requests=[]
    threading.Thread(target=server.serve_forever,daemon=True).start()
    url=f'http://127.0.0.1:{server.server_address[1]}/probe'
    probe=[str(OUT/'workspaceprobe'),'http',url]
    policy=project/'ironrun.yml'
    policy.write_text('version: "2"\ncommands:\n  - id: strict-loopback\n    argv: '+json.dumps(probe)+'\n    secrets: [IRONRUN_E2E_TOKEN]\n    ttl: 5s\n  - id: native-reopen-network\n    argv: '+json.dumps(probe)+'\n    secrets: [IRONRUN_E2E_TOKEN]\n    allow_network: true\n    ttl: 5s\n')
    commands=[];daemon=None;mcp=None

    def cli(label,args,data=None):
        argv=[str(OUT/'ironrun'),*args]
        p=subprocess.run(argv,cwd=project,input=data,capture_output=True,timeout=20)
        assert SYNTHETIC_VALUE.encode()not in p.stdout+p.stderr, label+' exposed full synthetic value'
        (OUT/(label+'.stdout.log')).write_bytes(p.stdout);(OUT/(label+'.stderr.log')).write_bytes(p.stderr)
        commands.append({'label':label,'argv':argv,'exit_code':p.returncode})
        assert p.returncode==0,label+': '+p.stderr.decode(errors='replace')
        return p.stdout.decode()

    def owner():
        q=subprocess.run(['gdbus','call','--session','--dest','org.freedesktop.DBus','--object-path','/org/freedesktop/DBus','--method','org.freedesktop.DBus.NameHasOwner','org.freedesktop.secrets'],capture_output=True,text=True,timeout=3)
        return '(true,)'in q.stdout

    def start_daemon(label):
        stdout=(OUT/(label+'.stdout.log')).open('wb');stderr=(OUT/(label+'.stderr.log')).open('wb')
        proc=subprocess.Popen([str(NATIVE/'usr/bin/gnome-keyring-daemon'),'--foreground','--components=secrets','--control-directory',str(Path(os.environ['XDG_RUNTIME_DIR'])/'keyring'),'--unlock'],stdin=subprocess.PIPE,stdout=stdout,stderr=stderr)
        proc.stdin.write(COLLECTION_PASSWORD);proc.stdin.close()
        for _ in range(60):
            if owner():return proc,stdout,stderr
            assert proc.poll()is None,'Native daemon exited before registration'
            time.sleep(.05)
        raise AssertionError('Native Secret Service did not register')

    def stop_daemon(handle):
        proc,stdout,stderr=handle;proc.terminate()
        try:proc.wait(timeout=5)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
        stdout.close();stderr.close()
        for _ in range(30):
            if not owner():return
            time.sleep(.05)
        raise AssertionError('Native Secret Service retained owner after stopping daemon')

    def pending(exclude=None):
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            try:
                state=json.loads((project/'.ironrun/access.json').read_text())
                matches=[r for r in state.get('requests',[])if r.get('kind')=='workspace'and r.get('status')=='pending'and r['id']!=exclude]
                if matches:return matches[0]
            except (FileNotFoundError,json.JSONDecodeError):pass
            time.sleep(.02)
        raise AssertionError('No pending workspace request observed')

    try:
        assert not owner(),'New DBus session unexpectedly already had Secret Service'
        daemon=start_daemon('daemon-first')
        cli('env-init',['env','init','dev'])
        cli('env-set',['env','set','dev','IRONRUN_E2E_TOKEN','--from-stdin','--unsafe'],(SYNTHETIC_VALUE+'\n').encode())
        cli('doctor',['doctor'])
        mcp=MCP([str(OUT/'ironrun'),'mcp','--policy',str(policy)],project)
        mcp.send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'native-secret-service-fixture','version':'1'}}})
        initialized=mcp.response(1);assert 'result'in initialized
        mcp.send({'jsonrpc':'2.0','method':'notifications/initialized'})
        mcp.send({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})
        catalog=mcp.response(2)['result'];assert any(x['name']=='run_sealed'for x in catalog['tools'])
        status,status_error=tool_text(mcp.call(3,'workspace_status',{}));assert not status_error and 'not trusted'in status
        mcp.send({'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'run_sealed','arguments':{'argv':probe}}})
        request=pending();time.sleep(.1);assert not server.requests,'Loopback reached before approval'
        grant_started=time.monotonic_ns();cli('trust-grant',['trust','grant',request['id'],'--ttl','1m'])
        response=mcp.response(4);text,error=tool_text(response)
        assert not error and 'exit_code: 0'in text and 'DIAL_OK'in text and 'LOOPBACK_RESPONSE [REDACTED]'in text
        assert SYNTHETIC_VALUE not in text and len(server.requests)==1 and server.requests[0]['credential_matches']
        assert server.requests[0]['observed_monotonic_ns']>=grant_started
        strict=mcp.call(5,'run_sealed',{'command_id':'strict-loopback'});strict_text,strict_error=tool_text(strict)
        if strict_error:
            assert 'network namespace creation was denied'in strict_text,strict_text
            strict_observation='failed closed before child; no attempted dial established'
        else:
            assert 'PROBE_STARTED'in strict_text and 'DIAL_BLOCKED'in strict_text and 'exit_code: 0'not in strict_text,strict_text
            strict_observation='child started and dial blocked'
        assert len(server.requests)==1 and SYNTHETIC_VALUE not in strict_text
        access=json.loads((project/'.ironrun/access.json').read_text());grant=next(g for g in access['workspace_grants']if g['request_id']==request['id'])
        cli('trust-revoke',['trust','revoke',grant['id']])
        mcp.send({'jsonrpc':'2.0','id':6,'method':'tools/call','params':{'name':'run_sealed','arguments':{'argv':probe}}})
        denied_request=pending(request['id']);cli('access-deny',['access','deny',denied_request['id']])
        denied=mcp.response(6);denied_text,denied_error=tool_text(denied)
        assert denied_error and 'denied'in denied_text and len(server.requests)==1
        messages=mcp.messages[:];mcp.close();mcp=None
        assert SYNTHETIC_VALUE not in json.dumps(messages)
        (OUT/'mcp-responses.json').write_text(json.dumps(messages,indent=2)+'\n')
        (OUT/'tool-catalog.json').write_text(json.dumps(catalog,indent=2)+'\n')
        stop_daemon(daemon);daemon=None
        keyring_files=list((Path(os.environ['XDG_DATA_HOME'])/'keyrings').glob('*.keyring'))
        assert keyring_files,'No persisted native keyring file'
        daemon=start_daemon('daemon-restarted')
        reopened=cli('after-daemon-restart',['run','native-reopen-network'])
        assert 'LOOPBACK_RESPONSE [REDACTED]'in reopened and 'DIAL_OK'in reopened
        assert len(server.requests)==2 and all(r['credential_matches']for r in server.requests)
        vault_files=list((Path.home()/'.ironrun/vaults').glob('*.irvault'));assert vault_files
        files=keyring_files+vault_files
        assert all(SYNTHETIC_VALUE.encode()not in p.read_bytes()for p in files)
        at_rest=[{'path':str(p.relative_to(OUT)),'bytes':p.stat().st_size,'mode':oct(p.stat().st_mode&0o777),'sha256':digest(p),'full_synthetic_value_present':False}for p in files]
        after=source_identity();assert before==after,'Runtime source changed during native probe'
        result={'result':'passed','started_at_utc':started,'ended_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_identity':'source-identity.json','merged_commit':before['merged_commit'],'native_backend':'GNOME Keyring48.0 via real libsecret secret-tool0.21.7','synthetic_native_adapter_used':False,'isolated_new_dbus_session_and_home':True,'existing_user_stores_accessed':False,'actual_cli_env_init_set_doctor':True,'mcp_tools':len(catalog['tools']),'no_request_during_100ms_pending_observation':True,'actual_cli_grant_then_loopback_delivery':True,'full_synthetic_value_absent_from_mcp_output':True,'strict_network_observation':strict_observation,'actual_cli_revoke_and_deny_prevented_second_call':True,'native_daemon_restart_then_new_cli_vault_reopen':True,'loopback_requests':server.requests,'at_rest_files':at_rest,'binary_sha256':digest(OUT/'ironrun'),'http_helper_sha256':digest(OUT/'workspaceprobe'),'secret_tool_sha256':digest(NATIVE/'usr/bin/secret-tool'),'gnome_keyring_daemon_sha256':digest(NATIVE/'usr/bin/gnome-keyring-daemon'),'commands':commands,'limits':['Headless password-unlocked brand-new test collection, not desktop login/PAM/keyring prompt UX.','Direct MCP protocol fixture, not a real agent host/model or human approval session.','Loopback authentication only, not an external provider.','No macOS Keychain, other host, installer or signed-release evidence.','At-rest byte absence is a bounded observation, not cryptographic validation.']}
        (OUT/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({k:result[k]for k in ['result','native_backend','mcp_tools','strict_network_observation','native_daemon_restart_then_new_cli_vault_reopen','merged_commit']}))
    finally:
        if mcp:mcp.close()
        if daemon:stop_daemon(daemon)
        server.shutdown();server.server_close()

def main():
    if '--inner'in sys.argv:
        run_inner();return
    home=OUT/'e2e-home'
    assert not home.exists(),'Do not reuse native test collection; choose a fresh output directory'
    for name in ['config','cache','state','data','runtime','runtime/keyring']:
        p=home/name;p.mkdir(parents=True,exist_ok=True);p.chmod(0o700)
    env=dict(os.environ)
    for key in ['GNOME_KEYRING_CONTROL','SSH_AUTH_SOCK','GPG_AGENT_INFO','DBUS_SESSION_BUS_ADDRESS','DISPLAY','WAYLAND_DISPLAY','IRONRUN_TEST_NATIVE_STORE_DIR']:
        env.pop(key,None)
    env.update(HOME=str(home),IRONRUN_HOME=str(home/'ironrun'),XDG_CONFIG_HOME=str(home/'config'),XDG_CACHE_HOME=str(home/'cache'),XDG_STATE_HOME=str(home/'state'),XDG_DATA_HOME=str(home/'data'),XDG_RUNTIME_DIR=str(home/'runtime'),PATH=str(NATIVE/'usr/bin')+':/usr/local/bin:/usr/bin:/bin',LD_LIBRARY_PATH=str(NATIVE/'usr/lib/x86_64-linux-gnu'))
    p=subprocess.run(['dbus-run-session','--','python3',str(Path(__file__).resolve()),'--inner'],env=env,capture_output=True,text=True,timeout=90)
    (OUT/'run.stdout.log').write_text(p.stdout);(OUT/'run.stderr.log').write_text(p.stderr)
    print(json.dumps({'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr[:2500]}))
    raise SystemExit(p.returncode)

if __name__=='__main__':main()
