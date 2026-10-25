from pathlib import Path
import hashlib,json,os,subprocess,sys,datetime,selectors,time
ROOT=Path('/workspace/ironrun-product-research/launch-flow-audit2')
BIN=Path('/workspace/ironrun-product-tools/ironrun-doctor-fixed')
POLICY='version: "2"\ncommands:\n  - id: health\n    argv: [/usr/bin/true]\n'

def env_for(root):
 e={'PATH':str(root/'bin'),'HOME':str(root/'home'),'IRONRUN_HOME':str(root/'home'/'ironrun'),'XDG_STATE_HOME':str(root/'state'),'XDG_CACHE_HOME':str(root/'cache')}
 return e

def snapshot(root):
 return {str(p.relative_to(root)):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(root.rglob('*')) if p.is_file()}

def prepare():
 for name in ['malformed-and-codex-failure','stale-registration','codex-unavailable']:
  root=ROOT/name;root.mkdir(exist_ok=True);(root/'home'/'.cursor').mkdir(parents=True,exist_ok=True);(root/'bin').mkdir(exist_ok=True)
  (root/'ironrun.yml').write_text(POLICY)
  if name=='malformed-and-codex-failure':
   (root/'.mcp.json').write_text('{');(root/'home'/'.cursor'/'mcp.json').write_text('{')
   script='#!/bin/sh\nif [ "$2" = "list" ]; then printf "[]\\n"; exit 0; fi\nprintf "synthetic registration failure\\n" >&2\nexit 23\n'
  elif name=='stale-registration':
   c=json.dumps({'mcpServers':{'ironrun':{'command':'/definitely/missing/ironrun','args':['wrong-subcommand']},'kept':{'command':'keep-me'}}})
   (root/'.mcp.json').write_text(c);(root/'home'/'.cursor'/'mcp.json').write_text(c)
   script='#!/bin/sh\nif [ "$2" = "list" ]; then printf "other-ironrun-helper disabled\\n"; exit 0; fi\nprintf "unexpected add\\n" >&2\nexit 24\n'
  else:script=None
  if script:
   p=root/'bin'/'codex';p.write_text(script);p.chmod(0o700)
  (ROOT/(name+'.environment.json')).write_text(json.dumps(env_for(root),indent=2)+'\n')
 print('Synthetic setup fixtures prepared')

def run_setup(name):
 root=ROOT/name;before=snapshot(root)
 r=subprocess.run([str(BIN),'setup','--yes'],cwd=root,env=env_for(root),text=True,capture_output=True,timeout=20)
 (ROOT/(name+'.stdout.txt')).write_text(r.stdout);(ROOT/(name+'.stderr.txt')).write_text(r.stderr)
 result={'argv':[str(BIN),'setup','--yes'],'cwd':str(root),'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'before':before,'after':snapshot(root),'synthetic_only':True}
 (ROOT/(name+'.result.json')).write_text(json.dumps(result,indent=2)+'\n')
 sys.stdout.write(r.stdout);sys.stderr.write(r.stderr);return r.returncode

def run_mcp():
 root=ROOT/'workspace-expiry';root.mkdir(exist_ok=True);(root/'home').mkdir(exist_ok=True);(root/'bin').mkdir(exist_ok=True)
 policy='version: "1"\nprovider: passthrough\nrequire_agent_leases: true\ncommands:\n  - id: health\n    argv: [/usr/bin/true]\n'
 path=root/'ironrun.yml';path.write_text(policy)
 p=subprocess.Popen([str(BIN),'mcp','--policy',str(path)],cwd=root,env=env_for(root),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
 transcript=[]
 def call(msg):
  p.stdin.write(json.dumps(msg)+'\n');p.stdin.flush();deadline=time.monotonic()+10
  sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ)
  while time.monotonic()<deadline:
   if not sel.select(deadline-time.monotonic()):raise TimeoutError('MCP response timeout')
   line=p.stdout.readline()
   if not line:raise RuntimeError('MCP closed')
   try:r=json.loads(line)
   except json.JSONDecodeError:continue
   transcript.append(r)
   if r.get('id')==msg['id']:return r
  raise TimeoutError('MCP response timeout')
 try:
  init=call({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'synthetic-flow-review','version':'1'}}})
  p.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\n');p.stdin.flush()
  response=call({'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'request_workspace_access','arguments':{'reason':'synthetic expiry review','argv':['/usr/bin/true']}}})
  state=json.loads((root/'.ironrun'/'access.json').read_text());request=state['requests'][0]
  parse=lambda s:datetime.datetime.fromisoformat(s.replace('Z','+00:00'))
  expiry_seconds=(parse(request['expires_at'])-parse(request['created_at'])).total_seconds()
  result={'response':response,'persisted_request':request,'pending_ttl_seconds':expiry_seconds,'requested_grant_ttl_seconds':request['requested_ttl']/1e9,'transcript':transcript,'synthetic_only':True}
  assert expiry_seconds==900 and request['requested_ttl']==7200000000000
  (ROOT/'workspace-expiry.result.json').write_text(json.dumps(result,indent=2)+'\n')
  print(json.dumps({'response':response,'pending_ttl_seconds':expiry_seconds,'requested_grant_ttl_seconds':request['requested_ttl']/1e9},indent=2))
 finally:
  p.stdin.close()
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:p.kill();p.wait()
  (ROOT/'workspace-expiry.stderr.txt').write_text(p.stderr.read())

if __name__=='__main__':
 if sys.argv[1]=='prepare':prepare()
 elif sys.argv[1]=='setup':raise SystemExit(run_setup(sys.argv[2]))
 elif sys.argv[1]=='mcp':run_mcp()
