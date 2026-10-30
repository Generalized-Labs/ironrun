from pathlib import Path
import hashlib,json,os,subprocess,sys,datetime,selectors,time,stat
ROOT=Path(__file__).resolve().parent
BIN=Path('/workspace/ironrun-product-tools/ironrun-setup-fixed')
BIN_SHA='2d75777c7f9bd44c0b8e42be50384d3d54cc5d05d66c792c0044c4ec0b8e4df7'
POLICY='version: "2"\ncommands:\n  - id: health\n    argv: [/usr/bin/true]\n'
NAMES=['malformed-and-codex-failure','stale-registration','codex-unavailable','write-only-config']

def env_for(root):
 return {'PATH':str(root/'bin'),'HOME':str(root/'home'),'IRONRUN_HOME':str(root/'home'/'ironrun'),'XDG_STATE_HOME':str(root/'state'),'XDG_CACHE_HOME':str(root/'cache')}

def prepare():
 for name in NAMES:
  root=ROOT/'fixtures'/name;root.mkdir(parents=True);(root/'home'/'.cursor').mkdir(parents=True);(root/'bin').mkdir()
  (root/'ironrun.yml').write_text(POLICY)
  paths=[root/'.mcp.json',root/'home'/'.cursor'/'mcp.json']
  if name=='malformed-and-codex-failure':
   for p in paths:p.write_text('{')
   script='#!/bin/sh\nif [ "$2" = "list" ]; then printf "[]\\n"; exit 0; fi\nprintf "synthetic registration failure\\n" >&2\nexit 23\n'
  elif name=='stale-registration':
   c=json.dumps({'mcpServers':{'ironrun':{'command':'/definitely/missing/ironrun','args':['wrong-subcommand']},'kept':{'command':'keep-me'}}})
   for p in paths:p.write_text(c)
   script='#!/bin/sh\nif [ "$2" = "list" ]; then printf "other-ironrun-helper disabled\\n"; exit 0; fi\nprintf "unexpected add\\n" >&2\nexit 24\n'
  elif name=='write-only-config':
   c=json.dumps({'other-setting':123456789012345678901234567890,'mcpServers':{'kept':{'command':'keep-me','args':['unchanged']}}})
   for p in paths:p.write_text(c)
   script=None
  else:script=None
  if script:
   p=root/'bin'/'codex';p.write_text(script);p.chmod(0o700)
  before={}
  for p in paths:
   if p.exists():
    if name=='write-only-config':p.chmod(0o200)
    # Expected content identity is derived from the prepared fixture before
    # removing read access, not by bypassing its mode during the product run.
    before[str(p.relative_to(root))]={'mode':oct(stat.S_IMODE(p.stat().st_mode)),'expected_sha256':hashlib.sha256((c if name in ['stale-registration','write-only-config'] else '{').encode()).hexdigest()}
  (ROOT/(name+'.before.json')).write_text(json.dumps(before,indent=2)+'\n')
  scenario={'executable':sys.executable,'arguments':[str(ROOT/'replay.py'),'setup',name],'working_directory':str(root),'environment':env_for(root),'filesystem_observation_paths':[str(root)],'timeout_ms':10000,'idle_timeout_ms':10000,'settle_ms':100,'limits':{'output_bytes':40000,'files':100,'file_bytes':200000,'processes':20,'filesystem_depth':8},'normalization':{'paths':True,'pids':True,'ports':True,'time_bucket_ms':10,'patterns':[]}}
  (ROOT/(name+'.scenario.json')).write_text(json.dumps(scenario,indent=2)+'\n')
 print('Prepared four fresh synthetic fixtures')

def setup(name):
 assert hashlib.sha256(BIN.read_bytes()).hexdigest()==BIN_SHA
 root=ROOT/'fixtures'/name
 r=subprocess.run([str(BIN),'setup','--yes'],cwd=root,env=env_for(root),text=True,capture_output=True,timeout=15)
 result={'argv':[str(BIN),'setup','--yes'],'cwd':str(root),'program_exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'binary_sha256':BIN_SHA,'synthetic_only':True,'uid':os.getuid(),'configuration_modes_after_setup':{str(p.relative_to(root)):oct(stat.S_IMODE(p.stat().st_mode)) for p in [root/'.mcp.json',root/'home'/'.cursor'/'mcp.json'] if p.exists()}}
 (ROOT/(name+'.result.json')).write_text(json.dumps(result,indent=2)+'\n')
 (ROOT/(name+'.stdout.txt')).write_text(r.stdout);(ROOT/(name+'.stderr.txt')).write_text(r.stderr)
 sys.stdout.write(r.stdout);sys.stderr.write(r.stderr)
 return r.returncode

def inspect_after():
 results=[]
 for name in NAMES:
  root=ROOT/'fixtures'/name;before=json.loads((ROOT/(name+'.before.json')).read_text());rows=[]
  for rel,expected in before.items():
   p=root/rel;mode=stat.S_IMODE(p.stat().st_mode)
   if not mode&stat.S_IRUSR:p.chmod(mode|stat.S_IRUSR)
   try:data=p.read_bytes()
   finally:p.chmod(mode)
   actual=hashlib.sha256(data).hexdigest();rows.append({'path':rel,'before':expected,'after_sha256':actual,'mode_after':oct(mode),'preserved_bytes':actual==expected['expected_sha256'],'preserved_mode':oct(mode)==expected['mode']})
  result=json.loads((ROOT/(name+'.result.json')).read_text());assert result['program_exit_code']==0
  assert 'host connections not checked' in result['stdout'] and 'automatically' not in result['stdout']
  assert all(x['preserved_bytes'] and x['preserved_mode'] for x in rows)
  results.append({'name':name,'program_exit_code':0,'uid':result['uid'],'preservation':rows,'post_capture_permission_inspection':name=='write-only-config'})
 (ROOT/'preservation-results.json').write_text(json.dumps({'results':results,'all_assertions_passed':True,'inspection_note':'Unreadable fixturefiles were temporarily given owner read permission only after REA capture, then their original mode was restored; product execution occurred with original0200mode.'},indent=2)+'\n')
 print('All four after outcomes and preserved configuration identities verified')

if __name__=='__main__':
 if sys.argv[1]=='prepare':prepare()
 elif sys.argv[1]=='setup':raise SystemExit(setup(sys.argv[2]))
 elif sys.argv[1]=='inspect':inspect_after()
