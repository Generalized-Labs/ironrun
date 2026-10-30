from pathlib import Path
import os, subprocess, hashlib, json, datetime, time, sys
REPO=Path('/workspace/ironrun-product-review')
OUT=Path('/workspace/ironrun-product-research/launch-20261026/snapshot')
TOOLS=Path('/workspace/ironrun-product-tools')
ENV=dict(os.environ)
SETTINGS={
 'PATH':str(TOOLS/'release-bin')+':'+str(TOOLS/'go/bin')+':/usr/local/bin:/usr/bin:/bin',
 'GOPATH':str(TOOLS/'gopath'),'GOMODCACHE':str(TOOLS/'go-modules'),
 'GOCACHE':str(TOOLS/'go-cache'),'GOTMPDIR':str(TOOLS/'go-tmp'),
 'TMPDIR':str(TOOLS/'go-tmp'),'GOFLAGS':'-buildvcs=false',
 'GOPROXY':'off','GOSUMDB':'off','GOTOOLCHAIN':'local',
 'SYFT_CHECK_FOR_APP_UPDATE':'false','GITHUB_ACTIONS':'false'}
ENV.update(SETTINGS)
def sha(data):return hashlib.sha256(data).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=REPO).decode().strip()
def manifest():
 tracked=subprocess.check_output(['git','ls-files','-z'],cwd=REPO).split(b'\0')
 extra=subprocess.check_output(['git','ls-files','--others','--exclude-standard','-z','--','*.go'],cwd=REPO).split(b'\0')
 selected={p.decode() for p in tracked+extra if p and (p.decode().endswith('.go') or p.decode() in ['go.mod','go.sum','.goreleaser.yml','README.md','LICENSE','ironrun.example.yml','install.sh'])}
 entries=[]
 for p in sorted(selected):
  data=(REPO/p).read_bytes();entries.append({'path':p,'bytes':len(data),'sha256':sha(data)})
 return {'head':git('rev-parse','HEAD'),'status':git('status','--short'),'files':entries}
def phase(name,argv):
 start=datetime.datetime.now(datetime.timezone.utc).isoformat();before=time.perf_counter_ns()
 with (OUT/(name+'.stdout.txt')).open('wb') as out,(OUT/(name+'.stderr.txt')).open('wb') as err:
  r=subprocess.run(argv,cwd=REPO,env=ENV,stdout=out,stderr=err,timeout=1200)
 result={'name':name,'command':argv,'cwd':str(REPO),'start_utc':start,'end_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'wall_ns':time.perf_counter_ns()-before,'exit_code':r.returncode}
 for stream in ['stdout','stderr']:
  data=(OUT/(name+'.'+stream+'.txt')).read_bytes();result[stream+'_bytes']=len(data);result[stream+'_sha256']=sha(data)
 (OUT/(name+'.result.json')).write_text(json.dumps(result,indent=2)+'\n')
 print(name,'exit',r.returncode,flush=True)
 if r.returncode:
  print((OUT/(name+'.stderr.txt')).read_text()[-7000:],flush=True)
  print((OUT/(name+'.stdout.txt')).read_text()[-3000:],flush=True)
  raise SystemExit(r.returncode)
 return result
assert sha((REPO/'mcp/server.go').read_bytes()) == '9efac5434d4c74ebb8adbc26cd66fceb374c09e52aeecfceecbc77add72c0dd4'
before=manifest();(OUT/'source-manifest-before.json').write_text(json.dumps(before,indent=2)+'\n')
provenance={'source_scope':'uncommitted reviewed source at hash-listed paths; base HEAD alone is not its identity','base_head':before['head'],'settings':SETTINGS,'goreleaser_config_original_sha256':sha((REPO/'.goreleaser.yml').read_bytes()),'snapshot_scope':'diagnostic, unpublished; no final release version chosen; local tags include v0.5.0','skips':['before hooks','signing','publication','snapshot validation'],'sbom':'enabled with pinned Syft','tool_checksum_verification':'official checksum files, signatures on tool checksum files not independently checked'}
(OUT/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
phase('goreleaser-check',[str(TOOLS/'release-bin/goreleaser'),'check'])
for n in [1,2]:
 config=OUT/f'config-run{n}.yml';config.write_bytes((REPO/'.goreleaser.yml').read_bytes()+f'\n# Review-only output override; product configuration is unchanged.\ndist: {OUT}/dist-run{n}\n'.encode())
 phase(f'snapshot-run{n}',[str(TOOLS/'release-bin/goreleaser'),'release','--config',str(config),'--snapshot','--clean','--skip=before,sign,publish','--parallelism=2','--timeout=20m'])
 (OUT/f'source-manifest-after-run{n}.json').write_text(json.dumps(manifest(),indent=2)+'\n')
print('Both snapshot commands completed',flush=True)
