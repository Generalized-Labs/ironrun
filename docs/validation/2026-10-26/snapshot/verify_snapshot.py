"""Verify two unpublished snapshots without rebuilding or publishing anything."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent
REPO = Path('/workspace/ironrun-product-review')
TOOLS = Path('/workspace/ironrun-product-tools')

def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()

def digest(path):
    return digest_bytes(path.read_bytes())

def write(name, value):
    (ROOT/name).write_text(json.dumps(value, indent=2)+'\n')

before = json.loads((ROOT/'source-manifest-before.json').read_text())
source_map = {e['path']:e for e in before['files']}
after_records = {n: json.loads((ROOT/f'source-manifest-after-run{n}.json').read_text()) for n in [1,2]}
run_sources = {1: before, 2: after_records[1]}
source_changes = []
for path, original in source_map.items():
    later = next(e for e in after_records[1]['files'] if e['path'] == path)
    if original['sha256'] != later['sha256']:
        source_changes.append(dict(path=path, run1_start_sha256=original['sha256'], run2_start_sha256=later['sha256']))
checksums=[]
sboms=[]
archives=[]
metadata=[]
casks=[]
binary_build_metadata=[]
targets={'ironrun_Darwin_arm64.tar.gz':'ironrun_darwin_arm64_v8.0/ironrun',
         'ironrun_Darwin_x86_64.tar.gz':'ironrun_darwin_amd64_v1/ironrun',
         'ironrun_Linux_arm64.tar.gz':'ironrun_linux_arm64_v8.0/ironrun',
         'ironrun_Linux_x86_64.tar.gz':'ironrun_linux_amd64_v1/ironrun'}
for run in [1,2]:
    run_source_map = {e['path']: e for e in run_sources[run]['files']}
    result=json.loads((ROOT/f'snapshot-run{run}.result.json').read_text())
    assert result['exit_code']==0, result
    dist=ROOT/f'dist-run{run}'
    meta=json.loads((dist/'metadata.json').read_text())
    metadata.append(dict(run=run,**meta))
    assert set(p.name for p in dist.glob('*.tar.gz'))==set(targets)
    rows=(dist/'checksums.txt').read_text().splitlines()
    assert len(rows)==9,rows
    for row in rows:
        expected,name=row.split(None,1)
        path=REPO/name if name=='install.sh' else dist/name
        assert digest(path)==expected,(run,name)
        checksums.append(dict(run=run,path=name,sha256=expected,verified=True))
    docs=list(dist.glob('*.sbom.json'))
    assert len(docs)==4
    for p in docs:
        doc=json.loads(p.read_text())
        assert doc['spdxVersion']=='SPDX-2.3'
        assert len(doc.get('packages',[]))>0
        archive_name=p.name.removesuffix('.sbom.json')
        assert doc['name']==archive_name
        sbom_binary=next(e for e in doc.get('files',[]) if e.get('fileName')=='ironrun')
        binary_sha=next(e['checksumValue'] for e in sbom_binary['checksums'] if e['algorithm']=='SHA256')
        assert binary_sha==digest(dist/targets[archive_name]),(run,p.name,'SBOM binary identity')
        sboms.append(dict(run=run,path=p.name,sha256=digest(p),spdx_version=doc['spdxVersion'],packages=len(doc['packages']),
                          binary_sha256=binary_sha,binary_identity_verified=True,
                          scope='JSON parse/version/package-presence and binary SHA256 verification; not full SPDX schema validation or vulnerability analysis'))
    for name,binary in targets.items():
        expected_goos='darwin' if 'Darwin' in name else 'linux'
        expected_goarch='arm64' if 'arm64' in name else 'amd64'
        info=subprocess.run([str(TOOLS/'go/bin/go'),'version','-m',str(dist/binary)],capture_output=True,timeout=30)
        assert info.returncode==0
        text=info.stdout.decode()
        assert 'go1.26.10' in text and f'GOOS={expected_goos}' in text and f'GOARCH={expected_goarch}' in text
        assert 'CGO_ENABLED=0' in text
        info_name=f'binary-run{run}-{expected_goos}-{expected_goarch}-go-version-m.txt'
        (ROOT/info_name).write_bytes(info.stdout)
        binary_build_metadata.append(dict(run=run,target=binary,go_version='go1.26.10',goos=expected_goos,goarch=expected_goarch,
                                          cgo_enabled=False,record=info_name,record_sha256=digest_bytes(info.stdout),
                                          scope='Build metadata inspection only; does not execute cross-compiled binaries.'))
        with tarfile.open(dist/name) as archive:
            members={m.name:m for m in archive.getmembers() if m.isfile()}
            assert set(members)=={'LICENSE','README.md','ironrun.example.yml','ironrun'},members
            entries=[]
            for member,m in members.items():
                data=archive.extractfile(m).read()
                observed=digest_bytes(data)
                expected=digest(dist/binary) if member=='ironrun' else run_source_map[member]['sha256']
                assert observed==expected,(run,name,member,observed,expected)
                entries.append(dict(path=member,bytes=len(data),sha256=observed,mode=m.mode,mtime=m.mtime,
                                    content_matches_built_binary_or_snapshot_input=True))
            archives.append(dict(run=run,path=name,sha256=digest(dist/name),members=entries))
    cask=(dist/'homebrew/Casks/ironrun.rb').read_text()
    assert 'version "0.5.1-next"' in cask
    assert 'binary "ironrun"' in cask
    for name in targets:
        assert digest(dist/name) in cask,(run,name,'cask checksum')
        assert f'/releases/download/v0.5.0/{name}' in cask,(run,name,'diagnostic tag URL')
    casks.append(dict(run=run,sha256=digest(dist/'homebrew/Casks/ironrun.rb'),archive_checksums_match=True,
                      version='0.5.1-next',url_tag='v0.5.0',
                      scope='Snapshot renders the existing tag into URLs. This diagnostic cask must not be installed or published. A real tagged release must regenerate and verify its version and URLs.'))

binary_pairs=[]
for name,relative in targets.items():
    one=ROOT/'dist-run1'/relative
    two=ROOT/'dist-run2'/relative
    binary_pairs.append(dict(target=relative,run1_bytes=one.stat().st_size,run2_bytes=two.stat().st_size,
                             run1_sha256=digest(one),run2_sha256=digest(two),byte_identical=digest(one)==digest(two),
                             reproducibility_comparison_valid=False,reason='The selected source/configuration changed between runs.'))

archive_pairs=[]
for name in targets:
    a=next(x for x in archives if x['run']==1 and x['path']==name)
    b=next(x for x in archives if x['run']==2 and x['path']==name)
    left={m['path']:m for m in a['members']}; right={m['path']:m for m in b['members']}
    differences=[]
    for member in left:
        changes={k:{'run1':left[member][k],'run2':right[member][k]} for k in ['sha256','bytes','mode','mtime'] if left[member][k]!=right[member][k]}
        if changes:differences.append(dict(path=member,changes=changes))
    archive_pairs.append(dict(path=name,byte_identical=a['sha256']==b['sha256'],member_differences=differences,
                              member_contents_identical=all(left[p]['sha256']==right[p]['sha256'] for p in left)))

after=[]
for run in [1,2]:
    record=json.loads((ROOT/f'source-manifest-after-run{run}.json').read_text())
    unchanged = run_sources[run]['files']==record['files']
    if run == 2:
        assert unchanged,'selected snapshot inputs changed during run2'
    after.append(dict(run=run,selected_inputs_unchanged_at_boundaries=unchanged,
                      scope='Run1 source changed after compilation/archive generation during SBOM phase; run2 uses the final copy and is stable at recorded boundaries.' if run==1 else 'Run2 inputs match the after-run1 and after-run2 manifests.'))
current_changes=[]
for path,record in source_map.items():
    if digest(REPO/path)!=record['sha256']:current_changes.append(path)

smoke_env=dict(os.environ,HOME=str(ROOT/'smoke-state/home'),IRONRUN_HOME=str(ROOT/'smoke-state/ironrun'),
               XDG_CONFIG_HOME=str(ROOT/'smoke-state/config'),XDG_STATE_HOME=str(ROOT/'smoke-state/state'),
               XDG_CACHE_HOME=str(ROOT/'smoke-state/cache'),GITHUB_ACTIONS='false')
for name in ['home','ironrun','config','state','cache']:(ROOT/'smoke-state'/name).mkdir(parents=True,exist_ok=True)
native=ROOT/'dist-run2/ironrun_linux_amd64_v1/ironrun'
smokes=[]
for name,args in [('version',['version']),('help',['--help']),('doctor-help',['doctor','--help']),('setup-help',['setup','--help'])]:
    proc=subprocess.run([str(native),*args],cwd=REPO,env=smoke_env,capture_output=True,timeout=30)
    (ROOT/f'smoke-{name}.stdout.txt').write_bytes(proc.stdout)
    (ROOT/f'smoke-{name}.stderr.txt').write_bytes(proc.stderr)
    assert proc.returncode==0,(name,proc.returncode,proc.stderr)
    smokes.append(dict(name=name,argv=[str(native),*args],exit_code=proc.returncode,
                       stdout_sha256=digest_bytes(proc.stdout),stderr_sha256=digest_bytes(proc.stderr),
                       scope='Linux amd64 CLI help/version only; no native store, network, or agent host'))
build_info=subprocess.run([str(TOOLS/'go/bin/go'),'version','-m',str(native)],capture_output=True,timeout=30)
assert build_info.returncode==0
(ROOT/'binary-go-version-m.txt').write_bytes(build_info.stdout)
tool_hashes={}
for name in ['goreleaser','syft']:
    provenance=json.loads((ROOT/'tooling'/f'{name}-provenance.json').read_text())
    observed=digest(TOOLS/'release-bin'/name)
    assert observed==provenance['binary_sha256'],name
    tool_hashes[name]=observed

summary=dict(recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    status='unpublished snapshot verification passed',base_head=before['head'],
    source_identity='Run1 start: source-manifest-before.json; run2 start/end: source-manifest-after-run1.json and source-manifest-after-run2.json. Base HEAD alone excludes dirty fixes.',
    source_stable_across_builds=False,source_boundary_checks=after,source_changes_between_runs=source_changes,
    metadata=metadata,checksums=checksums,binary_pairs=binary_pairs,generated_casks=casks,binary_build_metadata=binary_build_metadata,
    final_config_check=json.loads((ROOT/'goreleaser-check-final.result.json').read_text()),
    archives=archives,archive_pairs=archive_pairs,sboms=sboms,native_smokes=smokes,
    selected_input_changes_after_build=current_changes,tool_binary_hashes=tool_hashes,
    limits=['Diagnostic snapshot version is derived from existing local tags and is not a chosen release version.',
            'GoReleaser before hooks, signing, publication, announcements and snapshot validation are skipped; goreleaser check separately passed.',
            'Only Linux amd64 binaries were executed; Linux arm64 and both macOS targets were cross-compiled only.',
            'These runs use different source/configuration and are not a binary reproducibility experiment. Run1 compiler reads were not individually traced; phase observations and archived inputs bound its provenance.',
            'Run1 contains the pre-copy README and binaries; run2 contains the final copy. Archive hashes and member differences are retained.',
            'Generated diagnostic casks have snapshot version 0.5.1-next but URLs for the existing v0.5.0 tag; they are not publishable or installable release recipes.',
            'SBOMs were parsed and checked for SPDX/package presence; full schema validation and a new vulnerability analysis were not run.',
            'Tool hashes match earlier published-checksum provenance; checksum-file signatures were not independently verified.',
            'No tags, releases, npm packages, Homebrew tap writes, signatures, or public artifacts were created.',
            'Build information embeds base HEAD; use exact dirty-source hashes to identify the new runtime.'])
write('verification-summary.json',summary)
write('archive-metadata-comparison.json',archive_pairs)
write('native-smoke-results.json',smokes)

# Keep large binaries/archives/tools local; package enough evidence to inspect identity and outcomes.
selected=ROOT/'selected';selected.mkdir(exist_ok=True)
def retain(src,relative=None):
    relative=relative or src.relative_to(ROOT)
    dst=selected/relative;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst)
for p in ROOT.iterdir():
    if p.is_file() and p.suffix in ['.json','.txt','.py','.yml','.md'] and p.name not in ['artifact-manifest.json']:
        retain(p)
for run in [1,2]:
    for name in ['checksums.txt','artifacts.json','config.yaml','metadata.json','homebrew/Casks/ironrun.rb']:
        retain(ROOT/f'dist-run{run}'/name)
for p in (ROOT/'dist-run2').glob('*.sbom.json'):retain(p)
for p in (ROOT/'tooling').iterdir():
    if p.is_file():retain(p)
for name in ['README.md','LICENSE','ironrun.example.yml','install.sh']:
    retain(REPO/name,Path('inputs')/name)
for run in [1,2]:
    archive_path=ROOT/f'dist-run{run}/ironrun_Linux_x86_64.tar.gz'
    with tarfile.open(archive_path) as archive:
        for name in ['README.md','LICENSE','ironrun.example.yml']:
            dst=selected/'inputs'/f'run{run}'/name
            dst.parent.mkdir(parents=True,exist_ok=True)
            dst.write_bytes(archive.extractfile(name).read())
inventory=[]
for p in sorted(ROOT.rglob('*')):
    if p.is_file() and selected not in p.parents and 'smoke-state' not in p.parts and p.name not in ['artifact-manifest.json','full-workspace-inventory.json']:
        inventory.append(dict(path=str(p.relative_to(ROOT)),bytes=p.stat().st_size,sha256=digest(p)))
write('full-workspace-inventory.json',dict(scope='All retained full local outputs excluding selected copy, smoke-state and inventory itself.',files=inventory))
retain(ROOT/'full-workspace-inventory.json')
manifest=[dict(path=str(p.relative_to(selected)),bytes=p.stat().st_size,sha256=digest(p)) for p in sorted(selected.rglob('*')) if p.is_file() and p.name!='artifact-manifest.json']
(selected/'artifact-manifest.json').write_text(json.dumps(dict(algorithm='sha256',scope='Selected retained evidence; excludes this manifest itself.',files=manifest),indent=2)+'\n')
print(json.dumps(dict(status=summary['status'],checksum_entries=len(checksums),sbom_documents=len(sboms),binary_pairs=len(binary_pairs),
                      snapshot_versions=[m['version'] for m in metadata],native_smokes=len(smokes),current_input_changes=current_changes,
                      selected_files=len(manifest),selected_bytes=sum(e['bytes'] for e in manifest))))
