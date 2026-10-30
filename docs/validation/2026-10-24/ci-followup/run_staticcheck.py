from pathlib import Path
import datetime
import hashlib
import json
import os
import subprocess
import time

root = Path('/workspace/ironrun-product-research/launch-20261024/ci-followup')
repo = Path('/workspace/ironrun-product-review')
tool_root = Path('/workspace/ironrun-product-tools')
root.mkdir(parents=True, exist_ok=True)
(tool_root/'lint-bin').mkdir(exist_ok=True)
environment = dict(os.environ,
    PATH=str(tool_root/'go/bin')+':/usr/local/bin:/usr/bin:/bin',
    GOPATH=str(tool_root/'gopath'),
    GOMODCACHE=str(tool_root/'go-modules'),
    GOCACHE=str(tool_root/'go-cache'),
    GOTMPDIR=str(tool_root/'go-tmp'),
    TMPDIR=str(tool_root/'go-tmp'),
    GOBIN=str(tool_root/'lint-bin'),
    XDG_CACHE_HOME=str(root/'cache'),
    GOFLAGS='-buildvcs=false',
    GOTOOLCHAIN='local')
records = []

def run(label, argv, overrides=None):
    env = dict(environment, **(overrides or {}))
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    begin = time.monotonic()
    p = subprocess.run(argv, cwd=repo, env=env, capture_output=True)
    (root/(label+'.stdout.txt')).write_bytes(p.stdout)
    (root/(label+'.stderr.txt')).write_bytes(p.stderr)
    result = {'argv':argv, 'cwd':str(repo), 'started_at_utc':started,
              'elapsed_seconds':time.monotonic()-begin,
              'exit_code':p.returncode, 'stdout':label+'.stdout.txt',
              'stderr':label+'.stderr.txt', 'overrides':overrides or {}}
    records.append(result)
    (root/'staticcheck-commands.json').write_text(json.dumps(records, indent=2)+'\n')
    if p.returncode:
        print(json.dumps(result), flush=True)
        raise SystemExit(p.returncode)
    return p.stdout.decode()

go = str(tool_root/'go/bin/go')
version = run('go-version', [go,'version'])
assert 'go1.26.10' in version, version
run('staticcheck-install', [go,'install','honnef.co/go/tools/cmd/staticcheck@v0.8.2'],
    {'GOPROXY':'https://proxy.golang.org','GOSUMDB':'sum.golang.org'})
binary = tool_root/'lint-bin/staticcheck'
staticcheck_version = run('staticcheck-version', [str(binary),'-version'])
build_info = run('staticcheck-build-info', [go,'version','-m',str(binary)])
run('staticcheck-final', [str(binary),'./...'], {'GOPROXY':'off','GOSUMDB':'off'})
source = repo/'cmd/ironrun/mcp_registration.go'
summary = {'go_version':version.strip(), 'staticcheck_version':staticcheck_version.strip(),
           'binary':str(binary), 'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
           'checked_source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
           'exit_code':0, 'scope':'staticcheck ./... on current working tree; no full Go test suite run',
           'commands':'staticcheck-commands.json',
           'dependency_provenance':'Pinned v0.8.2 via Go module proxy and checksum database; build info and installation stderr retained.',
           'preceding_attempt':'initial-cache-failure: staticcheck could not create its default cache in read-only /home/agent/.cache; retained separately, then rerun with XDG_CACHE_HOME in writable evidence directory.',
           'environment_overrides':{k:environment[k] for k in ['PATH','GOPATH','GOMODCACHE','GOCACHE','GOTMPDIR','TMPDIR','GOBIN','XDG_CACHE_HOME','GOFLAGS','GOTOOLCHAIN']}}
(root/'staticcheck-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary), flush=True)
