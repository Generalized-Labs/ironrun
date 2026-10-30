#!/usr/bin/env python3
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

REPO = Path('/workspace/ironrun-product-review')
OUT = Path('/workspace/ironrun-product-research/launch-20261026/runtime-checks/final-copy')
TOOLS = Path('/workspace/ironrun-product-tools')
OUT.mkdir(parents=True, exist_ok=True)
SETTINGS = {
    'PATH': str(TOOLS/'go/bin') + ':/usr/local/bin:/usr/bin:/bin',
    'GOPATH': str(TOOLS/'gopath'),
    'GOMODCACHE': str(TOOLS/'go-modules'),
    'GOCACHE': str(TOOLS/'go-cache'),
    'GOTMPDIR': str(TOOLS/'go-tmp'),
    'TMPDIR': str(TOOLS/'go-tmp'),
    'GOFLAGS': '-buildvcs=false',
    'GOPROXY': 'off',
    'GOSUMDB': 'off',
    'GOTOOLCHAIN': 'local',
    'GITHUB_ACTIONS': 'false',
    'XDG_STATE_HOME': str(OUT/'state'),
    'XDG_CACHE_HOME': str(OUT/'cache'),
}
ENV = dict(os.environ, **SETTINGS)

def identity():
    names = set()
    for args in [('ls-files', '-z'), ('ls-files', '--others', '--exclude-standard', '-z')]:
        names.update(x for x in subprocess.check_output(['git', *args], cwd=REPO).decode().split('\0') if x)
    selected = []
    for name in sorted(names):
        if name.endswith('.go') or name in ['go.mod', 'go.sum']:
            p = REPO/name
            selected.append({'path': name, 'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()})
    return {'base_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO).decode().strip(),
            'scope': 'All tracked and untracked Go source plus go.mod/go.sum; dirty source is identified by hashes, not base HEAD alone.',
            'files': selected}

phase = sys.argv[1]
commands = {
    'race': (['go', 'test', '-race', '-count=1', './...'], REPO),
    'vet': (['go', 'vet', './...'], REPO),
    'staticcheck': ([str(TOOLS/'lint-bin/staticcheck'), './...'], REPO),
    'release': (['python3', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'release_test.py', '-v'], REPO),
    'npm': (['/opt/codex/runtimes/codex-primary-runtime/dependencies/node/bin/node', '--test', *sorted(str(p.relative_to(REPO/'npm')) for p in (REPO/'npm/test').glob('*.test.js'))], REPO/'npm'),
}
assert phase in commands, phase
if phase == 'npm':
    ENV['PATH'] = '/opt/codex/runtimes/codex-primary-runtime/dependencies/node/bin:' + SETTINGS['PATH']
before = identity()
if phase == 'race':
    (OUT/'source-before.json').write_text(json.dumps(before, indent=2)+'\n')
    (OUT/'environment-constants.json').write_text(json.dumps(SETTINGS, indent=2)+'\n')
assert next(x['sha256'] for x in before['files'] if x['path'] == 'mcp/server.go') == 'c585b0004ea56fa2de402987269ed1caa0446795b19648dab2caaa47dc0464d2'
argv, cwd = commands[phase]
start = datetime.datetime.now(datetime.timezone.utc).isoformat()
mono = time.monotonic()
with (OUT/(phase+'.log')).open('wb') as log:
    p = subprocess.run(argv, cwd=cwd, env=ENV, stdout=log, stderr=subprocess.STDOUT)
after = identity()
result = {'phase': phase, 'argv': argv, 'cwd': str(cwd), 'exit_code': p.returncode,
          'started_at_utc': start, 'ended_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'elapsed_seconds': time.monotonic()-mono, 'source_unchanged': before == after,
          'source_identity': 'source-before.json',
          'phase_environment_override': {'PATH': ENV['PATH']} if phase == 'npm' else {},
          'execution_scope': 'Outside extra filesystem sandbox, real containment still exercised' if phase == 'race' else 'Synthetic credential-free verification',
          'log': phase+'.log', 'log_sha256': hashlib.sha256((OUT/(phase+'.log')).read_bytes()).hexdigest()}
(OUT/(phase+'.result.json')).write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result))
assert before == after, 'Go source changed during verification'
raise SystemExit(p.returncode)
