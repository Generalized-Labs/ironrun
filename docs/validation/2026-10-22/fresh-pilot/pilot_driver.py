import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import time

REPO = pathlib.Path('/workspace/ironrun-product-review')
OUT = pathlib.Path('/workspace/ironrun-product-research/fresh-pilot')
TOOLS = pathlib.Path('/workspace/ironrun-product-tools')
GO = TOOLS / 'go/bin/go'
OUT.mkdir(parents=True, exist_ok=True)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def write_json(name, obj):
    (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n')

def read_optional(p):
    try:
        return pathlib.Path(p).read_text().strip()
    except OSError as ex:
        return {'unavailable': str(ex)}

def environment():
    # Record only explicit diagnostic settings, never enumerate the environment.
    explicit = {
        'PATH': str(TOOLS / 'go/bin') + ':/usr/local/bin:/usr/bin:/bin',
        'GOPATH': str(TOOLS / 'gopath'),
        'GOMODCACHE': str(TOOLS / 'go-modules'),
        'GOCACHE': str(TOOLS / 'go-cache'),
        'GOTMPDIR': str(TOOLS / 'go-tmp'),
        'TMPDIR': str(TOOLS / 'go-tmp'),
        'XDG_STATE_HOME': '/workspace/ironrun-product-research/test-state',
        'XDG_CACHE_HOME': '/workspace/ironrun-product-research/test-cache',
        'GOFLAGS': '-buildvcs=false',
        'GOTOOLCHAIN': 'local',
        'GOPROXY': 'off',
        'GOSUMDB': 'off',
    }
    result = os.environ.copy()
    result.update(explicit)
    return result, explicit

def source_manifest():
    listing = subprocess.run(['git', 'ls-files', '-z'], cwd=REPO, check=True, stdout=subprocess.PIPE).stdout
    entries = []
    for raw in listing.split(b'\0'):
        if not raw:
            continue
        rel = os.fsdecode(raw)
        p = REPO / rel
        if p.is_symlink():
            data = os.readlink(p).encode()
            kind = 'symlink-target'
        else:
            data = p.read_bytes()
            kind = 'file'
        entries.append({'path': rel, 'kind': kind, 'bytes': len(data), 'sha256': sha(data)})
    encoded = json.dumps(entries, separators=(',', ':'), sort_keys=True).encode()
    return {'files': entries, 'manifest_sha256': sha(encoded)}

def corpus_snapshot():
    # Matches filepath.WalkDir lexical traversal, including symlinked file reads.
    entries = []
    payload = bytearray()
    def walk(directory):
        for p in sorted(directory.iterdir(), key=lambda p: p.name):
            is_dir = p.is_dir() and not p.is_symlink()
            if is_dir:
                if p.name not in {'.claude', '.git', 'paper'}:
                    walk(p)
            elif p.name.endswith(('.go', '.md')):
                data = p.read_bytes()
                entries.append({'path': str(p.relative_to(REPO)), 'bytes': len(data),
                                'sha256': sha(data), 'corpus_offset': len(payload)})
                payload.extend(data)
    walk(REPO)
    source_bytes = len(payload)
    logs = ''.join('INFO connecting to db.internal:5432/app?sslmode=require attempt=%d\n' % i
                   for i in range(1000)).encode()
    payload.extend(logs)
    (OUT / 'fp-corpus.bin').write_bytes(payload)
    return {'files': entries, 'source_bytes': source_bytes, 'appended_log_lines': 1000,
            'appended_logs_bytes': len(logs), 'appended_logs_sha256': sha(logs),
            'total_bytes': len(payload), 'corpus_sha256': sha(payload),
            'read_errors': [], 'walk_order': 'Go filepath.WalkDir lexical depth-first',
            'excluded_directory_names': ['.claude', '.git', 'paper']}

def prepare():
    env, explicit = environment()
    for name in ['XDG_STATE_HOME', 'XDG_CACHE_HOME', 'GOTMPDIR']:
        pathlib.Path(explicit[name]).mkdir(parents=True, exist_ok=True)
    write_json('source-manifest-before.json', source_manifest())
    write_json('fp-corpus-manifest.json', corpus_snapshot())
    cpu_details = []
    for line in pathlib.Path('/proc/cpuinfo').read_text().splitlines():
        if line.startswith(('model name', 'cpu MHz', 'siblings', 'cpu cores')) and line not in cpu_details:
            cpu_details.append(line)
    cgroup_paths = ['cpu.max', 'cpu.stat', 'cpuset.cpus.effective', 'memory.max',
                    'memory.high', 'memory.current', 'pids.max']
    metadata = {
        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'repository': str(REPO),
        'commit': subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=REPO, check=True, text=True, stdout=subprocess.PIPE).stdout.strip(),
        'git_status': subprocess.run(['git', 'status', '--short'], cwd=REPO, check=True, text=True, stdout=subprocess.PIPE).stdout,
        'toolchain': subprocess.run([str(GO), 'version'], env=env, check=True, text=True, stdout=subprocess.PIPE).stdout.strip(),
        'go_binary_sha256': sha(GO.read_bytes()),
        'driver_sha256': sha(pathlib.Path(__file__).read_bytes()),
        'explicit_settings': explicit,
        'uname': list(platform.uname()),
        'os_release': read_optional('/etc/os-release'),
        'cpu_details': cpu_details,
        'logical_cpu_count': os.cpu_count(),
        'affinity_cpus': sorted(os.sched_getaffinity(0)),
        'cgroup_membership': read_optional('/proc/self/cgroup'),
        'cgroup': {n: read_optional('/sys/fs/cgroup/' + n) for n in cgroup_paths},
        'load_average_before': list(os.getloadavg()),
        'credential_policy': 'synthetic harness fixtures only; no provider calls or environment-file reads',
        'scope': 'fresh shared-host diagnostic, not reconstruction of historical performance or FP tables',
    }
    write_json('provenance.json', metadata)
    print(json.dumps({'phase':'prepare', 'commit':metadata['commit'], 'git_status':metadata['git_status'],
                      'toolchain':metadata['toolchain'],
                      'fp_bytes':json.loads((OUT/'fp-corpus-manifest.json').read_text())['total_bytes']}))

def execute(phase):
    env, _ = environment()
    commands = {
        'test': [str(GO), 'test', './paper/eval'],
        'build': [str(GO), 'build', '-o', str(OUT/'eval'), './paper/eval'],
        'leak': [str(OUT/'eval'), '-only', 'leak'],
        'fp': [str(OUT/'eval'), '-only', 'fp'],
        'perf': [str(OUT/'eval'), '-only', 'perf'],
    }
    argv = commands[phase]
    result = {'phase':phase, 'argv':argv, 'cwd':str(REPO),
              'start_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'load_average_before':list(os.getloadavg()),
              'cpu_stat_before':read_optional('/sys/fs/cgroup/cpu.stat')}
    start = time.monotonic_ns()
    try:
        with (OUT/(phase+'.stdout.txt')).open('wb') as stdout, (OUT/(phase+'.stderr.txt')).open('wb') as stderr:
            proc = subprocess.run(argv, cwd=REPO, env=env, stdout=stdout, stderr=stderr, timeout=600)
        result['exit_code'] = proc.returncode
    except subprocess.TimeoutExpired:
        result['exit_code'] = None
        result['timeout_seconds'] = 600
    result['wall_ns'] = time.monotonic_ns() - start
    result['end_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result['load_average_after'] = list(os.getloadavg())
    result['cpu_stat_after'] = read_optional('/sys/fs/cgroup/cpu.stat')
    for stream in ['stdout', 'stderr']:
        data = (OUT/(phase+'.'+stream+'.txt')).read_bytes()
        result[stream+'_bytes'] = len(data)
        result[stream+'_sha256'] = sha(data)
    if phase == 'build' and result['exit_code'] == 0:
        result['binary_sha256'] = sha((OUT/'eval').read_bytes())
    if phase == 'fp':
        after = source_manifest()
        write_json('source-manifest-after-fp.json', after)
        before = json.loads((OUT/'source-manifest-before.json').read_text())
        result['source_unchanged_since_snapshot'] = after == before
        corpus = json.loads((OUT/'fp-corpus-manifest.json').read_text())
        match = re.search(r'corpus (\d+) bytes', (OUT/'fp.stdout.txt').read_text())
        result['reported_corpus_matches_manifest_bytes'] = bool(match and int(match.group(1)) == corpus['total_bytes'])
    write_json(phase+'.result.json', result)
    print(json.dumps(result, sort_keys=True))
    if result['exit_code'] != 0:
        sys.exit(1)
    if phase == 'fp' and not (result['source_unchanged_since_snapshot'] and result['reported_corpus_matches_manifest_bytes']):
        sys.exit(2)

if __name__ == '__main__':
    if sys.argv[1] == 'prepare':
        prepare()
    else:
        execute(sys.argv[1])
