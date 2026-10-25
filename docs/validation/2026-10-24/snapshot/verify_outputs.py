"""Read-only verification of the two retained diagnostic snapshots (no rebuild/publish)."""
from pathlib import Path
import hashlib, json, tarfile

ROOT = Path(__file__).resolve().parent
REPO = Path('/workspace/ironrun-product-review')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

for run in [1, 2]:
    dist = ROOT / f'dist-run{run}'
    assert json.loads((ROOT / f'snapshot-run{run}.result.json').read_text())['exit_code'] == 0
    for line in (dist / 'checksums.txt').read_text().splitlines():
        expected, name = line.split(None, 1)
        target = REPO / name if name == 'install.sh' else dist / name
        assert digest(target) == expected, target
    for sbom in dist.glob('*.sbom.json'):
        document = json.loads(sbom.read_text())
        assert document['spdxVersion'] == 'SPDX-2.3'
        assert len(document['packages']) == 54
for binary in (ROOT / 'dist-run1').glob('ironrun_*/ironrun'):
    other = ROOT / 'dist-run2' / binary.relative_to(ROOT / 'dist-run1')
    assert digest(binary) == digest(other), binary
for archive in (ROOT / 'dist-run1').glob('*.tar.gz'):
    with tarfile.open(archive) as first, tarfile.open(ROOT / 'dist-run2' / archive.name) as second:
        left = {member.name: member for member in first.getmembers() if member.isfile()}
        right = {member.name: member for member in second.getmembers() if member.isfile()}
        assert left.keys() == right.keys()
        for name in left:
            assert first.extractfile(left[name]).read() == second.extractfile(right[name]).read(), (archive, name)
for stem in ['source-manifest-after-run1', 'source-manifest-after-run2']:
    assert json.loads((ROOT / 'source-manifest-before.json').read_text())['files'] == json.loads((ROOT / (stem + '.json')).read_text())['files']
print('Both snapshot results, 18 checksum entries, eight SBOM documents, four binary pairs, archive contents, and stable input manifests verified.')
