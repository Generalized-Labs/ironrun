import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

repo = Path('/workspace/ironrun-product-review')
out = Path('/workspace/ironrun-product-research/launch-20261026/paper/author-confirmation')
out.mkdir(exist_ok=True)
env = dict(os.environ, TEXMFHOME='/workspace/ironrun-product-tools/texmf',
           TEXMFVAR='/workspace/ironrun-product-tools/texmf-var',
           TEXMFCONFIG='/workspace/ironrun-product-tools/texmf-config')
commands = []

def run(argv, cwd, label):
    p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True)
    (out / (label + '.stdout.txt')).write_bytes(p.stdout)
    (out / (label + '.stderr.txt')).write_bytes(p.stderr)
    commands.append(dict(argv=argv, cwd=str(cwd), returncode=p.returncode,
                         stdout=label+'.stdout.txt', stderr=label+'.stderr.txt'))
    assert p.returncode == 0, (label, p.returncode)
    return p.stdout

run(['make', '-C', 'paper', 'arxiv'], repo, 'make-arxiv')
archive = repo / 'paper/ironrun-arxiv.tar.gz'
fresh = Path(tempfile.mkdtemp(prefix='fresh-bundle-', dir=out))
with tarfile.open(archive) as t:
    names = t.getnames()
    assert sorted(names) == ['ironrun.bbl', 'ironrun.tex', 'references.bib'], names
    t.extractall(fresh, filter='data')
for n in names:
    assert (fresh/n).read_bytes() == (repo/'paper'/n).read_bytes(), n
for i in range(1, 4):
    run(['pdflatex', '-no-shell-escape', '-interaction=nonstopmode',
         '-halt-on-error', 'ironrun.tex'], fresh, f'pdflatex-pass{i}')
review_text = run(['pdftotext', str(repo/'paper/ironrun.pdf'), '-'], repo, 'review-pdf-text')
bundle_text = run(['pdftotext', str(fresh/'ironrun.pdf'), '-'], fresh, 'bundle-pdf-text')
assert review_text == bundle_text, 'Extracted PDF text differs'
log_patterns = r'Warning|Overfull|undefined|Missing character|Font shape.*not available'
warnings = {}
underfull = {}
allowed_notices = {}
for label, path in [('review', repo/'paper/ironrun.log'), ('bundle', fresh/'ironrun.log')]:
    matches = [line for line in path.read_text().splitlines() if re.search(log_patterns, line)]
    allowed_notices[label] = [x for x in matches if x == 'Package epstopdf Warning: Shell escape feature is not enabled.']
    matches = [x for x in matches if x not in allowed_notices[label]]
    warnings[label] = matches
    underfull[label] = [line for line in path.read_text().splitlines() if 'Underfull' in line]
    assert not matches, (label, matches)
info = run(['pdfinfo', str(repo/'paper/ironrun.pdf')], repo, 'pdfinfo').decode()
assert re.search(r'^Pages:\s+14$', info, re.M), info
tex = (repo/'paper/ironrun.tex').read_text()
abstract = re.search(r'\\begin\{abstract\}(.*?)\\end\{abstract\}', tex, re.S).group(1)
abstract = abstract.replace('\\sys{}', 'ironrun').replace('\\%', '%')
abstract = abstract.replace('\\textbf{', '').replace('\\emph{', '').replace('}', '')
abstract = re.sub(r'\s+', ' ', abstract).strip()
metadata = (repo/'paper/ARXIV.md').read_text().split('## Abstract\n\n', 1)[1].split('\n\n## ', 1)[0].strip()
assert abstract == metadata, (abstract, metadata)
assert metadata.isascii() and len(metadata) == 1815
assert len(re.findall(r'\\begin\{figure\*?\}', tex)) == 5
assert len(re.findall(r'\\begin\{table\*?\}', tex)) == 4
artifacts = {}
for path in [repo/'paper/ironrun.tex', repo/'paper/references.bib', repo/'paper/ironrun.bbl',
             repo/'paper/ironrun.pdf', archive, fresh/'ironrun.pdf']:
    artifacts[str(path)] = dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
summary = dict(pages=14, figures=5, tables=4, abstract_ascii=True, abstract_characters=len(metadata),
               abstract_matches=True, bundle_members=names, source_members_identical=True,
               pdflatex_only_passes=3, shell_escape=False, extracted_pdf_text_identical=True,
               final_log_findings=warnings, allowed_notices=allowed_notices,
               underfull_box_notices=underfull, artifacts=artifacts, commands=commands,
               limitations=['Local TeX build is not arXiv server processing or moderation.',
                            'PDF byte identity is not expected because build metadata differs.',
                            'Visual page review is recorded separately after rendering.'])
(out/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
print(json.dumps({k:summary[k] for k in ['pages','figures','tables','abstract_characters','extracted_pdf_text_identical']}))
