# Doctor and paper follow-up evidence

This archive packages the completed October 23, 2026 doctor improvement and
paper checks. It introduces no experiment or new benchmark result. The
supervising agents observed the command exit statuses recorded in `summary.json`;
the packager independently checked retained bytes, hashes, capture results,
source-bundle contents, and final PDF text. No project credentials or real secret
values were used. The policy fixture names a synthetic entry but supplies no
value.

## Source and diagnostic binary identity

The reviewed changes started at `a4ab72e475bb6d3ed548e0dd7569294a1b3a0e8d`.
`summary.json` hashes the exact doctor implementation/tests, metadata inspector,
and Go module files at packaging. These were uncommitted reviewed changes when
captured, so the base commit alone does not identify the changed source.

The final diagnostic binary was built with Go 1.26.10 and
`GOFLAGS=-buildvcs=false`; its SHA-256 is
`b817d8a0d716cf2466d7df4147ff0e4067873665a181ec4014bb9deaf99a6f0d`.
The executable is not included. This is a development diagnostic build, not a
signed release asset. The REA capture records its prelaunch digest, not an atomic
binding to the OS-loaded image. Earlier capture binaries have their own recorded
digests and must not be confused with the final binary.

## Tests and static checks

| Evidence | Observed exit | Scope |
| --- | ---: | --- |
| `doctor-red.log` | 1, expected | Original doctor falsely accepts missing, expired, mismatched, and incomplete environment metadata; new regressions fail |
| `doctor-green-race.log` | 0 | Initial metadata-only implementation; precedes the padded-name compatibility repair |
| `doctor-padding-red.log` | 1, expected | Existing valid padded environment names expose the initial implementation's overly strict validation |
| `doctor-padding-green-race.log` | 0 | Final focused CLI and metadata checks under the race detector |
| `final-race.log` | 0 | `go test -race -count=1 ./...`; all packages, uncached execution |
| `final-vet.log` | 0 | `go vet ./...`; empty output |

Final race verification ran outside the agent filesystem sandbox so Linux
namespace tests could execute, with synthetic fixtures. This is not native macOS
or ARM execution evidence; platform skips do not establish containment. The
focused tests cover read-only metadata inspection and legacy compatibility, safe
recovery output, explicit policy roots, padded names, and native-store traps.
The full suite checks the repository's existing contracts as well; passing tests
does not prove complete security or absence of defects.

Selected final-check settings were Go 1.26.10, `GOFLAGS=-buildvcs=false`,
`GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, synthetic XDG state/cache
locations, and `GITHUB_ACTIONS=false` for the full suite. Dependency caches were
already populated. No environment dump was used. Outer command timestamps and
walltimes were not captured here and are not reconstructed; raw logs preserve
the durations they emitted.

## REA controlled replay

REA 6.7.0 ran doctor against the same synthetic v2 project with missing local
environment metadata. `fixture-policy.yml` is the exact policy. The two scenario
JSON files retain the original absolute fixture/tool paths; recreate the fixture
and rebuild the corresponding source before replaying elsewhere.

| Capture | Doctor exit | Recorded behavior |
| --- | ---: | --- |
| `rea-doctor-before.json` | 0 | Reports passthrough provider and “All checks passed” |
| `rea-doctor-final.json` | 1 | Identifies missing environment metadata, gives `ironrun env init dev`, and states that secret values and vault access were not checked |

Both successful REA captures report six observed filesystem entries, all
unchanged, no truncation, and verified owned-process cleanup. REA's own CLI
succeeded for the final capture even though the program under observation
correctly exited 1. This distinction matters when interpreting capture success.
The fixture's empty audit file existed before these captures; it was not created
by doctor.

An earlier attempt inside the filesystem sandbox failed REA's cleanup validation
because its process-ownership token could not be read (`EACCES`). It remains in
`rea-cleanup-failure.json` and `.stderr` as a **partial observation**, not a
successful full capture. The final successful capture ran outside that extra
filesystem sandbox with the same fixture. It supersedes that attempt for the
before/after observation; the failure is not hidden or relabeled.

Filesystem snapshots cannot exclude transient writes. Sampled process trees can
miss short-lived processes, inherited ambient environment is unrecorded, and
network activity is not observed. Native-store traps and source review supply
separate evidence for the intended no-vault-access contract.

## Paper build and artifacts

The final PDF has **13 pages, 5 figures, 3 tables**, and a synchronized
**1,812-character ASCII abstract**. The parent reviewed all final PDF pages at
1350px: diagrams and tables were readable, and no clipping or overlap was seen.
The chunking property stays together on page 5. This is bounded visual review,
not an automated guarantee about all viewers or print environments.

`paper-source.tar.gz` is the exact generated three-file source bundle, containing
`ironrun.tex`, `ironrun.bbl`, and `references.bib`. It matches the final built
source bytes. `paper-build.log` records the successful source build and source
packaging; `bundle-build-latexmk.log` records a successful extracted-bundle build.
The latter explicitly runs BibTeX and is not evidence of compiling without that
step. Final sources, PDF, bibliography, and bundle identities are in
`summary.json`. `tex-packages.json` records downloaded supplemental TeX package
identities; those packages are not included.

Final build logs contain no undefined references/citations, font-substitution
warnings, or overflowing boxes. Underfull-box diagnostics remain ordinary
spacing warnings. Extracted-bundle PDF text matches the source-tree build. The separate `bundle-pdflatex.result.json` and three
`bundle-pdflatex-pass*.log` files record three successful direct pdflatex passes
in a new directory initially containing only the three shipped source files.
No BibTeX command ran in this check. Its final log has no undefined references,
font substitutions, or overfull boxes, and the parent verified that the resulting
PDF text exactly matches the final tracked PDF. The first pass
retains ordinary cross-reference/rerun diagnostics; interpret final warnings from
the third pass.

The paper's experimental evidence remains separately pinned to the measured
runtime, in [the October 22 archive](../../2026-10-22/fresh-pilot/README.md).
This doctor change does not retroactively alter those inputs or results. No
publication, release, merge, registry package, or arXiv submission is claimed.

## Verify archived bytes

`artifact-manifest.json` inventories all archive files except itself. From this
directory:

```sh
python3 - <<'PY'
import hashlib, json
from pathlib import Path
root = Path('.')
entries = json.loads((root / 'artifact-manifest.json').read_text())['files']
assert {p.name for p in root.iterdir() if p.is_file()} - {'artifact-manifest.json'} == {e['path'] for e in entries}
for entry in entries:
    data = (root / entry['path']).read_bytes()
    assert len(data) == entry['bytes'], entry['path']
    assert hashlib.sha256(data).hexdigest() == entry['sha256'], entry['path']
print('Archive inventory verified')
PY
```

Changing the README, summary, or adding logs requires regenerating the inventory.
