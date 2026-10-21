# Open-source launch readiness review

Review date: October 19, 2026 (America/New_York).
Source baseline: commit `8e3c354`, branch `work`; documentation changes made
during the review are listed below.

**Assessment: automated Linux checks pass; launch verification remains incomplete.**
Release and runtime defects have been repaired locally. Signed final artifacts,
real target-platform execution, account setup, and human-validation gates remain
open. This review is not a security certification.

Scope: release workflows, installation, npm packaging, build reproducibility,
project governance, documentation, and test-gate coverage. The research-paper
review is a separate artifact. Repairs were requested by the user; this report
records both the initial audit and subsequent local repairs.

## GitHub review handoff

These repairs and evidence are prepared for the `launch/readiness-arxiv-review`
branch and pull request. No release tag, registry package, or arXiv submission is
part of this handoff. The [full paper walkthrough](PAPER_WALKTHROUGH.md) and
[algorithm walkthrough](REDACTION_WALKTHROUGH.md) explain the results and limits.

## Final code and arXiv validation — October 21, 2026

The final pass fixed swallowed stdout/stderr flush errors, bounded a quadratic
whitespace-gap scan, and aligned installer/Action prerelease tags with the
manifest validator. Both flush regressions and hyphenated prerelease installations
failed before repair and pass afterward. The independent runtime/release review
found no remaining blocker in those changes.

The full Go race suite, vet, and 11 offline release tests pass. The expanded
redactor fuzz target compares batch and chunked output as well as checking the
existing fixed-pattern leakage invariants: 22,581 executions passed in 11 seconds.
All four Linux/macOS snapshot archives built and their checksums verified; the
Linux amd64 binary runs. Cross-compilation does not establish target runtime
coverage. Signing, SBOM generation, before hooks and publication were skipped.

The arXiv build now generates its missing bibliography even when a tracked PDF
is already current. A fresh source bundle builds after extraction. The PDF is
14 pages and the synchronized metadata abstract is 1,905 ASCII characters, below
arXiv's documented 1,920 limit. Read `docs/REDACTION_WALKTHROUGH.md` for the full
algorithm/proof explanation and `paper/ARXIV.md` for submission requirements.
Raw final test logs and snapshot hashes are in `docs/validation/2026-10-21/`.
Historical audit/performance records and live release/platform gates remain open.

## Final documentation check — October 21, 2026

The manuscript now distinguishes installer/Action Sigstore verification from npm
manifest hash verification and omits the unconfirmed CodeQL claim. The refreshed
PDF builds successfully to 14 pages, with a monospace italic font fallback.
Earlier page counts below describe earlier builds. Check the venue page limit
before submission. Graphify and REA source reports were refreshed after the
launcher integration tests.

## Latest follow-up — launcher and baseline evidence

The actual launcher now has cold/warm/offline/corrupt-cache, concurrent-launch,
archive/binary tampering, exit-code, and signal integration tests. They exposed a
signal-swallowing defect: a child independently killed by SIGTERM made the
launcher exit zero. Forwarding listeners are now removed before mirroring the
child's signal. All 13 npm tests pass on Node 20.20.2, 22.23.3 and 24.19.0.
HTTP is fixture-backed; this does not replace live release downloads, proxy,
read-only-cache, or platform testing.

A new baseline experiment reproduced **52/126 versus 28/126** threshold cases,
with **21/72 versus 3/72** in the accidental subset. The baseline is pinned to
v0.5.0 commit `d16e04b09ec8c24e6d6e255caad9209182635af8`. Both runtimes used the
same corrected harness and Go 1.26.9. See `paper/REPRODUCING.md` and the raw logs
and source-hash provenance in `docs/validation/2026-10-20/`. This supersedes earlier
statements that baseline leakage counts were unverified. The self-audit count,
historical performance/false-positive tables, and RQ4 still need evidence.

## Validation update — October 20, 2026

The user explicitly authorized credential-free direct tests. The original audit
findings below describe the starting tree; this update supersedes its execution
blocker and no-fix status. Changes remain local and unpublished.

Implemented: tag-bound installer/action signature checks; draft GitHub release
until signing and verification finish; npm prerelease routing; commit-date
stamping; npm prepublication metadata validation and fixture tests; evaluation
failure detection; stricter seccomp regression assertion; paper corrections and
rebuilt PDF.

Verified so far on Linux amd64 with Go 1.26.9 and Node 24.19.0:

- `go build ./...` and `go vet ./...`: passed.
- `go test -race ./...`: all packages passed. Namespace tests required execution
  outside the filesystem sandbox; state/cache directories were redirected to
  temporary paths. The earlier sandbox failures are not hidden or counted as passes.
- Offline release tests: 10 passed, exercising installer and action with fixture
  downloads/verifier. This checks control flow and identity binding, not real
  Sigstore cryptography.
- Node tests: 13 passed on Node 20, 22, and 24, including launcher integration tests.
- Redactor fuzz smoke: 34,028 executions over approximately 11 seconds, passed.
- Current leakage corpus: 28/126 cases meet the case-insensitive 50% threshold;
  six entropy warnings on the 98 other cases. The baseline was subsequently reproduced
  at 52/126 using the same corrected harness; see the latest follow-up above.
- Paper: 13-page PDF rebuilt; no undefined citations or overfull boxes reported;
  an italic monospace font fallback warning remains. First-page layout inspected.
- Shell syntax and `git diff --check`: passed.
- `govulncheck`: no reachable vulnerabilities found. One advisory exists in a
  required module outside imported/called code; this is not a claim of zero
  advisories across the dependency graph. CI now treats scan failure as blocking.
- macOS arm64 cross-compilation passed (not a macOS runtime test).
- `staticcheck ./...`: passed.
- npm package dry-run: passed; direct publication metadata validation correctly
  rejects the unprepared checkout.
- GoReleaser 2.18.2 check: configuration structurally valid, but exits 2 for
  the pre-existing deprecated `brews` integration. Packaging migration remains
  an explicit maintenance gate.
- Performance harness completed with 200 successful samples per mode. Results
  were collected on a shared Linux host during concurrent builds and are
  diagnostic only, not replacement publication benchmarks.

Additional verified evidence: two GoReleaser 2.18.2 snapshot builds produced
identical binaries for Linux/macOS on amd64/arm64; all archive checksums verified.
Signing, SBOM generation, publishing, and before hooks were explicitly skipped.
This is local repeatability, not independent reproducibility across machines.

Remaining gates: real signed-release rehearsal and SBOM validation,
all-platform execution, complete npm launcher/cache
integration coverage, account/bootstrap checks, independent historical research
artifacts, and the checklist’s external-user/product studies. Homebrew changes now stage as a draft tap PR; maintainers must verify and merge
it after the signed GitHub release is public. GA readiness is therefore **not established**.

## Subsequent graph-assisted review

See `REVERSE_ENGINEERING.md` for REA, Graphify and primary-source web findings.
A relative-executable working-directory bug was reproduced and fixed; the full
race suite and vet passed again. Earlier release snapshot hashes predate this
fix, so release artifacts must be rebuilt before publication.

## Original audit evidence inspected

- `AGENTS.md`, `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`, and
  `.github/CODEOWNERS`.
- `go.mod`, `go.sum`, `Makefile`, `.goreleaser.yml`, and `action.yml`.
- `.github/workflows/ci.yml`, `release.yml`, and `fuzz.yml`.
- `install.sh`, `Formula/ironrun.rb`, npm launcher, manifest builder, package
  metadata, and launcher tests.
- `docs/INSTALL.md`, `NPM_BOOTSTRAP.md`, `RELEASE_CHECKLIST.md`,
  `ARCHITECTURE.md`, and Windows support documentation.

## Checklist status

| Category | Status | Evidence and practical limit | Confidence |
| --- | --- | --- | --- |
| Tooling/CI drift | Watch | Linux/macOS race tests and Node 20/22/24 jobs exist; release publication precedes final validation/signing. CI configuration was inspected, not executed. | High |
| Docs vs. reality | Watch; some drift resolved | Windows launch references and README's `op run` comparison were corrected during this review. Build-date/reproducibility claims and npm bootstrap instructions still need work. | High |
| Configuration/environment | Unknown operationally | Release requires tap credentials and npm trusted-publisher setup. Their existence and permissions were not inspected. | High about uncertainty |
| Dependency health | Unknown | Go manifest and checksum lockfile exist. No vulnerability scan or remote advisory check was run; CI vulnerability failures are advisory. | High about uncertainty |
| Test health/flakiness | Unknown execution; Watch coverage | Test sources and CI gates exist. Launcher tests cover mapping and hash verification, not complete installation/launch behavior. No tests were run in this review. | High |
| Package/release health | At risk | Public release ordering, broad signature identity, prerelease npm routing, and bootstrap validation gaps below. | High |
| Instruction drift | Blocked execution path | `AGENTS.md` requires sealed execution/proposals, but those tools are unavailable in this chat. No raw-shell fallback was used for tests. | High |
| Governance | Present, operationally unverified | MIT license, contribution/security/conduct documents, templates, and code owners exist. Private reporting, branch protection, ownership, and publishing controls were not verified remotely. | High |

## Prioritized findings

### Critical — Publication occurs before validation and signing finish

- Evidence: `.github/workflows/release.yml:42` runs `goreleaser release`;
  `.goreleaser.yml:104` sets `draft: false`. Manifest generation and tests begin
  at `release.yml:53`; signing and bundle uploads begin at line 76.
- Impact: later failures leave a public release without required verified
  installation assets. Successful runs still expose a partial-publication window.
- Confidence: high, based on workflow order; no failure was induced.
- Next module/action: **implementation** — build and validate first, stage a
  draft release, upload and verify all signed assets, then publish it.

### Critical — Signature identity does not authenticate the requested version

- Evidence: `install.sh:57` and `action.yml:101` accept signing identities for
  any tag under `@refs/tags/`. Archive filenames do not contain the version.
- Impact: substitution of an older genuine signed archive, checksums, and bundles
  can satisfy verification for a different requested version. This requires asset
  or download substitution; it is not a demonstrated compromise of HTTPS.
- Confidence: high for the missing version binding; no live attack performed.
- Next module/action: **implementation** — bind certificate identity to the
  validated requested tag in both installer and action, and add a cross-version
  rejection test.

### Watch — Alpha and beta tags can become npm `latest`

- Evidence: `release.yml:65` identifies prereleases only by `-rc.`; line 71
  publishes every other tag to `latest`.
- Impact: a tag such as `v1.0.0-beta.1` becomes the default npm installation.
- Confidence: high.
- Next module/action: **implementation** — classify all SemVer prereleases as
  `next`, and reserve `latest` for stable versions.

### Watch — Bootstrap instructions can publish an unusable npm package

- Evidence: `docs/NPM_BOOTSTRAP.md:20` refers to a built package but supplies
  only `cd npm` and `npm publish`. The checked-in manifest says `1.0.0` and has
  no artifacts; `package.json` says `0.5.1`. `npm/lib/launcher.js:43` rejects
  mismatched versions. There is no prepublish validation script.
- Impact: a maintainer following the commands from checkout can publish a
  permanently unusable package version. The automated release manifest builder
  does populate the package correctly when it succeeds.
- Confidence: high.
- Next module/action: **implementation** — document the exact artifact-building
  prerequisite and add a publish guard for version, platforms, sizes, and hashes.

### Watch — Release build date contradicts reproducibility claims

- Evidence: `.goreleaser.yml:33` stamps `{{.Date}}`, GoReleaser's build date;
  `docs/INSTALL.md:110–113` describes it as the commit date and claims no
  wall-clock input. The Make target uses the commit date separately.
- Impact: repeated release builds can differ even when local Make builds agree.
- Confidence: high for the configuration/documentation mismatch; release builds
  were not executed.
- Next module/action: **implementation** — stamp the commit date explicitly and
  compare binaries from repeated release-path builds with the same toolchain.

### Watch — Launcher tests do not substantiate the installation checklist

- Evidence: `npm/test/launcher.test.js` has platform-mapping and file-integrity
  tests, without integration tests of `verifiedBinary` or `launch`. Packed
  installation alone does not prove execution because postinstall tolerates
  download/preparation errors.
- Impact: download, cache repair, locking, offline behavior, and signal/exit
  propagation can regress without these tests detecting it.
- Confidence: high from test inspection; no runtime failure asserted.
- Next module/action: **implementation** — add fixture-backed integration tests
  and execute the installed packed CLI, not only `npm install`.

### Watch — Required release gates lack completion evidence

- Evidence: `docs/RELEASE_CHECKLIST.md` remains unchecked; npm publishing is
  nonblocking pending bootstrap; CI's vulnerability scan suppresses failure.
- Impact: a green workflow alone cannot establish GA readiness. Account setup,
  vulnerability triage, platform verification, and the human/product gates need
  actual results. Unchecked gates are unknown, not assumed failures.
- Confidence: high about missing evidence in this review.
- Next module/action: **task-creation**, then **shipping** — collect evidence for
  each required gate and enable mandatory publication checks once bootstrap is
  complete.

### Watch — Security tests can skip the platform property being claimed

- Evidence: `tests/seccomp_test.go:56` skips when the probe does not observe
  seccomp enforcement, with a message describing a "fail-open" case.
  `internal/runner/net_test.go:38` skips unavailable network isolation;
  `internal/runner/runner_test.go:458` and `:509` require unprivileged network
  namespaces. `mcp/key_material_guard_test.go:164–171` skips the live key-material
  probe when a native store is unavailable, hangs, or lacks the needed interface;
  its static removed-tool guard remains enforced.
- Impact: an aggregate passing suite can omit important platform proofs. The
  skip text does not establish that production seccomp currently fails open;
  the actual runner behavior and executed test coverage must be checked.
- Confidence: high for skip behavior, runtime coverage unknown.
- Next module/action: **implementation** / **shipping** — inventory skips in
  each supported platform run and require relevant security probes to execute
  on capable release-validation hosts.

## Documentation corrections already made

- `README.md` now acknowledges that `op run` masks output values.
- `docs/ARCHITECTURE.md` and `docs/RELEASE_CHECKLIST.md` now describe Linux and
  macOS as launch platforms and explicitly exclude Windows from this launch.

These corrections resolve documentation drift; they do not constitute runtime
or platform validation.

## Checks not run and why

`AGENTS.md` directs execution through `run_sealed` and requests through
`propose_command`, and says not to fall back to a raw shell for unlisted
commands. Neither tool is available here. Tests and builds are pending either
restoration of that execution path or an explicit user exception to the local
instruction. The broad launch request was not treated as an implicit waiver.

Consequently, this review has no new passing evidence for Go build/test/race/vet,
staticcheck, govulncheck, fuzzing, npm tests, package installation, installer
tamper tests, or reproducibility. Shell reads of source/configuration were used
for the audit; no credential values were requested or read.

Also unverified: live GitHub runs and release assets, npm account/bootstrap,
Homebrew tap contents, repository permissions/protection, macOS/ARM execution,
external-developer onboarding, seven-day dogfooding, and product timing gates.

## Concrete next actions

1. Restore sealed test execution or obtain the explicit local-instruction
   exception; run the required automated checks and retain their actual output.
2. Fix publication ordering and bind signatures to the requested release tag.
3. Fix npm prerelease routing, bootstrap preparation, and publish validation;
   add end-to-end launcher tests.
4. Align release date stamping with the reproducibility claim and verify the
   release build path, not only local Make builds.
5. Build a release candidate, inspect every platform artifact and signature,
   and complete fresh-install/tampering tests before publishing a stable release.
6. Complete and record the external account, platform, human, and product gates
   in `RELEASE_CHECKLIST.md`. Publish only after the evidence supports it.

## Checkpoint

- Outcome: source audit completed; launch readiness not established.
- Changes: documentation corrections above and this report; release behavior
  remains unchanged by this audit.
- Validation: source/configuration inspection only; execution pending.
- Open blockers: execution access, Critical findings, required release proofs.
- Handoff: implementation for contained repairs, shipping after proven gates.
