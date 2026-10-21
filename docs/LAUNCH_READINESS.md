# Open-source launch readiness

Updated October 21, 2026 (America/New_York). Repository baseline: `8e3c354`;
review and repairs: [PR #16](https://github.com/Generalized-Labs/ironrun/pull/16).

**Automated local checks pass. The changes are ready for pull-request review;
release and arXiv submission still have the evidence gates listed below.** Tests
and bounded source review do not establish perfect correctness or certify security.

## Repairs completed

- Resolve explicit relative executables from the effective child directory.
- Preserve errors from final stdout/stderr redaction flushes while flushing both
  streams and completing temporary-secret cleanup.
- Bound whitespace-gap scanning to the match span, removing a quadratic path.
- Serialize first-time vault key initialization with a kernel lock, preventing
  competing root-key writes from making committed vault data unreadable.
- Make pending proposals immutable and transactional across processes. Approval
  checks the reviewed content digest; dashboard refreshes preserve the reviewed
  item or cancel confirmation when its contents change.
- Preserve child signals in the npm launcher, including termination during
  native-process startup; reject invalid release manifests before npm publication
  and validate archive and extracted-binary hashes.
- Bind installer/Action signatures to the requested release tag, including
  hyphenated prereleases. Keep GitHub releases draft until signing and
  verification finish; route prerelease npm packages to `next`.
- Replace deprecated GoReleaser formulas with supported Homebrew casks, retaining
  versioned branches and draft tap PRs. `goreleaser check` now exits zero.
- Require Go 1.26.10 to address the reachable standard-library advisory
  [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809). Vulnerability scanning now
  blocks CI instead of suppressing failures.
- Reject failed evaluation children and missing output sentinels. Correct the
  paper's proof, threat claims, signature-verification description, and citations.
  Repair fresh-checkout arXiv source packaging.

## Verification observed

| Check | Result and scope |
| --- | --- |
| Go 1.26.10 full race suite | All packages pass on Linux amd64; namespace tests ran outside the filesystem sandbox with synthetic values |
| Vet and staticcheck | Pass |
| Govulncheck 1.9.0 | Zero reachable vulnerabilities; one advisory remains in a required module outside imported/called code |
| Focused concurrency tests | Vault initialization, immutable concurrent proposals, stale approval digests, and dashboard refresh behavior pass under the race detector |
| Actual MCP race probe | Both conflicting proposals accepted in 23/30 pre-fix pairs, 0/30 after repair; illustrative executions, not a statistical security bound |
| Offline release tests | 11 pass; synthetic downloads/verifier test control flow, not Sigstore cryptography |
| npm launcher | 19 tests pass locally on Node 20/22/24, including startup termination and real read-only cache permissions; prior 13-test suite and packed installation passed GitHub CI at `87a53b9` |
| npm proxy transport | Real TLS/CONNECT/redirect fixture passes 9 tests on Node 22/24; Node 20 passes 2 tests confirming unsupported environment-proxy opt-in fails safely |
| Historical public release | Real cosign verification passes for 6 v0.5.0 blobs; all 9 signed checksum entries match; wrong-tag and tampered-blob controls fail as expected |
| Redactor fuzz smoke | 22,581 executions pass; checks chunked/batch equivalence and existing fixed-pattern leakage invariants |
| Four-platform snapshot | Linux/macOS amd64/arm64 archives build, archive checksums and cask mappings verify, Linux amd64 binary runs |
| GoReleaser configuration | Version 2.18.2 check passes; cask generation covers all four platforms |
| Leakage comparison | Same harness and Go 1.26.10 reproduce 52/126 baseline versus 28/126 current threshold cases; accidental subset 21/72 versus 3/72 |
| Paper and arXiv bundle | 14-page PDF builds; extracted source bundle compiles; ASCII abstract is 1,905 characters |

Raw results and source hashes are in [validation/2026-10-21](validation/2026-10-21/).
Earlier Go 1.26.9 experiments remain in the prior evidence and commit history.
Local snapshots skipped signing, SBOM generation, before hooks, and publication.
Cross-compilation does not prove execution on every target architecture.

Head `87a53b9` passed every GitHub CI, dogfood, and fuzz job, including Go
1.26.10 on Linux/macOS. The installation follow-up changes must pass CI again;
consult the PR's checks for current status. Their source hashes, local results,
and historical-release evidence are in
[install-followup](validation/2026-10-21/install-followup/README.md).
Earlier source-hash manifests remain records of their original measured trees.

## Review scope

Independent source reviews covered execution/redaction, pending authorization
and its CLI/MCP/TUI callers, vault initialization and authenticated storage,
file-secret cleanup, audit verification, npm bootstrap, and release publication.
The new concurrency and runtime fixes received a second review and regression
coverage. No remaining blocker was found in those reviewed repairs. This is
bounded review; it does not prove the absence of defects elsewhere.

REA and Graphify were actually used; [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md)
records their provenance, outputs, and limits. The [full paper walkthrough](PAPER_WALKTHROUGH.md)
and [algorithm walkthrough](REDACTION_WALKTHROUGH.md) explain the design and proof.

## Gates before release or submission

1. Build the tagged final source, generate its SBOM, sign actual assets, and
   verify the real Sigstore bundles and downloads. Fixture verifiers are not
   sufficient evidence for this gate.
2. Complete npm registry/account bootstrap and verify the prepared manifest and
   final published package. The checked-in bootstrap manifest intentionally
   refuses publication until generated from actual matching release archives.
3. Follow [HOMEBREW_MIGRATION.md](HOMEBREW_MIGRATION.md). Verify actual clean
   installation and formula-to-cask upgrade on Linux and macOS before merging
   the tap change. Apple signing/Gatekeeper behavior must be tested; Sigstore
   does not supply Apple notarization. No quarantine bypass is configured.
4. Exercise remaining target architectures and installation environments beyond
   the tested Node proxy and directory-permission cases. See
   [NPM_RUNTIME_SUPPORT.md](NPM_RUNTIME_SUPPORT.md) for Node 20 proxy limitations
   and the read-only filesystem scope. Complete the external-user/product checks in
   [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
5. Supply or reproduce the historical self-audit, performance, false-positive,
   and RQ4 evidence before presenting those claims as validated arXiv results.
   See [PAPER_REVIEW.md](PAPER_REVIEW.md) and [ARXIV.md](../paper/ARXIV.md).

This PR creates no release tag, registry package, external tap change, or arXiv
submission. Reverting the PR restores the previous source; no data migration has
been performed. The original audit and interim findings remain available in
[the first review commit](https://github.com/Generalized-Labs/ironrun/blob/9794795e0f4de675d452d5769718ef0c14491e87/docs/LAUNCH_READINESS.md).
