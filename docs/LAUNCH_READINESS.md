# Open-source launch readiness

Updated October 24, 2026 (America/New_York). Repository baseline: `8e3c354`;
review and repairs: [PR #16](https://github.com/Generalized-Labs/ironrun/pull/16).

**Automated local checks pass. The changes are ready for pull-request review;
release and arXiv submission still have the evidence gates listed below.** Tests
and bounded source review do not establish perfect correctness or certify security.

The selected rollout is a **preview launch after readiness checks**, covering
Codex, Claude Code, and Cursor. Complete real setup, approval, and continuation
checks on each host, plus applicable signed-artifact and installation gates,
before preview publication. Stable-release product gates remain open separately.

## Repairs completed

- Make `doctor` check local environment metadata for project identity, selection,
  expiry, and required entry names. Print recovery steps, preserve legacy
  checks, and explicitly distinguish metadata configuration from vault access.
- Preserve unreadable, malformed, and custom MCP client configuration during
  setup. Report each client's observed state without claiming a host connection.
- Display the stored workspace-request review deadline separately from the
  requested access duration, including reused requests; preserve grant semantics.
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
| Vet and staticcheck | Vet passes; pinned staticcheck 0.8.2 passes locally after two error-message wording corrections required by CI; inspect the PR for new-head remote results |
| Govulncheck 1.9.0 | Zero reachable vulnerabilities; one advisory remains in a required module outside imported/called code |
| Focused concurrency tests | Vault initialization, immutable concurrent proposals, stale approval digests, and dashboard refresh behavior pass under the race detector |
| Actual MCP race probe | Both conflicting proposals accepted in 23/30 pre-fix pairs, 0/30 after repair; illustrative executions, not a statistical security bound |
| Offline release tests | 11 pass; synthetic downloads/verifier test control flow, not Sigstore cryptography |
| npm launcher | 19 tests pass locally on Node 24 for this follow-up; prior local/CI Node 20/22/24 and packed-installation evidence remains pinned separately |
| npm proxy transport | Real TLS/CONNECT/redirect fixture passes 9 tests on Node 22/24; Node 20 passes 2 tests confirming unsupported environment-proxy opt-in fails safely |
| Historical public release | Real cosign verification passes for 6 v0.5.0 blobs; all 9 signed checksum entries match; wrong-tag and tampered-blob controls fail as expected |
| Redactor fuzz smoke | 22,581 executions pass; checks chunked/batch equivalence and existing fixed-pattern leakage invariants |
| Four-platform snapshot | Two builds produce four matching binary pairs, archives, checksums and SPDX SBOMs; archive contents match but tar timestamps differ; Linux amd64 help/version smoke passes |
| GoReleaser configuration | Version 2.18.2 check passes; cask generation covers all four platforms |
| Leakage comparison | Same harness and Go 1.26.10 reproduce 52/126 baseline versus 28/126 current threshold cases; accidental subset 21/72 versus 3/72 |
| Setup and deadline replay | Four noninteractive UID 1000 setup cases preserve config; one actual synthetic MCP request reports stored deadline and requested grant duration; REA limits retained |
| Citation follow-up | All 82 cited references have contextual review rows; three comparison themes corrected; this is not full-article review or external experiment replication |
| Paper and arXiv bundle | Revised 14-page PDF and three-pass extracted source build have matching text; ASCII abstract is 1,815 characters |
| Fresh current-only paper diagnostics | Current leakage counts reproduce; frozen 1,209,966-byte corpus and raw outputs retained; shared-host performance medians and scanning measurements replace unsupported old timing claims |

Raw results and source hashes are in [validation/2026-10-21](validation/2026-10-21/).
Earlier Go 1.26.9 experiments remain in the prior evidence and commit history.
The October 24 snapshots include SBOMs and skip signing, before hooks, and publication.
Earlier snapshots skipped SBOM generation; their records remain historical.
Cross-compilation does not prove execution on every target architecture.

Head `bccf754` passed every GitHub CI, dogfood, and fuzz job, including Go
1.26.10 on Linux/macOS and the npm proxy fixture. Consult the PR's checks for
the current head after later paper/documentation edits. Installation source hashes, local results,
and historical-release evidence are in
[install-followup](validation/2026-10-21/install-followup/README.md).
Earlier source-hash manifests remain records of their original measured trees.
The later [source follow-up](validation/2026-10-21/source-followup/README.md)
refreshes Graphify/REA and corrects the paper's closest-system comparison using
primary sources; it does not change runtime source.
The [fresh experiment archive](validation/2026-10-22/fresh-pilot/README.md)
pins the measured runtime to `a4ab72e`, freezes inputs, and separates failed and
successful performance attempts. The [product review](PRODUCT_REVIEW.md) records
the approved doctor scope and the next setup/approval candidates.
The [October 23 verification records](validation/2026-10-23/product-followup/README.md)
retain doctor red/green regressions, the final uncached race suite and vet,
REA before/after captures, and the revised paper/source-bundle checks.
The [October 24 evidence](validation/2026-10-24/README.md) records the new setup
and deadline regressions, full race/vet and release tests, REA captures, two
four-platform snapshots with SBOMs, final manuscript checks, and citation
resolutions. Source hashes bind dirty tested files rather than relying on the
embedded base commit. Snapshot archives include their recorded inputs, which
precede the final documentation corrections and two setup-error wording edits;
the CI follow-up records that small source difference explicitly.

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
The proposed [developer pilot](LAUNCH_PILOT.md) turns the remaining setup and
approval questions into observable tasks; it contains no invented user results.

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
5. Confirm authorship, license, metadata, final publication source, and final
   artifact identities. Unsupported historical audit totals and timing claims
   have been removed; current-only diagnostics and current regression case
   studies replace them, with explicit limits. See [PAPER_REVIEW.md](PAPER_REVIEW.md)
   and [ARXIV.md](../paper/ARXIV.md). Component-level disclosure, tail/delivery
   latency, and actual developer usability remain research opportunities.

This PR creates no release tag, registry package, external tap change, or arXiv
submission. Reverting the PR restores the previous source; no data migration has
been performed. The original audit and interim findings remain available in
[the first review commit](https://github.com/Generalized-Labs/ironrun/blob/9794795e0f4de675d452d5769718ef0c14491e87/docs/LAUNCH_READINESS.md).
