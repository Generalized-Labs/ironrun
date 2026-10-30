# Open-source launch readiness

Updated October 29, 2026 (America/New_York). Repository baseline: `8e3c354`;
review and repairs: [PR #16](https://github.com/Generalized-Labs/ironrun/pull/16).

**The reviewed repairs have source-bound automated evidence; real-host, native-store,
signed-installation, release, and arXiv gates remain open.** Consult each retained
source manifest and the PR's current checks before transferring a result to a new
build. Tests and bounded review do not certify security or perfect correctness.

The selected rollout is a **preview launch after readiness checks**, covering
Codex, Claude Code, OpenCode, and Cursor. The maintainer's next checks are Codex,
Claude Code, and OpenCode on Mac, followed by Cursor's desktop editor on a
supported Linux PC with a graphical session. Complete real setup, native-store,
approval, and continuation checks on each host, plus applicable signed-artifact
and installation gates,
before preview publication. Stable-release product gates remain open separately.

## Repairs completed

- Make `doctor` check local environment metadata for project identity, selection,
  expiry, and required entry names. Print recovery steps, preserve legacy
  checks, and explicitly distinguish metadata configuration from vault access.
- Preserve unreadable, malformed, and custom MCP client configuration during
  setup. Report each client's observed state without claiming a host connection.
- Display the stored workspace-request review deadline separately from the
  requested access duration, including reused requests; preserve grant semantics.
- Make approved MCP workspaces use normal network access, matching the local
  approval screen, stored grant, and CLI. The maintainer explicitly selected this
  broad development scope. Saved commands retain their own policies and optional
  command leases; workspace trust does not transfer those permissions.
- Correct generated agent instructions, CLI help, and tool descriptions to
  describe known-value/supported-encoding filtering and its limits. Arbitrary
  transformations, files, and a trusted child's network traffic can disclose
  values; `exec` is the saved-command `run` alias.
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
| Go 1.26.10 full race suite | Full uncached Linux race runs pass at their recorded source hashes; final-copy results and source identities are retained separately in the new runtime archive; namespace tests use synthetic values outside the additional filesystem sandbox |
| Vet and staticcheck | Recorded vet and pinned staticcheck 0.8.2 runs pass; inspect the final-copy archive and current PR checks for the precise build under review |
| Govulncheck 1.9.0 | Zero reachable vulnerabilities; one advisory remains in a required module outside imported/called code |
| Focused concurrency tests | Vault initialization, immutable concurrent proposals, stale approval digests, and dashboard refresh behavior pass under the race detector |
| Actual MCP race probe | Both conflicting proposals accepted in 23/30 pre-fix pairs, 0/30 after repair; illustrative executions, not a statistical security bound |
| Offline release tests | 11 pass; synthetic downloads/verifier test control flow, not Sigstore cryptography |
| npm launcher | 19 tests pass locally on Node 24 for this follow-up; prior local/CI Node 20/22/24 and packed-installation evidence remains pinned separately |
| npm proxy transport | Real TLS/CONNECT/redirect fixture passes 9 tests on Node 22/24; Node 20 passes 2 tests confirming unsupported environment-proxy opt-in fails safely |
| Historical public release | Real cosign verification passes for 6 v0.5.0 blobs; all 9 signed checksum entries match; wrong-tag and tampered-blob controls fail as expected |
| Redactor fuzz smoke | 22,581 executions pass; checks chunked/batch equivalence and existing fixed-pattern leakage invariants |
| Four-platform snapshot | October 24's two source-bound builds produce four matching binary pairs and archives/checksums/SPDX SBOMs; archive contents match but tar timestamps differ. The later snapshot archive records its own inputs and any source delta; cross-compilation is not target-platform execution |
| GoReleaser configuration | Version 2.18.2 check passes; cask generation covers all four platforms |
| Leakage comparison | Same harness and Go 1.26.10 reproduce 52/126 baseline versus 28/126 current threshold cases; accidental subset 21/72 versus 3/72 |
| Setup and deadline replay | Four noninteractive UID 1000 setup cases preserve config; one actual synthetic MCP request reports stored deadline and requested grant duration; REA limits retained |
| Citation follow-up | All 82 cited references have contextual review rows; three comparison themes corrected; this is not full-article review or external experiment replication |
| Paper and arXiv bundle | Revised 14-page PDF has five figures and four tables; fresh three-pass extracted source build has matching text; ASCII abstract is 1,815 characters. All 14 final pages received visual review |
| Fresh current-only paper diagnostics | Current leakage counts reproduce; frozen 1,209,966-byte corpus and raw outputs retained; shared-host performance medians and scanning measurements replace unsupported old timing claims |
| Workspace networking regression | Six focused race tests pass at recorded server SHA `9efac543…`: actual CLI grant, encrypted v2 vault, stdio MCP, workspace loopback delivery, strict child `DIAL_BLOCKED`, revoke and deny. Native root-key storage alone is synthetic; the 100 ms preapproval observation is bounded |
| Actual Codex host fixture | Codex CLI 0.159.2 on Linux connects to final server SHA `c585b000…`, discovers twelve tools, resumes `run_sealed` after actual local approval, and returns redacted output to the next scripted model request. The model and native-store adapter are synthetic; the isolated host tool is explicitly preapproved |

Raw results and source hashes are in [validation/2026-10-21](validation/2026-10-21/).
Earlier Go 1.26.9 experiments remain in the prior evidence and commit history.
The October 24 snapshots include SBOMs and skip signing, before hooks, and publication.
Earlier snapshots skipped SBOM generation; their records remain historical.
Cross-compilation does not prove execution on every target architecture.

Head `64308e6` passed CI, dogfood, and fuzz before this network-contract/paper
follow-up, including Linux/macOS race jobs and supported Node versions. This
historical pass does not cover later dirty files. Consult the PR's checks for
the current head after delivery. Installation source hashes, local results,
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

The [new evidence archive](validation/2026-10-26/README.md) separates the focused
network regression, final-source Codex fixture, full runtime checks, paper build,
and snapshots. The focused network run predates the last help/catalog copy pass;
its original hashes remain unchanged, with the later delta recorded separately.
The final Codex capture records unchanged before/after identities for all 182
Go/module inputs at that later source. Its successful host call is useful
integration evidence, while default onboarding, real model decisions, native
Keychain/Secret Service, Mac execution, other hosts, and human UX remain open.
The captured host binary predates a final three-message guided-demo correction;
its MCP server is unchanged, and the later copy has separate runtime checks.
The host archive records the delta without claiming another host capture.
The archive directory retains the planned validation label; original UTC run
timestamps are preserved in its records.

## Review scope

Independent source reviews covered execution/redaction, pending authorization
and its CLI/MCP/TUI callers, vault initialization and authenticated storage,
file-secret cleanup, audit verification, npm bootstrap, and release publication.
The new concurrency and runtime fixes received a second review and regression
coverage. No remaining blocker was found in those reviewed repairs. This is
bounded review; it does not prove the absence of defects elsewhere.
The workspace network repair also received independent review of authorization,
session/environment binding, strict-branch isolation, and the real child probe.

REA and Graphify were actually used; [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md)
records their provenance, outputs, and limits. The [full paper walkthrough](PAPER_WALKTHROUGH.md)
and [algorithm walkthrough](REDACTION_WALKTHROUGH.md) explain the design and proof.
The proposed [developer pilot](LAUNCH_PILOT.md) turns the remaining setup and
approval questions into observable tasks; it contains no invented user results.
The [real-host walkthrough](HOST_E2E.md) provides concrete Mac and Linux client
configuration, native-store checks, negative cases, and an unfilled result matrix.
Host tool approval and Ironrun authorization are independent; do not globally
auto-approve host tools to imitate the scripted fixture.

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
5. Confirm paper-license consent, categories/submission metadata, final publication
   source, and final artifact identities. Unsupported historical audit totals and timing claims
   have been removed; current-only diagnostics and current regression case
   studies replace them, with explicit limits. See [PAPER_REVIEW.md](PAPER_REVIEW.md)
   and [ARXIV.md](../paper/ARXIV.md). The maintainer confirmed author order as
   Stephen Keehn, Mihir Gupta; unconfirmed affiliations are omitted. All-author
   agreement to the proposed CC BY 4.0 license remains pending. Component-level
   disclosure, tail/delivery latency, and actual developer usability remain
   research opportunities.

This PR creates no release tag, registry package, external tap change, or arXiv
submission. Reverting the PR restores the previous source; no data migration has
been performed. The original audit and interim findings remain available in
[the first review commit](https://github.com/Generalized-Labs/ironrun/blob/9794795e0f4de675d452d5769718ef0c14491e87/docs/LAUNCH_READINESS.md).

The research report and companion article can receive a separate Cloudflare
preview with accurate draft/evidence labels. Integrate them into ironrun.dev only
after the runtime readiness decision. A designed page does not close release gates.
