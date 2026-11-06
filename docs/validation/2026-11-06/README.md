# Launch verification checkpoint

Updated November 6, 2026 (America/New_York). Raw evidence retains its original
UTC timestamps, including executions on November 5 in the client's time zone.
This index updates readiness facts without changing the tested runtime candidate:
`b5b0059fc088745296999ad84f5b0726a631f85f`, tree
`ff248424f675a9f41969afe6ebec74c3cdf34185`.

The results below are bounded checks. They do not certify production readiness,
universal non-disclosure, real-model judgment, human usability, or signed
installation. No new release tag, npm package, tap migration, arXiv submission,
agent-created Vercel deployment, or production promotion resulted from them.

## Merged source and actual native stores

- [PR #17](https://github.com/Generalized-Labs/ironrun/pull/17) merged as
  `829099e4bb46247dc7abd324f18e870b6eb2cd9f`. Its actual native macOS Keychain
  [CI job](https://github.com/Generalized-Labs/ironrun/actions/runs/41966109469/job/127043373202)
  passed at reviewed head `a1c4949d74fbc86469b1aaae1b975795dee9c461`: root-key
  persistence, encrypted synthetic entry, two fresh CLI processes receiving the
  value and filtering stdout/stderr, a negative child control, and restoration
  of original preference metadata/deletion of the dedicated test Keychain.
  This is a disposable-account saved-command CLI fixture. It must not be run on
  the maintainer's primary Mac account and does not replace a human host pilot.
- [PR #18](https://github.com/Generalized-Labs/ironrun/pull/18) merged as the
  tested `b5b0059` candidate after all 16 substantive checks passed at head
  `ad590d609f110a20c24ba33bc1c0e8daa8ebc0e2`. Linux/macOS race suites, actual
  macOS Keychain, lint, vulnerability/output-filter checks, CodeQL and supported
  Node launcher checks passed. Optional Macroscope skipped; Graphify correctly
  reported no changed supported-language program code to verify.
- [Module normalization](module-normalization.json) records why the correction
  was necessary: the real release hooks previously changed a clean checkout's
  module files. Normalization preserves all 180 Go source files, 106 selected
  module versions, and the byte-identical 444-line requirement graph. A second
  tidy, generation, module verification, vet and an uncached race run pass.
  The selected dependency graph is unchanged; this is not a new paper experiment.

## Clean diagnostic release build

[Clean release verification](clean-release-verification.json) records a new
GoReleaser 2.18.2 snapshot from the exact clean `b5b0059` worktree using
Go 1.26.10 and Syft 1.55.0. Both actual hooks, `go mod tidy` and
`go generate ./...`, ran. All tracked bytes and modes, HEAD/tree, and complete
clean status remained unchanged.

All four Linux/macOS amd64/arm64 archives have the expected regular-file layout
and source-document bytes. Four SPDX 2.3 SBOMs bind to their archive SHA-256
values. All nine checksum entries match: four archives, four SBOMs and the
installer source. The extracted Linux amd64 binary's version/help and every
binary's Go build/module metadata were inspected. Cross-compilation is not
native macOS or ARM execution.

| Identity | SHA-256 |
| --- | --- |
| Linux amd64 diagnostic archive | `f6f3587ae42706dbd6ef70a10b99bf08cac974ad5ccb68a5e709e568b7a9fa83` |
| Its extracted/tested Linux binary | `1f5457786ccdc5aab009a143841486f28bc809d5c8b843bab2d30e68926d4ad0` |

An independent build with an initially empty Go cache, the same Go 1.26.10
toolchain, and exact source-derived release flags reproduced those Linux binary
bytes. This confirms native Linux amd64 binary reproducibility for those inputs;
it does not establish gzip archive-byte reproducibility, other platforms or
toolchains, signatures, or clean signed installation.

The version is `0.5.1-rc.1-diagnostic`. Snapshot signing and publication were
skipped. This is not a real `v0.5.1-rc.1` tag or public RC. This documentation
change does not retarget the candidate or assign a later build these outcomes.

## Two distinct Linux host evidence sets

| Package | Actual host observations | Identity and limits |
| --- | --- | --- |
| [Linux lifecycle fixtures](linux-host-fixtures.tar.gz) | Claude Code 2.1.318 and OpenCode 1.19.5 each pass approval/resume, denial, real short-grant expiry, revocation and bounded pending SIGINT: ten cases total, using native Linux Secret Service | Earlier diagnostic binary `809e6fe0ee5335ce26b09fb9153a28c74966a8789620d94167e1e20bc6e1c612`; all 182 recorded Go/module inputs match `829099e`. These outcomes are not transferred to the new candidate binary |
| [Clean candidate host smokes](clean-host-smoke.tar.gz) | Both actual hosts pass one fresh approval/resume each with native Linux Secret Service: two cases total | Exact `b5b0059` diagnostic archive member and Linux binary hash above; this set does not repeat or inherit the older ten-case lifecycle matrix |

Both sets use isolated homes/projects/DBus sessions, random synthetic values,
local scripted model providers, explicit permission for one Ironrun host tool,
and controller-issued actual CLI approvals. A matching loopback credential and
redacted tool output reaching a subsequent provider request are observed in the
approval cases. A host exit code or final model sentence alone is insufficient.
No real-provider account, default interactive host permission UX, human timing,
Mac host, signed installation, or uninstrumented background traffic is validated.

The bounded SIGINT case interrupts the isolated host/MCP process group while
awaiting approval. No grant or probe HTTP request was observed before exit;
there is no independent child-start sentinel. This is not proof of a GUI cancel
button, MCP cancellation notification, running-child termination, or persisted
request denial. Short grant expiry is separate from the default 15-minute
request deadline, which these cases do not wait out.

The earlier package retains setup failures and result-predicate corrections,
including OpenCode directory selection, native control-socket path length and
Claude's structured abort despite process exit zero. Its manifest verifies
96 selected entries. The new package verifies 22 selected entries. Raw built-in
host instructions, full provider bodies, native stores, caches, authentication
state, and binaries are excluded. Selected driver/provenance hashes remain
available for replay.

| Compact package | SHA-256 |
| --- | --- |
| `linux-host-fixtures.tar.gz` | `a7d4631e38e9f4050af96ae847ebbafd0284787b65b6e290f87857aaaee19b08` |
| `clean-host-smoke.tar.gz` | `b52c19b509040189b06e1cb749d43a8626a35f8fec29e539d65005b96ac0bb5e` |

Earlier actual Codex CLI evidence retains its synthetic native-store-adapter
limitation; it does not acquire the other hosts' native Secret Service outcome.
Cursor's official Linux package endpoint returned HTTP 403/Cloudflare 1010 on
the retained recheck, and the fixture lacks a running GUI/authorized desktop
session. No Cursor execution is claimed. These are observed fixture blockers,
not a claim that Cursor cannot run on a supported Linux desktop.

## Website, paper and remaining decisions

Site [draft PR #2](https://github.com/Generalized-Labs/ironrun-site/pull/2) head
`7bd0fbab16287d1464b75fcd3194997dc9100e92`, tree
`30fa45e012642cf3d95b5b6a79be59744aae3a07`, has an explicit 33-file public-output
build and passing local static/Chromium checks. Actual Vercel edge routes,
headers, protected-preview access, downloads and mobile behavior remain
unverified. Project inspection returns 403 pending team-access consent;
independently, the PR's Vercel status reports the Hobby/private-organization
deployment restriction. A consent link alone does not resolve that reported
plan restriction; inspect the current team/project after access is restored.
No billing, repository visibility, project ownership or DNS change is implied.

The checked draft paper remains attributed to Stephen Keehn then Mihir Gupta,
with PDF SHA-256
`586bd7765db2af3e3bf42a6bf6657cefcebe8b7d8cde2327d8ddb0d38db51208`.
Historical measured identities and known-match/output-channel limitations remain
explicit. This module/documentation follow-up does not create a new experiment
cohort. Author license assent and arXiv account/category/submission decisions
remain separate from runtime release.

Next complete the [human Mac/Cursor host matrix](../../HOST_E2E.md), real
signed-release clean installations and channel checks in
[launch readiness](../../LAUNCH_READINESS.md), and the actual pinned Vercel
preview before site promotion. Preserve the
[stable-release pilot gates](../../LAUNCH_PILOT.md), including the external
cohort and dogfood requirements; the selected rollout remains preview, not
stable.
