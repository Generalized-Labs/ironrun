# Runtime checks and final demo-copy follow-up

The latest [demo-copy follow-up](demo-copy-followup/README.md) passes a fresh
uncached full Go race suite, vet, Staticcheck and diagnostic CLI build after
three guided-demo strings were corrected. Its compiled-copy and help/version
smoke also passes. Final `cmd/ironrun/init.go` SHA-256 is
`ccf08e39b4ceb7cc80aa2657b6d280b999738704caa1ad9bdf8981c2ea2d9d0a`.
The separately recorded README change narrows the diagram to registered matches.
An archived overlay was made inert before that successful rerun; the initial
packaging failure remains recorded in the follow-up.

The original five phases below passed against the preceding hash-listed,
uncommitted Go/module source based on `64308e6`, before those demo-copy strings.
Their records retain their original source identities. The unchanged
`mcp/server.go` SHA-256 is
`c585b0004ea56fa2de402987269ed1caa0446795b19648dab2caaa47dc0464d2`.
The archive folder preserves the original October 26 session label; this fresh
rerun occurred October 30 UTC, as recorded in the result JSON files.

| Earlier final-copy phase | Observed result |
| --- | --- |
| `go test -race -count=1 ./...` | Exit 0, uncached; includes the MCP loopback/approval/revocation regression |
| `go vet ./...` | Exit 0, empty output |
| Pinned Staticcheck 0.8.2 `./...` | Exit 0, empty output |
| Python release regressions | Exit 0, 11 tests |
| Node 24.19.0 launcher regressions | Exit 0, 19 pass / 0 fail / 0 skip |

`summary.json` and the per-phase records retain argv, working directories, actual
UTC timestamps, exit codes and raw-log hashes. All 182 Go/module inputs matched
before and after every phase; `source-before.json` and `source-after.json` match.
`verification-inputs.json` identifies the 204 current Go/module, npm, installer,
release and workflow inputs captured after the checks. It does not claim a
separate before-phase observation for non-Go files. `copy-followup-delta.json`
identifies the four inputs changed after the preceding local check; the earlier
9efac543 source records were not relabeled as this final source.

The earlier host, snapshot and Graphify captures also precede the final guided-
demo copy correction. Their source/binary hashes are preserved. The new
[two-path delta](demo-copy-followup/source-delta.json) records the three print
strings and README diagram line; it does not claim a new host/model capture,
four-platform snapshot or graph extraction. Release/Node inputs remain unchanged
from the original passing phases and those suites were not repeated.

The race suite ran outside the additional agent filesystem sandbox so real
namespace checks could execute. Ironrun containment remained enabled. Test data
was synthetic, with no project credentials. The new MCP integration uses a
synthetic platform root-key adapter and local loopback service. This suite does
not establish native Secret Service/Keychain, external providers, real model
judgment, human approvals or macOS runtime behavior. Nonverbose Go output does
not enumerate platform skips; skips are not positive evidence.

Node 20/22, proxy tests and signed installation were not repeated locally. The
installer unit tests use a fixture verifier rather than future release
signatures. Build VCS metadata was disabled for this worktree; exact source
hashes identify the reviewed code. Durations are diagnostics, not product
latency benchmarks. No production source was edited by this verification.

`run_checks.py` is the external driver and its absolute workspace/tool paths need
adaptation elsewhere. Only non-secret environment constants are retained.
`tool-identities.json` binds actual tool versions and executable digests.
Caches, state and production credentials are absent from this compact archive.
`artifact-manifest.json` hashes selected retained files and excludes itself.
