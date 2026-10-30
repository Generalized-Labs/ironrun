# Final guided-demo copy follow-up

The final current source passes a fresh uncached `go test -race -count=1 ./...`,
`go vet ./...`, pinned Staticcheck 0.8.2 and a diagnostic CLI build. Source
`cmd/ironrun/init.go` is
`ccf08e39b4ceb7cc80aa2657b6d280b999738704caa1ad9bdf8981c2ea2d9d0a`;
`mcp/server.go` remains `c585b000…`. All 182 Go/module files and README.md were
unchanged across each successful phase. The source manifests match exactly.

`source-delta.json` and `copy-only.diff` preserve the only later implementation
change: three guided-demo print strings now describe private temporary files,
registered output filtering and possible disclosure through other channels.
The README diagram separately says registered matches. Exact string-replacement
assertions confirmed no other bytes changed in these two files. Other Go/module
files match the preceding suite. Previous release/Node inputs are unchanged,
so the earlier 11 release and 19 Node 24 passing tests remain separately recorded;
those suites were not rerun for this copy correction.

The rebuilt diagnostic binary contains all three corrected literals and none
of the three replaced universal claims. Its `--help` and `version` commands
pass with isolated empty application state. This checks compiled copy and CLI
startup, not the guided demo's vault execution or native secure storage.
`compiled-copy-smoke.json` binds the binary digest and observations. No binary
is duplicated in this archive.

The initial broad check found an archived overlay named `.go`, which Go treated
as a package with undefined MCP-internal symbols. Its owner renamed the exact
bytes to `.go.txt` and recorded the mapping. `packaging-failure/` retains that
negative result; the green rerun above occurred after repair. No implementation
or runtime test was modified to resolve that packaging failure. An initial
incorrect `--version` probe is retained under `probe-notes/`; this CLI uses the
`version` subcommand documented in help.

Earlier host, snapshot and Graphify records retain their original source and
binary identities. They precede the three demo-copy literals and README line;
no new host/model capture, four-target snapshot or graph regeneration is
claimed here. The prior source deltas within those archives also remain intact.

Actual commands ran October 30 UTC under the original October 26 session-label
folder. The race suite ran outside the additional agent filesystem sandbox;
Ironrun containment stayed enabled. Data was synthetic and credential-free.
Platform skips are not positive evidence, and native Keychain/Secret Service,
Mac/other-host workflows, human usability and signed installation remain open
launch gates. Tool identities are copied from the same pinned executables used
for these commands. The manifest excludes itself, caches, state and binaries.
