# Approved workspace networking regression

These retained records diagnose and repair a contradiction: the stored workspace
grant, local approval screen and CLI promised normal network access, but the MCP
execution path omitted the corresponding option. The maintainer explicitly chose
normal networking for approved workspaces, with saved commands keeping their own
policies. The fix sets that option only after workspace authorization.

The red/green Linux regression uses the actual built Ironrun CLI, stdio MCP, v2
encrypted vault, child runner and loopback HTTP endpoint. Only native root-key
storage is replaced by a synthetic `secret-tool` adapter. Actual CLI actions grant,
revoke and deny access. The final focused race run passes six tests. The workspace
child reaches loopback and its output is redacted; the strict child actually starts
and emits `DIAL_BLOCKED`, with no endpoint request. Revoke followed by a fresh
denied request does not execute another loopback call. The 100 ms preapproval
observation is bounded regression evidence, not a latency or authorization proof.

`final-summary.json` and the original logs are preserved byte for byte from their
measured phase at server SHA `9efac543…`. `source-comparison.json` records the later
server copy change to `c585b000…`; it does not transfer the old test result to new
bytes. The final full suite is recorded separately in [runtime](../runtime/), and
the later actual [Codex host fixture](../codex-host/README.md) uses the final source.
No native Keychain/Secret Service, real model, human session, external service,
installation route or macOS execution is established by this regression.

`READINESS_AUDIT.md` is chronological: its early conflicting/pending findings are
followed by the explicit decision and observed resolution. Initial failed
filesystem-sandbox attempts are retained separately from the behavioral red
result, in which the child actually attempted loopback. Removing the additional
agent filesystem sandbox did not disable Ironrun containment. The overlay path
in the initial seam record is the original local absolute path; adapt that path
if replaying from this archive. The retained test overlay is named
`server_internal_overlay_test.go.txt` so `go test ./...` does not compile the
archive as a Go package. Point the replay overlay replacement at this file;
its bytes are unchanged. `archive-path-map.json` maps the historical `.go`
filename to its archive filename.

`original-artifact-manifest.json` verifies the unchanged original records using
that explicit filename map. Historical command JSON and the original overlay
JSON keep their actual absolute paths rather than being rewritten. The
new `artifact-manifest.json` covers this compact archive, excluding itself and
state/cache directories.
