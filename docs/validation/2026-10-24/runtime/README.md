# Runtime repair verification, October 24

These records cover the setup-preservation and workspace-request-message repairs
in the working tree based on `bccf7547280804c8cef915a3510b099c99e38cfd`.
The base commit does **not** contain these repairs. `source-manifest.json` hashes
202 selected source/configuration files, including the new registration helper
and its tests. The final PR commit should be used together with these hashes.

All recorded commands used synthetic fixtures and no project credentials. The
full Go run used Go 1.26.10 on Linux amd64, with `GITHUB_ACTIONS=false` and
`GOFLAGS=-buildvcs=false`. Namespace-dependent tests ran outside the additional
filesystem sandbox. Host proxy/CA settings were preserved. `results.json`
distinguishes the supervising process exit observations from the raw log text;
the log files themselves do not contain shell exit-status markers.

| Record | Observed result |
| --- | --- |
| `final-race.log` | `go test -race -count=1 ./...`, exit 0, all packages pass |
| `final-vet.log` | `go vet ./...`, exit 0 with no output |
| `release-regressions.log` | `python3 -m unittest discover -s tests -p release_test.py -v`, exit 0, 11 tests |
| `npm-node24.log` | `node --test test/*.test.js` from `npm/`, Node 24.19.0, exit 0, 19 pass / 0 fail / 0 skip |
| `setup-red.log` | Expected exit 1 before the setup repair; preservation and misleading-summary regressions fail |
| `setup-record-shape-red.log` | Expected exit 1 before malformed Codex list records were handled conservatively |
| `setup-json-transport-red.log` | Expected exit 1 before mixed remote/local configuration was classified conservatively |
| `setup-green-race.log` | Focused setup command/integration packages pass under the race detector, exit 0 |
| `workspace-deadline-red.log` | Expected exit 1: response incorrectly reports requested grant duration as request expiry |
| `workspace-deadline-green-race.log` | Focused MCP/access tests pass under the race detector, exit 0 |

The focused command filters were not embedded in these logs, so no exact filter
is reconstructed. The new tests and their final source are identified by the
source manifest. The full uncached race run separately covers the final Go tree.

The setup repair preserves unreadable, malformed, custom, disabled, and remote
client configurations rather than treating them as absent; Codex inspection
failure cannot authorize an automatic registration write. Its summary reports
configuration state and explicitly says host connections were not checked.
The MCP repair reports the persisted review deadline separately from the
requested access duration, including when a pending request is reused; it does
not change authorization or expiry semantics.

The permission-sensitive Go fixture skips when run as root. The raw nonverbose
race logs do not enumerate individual skips. The separate REA evidence exercises
the write-only configuration fixture as UID 1000; a root-only test pass would not
establish that behavior. A preceding test-fixture umask mismatch was corrected
with explicit `chmod`; its diagnostic remains outside this compact archive and
is not represented as a product failure or a successful verification run.

Offline release tests use synthetic downloads and a fixture verifier; they do
not validate real Sigstore cryptography or a future release. These Linux and
Node 24 results do not establish macOS, other architectures, Node 20/22, actual
agent-host connections, native secure-storage availability, or usability.
Historical checks and new-head GitHub CI must retain their own source identities.

`artifact-manifest.json` inventories every file in this directory except itself.
Raw logs are copied byte-for-byte, including their original whitespace.
