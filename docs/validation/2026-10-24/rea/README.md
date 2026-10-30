# Fixed setup and workspace-deadline REA evidence

REA 6.7.0 captured four synthetic noninteractive setup scenarios and one fresh MCP request. Every observed process exited 0 and settled as quiesced. All setup product processes ran as UID 1000. The driver assertions bind the Ironrun diagnostic binary SHA256 separately from REA's selected Python executable identity.

The malformed JSON and stale registration cases preserve existing client config bytes and permissions and report repair or inspection steps. The missing Codex CLI case reports unavailability while writing the other synthetic client configs. The write-only mode 0200 case reports permission errors and preserves both client configs. Setup still exits 0 for optional-client issues; its final summary explicitly says host connections were not checked.

The fresh MCP response reports the stored pending-review deadline (15 minutes after creation) separately from the requested grant duration (2 hours if approved). Its driver checks that the response deadline matches persisted expiry at RFC3339 second precision.

Start with `summary.json`, `preservation-results.json`, and `mcp/workspace-expiry.result.json`. The raw `*.capture.json` files retain REA's limitations and truncation fields. `artifact-manifest.json` hashes the selected compact evidence files; `runtime-source-sha256.json` hashes all 180 current Go/module source files, including the uncommitted fixes. The base commit alone does not identify this dirty source snapshot.

REA could not hash the write-only configs and marks both filesystem snapshots truncated with EACCES omissions. Byte preservation for those two files is established by separate post-capture inspection: temporarily add owner-read, hash against fixture identities, then restore 0200. That inspection is outside REA. Snapshot agreement does not rule out transient writes. Process samples can omit short-lived children. There is no network trace, actual agent-host MCP connection, TUI/native-store flow, model invocation, or human usability result here.

The wrappers use synthetic HOME/PATH/IRONRUN_HOME/XDG directories; no project credentials or real client configs are used. The product receives an explicit synthetic environment, while REA itself labels ambient inherited variables unknown. The selected executable and separately asserted Ironrun digests are prelaunch file samples, not atomic OS image attestations.

Earlier local reproductions are in `/workspace/ironrun-product-research/launch-flow-audit2`. They are historical before evidence, not a formal cross-binary equivalence claim. The first MCP capture (without the added digest assertion) remains locally under `mcp-initial-capture`; only the final top-level MCP capture is included in this compact manifest. Fixture directories and diagnostic binaries remain outside the compact evidence set.
