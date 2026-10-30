# Historical before-state observations

These retained synthetic observations precede the setup/deadline repairs.
`probe.py` invokes the earlier diagnostic binary at its recorded local path.
The raw results show setup exit0 despite optional client failures or stale
configuration, overwrite of unreadable-but-writable mode0200 configuration,
and a workspace response describing two hours while stored pending expiry is
fifteen minutes. One REA setup capture is retained alongside these probes.

These are historical observations, not a formally equivalent scenario replay
against two atomically bound runtime images. The later wrappers and fixture
records differ and add binary SHA assertions. Do not infer code identity from
a local filename or treat filesystem snapshots as transient-write tracing.
No actual host configuration, project credentials, or model invocation was used.

`codex-native-fixture/results.json` separately records Codex CLI0.159.2 structured
list/add/get behavior in an isolated synthetic CODEX_HOME. It informs the JSON
parser shape; it does not establish a live agent-host MCP connection.
