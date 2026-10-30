# Actual Codex host-to-Ironrun local fixture

The final capture passes with the actual installed Codex CLI 0.159.2 on Linux
amd64. Codex connects to Ironrun over stdio MCP, discovers its twelve tools,
executes `run_sealed`, and supplies its returned redacted output to a second
model request. The model service is a scripted Responses/SSE fixture bound to
127.0.0.1; no real model, provider account, or API credential is used.

The actual path exercised is:

1. Compile the reviewed Ironrun binary and the test-only `secret-tool` adapter.
2. Use actual Ironrun CLI `env init`, `env set --from-stdin --unsafe` with a
   synthetic fixture, and `doctor` in an isolated project.
3. Start actual Codex with an isolated HOME/CODEX_HOME/XDG configuration, a local
   model provider, and the actual Ironrun stdio MCP server.
4. The scripted model requests `run_sealed` through the discovered MCP namespace.
5. Observe a persisted pending workspace request and no loopback request during
   a 100 ms observation window, then approve using actual `ironrun trust grant`.
6. The original waiting MCP call resumes. Its child sends the configured
   synthetic value in a local HTTP header. The test controller verifies the
   received header value. The child and endpoint print that value, and Codex
   receives `credential=[REDACTED]` and `LOOPBACK_RESPONSE [REDACTED]`.
7. The next scripted model request contains that redacted tool output and no
   complete synthetic value. Codex completes with process exit 0.

The HTTP endpoint records credential delivery; this is not authentication to a
real external service. The fixture is not a model-behavior or human-usability
study. Only the platform root-key provider is replaced: the synthetic adapter
stores the fixture root key in the isolated test directory, while environment
values use the actual Ironrun v2 encrypted vault. It does not validate macOS
Keychain or Linux Secret Service.

## The two approval boundaries

The successful capture explicitly sets the one isolated fixture MCP server's
`default_tools_approval_mode` to `approve`. Ironrun still requires its own
workspace grant, supplied separately by the test controller through the CLI.
This host setting is test configuration, not a recommendation to globally
auto-approve tools in real developer environments.

The retained `host-approval-gate/` case shows why this distinction matters:
Codex's `auto` host setting plus noninteractive `approval_policy=never` rejects
the side-effecting MCP call before Ironrun can create a pending request. Codex
itself exits0 after the scripted model responds, but the tool call fails, no
Ironrun grant is issued, and no loopback request occurs. Process exit 0 alone is
therefore not counted as a successful E2E outcome.

## Identity and retained records

`final/summary.json` records exact Codex, Ironrun, probe, driver and config hashes.
`final/runtime-source-build.json` hashes all Go/module source before and after
the build and asserts equality; the final driver also verifies source stability
through execution. The tested `mcp/server.go` SHA256 is
`c585b0004ea56fa2de402987269ed1caa0446795b19648dab2caaa47dc0464d2`.
The Ironrun diagnostic binary SHA256 is
`1e1d215de96a6db8f0ca0b68544d5272118d322300059be3e225e4767cd76126`.
All 182 recorded Go/module inputs were unchanged during that capture. A later
correction changes only three guided-demo message literals in
`cmd/ironrun/init.go`; it does not change the tested MCP server or execution
behavior. The captured binary predates those messages and is not relabeled as
the latest binary. `source-followup.json` records that exact one-file Go-source
delta. Fresh checks for the later copy are retained in
[runtime/demo-copy-followup](../runtime/demo-copy-followup/source-delta.json).
No new Codex capture is claimed. Go build metadata alone identifies a base
commit, so use the per-file hashes.
These are sampled file identities, not an operating-system image attestation.

Raw CLI/Codex output and command completion statuses are retained under `final/`.
`final/model-observations.json` preserves the actual discovered Ironrun catalog
and function-call/result items from both model requests. It omits built-in
system instructions and unrelated prompt messages. The complete original
request file remains local; its byte count and hash are recorded in
`final/raw-request-inventory.json`. `earlier-success/` preserves the first success
before the later catalog/help copy corrections. The immediately preceding source-bound success at server SHA `9efac543…` remains identified in the case inventory; `final/` is the later `c585b000…` capture. `case-inventory.json` records the
provider-only smoke, the initial fixture namespace mistake, the host approval
gate, and later successful recaptures without treating them as identical runs.

The artificial model name emits a Codex fallback-metadata warning; that warning
is retained. The final pass requires actual tool success, one matching local
credential delivery, no complete value in host/model input, a successful local
grant, and stable source/driver identities. It does not infer success from the
model's final text or Codex process status alone.

## Replay and limits

`probe_codex_host.py` is the exact final driver. Adapt its ROOT, REPO, GO and
CODEX paths to another checkout with the hash-listed source and test helper,
then run `python3 probe_codex_host.py --mode mcp`. It creates fresh synthetic
HOME/CODEX_HOME/XDG directories, model and child loopback endpoints, and local
test-store data. No dependencies are installed by the script. Build caches are
reused from the documented workspace paths. The driver preserves inherited
managed-runtime proxy/CA and guard settings; only test-specific directories and
Go settings are overridden.

This capture does not validate default onboarding, interactive host approval,
real-model reasoning, tool-timeout recovery, native credential stores, other
agent hosts, macOS execution, real service authentication, sustained daily use,
or human completion times. Only instrumented model/child endpoints are observed;
background host network traffic and every subprocess/syscall are not traced.
The short preapproval observation is a regression check, not a universal timing
or authorization proof.

`artifact-manifest.json` hashes files actually retained here and excludes itself.
Diagnostic binaries, native-store files, caches, full built-in prompt text, and
unrelated session files are intentionally absent from this compact archive.
