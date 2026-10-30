# Production workflow audit, bounded October 26 follow-up

Scope: local CLI setup/environment, stdio MCP authorization and execution,
network contract, generated instructions, and observable test seams at base
`64308e62eb553716f7ef0c5e8bfcd7205a698696`. This is a workflow-condition audit,
not certification of all source, native stores, hosts, or release channels.

The initial reconnaissance was read-only. The supervisor subsequently authorized
narrow MCP regression tests and a repair after resolving the network contract.
At this checkpoint, only regression tests/testdata have been added; production
`mcp/server.go` remains unchanged while the policy decision is pending.

## Checklist status

| Area | Observed status | Evidence and confidence |
| --- | --- | --- |
| Tooling/CI drift | Not rescanned here | Existing pipeline uses Go1.26.10 and credential-free synthetic tests; no new CI verdict produced by this audit |
| Docs versus behavior | Conflicting | README says workspace default-deny; grant metadata/TUI/CLI advertise normal network; actual child is isolated. High confidence |
| Config/environment | Native availability gap | This Linux workspace has Codex, but no Claude/Cursor/secret-tool/Keychain tool; native adapter tests cannot establish real Secret Service behavior. High confidence |
| Dependencies | Not rescanned | No dependency or package changes in the bounded repair |
| Test health | Missing integration seam found | Existing handler stubs discard network option; execution test explicitly opts out; new real stdio/v2/vault/loopback test fails on current behavior. High confidence |
| Packaging/release | Outside this audit | No installer/tagged-signature/native architecture validation run |
| Agent instructions | Drift found | Generated guidance still says output values never leak and describes strict `exec` alias as trusted-session behavior. High confidence |

## Findings

1. **Critical / conflicting contract — trusted workspace network.**
   - Evidence: `access.ApproveWorkspace` records `Network: "normal"`;
     TUI request details say "Network: normal development access";
     `ironrun trust grant` says normal network is enabled. Conversely,
     README.md describes default-deny workspace isolation. The MCP handler
     omits `Options.AllowWorkspaceNetwork`; `RunWorkspace` copies false into
     the transient policy command. Secret-bearing commands are isolated.
   - Impact: ordinary development API calls fail after the operator is told
     they approved normal network. The project must choose and consistently
     expose one contract before claiming production readiness.
   - Reproduction: a seam assertion fails; an actual child in the stdio MCP
     path prints `PROBE_STARTED`, redacted credential, then `DIAL_BLOCKED` and
     exits1 after successful local grant. No loopback request reaches the
     host endpoint. See `workspace-real-red-outside-sandbox.log`.
   - Confidence: High. Not merely a mocked callback observation; the real
     binary/v2 vault/runner/network path was exercised with a synthetic native
     root-key provider.
   - Next module: product-planning for the conflicting permission contract,
     then implementation/change-review for the bounded repair.

2. **Watch / stale agent-facing instructions.**
   - Evidence: `cmd/ironrun/instructions.go:23–24` promises values "never leak";
     lines42–43 attach `ironrun exec <command-id>` to trusted sessions, although
     `exec` is a strict `run` alias in `main.go`. Session trust is MCP state.
   - Impact: newly generated CLAUDE.md/AGENTS.md/.cursorrules can teach agents
     a stronger confidentiality promise and a misleading execution model.
   - Confidence: High for source drift; actual model behavior is unmeasured.
   - Next module: implementation for a small generated-copy correction, with
     the real-host agent workflow still requiring observation.

3. **Watch / incomplete v2/native/host proof.**
   - Evidence: existing missing-secret-resume MCP test uses version1/envfile;
     v2 execution tests inject an in-memory manager; native key-material probe
     can skip. No real Claude Code/Cursor host or native Secret Service exists
     in this Linux environment. The new fixture substitutes only root-key
     storage and otherwise runs CLI, encrypted vault, stdio MCP and child.
   - Impact: component successes cannot establish a fresh user's native-store
     setup, host discovery, timeout/cancel UX, or full in-place continuation.
   - Confidence: High for coverage/availability; no untested behavior is
     classified as broken solely because evidence is absent.
   - Next module: task-creation/context-survey for actual Mac/Linux host pilot.

## Existing positive coverage inspected

Local protocol tests cover lease approval/run/revocation, session non-transfer,
value-blind secret requests, deduplication, stored review deadline and secret
fulfillment/resumption. Access-manager tests cover workspace session/environment
pinning, pause/revoke/expiry. Execution tests cover v2 value injection/redaction,
file workspace permissions and cleanup, cancellation, and stale recovery.
These are distinct component/integration observations, not a real host session.

## New regression checkpoint

- `network-contract-red.log`: callback-level read-only overlay, expected exit1.
- `workspace-real-red.log`: initial extra-sandbox attempt, exit1 due unrelated
  read-only filesystem namespace setup; retained as a failed environment attempt.
- `workspace-real-red-outside-sandbox.log`: expected contract failure while the
  actual synthetic child attempts loopback; exit1. Ironrun's own network controls
  remain enabled; only the additional agent filesystem sandbox was removed.
- The current test was then strengthened to use actual local `trust grant`,
  `trust revoke`, and `access deny` CLI actions; fresh red/green results for that
  exact version must be recorded before delivery.

No public network request, project credential, actual client config, release,
tag, npm publication, or Homebrew mutation was used. Native-store availability,
real host sessions, end-user completion rates, and actual release installation
remain unchecked here for explicit environmental/scope reasons.

## Resolution after explicit network-contract selection

The maintainer explicitly chose normal network access for trusted workspaces,
matching the approval screen and CLI, while retaining each saved command's own
policy. The minimal MCP change now sets `AllowWorkspaceNetwork: true` only after
the existing workspace authorization returns. No strict policy branch, grant
timing, lease scope, or session/environment binding was changed.

The exact CLI-based regression failed before the production fix
(`workspace-cli-red.log`, exit1). The final focused race run then passed six
tests (`workspace-final-green-race.log`, exit0): a real synthetic child reached
the local HTTP server with the configured credential and returned redacted
output; the saved strict child actually started and emitted `DIAL_BLOCKED`;
CLI revocation followed by denied fresh approval produced no further endpoint
request. A bounded100ms pending interval observes that no endpoint request
arrives before approval; it is not a latency/usability measurement.

`final-summary.json` hashes the four changed/added MCP files. The files are
frozen for independent review. The supervisor will run the full suite after
all agents' patches are assembled; this subtask's final run is focused coverage,
not a newly claimed full-suite result. Generated instructions/documentation are
owned and corrected separately by the supervisor.

## Final catalog-copy checkpoint

After the network behavior was frozen, the supervisor requested a catalog-only
correction: `run_sealed` now describes configured child-process injection and
known-value/supported-encoding output filtering, with explicit limits for
arbitrary transformations, files, and network access. Universal confidentiality
wording was removed. Final source SHA256 values are in `final-summary.json`.

`workspace-catalog-final-green-race.log` records the final frozen source: all six
focused tests pass under the race detector, package runtime3.376s. The actual
workspace probe reached loopback and produced redacted output; the strict child
started and emitted `DIAL_BLOCKED`; revoke/deny assertions passed.
`git diff --check -- mcp` also exits0. All four owned source files are frozen;
full-suite validation and actual-host recapture remain supervisor-owned.
