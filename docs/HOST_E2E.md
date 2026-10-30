# Real-host and native-store walkthrough

This is an operator-run protocol, not a record of completed human tests. The
next machines are the maintainer's Mac with Codex, Claude Code, and OpenCode,
then a Linux PC with the Cursor **desktop editor**, if its distribution and
architecture are supported. Every row below remains pending until observed on
that machine. Use disposable projects and synthetic credentials throughout.

The [developer pilot](LAUNCH_PILOT.md) separates preview checks from the existing
stable-release human gates. This walkthrough does not publish a release, install
an agent, edit your existing client settings, or certify production readiness.

## What counts as evidence

Keep these results separate:

| Check | Evidence required | Does not establish |
| --- | --- | --- |
| Source build | Exact commit, dirty-file diff/hashes, Go version, binary hash, actual execution | Signed release installation or Apple Gatekeeper behavior |
| Signed installation | Exact release tag, archive/checksum/bundle verification, install route, installed binary identity, actual startup | Human approval UX or native-store use |
| Native store | Actual Keychain/Secret Service, successful local masked write, fresh process decrypting and using the synthetic entry | A `doctor` pass alone is insufficient |
| Actual host | Installed host version, connected tool catalog, actual call/result and command effect | A config file or host process exit code alone is insufficient |
| Human workflow | Observed prompts, actions, continuation, errors and assistance | A scripted model fixture is not a usability session |

The local Linux Codex fixture used the actual Codex CLI, Ironrun encrypted v2
vault, CLI approval, child process, and loopback endpoint. Its model responses
and OS root-key adapter were synthetic, and its one isolated MCP server was
preapproved. See the retained
[Codex host evidence](validation/2026-10-26/codex-host/README.md) and
[MCP regression records](validation/2026-10-26/e2e/final-summary.json).
It does not close any Mac/native-store/human row below. Component
regressions in [the MCP integration test](../mcp/workspace_network_linux_test.go)
also retain this distinction. Record exact identities with each new result;
do not transfer a pass between hosts, architectures, builds, or install routes.

## Before starting

1. Record OS, architecture (`uname -m`), host version, terminal/shell, Ironrun
   version (`ironrun version --verbose`), binary location (`command -v ironrun`),
   and SHA-256. Use `shasum -a 256 /absolute/path/to/ironrun` on Mac or
   `sha256sum /absolute/path/to/ironrun` on Linux. Read the installed host's
   `--help`; vendor options can change between versions.
2. Choose the build lane. For source testing, record `git rev-parse HEAD`,
   `git status --short`, the actual diff, and `go version` in the Ironrun
   checkout; build with Go 1.26.10 or the repository's later required version:
   `go build -trimpath -o /absolute/path/to/test-bin/ironrun ./cmd/ironrun`.
   Recheck the binary that the host will launch. For release testing, use the
   exact verified tag and supported installation procedure in
   [INSTALL.md](INSTALL.md); retain its signature/checksum results. Snapshot
   cross-compilation and `go install` do not close the signed-install row.
3. On Mac, use the real logged-in account's Keychain and real `/usr/bin/security`.
   On Linux, use an active desktop/session bus and an unlocked Secret Service
   provider with real `secret-tool`. Availability on PATH is only a prerequisite.
   Do not substitute the test adapter or put a mock `security`/`secret-tool` on
   PATH. If the native store fails, record the failure and its recovery; do not
   switch to plaintext storage to mark the row passed.
4. Make a fresh disposable directory, open it in the selected host, and confirm
   `python3 --version`. The small probes below require Python 3; Python is not
   bundled with Ironrun or guaranteed on a new Mac. Use no real `.env` file,
   production service, inherited application token, or credential-bearing URL.
5. Before setup, privately back up any existing `.mcp.json`, `.codex/config.toml`,
   `.cursor/mcp.json`, `opencode.json`/`opencode.jsonc`, agent instruction files,
   `~/.codex/config.toml`, and `~/.cursor/mcp.json` that could be affected. Use
   your editor or a local backup with restricted permissions. Do not paste
   unrelated configuration into chat or attach it to the result report.

`ironrun setup` previews local policy/instruction files and attempts Codex and
Cursor user-level registration as well as Claude project registration. Run it
interactively only after reviewing those destinations; no script here runs it
against your account. OpenCode registration is currently manual. The setup
summary describes configuration, so verify the actual host connection next.
Record setup-assistance and manual configuration as separate outcomes.

## Prepare the disposable project

Run `ironrun setup` in the disposable project. Decline optional daemon/demo
steps if measuring the core path, and record that choice. Check whether setup
already created `dev`; otherwise run `ironrun env init dev`. Then use:

```sh
ironrun env set dev IRONRUN_PILOT_TOKEN
```

At its masked local prompt, enter a long, unique throwaway value. Never put it
in a flag, shell assignment, policy, host `env` configuration, or chat. The
credential value is not needed in the report. Native-store evidence requires
this write and a later actual child reading the entry after process restart.

Create `pilot_probe.py` manually in this disposable directory, using this
credential-free source. It records only case labels and prints its synthetic
credential deliberately so the sealed output path can be inspected:

```python
import json
import os
from pathlib import Path
import sys
import time
import urllib.request

mode, label = sys.argv[1:3]
def event(state):
    with Path("pilot-events.jsonl").open("a") as stream:
        stream.write(json.dumps({"case": label, "state": state}) + "\n")

event("started")
print("PILOT_STARTED " + label, flush=True)
if mode == "slow":
    time.sleep(30)
else:
    key = "IRONRUN_PILOT_MISSING" if mode == "missing" else "IRONRUN_PILOT_TOKEN"
    value = os.environ.get(key)
    if not value:
        raise SystemExit("PILOT_SECRET_MISSING")
    print("credential=" + value, flush=True)
    if mode in ("network", "expect-blocked"):
        # Deliberately local: ignore ambient HTTP proxy settings for this probe.
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request = urllib.request.Request("http://127.0.0.1:8787/", headers={"X-Pilot": value})
        try:
            with client.open(request, timeout=2) as response:
                print("PILOT_HTTP_RESPONSE " + response.read().decode(), flush=True)
        except OSError:
            print("PILOT_NETWORK_BLOCKED", flush=True)
            if mode != "expect-blocked":
                raise SystemExit(2)
        else:
            if mode == "expect-blocked":
                raise SystemExit("PILOT_UNEXPECTED_NETWORK")
            print("PILOT_NETWORK_OK", flush=True)
event("completed")
print("PILOT_DONE " + label, flush=True)
```

For the network cases, separately create `pilot_server.py` in the same directory:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        value = self.headers.get("X-Pilot", "")
        print("PILOT_HTTP_RECEIVED" if value else "PILOT_HTTP_NO_HEADER", flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(value.encode())
    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", 8787), Handler).serve_forever()
```

Start it in a separate terminal with `python3 -u pilot_server.py`. If port 8787
is occupied, choose another unused loopback port and change both probes before
testing. The server logs only a received-header marker; it returns the synthetic
value to the sealed child so both child stdout and echoed HTTP output exercise
filtering. Keep it local and stop it with Ctrl-C when finished. This proves
loopback delivery, not authentication to a real service or unrestricted internet
access.

In this disposable project only, replace the generated `ironrun.yml` with:

```yaml
version: "2"
environment_set: active
require_agent_leases: true
commands:
  - id: pilot-strict
    argv: [python3, ./pilot_probe.py, secret, strict]
    secrets: [IRONRUN_PILOT_TOKEN]
    ttl: 10s
    max_bytes: 8192
  - id: pilot-network-denied
    argv: [python3, ./pilot_probe.py, expect-blocked, strict-network]
    secrets: [IRONRUN_PILOT_TOKEN]
    ttl: 10s
    max_bytes: 8192
  - id: pilot-missing
    argv: [python3, ./pilot_probe.py, missing, missing-secret]
    secrets: [IRONRUN_PILOT_MISSING]
    ttl: 10s
    max_bytes: 8192
```

Run `ironrun validate`. `ironrun doctor` initially reports the deliberately
missing `IRONRUN_PILOT_MISSING` entry; retain that expected finding until the
missing-secret case fulfills it. `doctor` checks metadata and does not open or
decrypt the local vault. `ironrun env doctor` is a different command and can
prune expired sets; it is not a substitute for an actual sealed run.

## Connect each installed host

Replace every `/absolute/path/...` below with the actual local path. These are
entries to review and merge, not whole-file replacements. Preserve unrelated
servers, options, and permissions. An absolute binary path helps desktop apps
whose PATH differs from the terminal. The absolute policy path also pins
Ironrun's project root when a host starts its server elsewhere.

### Codex on Mac

Inspect existing registration with `codex mcp list --json` and, if present,
`codex mcp get ironrun --json`. A supported global registration command is
`codex mcp add ironrun -- ironrun mcp`; setup attempts that registration only
when absent. Do not add a second conflicting server or globally bind one
project's policy for use by every project.

For an explicitly scoped manual check, review this entry in the trusted test
project's `.codex/config.toml`:

```toml
[mcp_servers.ironrun]
command = "/absolute/path/to/ironrun"
args = ["mcp", "--policy", "/absolute/path/to/project/ironrun.yml"]
cwd = "/absolute/path/to/project"
required = true
startup_timeout_sec = 20
tool_timeout_sec = 1200
```

The chosen 20-second startup and 1,200-second tool budgets are test settings,
not measured latency or defaults. The latter allows a 15-minute review plus
these short commands; longer commands need their own budget. Project config
loads only for a trusted project. Launch interactively with
`codex -C /absolute/path/to/project -a on-request`, review project trust, and use
`/mcp` to inspect the active server and tools. Keep the host's tool approval
prompts. Do not copy the fixture's `default_tools_approval_mode = "approve"`,
custom model provider, synthetic native adapter, or noninteractive approval
settings into your account.

### Claude Code on Mac

Setup uses the project-root `.mcp.json`, not `.claude/mcp.json`. Review/merge:

```json
{
  "mcpServers": {
    "ironrun": {
      "type": "stdio",
      "command": "/absolute/path/to/ironrun",
      "args": ["mcp", "--policy", "/absolute/path/to/project/ironrun.yml"]
    }
  }
}
```

Alternatively, when no registration exists, the official CLI supports
`claude mcp add --transport stdio --scope project ironrun -- ironrun mcp`.
Do not run both paths blindly. Start `claude` from the project, review workspace
trust and the project MCP-server approval, then inspect `/mcp` and
`claude mcp get ironrun`. A written registration can still be pending approval.
Review each requested tool call separately from the Ironrun grant below.
For a deliberately extended waiting-call test, current Claude documentation
describes `MCP_TOOL_TIMEOUT`; verify the installed version's behavior before
using a per-launch setting such as `MCP_TOOL_TIMEOUT=1200000 claude`.
Startup, idle timeout, backgrounding, and tool execution are distinct behaviors;
record which one actually ends a waiting call. Do not bypass host permissions
to hide a failed approval test.

### OpenCode on Mac

Setup does not currently register OpenCode. Review its existing project config
and manually merge into `opencode.json` or `opencode.jsonc`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ironrun": {
      "type": "local",
      "command": ["/absolute/path/to/ironrun", "mcp", "--policy", "/absolute/path/to/project/ironrun.yml"],
      "cwd": "/absolute/path/to/project",
      "enabled": true,
      "timeout": 60000
    }
  }
}
```

Launch `opencode` from the project and inspect `opencode mcp list`, the active
tools, and the actual call. Preserve existing permission rules. The official
local-server options document `cwd` relative to the workspace and `timeout` in
milliseconds. Retrieved documentation versions differ on the timeout default
and whether its wording includes tool calls; the current `/docs/` table calls
it a tool-discovery timeout. The explicit 60,000 ms here is a test setting,
**not proof that an approval-waiting call gets that duration**. Record installed
OpenCode version and actual wait/cancel behavior; check the matching version's
documentation if it expires before Ironrun review completes.

### Cursor desktop on Linux

Use [Cursor's official downloads](https://cursor.com/downloads) to select the
desktop package for the actual distribution and `uname -m`: the fetched page
offers Linux x64 and ARM64 options with Debian, RPM, and AppImage variants.
`x86_64` corresponds to x64; `aarch64` corresponds to ARM64.
Record the chosen package and actual application version after installation.
A `cursor`/agent CLI alone does not establish the desktop editor is installed,
launches in a graphical session, or loads local MCP tools. If the PC lacks an
applicable package or usable GUI, mark the desktop row blocked and state why.

Open the disposable folder in the editor. Setup attempts user-level
`~/.cursor/mcp.json`; inspect it before adding a project `.cursor/mcp.json`
entry. For a deliberate project-scoped manual configuration, use the same JSON
shape as Claude above, preserving other settings. Avoid duplicate/conflicting
registrations. Open Customize, enable Ironrun, and inspect its available tools
and connection errors. Keep Cursor's tool approval enabled and expand the
arguments before approving. Record Run Mode and any administrator MCP/network
policy. No undocumented Cursor timeout field is prescribed here; test the
installed editor's waiting-call and cancellation behavior explicitly.

## Exercise the complete flow on each host

Use a second local terminal in the same project for `ironrun` (Projects/Inbox)
and the CLI review commands. Values are entered only through local masked
prompts. In chat, ask for the exact Ironrun tool and argument object, with no
fallback raw-shell execution. The host may prefix tool names; verify the
underlying Ironrun tool and actual result. First call `workspace_status` and
`list_commands` and check the project, `dev`, names, and configured commands.

| Case | Operator and agent actions | Required observation |
| --- | --- | --- |
| Host approval | Request a `run_sealed` call; first reject the host's tool prompt | No child event. Check whether an Ironrun request was created; host rejection commonly happens before Ironrun is called. Record the actual boundary. |
| Workspace request | Call `run_sealed({"argv":["python3","./pilot_probe.py","network","workspace-approved"]})`; leave Ironrun unapproved briefly | Inbox shows the correct project, environment, MCP session, first argv, stored review deadline, and requested access lifetime. No new probe event or HTTP marker before grant. |
| Approval and continuation | Review locally; `ironrun access list`, then `ironrun trust grant REQUEST_ID --ttl 2m` or the corresponding Inbox approval | Original waiting call resumes without retry; child events show start/completion, loopback server receives a header, tool result has exit 0, `credential=[REDACTED]`, redacted HTTP echo, and `PILOT_NETWORK_OK`. Inspect actual output, not just the agent's summary. |
| Normal network versus strict policy | Call `run_sealed({"command_id":"pilot-network-denied"})`; review its separate lease request with `ironrun access approve REQUEST_ID --ttl 2m` | Strict child actually starts, emits `PILOT_NETWORK_BLOCKED`, and adds no server request. The policy's secret-bearing default denies network. A containment setup error is a fail-closed outcome, not proof of a blocked child dial; record it separately. |
| Strict known-secret run | Call `run_sealed({"command_id":"pilot-strict"})`; approve its command lease if requested | Actual start/completion and exit 0 with redacted credential. A workspace grant does not replace a strict command lease. |
| Missing-secret strict branch | Call `run_sealed({"command_id":"pilot-missing"})` while `IRONRUN_PILOT_MISSING` is absent | Secret and possibly lease requests appear; child has not started. Use `ironrun access fulfill SECRET_REQUEST_ID` and its local masked prompt once, then approve the separate lease if needed. The original call resumes and output is redacted. Re-run `ironrun doctor` after fulfillment. Do not claim this test covers arbitrary workspace missing-secret requests. |
| Denial | Revoke any active workspace grant, request a new workspace call with a fresh case label, then `ironrun access deny REQUEST_ID` | Waiting tool returns denial; no event for that label or endpoint request. Inspect `ironrun access list --all`. A later retry needs a new pending request. |
| Grant expiry | Approve a new workspace request with `--ttl 10s`; after the recorded expiry, request a fresh labeled call without approval | Expired grant does not authorize the next command. A new review is required. Deny it after observation. Do not change the machine clock or edit stored access state. |
| Request expiry | Leave a fresh request unapproved through its displayed deadline; keep this separate from the 10-second grant test | No child executes, expiry is visible, and a late approval fails. Default review is 15 minutes; the host may time out first. Record both outcomes and recover explicitly. |
| Revocation | While a grant is active, `ironrun trust list`, then `ironrun trust revoke TRUST_ID`; retry with a new label | The next workspace call cannot run under that grant. Revocation does not promise to terminate a child that was already authorized/running. Deny any resulting fresh request. |
| Cancel while pending | Start an unapproved call, use the host's cancel/stop control, then inspect Inbox | Record whether the host sends cancellation and the tool's actual result. Do not assume cancellation denies the persisted request. Deny remaining pending requests locally; reissue only when deliberately ready. |
| Cancel while running | With approved workspace access, call argv `["python3","./pilot_probe.py","slow","cancel-running"]`, wait for its started event, then cancel | Check actual process termination and absence of the completed event after the probe's 30-second sleep plus observation margin. Record a host that only stops displaying output as a failure, not successful cancellation. |
| Host timeout | In a separate run, deliberately use the host's documented short tool budget, leave review pending, and wait for the observed timeout | No child before approval; record error, remaining request, and any late/background activity. Restore the chosen budget, deny the stale request, and reissue. A timed-out call is not counted as in-place continuation. |
| Restart and continuation | Record grant/session, restart the host's Ironrun MCP server, call `workspace_status`, then request a new labeled workspace run | New MCP process has a new session and cannot inherit the old grant. Review/approve the new request. A canceled/disconnected old call is not promised to resume; inspect markers before retry to avoid duplicate execution. |

If an installed host exposes no documented short tool-timeout control, mark
that deliberate-timeout case blocked with its reason; do not invent a config
property. Keep its natural timeout and user cancellation observations separate.

Trusted workspace access is broad: arbitrary argv can use the selected
environment with normal network access. Filtering intercepted stdout/stderr
masks known values and supported encodings; it cannot prevent a trusted child
from sending values through files, network, or unsupported transformations.
Use the restricted saved-command mode when that scope is needed. Its
`no_network: true` wins over `allow_network: true`; a secret-bearing command
without an explicit allow defaults to network isolation.

The two approval layers are independent. Allowing a host tool does not issue
Ironrun trust; issuing Ironrun trust does not override a host's tool denial.
Likewise, `ironrun run COMMAND_ID`/`exec` is the human CLI strict-policy route,
not an agent workspace-grant test. Never count a final chat sentence or host
exit 0 as proof of a successful child.

## Configuration preservation and recovery

Test malformed/custom configuration using a disposable OS account or supported
isolated host profile, not by corrupting the maintainer's everyday files.
Retain a private pre-change copy and hash. Include one unrelated server and
one intentionally custom `ironrun` entry; exercise setup and verify both are
preserved, with an understandable inspection/repair message. Separately test
malformed JSON/TOML in the isolated profile. A parse failure must not justify
replacing the file. Compare locally; never attach unrelated config contents.

For a real configuration failure, first record the exact error and affected
path, stop that host connection, and manually repair/merge only the Ironrun
entry or restore the reviewed backup. Reopen the host and verify tools and
unrelated settings. Do not delete the full config, reset all host permissions,
or rerun setup repeatedly as a substitute for understanding its reported state.
If a server starts in the wrong folder, check absolute binary/policy paths and
the supported `cwd` option rather than copying credentials into host settings.

On completion, deny unused pending requests, revoke test workspace grants and
strict leases (`ironrun access leases`, `ironrun access revoke LEASE_ID`), and
stop the loopback server. Keep evidence free of values. If deleting the test
environment, use the confirmation in `ironrun env remove dev` only from this
disposable project. Remove only the test registration/files you intentionally
added, preserving later unrelated edits and the user's existing vaults.

## Result matrix and per-case record

Fill `pending`, `pass`, `fail`, `blocked`, or `abandoned`, with an evidence link.
Never infer another column from a pass in one column. Record source-build and
signed-install runs separately, even if they use the same host version.

| Machine/host | OS/arch + actual versions | Source build | Signed install | Real native store | Tools + actual run | Approval/continuation | Negative/recovery cases |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Mac / Codex | To record | Pending | Pending | Pending: Keychain | Pending | Pending | Pending |
| Mac / Claude Code | To record | Pending | Pending | Pending: Keychain | Pending | Pending | Pending |
| Mac / OpenCode | To record | Pending | Pending | Pending: Keychain | Pending | Pending | Pending |
| Linux PC / Cursor desktop | To record; GUI/package availability first | Pending | Pending | Pending: Secret Service | Pending | Pending | Pending |

Copy this compact record for each case; keep native-store and signed-install
failures even if a source-build case succeeds:

```text
Run/date/operator pseudonym:
Host version / OS / architecture / GUI or CLI / permission mode:
Ironrun source commit + dirty diff/hashes OR release tag + verification records:
Actual launched binary path + SHA-256 / install route:
Native provider (actual or synthetic) + write/fresh-process-use evidence:
Config scope and private before/after hashes (no unrelated contents):
Case / exact tool arguments (names and argv only) / case label:
Expected start/end events / actual elapsed time if measured:
Host approval outcome / Ironrun request + grant or lease IDs / deadlines:
Actual child exit + marker events / redaction observation / endpoint count:
Pass, fail, blocked, or abandoned / error / help given / recovery:
Evidence paths reviewed for values / follow-up owner:
```

The research report may have a Cloudflare preview before this runtime matrix
is complete. Label its evidence and pending gates accurately. Integrate it
into the main ironrun.dev site only after the runtime readiness decision; a
polished page does not close runtime or stable-release gates.

## Sources and command provenance

Checked October 27, 2026. Ironrun command spellings above were compared with
actual `--help` from the reviewed source-built binary and the CLI/MCP source.
Host options are grounded in official documentation; check the installed
version before changing existing settings:

- [Codex MCP](https://developers.openai.com/codex/mcp/),
  [project configuration](https://developers.openai.com/codex/config-advanced/#project-config-files-codexconfigtoml),
  and [configuration reference](https://developers.openai.com/codex/config-reference/).
- [Claude Code MCP](https://code.claude.com/docs/en/mcp): project scope,
  server/tool approvals, timeout controls, and connection-loss behavior.
- [OpenCode MCP](https://opencode.ai/docs/mcp-servers/): local command array,
  `cwd`, enabled flag, and timeout; consult the matching version's documentation.
- [Cursor MCP](https://cursor.com/docs/context/mcp) and
  [official desktop downloads](https://cursor.com/downloads): project/global
  config, tool approval, desktop platform/package selection, and failure UI.
- [Ironrun setup](../cmd/ironrun/init.go),
  [registration preservation](../cmd/ironrun/mcp_registration.go),
  [workspace/strict handlers](../mcp/server.go),
  [access deadlines](../internal/access/access.go), and
  [network policy](../internal/policy/policy.go).
