# Telemetry: ironrun collects none

**ironrun collects zero telemetry.** No usage data, no crash reports, no
phone-home, no update checks, no analytics of any kind leave your machine.

## What "no telemetry" covers

- **No network calls initiated by ironrun itself.** The binary never opens
  an outbound connection except when *you* explicitly ask it to — the only
  such case today is MCP server tools that fetch remote resources at your
  command, which are ordinary user-initiated requests, not telemetry.
- **No identifiers.** No machine IDs, install IDs, user IDs, or fingerprints
  are generated, stored, or transmitted.
- **No usage or crash reporting.** Errors stay in your terminal and your
  local audit log. Nothing is uploaded.
- **No update checks.** ironrun never asks the network whether a newer
  version exists. The npm launcher's `postinstall` downloads the pinned
  release binary exactly once (a plain file download from the GitHub
  release, verified by SHA-256); it sends nothing back.
- **No build-time beacons.** Release binaries contain no analytics SDKs and
  no network code paths that activate on their own.
- **Local state stays local.** The vault, audit log, project registry, and
  secret stores live under `~/.ironrun` and your project directories. They
  are never transmitted anywhere by ironrun.

## How to verify

1. **Read the code.** The module dependency list (`go.mod` / `go.sum`)
   contains no analytics or telemetry libraries. `grep -ri "telemetry\|analytics\|segment\|amplitude\|posthog\|mixpanel" --include="*.go" .`
   should return nothing outside of docs.
2. **Watch the network.** Run ironrun under a firewall or with network
   logging (`sudo tcpdump -i any host not <your-mcp-host>`); during normal
   use — setup, add, run sealed commands, approve/reject — you will see no
   outbound connections initiated by the ironrun process.
3. **Inspect the binary.** `go list -deps ./cmd/ironrun` shows the full
   dependency closure; there is no telemetry package in it.
4. **Reproduce the build.** `make verify-reproducible` builds the binary
   twice from source and requires byte-identical output — the binary you
   audit is the binary you run.

## If this ever changes

Telemetry would be a product decision requiring explicit, informed,
opt-in consent — never silent, never default-on. Any future network behavior
will be documented here first, with exact endpoints, payloads, and how to
disable it. A release that phones home without disclosure is treated as a
security bug: report it via the private vulnerability reporting channel in
SECURITY.md.
