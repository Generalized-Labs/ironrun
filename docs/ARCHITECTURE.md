# Ironrun architecture

Ironrun is a local-first encrypted environment workspace. The Go binary is the
security boundary; the optional npm package is only a verified binary launcher.

## Data model

- The global owner-only registry stores stable random project IDs, checkout
  paths, remote hints, and last-opened timestamps. It contains no values.
- Each project owns environment metadata under `.ironrun/`. Metadata records
  safe names, kinds, targets, filenames, and timestamps only.
- Values are encrypted in the per-project vault. The random vault root key is
  protected by the native OS credential manager. A project's registry ID and
  immutable vault identity are intentionally separate.
- `ironrun.yml` version 2 binds approved commands directly to environment entry
  names. Version 1 aliases and provider mappings remain supported.

## Execution boundary

All CLI, MCP, TUI, and local API runs converge on `internal/execution`:

1. Authorize an exact saved command and pin the reviewed environment.
2. Resolve only the entries declared for that command.
3. Materialize file secrets inside an owner-only temporary directory.
4. Inject environment values and temporary paths into the child process.
5. Redact literal and encoded values from captured and streamed output.
6. Audit safe names and cleanup results, then remove temporary files.

Strict policy mode gives agents only exact saved commands. The default local
development path also supports a temporary trusted workspace grant bound to one
MCP session, project, and environment. During that explicit grant an agent may
run arbitrary argv and receives all configured entries for the pinned
environment; the same runner still injects below agent visibility and redacts
output. This is a convenience/security tradeoff, not containment of a hostile
same-user process.

## Requests and continuation

`run_sealed` reloads policy on every call. A pending strict command, lease,
missing entry, or trusted workspace request produces deduplicated value-blind
request records. A workspace grant defaults to two hours, is tied to the MCP
session and selected environment, and can be paused, extended, or revoked from
the TUI or CLI. The MCP call waits for the persisted request deadline. Human
approval or masked TUI entry changes the local state; the original call
revalidates authorization, then resumes without an application restart or chat
acknowledgement.

The per-user daemon exposes global project and inbox metadata over an owner-only
Unix socket. Accepted peers are checked against the daemon's OS user ID. Its RPC
schema has no field that can accept or return a secret value. The foreground TUI
writes masked input directly through the native vault library.

## Platform support

macOS and Linux are GA targets. Windows amd64 remains beta and uses on-demand
operation until the persistent service has a Windows-native transport.

See [SECURITY.md](../SECURITY.md) for the threat boundary and disclosure process.
