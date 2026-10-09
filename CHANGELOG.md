# Changelog

All notable changes to ironrun are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Phase 0 leak-prevention stack: exact-value secret matching and redaction,
  sealed execution with a fail-closed seccomp sandbox on Linux, git
  pre-commit/pre-push hooks that block leaked secrets, and a value-blind local
  API with agent lease enforcement.
- Verified release pipeline: reproducible builds, Sigstore bundles and
  checksums, an SBOM, the Homebrew formula, and a native npm launcher whose
  postinstall verifies the published artifact manifest before install.
- Universal agent instructions for Claude Code, Grok, Codex, Hermes, Pi,
  HumanLayer, and Conductor workspaces.
- Google Drive environment sync, additional MCP tools, and redactor
  performance optimizations.
- MCP guard suite: banned-tool registry (share_environment /
  sync_environment stay removed) and key-material negative probes that fail a
  build if any tool result ever carries vault key material.

### Fixed

- Linux network isolation now works unprivileged: CLONE_NEWUSER plus
  identity-mapped uid/gid authorize CLONE_NEWNET on default Ubuntu 24.04+
  hosts (previously EPERM -> fail-closed refusal). CI exercises the real
  isolation path instead of bypassing it.
- macOS CI matrix: pty regression test now uses the BSD util-linux script
  invocation, and Linux-only sealed-shim expectations skip outside Linux.
- HTTPS and SSH remotes of the same repository no longer produce different
  project identities (which locked users out of their vault); existing projects
  keep their recorded identity.
- `environments.json` is updated atomically under the vault lock, so
  concurrent TUI/CLI/MCP writers no longer drop each other's entries (dropped
  entries also resurfaced after `env remove`); `.ironrun/pending.yml` is
  replaced atomically.
- `.env` import resolves symlinks (and case on macOS) before refusing
  project-local files, and single-quoted values are kept literal.
- Wrapped-base64 redaction no longer swallows the newline that ends the line.
- macOS network isolation no longer blocks `fork`: the Seatbelt profile denied
  everything except exec and file access, so most secret-bearing commands
  (`npm`, `go test`, Python and Node subprocesses) failed under the default
  policy. The macOS network test now distinguishes "blocked" from "crashed".
- A relative `workdir` resolves against the project root, not the directory
  ironrun was started from.
- Git hooks are installed where git reads them (linked worktrees,
  `core.hooksPath`), and hook scanning checks only added lines, across every
  environment, including multi-line and binary values.
- The npm package now includes its postinstall script (installs previously
  failed), and the release workflow passes the Homebrew tap token.
- The envfile provider keeps path case, strips `export`, honors inline comments,
  and expands `\n` only inside double quotes; `ironrun setup` handles `export`
  lines in `.env`.
- Exit codes: a cancelled run returns an error, a signal-killed child reports
  `128+signal`, exit codes 124/125 are attributed to the sealing shim only when
  it ran, and `truncated` is reported only when output was actually dropped.
- `ironrun gh protect --org` sends typed booleans; `lint` counts version-2
  secret bindings.

### Security

- Removed the MCP share_environment tool (returned the vault root key with no
  approval gate) and the sync_environment stub; guard tests fail on
  reintroduction.
- Removed `ironrun env share` / `vault share`, which printed the vault root key
  to stdout without any gate. Agents have shells, so the CLI is now treated as
  agent-reachable like MCP.
- Approving a proposal no longer splices agent-written text into
  `ironrun.yml` unescaped. A line break in a proposal's reason, env binding, or
  secret name (including U+2028/U+2029, which YAML treats as line breaks) could
  smuggle extra commands past the human reviewer. Scalars are now quoted,
  comments flattened, multi-line text rejected at the MCP boundary, and pending
  proposals are immutable so the content cannot change between review and
  approval. Review output shows argv with explicit element boundaries and
  sanitized text; the TUI shows provider references.
- `--emit-github-masks` (always passed by the Action) printed lines 2..N of
  multi-line secrets — PEM keys, service-account JSON — to the job log in
  cleartext. Each line is now masked separately and workflow-command data is
  escaped.
- The redactor now covers base64 at all three byte alignments (HTTP Basic
  `Authorization` headers, docker `auth`, `printenv | base64` previously leaked
  whole secrets), JSON-escaped forms, JavaScript and Python percent-encoding,
  partial prints of secrets up to 64 KiB (was 1 KiB, which excluded PEM and
  JSON file secrets), and hex dumps (`xxd`, `hexdump -C`, `od -c`) via
  whitespace-tolerant fragment matching. Agent-transcript scrubbing and CI masks
  share the new alignment and JSON variants.
- The audit log now fails closed in the CLI and MCP server, as it already did in
  the local API, instead of continuing unaudited when tampering is detected.
- The vault root key is no longer passed on the `security` command line on
  macOS (visible to process listings and EDR); keychain writes go through
  `security -i` on stdin and are read back to confirm.
- `env sync pull` verifies the pulled vault's MAC, project, and revision under
  the vault lock and writes it atomically, instead of blindly overwriting the
  local vault (data loss and silent rollback).
- `ironrun api` and `propose_command` re-read the policy on every request, so
  removing a command, requiring leases, or disabling proposals takes effect
  without a restart.
- GitHub fork pull requests were never detected: the check compared a variable
  GitHub does not set. Fork status now comes from the event payload for
  `pull_request`, `pull_request_review`, `pull_request_review_comment`, and
  `workflow_run`, fails closed when the payload is missing, and runs before any
  secret is resolved or mask printed.
- A command's time limit now covers its whole process group: grandchildren that
  held the output pipe could block a run indefinitely, and descendants could
  outlive the run with secrets in their environment. A signal to ironrun
  (Ctrl-C, SIGTERM, SIGHUP, a closed pipe) now tears down the child and removes
  temporary file secrets; leftovers from a crashed ironrun are recovered as
  soon as the owning process is gone.
- `no_network` on macOS invokes `/usr/bin/sandbox-exec` by absolute path, so a
  `sandbox-exec` earlier on `PATH` can no longer disable isolation.
- `history purge --apply` no longer leaves a plaintext `.ironrun.bak` copy of the
  purged secret (and removes one left by older versions).
- The argv[0] shell check matches on the cleaned base name (`/bin//sh`,
  `/opt/homebrew/bin/bash`), covers more shells, and looks through `env`. The
  inherited-environment deny list adds `DYLD_*`, `GIT_CONFIG_*`, `GOFLAGS`,
  `NODE_PATH`, `GCONV_PATH`, and `RUSTC_WRAPPER`.
- Policy `env:` keys must be valid environment variable names.
- Release workflow actions are pinned to full commit SHAs.

## [0.4.0] - 2026-07-16

### Added

- Trusted workspace sessions: one human approval grants one MCP session
  revocable two-hour access to a project environment for normal development
  argv, while strict command policy remains available for sensitive workflows.
- `ironrun trust list|grant|pause|extend|revoke`, plus value-blind
  `request_workspace_access` and `workspace_status` MCP tools.
- A global, owner-only project registry and task-oriented workspace available
  from any directory with `ironrun`, `ironrun open`, and `ironrun inbox`.
- Version-2 policies that bind approved commands directly to encrypted
  environment entry names while retaining version-1 provider compatibility.
- A value-blind, reversible migration flow with preview, verified encrypted
  copy, ignored backups, rollback, and explicit cleanup.
- Automatic MCP continuation for missing command approval, agent lease, and
  secret requests. The original sealed call resumes after the human completes
  the request in the TUI.
- A peer-UID-verified per-user daemon for project, inbox, and request
  coordination, with launchd and systemd user-service management.
- Top-level `add`, `import`, `use`, `status`, `run`, `projects`, `daemon`, and
  `migrate` workflows; existing nested commands and aliases remain compatible.
- An event-driven, responsive TUI with one primary action, global projects and
  inbox views, exact waiting-run review, contextual help, and `NO_COLOR`
  support.
- A fail-closed verified installer served from ironrun.dev, GoReleaser SBOM and
  Sigstore publication, OpenSSF Scorecard, and a minimal native npm launcher with
  immutable artifact verification.

### Changed

- Encrypted environment entries are the everyday source of truth. Updating a
  stored value no longer requires rewriting command policy.
- Bare `ironrun` opens the global workspace instead of printing command help or
  opening a decorative project dashboard.
- New setup writes a version-2 policy, registers the project, previews every
  local change, optionally installs the daemon, and ends with a redaction and
  health check.
- Requests and leases are secondary views; secrets, environments, commands,
  projects, and waiting human actions lead the interaction model.

### Security

- Authorization is pinned to the reviewed project, environment, command, and
  authenticated MCP session through approval and execution.
- Daemon RPC schemas are value-blind and local Unix peers must match the owner
  user ID.
- File secrets use owner-only temporary directories outside the repository,
  include output-redaction-only values, and are cleaned after all normal exit
  paths with validated stale-run recovery.
- Release gates now explicitly separate automated proof from multi-machine and
  external-user validation; Ironrun must not be tagged GA until both pass.

### Added
- **Encrypted project vaults.** Environment values are stored outside the
  repository with per-environment AES-256-GCM data keys wrapped by a project
  root key in the native OS credential manager. Existing native records migrate
  lazily with commit-before-delete ordering.
- **Revocable agent leases.** The opt-in `require_agent_leases` policy gate binds
  MCP authority to one server session, environment, command set, and expiry.
  Agents may request leases; only the local CLI/TUI can approve them.
- **Safe secret requests and chat capsules.** Agents request declared aliases
  without a value field. Humans can fulfill through masked local input or create
  a short-lived `ir1.` ciphertext bound to the project, request, and MCP session.
- **Terminal control room.** Running `ironrun` or `ironrun tui` opens a
  value-blind environment/request/lease dashboard with masked fulfillment,
  approvals, denial, switching, and immediate revocation.
- **Unix-socket curl API.** `ironrun serve` exposes strict, non-cacheable local
  status, environment, access, revocation, and sealed-run endpoints with no
  plaintext-secret endpoint.
- **Typed workspace entries and file secrets.** Versioned environment metadata
  now distinguishes environment values from encrypted file contents. Existing
  key lists migrate automatically. File secrets are materialized in isolated
  owner-only run directories and removed after every execution path.
- **Secret-manager-first workspace TUI.** The default screen now exposes
  environments, masked typed entries, `.env` preview/import, file import,
  approved command execution, and persistent actions, with requests and leases
  moved to secondary tabs plus `/` palette and `?` help.

### Changed
- CLI, MCP, and the local API now share one sealed execution core.
- MCP and the local API expose typed entry metadata (name, kind, target, safe
  filename) without values. Audit records include the same safe use metadata
  and temporary-file cleanup result.
- Everyday workflows now have top-level commands: `add`, `new`, `session`,
  `use`, `envs`, and `exec`. Help is grouped by user intent; readable names
  (`agents`, `share`, `api`, `dashboard`, and `setup`) retain the original
  command names as aliases, and `vault` aliases `env`.
- Bare `ironrun` now bootstraps a missing policy and encrypted `dev`
  environment before opening the TUI. The control room can enable the vault on
  older policies, add secrets, and create persistent or 24-hour environments.

### Security
- Vault manifests are authenticated and atomically committed; missing protected
  root keys, tampering, wrong project/key use, expired leases, capsule replay,
  and cross-session lease use fail closed and have regression coverage.
- File-secret policies reject absolute/traversing/separator names, duplicate
  targets and filenames, while output redaction covers literal and encoded file
  contents without injecting those contents as environment variables.

### Fixed
- The TUI now reserves space for its action bar and input/approval prompts in
  short embedded terminals instead of clipping the controls below the viewport.
- macOS Keychain writes now use deterministic binary data input instead of the
  interactive `security` prompt path, which could create an empty credential
  when run without a terminal.

## [0.3.0] - 2026-06-24

The first release since 0.2.0, and a big one: more exfiltration paths are closed,
agents can request commands without bypassing the seal, and every sealed run
leaves a tamper-evident trail.

### Added
- **Propose-and-approve.** A `propose_command` MCP tool lets an agent stage a
  command it needs (to `.ironrun/pending.yml`) instead of running it in a raw
  shell. Review with `ironrun review`; decide with `ironrun approve <id>` /
  `ironrun reject <id>`. Gated by the `allow_proposals` policy field (off for
  existing policies; new ones enable it). An unapproved command is never
  executed, and an agent can never self-approve.
- **Policy linter — `ironrun lint`.** Flags risky policies: shell or
  general-interpreter argv, eval-with-secrets, missing `ttl`, open egress with
  secrets, hardcoded credentials in argv, and a secret spread across many
  commands. Supports `--format json` and `--strict` (warnings become errors).
- **Tamper-evident audit log.** Every sealed run appends a SHA-256 hash-chained
  JSONL entry recording the command id, argv, env var *names*, redaction/entropy
  counts, exit code, duration, kill reason, and seccomp/`no_network` flags —
  **never secret values**. `ironrun audit verify` replays the chain and reports
  the first tampered line. Configure with the `audit_log` policy field or
  `IRONRUN_AUDIT_LOG` (`off` to disable); defaults to
  `~/.local/state/ironrun/audit.log`.
- **Smart `ironrun init`.** Generates the policy from the project's real task
  runner (package.json scripts, Makefile targets; Go/Rust/Python defaults), and
  the agent-instruction files (`CLAUDE.md`/`AGENTS.md`/`.cursorrules`) reference
  the actual command ids instead of stale examples.
- **HashiCorp Vault provider** (`vault://<path>#<field>`, KV v2 via the `vault`
  CLI; reads `VAULT_ADDR`/`VAULT_TOKEN`).
- **`ironrun doctor`** — read-only setup diagnostics: validates the policy,
  checks the provider is installed and authenticated, runs a redaction
  self-test, and verifies every command's binary resolves on PATH.
- `init` writes `AGENTS.md` and `.cursorrules` (Codex/Cursor guardrails) plus an
  `examples/` directory of runnable starter policies.

### Changed
- **Redaction now catches encoded secret forms** — base64 (standard/URL, padded
  and unpadded), hex (upper/lower), and URL-escaping — of any secret ≥ 8 bytes,
  not just the literal value. Length-gated to avoid false positives.

### Security
- **`no_network` is now fail-closed.** If isolation cannot be enforced
  (unsupported platform, missing `sandbox-exec` on macOS, disabled Linux user
  namespaces), the run is **refused** rather than silently executed with the
  network open. Covered by tests (a dialer fixture) and a macOS CI leg.
- **seccomp syscall filtering (Linux).** Sealed commands run under a seccomp
  filter that blocks memory-inspection / escape syscalls (`ptrace`,
  `process_vm_readv`/`writev`, `kcmp`, `perf_event_open`, `bpf`, `userfaultfd`).
  On by default; control it with the per-command `seccomp` or top-level
  `seccomp_default` policy field, or `IRONRUN_SECCOMP=off`. Linux amd64/arm64;
  a no-op elsewhere; fails open with a warning if the filter can't install.
- **High-entropy output warnings.** After redaction, output is scanned for
  high-entropy tokens (≥ 3.5 bits/char, 20+ chars, excluding UUIDs/SHAs) that may
  be an unredacted secret, and a warning is emitted. Warn-only — it never alters
  output. Disable with `IRONRUN_ENTROPY_SCAN=off`.
- Resolved secret values shorter than 4 bytes are skipped (with a warning) rather
  than redacted — a 1-3 byte value would corrupt unrelated output while
  protecting nothing real.

### Fixed
- `init` now writes/merges Claude Code's MCP config into **`.mcp.json` at the
  repo root** (the file Claude Code actually reads) instead of `.claude/mcp.json`,
  which was silently ignored. Existing servers are preserved.
- README: corrected the Codex registration command
  (`codex mcp add ironrun -- ironrun mcp`) and the Claude Code config path.

### Distribution
- Homebrew is deferred until ironrun is notable enough for homebrew-core; install
  via the curl installer (checksum-verified) or `go install`.

## [0.2.0] - 2026-06-14

Initial public release: agent-safe sealed command execution.

### Added
- Sealed command execution: secrets resolved from a provider, injected into the
  child process environment, and redacted from all stdout/stderr before the
  agent sees them.
- Providers: 1Password, Doppler, Infisical, env, envfile, passthrough.
- Policy file (`ironrun.yml`): exact-argv allowlist, per-command TTL,
  `max_bytes` output cap, best-effort `no_network` isolation.
- MCP stdio server (`ironrun mcp`) exposing `run_sealed` to Claude Code, Cursor,
  and Codex — agents run commands, never read secrets.
- GitHub Action with fork-PR / `pull_request_target` secret-exposure guards.
- Rolling-buffer redaction engine that catches secrets split across write
  boundaries.

[Unreleased]: https://github.com/generalized-labs/ironrun/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/generalized-labs/ironrun/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/generalized-labs/ironrun/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/generalized-labs/ironrun/releases/tag/v0.2.0
