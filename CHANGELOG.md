# Changelog

All notable changes to ironrun are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed
- CLI, MCP, and the local API now share one sealed execution core.
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

### Fixed
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

[Unreleased]: https://github.com/generalized-labs/ironrun/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/generalized-labs/ironrun/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/generalized-labs/ironrun/releases/tag/v0.2.0
