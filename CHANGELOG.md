# Changelog

All notable changes to ironrun are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Smart `ironrun init`** — generates the policy from the project's real task
  runner (package.json scripts, Makefile targets; Go/Rust/Python defaults) and
  writes agent instructions (`CLAUDE.md`/`AGENTS.md`/`.cursorrules`) that
  reference the actual command ids instead of stale examples.
- **Propose-and-approve** — a `propose_command` MCP tool lets an agent stage a
  command it needs (to `.ironrun/pending.yml`) instead of bypassing to a raw
  shell. The human reviews with `ironrun review` and decides with
  `ironrun approve <id>` / `ironrun reject <id>`. Gated by `allow_proposals`
  (off for existing policies; new policies enable it). An unapproved command is
  never executed, and an agent can never self-approve.

### Security
- **`no_network` is now fail-closed.** If isolation cannot be enforced
  (unsupported platform, missing `sandbox-exec` on macOS, disabled Linux user
  namespaces), the run is **refused** rather than silently executed with the
  network open. Covered by tests (a dialer fixture) and a macOS CI leg.

## [0.3.0] - 2026-06-24

### Added
- HashiCorp **Vault** provider (`vault://<path>#<field>`, KV v2 via the `vault`
  CLI; reads `VAULT_ADDR`/`VAULT_TOKEN`).
- **`ironrun doctor`** — read-only setup diagnostics: validates the policy,
  checks the provider is installed and authenticated, runs a redaction
  self-test, and verifies every command's binary resolves on PATH.
- `init` now writes `AGENTS.md` and `.cursorrules` so the "use `run_sealed`"
  guardrail nudge fires for Codex and Cursor, not just Claude Code.
- `examples/` directory with runnable starter policies.

### Fixed
- `init` now writes/merges Claude Code's MCP config into **`.mcp.json` at the
  repo root** (the file Claude Code actually reads) instead of
  `.claude/mcp.json`, which was silently ignored. Existing servers are
  preserved.
- README: corrected the Codex registration command
  (`codex mcp add ironrun -- ironrun mcp`) and the Claude Code config path.

### Security
- Resolved secret values shorter than 4 bytes are skipped (with a warning)
  rather than redacted — a 1-3 byte value would corrupt unrelated output while
  protecting nothing real.
- SECURITY.md documents the literal-only redaction limit (base64/hex/URL-encoded
  forms are not caught) and clarifies that macOS `no_network` restricts network
  only, not disk.

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
