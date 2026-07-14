# ironrun Security Model

## Threat model (v0)

ironrun v0 targets a specific, well-scoped threat: **accidental secret exposure via stdout/stderr in AI-agent workflows.**

### In scope (protected)

| Vector | Protection |
|---|---|
| `env` / `printenv` in child process | Rolling-buffer redactor strips all registered secret values from output |
| `cat /proc/self/environ` | Same redactor |
| Secret appearing in any stdout/stderr line | Redactor replaces all occurrences with `[REDACTED]` |
| Shell command execution (sh/bash/zsh) | Denied at argv level before exec — no shell expansion possible |
| Fork PR secret exposure in GitHub Actions | Fail-closed CI trust gate: fork PRs never get secrets injected |
| `pull_request_target` secret exposure | Denied unless `IRONRUN_ALLOW_PRT=1` set explicitly |
| Unauthorized command IDs | Exact argv matching — no command runs unless in policy |
| Common encoded forms of a secret in output (base64, hex, URL-encoded) | Redacted — the runner registers these encodings of each value alongside the literal (see "Redaction notes"). |
| Sealed process reading another process's memory (ptrace, `process_vm_readv`) | Blocked by a seccomp denylist on Linux (see "Syscall hardening"). |
| Repository, Git history, or offline copy of a project environment vault | Values and key names are encrypted with per-environment AES-256-GCM data keys; the project root key remains in the native OS credential manager. |
| Agent self-authorizing secret or command access | MCP can create requests but cannot approve them. Optional leases require local human approval and are bound to session, environment, command set, and expiry. |
| Revoked or expired agent capability | Checked immediately before sealed execution; restart creates a distinct MCP session. |
| Secret supplied through chat | Safe only as an `ir1.` capsule encrypted locally before it enters chat; capsules are project/request/session-bound, short-lived, and one-use. |
| Local curl control | Owner-only Unix socket, exact policy command IDs, bounded/strict JSON, no plaintext-secret endpoint, and non-cacheable responses. |

### Defense in depth (v1)

| Layer | What it adds |
|---|---|
| seccomp syscall filter (Linux) | Default-deny of `ptrace`, `process_vm_readv`/`writev`, `kcmp`, `perf_event_open`, `bpf`, `userfaultfd` in the sealed child. Best-effort: fails open with a warning on unsupported kernels. Toggle with `seccomp:` per command, `seccomp_default:`, or `IRONRUN_SECCOMP=off`. |
| Multi-encoding redaction | base64 (std/raw/url), hex, and URL-encoded forms of each secret are redacted in addition to the literal. |
| Entropy warn pass | After redaction, a Shannon-entropy scan flags high-entropy tokens that survived (a possible unredacted secret). Warn-only — it never alters output. Disable with `IRONRUN_ENTROPY_SCAN=off`. |
| Tamper-evident audit log | Append-only, SHA-256 hash-chained record of each run (command, argv, secret **names** only, counts, exit/kill reason). `ironrun audit verify` detects edits. Configure with `IRONRUN_AUDIT_LOG` / `audit_log:`. |
| `ironrun lint` | Flags risky policy patterns (shell/interpreter argv, missing ttl, secrets with open egress, hardcoded creds in argv, secret spread) before they ship. |
| Encrypted project vault | Per-environment data keys, project-root key wrapping, authenticated manifest, atomic fsync+rename commits, and lazy commit-before-delete migration from legacy native records. |
| Agent access ledger | Atomic request/lease state stores names and scopes only. Lease approval and secret fulfillment remain local human actions. |

### Out of scope (v1)

| Vector | Status |
|---|---|
| Network exfiltration by approved binary | Best-effort via `no_network: true` (Linux: network namespace; macOS: sandbox-exec). No per-destination egress allowlist yet. |
| Other custom encodings/transforms of a secret in output | Only base64/hex/URL forms are registered; a binary that applies a bespoke transform (e.g. ROT, compression, chunked split) can still bypass literal matching. |
| Secrets written to disk by child | Not prevented |
| Side-channel leaks (timing, cache) | Not prevented |
| Malicious binary substitution | Not prevented (PATH is inherited) |
| Memory scraping of the ironrun process by an external attacker | Not prevented — seccomp constrains the sealed child, not other processes on the host. |
| Same-user inspection of short-lived credential-manager helper arguments on macOS | Not prevented. Ironrun hex-encodes protected vault/capsule keys for deterministic Keychain writes; they are not written to project files or Ironrun logs, but a host process with sufficient inspection rights may observe the helper while it runs. |
| Plaintext secret already pasted into a chat | Cannot be removed retroactively. Rotate it; future transfers should use local masked entry or a pre-encrypted capsule. |
| Provider-level credential revocation | Revoking an Ironrun lease blocks future Ironrun use, but does not invalidate an upstream credential already disclosed elsewhere. Rotate/delete it with the provider. |
| Rollback of the entire vault plus matching host credential state | Manifest tampering is detected, but a fully compromised user account can restore older ciphertext and credential-manager state together. |

### Encrypted vault and capsule notes

Ironrun defines a versioned storage format and key lifecycle, not a new cipher.
The implementation uses the Go standard library's AES-256-GCM and random nonces.
Associated data binds wrapped environment keys and ciphertext to the format,
project identity, and environment scope. Rewriting an environment rotates its
data key. Deleting the scope removes both its wrapped key and ciphertext from
the next atomically committed revision.

The manifest is authenticated with HMAC-SHA-256. Vault changes are written to an
owner-only temporary file, synced, renamed, and followed by a best-effort parent
directory sync. A pre-existing vault without its protected root key fails closed
instead of silently generating a replacement key.

An encrypted chat capsule contains one value plus its request, environment,
alias, MCP session, and expiry. Those fields are authenticated together. The
MCP claim path verifies all bindings against the still-pending local request,
stores the value below model visibility, then closes the request to reject
replay. Ordinary MCP form fields must never be used for passwords or API keys.

### Redaction notes

The rolling-buffer redactor holds back `(max_secret_len - 1)` bytes at each Write boundary, ensuring secrets split across write calls are still caught. After the child exits, all buffered bytes are flushed and redacted.

The redactor matches **literal** secret bytes. For each value it also registers the common encoded forms — base64 (std/raw, url/raw-url), lower/upper hex, and URL escaping — so a process that base64-, hex-, or URL-encodes a secret before printing it is still caught (only for values ≥ 8 bytes, to keep derivations specific). Bespoke transforms outside that set (custom encodings, compression, splitting the value across unrelated output) still defeat redaction: ironrun guards against accidental leakage in common forms, not an actively hostile binary that invents an arbitrary transform.

After redaction, an optional entropy pass scans the (already redacted) output for high-entropy, secret-shaped tokens that slipped through and emits a warning with the token's offset — never the token itself, and never modifying the output. Benign shapes (UUIDs, git SHAs, timestamps) are allowlisted to limit noise.

Empty strings are not registered as secrets (they would match everything). Secrets resolved to empty strings from your provider log a warning and are skipped. Values shorter than 4 bytes are likewise skipped with a warning — redacting a 1-3 byte value would corrupt unrelated output while protecting nothing real (genuine credentials are never that short).

### Network isolation

`no_network: true` is a **fail-closed** control: if isolation cannot be enforced, ironrun **refuses to run** the command rather than execute it with the network open (returning `ErrNoNetworkUnsupported`).

- **Linux**: Uses `CLONE_NEWNET` (new network namespace with no interfaces). Requires unprivileged user namespaces (default on ubuntu-latest, Debian 11+, Fedora). The loopback interface exists but has no external connectivity. If the namespace cannot be created (userns disabled — surfaces as `EPERM` at exec), the run is refused.
- **macOS**: Uses `sandbox-exec` with a deny-all *network* Seatbelt profile. This restricts network only — the child can still read and write the filesystem. If `sandbox-exec` is not present on the host, the run is refused.
- **Other platforms (including Windows)**: no isolation mechanism is available, so a `no_network: true` command is refused.

This is exercised by tests (`internal/runner/net_test.go`): a fixture that attempts an outbound connection is confirmed blocked under `no_network`, and the macOS fail-closed path is verified when `sandbox-exec` is unavailable.

### Syscall hardening

On Linux, the sealed child runs under a seccomp-bpf filter. ironrun re-executes
itself as a tiny shim (see `internal/sealedexec`) that sets `no_new_privs` and
installs the filter, then `execve`s the real target in place — so the filter and
the network namespace apply to the target while the TTL kill still lands on it
(same PID). No root is required. The filter is a **denylist** returning `EPERM`
for `ptrace`, `process_vm_readv`/`process_vm_writev`, `kcmp`, `perf_event_open`,
`bpf`, and `userfaultfd`; everything else is allowed, so ordinary build/test/deploy
commands are unaffected. It is **best-effort**: on a kernel or sandbox that
rejects the filter, ironrun logs a warning and continues (the redaction and
argv/env guarantees do not depend on it). Disable per command with `seccomp: false`,
policy-wide with `seccomp_default: false`, or globally with `IRONRUN_SECCOMP=off`.
seccomp is Linux-only; macOS and Windows skip it.

### Audit log

Every run appends one JSON line to a tamper-evident, SHA-256 hash-chained log
(each record carries the hash of the previous one). Records contain the command
id, argv, the **names** of injected secrets (never their values), redaction and
entropy-warning counts, exit code, duration, kill reason, and whether seccomp was
requested. `ironrun audit verify` walks the chain and reports the first broken
record. The log defaults to the per-user state directory
(`$XDG_STATE_HOME/ironrun/audit.log`); override with `IRONRUN_AUDIT_LOG=<path|off>`
or the top-level `audit_log:` policy field. The chain is tamper-*evident*, not
tamper-*proof* — an attacker who can rewrite the whole file can recompute every
hash; it exists to detect after-the-fact edits.

### Reporting vulnerabilities

Please email security@generalized-labs.com with subject `[ironrun] Security`.
