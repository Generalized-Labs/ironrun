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

### Out of scope (v0)

| Vector | Status |
|---|---|
| Network exfiltration by approved binary | Best-effort via `no_network: true` (Linux: network namespace; macOS: sandbox-exec). Not enforced on other platforms. |
| Secrets written to disk by child | Not prevented |
| Side-channel leaks (timing, cache) | Not prevented |
| Malicious binary substitution | Not prevented (PATH is inherited) |
| Memory scraping of the ironrun process | Not prevented |

### Redaction notes

The rolling-buffer redactor holds back `(max_secret_len - 1)` bytes at each Write boundary, ensuring secrets split across write calls are still caught. After the child exits, all buffered bytes are flushed and redacted.

Empty strings are not registered as secrets (they would match everything). Secrets resolved to empty strings from your provider will log a warning and be skipped.

### Network isolation

`no_network: true` is best-effort:

- **Linux**: Uses `CLONE_NEWNET` (new network namespace with no interfaces). Requires unprivileged user namespaces (default on ubuntu-latest, Debian 11+, Fedora). The loopback interface exists but has no external connectivity.
- **macOS**: Uses `sandbox-exec` with a deny-all network Seatbelt profile. Can be bypassed by privileged processes.
- **Other platforms**: No isolation applied; a warning is emitted to stderr.

### Reporting vulnerabilities

Please email security@generalized-labs.com with subject `[ironrun] Security`.
