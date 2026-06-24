# ironrun Security Model

## Threat model (v0)

ironrun v0 targets a specific, well-scoped threat: **accidental secret exposure via stdout/stderr in AI-agent workflows.**

### In scope (protected)

| Vector | Protection |
|---|---|
| `env` / `printenv` in child process | Rolling-buffer redactor strips all registered secret values from output |
| `cat /proc/self/environ` | Same redactor |
| Secret appearing in any stdout/stderr line | Redactor replaces all occurrences with `[REDACTED]` |
| Common ENCODINGS of a secret (base64, hex, URL-encoded) | Best-effort: the runner also registers base64 (std/url, padded/unpadded), hex, and URL-escaped forms of each resolved secret, length-gated to avoid false positives |
| Shell command execution (sh/bash/zsh) | Denied at argv level before exec — no shell expansion possible |
| Fork PR secret exposure in GitHub Actions | Fail-closed CI trust gate: fork PRs never get secrets injected |
| `pull_request_target` secret exposure | Denied unless `IRONRUN_ALLOW_PRT=1` set explicitly |
| Unauthorized command IDs | Exact argv matching — no command runs unless in policy |

### Out of scope (v0)

| Vector | Status |
|---|---|
| Network exfiltration by approved binary | Best-effort via `no_network: true` (Linux: network namespace; macOS: sandbox-exec). Not enforced on other platforms. |
| Uncommon/custom transforms of a secret (gzip, encryption, char-substitution, chunk-splitting) | Not redacted — only the literal value and its common base64/hex/URL encodings are registered. An actively hostile binary can still re-encode a secret in a form we don't anticipate. |
| Secrets written to disk by child | Not prevented |
| Side-channel leaks (timing, cache) | Not prevented |
| Malicious binary substitution | Not prevented (PATH is inherited) |
| Memory scraping of the ironrun process | Not prevented |

### Redaction notes

The rolling-buffer redactor holds back `(max_secret_len - 1)` bytes at each Write boundary, ensuring secrets split across write calls are still caught. After the child exits, all buffered bytes are flushed and redacted.

Beyond the literal value, the runner also registers each secret's **common encodings** — base64 (standard/URL alphabets, padded and unpadded), hex (upper/lower), and URL escaping — so a command that prints, say, a base64-wrapped token is still caught. To avoid over-redaction, encoded variants must be at least 8 bytes and hex variants require a secret of at least 8 bytes (an 8-hex string is indistinguishable from a git short SHA). This is best-effort: an actively hostile binary that applies a transform we don't anticipate (compression, encryption, character substitution, splitting the value across chunks of its own choosing) can still defeat it. ironrun guards against accidental and common-encoding leakage, not an adversary purpose-built to exfiltrate.

Empty strings are not registered as secrets (they would match everything). Secrets resolved to empty strings from your provider log a warning and are skipped. Values shorter than 4 bytes are likewise skipped with a warning — redacting a 1-3 byte value would corrupt unrelated output while protecting nothing real (genuine credentials are never that short).

### Network isolation

`no_network: true` is a **fail-closed** control: if isolation cannot be enforced, ironrun **refuses to run** the command rather than execute it with the network open (returning `ErrNoNetworkUnsupported`).

- **Linux**: Uses `CLONE_NEWNET` (new network namespace with no interfaces). Requires unprivileged user namespaces (default on ubuntu-latest, Debian 11+, Fedora). The loopback interface exists but has no external connectivity. If the namespace cannot be created (userns disabled — surfaces as `EPERM` at exec), the run is refused.
- **macOS**: Uses `sandbox-exec` with a deny-all *network* Seatbelt profile. This restricts network only — the child can still read and write the filesystem. If `sandbox-exec` is not present on the host, the run is refused.
- **Other platforms (including Windows)**: no isolation mechanism is available, so a `no_network: true` command is refused.

This is exercised by tests (`internal/runner/net_test.go`): a fixture that attempts an outbound connection is confirmed blocked under `no_network`, and the macOS fail-closed path is verified when `sandbox-exec` is unavailable.

### Reporting vulnerabilities

Please email security@generalized-labs.com with subject `[ironrun] Security`.
