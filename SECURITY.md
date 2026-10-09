# Security policy

## Supported versions

Security fixes are provided for the latest stable Ironrun release. During the
v1 release-candidate period, fixes are also provided for the latest v1 RC.

| Version | Supported |
| --- | --- |
| Latest stable | Yes |
| Latest v1 RC | Yes, until v1 GA |
| Older releases | No |

## What Ironrun protects

Ironrun is a local, tool-boundary security system. It is designed to keep
secret values out of agent context, transcripts, routine terminal output,
policies, metadata, audit records, and Git history while still letting an
approved child command use them.

Ironrun provides:

- encrypted, project-scoped environment and file-secret storage;
- exact command and environment authorization;
- revocable, session-bound strict leases and trusted workspace sessions;
- child-command-only value and temporary-file injection;
- literal and encoded output redaction;
- value-blind project, request, policy, daemon, and audit interfaces; and
- owner-only local state and authenticated same-user daemon access.

Secret values are intentionally not revealable, copyable, printable, or
exportable through the CLI, TUI, MCP server, local API, daemon, or audit log.

## Threat boundary

Ironrun protects tool-mediated execution and reduces accidental or
prompt-driven disclosure. It does not contain a fully hostile process that is
already running as the same operating-system user. Depending on the platform,
such a process may inspect another process, user-owned files, input devices, or
IPC. Use an external OS sandbox, isolated user account, container, or virtual
machine when the agent itself is not trusted at that boundary.

The per-user daemon verifies the peer user ID on supported Unix platforms and
exposes value-blind RPC schemas. The foreground native TUI writes masked input
directly to the encrypted vault; secret values are never sent to the daemon.

Trusted workspace sessions are deliberately broad: a human grants one MCP
session arbitrary argv against the selected project environment. They reduce
day-to-day approval friction but do not prevent a deliberately malicious trusted
process from transforming and printing a secret, and because the session can run
`ironrun` itself, a grant should be treated as authority over the whole project.
Pause or revoke a session from the TUI or `ironrun trust` as soon as it is no
longer needed.

An executable upgrade necessarily requires starting a process from the new
binary. Once v1 is running, policy approval, secret fulfillment, lease approval,
revocation, and retry do not require an MCP client or application restart.

## Known limitations

These follow from the threat boundary above and are documented so nobody relies
on a property Ironrun does not provide:

- **Redaction matches known values.** Literal, encoded (base64 at every
  alignment, hex, URL, JSON), whitespace-interleaved, and partial forms of
  injected values are redacted. A process that applies an arbitrary
  transformation (reversal, compression, encryption) before printing defeats it.
  Partial prints of values shorter than 24 bytes are not covered.
- **Agent-writable state.** Approval state (`ironrun.yml`, `.ironrun/`) lives in
  the project. An agent with unrestricted file-edit or shell tools can change it;
  pair Ironrun with the agent host's own permission rules or sandbox.
- **Same-user credential stores.** On macOS, a keychain item created through
  `/usr/bin/security` can be read by any same-user process that invokes it. The
  legacy version-1 file store keeps its key beside its ciphertext.
- **Rollback and truncation.** The vault manifest MAC and the audit hash chain
  detect modification, not replacement with an older valid copy or deletion of
  the newest audit records.
- **CI events.** Fork detection covers `pull_request`, `pull_request_review`,
  `pull_request_review_comment`, and `workflow_run` payloads; `issue_comment`
  workflows that check out pull-request code must gate themselves.

## File-secret limitations

During an approved command, a file secret exists temporarily as plaintext in a
unique owner-only directory outside the repository. Ironrun rejects unsafe
names, traversal, separators, absolute paths, and symlinks, and removes the run
directory after success, error, timeout, or cancellation. Validated stale run
directories are recovered at startup.

Deletion cannot guarantee physical erasure from SSDs, copy-on-write filesystems,
snapshots, swap, backups, or storage-controller caches. Do not claim otherwise.

## Responsible disclosure

Please do not open a public issue for a suspected vulnerability or include a
real secret in a report, fixture, screenshot, recording, or reproduction.

Use GitHub's private vulnerability reporting for this repository. Include:

- the affected version and platform;
- the smallest value-free reproduction you can provide;
- the expected and observed security boundary; and
- whether you believe secret material may have been exposed.

We will acknowledge a complete report as soon as practical, coordinate a fix
and disclosure timeline, and credit reporters who want public attribution.

## Security development gates

Every release must pass the automated, product, human, platform, and publication
checks in [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md). A green unit
test suite alone is not authorization to publish a GA release.
