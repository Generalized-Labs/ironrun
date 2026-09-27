# Windows: unsupported in the OSS launch

**Status: Windows is not supported.** ironrun targets Linux and macOS for the
open-source launch. This document records what fails on Windows and why, so
the cut is explicit rather than a silent degradation. Half-supported is worse
than unsupported.

## Why Windows was cut

ironrun's security model rests on platform primitives that do not exist on
Windows, and the one that could have been faked (terminal masking) failed
silently. Rather than ship a beta that quietly offered less protection, the
launch cuts Windows entirely: secret-input commands refuse to run there.

## What fails on Windows, and why

| Area | Behavior on Windows | Why |
|---|---|---|
| Secret input (`secrets set`/`rotate`, `env set`/`rotate`/`file`, `agents fulfill`, `add`, `share`) | **Hard error, exit 1:** `Windows is not supported by ironrun: terminal input cannot be masked securely on this platform` | The old code ran `stty -echo` and *discarded the error*; `stty` does not exist on Windows, so secrets were typed in cleartext while the prompt claimed "input hidden". Masking now fails loudly on every platform instead of degrading. (`cmd/ironrun/secrets.go`) |
| Persistent daemon | `ErrUnsupported` — the daemon is not supported on this platform | No Windows socket/peer-credential equivalent was implemented. (`internal/daemon/server_windows.go`) |
| Seccomp syscall filter | No-op | There is no Linux-seccomp equivalent on Windows. (`internal/runner/seccomp_other.go`) |
| Network isolation | No-op | Linux network namespaces do not exist on Windows. (`internal/runner/net_other.go`) |
| Audit log locking | Best-effort | Windows has no `flock`; locking relies on `O_APPEND` atomicity plus an in-process mutex. Cross-process concurrency is not guaranteed. (`internal/audit/lock_windows.go`) |
| Secret storage backends | No OS credential store | The keychain backend is macOS-only (`security` CLI); on Windows secrets fall back to the encrypted envfile backend. |

## What would be needed to support Windows later

1. **Terminal masking**: use `golang.org/x/term.ReadPassword` (already an indirect dependency via the charm libraries) or the Win32 console API (`SetConsoleMode` without `ENABLE_ECHO_INPUT`). This is the launch-blocker-class item — no secret may ever be read via a cleartext fallback.
2. **Daemon IPC**: a Windows transport (named pipes) with a peer-authentication story equivalent to Unix socket peer credentials.
3. **Execution isolation**: a Windows sandboxing story to replace Linux network namespaces + seccomp (job objects / AppContainers / WSL2), with honest per-primitive degradation docs.
4. **Audit integrity**: a cross-process locking primitive for the audit log (e.g. file-range locking via Win32).
5. **Release artifacts**: re-add the Windows targets to `.goreleaser.yml` and the CI matrix (`.github/workflows/ci.yml`), and restore a documented install path.

Until those land, `go build` still compiles for Windows (`GOOS=windows go build ./...`
must stay green) — the decision is runtime refusal plus documented unsupported
status, not a compile break.
