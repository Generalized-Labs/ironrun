# Concepts

The mental model behind ironrun: what it guarantees, how the pieces fit,
and where the guarantees end. For the implementation, see
[ARCHITECTURE.md](ARCHITECTURE.md).

## Sealed execution

Every secret-bearing command runs as a *sealed child*: a subprocess launched
through a hardened path that, before `exec`, applies `RLIMIT_CORE=0` (core
dumps would contain the child's full address space, secrets included — the
limit survives `execve`, verified) and installs a seccomp denylist blocking
the child's `ptrace(2)`, `process_vm_readv/writev`, and related
memory-read syscalls so the child can't reach back into the host. Network
access is default-deny for secret-bearing commands on Linux (a command keeps
network only with explicit `allow_network: true`).

What the seal deliberately does *not* claim: `PR_SET_DUMPABLE=0` was
evaluated and rejected — the flag lives in `mm_struct`, which `execve`
replaces, so it doesn't survive into the target (verified with a kernel
reproducer). A same-UID debugger can therefore still attach to the child;
that direction is the host's Yama `ptrace_scope` setting, not something a
launcher flag can fix. Same-UID `/proc/<pid>/environ` reads are likewise a
documented residual risk. The `--no-seal` escape hatch exists for post-mortem
core debugging and is logged loudly.

## Below-visibility injection

Secrets resolve into the *child process's environment only*. They never pass
through your shell (no `export`, no history entry), never appear in argv or
process lists, and never reach the agent's context. This is the one blessed
pattern — `ironrun run -- <cmd>` works identically for humans, CI, and
agents — because it's the only model where the thing running the command
never holds the credential.

## Redaction

Everything the child prints on stdout/stderr passes through the redactor
before anyone sees it: managed values and their encoded variants are replaced
with `[REDACTED]`. A post-run entropy scan flags high-entropy output that
*looks* like an unredacted secret (stderr warning — investigate before
sharing). Redaction is a backstop, not the primary defense; the primary
defense is that values never leave the vault except into a sealed child's
environment.

## Environments

An environment is a named set of secrets (`dev`, `staging`, `prod`…),
encrypted at rest in the local vault. `ironrun new NAME` creates one,
`ironrun use NAME` selects it, `ironrun env set KEY` stores a value via
masked prompt. Sessions (`ironrun session`) are environments with an expiry.
`ironrun.yml` references secrets by name; `run --set NAME` selects the
environment per invocation. Names are visible (`ironrun env list`); values
never are — there is no command that prints one.

## Policy: the allowlist model

`ironrun.yml` is a policy file, safe to commit: command IDs with fixed argv,
secret-name bindings, TTLs, network posture. Agents may only run declared
command IDs — arbitrary argv requires a lease you explicitly approve (see
below), and shell-string commands are denied at runtime. `ironrun validate`
checks the file without executing anything; `ironrun lint` runs the security
checks; `ironrun doctor` verifies the live setup (provider auth, redaction
actually stripping a canary, binaries on PATH).

## Leases and approvals

For agent workflows, commands carrying secrets additionally require a
time-boxed *lease*: the agent calls `request_lease` (via MCP) with command
IDs, a reason, and a TTL; the request waits in your inbox until you approve
or deny it. Leases bind to the exact MCP session, environment, and command
set, and they expire. `ironrun trust` grants longer-lived sessions you
choose; everything is revocable (`ironrun agents revoke LEASE_ID`). The
default is deny — convenience is opt-in, per session, with an expiry.

## Audit log

Every run appends to a tamper-evident, value-blind audit log: a SHA-256 hash
chain (each record commits to the previous one), verified on open —
`ironrun audit verify` detects retroactive edits. Records contain command
IDs, secret *names*, timestamps, and outcomes — never values. The log path is
set via the `audit_log:` policy field, deliberately not via environment
variable (an agent-inherited env var could silently redirect or disable the
one record that must survive agent interference).

## Honest limits

What ironrun does *not* claim:

- **Same-UID observers.** Another process running as you can read
  `/proc/<pid>/environ` and can ptrace the child (see "Sealed execution").
  The threat model is the *agent* and the *transcript*, not a hostile
  same-user process. Shared boxes want `hidepid=2` / UID separation (your
  sysadmin's call).
- **Values the agent generates itself.** If the model invents a credential
  (or you paste one into chat), it was never in the vault — nothing can
  redact it from provider-side logs. Rotate it; `ironrun agent-scrub`
  exact-match scrubs local transcript stores afterward.
- **Must-see values.** If a workflow genuinely requires a human to read a
  value, ironrun refuses to be the conduit — that's the product's reason to
  exist. Handle it outside any agent session.
- **Screenshots, clipboard, shoulder-surfing.** Out of scope to enforce;
  the invariant is that ironrun itself never displays, copies, or exports
  a value.

Stating these plainly is the trust story: the guarantees above are real and
auditable precisely because they don't pretend to cover everything.
