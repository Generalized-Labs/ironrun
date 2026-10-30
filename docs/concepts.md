# Concepts

Ironrun gives authorized child commands access to credentials and filters their
captured output. The child receives real values. Authorization, output filtering,
and platform controls address different parts of that workflow; none makes
arbitrary trusted code safe. See [SECURITY.md](../SECURITY.md) for the threat model
and [ARCHITECTURE.md](ARCHITECTURE.md) for implementation details.

## Sealed execution and platform controls

On Linux, the default core-dump seal applies `RLIMIT_CORE=0` before executing a
secret-bearing child. The Linux seccomp filter restricts the child's
`ptrace`, process-memory, and related syscalls when enabled. In the Linux sealed
execution path, a requested filter or seal that cannot be installed prevents the
target child from executing. The `--no-seal` and `--disable-seccomp` operator flags
weaken these controls and produce warnings. macOS provides network-only Seatbelt
controls, not the Linux core-dump seal or syscall filter.

Saved policy commands carrying secrets use network isolation by default unless
their policy permits networking. If requested network isolation cannot be
established, execution fails. An approved **trusted workspace** instead has
normal network access, as its approval screen promises. Saved commands retain
their own network policies even when the session also has a workspace grant.

These controls do not contain all file access, local IPC, same-user observers,
or detached descendants. Cleanup targets the original process group. On Linux,
host permissions and settings such as Yama determine whether a same-user process
can inspect the child; launcher flags do not replace that protection.

## Credential injection

Ironrun resolves configured values for the child rather than requiring them in
the agent's command arguments. Environment entries become child environment
variables. File entries become plaintext files in an owner-only temporary
directory, with their paths passed to the child. Normal cleanup removes those
files, and stale-run recovery can remove crash remnants; removal is not a
physical-erasure guarantee.

The child can use the real credential. Malicious or compromised authorized code
can transform it, write it to a file, or send it over an available network.
Protect the executable, its dependencies and inputs, and the surrounding host.

## Output filtering

Intercepted stdout and stderr pass through the redactor. It recognizes
registered values and supported encodings and replaces matching spans with
`[REDACTED]`. Minimum lengths, fragment thresholds, tier priority, overlapping
patterns, and unsupported transformations limit coverage. Output below an
evaluation threshold is not necessarily free of sensitive fragments.

The post-run entropy scan warns about some high-entropy output; it is advisory,
not a detector for every credential. The streaming algorithm retains bounded
lookahead bytes under its stated assumptions. That byte bound does not bound
wall-clock delay for quiet interactive commands. Files, screenshots, network
traffic, and values pasted directly into a conversation are outside this output
filter. See [REDACTION_WALKTHROUGH.md](REDACTION_WALKTHROUGH.md).

## Project environments and diagnosis

An environment is a project-scoped set of encrypted entries, such as `dev` or
`staging`. `ironrun env init dev` registers the project and selects its first set;
`ironrun env create NAME` creates another, and `ironrun env use NAME` selects it.
`ironrun env set dev KEY` accepts masked input. Temporary sets can be created
with `ironrun env create NAME --temporary --ttl 2h`. Policy files refer to entry
names; `ironrun run COMMAND_ID --set NAME` selects a set for one saved-command run.
Keep plaintext values out of policy files and agent-authored arguments.

`ironrun validate` parses the policy without executing its saved commands.
`ironrun doctor` also tests the redactor, resolves saved-command binaries on PATH,
and checks relevant local environment metadata: project identity, selection,
expiry, and required entry names. It prints repair commands when possible.
Those local checks do **not** open the vault, resolve values, execute saved
commands, or change files. They cannot establish decryption or application
authentication. Legacy provider installation/authentication checks remain where
the provider supports them.

## Saved commands and trusted workspaces

`ironrun run COMMAND_ID` executes the saved argv for that policy ID; `exec` is an
alias for this same interface. It is not an arbitrary shell-command wrapper.
MCP callers use `run_sealed` with `command_id` for the saved-command path. A
policy can additionally require session-bound leases with
`require_agent_leases: true`. `propose_command` stages a proposed command for
human review and does not execute it.

For broader development work, an MCP caller can request workspace access, or
call `run_sealed` with exact `argv` and wait for approval. The human can approve
with `ironrun trust grant REQUEST_ID`. This grants arbitrary argv with the
selected environment and normal network access; it includes the ability to run
Ironrun itself. Treat it as broad authority over the project. Requests normally
have a 15-minute review deadline; the default approved workspace duration is two
hours. The review deadline and access duration are different limits.

Grants bind to the MCP session, project, environment, and expiry. Restarting the
MCP server creates a new session, so an old grant does not transfer. A separate
CLI run does not inherit an MCP workspace grant. Pause or revoke workspace access
with `ironrun trust pause TRUST_ID` or `ironrun trust revoke TRUST_ID`; authorization
is checked before the next workspace run. Revocation is not a claim that an
already-running process has been stopped.

Strict MCP runs can wait for a proposed command, a missing declared value, or a
required lease. Workspace runs wait for workspace authorization. Denial, expiry,
cancellation, or the host's tool timeout can end the wait. Cancelling a tool call
does not itself revoke a persisted grant or deny a pending request. The agent
host's own tool approval is also separate from Ironrun's authorization. See
[HOST_E2E.md](HOST_E2E.md) for setup and verification boundaries.

## Audit records and disclosed values

Auditing is enabled by default and can be configured or disabled through the
policy's `audit_log` field. Logger open verifies the existing SHA-256 chain and
fails if it cannot verify it. Later append or sync failures warn without failing
the command, so the log is not a guaranteed record of every run. Records contain
command metadata and entry names; argv is scrubbed for registered matches.
This does not make arbitrary caller-controlled text safe to log.

`ironrun audit verify` detects a broken chain. An attacker who can rewrite the
whole log can recompute its unkeyed hashes, and deletion or truncation requires
an external trusted checkpoint to detect reliably. The chain is not a signature
or a tamper-proof store.

The explicit CI flag `--emit-github-masks` emits values through GitHub Actions'
mask-registration channel. Use it only in that operator-controlled context;
it must not be captured as an agent transcript. If a value already reached a
conversation or provider log, rotate it. Local transcript scrubbing cannot undo
remote disclosure.
