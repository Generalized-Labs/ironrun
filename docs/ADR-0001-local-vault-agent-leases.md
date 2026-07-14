# ADR-0001: Local encrypted vault and revocable agent leases

**Status:** Accepted for prototype
**Date:** 2026-07-13
**Deciders:** Ironrun maintainers

## Technical objective

Let a human manage project and session environment values locally while an AI
agent can use narrowly authorized values without receiving their plaintext.
CLI, MCP, and future TUI/HTTP surfaces must share one authorization and storage
core so a safer surface cannot be bypassed through a weaker one.

## Invariants

1. Secret plaintext is never returned by MCP, status commands, audit records,
   policy files, lease files, or local HTTP responses.
2. A secret entered through chat is safe only when it was encrypted before it
   entered the transcript. Ironrun must never imply it can erase an already
   pasted plaintext value from provider logs.
3. Agents receive capabilities to execute approved commands, not capabilities
   to read secret values.
4. Leases are scoped to one MCP session, environment, command set, and expiry.
   Revocation blocks the next execution.
5. Existing policies remain compatible. Agent-lease enforcement is opt-in.
6. Committed vault mutations are atomic across process crashes: the previous
   complete revision or the new complete revision is readable, never a partial
   JSON document.
7. Cryptographic primitives come from the Go standard library. Ironrun defines
   a file format and key lifecycle, not new cryptography.

## Threat and failure model

The prototype protects against accidental transcript/log exposure, repository
and Git-history inclusion, offline reading of copied vault files, cross-project
confusion, replay of expired/revoked leases, and common output encodings already
handled by the runner redactor.

It does not protect against a fully compromised user account, a malicious
process able to inspect Ironrun memory while a secret is in use, hostile child
code inventing arbitrary exfiltration transforms, or an upstream provider key
that was disclosed before Ironrun received it. Revoking an Ironrun lease blocks
future Ironrun use; provider-level revocation still requires rotating or deleting
the upstream credential.

Operational failures to test include disk full, torn/truncated writes, vault
tampering, missing OS credential storage, concurrent CLI/MCP mutations, clock
expiry boundaries, MCP restarts, and migration interruption.

## Options considered

### Continue with one OS credential record per value

Simple and already implemented, but difficult to back up, inspect as a coherent
project, version, or evolve into a portable encrypted store.

### Encrypted dotenv files

Familiar, but encourages materializing plaintext files and gives weak semantics
for agent authority, expiry, and revocation.

### Mounted FUSE-style encrypted filesystem

Attractive filesystem UX, but a plaintext mount would become visible to shells,
indexers, agents, and backups. It also creates substantial cross-platform and
crash-recovery complexity before validating the core user workflow.

### Local encrypted vault plus capabilities

Keeps ciphertext outside the repository, uses the OS credential manager only to
protect a root key, preserves sealed execution, and supports project/session
lifecycles and revocable agent authority. This is the selected path.

## Decision

Add a project vault stored outside the repository. Each environment scope owns
a random 256-bit data-encryption key. The environment map is encrypted with
AES-256-GCM; the data key is independently wrapped with a project root key using
AES-256-GCM. Associated data binds both layers to the format version, project
identity, and environment scope. Rewriting a scope rotates its data key.

The project root key is random and protected by the native OS credential store.
The existing per-value native records remain a read-through migration source:
on first successful read, Ironrun writes the value into the vault and deletes
the legacy record only after the vault commit succeeds.

Add an opt-in `require_agent_leases` policy flag. CLI execution remains a human
authority path. MCP execution must present the server's current session identity
to the access manager, which authorizes only active, unrevoked leases covering
the selected environment and command.

MCP may request a secret or lease, but cannot approve either. A human fulfills
the request through a masked local prompt or approves it through the CLI/TUI.
No MCP tool accepts plaintext secret input. A later encrypted-capsule tool may
accept ciphertext bound to a machine, project, purpose, expiry, and one-use ID.

## Prototype acceptance metrics

- Zero plaintext matches in vault, metadata, access state, MCP responses, audit
  output, and Git fixtures across adversarial tests.
- All vault tampering and wrong-key/project attempts fail closed.
- Revocation and expiry are observed on the next MCP execution.
- Existing non-lease policies retain their current behavior and tests.
- Lazy migration is lossless under injected failures.
- Normal environment lookup adds less than 20 ms p95 on a local development
  project with 100 keys; measure rather than assume.

## Near-term build

1. Encrypted vault package, atomic persistence, key protection adapter, and lazy
   migration from native per-value records.
2. Durable request/lease state with atomic cross-process mutations.
3. CLI request review, fulfill, approve, revoke, and list commands.
4. MCP request/status tools and optional lease enforcement around `run_sealed`.
5. Adversarial tests, race tests, vet, and ciphertext inspection.

## 90-day research and product plan

1. Add URL-mode MCP elicitation when host support is sufficiently widespread;
   retain the masked terminal fallback.
2. Prototype one-use encrypted chat capsules and attempt replay, substitution,
   confused-deputy, and decryption-oracle attacks.
3. Put CLI, MCP, a Unix-socket HTTP API, and the premium TUI over one local
   broker with peer-credential checks and idempotency keys.
4. Build the Bubble Tea control-room UI for environments, missing keys, pending
   requests, leases, expiry countdowns, and the audit timeline.
5. Add encrypted backup/import with an explicit recovery key and no plaintext
   export path.
6. Run cross-platform crash, disk-full, permission, and credential-manager tests.

## Long-term bet

Ironrun becomes a local capability kernel for agents: identity, scoped execution,
secret use, network/process constraints, human approvals, revocation, and replayable
policy decisions. Remote synchronization, if added, synchronizes ciphertext and
wrapped environment keys rather than turning a cloud service into the default
trust root.

## Falsification and kill criteria

Stop or redesign the vault path if any of these remain true after the prototype:

- A normal supported workflow requires plaintext to cross MCP or local HTTP.
- Crash/failure injection can lose the only committed copy during migration.
- The OS root-key lifecycle is less reliable than the existing per-secret store
  on a supported platform.
- Lease identity cannot be bound strongly enough to distinguish concurrent agent
  sessions without burdening users with persistent bearer tokens.
- Users consistently need plaintext file mounting more than sealed execution;
  that would indicate a different product and threat model.
