# Reading the Ironrun paper, section by section

This guide explains the current [manuscript](../paper/ironrun.tex) and
[PDF](../paper/ironrun.pdf). It separates the design argument, reported historical
results, and checks reproduced during this review. The main defensible claim is
that Ironrun reduces accidental credential disclosure through intercepted command
output. The child still receives real credentials, so the execution boundary and
its assumptions matter throughout the paper.

## Abstract and introduction: what problem is being solved?

A coding agent learns from the output of commands it runs. A database client can
print a connection URL containing a password; verbose HTTP output can print an
Authorization header; configuration expansion can print environment values.
Once that output enters model context or transcripts, a secret manager cannot
retract it. Depending on the exposure, the operator may need to rotate it.

Ironrun connects two jobs: resolving the actual values supplied to a child and
filtering those known values from its output before returning it to the agent.
The system can therefore match specific injected values instead of guessing
whether arbitrary text looks like a secret.

The contribution is the combined boundary: value-blind interfaces, session-bound
human authorization, a streaming redactor with supported transformations, OS
controls, and audit records. Redaction by itself is established practice. The
paper's comparison must account for tools such as `op run`, which already masks
known values in stdout/stderr by default.

The introduction also cites a study of 17,022 agent skills. Its 73.5% statistic
is 1,007 of 1,371 vulnerability issues in a particular category, not a universal
credential-leakage rate across agents. Keep that denominator attached to the
claim when discussing or presenting the work.

## Background: three ways a secret can leave

The paper distinguishes values entering agent context, secret-bearing child
output, and side channels such as network access. Ironrun principally mediates
child output. Authorization determines which child may receive a credential;
network and process controls constrain other behavior.

The Basic-auth example motivates more than literal matching. The header encodes
`username:password` together, so the secret's base64 characters depend on its
alignment within a larger message. Merely registering `base64(password)` misses
some ordinary output formats. The detailed alignment derivation appears in the
[redaction walkthrough](REDACTION_WALKTHROUGH.md).

## Threat model: who is trusted, and against what?

The operator is trusted to author policy and approve access. The agent and its
host act for that operator but may make mistakes or follow malicious content.
Child commands are the programs receiving real values. The model provider sees
whatever enters context and is outside the operator's direct control.

Three adversaries explain the intended boundary:

| Adversary | Example | Implication |
| --- | --- | --- |
| A1: accidental disclosure | A test failure prints a database URL | The principal redaction target |
| A2: manipulated agent | Repository text persuades the agent to print or transmit a token | Requires command, file, and execution restrictions in addition to redaction |
| A3: hostile same-user native code | A process rewrites user-owned state or reads accessible credential storage | Excluded from the claimed boundary; stronger OS separation is required |

An unrestricted same-user shell makes A2 approach A3. Protecting an MCP endpoint
alone does not stop the agent from invoking another CLI, changing approved
program code, or reading state through other permitted tools.

The goals are value-blind interfaces, filtered output, least authority, bounded
execution, and accountability. Read output-confidentiality goals in light of the
matching thresholds and supported forms. They do not establish universal
information-flow confidentiality or deletion from provider logs.

## Design: one execution core and explicit capabilities

CLI, MCP, TUI, and local API entry points are intended to converge on the same
execution core. This reduces the chance that one surface forgets authorization,
redaction, cleanup, or audit. [execution](../internal/execution) and
[runner](../internal/runner) are useful source directories for tracing that path.

The agent requests an effect—run a test with approved credentials—rather than
requesting the credential value. Tool responses contain command descriptions,
request IDs, grant state, exit status, and redacted output. `request_secret`
accepts an alias and reason; the operator supplies the value through local input.
An encrypted capsule can carry ciphertext through chat, bound to the project,
session, request, alias, expiry, and one-time use. Its keys and plaintext must
remain outside the agent-visible interface.

Authorization has four modes:

- Strict commands specify approved argv and required secrets. Proposals can add
  commands only after human approval.
- Leases additionally restrict strict commands by session, environment, command
  set, and expiry.
- Trusted workspace grants allow broader argv for a selected session and
  environment, trading control for convenience.
- A blocked request can wait for human approval and continue in the same call.

Session IDs are minted by the server, not chosen by the agent. Approval is
rechecked, and revocation affects the next call. This is not a claim that revoking
access instantly terminates every already-running child.

Exact argv prevents some shell expansion attacks, but it does not freeze what a
program computes. If the agent can modify the script, dependencies, configuration,
or inputs that approved argv executes, it can still change the computation.
Strict-mode deployments must protect those inputs through the host boundary.

## Storage: encrypt values and bind them to their context

The vault keeps a random root key in the OS credential manager. Each environment
write uses a fresh data key; AES-256-GCM encrypts the scope data and wraps that
key. Authenticated additional data binds ciphertext to its version, purpose,
project, and scope, so moving ciphertext between contexts fails verification.
An HMAC covers the manifest. Temp-write, fsync, rename, and directory fsync aim to
make updates durable without partially written state.

File secrets are materialized in an owner-only temporary directory outside the
checkout, with restrictive file permissions and validated names. Only their
paths are injected; their contents are registered for redaction. Cleanup removes
them after execution. Removal is not physical erasure on SSD or copy-on-write
storage, and encryption does not protect a root key already accessible to hostile
same-user code. See [vault](../internal/vault) and [secrets](../internal/secrets).

## Redaction: what the algorithm proves

Each stream gets its own writer. The writer registers literals and selected
encodings, then tries exact, gap-tolerant, and fragment matching. A bounded suffix
waits for enough lookahead to make a stable decision. The final flush handles the
remaining complete suffix.

The theorem says that a fixed matcher produces identical output regardless of
write boundaries, assuming the same ordered bytes, successful complete output
writes, and a final flush with no intermediate flushes. It does not prove every
sensitive transformation is recognized. Overlap priority, minimum pattern and
fragment lengths, and finite encoding coverage remain material limits.

[REDACTION_WALKTHROUGH.md](REDACTION_WALKTHROUGH.md) develops the examples,
equations, proof induction, code correspondence, and tests without compressing
those details into this whole-paper guide.

## Containment and audit: what survives failure?

Linux network isolation uses user/network namespaces; macOS uses an absolute
`sandbox-exec` path with a network-denial profile. Unsupported requested isolation
refuses execution. Linux sealed execution also applies syscall restrictions and
core-dump controls. A failed setup must prevent the protected command from
starting rather than silently remove a requested control.

Timeout, cancellation, and normal completion trigger process-group cleanup.
Descendants that detach with `setsid` can escape the original group. The current
mechanism therefore does not establish complete descendant-tree containment.
macOS runtime support also needs actual platform tests; successful cross-builds
do not exercise Seatbelt behavior.

Audit records include command metadata, secret names/kinds, scrubbed argv,
redaction counts, exit status, and sandbox outcome. Each record hashes the previous
record's hash. Verification detects broken links, edits, and reordering. Without
an independently anchored latest head, deleting the tail leaves a shorter valid
chain. Likewise, a manifest MAC cannot distinguish current state from a valid
older vault copy. Accountability has an integrity boundary as well as a format.

## Implementation and distribution

The implementation is Go, built as a static binary for Linux/macOS on amd64/arm64.
The manuscript's code-size counts describe its reported implementation snapshot;
new fixes and tests change those counts. Windows is unsupported.

Release checksums and Sigstore bundles address distribution integrity. The
installer and GitHub Action verify both; the npm launcher verifies archive and
binary hashes against its bundled manifest. Those mechanisms have different
trust chains. Snapshot builds and fixture verifiers do not validate the final
published signing workflow. The [launch assessment](LAUNCH_READINESS.md) records
which checks ran and which platform/release gates remain open.

## Self-audit: useful lessons and unfinished evidence

The manuscript reports five LLM-based reviewers directed and checked by the
authors, 49 deduplicated defects, and 44 fixes. Those are reported historical
results. The original finding records, severity decisions, and mappings to
commits/regression tests still need supporting evidence before submission.

Four lessons carry beyond the tally: humans must approve the artifact actually
enforced; every agent-reachable surface matters, including human-oriented CLIs;
encodings have alignment and formatting structure; and a security test can pass
vacuously when its probe fails before reaching the behavior being tested.

The current evaluation harness now checks successful child exits and execution
sentinels. A child failing before printing a payload must not count as successful
redaction. That repair strengthens fresh experiments without retroactively
proving every historical measurement.

## Evaluation: four separate research questions

| Question | What is measured | Evidence status |
| --- | --- | --- |
| RQ1 | Recoverable synthetic credential content after output transformations | Baseline/current threshold counts reproduced with the same corrected harness |
| RQ2 | Unwanted redactions on benign text | Historical table still needs its exact corpus and raw records |
| RQ3 | Spawn overhead and redactor throughput | Historical machine-specific results still need supporting records |
| RQ4 | Streaming output equals batch output | Current differential/fuzz checks support the property; historical before/after records remain separate |

RQ1 uses 21 transformations and six credential shapes: 126 cases. A decoder
battery tries reversal, case folding, encodings, gap removal, and related
reconstruction. A case crosses the threshold when a case-insensitive contiguous
run of at least 50% of the registered value can be recovered.

The same corrected harness with Go 1.26.10 reproduced **52/126 → 28/126** overall
and **21/72 → 3/72** for the accidental subset. The pinned baseline and raw logs
are documented in [REPRODUCING.md](../paper/REPRODUCING.md). This is a deterministic
corpus result, not a probability that a real execution leaks. Matching half a
value case-insensitively need not yield a usable credential; conversely, a short
URL password may be entirely exposed while remaining below half the whole URL.

The three accidental residuals concern the short password and partial/formatted
prints. Deliberate transformations also remain. Warn-only entropy scanning can
flag some output but cannot establish confidentiality or replace authorization.

RQ2 exposes a usability tradeoff: a structured Postgres URL contains common
12-byte windows, causing reported masking of benign log text. Those are false
positives even though their removal does not itself expose a secret. Reproducing
the exact counts requires fixed corpus bytes; a changing checkout changes the
experiment.

RQ3 reports historical sub-millisecond wrapper overhead without network isolation
and lower throughput as more secrets/patterns are registered. Spawn cost, OS
isolation, provider lookup, and filtering are different contributors. Shared-host
Linux diagnostics cannot be substituted for the reported Apple M3 Pro timings.

RQ4 is exercised by 3,000 deterministically randomized batch-versus-stream cases,
plus fuzzing. Current checks are evidence for the present implementation. They
do not supply missing historical v0.5.0 run records or prove all possible inputs.

## Discussion, related work, and conclusion

Proxy substitution is stronger where applicable: a child that never receives the
real credential cannot print it. Ironrun addresses broader command workflows,
including database, signing, SSH, and file credentials. CI masking, secret-manager
wrappers, agent hooks, and policy/isolation systems supply related pieces.
Differentiation should rest on the combined boundary and tested supported forms,
not a claim that output masking is new or absent from 1Password.
Current fnox documentation includes tool/secret allowlists, and Prismor documents
command policy and human approval alongside output filtering. The manuscript now
acknowledges those overlapping controls and avoids a broad firstness claim.
This comparison does not establish when those features became available or prove
equivalent enforcement across systems.

The conclusion should carry all these conditions forward: known-value filtering
reduces common accidental output disclosure; deliberate transformations and
writable execution inputs require stronger controls; same-user hostile code,
provider retention, detached descendants, rollback, and partial disclosure remain
limits. The algorithm's chunking proof is narrower and firmer than universal
credential confidentiality.

## Preparing this version for arXiv

The current PDF is 14 pages. [ARXIV.md](../paper/ARXIV.md) supplies the synchronized
1,905-character ASCII metadata abstract and source-bundle checklist. The revised
build handles the bibliography on a fresh checkout, and a source-bundle build was
checked during this review.

Before submission, retain the final source commit, PDF, source archive, experiment
corpus and logs, and toolchain/host metadata together. Resolve the original
audit/performance/false-positive and historical RQ4 records, or revise unsupported
claims. Account eligibility, authorship agreement, and arXiv moderation remain
submission matters. The [paper review](PAPER_REVIEW.md) preserves the audit trail
and current validation, so a reader can distinguish fresh evidence from claims
still awaiting records.
