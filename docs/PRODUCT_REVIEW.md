# Product and research priorities

This review follows the maintainer's selected audience, **developers and small
teams**, and priority, **faster setup and a smoother approval flow**. The first
approved implementation is a read-only local-environment preflight in
`ironrun doctor`, implemented in this follow-up. These are product decisions
from the maintainer, not findings
from a user study.

## First improvement: trustworthy setup diagnostics

At source `a4ab72e`, a synthetic v2 policy required an entry but had no local
environment metadata. `doctor` exited zero with “All checks passed,” while
running the saved command immediately failed because local secure storage was
unavailable. The old diagnostic checked a passthrough provider instead of the
local environment used by execution.

The approved scope checks project identity, environment selection and expiry,
and required entry names from metadata, with specific recovery commands. It
preserves legacy provider diagnostics and does not open the vault, resolve
values, prune expired sets, migrate metadata on disk, or execute saved commands.
Policies with no entry-bearing saved commands need no local environment for
this check. Passing metadata checks cannot establish vault accessibility,
application authentication, MCP host integration, or a successful real command.

The complete uncached Linux race suite and vet pass after implementation.
Regression tests cover false-green blockers, legacy compatibility, unchanged
files, and native-store traps. A final REA replay of the original fixture exits
one with a repair command, versus zero before, with no observed filesystem
changes. [Verification records](validation/2026-10-23/product-followup/README.md)
retain the source hashes, red/green logs, captures, and limits.

## Next candidates, pending a separate implementation design

| Priority | Evidence and proposed result | Verification needed |
| --- | --- | --- |
| Truthful setup summary | `init.go` warns on MCP registration errors but ends with unconditional registration claims; report each client's actual status and a recovery step | Synthetic malformed/stale client configuration; clean host sessions on supported clients |
| Clear approval deadlines | `request_workspace_access` prints the two-hour grant duration as the pending-request expiry, although pending requests expire after 15 minutes | Check displayed deadline against the persisted request; distinguish review deadline from access duration |
| Approval waiting feedback | The implicit run path waits for persisted approval; whether users can find the Inbox and understand the wait remains unobserved | Actual Claude Code, Codex, and Cursor sessions; denial, expiry, revocation, and continuation |

Do not turn these observations into an approval-system rewrite without host
evidence. A useful usability pilot measures time from a clean installation to
the first successful sealed command, setup failures and recovery, time to find
and understand an approval, and whether the command resumes as expected. Use
synthetic credentials and record environment/client versions. These are proposed
measurements; this review reports no user completion rates or measured UX gains.

## Paper improvements and next experiments

The revised manuscript replaces unsupported historical audit totals and old
overhead claims with source-linked regression case studies and fresh evidence.
The [frozen experiment archive](validation/2026-10-22/fresh-pilot/README.md)
separates prior paired leakage evidence from current-only diagnostics and keeps
the failed performance attempt alongside the successful later run.

The strongest next research additions are:

1. Measure sensitive-component disclosure alongside preservation of useful
   output. A whole-value 50% recovery threshold can miss an exposed URL password.
2. Compare representation and matching-tier configurations on identical frozen
   leakage and benign corpora. Passing only literal patterns to the existing
   constructor still enables gap and fragment matching; an exact-only ablation
   requires explicit instrumentation.
3. Measure matcher construction, memory, time to first visible output, quiet
   process delay, long values, and latency distributions. Existing best-of-five
   scanning throughput and spawn medians do not supply these quantities.

Avoid changing overlap behavior or flushing early as a UX shortcut: either can
change redaction coverage or invalidate the current chunking argument. Any such
change needs its own policy, evidence, and proof review.

## Tools and external sources

REA 6.7.0 inspected the diagnostic Go binary's build metadata, analyzed the npm
source, and captured the false-green doctor process on a synthetic fixture.
The capture records output, exit status, and filesystem snapshots; snapshots
cannot prove the absence of transient writes or short-lived subprocesses. The
npm analysis is partial structural coverage, not a vulnerability certificate.

The earlier [Graphify review](validation/2026-10-21/source-followup/graph-summary.json)
maps authorization, execution, and redaction at source `803aa42`. It was used for
navigation; it predates this doctor change and is not a new runtime validation.

Primary web sources consulted October 22–23, 2026:

- [CLI Guidelines](https://clig.dev/#errors): actionable error messages and
  concrete recovery steps inform doctor output. This is practitioner guidance,
  not evidence that a proposed flow improves completion rates.
- [MCP tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools):
  clear tool presentation and human control inform approval review. This does
  not establish compatibility of the installed SDK with every protocol feature.
- [USENIX Security artifact guidance](https://www.usenix.org/conference/usenixsecurity26/call-for-artifacts):
  availability, functionality, and reproducibility motivate pinned sources,
  frozen inputs, commands, and raw results. The paper targets arXiv; this guidance
  is methodological, not an arXiv submission requirement.
