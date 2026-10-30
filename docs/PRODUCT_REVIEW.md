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

## Setup and approval-message repairs, October 24

The next bounded correctness slice is now implemented: setup preserves unreadable
or malformed client configuration and existing custom registrations, reports each
client's actual configuration state, and asks users to verify the connection in
their host. Codex inspection failure no longer implies that registration is absent.
The workspace request reports its stored review deadline separately from the
requested access duration. Optional client issues still leave core setup successful;
no authorization or grant timing semantics changed.

Red/green regressions, the full race suite, and five synthetic REA captures support
these repairs. [October 24 evidence](validation/2026-10-24/README.md) records their
scope. Those records do not measure a real host connection, native-store
interaction, or human completion time; later host evidence is scoped below.

## Approved workspace contract and actual-host fixture

The approval UI, stored grant and human CLI promise normal network access for
an approved development workspace. The MCP path previously omitted the option
that enables it. The maintainer explicitly chose to preserve that normal-network
contract while keeping saved commands governed by their own policies. The repair
sets `AllowWorkspaceNetwork` after workspace authorization; it does not change
grant lifetime, project/environment/session binding, or the strict saved-command
branch. [Red/green evidence](validation/2026-10-26/e2e/README.md) includes an actual
child HTTP request, separate strict child dial failure, and actual CLI grant,
revoke and deny actions. Root-key storage is synthetic; the encrypted v2 vault,
CLI, stdio MCP and child execution are real.

Generated instructions and CLI/tool copy now describe filtered intercepted output
with explicit limits. They no longer promise universal confidentiality or imply
that the saved-command `exec` alias inherits an MCP workspace grant. A trusted
child with normal network access can send credentials to a remote destination;
filtering its stdout/stderr cannot prevent that.

The final-source [Codex fixture](validation/2026-10-26/codex-host/README.md) uses
actual Codex CLI 0.159.2 on Linux, actual tool discovery and a waiting `run_sealed`
call. Actual local CLI approval resumes it, a child delivers the synthetic value
to loopback, and the next scripted model request contains the redacted result.
Its local model server and native root-key adapter are synthetic. The isolated
host server is explicitly preapproved; this does not establish default tool
approval or interactive UX. No native-store, real-model, Mac, other-host or human
completion result is inferred from this pass.

## Next product validation

The maintainer selected a preview launch after readiness checks and coverage of
all selected hosts: Codex, Claude Code, OpenCode, and Cursor. The next machines are
the maintainer's Mac for Codex/Claude Code/OpenCode and a supported Linux desktop
for Cursor. The [pilot protocol](LAUNCH_PILOT.md)
requires separate host setup/approval/continuation observations and preserves
the stricter stable-release gates.

| Priority | Evidence and proposed result | Verification needed |
| --- | --- | --- |
| Setup recovery | Preservation and per-client reporting are repaired and tested synthetically | Clean host sessions on supported clients, including existing custom configuration |
| Clear approval deadlines | The message now uses persisted expiry and requested grant duration; request reuse is covered | Confirm human understanding of the distinction in the host workflow |
| Approval waiting feedback | A scripted actual Codex call resumes after persisted CLI approval; whether people can find the Inbox and understand the wait remains unobserved | Interactive Codex, Claude Code, OpenCode, and Cursor sessions; native stores, host tool approval, denial, expiry, revocation, cancel/timeout, and continuation |
| Workspace permission clarity | MCP normal networking now matches the explicitly approved workspace contract; strict policy remains separate | Confirm that people understand arbitrary argv, selected environment, normal network, grant lifetime, and the limits of output filtering |

Do not turn these observations into an approval-system rewrite without host
evidence. A useful usability pilot measures time from a clean installation to
the first successful sealed command, setup failures and recovery, time to find
and understand an approval, and whether the command resumes as expected. Use
synthetic credentials and record environment/client versions. These are proposed
measurements; this review reports no user completion rates or measured UX gains.
The [host walkthrough](HOST_E2E.md) supplies exact setup examples and required
observations without marking the unrun machine/host matrix complete. Cursor's
Linux desktop package and GUI availability must be checked before testing; a
CLI download alone does not establish the editor or its MCP behavior.

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
