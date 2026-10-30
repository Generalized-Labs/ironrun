This records the read-only discovery pass before the manuscript correction. The current paper incorporates the narrower comparison; the suggested wording below is retained as research provenance.

# Primary-source prior-work check: fnox and Prismor Cloak

Repository reviewed: ironrun `803aa420d35af969ca4ff858a374a7dcdf20796d`; working tree was clean. No repository files changed. Retrieval session: 2026-10-22 UTC (execution environment date). This checks the current public sources, not what was available on the manuscript's stated access date, 2026-10-09.

Method: Exa Search skill; three targeted searches, nine result slots, followed by first-party page fetches. These are not nine independent validated sources. Pinned public GitHub source was fetched without credentials where Exa could not resolve a guessed source path. No competitor code was executed and no external humans were contacted.

## Result

The manuscript's narrow descriptions of fnox MCP execution and Cloak placeholder/output filtering are supported. The broad introductory implication that combining output filtering with agent command control is missing from prior systems needs qualification: Prismor publicly documents policy decisions, human approval with suspended-call continuation, and output masking in the same system. This does **not** establish that Prismor implements ironrun's exact combination of encoding/fragment matching, session/environment grants, or OS containment; it does mean novelty should be claimed at that specific level rather than by portraying competitors as only redactors.

## Source versions

| Source | Version checked | Evidence status |
| --- | --- | --- |
| [fnox MCP guide](https://fnox.jdx.dev/guide/mcp.html) | Live docs; also verified against [guide at commit 9a51b390](https://github.com/jdx/fnox/blob/9a51b390fca0a060a7eee3003ff3e99ea4200272/docs/guide/mcp.md) | First-party documentation and pinned source agree |
| [fnox implementation](https://github.com/jdx/fnox/blob/9a51b390fca0a060a7eee3003ff3e99ea4200272/src/mcp_server.rs) | `9a51b390fca0a060a7eee3003ff3e99ea4200272`, GitHub commit timestamp 2026-10-22T00:36:09Z | Source inspection, not execution |
| [Prismor Cloak guide](https://www.prismor.dev/docs/cloak) | Live, unversioned documentation | Describes behavior; not independently runtime-validated |
| [Prismor scrubber](https://github.com/PrismorSec/prismor/blob/9fd0e452bb0f1be2a836390011fc78524b04e994/prismor/runtime/cloaking/hooks/scrub-stream.sh) | `9fd0e452bb0f1be2a836390011fc78524b04e994`, GitHub commit timestamp 2026-10-21T16:17:05Z | Exact literal substitution observed in pinned source |
| [Prismor decision contract](https://www.prismor.dev/docs/decision-contract) and [approvals](https://www.prismor.dev/docs/approvals) | Live, unversioned docs; approvals page specifies >=1.36.0 for configuration knobs and >=1.38.0 for tool-level step-up | First-party affirmative feature claims; no historical introduction date established |

The GitHub default-branch commit IDs were obtained from the public GitHub API. Live website pages are not proven to correspond exactly to those commits; only the linked source files are pinned.

## fnox: supported comparison, but acknowledge existing controls

**Observed:** the guide states that `exec` runs a command with injected secrets and replaces secret output with `[REDACTED]`. It explicitly says “Redaction matches literal values only, so base64 or other transformed output isn't caught.” The pinned implementation corroborates this: `ExecParams.command` is an argv vector; `exec` supplies secrets through environment variables or temporary files, and `redact_secrets` performs Aho-Corasick literal matching over trimmed values with a minimum length threshold (source lines 43–48, 315–379, 485–490, 544–567).

**Existing authorization controls:** the `[mcp]` configuration restricts offered tools and permitted secret names; unlisted secrets are not resolved, injected, or returned. Operators can disable `get_secret`, which otherwise is offered by default alongside `exec`. The selected profile also determines the served environment. This is a real secret/tool access boundary and should not be described as no authorization at all.

**Command selection:** the guide explicitly states “the agent chooses the command” and calls this “not isolation.” The pinned MCP handler executes the caller-supplied argv. Thus the documented MCP path is meaningfully different from ironrun's saved exact-command mode. This observation is scoped to this path; no claim is made that all fnox features lack other controls. fnox's docs also point to a separate credential proxy for stronger isolation.

**Manuscript assessment:** `paper/ironrun.tex:1032`–1033 (“fnox's MCP exec, which injects secrets and redacts their literal values”) is supported. An expanded comparison should mention fnox's tool/secret allowlists and optional value-return tool, then contrast the specific saved-command/session-grant design. Do not generalize from MCP exec to all fnox capabilities.

## Prismor Cloak: literal substitution supported; broader authorization exists

**Observed substitution/filtering:** the Cloak guide describes `@@SECRET:name@@` placeholders resolved immediately before shell execution and registered real values replaced back with placeholders in output. It documents Bash output filtering, MCP response recloaking, prompt/raw-secret guards, and file-read guards. The child shell receives the real value: this is execution-time substitution plus output filtering, not a credential proxy that withholds the value from the child.

**Pinned implementation:** `scrub-stream.sh` reads registered secret files, applies eligibility rules (>=16 characters, or >=8 with digit/symbol/mixed case), buffers input into a Bash string, and executes literal `${data//"$real"/@@SECRET:${name}@@}` replacement. This supports the manuscript's literal-value description for this scrubber. It does not establish that every Prismor subsystem exclusively performs literal filtering. The decision-contract documentation describes an exact Cloak swap followed by separate data-boundary classification.

**Host distinctions:** live Cloak docs say Claude Code and Hermes support automatic decloak/output scrubbing; Codex hooks are block-only and use the explicit `prismor cloak run -- <command>` path. Avoid claiming identical hook behavior across all agent hosts.

**Observed command control:** the first-party [decision contract](https://www.prismor.dev/docs/decision-contract) explicitly routes shell events with a `command` field through policy evaluation and returns allow/block/step-up/defer/modify decisions. The [approvals guide](https://www.prismor.dev/docs/approvals) states that `action: step_up` holds a call for a human, deduplicates requests, resumes approved calls, and blocks on denial/expiry/error. These are affirmative evidence of policy mediation and human approval, not an inference from marketing omission.

**Filtering failure semantics:** the decision-contract page states result masking is best-effort and does not fail a call closed. The inspected scrubber likewise comments that errors can pass input unchanged. This is a potentially meaningful comparison dimension, but it should be described as the documented contract, not an independently reproduced exploit. The Cloak page's broad “never”/“fail-closed” language must not be copied as a validated universal guarantee.

**Manuscript assessment:** `paper/ironrun.tex:1033`–1035 (“Cloak, which substitutes placeholders through agent-host hooks and scrubs literal values”) is supported but incomplete. The introduction at lines 141–145 introduces these systems as output scrubbers and then says a design combining these at the agent boundary is missing. Without a more precise scope or historical cutoff this is an unsupported novelty implication given Prismor's documented integrated command-policy and approval behavior.

## Suggested wording for author review (not applied)

> fnox's MCP server offers configurable tool and secret allowlists, command execution with injected values, and literal output masking; its documented exec mode lets the agent choose the command. Prismor combines execution-time placeholders and literal-value filtering with host-integrated policy and human-approval controls. Our focus is the specific combination of alignment-, whitespace-, and fragment-aware streaming known-value redaction, session/environment-bound authorization, and OS containment, evaluated against a disclosed transformation corpus.

This describes evidenced features rather than claiming no competitor implements an uninspected feature. A “first” or “missing design” claim still needs a dated comparison table, precise evaluation criteria, and a broader literature search.

## Remaining uncertainty

- No historical snapshot was examined for 2026-10-09. Current Prismor approval features may postdate the manuscript's access date; establish that history before asserting the original comparison was wrong at writing time.
- No complete competitor security audit or end-to-end execution tests were performed. Product documentation is evidence of what is documented, not proof every advertised enforcement path works.
- No equivalence was established between Prismor's policies and ironrun's per-secret, per-environment lease semantics, nor between their containment implementations.
- No firstness claim is validated by this two-system check. This evidence supports narrowing the framing and acknowledging concrete overlapping capabilities.
