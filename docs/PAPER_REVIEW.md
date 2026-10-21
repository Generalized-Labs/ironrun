# Paper review and discussion guide

Initial review: October 19, 2026; updated October 21, 2026. Scope: the manuscript, evaluation harness, implementation, and release evidence. The manuscript and harness have been corrected, the PDF rebuilt, and baseline/current leakage counts independently reproduced. Historical findings below are retained as an audit trail; the updates state what has been resolved. This is not an independent security certification.

## GitHub review handoff

These repairs and evidence are prepared for the `launch/readiness-arxiv-review`
branch and pull request. No release tag, registry package, or arXiv submission is
part of this handoff. The [full paper walkthrough](PAPER_WALKTHROUGH.md) and
[algorithm walkthrough](REDACTION_WALKTHROUGH.md) explain the results and limits.

## Final code and arXiv validation — October 21, 2026

The final pass fixed swallowed stdout/stderr flush errors, bounded a quadratic
whitespace-gap scan, and aligned installer/Action prerelease tags with the
manifest validator. Both flush regressions and hyphenated prerelease installations
failed before repair and pass afterward. The independent runtime/release review
found no remaining blocker in those changes.

The full Go race suite, vet, and 11 offline release tests pass. The expanded
redactor fuzz target compares batch and chunked output as well as checking the
existing fixed-pattern leakage invariants: 22,581 executions passed in 11 seconds.
All four Linux/macOS snapshot archives built and their checksums verified; the
Linux amd64 binary runs. Cross-compilation does not establish target runtime
coverage. Signing, SBOM generation, before hooks and publication were skipped.

The arXiv build now generates its missing bibliography even when a tracked PDF
is already current. A fresh source bundle builds after extraction. The PDF is
14 pages and the synchronized metadata abstract is 1,905 ASCII characters, below
arXiv's documented 1,920 limit. Read `docs/REDACTION_WALKTHROUGH.md` for the full
algorithm/proof explanation and `paper/ARXIV.md` for submission requirements.
Raw final test logs and snapshot hashes are in `docs/validation/2026-10-21/`.
Historical audit/performance records and live release/platform gates remain open.

## Final documentation check — October 21, 2026

The manuscript now distinguishes installer/Action Sigstore verification from npm
manifest hash verification and omits the unconfirmed CodeQL claim. The refreshed
PDF builds successfully to 14 pages, with a monospace italic font fallback.
Earlier page counts below describe earlier builds. Check the venue page limit
before submission. Graphify and REA source reports were refreshed after the
launcher integration tests.

## Latest follow-up — launcher and baseline evidence

The actual launcher now has cold/warm/offline/corrupt-cache, concurrent-launch,
archive/binary tampering, exit-code, and signal integration tests. They exposed a
signal-swallowing defect: a child independently killed by SIGTERM made the
launcher exit zero. Forwarding listeners are now removed before mirroring the
child's signal. All 13 npm tests pass on Node 20.20.2, 22.23.3 and 24.19.0.
HTTP is fixture-backed; this does not replace live release downloads, proxy,
read-only-cache, or platform testing.

A new baseline experiment reproduced **52/126 versus 28/126** threshold cases,
with **21/72 versus 3/72** in the accidental subset. The baseline is pinned to
v0.5.0 commit `d16e04b09ec8c24e6d6e255caad9209182635af8`. Both runtimes used the
same corrected harness and Go 1.26.9. See `paper/REPRODUCING.md` and the raw logs
and source-hash provenance in `docs/validation/2026-10-20/`. This supersedes earlier
statements that baseline leakage counts were unverified. The self-audit count,
historical performance/false-positive tables, and RQ4 still need evidence.

## Follow-up validation — October 20, 2026

The findings below record the initial audit. The evaluation now rejects failed
children and missing execution sentinels, validates experiment names, and checks
performance probe results. Regression tests passed as part of the full Go race
suite. The current leak experiment reproduced **28/126** threshold leaks and six
entropy warnings on the remaining 98 cases. This does not reproduce the baseline,
historical performance tables, self-audit counts, or RQ4. The performance harness
also completed on this shared Linux host; its concurrent-build timings are
diagnostic only and were not substituted into the paper.

The manuscript now qualifies process-group cleanup, corrects the pseudocode’s
safe-lookahead condition and arbitrary-transformation observation, names the
case-insensitive metric, and limits its reproducibility claim. The PDF was
rebuilt successfully (13 pages). Historical measurements remain as reported by
the authors; their supporting records and external citations need independent
verification before submission.

## Main assessment

The paper has a useful systems contribution: resolving a credential and filtering the output of the program that receives it at the same boundary. It explains why ordinary debugging can disclose credentials and why matching known values is useful. Its strongest defensible positioning is **reducing accidental disclosure through intercepted command output**. Several statements currently overstate containment, experimental reproducibility, or the formal result and should be corrected before publication.

The central distinction to maintain throughout discussion is that the child receives the real secret. A child or writable program controlled by an attacker can transform it or write it elsewhere. Redaction does not make secret-bearing computation information-flow secure.

## Findings

### Critical — evaluation can count failed commands as successful evidence

- Evidence: `paper/eval/main.go:315` checks the returned Go error but not `Result.ExitCode` before calculating leakage. `paper/eval/main.go:405` ignores `LookPath` errors, line 411 ignores the direct command error, line 414 ignores both runner result and error, and line 417 accepts isolation samples solely on a nil Go error. The runner represents child failure in the result's exit status (`internal/runner/runner.go:355`).
- Impact: a child that fails without printing the payload may look like perfect redaction; a failed invocation may enter latency measurements. This repeats the class of vacuous-success problem the paper itself describes in Lesson 4. This is a release blocker for treating fresh results as publication evidence, not proof that the historical measurements are wrong.
- Confidence: high from control flow; not executed.
- Next Keystone module: implementation. Require successful child exit and expected execution sentinels; retain errors, record successful sample counts, and add a negative-control test with a failing child.

### Critical — descendant-lifetime guarantee exceeds process-group containment

- Evidence: `paper/ironrun.tex:618` says no descendant outlives a run holding secrets. `internal/runner/runner.go:295` explicitly accepts descendants escaping through `setsid(2)`; cleanup kills the original process group.
- Impact: readers may rely on a stronger lifetime boundary than implemented. A daemonizing child can retain injected values after the leader exits. This need not be a hostile process; ordinary tools also daemonize.
- Confidence: high; implementation documents the exception.
- Next Keystone module: implementation for correcting the security documentation, or product-planning if stronger containment is required. State that cleanup covers members remaining in the original process group; stronger guarantees require additional containment such as cgroups or an external supervisor.

### Watch — pseudocode performs a match outside the proven decidable region

- Evidence: `paper/ironrun.tex:520` stops its inner loop at `i == |B|-h`, but line 521 then unconditionally calls `Match(B,i)`. The proof at line 562 assumes decisions only occur with at least `m` bytes available. The implementation instead retains a `matchedLen` found only inside the guarded loop (`internal/redact/redact.go:128`).
- Impact: Algorithm 1 does not express the implementation whose property is claimed. At the first held position only `m-1` bytes remain; a short flexible match can be chosen before a longer flexible match becomes visible. For example, with patterns `abcdefg` and `abcdefgh`, `m=48`, a held suffix `a bcdefg` followed by 39 spaces has length 47. The shorter flexible match is visible; adding `h` supplies the longer 48-byte match. A prefix of two unmatched `z` bytes makes this suffix precisely the boundary reached by the inner loop. The pseudocode may emit the shorter match early, while a batch scan chooses the longer one.
- Confidence: high for the boundary mismatch; this counterexample is a manual trace, not an executed reproduction.
- Next Keystone module: implementation. Save the match found inside the safe loop, as the code does, and stop without matching when the safe region is exhausted. State fixed pattern-set, successful-writer, and final-flush assumptions explicitly. Dynamic `AddSecret` registration cannot retroactively redact previously emitted bytes.

### Watch — the impossibility observation is too broadly quantified

- Evidence: `paper/ironrun.tex:831` states that an unregistered invertible transformation defeats redaction because its output shares no registered pattern. Being unregistered or invertible does not imply that property. A reversal of a palindrome is unchanged; other transformations may preserve registered fragments.
- Impact: the general limitation is sound, but the stated observation does not establish it. Uppercasing, also counted in the evaluation, is not invertible on mixed-case inputs.
- Confidence: high, mathematical counterexamples.
- Next Keystone module: implementation. Say arbitrary transformations are outside the guarantee and an attacker can choose encodings whose output avoids the finite registered patterns. Distinguish complete reconstruction from case-insensitive matching.

### Watch — the published reproduction command does not reproduce every reported result

- Evidence: `paper/ironrun.tex:1058` says `go run ./paper/eval` regenerates every evaluation number. The harness dispatches only leak, fp, and perf (`paper/eval/main.go:447`). RQ4's 3,000-case check exists separately as `TestStreamingMatchesBatch` (`internal/redact/shapes_test.go:170`). No baseline implementation selector, baseline commit recipe, or saved result files are supplied in `paper/`. False-positive input is the changing checkout (`paper/eval/main.go:344`). The local checkout currently has no tags listed; this does not prove remote release tags are absent.
- Impact: readers cannot reproduce the before/after tables with the single documented command. Changes in repository content change the benign corpus. Historic measurements and the claim of 44 regression tests failing on the baseline lack a public finding-to-test manifest here.
- Confidence: high for missing local reproduction material; baseline measurements themselves unverified.
- Next Keystone module: implementation. Pin baseline and fixed commits, preserve identical corpus bytes with hashes, document the RQ4 command and baseline test procedure, and retain raw outputs plus host/toolchain metadata. Map the 49 audit findings and 44 fixes to tests and commits.

### Watch — leakage metric is not literal credential recovery

- Evidence: `paper/eval/main.go:269` lowercases both candidate and secret before matching, while `paper/ironrun.tex:777` describes a contiguous run of secret bytes. The experiment uses one deterministic sample per credential format (`paper/eval/main.go:45`), generated transformations rather than invoking each named tool, and a 50% threshold.
- Impact: an uppercase result can count as 100% recovered even when the original case-sensitive credential cannot be reconstructed uniquely. Conversely, less than 50% of a structured URL can include its entire password. The reported 3/72 is a result for this corpus and metric, not an estimated probability of real-world leakage.
- Confidence: high.
- Next Keystone module: implementation. Name the metric case-insensitive contiguous disclosure, also report exact recovery and sensitive-component recovery, and explicitly characterize the study as a small deterministic microbenchmark. Add multiple seeds, lengths, structured secret components, and real-tool output fixtures before broader claims.

### Watch — headline guarantees conflict with the paper's own limitations

- Evidence: abstract `paper/ironrun.tex:81` says values flow in but not out; line 95 characterizes the residue as deliberate transformations despite three reported accidental leaks. Lines 574–575 call buffering a short interactive lag, but a quiet process may not emit enough bytes to release the buffer until exit. The strict-mode discussion at line 922 says agents cannot choose what the program computes, while line 927 acknowledges writable project state.
- Impact: readers may miss that a writable test script or dependency changes the behavior of an unchanged approved argv. Trusting the command name is not reviewing all executable inputs. Bounded bytes of buffering do not imply bounded wall-clock delay.
- Confidence: high.
- Next Keystone module: implementation. Qualify the abstract and conclusion, preserve all three accidental residual cases, explain indefinite quiet-stream buffering, and state that strict commands require trusted executable code and inputs plus host-enforced state restrictions.

### Info — implementation evidence supports several important design details

- Evidence: twelve MCP tool definitions match the table (`mcp/server.go:89` onward); the real scanner checks matches inside a held-back safe region (`internal/redact/redact.go:117`); encoding/fragment tests and the 3,000-case differential test exist; `.github/workflows/fuzz.yml` runs seeded tests and 60 seconds of fuzzing on relevant changes and weekly.
- Impact: these are concrete strengths. Scheduled fuzzing is accurately described as scheduled, rather than literally continuous. Existence of tests is not evidence they passed in this review.
- Confidence: high for source existence; execution unknown.
- Next Keystone module: change-review after test execution.

## Section-by-section walkthrough

### 1. Introduction: the problem and proposed contribution

The problem is not just secrets committed to Git. A debugging command can print a secret into a tool result, which the agent host forwards into model context and stores in a transcript. The design makes the component that knows the secret responsible for filtering the output. This is more reliable for known literal values than asking a model or pattern detector to recognize every possible credential.

The intended novelty is the combination of value-blind interfaces, human-approved access, streaming encoding-aware redaction, containment, and an adversarial evaluation. The paper already acknowledges prior encoding masks in GitHub Actions and masking in `op run`; it should not imply inventing either. External citations and novelty claims still need independent source verification.

Discussion prompt: are we launching an accidental-disclosure tool, or promising defense against a malicious agent? The evidence most clearly supports the former.

### 2. Background: three disclosure channels

Inputs, outputs, and side effects are different channels. Keeping values out of tool arguments addresses inputs. The redactor addresses intercepted stdout/stderr. Network and filesystem writes are side effects. Protection of one channel does not establish confidentiality across all three.

HTTP Basic authentication is a good motivating example: base64 encodes `username:secret`, so the secret's encoded representation depends on where it starts in a group of three bytes. Registering only `base64(secret)` misses many embedded cases.

### 3. Threat model: who is trusted

A1 is an honest agent causing accidental output. A2 is a manipulated agent using its permitted tools. A3 is arbitrary code running as the same OS user. A3 is excluded, but an unrestricted native shell makes A2 approach A3. The paper recognizes this tension; it should remain prominent in launch messaging.

G1–G5 describe desired value-blindness, output filtering, least authority, containment, and auditability. Treat them as conditional properties with explicit exceptions: disabled auditing, allowed network access, short/partial secrets, writable state, detached processes, and arbitrary transformations.

Discussion prompt: what restrictions will a recommended deployment actually enforce outside ironrun itself?

### 4. Design: follow one command end to end

The agent requests a command. Authorization checks a policy or temporary grant. The runtime resolves secrets, injects them into the child, filters the output, and records names and execution metadata. The parent model receives the exit result and filtered output.

Value-blind tools avoid exposing an explicit secret-return operation. Encrypted capsules allow ciphertext to traverse chat; session, project, request, alias, expiry, and single-use bindings matter as much as encryption.

Strict commands limit argv, leases add temporary session-bound access, and trusted workspaces allow arbitrary argv against an approved environment. Trusted workspaces are a convenience mode and expose all selected environment entries to the child. Proposals stage changes for review; review must show exactly what will execute.

The vault uses envelope encryption: a root key wraps fresh per-environment data keys; authenticated data binds ciphertext to project and scope. The manifest MAC detects unauthorized modifications but not restoration of an older valid copy. Atomic writes address crash consistency, not malicious rollback.

The redactor tries exact, gap-tolerant, and fragment matches. Holding back enough trailing bytes prevents a write boundary from splitting a detectable occurrence. This proves equivalence to the batch matcher under assumptions; it does not prove that the batch matcher catches arbitrary disclosure. Base64 alignment cores handle embedding without knowing the username or surrounding message.

Containment layers reduce capabilities rather than turn the runtime into a complete hostile-code sandbox. The process-group exception and editable-program issue are essential here. The audit hash chain reveals edits and reordering but cannot independently detect deletion of the newest valid records.

### 5. Implementation: packaging and operational claims

The paper describes a static Go binary on Linux/macOS amd64/arm64, signed release artifacts, verified installers, dependency scanning, and fuzzing. Build flags and workflow definitions are evidence of intended processes; successful release artifacts and CI results are separate evidence. This review did not verify reproducible builds, signature verification, external advisory scans, production line counts, or supported-platform behavior.

### 6. Self-audit: useful lessons, bounded evidence

The reported findings focus on authorization rendering, alternate secret-return surfaces, encoding structure, and fail-closed tests that accidentally pass because the probe never ran. These are useful engineering lessons. Five LLM-assisted reviewers directed by the authors are not five independent external security audits. The disclosure is appropriate; a finding-to-test ledger would make the result auditable.

The claim “44 fixed, each with a regression test that fails on v0.5.0” should be backed by an explicit test manifest and baseline-run instructions. The summary table groups fewer rows than 49, so readers cannot reconstruct the count from it alone.

### 7. Evaluation: what each research question demonstrates

- **RQ1:** six deterministic synthetic credentials times 21 transformations produce 126 cases. The reported accidental cases decrease from 21/72 to 3/72; all cases decrease from 52/126 to 28/126. These numbers remain unverified in this review. The harness generates text shaped like each tool's output and passes it through a real child and runner; it does not run 21 real tools or evaluate an autonomous agent end to end.
- **RQ2:** false-positive counts show structured URLs can hide benign boilerplate. The injected 1,000 matching log lines intentionally expose this weakness. The count is not a general false-positive rate for production logs.
- **RQ3:** timings compare `true`, runner execution, and network isolation on a named Mac. The no-network overhead is around 6 ms in the reported results, larger than the roughly 0.06 ms unisolated increment. The headline “about 0.1 ms” needs that qualification. Throughput selects the fastest of five runs, excludes matcher construction, and uses one repeated benign line; document these choices.
- **RQ4:** a differential test compares chunked and whole-buffer processing. It supports the streaming implementation but does not independently establish confidentiality or validate the pseudocode as currently printed.

Discussion prompt: which reported numbers are launch claims, and which are exploratory results? Publication claims should have archived raw output and a checked reproduction path.

### 8. Discussion: limitations that define the product

Substitution is stronger where the child never receives the real value. Redaction remains useful for protocols and programs where substitution is impractical. Same-user state, credential-store accessibility, rollback, short fragments, structured-value false positives, overlap, and platform constraints are real boundaries. They should be reflected in quickstart guidance, not confined to the paper's final pages.

### 9. Related work and 10. Conclusion

The related-work section appropriately connects prompt injection, secret managers, proxy substitution, MCP security, CI masking, and containment primitives. All external references, dates, and comparative product claims still need verification against the linked sources. The conclusion should summarize the measured reduction in accidental disclosure, avoiding an unconditional one-way-valve guarantee.

## Publication evidence still needed

1. Successful tests and a paper build, with toolchain and platform recorded.
2. Corrected evaluation validity checks and rerun current-version results.
3. A documented, pinned baseline reproduction path with identical corpus bytes.
4. Raw results, corpus hashes, exact commit IDs, and the audit finding/test manifest.
5. Corrected pseudocode, mathematical quantifiers, containment limits, and headline claims.
6. Verification of external citations and comparison claims.
7. A PDF generated from the exact reviewed source and checked for references, layout, table consistency, and arXiv metadata.

Overall status: **at risk for publication until the evidence and claim issues above are resolved**. This is not a finding that the entire runtime is broken; it is a distinction between a promising implementation and a defensible security/publication claim.
