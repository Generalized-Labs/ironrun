# Paper review and evidence status

Updated October 29, 2026. The revised manuscript separates retained paired
leakage evidence from fresh current-only diagnostics and current regression
case studies. It removes unsupported historical self-audit/severity/fix totals,
old before/after timing comparisons, and blanket sub-millisecond overhead claims.
The revised 14-page PDF and freshly extracted three-file source bundle compile.
Their extracted text matches, with no undefined citations/references, font
substitutions, or overflowing boxes in the final logs.
All 14 final pages were visually inspected, including diagrams, tables, and
the chunking property's page break.

Read [REPRODUCING.md](../paper/REPRODUCING.md) for exact source identities,
commands, failure checks, corpus hashes and measurement limits.
[REDACTION_WALKTHROUGH.md](REDACTION_WALKTHROUGH.md) explains the proof and its
assumptions. Older walkthroughs/reviews can retain superseded historical
figures; the revised manuscript and pinned raw evidence control those claims.

## Claims and implementation boundaries

| Topic | Current statement |
| --- | --- |
| Secret handling | The child receives real values; known-value filtering reduces disclosure through intercepted output |
| Chunking invariance | Fixed patterns/indexes, complete successful underlying writes, and one final flush yield identical batch/chunked output |
| Match window | Match decisions depend on a bounded global span; empty pattern sets are included |
| Pseudocode | Matching stops at the safe lookahead boundary, as the implementation does |
| Latency | Hold-back bounds retained bytes, not wall-clock delay for quiet interactive output |
| Coverage | Tier priority, overlaps, thresholds, and unsupported transformations limit recognition |
| Overlap counterexample | A reproducible two-pattern example leaves 22 of 23 bytes of the later value; no general eleven-byte overlap bound is claimed |
| Agent interface | No secret-reveal API; arbitrary string fields are not a content confidentiality proof, and CI mask-registration output is a separate operator channel |
| Platform controls | Linux supplies the core seal and seccomp filter; macOS network controls do not provide those protections; files and local IPC need host controls |
| Audit chain | Optional by policy, verified at logger open, best-effort appends; an unkeyed chain does not prevent rewriting/re-hashing or truncation |
| Process lifetime | Cleanup covers the original process group; detached descendants can escape |
| Strict command approval | Fixed argv does not make attacker-writable executables, dependencies, or inputs safe |
| Distribution | Installer/Action verify Sigstore bundles; npm verifies hashes against its bundled manifest |
| Prior systems | 1Password `op run` masks stdout/stderr by default; redaction alone is not unique |
| Closest systems | fnox provides tool/secret allowlists; Prismor documents command policy and human approval alongside filtering; broad missing-design/firstness wording is not claimed |
| Leakage-study citation | The 73.5% statistic concerns 1,007 of 1,371 vulnerability issues in the cited study, not all agent executions |

The evaluation checks returned errors, child exit codes and expected leakage
sentinels. Failed or unexecuted probes cannot count as successful redaction.
The streaming property does not establish absence of arbitrary transformed or
partial disclosure. A 50% whole-value threshold can miss an exposed URL password;
its complement is not a corpus of proven secret-free output.

## Retained paired evidence, October 21

| Evidence | Scope |
| --- | --- |
| v0.5.0 baseline | Pinned to `d16e04b09ec8c24e6d6e255caad9209182635af8`; original runtime and dependencies retained |
| Harness | Same checked harness copied into both runtimes; the baseline contains no original paper harness |
| Compiler | Both sides freshly run with Go 1.26.10; earlier Go 1.26.9 paired output retained |
| Overall threshold cases | 52/126 baseline versus 28/126 reviewed runtime |
| Accidental threshold cases | 21/72 versus 3/72 |
| Code identity | The reviewed tree had uncommitted fixes; source-file hashes, not the base commit alone, identify it |

Raw paired output and compiler/source provenance remain under
[validation/2026-10-21](validation/2026-10-21/). The baseline archive hash and
older paired run remain under [validation/2026-10-20](validation/2026-10-20/).
This comparison measures case-insensitive longest contiguous recovery of at
least 50% after the decoder battery. It does not establish a production leak
probability or usable-credential recovery rate.

The [source follow-up](validation/2026-10-21/source-followup/README.md) records
Graphify/REA evidence and primary-source prior-work checks. The related-work
correction is based on current documentation and pinned source inspection, not
competitor execution or proof of historical feature availability.

## Fresh current-only diagnostics, October 22

The fresh run uses clean source commit
`a4ab72e475bb6d3ed548e0dd7569294a1b3a0e8d`, Go 1.26.10 and the existing harness.
It ran on shared Linux amd64 hardware with a two-CPU cgroup quota and 8 GiB memory
limit. The frozen-source manifests, raw outputs, phase status records and corpus
are archived under
[validation/2026-10-22/fresh-pilot](validation/2026-10-22/fresh-pilot/).

| Evidence | Fresh result and limitation |
| --- | --- |
| Harness tests/build | Exit 0; fixed evaluation binary retained and hashed |
| Current leakage | 28/126 threshold cases, accidental subset 3/72; all 126 child probes completed successfully with sentinels |
| Entropy warnings | 21 warned threshold cases, six warned below-threshold cases; the latter are not necessarily false alarms |
| FP corpus identity | 209 Go/Markdown files plus 1,000 generated DSN log lines, exactly 1,209,966 bytes; ordered file hashes and compressed corpus retained |
| Current FP events | Postgres URL 1,002, each other format zero; no fresh baseline FP comparison, byte/line preservation or mixed-corpus precision/recall |
| Complete performance run | Exit 0 outside an additional filesystem sandbox; runtime isolation still enabled; 34/21/9 MB/s for 1/10/50 synthetic values |
| Spawn medians | Direct/runner/runner+no_network 1.042919/2.5609/3.34219 ms, n=200 successful samples per mode |
| Preceding sandboxed performance attempt | Exit 1 at first isolated spawn with `read-only file system`; original failure retained separately in `perf.*` |

The throughput figures are best-of-five scanning/flush measurements over
repeated no-match text in 32 KiB writes. Encoding generation and writer
construction are excluded; padded random values share prefixes. Spawn modes use
fixed direct/runner/isolated ordering; differences between the reported medians
are not measured paired per-command increments. No p95/p99, interactive delivery
delay, provider lookup or long-value scaling claim follows. A fresh successful
run does not reconstruct the old M3/macOS performance records.
The spawn microbenchmark also excludes session authorization, audit writes, and
the production seccomp filter; its runner path includes the default Linux
core-dump seal. It is not an end-to-end product timing measurement.

The FP result is now reproducible for its frozen input, but 1,000 deliberately
similar generated log lines dominate the structured-value collision. A matching
old aggregate count does not establish identical original inputs or validate a
before/after claim. No human usability study has been performed. Shared-host
microbenchmarks do not validate every deployment or replace end-to-end workflow
measurement.

## Current regression case studies

The historical aggregate audit table is replaced by four lessons supported by
current source/tests at the measured commit:

- Approval serialization and content binding: newline/Unicode/YAML-shaped
  proposal fixtures and stale-digest rejection in `cmd/ironrun/review_test.go`.
- Agent-reachable surfaces: absence of the CLI root-key-sharing command and
  line-safe CI masking in `cmd/ironrun/cli_usability_test.go` and
  `internal/execution/github_masks_test.go`.
- Encoding structure: alignment, JSON/percent forms, hexdump columns and file
  fragments in `internal/redact/shapes_test.go`.
- Non-vacuous containment: `DIAL_BLOCKED` and platform-specific fork/sandbox
  checks in `internal/runner/net_test.go` and `net_internal_test.go`.

These checks specify current behavior. They are not an original defect manifest,
a severity census or proof that each check failed on v0.5.0. The original
finding/fix ledger remains unavailable and is not required to substantiate a
removed tally. Separate source-review fixes such as final-flush propagation,
gap-scanning cost, initial vault key persistence and concurrent approval integrity
must not be folded into a fabricated historical or replacement defect count.

`TestStreamingMatchesBatch` contains 3,000 deterministic cases with 1–13-byte
chunks; `FuzzRedact` separately exercises streaming/batch agreement and fragment
coverage. These tests are separate from `paper/eval`. The harness-only pilot does
not itself execute them or establish a new full race-suite outcome. Retain final
race-suite output and platform skips separately; macOS-only checks are not
validated by a Linux run, and skips are not successful containment samples.

## arXiv preparation

- The revised TeX and ASCII metadata abstract match: **1,815 characters**, within
  the official 1,920-character limit. Historical audit counts and blanket
  overhead claims are absent from the abstract.
- The review build has 14 pages, 5 figures, and 4 tables. The upright monospace
  selection fixes the earlier italic-font fallback. Rebuild and inspect again
  after any publication edits.
- `make arxiv` generates the bibliography on a fresh checkout even when the
  tracked PDF is current. The extracted bundle sources match the built sources;
  compilation uses the shipped bibliography without a BibTeX step.
- The three-pass extracted-bundle check disables shell escape. Its expected
  `epstopdf` notice records that choice; underfull box notices are retained and
  assessed visually. Neither check reports overflowing boxes, missing glyphs,
  font substitution, or unresolved references/citations.
- [ARXIV.md](../paper/ARXIV.md) records confirmed author order Stephen Keehn,
  Mihir Gupta, with affiliations omitted. Categories/submission metadata and
  all-author consent to the proposed CC BY 4.0 license remain to be confirmed.
  No submission has been made by this review.

## Final source and citation follow-up, October 24

The [new evidence archive](validation/2026-10-24/README.md) binds the final
manuscript, PDF, source bundle, source-level review, and overlap counterexample
to exact hashes. All 82 cited references have a contextual review row: 78 have
retained primary URL excerpts, three use additional official/publisher/Crossref
metadata, and one uses an Apple manual mirror. This is not a claim that every
full article was read or every external experiment replicated.

That pass corrected Secretless Broker's database/SSH scope, LangWatch's trace
filtering timing, and discussion of current Claude filesystem deny controls.
It pins the cited Progent version, adds the Parasites DOI, and removes an
unsupported native-macOS check claim from the Apple manual reference. The
original citation matrix retains findings against its reviewed source;
`citations/RESOLUTIONS.md` records corrections against the final manuscript.
An independent source review found no material issue in the corrected passages;
this does not validate the whole system or establish novelty priority.

Pin the final publication source, retain the exact measured runtime separately
if later changes modify it, and preserve source/archive/PDF hashes, raw outputs,
failures and frozen inputs together. Successful compilation is not a security
certification or validation of the whole product.

## Deeper method and proof follow-up

The [latest paper archive](validation/2026-10-26/paper/README.md) retains the
14-page, five-figure, four-table revision. The directory name is a session label;
the recorded build/visual-review evidence retains its October 27 UTC provenance.
The additional table maps paired, current-only, and regression evidence to their
own sources. No new leakage or performance result is introduced by the prose
revision, and later product repairs do not silently change a measured source.

The chunking argument now states its buffer invariant and explains decisions
at unmatched byte positions, including index expansion and a fixed bounded
matching span. It remains conditional on fixed patterns/indexes, successful
underlying writes, and a final flush. It does not prove complete detection,
constant allocated memory, output delivery deadlines, or equivalence between
separate streams or error paths.

The recovery equation now follows the harness's candidate decoding and
case-folded longest contiguous substring calculation. The synthetic tool-shaped
fixtures are printed through `cat` into the runner; they are not executions of
the depicted tools, coding agents, or models. The newer actual Codex host fixture
is separate integration evidence with its own scripted-model and substituted
key-store limitations, not a replacement for those measurements.

The manuscript also distinguishes strict missing-value/lease continuation from
workspace authorization, explains wait termination, and states the approved
workspace's normal network access separately from saved-command policies.
The synchronized 1,815-character ASCII abstract and bibliography are unchanged.
Three pdflatex-only passes from the freshly extracted bundle succeeded with
shell escape disabled; extracted PDF text matched. All 14 final pages were
rendered and independently inspected. Expected disabled-shell-escape and
underfull-box notices remain in the raw logs; no blocking layout, font, or
reference finding remained in the reviewed scope.

This does not establish that the paper has no possible typo or semantic error.
The maintainer confirmed the author order Stephen Keehn, Mihir Gupta;
affiliations are omitted because none have been confirmed. Consent by all
authors to the proposed CC BY 4.0 license still needs confirmation before
submission; no arXiv upload is authorized or performed by this review.

The author-only source change was rebuilt with actual October 30 UTC records
(October 29 in the user's timezone). Removing the affiliation line reflowed
later pages, so all 14 new pages were rendered and inspected again. The new
source/bundle check again passes three pdflatex-only runs with shell escape
disabled, 14/5/4 counts, and matching extracted PDF text. The archive preserves
the preceding October 27 method/proof evidence separately and records the exact
author-only TeX delta; it does not relabel an older PDF's visual review.

The detailed original findings and interim follow-ups remain available in
[the first review commit](https://github.com/Generalized-Labs/ironrun/blob/9794795e0f4de675d452d5769718ef0c14491e87/docs/PAPER_REVIEW.md)
as historical review material, rather than support for the removed aggregate
claims.
