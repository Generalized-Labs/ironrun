# Paper review and evidence status

Updated October 21, 2026. The manuscript, harness, PDF, code, and submission guide
have been reviewed together. Read [PAPER_WALKTHROUGH.md](PAPER_WALKTHROUGH.md) for
an explanation of the full paper and [REDACTION_WALKTHROUGH.md](REDACTION_WALKTHROUGH.md)
for examples, equations, code paths, and proof assumptions.

**The corrected paper builds and its leakage comparison reproduces. Historical
self-audit and other measurements still need their supporting records before
arXiv submission.** This review is not a security certification.

## Corrected claims and implementation

| Topic | Current statement |
| --- | --- |
| Secret handling | The child receives real values; known-value filtering reduces disclosure through intercepted output |
| Chunking invariance | Fixed patterns/indexes, complete successful underlying writes, and one final flush yield identical batch/chunked output |
| Match window | All match decisions depend on a bounded global span; empty pattern sets are included |
| Pseudocode | Matching stops at the safe lookahead boundary, as the implementation does |
| Latency | Hold-back bounds retained bytes, not wall-clock delay for quiet interactive output |
| Coverage | Tier priority, overlaps, thresholds, and unsupported transformations limit recognition |
| Process lifetime | Cleanup covers the original process group; detached descendants can escape |
| Strict command approval | Fixed argv does not make attacker-writable executables, dependencies, or inputs safe |
| Distribution | Installer/Action verify Sigstore bundles; npm verifies hashes against its bundled manifest |
| Prior systems | 1Password `op run` masks stdout/stderr by default; redaction alone is not unique |
| Closest systems | fnox provides tool/secret allowlists; Prismor documents command policy and human approval alongside filtering; broad missing-design/firstness wording removed |
| Leakage-study citation | The 73.5% statistic concerns 1,007 of 1,371 vulnerability issues in the cited study, not all agent executions |

The evaluation now checks returned errors, child exit codes, and expected output
sentinels. Failed or unexecuted probes cannot count as successful redaction.
Performance probes also check execution results and sample counts. Regression
coverage passes in the Go 1.26.10 race suite.

The [source follow-up](validation/2026-10-21/source-followup/README.md) records
fresh Graphify/REA evidence and primary-source prior-work checks. The related-work
correction is based on current documentation and pinned source inspection, not
competitor execution or proof of historical feature availability. The updated
PDF and extracted source bundle compile to 14 pages.

The code audit additionally repaired final-flush errors, quadratic gap scanning,
first-time vault key initialization, and concurrent proposal/approval integrity.
These launch-review findings are recorded separately from the paper's historical
49-defect tally; no unsupported new tally is inferred.

## Experiments checked

| Evidence | Status |
| --- | --- |
| v0.5.0 baseline | Pinned to `d16e04b09ec8c24e6d6e255caad9209182635af8`; original runtime and dependencies retained |
| Harness comparison | Same corrected harness on both runtimes; baseline contains no original paper harness, so it is copied in explicitly |
| Compiler | Both sides freshly rerun with Go 1.26.10; earlier paired Go 1.26.9 run is retained |
| Overall leakage | 52/126 baseline versus 28/126 current threshold cases reproduced |
| Accidental subset | 21/72 versus 3/72 reproduced |
| Entropy warning | Six warnings among the current 98 cases below the leakage threshold |
| Historical audit | Original 49-defect/severity/44-fix records and regression mapping not independently available |
| Historical latency/throughput | Original machine and run records needed; shared-host diagnostic runs do not validate those tables |
| False positives | Published corpus identity and original raw outputs still needed; the repository corpus changes as code/docs are added |
| RQ4 streaming equivalence | Existing 3,000-case batch/chunked test and expanded fuzz checks support the property; original historical experiment records still needed |

The leakage metric is case-insensitive longest contiguous recovery of at least
50% after the harness's decoder battery. It is a deterministic corpus metric,
not a usable-credential test or a real-world leakage rate. A shorter recovered
URL password can be important even when less than half of the whole URL leaks.
The three remaining accidental cases involve a 12-byte password below fragment
protection. Deliberate transformations remain outside the registered patterns.

[REPRODUCING.md](../paper/REPRODUCING.md) gives the procedure. Raw paired outputs,
source hashes, and compiler details are in
[validation/2026-10-21](validation/2026-10-21/); the baseline archive hash and
prior run provenance remain in [validation/2026-10-20](validation/2026-10-20/).

## arXiv preparation

- The final PDF builds to 14 pages, including a short final references page.
  Contact-sheet inspection found no obvious clipping; a monospace italic font
  fallback remains. No undefined citations or overfull boxes were reported.
- The ASCII metadata abstract matches the manuscript after expanding formatting
  macros: 1,905 characters, within the official 1,920 limit.
- `make arxiv` now generates the missing bibliography on a fresh checkout even
  when the tracked PDF is current. The extracted source archive compiles.
- [ARXIV.md](../paper/ARXIV.md) records metadata, authors, proposed categories and
  license, submission checks, and the evidence still required. No submission has
  been made by this review.

Before submission, retain the original audit manifest with defect/fix commit
mapping and raw performance/false-positive/streaming records, or revise the
unsupported historical claims. The fresh leakage reproduction alone does not
validate the entire paper. Pin the final code commit and retain the source
archive, PDF, harness, toolchain, and raw results together.

The detailed original findings and interim follow-ups remain available in
[the first review commit](https://github.com/Generalized-Labs/ironrun/blob/9794795e0f4de675d452d5769718ef0c14491e87/docs/PAPER_REVIEW.md).
