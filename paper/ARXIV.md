# Submitting the paper to arXiv

Prepare the source bundle with `make -C paper arxiv`. The archive contains
`ironrun.tex`, `ironrun.bbl`, and `references.bib`; all figures are TikZ. Select
PDFLaTeX in the arXiv processor form. Uploading or submitting to arXiv is a separate
maintainer action. First-time submitters to cs.CR may need endorsement; follow
the instructions shown by arXiv.

| Field | Value |
| --- | --- |
| Title | Sealed Execution: Letting LLM Coding Agents Use Credentials Without Seeing Them |
| Authors | Stephen Keehn, Mihir Gupta; names and order confirmed by the maintainer; affiliations omitted |
| Primary category | cs.CR (Cryptography and Security) |
| Proposed cross-lists | cs.SE, cs.AI; subject to arXiv moderation |
| Comments | 14 pages, 5 figures, 4 tables. Code and evaluation harness: https://github.com/Generalized-Labs/ironrun |
| Proposed license | CC BY 4.0; confirm all authors agree before submission |

The ASCII metadata abstract below matches the revised manuscript after expanding
formatting commands. It contains **1815 characters**, excluding its trailing
newline. [arXiv's preparation instructions](https://info.arxiv.org/help/prep.html)
require ASCII input and reject abstracts exceeding 1,920 characters. Preserve
this limit when editing the manuscript and metadata together.

## Abstract

LLM coding agents run shell commands, and their output becomes model context. A credential printed by a debugging command can therefore reach the model provider and local transcripts. We present ironrun, an open-source runtime that injects secret values into child processes as environment variables or temporary files and filters known values and supported encodings before output reaches the agent. It combines value-blind Model Context Protocol interfaces, session-bound human authorization, a streaming redactor with whitespace-tolerant, fragment, and alignment-aware matching, and platform-specific OS controls with a hash-chained audit log. We state a chunking-invariance property for fixed patterns, bounded matching spans, successful writes, and a final flush, and present current regression case studies for approval integrity, agent-reachable surfaces, encoding structure, and non-vacuous containment tests. In a paired reproduction using the same checked harness on v0.5.0 and the reviewed runtime, 52 of 126 transformation/credential cases permit at least 50% case-insensitive contiguous recovery on the baseline, versus 28 on the reviewed runtime. For ordinary-tool transformations the counts are 21 of 72 versus 3 of 72; the three remaining cases involve a 12-byte password below fragment protection. A fresh current-only run reproduces these current counts. Shared-host Linux diagnostics additionally expose structured-value over-redaction and measure throughput and median spawn costs; they do not establish deployment leak rates, tail latency, or usability. Known-value redaction reduces accidental disclosure, but thresholds, partial disclosure, and unregistered transformations limit coverage. Authorization, protected executable code and inputs, and isolation must bound deliberate exfiltration.

## Evidence scope

The revised manuscript removes unsupported historical self-audit totals,
severity/fix counts, blanket sub-millisecond overhead claims, and old timing
comparisons. Current regression case studies replace the historical severity
table; their tests specify behavior at a pinned source commit and do not prove
that each test failed on v0.5.0.

- The October 21 paired leakage reproduction is retained as its own evidence:
  52/126 threshold cases on v0.5.0 versus 28/126 on the reviewed runtime,
  with accidental subsets 21/72 versus 3/72. Its original archive, harness,
  runtime source hashes, and raw outputs remain under `docs/validation/2026-10-21/`
  and `docs/validation/2026-10-20/`.
- Fresh October 22 diagnostics use source commit
  `a4ab72e475bb6d3ed548e0dd7569294a1b3a0e8d` and Go 1.26.10. The current-only
  leakage run reproduces 28/126 and 3/72. The frozen 1,209,966-byte benign corpus
  yields 1,002 Postgres-URL replacement events and zero for each other format.
  No fresh baseline FP/performance comparison is claimed.
- Fresh shared-host Linux performance diagnostics report scanning throughput and
  spawn medians with 200 successful samples per mode. Best-of-five scanning
  excludes encoding generation and writer construction; no p95/p99 or delivery
  latency is measured. A preceding sandboxed failure is preserved separately
  from the successful run outside that additional filesystem sandbox; runtime
  network isolation remained enabled.
- Raw records, exact source/artifact hashes, and the compressed frozen corpus
  are archived in `docs/validation/2026-10-22/fresh-pilot/`.
  [REPRODUCING.md](REPRODUCING.md) identifies commands, checks, and confounders.
- These deterministic corpus diagnostics do not establish production leak rates,
  component-level precision/recall, developer usability, or complete containment.
  No human usability study was conducted. Redactor differential/fuzz tests are
  separate from `paper/eval`; platform-specific skips are not positive evidence.

## Before uploading

1. Rebuild the exact final manuscript with `make -C paper` after any edits.
   The latest retained review build has 14 pages, 5 figures, and 4 tables; it has no
   undefined references/citations or overflowing boxes. Keep these counts in sync.
2. Confirm `paper/ironrun.pdf` was built from the exact submitted sources and
   visually inspect all pages, including tables and page breaks.
3. Run `make -C paper arxiv`, then unpack the bundle in a fresh directory and
   compile it with pdflatex using the included `.bbl`. Check that no local file,
   external figure, generated bibliography, or shell-escape step is missing.
4. Verify the title, license, abstract,
   categories, and code URL with the authors. Validate metadata in the live
   arXiv form; a local build cannot establish account or moderation eligibility.
   The maintainer confirmed the author order Stephen Keehn, Mihir Gupta;
   affiliations are omitted because none have been confirmed.
5. Pin the final publication source, retain the exact measured runtime source
   separately if later edits change it, and verify the archived raw results and
   corpus decompress/hash correctly. Retain final checks, source archive, PDF,
   runtime/harness hashes and experiment records together. No submission has
   been made by this review. Agreement by all authors to the proposed CC BY 4.0
   license remains a publication gate.

The [latest paper validation archive](../docs/validation/2026-10-26/paper/README.md)
binds the deeper method/proof revision to exact TeX, PDF, and source-bundle hashes.
Its raw build and visual-review timestamps are retained as recorded; the archive
directory name is a session label, not a new experiment date.

The [redaction walkthrough](../docs/REDACTION_WALKTHROUGH.md) explains the proof
and its assumptions. The [paper review](../docs/PAPER_REVIEW.md) records current
evidence scope. Older walkthroughs/reviews may retain superseded historical
figures; the revised manuscript and pinned raw evidence control those claims.
