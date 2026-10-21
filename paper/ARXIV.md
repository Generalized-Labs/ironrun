# Submitting the paper to arXiv

Prepare the source bundle with `make -C paper arxiv`. The archive contains
`ironrun.tex`, `ironrun.bbl`, and `references.bib`; all figures are TikZ, and
`\pdfoutput=1` selects pdflatex. Uploading or submitting to arXiv is a separate
maintainer action. First-time submitters to cs.CR may need endorsement; follow
the instructions shown by arXiv.

| Field | Value |
| --- | --- |
| Title | Sealed Execution: Letting LLM Coding Agents Use Credentials Without Seeing Them |
| Authors | Mihir Gupta, Stephen Keehn |
| Primary category | cs.CR (Cryptography and Security) |
| Proposed cross-lists | cs.SE, cs.AI; subject to arXiv moderation |
| Comments | 14 pages, 5 figures, 4 tables. Code and evaluation harness: https://github.com/Generalized-Labs/ironrun |
| Proposed license | CC BY 4.0; confirm all authors agree before submission |

The ASCII metadata abstract below matches the current manuscript after expanding
formatting commands. It contains **1905 characters**, excluding its trailing
newline. [arXiv's preparation instructions](https://info.arxiv.org/help/prep.html)
require ASCII input and reject abstracts exceeding 1,920 characters. Preserve
this limit when editing the manuscript and metadata together.

## Abstract

LLM coding agents run shell commands, and whatever those commands print becomes model context. A credential that surfaces in output---via printenv, a verbose curl, or a stack trace---reaches the model provider and local transcripts and must be rotated. We present ironrun, an open-source runtime that injects secret values into child processes as environment variables or temporary files and filters known values and supported encodings from their output before it reaches the agent. ironrun combines (i) value-blind agent interfaces exposed over the Model Context Protocol, (ii) human authorization tiers bound to a single agent session, environment, and expiry, (iii) a streaming known-value redactor with whitespace-tolerant, fragment, and alignment-aware encoding matching under a bounded hold-back, and (iv) fail-closed containment---network and syscall isolation, process-group lifetime control, CI fork gating---with a hash-chained audit log. We report an adversarial self-audit of the 16.6 kLOC Go implementation that confirmed 49 distinct defects---2 critical and 6 high severity, 44 now fixed---among them a YAML-injection path that let an agent smuggle commands past human review and a CLI command that printed the vault root key. On a corpus of 21 output transformations x 6 credential formats run through the real execution path, the number of cases that leak at least half of a secret falls from 52 to 28; for transformations produced by ordinary tools it falls from 21 of 72 to 3 of 72, all three involving a 12-byte password below the fragment threshold. The residue includes these three accidental cases and deliberate transformations not covered by the registered patterns. Overhead is about 0.1 ms per command, and the redactor sustains 14--36 MB/s. We argue that redaction is a safety net for accidental disclosure, while authorization and isolation must bound deliberate exfiltration.

## Evidence to finish before submission

The manuscript still reports historical self-audit and performance results. A
successful PDF build does not validate those results.

- Preserve the supporting records for the reported 49 defects, severity counts,
  and 44 fixes, with a mapping to the affected and fixed commits. Those records
  have not been independently checked in this review.
- Preserve or freshly reproduce the historical latency, redactor throughput,
  false-positive, and RQ4 containment measurements with machine/toolchain details,
  commands, raw results, and failures. The leakage reproduction does not validate
  these other tables.
- Follow [REPRODUCING.md](REPRODUCING.md) for the corrected leakage experiment.
  The same harness and Go 1.26.9 reproduced 52/126 threshold cases on v0.5.0 and
  28/126 on the reviewed working tree; accidental cases were 21/72 and 3/72.
  Pin the final committed current source and retain its hashes and raw outputs.
  These case-insensitive 50% recovery counts are a deterministic corpus metric,
  not real-world leakage rates; disclosures below the threshold can still matter.
- Review the manuscript's claims against these records. If a historical result
  cannot be supported, revise or remove the claim before submission rather than
  presenting a partial reproduction as validation of the whole paper.

## Before uploading

1. Build the final manuscript with `make -C paper` and resolve undefined
   references/citations or layout errors. The reviewed local build is 14 pages;
   recount after later edits. A monospace italic font fallback was observed.
2. Confirm `paper/ironrun.pdf` was built from the exact submitted sources and
   visually inspect all pages, including tables and page breaks.
3. Run `make -C paper arxiv`, then unpack the bundle in a fresh directory and
   compile it with pdflatex using the included `.bbl`. Check that no local file,
   external figure, generated bibliography, or shell-escape step is missing.
4. Verify the title, author spelling/order, affiliations, license, abstract,
   categories, and code URL with the authors. Validate metadata in the live
   arXiv form; a local build cannot establish account or moderation eligibility.
5. Submit only after the evidence items above are resolved. Retain the source
   archive, final PDF, exact code commit, and reproduction records together.

The [redaction walkthrough](../docs/REDACTION_WALKTHROUGH.md) explains the proof
and its assumptions. The [paper review](../docs/PAPER_REVIEW.md) and
[launch assessment](../docs/LAUNCH_READINESS.md) record the broader review.
