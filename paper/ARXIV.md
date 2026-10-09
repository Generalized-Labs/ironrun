# Submitting the paper

## arXiv

Build the source bundle with `make -C paper arxiv` and upload
`paper/ironrun-arxiv.tar.gz` (it contains `ironrun.tex`, `ironrun.bbl`, and
`references.bib`; all figures are TikZ, and `\pdfoutput=1` tells arXiv to use
pdflatex). First-time submitters to cs.CR may be asked for an endorsement from
an established arXiv author; arXiv says so during submission.

| Field | Value |
|---|---|
| Title | Sealed Execution: Letting LLM Coding Agents Use Credentials Without Seeing Them |
| Authors | Mihir Gupta, Stephen Keehn |
| Primary category | cs.CR (Cryptography and Security) |
| Cross-lists | cs.SE, cs.AI |
| Comments | 13 pages, 5 figures, 4 tables. Code and evaluation harness: https://github.com/Generalized-Labs/ironrun |
| License | CC BY 4.0 |

Abstract (1885 characters; the arXiv limit is 1,920):

LLM coding agents run shell commands, and whatever those commands print becomes model context. A credential that surfaces in output—via printenv, a verbose curl, or a stack trace—reaches the model provider and local transcripts and must be rotated. We present ironrun, an open-source runtime that turns the agent's tool boundary into a one-way valve: secret values flow into child processes as environment variables or temporary files, but not back out. ironrun combines (i) value-blind agent interfaces exposed over the Model Context Protocol, (ii) human authorization tiers bound to a single agent session, environment, and expiry, (iii) a streaming known-value redactor with whitespace-tolerant, fragment, and alignment-aware encoding matching under a bounded hold-back, and (iv) fail-closed containment—network and syscall isolation, process-group lifetime control, CI fork gating—with a hash-chained audit log. We report an adversarial self-audit of the 16.6 kLOC Go implementation that confirmed 49 distinct defects—2 critical and 6 high severity, 44 now fixed—among them a YAML-injection path that let an agent smuggle commands past human review and a CLI command that printed the vault root key. On a corpus of 21 output transformations × 6 credential formats run through the real execution path, the number of cases that leak at least half of a secret falls from 52 to 28; for transformations produced by ordinary tools it falls from 21 of 72 to 3 of 72, all three involving a 12-byte password below the fragment threshold. The residue consists of deliberate transformations that no known-value redactor can catch. Overhead is about 0.1 ms per command, and the redactor sustains 14–36 MB/s. We argue that redaction is the right safety net for accidental disclosure, while authorization and isolation must bound deliberate exfiltration, and we make the limits of each explicit.

## Before uploading

- `make -C paper` builds with no errors, then `make -C paper arxiv`.
- The numbers in Section 7 match `go run ./paper/eval` on the tagged commit.
- `paper/ironrun.pdf` in the repository is built from the submitted source.
