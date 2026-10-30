# Final manuscript and local arXiv bundle checks

`summary.json` records exact source, bibliography, PDF, and source-archive hashes
and the executed build commands/statuses. The final manuscript has 14 pages,
5 figures and 3 tables. Its ASCII metadata abstract matches the expanded TeX
abstract at 1,815 characters, within arXiv's 1,920-character limit.

`paper-source.tar.gz` contains exactly `ironrun.tex`, `ironrun.bbl`, and
`references.bib`. Each extracted source member matches the working source byte
for byte. A fresh directory compiled with three direct `pdflatex` passes using
the shipped bibliography, with shell escape disabled and no BibTeX invocation.
Extracted PDF text matches the working-source build. PDF bytes differ because
build metadata is not normalized; both hashes are retained.

The final logs contain no unresolved references/citations, font substitution,
missing glyphs, or overflowing boxes. Underfull box notices remain recorded;
they were assessed during page inspection. The bundle's `epstopdf` warning that
shell escape is disabled is expected: no external-image conversion is needed.
The local validator initially treated informational/underfull notices and that
disabled-shell-escape notice as fatal; its filters were corrected before the
successful final run. Those were validation-script errors, not failed paper
compilations.

All final pages were rendered and inspected for column breaks, diagrams, tables,
and bibliography layout. `visual-review.json` binds that inspection to the final
PDF and rendered page hashes. A short RQ4 sentence was tightened to remove an
orphaned word at a column break; no empirical result changed.

`arxiv-official-help.txt` retains the October 24 fetch of the official metadata
and TeX submission instructions. The manuscript uses PDFLaTeX without an explicit
output-format override. The validator is retained for inspection, with absolute
workspace/tool paths that need adaptation elsewhere. This is a local TeX check,
not processing on arXiv's servers, author consent, moderation, or account access.
