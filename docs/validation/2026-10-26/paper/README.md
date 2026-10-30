# Deeper manuscript and confirmed-author build

The current manuscript has **14 pages, 5 figures, and 4 tables**. Its expanded
TeX abstract matches the ASCII arXiv metadata abstract at **1,815 characters**.
The maintainer confirmed author order as **Stephen Keehn, Mihir Gupta**.
Affiliations are omitted because none have been confirmed. The proposed
CC BY 4.0 license still needs agreement from all authors; no arXiv submission
was performed.

`summary.json` binds the final source, bibliography, PDF, and three-file source
bundle to exact hashes and retains command/status records. `paper-source.tar.gz`
contains exactly `ironrun.tex`, `ironrun.bbl`, and `references.bib`. Each extracted
member matches its built source. Three direct `pdflatex` passes succeeded from a
fresh extraction using the shipped bibliography, shell escape disabled, and no
BibTeX step. The extracted PDF text matches the working-source PDF text.
PDF bytes differ because build metadata is not normalized; both hashes remain
in the summary.

The final logs have no unresolved references/citations, missing glyphs, font
substitutions, or overflowing boxes. Expected underfull-box notices and the
bundle's disabled-shell-escape `epstopdf` notice are retained. All 14 final pages
were rendered and inspected after the author change, including proof/column
breaks, five figures, four tables, and the bibliography. `visual-review.json`
records the exact PDF and rendered-page hashes; PNGs remain local.

The previous method/proof revision and its all-page visual review are retained
separately under `earlier-method-revision/`. `author-change.patch` and
`author-provenance.json` verify that the later TeX change only reorders the
authors in the header/PDF metadata and removes the unconfirmed affiliation.
Removing that line reflows pagination; the earlier page review was therefore
followed by a new all-page inspection rather than being relabeled as current.
The body, abstract, bibliography, and measured results are unchanged in TeX.

This archive's directory name is a session label. Earlier records retain their
October 27 UTC provenance; the author-confirmed rebuild and review retain their
actual October 30 UTC times. No timestamp is rewritten to match the directory.
The documentation update is dated October 29 in the user's timezone.

These are local build and bounded review results, not arXiv server processing,
moderation, author license consent, proof of every paper claim, or a guarantee
that no typo remains. The earlier leakage/performance experiments retain their
own measured runtimes and frozen inputs under the October 21–22 archives. This
prose/author follow-up does not create new measurements. The retained validator
contains absolute workspace/tool paths that need adaptation elsewhere.

`artifact-manifest.json` hashes all retained files except itself. Raw log bytes,
including trailing whitespace, are preserved.
