# Build the paper:            make -C paper
# Regenerate its numbers:     go run ./paper/eval   (from the repo root)
ironrun.pdf: ironrun.tex references.bib
	latexmk -pdf -interaction=nonstopmode -halt-on-error ironrun.tex

clean:
	latexmk -C ironrun.tex
.PHONY: clean

# arXiv source bundle: arXiv compiles with pdflatex and uses the shipped .bbl.
arxiv: ironrun.pdf
	tar czf ironrun-arxiv.tar.gz ironrun.tex ironrun.bbl references.bib
.PHONY: arxiv
