# Build the paper:            make -C paper
# Run current-implementation experiments:     go run ./paper/eval   (from the repo root)
ironrun.pdf: ironrun.tex references.bib
	latexmk -pdf -interaction=nonstopmode -halt-on-error ironrun.tex

clean:
	latexmk -C ironrun.tex
.PHONY: clean

# A fresh checkout includes the PDF but not the generated bibliography.
# Declare it separately so an up-to-date tracked PDF cannot skip its build.
ironrun.bbl: ironrun.tex references.bib
	latexmk -pdf -interaction=nonstopmode -halt-on-error ironrun.tex

# arXiv source bundle: arXiv compiles with pdflatex and uses the shipped .bbl.
arxiv: ironrun.pdf ironrun.bbl
	tar czf ironrun-arxiv.tar.gz ironrun.tex ironrun.bbl references.bib
.PHONY: arxiv
