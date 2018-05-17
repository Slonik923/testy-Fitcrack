# makefile pro preklad LaTeX verze Bc. prace
# makefile for compilation of the thesis
# Autori / Authors: 2008 Michal Bidlo, 2016 Jaroslav Dytrych
# E-mail: dytrych AT fit vutbr cz
#===========================================
# asi budete chtit prejmenovat / you will probably rename:
CO=xchrip00_bp

all: $(CO).pdf

pdf: $(CO).pdf

$(CO).ps: $(CO).dvi
	dvips $(CO)

draft: $(CO)*.tex
	pdflatex $(CO)

$(CO).pdf: clean
	pdflatex -draftmode $(CO)
	bibtex $(CO)
	pdflatex -draftmode $(CO)
	pdflatex $(CO)

$(CO).dvi: $(CO).tex $(CO).bib
	latex $(CO)
	bibtex $(CO)
	latex $(CO)
	latex $(CO)

clean:
	rm -f *.dvi *.log $(CO).blg $(CO).bbl $(CO).toc *.aux $(CO).out $(CO).lof $(CO).ptc
	rm -f $(CO).pdf
	rm -f *~

pack:
	tar czvf $(CO).tar.gz $(CO)*.tex *.bib template-fig/* bib-styles/* zadani.pdf $(CO).pdf Makefile kapitoly/$(CO)*.tex obrazky/*

	
# Pozor, vlna neresi vse (viz popis.txt) / Warning - vlna is not solving all problems (see description.txt)
vlna:
	vlna -l $(CO)-*.tex

# Spocita normostrany / Count of standard pages
normostrany:
	echo "scale=2; `detex -n $(CO)-[01]*.tex | wc -c`/1800;" | bc

progress:
	@progress "kapitoly/$(CO)-0*.tex" 45 80
