# usage: make filename.pdf
%.pdf: %.tex
	pdflatex $<
	pdflatex $<

clean:
	rm -f *.aux *.log *.nav *.toc *.snm *.out *.vrb
	rm -f *.pdf
	rm -f *~
