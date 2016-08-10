fy16_report.pdf: fy16_report.tex
	pdflatex fy16_report
	bibtex fy16_report
	pdflatex fy16_report
	pdflatex fy16_report

.PHONY: rfc.bib
rfc.bib: 
	mv -f rfc.bib rfc.bak
	wget http://tm.uka.de/~bless/rfc.bib

