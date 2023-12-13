# Variables
ARCHIVO = presentacion
LATEX = $(ARCHIVO).tex
PDF = $(ARCHIVO).pdf

all: compile

compile: $(LATEX) # hay que compilarlo 2 veces
	pdflatex --shell-escape $(LATEX) -o $(PDF)
	pdflatex --shell-escape $(LATEX) -o $(PDF)

open: $(PDF)
	evince $(PDF) &

clean:
	rm -f $(ARCHIVO).aux $(ARCHIVO).log $(ARCHIVO).nav $(ARCHIVO).out $(ARCHIVO).snm $(ARCHIVO).toc