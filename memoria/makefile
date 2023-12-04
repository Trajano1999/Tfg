# Nombre del archivo latex
ARCHIVO=tfg

# Variables
LATEX=$(ARCHIVO).tex
PDF=$(ARCHIVO).pdf

all: compile

compile:
	latexmk -pdf $(LATEX)

open:
	evince $(PDF) &

clean:
	find . -name "*.aux" -type f -delete
	rm -f $(ARCHIVO).toc $(ARCHIVO).out $(ARCHIVO).lot $(ARCHIVO).log $(ARCHIVO).lof $(ARCHIVO).ind $(ARCHIVO).ilg $(ARCHIVO).fls $(ARCHIVO).fdb_latexmk $(ARCHIVO).brf $(ARCHIVO).blg $(ARCHIVO).bbl $(ARCHIVO).idx $(ARCHIVO).synctex.gz data.csv
