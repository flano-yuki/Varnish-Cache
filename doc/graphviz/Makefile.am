# Makefile for graphviz outputs

# for an out-of-tree build, sphinx needs the output in builddir
# XXX is there a better way to do this?
# .PHONY is required as VPATH will happily register the files in
# buildi

dist: html

# You can set these variables from the command line.
# this is a4, letter is 8.5,11
SIZE	      = 8.4,11.7

EXTRA_DIST += \
	doc/graphviz/cache_http1_fsm.dot \
	doc/graphviz/cache_req_fsm.dot \
	doc/graphviz/cache_fetch.dot

if HAVE_DOT
PDFS = \
	doc/graphviz/cache_http1_fsm.pdf \
	doc/graphviz/cache_req_fsm.pdf \
	doc/graphviz/cache_fetch.pdf

SVGS = \
	doc/graphviz/cache_http1_fsm.svg \
	doc/graphviz/cache_req_fsm.svg \
	doc/graphviz/cache_fetch.svg

CLEANFILES += \
	$(PDFS)	\
	$(SVGS)
endif

pdf: $(PDFS)
if ! HAVE_DOT
	@echo ==================================================
	@echo You need graphviz installed to generate pdf output
	@echo ==================================================
	@false
endif

graphviz: $(SVGS)
if ! HAVE_DOT
	@echo ===================================================
	@echo You need graphviz installed to generate html output
	@echo ===================================================
	@false
endif

# XXX does not fit onto a4 unless in landscape
doc/graphviz/cache_fetch.pdf: doc/graphviz/cache_fetch.dot
	mkdir -p $(top_builddir)/doc/graphviz
	@DOT@ -Tpdf -Gsize=$(SIZE) -Grotate=90 $< >$@

%.pdf: %.dot
	mkdir -p $(top_builddir)/doc/graphviz
	@DOT@ -Tpdf -Gsize=$(SIZE) $< >$@

%.svg: %.dot
	mkdir -p $(top_builddir)/doc/graphviz
	@DOT@ -Tsvg $< >$@
