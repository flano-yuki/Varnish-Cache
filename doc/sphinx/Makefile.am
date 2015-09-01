# Makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build -W -q -N
PAPER         = a4
BUILDDIR      = $(builddir)/doc/sphinx/build

# Internal variables.
PAPEROPT_a4     = -D latex_paper_size=a4
PAPEROPT_letter = -D latex_paper_size=letter
ALLSPHINXOPTS   = -d $(BUILDDIR)/doctrees $(PAPEROPT_$(PAPER)) $(SPHINXOPTS) $(builddir)/doc/sphinx

.PHONY: help clean html dirhtml pickle json htmlhelp qthelp latex changes linkcheck doctest

help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  html      to make standalone HTML files"
	@echo "  dirhtml   to make HTML files named index.html in directories"
	@echo "  pickle    to make pickle files"
	@echo "  json      to make JSON files"
	@echo "  htmlhelp  to make HTML files and a HTML help project"
	@echo "  qthelp    to make HTML files and a qthelp project"
	@echo "  latex     to make LaTeX files, you can set PAPER=a4 or PAPER=letter"
	@echo "  changes   to make an overview of all changed/added/deprecated items"
	@echo "  linkcheck to check all external links for integrity"
	@echo "  doctest   to run all doctests embedded in the documentation (if enabled)"

clean-local: sphinx-clean

# use index.rst as an indicator if we have copied already
.PHONY: link_srcdir
link_srcdir:
	if test "x$(srcdir)" != "x$(builddir)" && test ! -f index.rst ; then \
		d=`pwd`/$(builddir)/doc/sphinx ; \
		cd $(srcdir)/doc/sphinx/ && find . -type f | cpio -ldmp $${d} ; \
		chmod -R +w $${d} ;\
	fi

sphinx_prereq: link_srcdir graphviz doc/sphinx/conf.py

html: sphinx_prereq
	$(SPHINXBUILD) -b html $(ALLSPHINXOPTS) $(BUILDDIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."

dirhtml: sphinx_prereq
	$(SPHINXBUILD) -b dirhtml $(ALLSPHINXOPTS) $(BUILDDIR)/dirhtml
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/dirhtml."

pickle: sphinx_prereq
	$(SPHINXBUILD) -b pickle $(ALLSPHINXOPTS) $(BUILDDIR)/pickle
	@echo
	@echo "Build finished; now you can process the pickle files."

json: sphinx_prereq
	$(SPHINXBUILD) -b json $(ALLSPHINXOPTS) $(BUILDDIR)/json
	@echo
	@echo "Build finished; now you can process the JSON files."

htmlhelp: sphinx_prereq
	$(SPHINXBUILD) -b htmlhelp $(ALLSPHINXOPTS) $(BUILDDIR)/htmlhelp
	@echo
	@echo "Build finished; now you can run HTML Help Workshop with the" \
	      ".hhp project file in $(BUILDDIR)/htmlhelp."

qthelp: sphinx_prereq
	$(SPHINXBUILD) -b qthelp $(ALLSPHINXOPTS) $(BUILDDIR)/qthelp
	@echo
	@echo "Build finished; now you can run "qcollectiongenerator" with the" \
	      ".qhcp project file in $(BUILDDIR)/qthelp, like this:"
	@echo "# qcollectiongenerator $(BUILDDIR)/qthelp/Varnish.qhcp"
	@echo "To view the help file:"
	@echo "# assistant -collectionFile $(BUILDDIR)/qthelp/Varnish.qhc"

latex: sphinx_prereq
	$(SPHINXBUILD) -b latex $(ALLSPHINXOPTS) $(BUILDDIR)/latex
	@echo
	@echo "Build finished; the LaTeX files are in $(BUILDDIR)/latex."
	@echo "Run \`make all-pdf' or \`make all-ps' in that directory to" \
	      "run these through (pdf)latex."

changes: sphinx_prereq
	$(SPHINXBUILD) -b changes $(ALLSPHINXOPTS) $(BUILDDIR)/changes
	@echo
	@echo "The overview file is in $(BUILDDIR)/changes."

linkcheck: sphinx_prereq
	$(SPHINXBUILD) -b linkcheck $(ALLSPHINXOPTS) $(BUILDDIR)/linkcheck
	@echo
	@echo "Link check complete; look for any errors in the above output " \
	      "or in $(BUILDDIR)/linkcheck/output.txt."

doctest: sphinx_prereq
	$(SPHINXBUILD) -b doctest $(ALLSPHINXOPTS) $(BUILDDIR)/doctest
	@echo "Testing of doctests in the sources finished, look at the " \
	      "results in $(BUILDDIR)/doctest/output.txt."

EXTRA_DIST += \
	doc/sphinx/conf.py \
	doc/sphinx/index.rst \
	doc/sphinx/include \
	doc/sphinx/glossary \
	doc/sphinx/installation \
	doc/sphinx/phk \
	doc/sphinx/tutorial \
	doc/sphinx/users-guide \
	doc/sphinx/whats-new

dist-hook: sphinx-dist
.PHONY: sphinx-dist
sphinx-dist:
	rm -rf $(BUILDDIR)/doctrees
	cp -r $(BUILDDIR)/html $(distdir)/doc/html

distclean-local: sphinx-clean
sphinx-clean:
	rm -rf $(BUILDDIR)

doc/sphinx/include:
	test -d $@ || mkdir -m0755 $@

SPHINXFIRSTS = $(top_builddir)/lib/libvarnishapi/vsl-tags.rst

$(top_builddir)/doc/sphinx/include/params.rst: $(top_builddir)/bin/varnishd/varnishd $(top_builddir)/doc/sphinx/include
	$(top_builddir)/bin/varnishd/varnishd -x dumprstparam > $@
SPHINXFIRSTS += $(top_builddir)/doc/sphinx/include/params.rst

# XXX add varnishstat here when it's been _opt2rst'ed

$(top_builddir)/doc/sphinx/include/varnishncsa_options.rst: $(top_builddir)/bin/varnishncsa/varnishncsa_opt2rst
	$(top_builddir)/bin/varnishncsa/varnishncsa_opt2rst options > $@
$(top_builddir)/doc/sphinx/include/varnishncsa_synopsis.rst: $(top_builddir)/bin/varnishncsa/varnishncsa_opt2rst
	$(top_builddir)/bin/varnishncsa/varnishncsa_opt2rst synopsis > $@
SPHINXFIRSTS += $(top_builddir)/doc/sphinx/include/varnishncsa_options.rst \
	$(top_builddir)/doc/sphinx/include/varnishncsa_synopsis.rst

$(top_builddir)/doc/sphinx/include/varnishlog_options.rst: $(top_builddir)/bin/varnishlog/varnishlog_opt2rst
	$(top_builddir)/bin/varnishlog/varnishlog_opt2rst options > $@
$(top_builddir)/doc/sphinx/include/varnishlog_synopsis.rst: $(top_builddir)/bin/varnishlog/varnishlog_opt2rst
	$(top_builddir)/bin/varnishlog/varnishlog_opt2rst synopsis > $@
SPHINXFIRSTS += $(top_builddir)/doc/sphinx/include/varnishlog_options.rst \
	$(top_builddir)/doc/sphinx/include/varnishlog_synopsis.rst

$(top_builddir)/doc/sphinx/include/varnishtop_options.rst: $(top_builddir)/bin/varnishtop/varnishtop_opt2rst
	$(top_builddir)/bin/varnishtop/varnishtop_opt2rst options > $@
$(top_builddir)/doc/sphinx/include/varnishtop_synopsis.rst: $(top_builddir)/bin/varnishtop/varnishtop_opt2rst
	$(top_builddir)/bin/varnishtop/varnishtop_opt2rst synopsis > $@
SPHINXFIRSTS += $(top_builddir)/doc/sphinx/include/varnishtop_options.rst \
	 $(top_builddir)/doc/sphinx/include/varnishtop_synopsis.rst

$(top_builddir)/doc/sphinx/include/varnishhist_options.rst: $(top_builddir)/bin/varnishhist/varnishhist_opt2rst
	$(top_builddir)/bin/varnishhist/varnishhist_opt2rst options > $@
$(top_builddir)/doc/sphinx/include/varnishhist_synopsis.rst: $(top_builddir)/bin/varnishhist/varnishhist_opt2rst
	$(top_builddir)/bin/varnishhist/varnishhist_opt2rst synopsis > $@
SPHINXFIRSTS += $(top_builddir)/doc/sphinx/include/varnishhist_options.rst \
	 $(top_builddir)/doc/sphinx/include/varnishhist_synopsis.rst

$(top_builddir)/doc/sphinx/reference/vmod_std.generated.rst: \
		$(top_builddir)/lib/libvmod_std/vmod_std.rst
	mkdir -p $(top_builddir)/doc/sphinx/reference
	cp -f $(top_builddir)/lib/libvmod_std/vmod_std.rst $@
SPHINXFIRSTS += $(top_builddir)/doc/sphinx/reference/vmod_std.generated.rst

$(top_builddir)/doc/sphinx/reference/vmod_directors.generated.rst: \
		$(top_builddir)/lib/libvmod_directors/vmod_directors.rst 
	mkdir -p $(top_builddir)/doc/sphinx/reference
	cp -f $(top_builddir)/lib/libvmod_directors/vmod_directors.rst $@
SPHINXFIRSTS += $(top_builddir)/doc/sphinx/reference/vmod_directors.generated.rst

sphinx_prereq: $(SPHINXFIRSTS)

$(SPHINXFIRSTS): doc/sphinx/include

EXTRA_DIST += $(SPHINXFIRSTS) \
			  doc/sphinx/reference/directors.rst \
			  doc/sphinx/reference/index.rst \
			  doc/sphinx/reference/states.rst \
			  doc/sphinx/reference/varnishadm.rst \
			  doc/sphinx/reference/varnish-cli.rst \
			  doc/sphinx/reference/varnishd.rst \
			  doc/sphinx/reference/varnishhist.rst \
			  doc/sphinx/reference/varnishlog.rst \
			  doc/sphinx/reference/varnishncsa.rst \
			  doc/sphinx/reference/varnishstat.rst \
			  doc/sphinx/reference/varnishtest.rst \
			  doc/sphinx/reference/varnishtop.rst \
			  doc/sphinx/reference/vcl.rst \
			  $(top_builddir)/doc/sphinx/reference/vmod_directors.generated.rst \
			  doc/sphinx/reference/vmod.rst \
			  $(top_builddir)/doc/sphinx/reference/vmod_std.generated.rst \
			  doc/sphinx/reference/vsl-query.rst \
			  doc/sphinx/reference/vsl.rst \
			  doc/sphinx/reference/vsm.rst
MAINTAINERCLEANFILES += $(SPHINXFIRSTS)
