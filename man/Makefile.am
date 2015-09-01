#

noinst_PROGRAMS += man/vsc2rst
man_vsc2rst_SOURCES = man/vsc2rst.c \
	include/tbl/vsc_fields.h

man_vsc2rst_CPPFLAGS = -I$(top_srcdir)/include

dist_man_MANS = \
	man/varnish-cli.7 \
	man/varnish-counters.7 \
	man/vcl.7 \
	man/vsl.7 \
	man/vsl-query.7 \
	man/varnishadm.1 \
	man/varnishd.1 \
	man/varnishhist.1 \
	man/varnishlog.1 \
	man/varnishncsa.1 \
	man/varnishstat.1 \
	man/varnishtest.1 \
	man/varnishtop.1 \
	man/vmod_directors.3 \
	man/vmod_std.3

MAINTAINERCLEANFILES += $(dist_man_MANS)

man/varnish-cli.7: $(top_srcdir)/doc/sphinx/reference/varnish-cli.rst
	${RST2MAN} $(RST2ANY_FLAGS) $(top_srcdir)/doc/sphinx/reference/varnish-cli.rst $@

man/varnish-counters.7: $(top_builddir)/man/vsc2rst
	$^ | ${RST2MAN} $(RST2ANY_FLAGS) - $@

man/vcl.7: $(top_srcdir)/doc/sphinx/reference/vcl.rst \
	bin/varnishd/builtin.vcl
	${RST2MAN} $(RST2ANY_FLAGS) $(top_srcdir)/doc/sphinx/reference/vcl.rst $@

man/vsl.7: $(top_srcdir)/doc/sphinx/reference/vsl.rst \
	$(top_srcdir)/lib/libvarnishapi/vsl-tags.rst
	${RST2MAN} $(RST2ANY_FLAGS) $(top_srcdir)/doc/sphinx/reference/vsl.rst $@

man/vsl-query.7: $(top_srcdir)/doc/sphinx/reference/vsl-query.rst
	${RST2MAN} $(RST2ANY_FLAGS) $(top_srcdir)/doc/sphinx/reference/vsl-query.rst $@

man/varnishadm.1: $(top_srcdir)/doc/sphinx/reference/varnishadm.rst
	${RST2MAN} $(RST2ANY_FLAGS) $(top_srcdir)/doc/sphinx/reference/varnishadm.rst $@

man/varnishd.1: \
	$(top_srcdir)/doc/sphinx/reference/varnishd.rst \
	$(top_srcdir)/doc/sphinx/include/params.rst
	${RST2MAN} $(RST2ANY_FLAGS) $(top_srcdir)/doc/sphinx/reference/varnishd.rst $@

man/varnishncsa.1: \
	$(top_srcdir)/doc/sphinx/reference/varnishncsa.rst \
	$(top_srcdir)/doc/sphinx/include/varnishncsa_options.rst \
	$(top_srcdir)/doc/sphinx/include/varnishncsa_synopsis.rst
	${RST2MAN} $(RST2ANY_FLAGS) $(top_srcdir)/doc/sphinx/reference/varnishncsa.rst $@

man/varnishlog.1: \
	$(top_srcdir)/doc/sphinx/reference/varnishlog.rst \
	$(top_srcdir)/doc/sphinx/include/varnishlog_options.rst \
	$(top_srcdir)/doc/sphinx/include/varnishlog_synopsis.rst
	${RST2MAN} $(RST2ANY_FLAGS) $(top_srcdir)/doc/sphinx/reference/varnishlog.rst $@

man/varnishreplay.1: $(top_srcdir)/doc/sphinx/reference/varnishreplay.rst
	${RST2MAN} $(RST2ANY_FLAGS) $(top_srcdir)/doc/sphinx/reference/varnishreplay.rst $@

# XXX add _options.rst and _synopsis.rst here when it's been _opt2rst'ed
man/varnishstat.1: $(top_srcdir)/doc/sphinx/reference/varnishstat.rst
	${RST2MAN} $(RST2ANY_FLAGS) $(top_srcdir)/doc/sphinx/reference/varnishstat.rst $@

man/varnishtest.1: $(top_srcdir)/doc/sphinx/reference/varnishtest.rst
	${RST2MAN} $(RST2ANY_FLAGS) $(top_srcdir)/doc/sphinx/reference/varnishtest.rst $@

man/varnishtop.1: \
	$(top_srcdir)/doc/sphinx/reference/varnishtop.rst \
	$(top_srcdir)/doc/sphinx/include/varnishtop_options.rst \
	$(top_srcdir)/doc/sphinx/include/varnishtop_synopsis.rst
	${RST2MAN} $(RST2ANY_FLAGS) $(top_srcdir)/doc/sphinx/reference/varnishtop.rst $@

man/varnishhist.1: \
	$(top_srcdir)/doc/sphinx/reference/varnishhist.rst \
	$(top_srcdir)/doc/sphinx/include/varnishhist_options.rst \
	$(top_srcdir)/doc/sphinx/include/varnishhist_synopsis.rst
	${RST2MAN} $(RST2ANY_FLAGS) $(top_srcdir)/doc/sphinx/reference/varnishhist.rst $@

man/vmod_std.3: $(top_builddir)/lib/libvmod_std/vmod_std.man.rst
	${RST2MAN} $(RST2ANY_FLAGS) $? $@

man/vmod_directors.3: $(top_builddir)/lib/libvmod_directors/vmod_directors.man.rst
	${RST2MAN} $(RST2ANY_FLAGS) $? $@
