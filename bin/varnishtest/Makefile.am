#

VTC_LOG_COMPILER = bin/varnishtest/varnishtest -v -i
TEST_EXTENSIONS = .vtc
TESTS = @VTC_TESTS@

check: lib/libvmod_debug/libvmod_debug.la verify-tests-list
# See if list of checks have changed, recheck
verify-tests-list :
	if [ "$$(cd $(top_srcdir) && echo bin/varnishtest/tests/*.vtc)" != "@VTC_TESTS@" ]; then \
		./config.status --recheck ; \
	fi

DISTCLEANFILES += bin/varnishtest/_.ok


bin_varnishtest_varnishtest_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/lib/libvgz

bin_PROGRAMS +=	bin/varnishtest/varnishtest

bin_varnishtest_varnishtest_SOURCES = \
		bin/varnishtest/vtc.c \
		bin/varnishtest/vtc.h \
		bin/varnishtest/vmods.h \
		bin/varnishtest/programs.h \
		bin/varnishtest/vtc_client.c \
		bin/varnishtest/vtc_http.c \
		bin/varnishtest/vtc_main.c \
		bin/varnishtest/vtc_log.c \
		bin/varnishtest/vtc_sema.c \
		bin/varnishtest/vtc_server.c \
		bin/varnishtest/vtc_varnish.c \
		bin/varnishtest/vtc_logexp.c \
		bin/varnishtest/vtc_process.c

bin_varnishtest_varnishtest_LDADD = \
		$(top_builddir)/lib/libvarnish/libvarnish.la \
		$(top_builddir)/lib/libvarnishcompat/libvarnishcompat.la \
		$(top_builddir)/lib/libvarnishapi/libvarnishapi.la \
		$(top_builddir)/lib/libvgz/libvgz.la \
		${LIBM} ${PTHREAD_LIBS}

bin_varnishtest_varnishtest_CFLAGS = \
		-DTOP_BUILDDIR='"${top_builddir}"'

EXTRA_DIST += @VTC_TESTS@ \
	$(top_srcdir)/bin/varnishtest/tests/README
