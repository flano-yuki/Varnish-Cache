#

bin_varnishstat_varnishstat_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include

bin_PROGRAMS += bin/varnishstat/varnishstat

bin_varnishstat_varnishstat_SOURCES = \
	bin/varnishstat/varnishstat.h \
	\
	bin/varnishstat/varnishstat.c \
	bin/varnishstat/varnishstat_curses.c \
	lib/libvarnish/vas.c \
	lib/libvarnish/version.c \
	lib/libvarnish/vtim.c

bin_varnishstat_varnishstat_LDADD = \
	$(top_builddir)/lib/libvarnishcompat/libvarnishcompat.la \
	$(top_builddir)/lib/libvarnishapi/libvarnishapi.la \
	@CURSES_LIB@ ${RT_LIBS} ${LIBM} ${PTHREAD_LIBS}
