#

bin_varnishlog_varnishlog_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/bin/varnishlog \
	-I$(top_builddir)/include

bin_PROGRAMS += bin/varnishlog/varnishlog

bin_varnishlog_varnishlog_SOURCES = \
	bin/varnishlog/varnishlog.c \
	bin/varnishlog/varnishlog_options.h \
	bin/varnishlog/varnishlog_options.c \
	lib/libvarnishtools/vut.c \
	lib/libvarnish/vas.c \
	lib/libvarnish/flopen.c \
	lib/libvarnish/version.c \
	lib/libvarnish/vsb.c \
	lib/libvarnish/vpf.c \
	lib/libvarnish/vtim.c

bin_varnishlog_varnishlog_LDADD = \
	$(top_builddir)/lib/libvarnishcompat/libvarnishcompat.la \
	$(top_builddir)/lib/libvarnishapi/libvarnishapi.la \
	${RT_LIBS} ${LIBM} ${PTHREAD_LIBS}

noinst_PROGRAMS += bin/varnishlog/varnishlog_opt2rst

bin_varnishlog_varnishlog_opt2rst_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/bin/varnishlog \
	-I$(top_builddir)/include

bin_varnishlog_varnishlog_opt2rst_SOURCES = \
	bin/varnishlog/varnishlog_options.h \
	bin/varnishlog/varnishlog_options.c \
	lib/libvarnishtools/opt2rst.c
