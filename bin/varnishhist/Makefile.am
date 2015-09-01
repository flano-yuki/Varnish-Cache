#

bin_varnishhist_varnishhist_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/bin/varnishhist/ \
	-I$(top_builddir)/include

bin_PROGRAMS += bin/varnishhist/varnishhist

bin_varnishhist_varnishhist_SOURCES = bin/varnishhist/varnishhist.c \
	bin/varnishhist/varnishhist_options.h \
	bin/varnishhist/varnishhist_options.c \
	lib/libvarnish/vas.c \
	lib/libvarnish/version.c \
	lib/libvarnish/vpf.c \
	lib/libvarnish/vtim.c \
	lib/libvarnish/flopen.c \
	lib/libvarnishtools/vut.c

bin_varnishhist_varnishhist_LDADD = \
	$(top_builddir)/lib/libvarnishcompat/libvarnishcompat.la \
	$(top_builddir)/lib/libvarnishapi/libvarnishapi.la \
	-lm \
	@CURSES_LIB@ ${RT_LIBS} ${PTHREAD_LIBS}

noinst_PROGRAMS += bin/varnishhist/varnishhist_opt2rst

bin_varnishhist_varnishhist_opt2rst_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/bin/varnishhist/ \
	-I$(top_builddir)/include

bin_varnishhist_varnishhist_opt2rst_SOURCES = \
	bin/varnishhist/varnishhist_options.h \
	bin/varnishhist/varnishhist_options.c \
	lib/libvarnishtools/opt2rst.c
