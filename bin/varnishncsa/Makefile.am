#

bin_varnishncsa_varnishncsa_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/bin/varnishncsa \
	-I$(top_builddir)/include

bin_PROGRAMS += bin/varnishncsa/varnishncsa

bin_varnishncsa_varnishncsa_SOURCES = \
	bin/varnishncsa/varnishncsa.c \
	bin/varnishncsa/varnishncsa_options.h \
	bin/varnishncsa/varnishncsa_options.c \
	bin/varnishncsa/base64.h \
	bin/varnishncsa/base64.c \
	lib/libvarnishtools/vut.c \
	lib/libvarnish/vas.c \
	lib/libvarnish/flopen.c \
	lib/libvarnish/version.c \
	lib/libvarnish/vpf.c \
	lib/libvarnish/vtim.c \
	lib/libvarnish/vsb.c

bin_varnishncsa_varnishncsa_LDADD = \
	lib/libvarnishcompat/libvarnishcompat.la \
	lib/libvarnishapi/libvarnishapi.la \
	${RT_LIBS} ${LIBM}

noinst_PROGRAMS += bin/varnishncsa/varnishncsa_opt2rst

bin_varnishncsa_varnishncsa_opt2rst_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/bin/varnishncsa \
	-I$(top_builddir)/include

bin_varnishncsa_varnishncsa_opt2rst_SOURCES = \
	bin/varnishncsa/varnishncsa_options.h \
	bin/varnishncsa/varnishncsa_options.c \
	lib/libvarnishtools/opt2rst.c
