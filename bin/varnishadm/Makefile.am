#

bin_varnishadm_varnishadm_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include

bin_PROGRAMS += bin/varnishadm/varnishadm

bin_varnishadm_varnishadm_SOURCES = \
	bin/varnishadm/varnishadm.c \
	lib/libvarnish/vas.c \
	lib/libvarnish/vsa.c \
	lib/libvarnish/vtcp.c \
	lib/libvarnish/vss.c

bin_varnishadm_varnishadm_CFLAGS = @LIBEDIT_CFLAGS@

bin_varnishadm_varnishadm_LDADD = \
	lib/libvarnishapi/libvarnishapi.la \
	lib/libvarnishcompat/libvarnishcompat.la \
	${PTHREAD_LIBS} ${RT_LIBS} ${NET_LIBS} @LIBEDIT_LIBS@ ${LIBM}
