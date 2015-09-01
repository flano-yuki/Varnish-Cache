#

bin_varnishtop_varnishtop_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/bin/varnishtop \
	-I$(top_builddir)/include

bin_PROGRAMS += bin/varnishtop/varnishtop

bin_varnishtop_varnishtop_SOURCES = bin/varnishtop/varnishtop.c \
	bin/varnishtop/varnishtop_options.h \
	bin/varnishtop/varnishtop_options.c \
	lib/libvarnishtools/vut.c \
	lib/libvarnish/vas.c \
	lib/libvarnish/flopen.c \
	lib/libvarnish/version.c \
	lib/libvarnish/vpf.c \
	lib/libvarnish/vtim.c \
	lib/libvarnish/vsb.c

bin_varnishtop_varnishtop_LDADD = \
	$(top_builddir)/lib/libvarnishcompat/libvarnishcompat.la \
	$(top_builddir)/lib/libvarnishapi/libvarnishapi.la \
	@CURSES_LIB@ ${RT_LIBS} ${LIBM} ${PTHREAD_LIBS}

noinst_PROGRAMS += bin/varnishtop/varnishtop_opt2rst
bin_varnishtop_varnishtop_opt2rst_SOURCES = \
	bin/varnishtop/varnishtop_options.h \
	bin/varnishtop/varnishtop_options.c \
	lib/libvarnishtools/opt2rst.c

bin_varnishtop_varnishtop_opt2rst_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/bin/varnishtop \
	-I$(top_builddir)/include