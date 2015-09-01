#

lib_libvarnishcompat_libvarnishcompat_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include

pkglib_LTLIBRARIES += lib/libvarnishcompat/libvarnishcompat.la

lib_libvarnishcompat_libvarnishcompat_la_LDFLAGS = $(AM_LT_LDFLAGS) -avoid-version

lib_libvarnishcompat_libvarnishcompat_la_SOURCES = \
	lib/libvarnishcompat/daemon.c \
	lib/libvarnishcompat/execinfo.c
