#

lib_libvmod_std_libvmod_std_la_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/bin/varnishd \
	-I$(top_builddir)/include \
	-I$(top_builddir)/lib/libvmod_std

vmod_LTLIBRARIES += lib/libvmod_std/libvmod_std.la

lib_libvmod_std_libvmod_std_la_LDFLAGS = $(AM_LT_LDFLAGS) -module -export-dynamic -avoid-version -shared

lib_libvmod_std_libvmod_std_la_SOURCES = \
	lib/libvmod_std/vmod_std.c \
	lib/libvmod_std/vmod_std_conversions.c \
	lib/libvmod_std/vmod_std_fileread.c \
	lib/libvmod_std/vmod_std_querysort.c

nodist_lib_libvmod_std_libvmod_std_la_SOURCES = \
	lib/libvmod_std/vcc_if.c \
	lib/libvmod_std/vcc_if.h

lib/libvmod_std/lib_libvmod_std_libvmod_std_la-vmod_vcc_if.$(OBJEXT) : include/vmod_abi.h

$(lib_libvmod_std_libvmod_std_la_OBJECTS) : lib/libvmod_std/vcc_if.h include/tbl/vcl_returns.h

# stupid hack to run vmodtool only once
lib/libvmod_std/vcc_if.c \
	lib/libvmod_std/vmod_std.rst \
	lib/libvmod_std/vmod_std.man.rst : lib/libvmod_std/vcc_if.h
	@#

lib/libvmod_std/vcc_if.h: $(vmodtool) lib/libvmod_std/vmod.vcc
	cd lib/libvmod_std/ && @PYTHON@ ../../$(vmodtool) $(vmodtoolargs) $(abs_top_srcdir)/lib/libvmod_std/vmod.vcc

EXTRA_DIST += lib/libvmod_std/vmod.vcc

CLEANFILES +=  lib/libvmod_std/vcc_if.c  lib/libvmod_std/vcc_if.h \
	lib/libvmod_std/vmod_std.rst \
	lib/libvmod_std/vmod_std.man.rst
	
