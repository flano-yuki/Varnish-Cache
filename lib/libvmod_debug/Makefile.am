#


lib_libvmod_debug_libvmod_debug_la_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/bin/varnishd \
	-I$(top_builddir)/include \
	-I$(top_builddir)/lib/libvmod_debug

noinst_LTLIBRARIES += lib/libvmod_debug/libvmod_debug.la

lib_libvmod_debug_libvmod_debug_la_LDFLAGS = $(AM_LT_LDFLAGS) -module -export-dynamic -avoid-version -shared -rpath $(abs_builddir)

lib_libvmod_debug_libvmod_debug_la_SOURCES = \
	lib/libvmod_debug/vmod_debug.c \
	lib/libvmod_debug/vmod_debug_obj.c \
	lib/libvmod_debug/vmod_debug_dyn.c

nodist_lib_libvmod_debug_libvmod_debug_la_SOURCES = \
	lib/libvmod_debug/vcc_if.c \
	lib/libvmod_debug/vcc_if.h

$(lib_libvmod_debug_libvmod_debug_la_OBJECTS) : lib/libvmod_debug/vcc_if.h include/tbl/vcl_returns.h

# stupid hack to run vmodtool only once
lib/libvmod_debug/vcc_if.c \
	lib/libvmod_debug/vmod_debug.rst \
	lib/libvmod_debug/vmod_debug.man.rst : lib/libvmod_debug/vcc_if.h
	@#

lib/libvmod_debug/vcc_if.h: $(vmodtool) lib/libvmod_debug/vmod.vcc
	cd lib/libvmod_debug/ && @PYTHON@ ../../$(vmodtool) $(vmodtoolargs) $(abs_top_srcdir)/lib/libvmod_debug/vmod.vcc

EXTRA_DIST += lib/libvmod_debug/vmod.vcc

CLEANFILES +=  $(builddir)/lib/libvmod_debug/vcc_if.c  $(builddir)/lib/libvmod_debug/vcc_if.h \
	$(builddir)/lib/libvmod_debug/vmod_debug.rst \
	$(builddir)/lib/libvmod_debug/vmod_debug.man.rst
