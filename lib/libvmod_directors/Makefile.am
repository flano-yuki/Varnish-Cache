#
lib_libvmod_directors_libvmod_directors_la_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/bin/varnishd \
	-I$(top_builddir)/include \
	-I$(top_builddir)/lib/libvmod_directors

vmod_LTLIBRARIES += lib/libvmod_directors/libvmod_directors.la

lib_libvmod_directors_libvmod_directors_la_LDFLAGS = $(AM_LT_LDFLAGS) -module -export-dynamic -avoid-version -shared

lib_libvmod_directors_libvmod_directors_la_SOURCES = \
	lib/libvmod_directors/vdir.c \
	lib/libvmod_directors/vdir.h \
	lib/libvmod_directors/fall_back.c \
	lib/libvmod_directors/hash.c \
	lib/libvmod_directors/random.c \
	lib/libvmod_directors/round_robin.c

nodist_lib_libvmod_directors_libvmod_directors_la_SOURCES = \
	lib/libvmod_directors/vcc_if.c \
	lib/libvmod_directors/vcc_if.h

lib/libvmod_std/lib_libvmod_std_libvmod_std_la-vmod_vcc_if.lo : include/vmod_abi.h

$(lib_libvmod_directors_libvmod_directors_la_OBJECTS) : lib/libvmod_directors/vcc_if.h include/tbl/vcl_returns.h

# stupid hack to run vmodtool only once
lib/libvmod_directors/vcc_if.c \
	lib/libvmod_directors/vmod_directors.rst \
	lib/libvmod_directors/vmod_directors.man.rst : lib/libvmod_directors/vcc_if.h
	@#

lib/libvmod_directors/vcc_if.h: $(vmodtool) lib/libvmod_directors/vmod.vcc
	cd lib/libvmod_directors/ && @PYTHON@ ../../$(vmodtool) $(vmodtoolargs) $(abs_top_srcdir)/lib/libvmod_directors/vmod.vcc

EXTRA_DIST += lib/libvmod_directors/vmod.vcc

CLEANFILES +=  $(top_builddir)/lib/libvmod_directors/vcc_if.c  $(top_builddir)/lib/libvmod_directors/vcc_if.h \
	$(top_builddir)/lib/libvmod_directors/vmod_directors.rst \
	$(top_builddir)/lib/libvmod_directors/vmod_directors.man.rst
