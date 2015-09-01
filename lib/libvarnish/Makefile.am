lib_libvarnish_libvarnish_la_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	@PCRE_CFLAGS@

pkglib_LTLIBRARIES += lib/libvarnish/libvarnish.la

lib_libvarnish_libvarnish_la_LDFLAGS = $(AM_LT_LDFLAGS) -avoid-version

lib_libvarnish_libvarnish_la_SOURCES = \
	lib/libvarnish/vav.c \
	lib/libvarnish/vas.c \
	lib/libvarnish/binary_heap.c \
	lib/libvarnish/vsub.c \
	lib/libvarnish/cli_auth.c \
	lib/libvarnish/cli_common.c \
	lib/libvarnish/cli_serve.c \
	lib/libvarnish/flopen.c \
	lib/libvarnish/vnum.c \
	lib/libvarnish/vtim.c \
	lib/libvarnish/vtcp.c \
	lib/libvarnish/vct.c \
	lib/libvarnish/version.c \
	lib/libvarnish/vev.c \
	lib/libvarnish/vfil.c \
	lib/libvarnish/vin.c \
	lib/libvarnish/vlu.c \
	lib/libvarnish/vmb.c \
	lib/libvarnish/vpf.c \
	lib/libvarnish/vre.c \
	lib/libvarnish/vrnd.c \
	lib/libvarnish/vsa.c \
	lib/libvarnish/vsb.c \
	lib/libvarnish/vsha256.c \
	lib/libvarnish/vss.c

lib_libvarnish_libvarnish_la_CFLAGS = -DVARNISH_STATE_DIR='"${VARNISH_STATE_DIR}"'
lib_libvarnish_libvarnish_la_LIBADD = ${RT_LIBS} ${NET_LIBS} ${LIBM} @PCRE_LIBS@

if ENABLE_TESTS
TESTS += lib/libvarnish/vnum_c_test

noinst_PROGRAMS += lib/libvarnish/vnum_c_test

lib_libvarnish_vnum_c_test_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	@PCRE_CFLAGS@

lib_libvarnish_vnum_c_test_SOURCES = lib/libvarnish/vnum.c lib/libvarnish/vas.c
lib_libvarnish_vnum_c_test_CFLAGS = -DNUM_C_TEST -include config.h
lib_libvarnish_vnum_c_test_LDADD = ${LIBM}

test: lib/libvarnish/vnum_c_test
	@for test in ${TESTS} ; do ./$${test} ; done
endif
