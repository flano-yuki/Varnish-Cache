ACLOCAL_AMFLAGS = -I m4

CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =
EXTRA_DIST =
bin_PROGRAMS =
sbin_PROGRAMS =
noinst_PROGRAMS =
noinst_HEADERS =
vmod_LTLIBRARIES =
pkglib_LTLIBRARIES =
dist_pkgdata_SCRIPTS =
check_LTLIBRARIES =
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
BUILT_SOURCES =
pkginclude_HEADERS =
nobase_pkginclude_HEADERS =
nobase_noinst_HEADERS =

# etc
include etc/Makefile.am

# include
include include/Makefile.am

# bin
include bin/varnishd/Makefile.am
include bin/varnishlog/Makefile.am
include bin/varnishncsa/Makefile.am
include bin/varnishadm/Makefile.am
include bin/varnishhist/Makefile.am
include bin/varnishstat/Makefile.am
include bin/varnishtop/Makefile.am
include bin/varnishtest/Makefile.am
# Disabling building of the tools while api is in flux
#include bin/varnishreplay/Makefile.am

# lib
vmoddir = $(pkglibdir)/vmods
vmodtool = $(top_srcdir)/lib/libvcc/vmodtool.py
vmodtoolargs = --strict
lib/libvmod_%.lo : include/vmod_abi.h

include lib/libvarnish/Makefile.am
include lib/libvarnishcompat/Makefile.am
include lib/libvarnishtools/Makefile.am
include lib/libvarnishapi/Makefile.am
include lib/libvcc/Makefile.am
include lib/libvgz/Makefile.am
include lib/libvmod_debug/Makefile.am
include lib/libvmod_std/Makefile.am
include lib/libvmod_directors/Makefile.am

RST2ANY_FLAGS = --halt=2
# doc
include doc/Makefile.am
include doc/graphviz/Makefile.am
include doc/sphinx/Makefile.am

# man
include man/Makefile.am

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = varnishapi.pc

m4dir = $(datadir)/aclocal
m4_DATA = varnish.m4

CLEANFILES += cscope.in.out cscope.out cscope.po.out
EXTRA_DIST += LICENSE autogen.sh varnishapi.pc.in varnish.m4

DISTCHECK_CONFIGURE_FLAGS = \
    --enable-developer-warnings \
    --enable-debugging-symbols \
    --enable-dependency-tracking \
    --enable-tests

distcleancheck_listfiles = \
	find . -type f -exec sh -c 'test -f $(srcdir)/$$1 || echo $$1' \
		sh '{}' ';'

cscope:
	-rm -f cscope*
	find . -name '*.[hcS]' > cscope.files
	cscope -b

.PHONY: cscope
