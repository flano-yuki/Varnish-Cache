#

lib_libvarnishapi_libvarnishapi_la_CPPFLAGS = \
	-I$(top_srcdir)/lib/libvarnishapi \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	@PCRE_CFLAGS@

lib_LTLIBRARIES += lib/libvarnishapi/libvarnishapi.la

lib_libvarnishapi_libvarnishapi_la_LDFLAGS = $(AM_LT_LDFLAGS) -version-info 1:0:0

lib_libvarnishapi_libvarnishapi_la_SOURCES = \
	lib/libvarnishapi/vsm_api.h \
	lib/libvarnishapi/vsl_api.h \
	lib/libvarnishapi/vxp.h \
	lib/libvarnishapi/vxp_tokens.h \
	\
	lib/libvarnish/vas.c \
	lib/libvarnish/vav.c \
	include/vcs_version.h \
	lib/libvarnish/version.c \
	lib/libvarnish/cli_common.c \
	lib/libvarnish/cli_auth.c \
	lib/libvarnish/vin.c \
	lib/libvarnish/vmb.c \
	lib/libvarnish/vre.c \
	lib/libvarnish/vsb.c \
	lib/libvarnish/vtim.c \
	lib/libvarnish/vnum.c \
	lib/libvarnish/vsha256.c \
	\
	lib/libvarnishapi/vxp_fixed_token.c \
	lib/libvarnishapi/vsm.c \
	lib/libvarnishapi/vsl_arg.c \
	lib/libvarnishapi/vsl_cursor.c \
	lib/libvarnishapi/vsl_dispatch.c \
	lib/libvarnishapi/vsl_query.c \
	lib/libvarnishapi/vsl.c \
	lib/libvarnishapi/vsc.c \
	lib/libvarnishapi/vxp.c \
	lib/libvarnishapi/vxp_parse.c \
	lib/libvarnishapi/vxp_lexer.c \
	lib/libvarnishapi/libvarnishapi.map

lib/libvarnish/lib_libvarnish_libvarnish_la-version.lo FORCE: include/vcs_version.h

lib_libvarnishapi_libvarnishapi_la_CFLAGS = \
	-DVARNISH_STATE_DIR='"${VARNISH_STATE_DIR}"'

lib_libvarnishapi_libvarnishapi_la_LIBADD = @PCRE_LIBS@ @RT_LIBS@

if HAVE_LD_VERSION_SCRIPT
lib_libvarnishapi_libvarnishapi_la_LDFLAGS += -Wl,--version-script=$(top_srcdir)/lib/libvarnishapi/libvarnishapi.map
else
lib_libvarnishapi_libvarnishapi_la_LDFLAGS += -export-symbols-regex '^V'
endif

EXTRA_DIST += \
	lib/libvarnishapi/generate.py \
	lib/libvarnishapi/vsl-tags.rst

#BUILT_SOURCES += \
#	lib/libvarnishapi/vxp_fixed_token.c \
#	lib/libvarnishapi/vxp_tokens.h

CLEANFILES += \
	$(top_builddir)/lib/libvarnishapi/vxp_fixed_token.c \
	$(top_builddir)/lib/libvarnishapi/vxp_tokens.h

MAINTAINERCLEANFILES += \
	lib/libvarnishapi/vsl-tags.rst

noinst_PROGRAMS += lib/libvarnishapi/vsl2rst

lib_libvarnishapi_vsl2rst_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	@PCRE_CFLAGS@

lib_libvarnishapi_vsl2rst_SOURCES = \
	lib/libvarnishapi/vsl2rst.c \
	$(top_srcdir)/include/tbl/vsl_tags.h \
	$(top_srcdir)/include/tbl/vsl_tags_http.h

$(top_builddir)/lib/libvarnishapi/vsl-tags.rst: lib/libvarnishapi/vsl2rst
	lib/libvarnishapi/vsl2rst > lib/libvarnishapi/vsl-tags.rst

lib/libvarnishapi/vxp_fixed_token.c : lib/libvarnishapi/vxp_tokens.h

lib/libvarnishapi/vxp_tokens.h: \
		lib/libvarnishapi/generate.py
	@PYTHON@ $(top_srcdir)/lib/libvarnishapi/generate.py lib/libvarnishapi/ .

EXTRA_PROGRAMS = lib/libvarnishapi/vxp_test lib/libvarnishapi/vsl_glob_test

lib_libvarnishapi_vxp_test_LDADD = @PCRE_LIBS@ \
	${RT_LIBS} ${LIBM} ${PTHREAD_LIBS}

lib_libvarnishapi_vxp_test_CFLAGS = \
	-DVARNISH_STATE_DIR='"${VARNISH_STATE_DIR}"' \
	-DVXP_DEBUG

lib_libvarnishapi_vxp_test_SOURCES = \
	$(libvarnishapi_la_SOURCES) \
	lib/libvarnishapi/vxp_test.c

lib_libvarnishapi_vsl_glob_test_SOURCES = \
	lib/libvarnishapi/vsl_glob_test.c

lib_libvarnishapi_vsl_glob_test_LDADD = @PCRE_LIBS@ ${RT_LIBS} ${LIBM} libvarnishapi.la

lib_libvarnishapi_vsl_glob_test_CFLAGS = -I$(top_srcdir)/include
