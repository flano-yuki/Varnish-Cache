#

lib_libvcc_libvcc_la_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include

pkglib_LTLIBRARIES += lib/libvcc/libvcc.la

lib_libvcc_libvcc_la_LDFLAGS = $(AM__LT_LDFLAGS) -avoid-version

lib_libvcc_libvcc_la_SOURCES = \
	lib/libvcc/vcc_compile.h \
	lib/libvcc/vcc_token_defs.h \
	\
	lib/libvcc/vcc_acl.c \
	lib/libvcc/vcc_action.c \
	lib/libvcc/vcc_backend.c \
	lib/libvcc/vcc_backend_util.c \
	lib/libvcc/vcc_compile.c \
	lib/libvcc/vcc_expr.c \
	lib/libvcc/vcc_parse.c \
	lib/libvcc/vcc_fixed_token.c \
	lib/libvcc/vcc_obj.c \
	lib/libvcc/vcc_storage.c \
	lib/libvcc/vcc_utils.c \
	lib/libvcc/vcc_symb.c \
	lib/libvcc/vcc_token.c \
	lib/libvcc/vcc_var.c \
	lib/libvcc/vcc_vmod.c \
	lib/libvcc/vcc_xref.c

EXTRA_DIST += \
	lib/libvcc/generate.py

dist_pkgdata_SCRIPTS += \
	lib/libvcc/vmodtool.py

lib/libvcc/lib_libvcc_libvcc_la-vcc_vmod.lo FORCE: include/vmod_abi.h include/vcl.h

lib/libvcc/lib_libvcc_libvcc_la-vcc_obj.$(OBJEXT) \
	lib/libvcc/lib_libvcc_libvcc_la-vcc_fixed_token.$(OBJEXT) \
	lib/libvcc/lib_libvcc_libvcc_la-vcc_token_defs.$(OBJEXT) : include/vcl.h

CLEANFILES += $(builddir)/lib/libvcc/vcc_token_defs.h \
	$(builddir)/lib/libvcc/vcc_fixed_token.c \
	$(builddir)/lib/libvcc/vcc_obj.c
