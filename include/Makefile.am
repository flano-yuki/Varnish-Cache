#

# API headers

public_include_headers = \
	include/tbl/acct_fields_req.h \
	include/tbl/acct_fields_bereq.h \
	include/tbl/backend_poll.h \
	include/tbl/ban_vars.h \
	include/tbl/bo_flags.h \
	include/tbl/body_status.h \
	include/tbl/debug_bits.h \
	include/tbl/feature_bits.h \
	include/tbl/http_headers.h \
	include/tbl/http_response.h \
	include/tbl/locks.h \
	include/tbl/obj_attr.h \
	include/tbl/params.h \
	include/tbl/req_body.h \
	include/tbl/req_flags.h \
	include/tbl/sess_attr.h \
	include/tbl/sess_close.h \
	include/tbl/steps.h \
	include/tbl/symbol_kind.h \
	include/tbl/vcc_types.h \
	include/tbl/vcl_returns.h \
	include/tbl/vrt_stv_var.h \
	include/tbl/vsc_types.h \
	include/tbl/vsc_all.h \
	include/tbl/vsc_fields.h \
	include/tbl/vsc_levels.h \
	include/tbl/vsc_f_main.h \
	include/tbl/vsl_tags.h \
	include/tbl/vsl_tags_http.h \
	include/vapi/vsm.h \
	include/vapi/vsm_int.h \
	include/vapi/vsc.h \
	include/vapi/vsc_int.h \
	include/vapi/vsl.h \
	include/vapi/vsl_int.h \
	include/vapi/voptget.h \
	include/vapi/vapi_options.h \
	include/vcli.h

# This saddens me, but nobase will strip the path completely
# and we want to keep everything after 'include/'
# XXX one mkdir per file is wasteful, but we won't risk
# forgetting subdirs
install-data-local: install-public-include-headers
install-public-include-headers:
	for i in $(public_include_headers); do \
		h_dir="$$(dirname $(DESTDIR)$(includedir)/varnish`echo $$i | sed s@include@@`)"; \
		$(install_sh) -d -m 0755 $$h_dir; \
		$(INSTALL_HEADER) $(srcdir)/$$i $$h_dir; \
	done

#		chmod +w $$(dirname $(includedir)/`echo $$i |
#			sed s@include@varnish@`);
uninstall-hook: uninstall-public-include-headers 
uninstall-public-include-headers :
	for i in $(public_include_headers); do \
		rm -f $(DESTDIR)$(includedir)/`echo $$i | sed s@include@varnish@`; \
	done
	
.PHONY : install-public-include-headers uninstall-public-include-headers
EXTRA_DIST += $(public_include_headers)

# Headers for use with vmods
pkginclude_HEADERS += \
	include/miniobj.h \
	include/vas.h \
	include/vav.h \
	include/vbm.h \
	include/vcl.h \
	include/vcs.h \
	include/vmod_abi.h \
	include/vqueue.h \
	include/vre.h \
	include/vdef.h \
	include/vrt.h \
	include/vrt_obj.h \
	include/vsa.h \
	include/vsb.h \
	include/vsha256.h \
	include/vtcp.h \
	include/vtim.h

# Private headers
nobase_noinst_HEADERS += \
	include/binary_heap.h \
	include/compat/daemon.h \
	include/compat/execinfo.h \
	include/flopen.h \
	include/libvcc.h \
	include/vcli_common.h \
	include/vcli_priv.h \
	include/vcli_serve.h \
	include/vcs_version.h \
	include/vct.h \
	include/vcurses.h \
	include/vend.h \
	include/vev.h \
	include/vfil.h \
	include/vin.h \
	include/vlu.h \
	include/vmb.h \
	include/vnum.h \
	include/vpf.h \
	include/vrnd.h \
	include/vsl_priv.h \
	include/vsm_priv.h \
	include/vsub.h \
	include/vss.h \
	include/vtcp.h \
	include/vtree.h \
	include/vut.h \
	include/vut_options.h

include/tbl/vrt_stv_var.h \
	include/tbl/vcl_returns.h \
	include/tbl/vcc_types.h \
	include/vrt_obj.h \
	lib/libvcc/vcc_fixed_token.c \
	lib/libvcc/vcc_obj.c \
	lib/libvcc/vcc_token_defs.h: \
		include/vcl.h
include/vcl.h: lib/libvcc/generate.py include/vrt.h 
	mkdir -p include/tbl
	@PYTHON@ $(top_srcdir)/lib/libvcc/generate.py . .

MAINTAINERCLEANFILES += $(top_builddir)/include/vcs_version.h

include/vcs_version.h:
	@mkdir -p include
	@if [ -d "$(top_srcdir)/.git" ]; then \
		V="$$(git show -s --pretty=format:%h)" \
		B="$$(git rev-parse --abbrev-ref HEAD)" \
		H="$$(head -n 1 include/vcs_version.h 2>/dev/null || true)"; \
		if [ "/* $$V */" != "$$H" ]; then \
		( \
		  echo "/* $$V */" ;\
		  echo '/*' ;\
		  echo ' * NB:  This file is machine generated, DO NOT EDIT!' ;\
		  echo ' *' ;\
		  echo ' * Run make to regenerate' ;\
		  echo ' *'  ;\
		  echo ' */' ;\
		  echo "/* $$V */" ;\
		  echo '' ;\
		  echo "#define VCS_Version \"$$V\"" ; \
		  echo "#define VCS_Branch \"$$B\"" \
		) > include/vcs_version.h ; \
		fi \
	else \
		if [ ! -f include/vcs_version.h ]; then \
		( \
		  echo "/* NOGIT */" ; \
		  echo '/* No git commit ID available, see include/Makefile.am for explanation */' ; \
		  echo '#define VCS_Version "NOGIT"' ; \
		  echo '#define VCS_Branch "NOGIT"' \
		) >  include/vcs_version.h ; \
		fi \
	fi
FORCE:

# If vcs_version contains NOGIT, Varnish has not been built from a
# tarball made with make dist, nor from a git checkout, so there's no
# way for us to give strong guarantees about what version you're
# actually running.
#
# The way to fix this is to either build Varnish from a tarball made
# with `make dist` or a git checkout.

include/vmod_abi.h: include/vcs_version.h
	@GITID=$$(sed 's/[^0-9a-f]//g;q' include/vcs_version.h) ; \
	if [ -z "$$GITID" ]; then \
		echo "warning: weak VMOD ABI checking, see include/Makefile.am" ; \
	fi ; \
	echo "#define VMOD_ABI_Version \"@PACKAGE_STRING@ $$GITID\"" > $(top_builddir)/include/vmod_abi.h

CLEANFILES += \
	include/tbl/vcl_returns.h \
	include/tbl/vrt_stv_var.h \
	include/vcl.h \
	include/vrt_obj.h \
	include/vmod_abi.h
