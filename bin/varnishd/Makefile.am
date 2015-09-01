#

bin_varnishd_varnishd_CPPFLAGS = \
	-I$(top_srcdir)/bin/varnishd \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libvgz \
	-I$(top_builddir)/bin/varnishd \
	-I$(top_builddir)/include

sbin_PROGRAMS += bin/varnishd/varnishd

bin_varnishd_varnishd_SOURCES = \
	bin/varnishd/cache/cache_acceptor.c \
	bin/varnishd/cache/cache_backend.c \
	bin/varnishd/cache/cache_backend_cfg.c \
	bin/varnishd/cache/cache_backend_probe.c \
	bin/varnishd/cache/cache_backend_tcp.c \
	bin/varnishd/cache/cache_ban.c \
	bin/varnishd/cache/cache_busyobj.c \
	bin/varnishd/cache/cache_cli.c \
	bin/varnishd/cache/cache_deliver_proc.c \
	bin/varnishd/cache/cache_director.c \
	bin/varnishd/cache/cache_esi_deliver.c \
	bin/varnishd/cache/cache_esi_fetch.c \
	bin/varnishd/cache/cache_esi_parse.c \
	bin/varnishd/cache/cache_expire.c \
	bin/varnishd/cache/cache_fetch.c \
	bin/varnishd/cache/cache_fetch_proc.c \
	bin/varnishd/cache/cache_gzip.c \
	bin/varnishd/cache/cache_hash.c \
	bin/varnishd/cache/cache_http.c \
	bin/varnishd/cache/cache_lck.c \
	bin/varnishd/cache/cache_main.c \
	bin/varnishd/cache/cache_mempool.c \
	bin/varnishd/cache/cache_obj.c \
	bin/varnishd/cache/cache_panic.c \
	bin/varnishd/cache/cache_pool.c \
	bin/varnishd/cache/cache_req.c \
	bin/varnishd/cache/cache_req_body.c \
	bin/varnishd/cache/cache_req_fsm.c \
	bin/varnishd/cache/cache_rfc2616.c \
	bin/varnishd/cache/cache_range.c \
	bin/varnishd/cache/cache_session.c \
	bin/varnishd/cache/cache_shmlog.c \
	bin/varnishd/cache/cache_vary.c \
	bin/varnishd/cache/cache_vcl.c \
	bin/varnishd/cache/cache_vrt.c \
	bin/varnishd/cache/cache_vrt_priv.c \
	bin/varnishd/cache/cache_vrt_re.c \
	bin/varnishd/cache/cache_vrt_var.c \
	bin/varnishd/cache/cache_vrt_vmod.c \
	bin/varnishd/cache/cache_wrk.c \
	bin/varnishd/cache/cache_ws.c \
	bin/varnishd/common/common_vsm.c \
	bin/varnishd/common/common_vsc.c \
	bin/varnishd/hash/hash_classic.c \
	bin/varnishd/hash/hash_critbit.c \
	bin/varnishd/hash/mgt_hash.c \
	bin/varnishd/hash/hash_simple_list.c \
	bin/varnishd/http1/cache_http1_deliver.c \
	bin/varnishd/http1/cache_http1_fetch.c \
	bin/varnishd/http1/cache_http1_fsm.c \
	bin/varnishd/http1/cache_http1_line.c \
	bin/varnishd/http1/cache_http1_pipe.c \
	bin/varnishd/http1/cache_http1_proto.c \
	bin/varnishd/http1/cache_http1_vfp.c \
	bin/varnishd/mgt/mgt_acceptor.c \
	bin/varnishd/mgt/mgt_child.c \
	bin/varnishd/mgt/mgt_cli.c \
	bin/varnishd/mgt/mgt_jail.c \
	bin/varnishd/mgt/mgt_jail_unix.c \
	bin/varnishd/mgt/mgt_jail_solaris.c \
	bin/varnishd/mgt/mgt_main.c \
	bin/varnishd/mgt/mgt_param.c \
	bin/varnishd/mgt/mgt_param_tbl.c \
	bin/varnishd/mgt/mgt_param_bits.c \
	bin/varnishd/mgt/mgt_param_tcp.c \
	bin/varnishd/mgt/mgt_param_tweak.c \
	bin/varnishd/mgt/mgt_pool.c \
	bin/varnishd/mgt/mgt_shmem.c \
	bin/varnishd/mgt/mgt_vcc.c \
	bin/varnishd/mgt/mgt_vcl.c \
	bin/varnishd/proxy/cache_proxy_proto.c \
	bin/varnishd/storage/stevedore.c \
	bin/varnishd/storage/mgt_stevedore.c \
	bin/varnishd/storage/stevedore_utils.c \
	bin/varnishd/storage/storage_file.c \
	bin/varnishd/storage/storage_malloc.c \
	bin/varnishd/storage/storage_persistent.c \
	bin/varnishd/storage/mgt_storage_persistent.c \
	bin/varnishd/storage/storage_persistent_silo.c \
	bin/varnishd/storage/storage_persistent_subr.c \
	bin/varnishd/storage/storage_umem.c \
	bin/varnishd/waiter/mgt_waiter.c \
	bin/varnishd/waiter/cache_waiter.c \
	bin/varnishd/waiter/cache_waiter_epoll.c \
	bin/varnishd/waiter/cache_waiter_kqueue.c \
	bin/varnishd/waiter/cache_waiter_poll.c \
	bin/varnishd/waiter/cache_waiter_ports.c 

noinst_HEADERS += \
	bin/varnishd/builtin_vcl.h \
	bin/varnishd/cache/cache_esi.h \
	bin/varnishd/cache/cache_pool.h \
	bin/varnishd/cache/cache_priv.h \
	bin/varnishd/common/heritage.h \
	bin/varnishd/hash/hash_slinger.h \
	bin/varnishd/http1/cache_http1.h \
	bin/varnishd/mgt/mgt.h \
	bin/varnishd/mgt/mgt_cli.h \
	bin/varnishd/mgt/mgt_param.h \
	bin/varnishd/storage/storage.h \
	bin/varnishd/storage/storage_persistent.h \
	bin/varnishd/waiter/waiter_priv.h \
	bin/varnishd/waiter/mgt_waiter.h

# Headers for use with vmods
public_varnishd_headers = \
	bin/varnishd/cache/cache.h \
	bin/varnishd/cache/cache_filter.h \
	bin/varnishd/cache/cache_backend.h \
	bin/varnishd/cache/cache_director.h \
	bin/varnishd/common/common.h \
	bin/varnishd/common/params.h \
	bin/varnishd/waiter/waiter.h

# This saddens me, but nobase will strip the path completely
# and we want to change 'bin/varnishd/' to 'varnish/cache/'
# XXX one mkdir per file is wasteful, but we won't risk
# forgetting subdirs
install-data-local: install-public-varnishd-headers
install-public-varnishd-headers:
	for i in $(public_varnishd_headers); do \
		h_dir="$$(dirname $(DESTDIR)$(includedir)/varnish`echo $$i |sed s@bin/varnishd@@`)"; \
		$(install_sh) -d -m 0755 $$h_dir; \
		$(INSTALL_HEADER) $(srcdir)/$$i $$h_dir; \
	done

#		chmod +w $$(dirname $(includedir)/`echo $$i |
#		            sed s@bin/varnishd@varnish@`);
uninstall-hook: uninstall-public-varnishd-headers 
uninstall-public-varnishd-headers :
	for i in $(public_varnishd_headers); do \
		rm -f $(DESTDIR)$(includedir)/`echo $$i | \
			sed s@bin/varnishd@varnish@`; \
	done

.PHONY: install-public-varnishd-headers uninstall-public-varnishd-headers

EXTRA_DIST += $(public_varnishd_headers)

bin_varnishd_varnishd_CFLAGS = \
	@PCRE_CFLAGS@ \
	-DVARNISHD_IS_NOT_A_VMOD \
        -DVARNISH_STATE_DIR='"${VARNISH_STATE_DIR}"' \
	-DVARNISH_VMOD_DIR='"${pkglibdir}/vmods"' \
	-DVARNISH_VCL_DIR='"${varnishconfdir}"'

bin_varnishd_varnishd_LDFLAGS = -export-dynamic

bin_varnishd_varnishd_LDADD = \
	$(top_builddir)/lib/libvarnish/libvarnish.la \
	$(top_builddir)/lib/libvarnishcompat/libvarnishcompat.la \
	$(top_builddir)/lib/libvcc/libvcc.la \
	$(top_builddir)/lib/libvgz/libvgz.la \
	@JEMALLOC_LDADD@ \
	@PCRE_LIBS@ \
	${DL_LIBS} ${PTHREAD_LIBS} ${NET_LIBS} ${LIBM} ${LIBUMEM}

$(bin_varnishd_varnishd_OBJECTS) : include/tbl/vcl_returns.h

EXTRA_DIST += bin/varnishd/builtin.vcl
DISTCLEANFILES += bin/varnishd/builtin_vcl.h

#
# Turn the builtin.vcl file into a C-string we can include in the program.
#
bin/varnishd/builtin_vcl.h:	bin/varnishd/builtin.vcl
	echo '/*' > $@
	echo ' * NB:  This file is machine generated, DO NOT EDIT!' >> $@
	echo ' *' >> $@
	echo ' * Edit builtin.vcl instead and run make' >> $@
	echo ' *' >> $@
	echo ' */' >> $@
	echo '' >> $@
	sed -e 's/"/\\"/g' \
	    -e 's/$$/\\n"/' \
	    -e 's/^/ "/' $(srcdir)/bin/varnishd/builtin.vcl >> $@

# Explicitly record dependency
bin/varnishd/mgt/mgt_vcc.c:	bin/varnishd/builtin_vcl.h
