#

DISTCLEANFILES += etc/builtin.vcl

dist_doc_DATA = etc/builtin.vcl \
		etc/example.vcl

etc/builtin.vcl:	bin/varnishd/builtin.vcl
	( printf "This is the VCL configuration Varnish will automatically append to your VCL\nfile during compilation/loading. See the vcl(7) man page for details on syntax\nand semantics.\n\
New users is recommended to use the example.vcl file as a starting point.\n\n";\
	sed -n '/vcl_recv/,$$p' bin/varnishd/builtin.vcl ) | \
	sed 's/^\(.*\)$$/# \1/' > etc/builtin.vcl
