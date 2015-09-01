#
#
EXTRA_DIST += doc/changes.rst doc/changes.html

doc/changes.html: doc/changes.rst
if HAVE_RST2HTML
	${RST2HTML} ${RST2ANY_FLAGS} $? $@
else
	@echo "========================================"
	@echo "You need rst2html installed to make dist"
	@echo "========================================"
	@false
endif
