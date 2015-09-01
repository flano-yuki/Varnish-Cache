#
pkglib_LTLIBRARIES += lib/libvgz/libvgz.la

lib_libvgz_libvgz_la_LDFLAGS = $(AM__LTLDFLAGS) -avoid-version
lib_libvgz_libvgz_la_CFLAGS = -D_LARGEFILE64_SOURCE=1 -DZLIB_CONST $(libvgz_extra_cflags)

lib_libvgz_libvgz_la_SOURCES = \
	lib/libvgz/adler32.c \
	lib/libvgz/compress.c \
	lib/libvgz/crc32.c \
	lib/libvgz/crc32.h \
	lib/libvgz/deflate.c \
	lib/libvgz/deflate.h \
	lib/libvgz/gzguts.h \
	lib/libvgz/infback.c \
	lib/libvgz/inffast.c \
	lib/libvgz/inffast.h \
	lib/libvgz/inffixed.h \
	lib/libvgz/inflate.c \
	lib/libvgz/inflate.h \
	lib/libvgz/inftrees.c \
	lib/libvgz/inftrees.h \
	lib/libvgz/trees.c \
	lib/libvgz/trees.h \
	lib/libvgz/uncompr.c \
	lib/libvgz/zconf.h \
	lib/libvgz/vgz.h \
	lib/libvgz/zutil.c \
	lib/libvgz/zutil.h

EXTRA_DIST += lib/libvgz/README
