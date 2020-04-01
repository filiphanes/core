fs_moduledir = $(moduledir)
fs_module_LTLIBRARIES = \
	libfs_s3.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-fs \
	-I$(top_srcdir)/src/lib-http \
	-I$(top_srcdir)/src/lib-ssl-iostream

NOPLUGIN_LDFLAGS =

libfs_s3_la_SOURCES = \
	fs-s3.c

libfs_s3_la_LIBADD = \
	../../lib-http/libhttp.la \
	../../lib-dns/libdns.la

libfs_s3_la_DEPENDENCIES = \
	../../lib-http/libhttp.la \
	../../lib-dns/libdns.la

libfs_s3_la_LDFLAGS = -module -avoid-version
