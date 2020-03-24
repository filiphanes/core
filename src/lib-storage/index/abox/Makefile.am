noinst_LTLIBRARIES = libstorage_abox.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-fs \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \

libstorage_abox_la_SOURCES = \
	abox-copy.c \
	abox-file.c \
	abox-mail.c \
	abox-save.c \
	abox-sync.c \
	abox-sync-rebuild.c \
	abox-storage.c

headers = \
	abox-file.h \
	abox-storage.h \
	abox-sync.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
