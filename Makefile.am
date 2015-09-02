# Copyright (C) 2014 Cryptotronix, LLC.

AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I m4

libyacl_la_CPPFLAGS = $(DEPS_CFLAGS)
libyacl_la_LIBADD = $(DEPS_LIBS)
lib_LTLIBRARIES = libyacl.la

SUBDIRS = .

AM_YFLAGS = -d

libyacl_la_SOURCES = src/ecc/uECC.h \
                     src/ecc/uECC.c \
                     src/hash/sha256.c \
                     src/hash/sha256.h \
                     src/api.c \
                     yacl.h

libyacl_la_LDFLAGS = -version-info $(YACL_SO_VERSION) -release $(YACL_API_VERSION)

yacl_includedir = $(includedir)/yacl-$(YACL_API_VERSION)
nobase_yacl_include_HEADERS = yacl.h

yacl_libincludedir = $(libdir)/yacl-$(YACL_API_VERSION)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = yacl.pc

dist_noinst_SCRIPTS = autogen.sh

#TESTS = src/tests/test_cli.sh
#EXTRA_DIST = src/tests/test_cli.sh
