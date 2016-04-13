# Copyright (C) 2014 Cryptotronix, LLC.

AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libyacl.la

SUBDIRS = . src/aes test

if HAVE_GUILE
SUBDIRS += src/guile
endif

AM_YFLAGS = -d

libyacl_la_SOURCES = src/ecc/uECC.h \
                     src/ecc/uECC.c \
                     src/hash/sha256.c \
                     src/hash/sha256.h \
                     src/hash/hkdf.c \
                     src/api.c \
                     src/sodium_wrappers.c \
                     src/hexdump.c \
                     src/base64url.c \
                     src/base64url.h \
                     yacl.h

if !HAVE_LIBSODIUM
libyacl_la_SOURCES += src/libsodium/sodium.h \
                     src/libsodium/sodium/core.c \
                     src/libsodium/sodium/core.h \
                     src/libsodium/sodium/export.h \
                     src/libsodium/sodium/utils.h \
                     src/libsodium/sodium/utils.c \
                     src/libsodium/sodium/runtime.c \
                     src/libsodium/sodium/runtime.h \
                     src/libsodium/sodium/randombytes.h \
                     src/libsodium/sodium/randombytes_sysrandom.h \
                     src/libsodium/sodium/randombytes.c \
                     src/libsodium/sodium/randombytes_sysrandom.c \
                     src/libsodium/sodium/version.c \
                     src/libsodium/sodium/version.h
endif

if WANT_ARM
libyacl_la_SOURCES += src/ecc/asm_arm.inc
endif

if HAVE_GUILE
libyacl_la_SOURCES += src/guile/extension.c \
                      src/guile/extension.h

endif

# SCM_SOURCES = src/guile/cryptotronix/yacl.scm
# pkgguilesitedir = $(GUILE_SITE)
# nobase_dist_pkgguilesite_DATA = $(SCM_SOURCES)
# ETAGS_ARGS = $(SCM_SOURCES)
# endif

libyacl_la_CPPFLAGS = $(DEPS_CFLAGS) $(GUILE_CFLAGS) $(LIBSODIUM_CFLAGS) $(LIBGLIB_CFLAGS)
libyacl_la_LIBADD = $(DEPS_LIBS) $(GUILE_LIBS) $(LIBSODIUM_LIBS) $(LIBGLIB_LIBS) src/aes/libaes.la


libyacl_la_LDFLAGS = -version-info $(YACL_SO_VERSION) -release $(YACL_API_VERSION)

yacl_includedir = $(includedir)/yacl-$(YACL_API_VERSION)
nobase_yacl_include_HEADERS = yacl.h

yacl_libincludedir = $(libdir)/yacl-$(YACL_API_VERSION)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = yacl.pc

dist_noinst_SCRIPTS = autogen.sh

EXTRA_DIST =  rpm/yacl.spec
