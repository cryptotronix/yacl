# Copyright (C) 2014-2016 Cryptotronix, LLC.

TESTS = ecc hmac util hkdf
check_PROGRAMS = ecc hmac util hkdf

ecc_SOURCES = ecc.c
ecc_CFLAGS = $(LIBGLIB_CFLAGS) $(LIBSODIUM_CFLAGS)
ecc_LDADD = ../libyacl.la $(LIBGLIB_LIBS) $(LIBSODIUM_LIBS)

hmac_SOURCES = hmac.c
hmac_CFLAGS = $(LIBGLIB_CFLAGS) $(LIBSODIUM_CFLAGS)
hmac_LDADD = ../libyacl.la $(LIBGLIB_LIBS) $(LIBSODIUM_LIBS)

hkdf_SOURCES = hkdf_test.c
hkdf_CFLAGS = $(LIBGLIB_CFLAGS) $(LIBSODIUM_CFLAGS)
hkdf_LDADD = ../libyacl.la $(LIBGLIB_LIBS) $(LIBSODIUM_LIBS)

util_SOURCES = util.c
util_CFLAGS = $(LIBGLIB_CFLAGS) $(LIBSODIUM_CFLAGS)
util_LDADD = ../libyacl.la $(LIBGLIB_LIBS) $(LIBSODIUM_LIBS)
