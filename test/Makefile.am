# Copyright (C) 2014-2016 Cryptotronix, LLC.
bin_PROGRAMS = basic afl

basic_SOURCES = basic.c
basic_CFLAGS = $(LIBGLIB_CFLAGS) $(LIBSODIUM_CFLAGS)
basic_LDADD = ../libyacl.la $(LIBGLIB_LIBS) $(LIBSODIUM_LIBS)
basic_LDFLAGS = -all-static

afl_SOURCES = afl.c
afl_CFLAGS = $(LIBGLIB_CFLAGS) $(LIBSODIUM_CFLAGS)
afl_LDADD = ../libyacl.la $(LIBGLIB_LIBS) $(LIBSODIUM_LIBS)

TESTS = aes
check_PROGRAMS = aes

aes_SOURCES = test-aes.c
aes_LDADD = ../src/aes/libaes.la

if HAVE_LIBGLIB
TESTS += ecc hmac util hkdf aes-yacl
check_PROGRAMS += ecc hmac util hkdf aes-yacl

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
util_LDADD = ../libyacl.la $(LIBGLIB_LIBS) $(LIBSODIUM_LIBS) ../src/aes/libaes.la

aes_yacl_SOURCES = aes-yacl.c
aes_yacl_CFLAGS = $(LIBGLIB_CFLAGS) $(LIBSODIUM_CFLAGS)
aes_yacl_LDADD = ../libyacl.la $(LIBGLIB_LIBS) $(LIBSODIUM_LIBS) ../src/aes/libaes.la
endif
