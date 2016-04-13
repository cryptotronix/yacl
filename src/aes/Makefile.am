# Copyright (C) 2014 Cryptotronix, LLC.

AUTOMAKE_OPTIONS = subdir-objects

lib_LTLIBRARIES = libaes.la

libaes_la_SOURCES = aes-cbc.c \
                    aes-ccm.c \
                    aes-ctr.c \
                    aes-eax.c \
                    aes-encblock.c \
                    aes-gcm.c \
                    aes.h \
                    aes_i.h \
                    aes-internal.c \
                    aes-internal-dec.c \
                    aes-internal-enc.c \
                    aes-omac1.c \
                    aes-siv.c \
                    aes_siv.h \
                    aes-unwrap.c \
                    aes-wrap.c \
                    aes_wrap.h \
                    common.c \
                    common.h \
                    build_config.h \
                    os.h \
                    os_unix.c \
                    wpa_debug.c \
                    wpa_debug.h \
                    wpabuf.c \
                    wpabuf.h \
                    crypto.h



libaes_la_CPPFLAGS = $(GUILE_CFLAGS) $(LIBSODIUM_CFLAGS) $(LIBGLIB_CFLAGS)
libaes_la_LIBADD = $(GUILE_LIBS) $(LIBSODIUM_LIBS) $(LIBGLIB_LIBS)
