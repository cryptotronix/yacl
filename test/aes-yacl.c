/* -*- mode: c; c-file-style: "gnu" -*- */
#include "../yacl.h"
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <glib.h>
#include <string.h>

static void
test_wrap_unwrap (void)
{
    uint8_t kek[32];
    memset (kek, 0x61, sizeof kek);

    uint8_t wkey[32];
    memset (wkey, 0x62, 32);
    uint8_t wkey2[32];

    uint8_t cipher[40];

    int rc = yacl_aes_wrap(kek, sizeof(kek), wkey, cipher);

    g_assert (0 == rc);

    yacl_hexdump (cipher, sizeof cipher);
    yacl_hexdump (wkey, sizeof wkey);

    rc = yacl_aes_unwrap(kek, sizeof(kek), cipher, wkey2);
    g_assert (0 == rc);

    g_assert (0 == memcmp (wkey, wkey2, 32));

    yacl_hexdump (wkey2, sizeof wkey2);
}

static void
test_aes_gcm_yacl (void)
{
    uint8_t plaintext[16];
    memset (plaintext, 0x61, sizeof plaintext);

    uint8_t aad[16];
    memset (aad, 0x62, sizeof aad);

    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
    unsigned char ciphertext[sizeof(plaintext)];
    unsigned long long ciphertext_len;
    unsigned char tag[crypto_aead_aes256gcm_ABYTES];

    yacl_get_random(key, sizeof key);
    yacl_get_random(nonce, sizeof nonce);

    int rc = yacl_aes_gcm_encrypt(plaintext, sizeof plaintext,
                                  aad, sizeof aad,
                                  key, sizeof key,
                                  nonce, sizeof nonce,
                                  tag, sizeof tag,
                                  ciphertext, sizeof ciphertext);

    g_assert (0 == rc);

    uint8_t *p_copy = malloc (sizeof (plaintext));

    rc = yacl_aes_gcm_decrypt(ciphertext, sizeof ciphertext,
                              aad, sizeof aad,
                              key, sizeof key,
                              nonce, sizeof nonce,
                              tag, sizeof tag,
                              p_copy, sizeof plaintext);

    g_assert (0 == rc);
    g_assert (0 == yacl_memcmp (plaintext, p_copy, sizeof plaintext));

}

int
main(int argc, char **argv)
{
    yacl_init();
    g_test_init (&argc, &argv, NULL);

    g_test_add_func ("/yacl-aes/wrap", test_wrap_unwrap);
    g_test_add_func ("/yacl-aes/gcm", test_aes_gcm_yacl);


    return g_test_run ();
}
