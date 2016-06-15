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

    int rc = yacl_aes256gcm_encrypt(plaintext, sizeof plaintext,
                                    aad, sizeof aad,
                                    key, sizeof key,
                                    nonce, sizeof nonce,
                                    tag, sizeof tag,
                                    ciphertext, sizeof ciphertext);

    g_assert (0 == rc);

    uint8_t *p_copy = malloc (sizeof (plaintext));

    rc = yacl_aes256gcm_decrypt(ciphertext, sizeof ciphertext,
                                aad, sizeof aad,
                                key, sizeof key,
                                nonce, sizeof nonce,
                                tag, sizeof tag,
                                p_copy, sizeof plaintext);

    g_assert (0 == rc);
    g_assert (0 == yacl_memcmp (plaintext, p_copy, sizeof plaintext));

    /* try again with 128 bit key */
    rc = yacl_aes128gcm_encrypt(plaintext, sizeof plaintext,
                                aad, sizeof aad,
                                key, 16,
                                nonce, sizeof nonce,
                                tag, sizeof tag,
                                ciphertext, sizeof ciphertext);

    g_assert (0 == rc);

    p_copy = malloc (sizeof (plaintext));

    rc = yacl_aes128gcm_decrypt(ciphertext, sizeof ciphertext,
                                aad, sizeof aad,
                                key, 16,
                                nonce, sizeof nonce,
                                tag, sizeof tag,
                                p_copy, sizeof plaintext);
    printf ("RC: %d\n", rc);
    g_assert (0 == rc);
    g_assert (0 == yacl_memcmp (plaintext, p_copy, sizeof plaintext));
}

void
aes_gcm_test_vector (void)
{
  /* http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf */
  /* Test Case 4 */
  uint8_t k[] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 };
  uint8_t p[] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
                 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
                 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
                 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
  uint8_t a[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                 0xab, 0xad, 0xda, 0xd2 };
  uint8_t iv[] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  uint8_t c[] = {0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
                 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
                 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
                 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91 };
  uint8_t t[] = {0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47};

  uint8_t *tag = malloc (sizeof t);
  uint8_t *ctext = malloc (sizeof c);
  /* try again with 128 bit key */
  int rc = yacl_aes128gcm_encrypt(p, sizeof p,
                                  a, sizeof a,
                                  k, sizeof k,
                                  iv, sizeof iv,
                                  tag, sizeof t,
                                  ctext, sizeof c);

  g_assert (0 == rc);

  rc = memcmp (ctext, c, sizeof c);
  g_assert (0 == rc);

  rc = memcmp (tag, t, sizeof t);
  g_assert (0 == rc);

  uint8_t *ptext = malloc (sizeof p);
  rc = yacl_aes128gcm_decrypt(ctext, sizeof c,
                              a, sizeof a,
                              k, sizeof k,
                              iv, sizeof iv,
                              tag, sizeof t,
                              ptext, sizeof p);
  g_assert (0 == rc);
  rc = memcmp (p, ptext, sizeof p);
  g_assert ( 0 == rc);
}

int
main(int argc, char **argv)
{
    yacl_init();
    g_test_init (&argc, &argv, NULL);

    g_test_add_func ("/yacl-aes/wrap", test_wrap_unwrap);
    g_test_add_func ("/yacl-aes/gcm", test_aes_gcm_yacl);
    g_test_add_func ("/yacl-aes/gcm/test-vector", aes_gcm_test_vector);


    return g_test_run ();
}
