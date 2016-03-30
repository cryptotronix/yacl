#include "../yacl.h"
#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include "../src/ecc/uECC.h"
#include <stdio.h>
#include <glib.h>


static void
t_ecc_kat(void)
{

    /* test vector from Suite B Implementer Guide to FIPS 186-3 */
    /* https://www.nsa.gov/ia/_files/ecdsa.pdf */

    int rc;
    uint8_t pub[] = {0x81, 0x01, 0xec, 0xe4, 0x74, 0x64, 0xa6, 0xea, 0xd7, 0x0c,
                     0xf6, 0x9a, 0x6e, 0x2b, 0xd3, 0xd8, 0x86, 0x91, 0xa3, 0x26,
                     0x2d, 0x22, 0xcb, 0xa4, 0xf7, 0x63, 0x5e, 0xaf, 0xf2, 0x66,
                     0x80, 0xa8, 0xd8, 0xa1, 0x2b, 0xa6, 0x1d, 0x59, 0x92, 0x35,
                     0xf6, 0x7d, 0x9c, 0xb4, 0xd5, 0x8f, 0x17, 0x83, 0xd3, 0xca,
                     0x43, 0xe7, 0x8f, 0x0a, 0x5a, 0xba, 0xa6, 0x24, 0x07, 0x99,
                     0x36, 0xc0, 0xc3, 0xa9 };

    uint8_t dig[] = {0x7c, 0x3e, 0x88, 0x3d, 0xdc, 0x8b, 0xd6, 0x88, 0xf9, 0x6e,
                     0xac, 0x5e, 0x93, 0x24, 0x22, 0x2c, 0x8f, 0x30, 0xf9, 0xd6,
                     0xbb, 0x59, 0xe9, 0xc5, 0xf0, 0x20, 0xbd, 0x39, 0xba, 0x2b,
                     0x83, 0x77 };

    uint8_t sig[] = {0x72, 0x14, 0xbc, 0x96, 0x47, 0x16, 0x0b, 0xbd, 0x39, 0xff,
                     0x2f, 0x80, 0x53, 0x3f, 0x5d, 0xc6, 0xdd, 0xd7, 0x0d, 0xdf,
                     0x86, 0xbb, 0x81, 0x56, 0x61, 0xe8, 0x05, 0xd5, 0xd4, 0xe6,
                     0xf2, 0x7c, 0x7d, 0x1f, 0xf9, 0x61, 0x98, 0x0f, 0x96, 0x1b,
                     0xda, 0xa3, 0x23, 0x3b, 0x62, 0x09, 0xf4, 0x01, 0x33, 0x17,
                     0xd3, 0xe3, 0xf9, 0xe1, 0x49, 0x35, 0x92, 0xdb, 0xea, 0xa1,
                     0xaf, 0x2b, 0xc3, 0x67 };



    rc = yacl_ecdsa_verify(pub, dig, sig);

    g_assert (0 == rc);

}

static void
t_test_curve(void)
{
    g_assert (uECC_secp256r1 ==  uECC_curve());

}


static void
t_combined(void)
{

    uint8_t public_key[YACL_P256_COORD_SIZE*2];
    uint8_t private_key[YACL_P256_COORD_SIZE];

    int rc = yacl_create_key_pair(public_key, private_key);
    g_assert (rc == 0);

    uint8_t data[] = {0x01, 0x02, 0x03};
    uint8_t signature[YACL_P256_COORD_SIZE*2];

    rc = yacl_hash_ecdsa_sign(data, sizeof(data),
                              private_key, signature);

    g_assert (0 == rc);

    rc = yacl_hash_verify (data, sizeof(data),
                           public_key, signature);

    g_assert (0 == rc);

    rc = yacl_hash_verify (data, sizeof(data - 1),
                           public_key, signature);

    g_assert (0 != rc);
}

static void
t_ecdh(void)
{
    uint8_t alice_pub[YACL_P256_COORD_SIZE*2];
    uint8_t bob_pub[YACL_P256_COORD_SIZE*2];

    uint8_t alice_pri[YACL_P256_COORD_SIZE];
    uint8_t bob_pri[YACL_P256_COORD_SIZE];

    uint8_t alice_secret[YACL_P256_COORD_SIZE];
    uint8_t bob_secret[YACL_P256_COORD_SIZE];

    int rc;

    rc = yacl_create_key_pair(alice_pub, alice_pri);

    g_assert (0 == rc);
    rc = yacl_create_key_pair(bob_pub, bob_pri);
    g_assert (0 == rc);


    rc = yacl_ecdh (bob_pub, alice_pri, alice_secret);

    g_assert (0 == rc);

    rc = yacl_ecdh (alice_pub, bob_pri, bob_secret);
    g_assert (0 == rc);

    g_assert (0 == memcmp (alice_secret, bob_secret, YACL_P256_COORD_SIZE));
}


int main(int argc, char *argv[])
{
    g_test_init (&argc, &argv, NULL);

    g_test_add_func ("/ecc/curve", t_test_curve);
    g_test_add_func ("/ecc/kat", t_ecc_kat);
    g_test_add_func ("/ecc/ecdh", t_ecdh);
    g_test_add_func ("/ecc/combined", t_combined);

    return g_test_run ();
}
