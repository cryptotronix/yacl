#include "../yacl.h"
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include "../src/api.c"
#include <stdio.h>
#include <glib.h>


static void
t_test_random(void)
{
    int rc;
    uint8_t bytes1[128];
    uint8_t bytes2[128];

    rc = yacl_get_random(bytes1, sizeof(bytes1));
    g_assert (0 == rc);

    rc = yacl_get_random(bytes2, sizeof(bytes2));
    g_assert (0 == rc);

    rc = memcmp (bytes1, bytes2, sizeof(bytes1));

    g_assert (0 != rc);

}

static void
t_yacl_utils (void)
{
    unsigned char  buf_add[1000];
    unsigned char  buf1[1000];
    unsigned char  buf2[1000];
    unsigned char  buf1_rev[1000];
    unsigned char  buf2_rev[1000];
    char           buf3[33];
    unsigned char  buf4[4];
    unsigned char  nonce[24];
    char           nonce_hex[49];
    const char    *hex;
    const char    *hex_end;
    size_t         bin_len;
    unsigned int   i;
    unsigned int   j;
    int            rc;

    randombytes_buf(buf1, sizeof buf1);
    memcpy(buf2, buf1, sizeof buf2);
    g_assert (0 == yacl_memcmp(buf1, buf2, sizeof buf1));
    yacl_memzero(buf1, 0U);
    g_assert (0 == yacl_memcmp(buf1, buf2, sizeof buf1));
    yacl_memzero(buf1, sizeof buf1 / 2);
    g_assert (0 != yacl_memcmp(buf1, buf2, sizeof buf1));
    g_assert (0 == yacl_memcmp(buf1, buf2, 0U));
    yacl_memzero(buf2, sizeof buf2 / 2);
    g_assert (0 == yacl_memcmp(buf1, buf2, sizeof buf1));
    printf("%s\n",
           yacl_bin2hex(buf3, 33U, (const unsigned char *)"0123456789ABCDEF",
                          16U));
    hex = "Cafe : 6942";
    rc = yacl_hex2bin(buf4, sizeof buf4, hex, strlen(hex), ": ", &bin_len, &hex_end);
    g_assert (0 == rc);
    printf("%lu:%02x%02x%02x%02x\n", (unsigned long)bin_len, buf4[0], buf4[1],
           buf4[2], buf4[3]);
    printf("dt1: %ld\n", (long) (hex_end - hex));
    g_assert (0 == rc);

    hex = "Cafe : 6942";
    rc = yacl_hex2bin(buf4, sizeof buf4, hex, strlen(hex), ": ", &bin_len, NULL);
    printf("%lu:%02x%02x%02x%02x\n", (unsigned long)bin_len, buf4[2], buf4[3],
           buf4[2], buf4[3]);
    g_assert (0 == rc);

    hex = "deadbeef";
    g_assert (0 != yacl_hex2bin(buf1, 1U, hex, 8U, NULL, &bin_len, &hex_end) != -1);
    printf("dt2: %ld\n", (long) (hex_end - hex));

    hex = "de:ad:be:eff";
    g_assert (0 != yacl_hex2bin(buf1, 4U, hex, 12U, ":", &bin_len, &hex_end) != -1);
    if (yacl_hex2bin(buf1, 4U, hex, 12U, ":", &bin_len, &hex_end) != -1) {
        printf("yacl_hex2bin() with an odd input length and a short output buffer\n");
    }
    printf("dt3: %ld\n", (long) (hex_end - hex));

    hex = "de:ad:be:eff";
    rc = yacl_hex2bin(buf1, sizeof buf1, hex, 12U, ":", &bin_len, &hex_end);
    g_assert (0 == rc);
    if (yacl_hex2bin(buf1, sizeof buf1, hex, 12U, ":", &bin_len, &hex_end) != 0) {
        printf("yacl_hex2bin() with an odd input length\n");
    }
    printf("dt4: %ld\n", (long) (hex_end - hex));

    hex = "de:ad:be:eff";
    rc = yacl_hex2bin(buf1, sizeof buf1, hex, 13U, ":", &bin_len, &hex_end);
    if (rc != 0) {
        printf("yacl_hex2bin() with an odd input length\n");
    }
    g_assert (rc == 0);
    printf("dt5: %ld\n", (long) (hex_end - hex));

    memset(nonce, 0, sizeof nonce);
    yacl_increment(nonce, sizeof nonce);
    printf("%s\n", yacl_bin2hex(nonce_hex, sizeof nonce_hex,
                                  nonce, sizeof nonce));
    memset(nonce, 255, sizeof nonce);
    yacl_increment(nonce, sizeof nonce);
    printf("%s\n", yacl_bin2hex(nonce_hex, sizeof nonce_hex,
                                  nonce, sizeof nonce));
    nonce[1] = 1U;
    yacl_increment(nonce, sizeof nonce);
    printf("%s\n", yacl_bin2hex(nonce_hex, sizeof nonce_hex,
                                  nonce, sizeof nonce));
    nonce[1] = 0U;
    yacl_increment(nonce, sizeof nonce);
    printf("%s\n", yacl_bin2hex(nonce_hex, sizeof nonce_hex,
                                  nonce, sizeof nonce));
    nonce[0] = 255U;
    nonce[2] = 255U;
    yacl_increment(nonce, sizeof nonce);
    printf("%s\n", yacl_bin2hex(nonce_hex, sizeof nonce_hex,
                                  nonce, sizeof nonce));
    for (i = 0U; i < 1000U; i++) {
        bin_len = (size_t) randombytes_uniform(sizeof buf1);
        randombytes_buf(buf1, bin_len);
        randombytes_buf(buf2, bin_len);
        for (j = 0U; j < bin_len; j++) {
            buf1_rev[bin_len - 1 - j] = buf1[j];
            buf2_rev[bin_len - 1 - j] = buf2[j];
        }
        rc = memcmp(buf1_rev, buf2_rev, bin_len)
            * yacl_compare(buf1, buf2, bin_len);
        if (rc < 0) {
            printf("yacl_compare() failure with length=%u\n",
                   (unsigned int) bin_len);
        }
        g_assert (rc >= 0);
        memcpy(buf1, buf2, bin_len);
        rc = yacl_compare(buf1, buf2, bin_len);
        if (rc) {
            printf("yacl_compare() equality failure with length=%u\n",
                   (unsigned int) bin_len);
        }
        g_assert (0 == rc);
    }
    memset(buf1, 0, sizeof buf1);
    rc = yacl_is_zero(buf1, sizeof buf1);
    if (rc != 1) {
        printf("yacl_is_zero() failed\n");
    }
    g_assert (rc == 1);
    for (i = 0U; i < sizeof buf1; i++) {
        buf1[i]++;
        rc = yacl_is_zero(buf1, sizeof buf1);
        if (rc != 0) {
            printf("yacl_is_zero() failed\n");
        }
        g_assert (rc == 0);
        buf1[i]--;
    }
    bin_len = randombytes_uniform(sizeof buf1);
    randombytes_buf(buf1, bin_len);
    memcpy(buf2, buf1, bin_len);
    memset(buf_add, 0, bin_len);
    j = randombytes_uniform(10000);
    for (i = 0U; i < j; i++) {
        yacl_increment(buf1, bin_len);
        yacl_increment(buf_add, bin_len);
    }
    yacl_add(buf2, buf_add, bin_len);
    rc = yacl_compare(buf1, buf2, bin_len);
    if (rc != 0) {
        printf("yacl_add() failed\n");
    }
    g_assert (rc == 0);
    bin_len = randombytes_uniform(sizeof buf1);
    randombytes_buf(buf1, bin_len);
    memcpy(buf2, buf1, bin_len);
    memset(buf_add, 0xff, bin_len);
    yacl_increment(buf2, bin_len);
    yacl_increment(buf2, 0U);
    yacl_add(buf2, buf_add, bin_len);
    yacl_add(buf2, buf_add, 0U);
    rc = yacl_compare(buf1, buf2, bin_len);
    if (rc != 0) {
        printf("yacl_add() failed\n");
    }
    g_assert (rc == 0);

    assert(sizeof nonce >= 24U);
    memset(nonce, 0xfe, 24U);
    memset(nonce, 0xff, 6U);
    yacl_increment(nonce, 8U);
    printf("%s\n", yacl_bin2hex(nonce_hex, sizeof nonce_hex,
                                  nonce, sizeof nonce));
    memset(nonce, 0xfe, 24U);
    memset(nonce, 0xff, 10U);
    yacl_increment(nonce, 12U);
    printf("%s\n", yacl_bin2hex(nonce_hex, sizeof nonce_hex,
                                  nonce, sizeof nonce));
    memset(nonce, 0xff, 22U);
    yacl_increment(nonce, 24U);
    printf("%s\n", yacl_bin2hex(nonce_hex, sizeof nonce_hex,
                                  nonce, sizeof nonce));


    assert(sizeof nonce >= 24U);
    memset(nonce, 0xfe, 24U);
    memset(nonce, 0xff, 6U);
    yacl_add(nonce, nonce, 7U);
    yacl_add(nonce, nonce, 8U);
    printf("%s\n", yacl_bin2hex(nonce_hex, sizeof nonce_hex,
                                  nonce, sizeof nonce));
    memset(nonce, 0xfe, 24U);
    memset(nonce, 0xff, 10U);
    yacl_add(nonce, nonce, 11U);
    yacl_add(nonce, nonce, 12U);
    printf("%s\n", yacl_bin2hex(nonce_hex, sizeof nonce_hex,
                                  nonce, sizeof nonce));
    memset(nonce, 0xff, 22U);
    yacl_add(nonce, nonce, 23U);
    yacl_add(nonce, nonce, 24U);
    printf("%s\n", yacl_bin2hex(nonce_hex, sizeof nonce_hex,
                                  nonce, sizeof nonce));

}



int main(int argc, char *argv[])
{
    yacl_init ();
    g_test_init (&argc, &argv, NULL);

    g_test_add_func ("/util/t_test_random", t_test_random);
    g_test_add_func ("/util/t_yacl_util", t_yacl_utils);

    return g_test_run ();
}
