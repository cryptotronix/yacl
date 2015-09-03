#include "../yacl.h"
#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include "../src/ecc/uECC.h"
#include <stdio.h>

START_TEST(t_ecc_kat)
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

}
END_TEST

START_TEST(t_test_curve)
{
    ck_assert (uECC_secp256r1 ==  uECC_curve());

}
END_TEST

static Suite *
witech2_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("ecc");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, t_ecc_kat);
    tcase_add_test(tc_core, t_test_curve);

    suite_add_tcase(s, tc_core);

    return s;
}


int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = witech2_suite();
    sr = srunner_create(s);

    srunner_set_log (sr, "test_result.log");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}