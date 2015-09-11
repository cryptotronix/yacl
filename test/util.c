#include "../yacl.h"
#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include "../src/api.c"
#include <stdio.h>


START_TEST(t_test_random)
{
    int rc;
    uint8_t bytes1[128];
    uint8_t bytes2[128];

    rc = yacl_get_random(bytes1, sizeof(bytes1));
    ck_assert (0 == rc);

    rc = yacl_get_random(bytes2, sizeof(bytes2));
    ck_assert (0 == rc);

    rc = memcmp (bytes1, bytes2, sizeof(bytes1));

    ck_assert (0 != rc);

}
END_TEST

static Suite *
util_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("util");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, t_test_random);

    suite_add_tcase(s, tc_core);

    return s;
}


int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = util_suite();
    sr = srunner_create(s);

    srunner_set_log (sr, "util_result.log");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
