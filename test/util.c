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


int main(int argc, char *argv[])
{
    g_test_init (&argc, &argv, NULL);

    g_test_add_func ("/util/t_test_random", t_test_random);

    return g_test_run ();
}
