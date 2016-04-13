#include "../yacl.h"
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>


int main(int argc, char *argv[])
{
    printf ("yeah!\n");

    uint8_t test[32];
    uint8_t out[32];
    memset (test, 0x61, 32);

    return yacl_sha256 (test, 32, out);
}
