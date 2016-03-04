/* -*- mode: c; c-file-style: "gnu" -*- */
 #include <libguile.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "extension.h"
#include "../../yacl.h"

static void
copy_to_bytevector (const uint8_t *src, unsigned int len, SCM bv)
{
  unsigned int x = 0;

  assert (SCM_BYTEVECTOR_LENGTH (bv) == len);

  for (x = 0; x < len; x++)
    {
      scm_c_bytevector_set_x (bv, x, src[x]);
    }

}

SCM
yacl_scm_sha256 (SCM bv)
{
    int rc;
    uint8_t out[YACL_SHA256_LEN] = {};
    signed char* p = SCM_BYTEVECTOR_CONTENTS (bv);
    size_t len = SCM_BYTEVECTOR_LENGTH (bv);

    rc = yacl_sha256 (p, len, out);

    SCM digest = scm_c_make_bytevector (YACL_SHA256_LEN);

    memcpy (SCM_BYTEVECTOR_CONTENTS (digest), &out, YACL_SHA256_LEN);

    return digest;

}


void
yacl_init_guile (void)
{
    scm_c_define_gsubr ("yacl-sha256", 1, 0, 0, yacl_scm_sha256);

    scm_c_export ("yacl-sha256", NULL);
}
