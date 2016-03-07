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

SCM
yacl_scm_gen_p256_key_pair (void)
{
    int rc;
    uint8_t q[YACL_P256_COORD_SIZE*2];
    uint8_t d[YACL_P256_COORD_SIZE];
    rc = yacl_create_key_pair(q, d);

    SCM qs = scm_c_make_bytevector (YACL_SHA256_LEN*2);
    SCM ds = scm_c_make_bytevector (YACL_SHA256_LEN);

    memcpy (SCM_BYTEVECTOR_CONTENTS (qs), &q, YACL_SHA256_LEN*2);
    memcpy (SCM_BYTEVECTOR_CONTENTS (ds), &d, YACL_SHA256_LEN);

    SCM q_list = scm_list_2 (scm_from_locale_symbol ("q"), qs);
    SCM d_list = scm_list_2 (scm_from_locale_symbol ("d"), ds);
    SCM curve_list = scm_list_2 (scm_from_locale_symbol ("curve"),
                                 scm_from_locale_string("NIST P-256"));
    SCM l = scm_list_4 (scm_from_locale_symbol ("ecc"),
                        curve_list,
                        q_list,
                        d_list);


    SCM pri_key = scm_list_2 (scm_from_locale_symbol ("private-key"),
                              l);


    return pri_key;
}

SCM
yacl_scm_p256_sign(SCM data, SCM d)
{
    int rc;
    uint8_t out[YACL_SHA256_LEN*2] = {};
    unsigned char* data_ptr = SCM_BYTEVECTOR_CONTENTS (data);
    size_t data_len = SCM_BYTEVECTOR_LENGTH (data);

    unsigned char* d_ptr = SCM_BYTEVECTOR_CONTENTS (d);
    size_t d_len = SCM_BYTEVECTOR_LENGTH (d);

    rc = yacl_hash_ecdsa_sign(data_ptr, data_len, d_ptr, out);

    SCM sig = scm_c_make_bytevector (YACL_SHA256_LEN*2);
    memcpy (SCM_BYTEVECTOR_CONTENTS (sig), &out, YACL_SHA256_LEN*2);

    return sig;
}

SCM
yacl_scm_p256_verify(SCM data, SCM q, SCM sig)
{
    int rc;
    unsigned char* data_ptr = SCM_BYTEVECTOR_CONTENTS (data);
    size_t data_len = SCM_BYTEVECTOR_LENGTH (data);

    unsigned char* q_ptr = SCM_BYTEVECTOR_CONTENTS (q);
    size_t q_len = SCM_BYTEVECTOR_LENGTH (q);

    unsigned char* sig_ptr = SCM_BYTEVECTOR_CONTENTS (sig);
    size_t sig_len = SCM_BYTEVECTOR_LENGTH (sig);

    rc = yacl_hash_verify(data_ptr, data_len, q_ptr, sig_ptr);

    if (0 == rc)
        return SCM_BOOL_T;
    else
        return SCM_BOOL_F;

}

void
yacl_init_guile (void)
{
    scm_c_define_gsubr ("yacl-sha256", 1, 0, 0, yacl_scm_sha256);
    scm_c_define_gsubr ("yacl-gen-p256-key-pair", 0, 0, 0,
                        yacl_scm_gen_p256_key_pair);
    scm_c_define_gsubr ("yacl-p256-sign", 2, 0, 0, yacl_scm_p256_sign);
    scm_c_define_gsubr ("yacl-p256-verify", 3, 0, 0, yacl_scm_p256_verify);

    scm_c_export ("yacl-sha256", NULL);
    scm_c_export ("yacl-gen-p256-key-pair", NULL);
    scm_c_export ("yacl-p256-sign", NULL);
    scm_c_export ("yacl-p256-verify", NULL);
}
