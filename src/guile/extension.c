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

SCM
yacl_scm_get_random (SCM len)
{
  if (!scm_is_integer (len))
    goto EXCEPTION;

  size_t rndlen = scm_to_size_t (len);
  SCM rnd = scm_c_make_bytevector (rndlen);
  int rc = yacl_get_random(SCM_BYTEVECTOR_CONTENTS (rnd), rndlen);
  if (rc)
    goto EXCEPTION;
  else
    goto OUT;

 EXCEPTION:
  scm_throw (scm_from_locale_symbol ("BADRANDOM"), SCM_BOOL_T);
 OUT:
  return rnd;

}

SCM
yacl_scm_hexdump (SCM bv)
{
  int rc;
  unsigned char* data_ptr = SCM_BYTEVECTOR_CONTENTS (bv);
  size_t data_len = SCM_BYTEVECTOR_LENGTH (bv);

  yacl_hexdump (data_ptr, data_len);

  return SCM_BOOL_T;
}

SCM
yacl_scm_hkdf_sha256 (SCM ikm, SCM salt, SCM info)
{

  int rc;
  uint8_t * ikm_ptr, *salt_ptr, *info_ptr;
  size_t ikm_len, salt_len, info_len;

  if (!scm_is_bytevector (ikm))
    scm_throw (scm_from_locale_symbol ("BADIKM"), SCM_BOOL_T);

  ikm_ptr = SCM_BYTEVECTOR_CONTENTS (ikm);
  ikm_len = SCM_BYTEVECTOR_LENGTH (ikm);

  if (SCM_UNBNDP (salt))
    {
      salt_ptr = NULL;
      salt_len = 0;
    }
  else if (!scm_is_bytevector (salt))
    scm_throw (scm_from_locale_symbol ("BADSALT"), SCM_BOOL_T);
  else
    {
      salt_ptr = SCM_BYTEVECTOR_CONTENTS(salt);
      salt_len = SCM_BYTEVECTOR_LENGTH (salt);
    }

  if (SCM_UNBNDP (info))
    {
      info_ptr = NULL;
      info_len = 0;
    }
  else if (!scm_is_bytevector (info))
    scm_throw (scm_from_locale_symbol ("BADINFO"), SCM_BOOL_T);
  else
    {
      info_ptr = SCM_BYTEVECTOR_CONTENTS(info);
      info_len = SCM_BYTEVECTOR_LENGTH (info);
    }

  SCM out = scm_c_make_bytevector (YACL_SHA256_LEN);


  rc = yacl_hkdf_256(salt_ptr, salt_len,
                     ikm_ptr, ikm_len,
                     info_ptr, info_len,
                     SCM_BYTEVECTOR_CONTENTS (out), YACL_SHA256_LEN);

  if (rc)
    scm_throw (scm_from_locale_symbol ("BADHKDF"), SCM_BOOL_T);

  return out;

}

SCM
yacl_scm_b64url_encode (SCM bv)
{
  if (!scm_is_bytevector (bv))
    scm_throw (scm_from_locale_symbol ("BADBV"), SCM_BOOL_T);

  uint8_t *bv_ptr;
  size_t bv_len;

  bv_ptr = SCM_BYTEVECTOR_CONTENTS (bv);
  bv_len = SCM_BYTEVECTOR_LENGTH (bv);

  char *b64url = yacl_b64url_encode (bv_ptr, bv_len);

  if (NULL == b64url)
    scm_throw (scm_from_locale_symbol ("BADENCODE"), SCM_BOOL_T);

  SCM out = scm_from_utf8_string (b64url);

  free (b64url);

  return out;

}

SCM
yacl_scm_b64url_decode (SCM scmb64)
{
  if (!scm_is_string (scmb64))
    scm_throw (scm_from_locale_symbol ("BADSTR"), SCM_BOOL_T);

  size_t scmb64len, outlen;
  char * b64url = scm_to_utf8_stringn (scmb64, &scmb64len);

  if (NULL == b64url)
    scm_throw (scm_from_locale_symbol ("BADDECODE"), SCM_BOOL_T);

  uint8_t *decode = yacl_b64url_decode (b64url, &outlen);

  free (b64url);

  if (NULL == decode)
      scm_throw (scm_from_locale_symbol ("BADDECODED"), SCM_BOOL_T);

  SCM b64 = scm_c_make_bytevector (outlen);
  memcpy (SCM_BYTEVECTOR_CONTENTS (b64), decode, outlen);

  free (decode);

  return b64;


}

void
yacl_init_guile (void)
{
    scm_c_define_gsubr ("yacl-sha256", 1, 0, 0, yacl_scm_sha256);
    scm_c_define_gsubr ("yacl-gen-p256-key-pair", 0, 0, 0,
                        yacl_scm_gen_p256_key_pair);
    scm_c_define_gsubr ("yacl-p256-sign", 2, 0, 0, yacl_scm_p256_sign);
    scm_c_define_gsubr ("yacl-p256-verify", 3, 0, 0, yacl_scm_p256_verify);
    scm_c_define_gsubr ("yacl-get-random", 1, 0, 0, yacl_scm_get_random);
    scm_c_define_gsubr ("yacl-hexdump", 1, 0, 0, yacl_scm_hexdump);
    scm_c_define_gsubr ("yacl-hkdf-sha256", 1, 2, 0, yacl_scm_hkdf_sha256);
    scm_c_define_gsubr ("yacl-b64url-encode", 1, 0, 0, yacl_scm_b64url_encode);
    scm_c_define_gsubr ("yacl-b64url-decode", 1, 0, 0, yacl_scm_b64url_decode);

    scm_c_export ("yacl-sha256",
                  "yacl-gen-p256-key-pair",
                  "yacl-p256-sign",
                  "yacl-p256-verify",
                  "yacl-get-random",
                  "yacl-hexdump",
                  "yacl-hkdf-sha256",
                  "yacl-b64url-encode",
                  "yacl-b64url-decode",
                  NULL);

    yacl_init ();
}
