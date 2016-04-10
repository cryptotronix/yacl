/* -*- mode: c; c-file-style: "gnu" -*- */

#include "config.h"

#include <assert.h>
#include "../../yacl.h"
#include "sha256.h"

/*
 *  hkdfExtract
 *
 *  Description:
 *      This function will perform HKDF extraction.
 *
 *  Parameters:
 *      whichSha: [in]
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      salt[ ]: [in]
 *          The optional salt value (a non-secret random value);
 *          if not provided (salt == NULL), it is set internally
 *          to a string of HashLen(whichSha) zeros.
 *      salt_len: [in]
 *          The length of the salt value.  (Ignored if salt == NULL.)
 *      ikm[ ]: [in]
 *          Input keying material.
 *      ikm_len: [in]
 *          The length of the input keying material.
 *      prk[ ]: [out]
 *          Array where the HKDF extraction is to be stored.
 *          Must be larger than USHAHashSize(whichSha);
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int
yacl_hkdf_256_extract( const uint8_t *salt, int salt_len,
                       const uint8_t *ikm, int ikm_len,
                       uint8_t prk[YACL_SHA256_LEN])
{
  unsigned char nullSalt[YACL_SHA256_LEN];
  int rc;

  assert (salt >= 0);
  assert (ikm);
  assert (prk);

  if (salt == 0)
    {
      salt = nullSalt;
      salt_len = YACL_SHA256_LEN;
      memset(nullSalt, '\0', salt_len);
    }


  rc = yacl_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

  return rc;
}


int
yacl_hkdf_256_expand(const uint8_t prk[ ], int prk_len,
                     const unsigned char *info, int info_len,
                     uint8_t okm[ ], int okm_len)
{
  int hash_len, N;
  unsigned char T[YACL_SHA256_LEN];
  int Tlen, where, i, rc;

  if (info == 0)
    {
      info = (const unsigned char *)"";
      info_len = 0;
    }

  assert (info > 0);

  assert (okm_len > 0);
  assert (okm);

  hash_len = YACL_SHA256_LEN;
  if (prk_len < hash_len)
    return -2;
  N = okm_len / hash_len;
  if ((okm_len % hash_len) != 0) N++;
  if (N > 255)
    return -3;

  size_t tmp_len = YACL_SHA256_LEN + info_len + 1;
  uint8_t *tmp = yacl_malloc (YACL_SHA256_LEN + info_len + 1);
  memset (tmp, 0, tmp_len);

  uint8_t result[YACL_SHA256_LEN];

  Tlen = 0;
  where = 0;
  for (i = 1; i <= N; i++)
    {
      unsigned char c = i;

      memcpy (tmp, T, Tlen);
      memcpy (tmp + Tlen, info, info_len);
      memcpy (tmp + Tlen + info_len, &c, 1);

      size_t i_size = Tlen + info_len + 1;

      rc = hmac_sha256(prk, prk_len, tmp, i_size, result);

      if (rc)
        {
          yacl_free (tmp);
          return -4;
        }

      memcpy (T, result, hash_len);
      memcpy(okm + where, T,
             (i != N) ? hash_len : (okm_len - where));
      where += hash_len;
      Tlen = hash_len;
    }

  yacl_free (tmp);

  return rc;
}


int
yacl_hkdf_256(const unsigned char *salt, int salt_len,
              const unsigned char *ikm, int ikm_len,
              const unsigned char *info, int info_len,
              uint8_t okm[ ], int okm_len)
{
  uint8_t prk[YACL_SHA256_LEN];
  return yacl_hkdf_256_extract(salt, salt_len, ikm, ikm_len, prk) ||
         yacl_hkdf_256_expand(prk, YACL_SHA256_LEN, info,
                              info_len, okm, okm_len);
}
