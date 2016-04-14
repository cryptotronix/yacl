/* -*- mode: c; c-file-style: "gnu" -*- */
#include "../yacl.h"
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
  int rc;
  yacl_init();

  char *line = malloc (1);
  size_t n = 1;
  size_t out;
  ssize_t s = getline (&line, &n, stdin);

  /* Test base64url routines, should always be able to encode */
  char * encoded = yacl_b64url_encode (line, s);

  uint8_t *decoded = yacl_b64url_decode (encoded, &out);

  assert (0 == yacl_memcmp (decoded, line, out));

  /* SHA 256 should never fail */
  uint8_t buf[32];
  assert (0 == yacl_sha256 (line, s, buf));

  /* Throw the fuzz throw hkdf */
  assert (0 == yacl_hkdf_256 (NULL, 0, line, s, NULL, 0, buf, 32));

  /* Test the ECC functions */
  uint8_t public_key[YACL_P256_COORD_SIZE*2];
  uint8_t *private_key = yacl_malloc (YACL_P256_COORD_SIZE);
  assert (private_key);

  uint8_t signature[YACL_P256_COORD_SIZE*2];

  assert ( 0 == yacl_create_key_pair(public_key, private_key));

  /* Send the fuzz input to be signed, signed fuzz! */
  assert (0 == yacl_hash_ecdsa_sign(line, s, private_key, signature ));

  /* dump the fuzz :) */
  yacl_hexdump (line, s);

  /* memcmp the fuzz */
  ssize_t halflen = s / 2;
  yacl_memcmp (line, line+halflen, halflen);

  /* Try to use the fuzz in aes key wrap */
  uint8_t wkey[32];
  uint8_t wkey2[32];
  if (s >= 32)
    memcpy (wkey, line, 32);
  else
    memset (wkey, 0x61, 32);
  uint8_t kw_buf[40];

  rc = yacl_aes_wrap(line, s, wkey, kw_buf);
  if (0 == rc)
    {
      assert (0 == yacl_aes_unwrap(line, s, kw_buf, wkey2));
      assert (0 == yacl_memcmp (wkey, wkey2, 32));
    }

  memset (kw_buf, 0x61, 40);
  assert (0 != yacl_aes_unwrap (line, s, kw_buf, wkey2));

  /* cleanup */
  yacl_free (private_key);
  if (encoded)
    free (encoded);
  if (decoded)
    free (decoded);

  exit (0);

}
