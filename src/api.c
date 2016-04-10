/* -*- mode: c; c-file-style: "gnu" -*- */
#include "config.h"
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include "../yacl.h"
#include "hash/sha256.h"
#include "ecc/uECC.h"
#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#else
#include "libsodium/sodium.h"
#endif

int
yacl_init (void)
{
  return sodium_init();
}

int
yacl_sha256 (const uint8_t *in, size_t len, uint8_t out[YACL_SHA256_LEN])
{
#ifdef HAVE_LIBSODIUM
  return crypto_hash_sha256 (out, in, len);
#else
  return sha256 (in, len, out);
#endif
}

int
yacl_hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t mac[YACL_SHA256_LEN])
{
#ifdef HAVE_LIBSODIUM
  if (YACL_SHA256_LEN == key_len)
    {
      return crypto_auth_hmacsha256(mac, data, data_len, key);
    }
#endif

  return hmac_sha256(key, key_len, data, data_len, mac);
}

int
yacl_create_key_pair(uint8_t public_key[YACL_P256_COORD_SIZE*2],
                     uint8_t private_key[YACL_P256_COORD_SIZE])
{
    int rc;
    rc = uECC_make_key(public_key, private_key);
    rc = (rc == 1) ? 0 : 1;

    return rc;
}

int
yacl_ecdsa_sign(const uint8_t private_key[YACL_P256_COORD_SIZE],
                const uint8_t message_hash[YACL_P256_COORD_SIZE],
                uint8_t signature[YACL_P256_COORD_SIZE*2])
{
    int rc;
    rc = uECC_sign(private_key, message_hash, signature);

    rc = (rc == 1) ? 0 : 1;
    return rc;
}

int
yacl_ecdsa_verify(const uint8_t public_key[YACL_P256_COORD_SIZE*2],
                  const uint8_t hash[YACL_P256_COORD_SIZE],
                  const uint8_t signature[YACL_P256_COORD_SIZE*2])
{
    int rc;

    rc =  uECC_verify(public_key, hash, signature);

    if (rc == 1)
        return 0;
    else
        return 1;

    return rc;

}

int
yacl_get_random(uint8_t *dest, size_t size)
{
  randombytes_buf(dest, size);
  return 0;
}

int
yacl_hash_ecdsa_sign(const uint8_t *data, size_t len,
                     const uint8_t private_key[YACL_P256_COORD_SIZE],
                     uint8_t signature[YACL_P256_COORD_SIZE*2])
{

  int rc = -1;
  uint8_t digest[YACL_SHA256_LEN];

  if (NULL == data)
    return rc;

  rc = yacl_sha256 (data, len, digest);
  if (rc) return rc;

  rc = yacl_ecdsa_sign(private_key, digest, signature);

  return rc;


}

int
yacl_hash_verify(const uint8_t *data, size_t len,
                 const uint8_t public_key[YACL_P256_COORD_SIZE*2],
                 const uint8_t signature[YACL_P256_COORD_SIZE*2])
{
  int rc = -1;
  uint8_t digest[YACL_SHA256_LEN];

  if (NULL == data)
    return rc;

  rc = yacl_sha256 (data, len, digest);
  if (rc) return rc;

  rc = yacl_ecdsa_verify (public_key, digest, signature);

  return rc;
}


int
yacl_ecdh (const uint8_t public_key[YACL_P256_COORD_SIZE*2],
           const uint8_t private_key[YACL_P256_COORD_SIZE],
           uint8_t secret[YACL_P256_COORD_SIZE])
{
  int rc;

  rc = uECC_shared_secret(public_key, private_key, secret);

  if (1 == rc)
    rc = 0;
  else
    rc = 1;

  return rc;
}
