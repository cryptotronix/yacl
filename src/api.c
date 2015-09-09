/* -*- mode: c; c-file-style: "gnu" -*- */
#include "config.h"
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include "../yacl.h"
#include "hash/sha256.h"
#include "ecc/uECC.h"

int
yacl_sha256 (const uint8_t *in, size_t len, uint8_t out[YACL_SHA256_LEN])
{
    return sha256 (in, len, out);
}

int
yacl_hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t mac[YACL_SHA256_LEN])
{
    return hmac_sha256(key, key_len, data, data_len, mac);
}

/* --- ECC functions ---*/

#define YACL_P256_COORD_SIZE 32

int
yacl_create_key_pair(uint8_t public_key[YACL_P256_COORD_SIZE*2],
                     uint8_t private_key[YACL_P256_COORD_SIZE])
{
    int rc;
    rc = uECC_make_key(public_key, private_key);
    if (rc == 1)
        return 0;
    else
        return 1;
}

int
yacl_ecdsa_sign(const uint8_t private_key[YACL_P256_COORD_SIZE],
                const uint8_t message_hash[YACL_P256_COORD_SIZE],
                uint8_t signature[YACL_P256_COORD_SIZE*2])
{
    int rc;
    rc = uECC_sign(private_key, message_hash, signature);

    if (rc == 1)
        return 0;
    else
        return 1;

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
yacl_memcmp_ct (const void *a, const void *b, size_t size)
{
  const uint8_t *ap = a;
  const uint8_t *bp = b;
  int rc = 0;
  size_t i;

  if (NULL == a || NULL == b) return -1;

  for (i = 0; i < size; i++)
    rc |= *ap++ ^ *bp++;

  return rc;
}

int
yacl_get_random(uint8_t *dest, size_t size)
{
  int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd == -1)
    {
      fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
      if (fd == -1)
        {
          return fd;
        }
    }

  char *ptr = (char *)dest;
  size_t left = size;
  while (left > 0)
    {
      ssize_t bytes_read = read(fd, ptr, left);
      if (bytes_read <= 0)
        {
          close(fd);
          return -1;
        }
      left -= bytes_read;
      ptr += bytes_read;
    }

  close(fd);
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
