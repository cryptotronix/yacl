/* -*- mode: c; c-file-style: "gnu" -*- */
#include "config.h"
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include "../yacl.h"
#include "hash/sha256.h"
#include "ecc/uECC.h"
#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#else
#include "libsodium/sodium.h"
#endif
#include "aes/aes_wrap.h"


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

int
yacl_aes_wrap(const uint8_t *kek, size_t kek_len,
                  const uint8_t *wkey, uint8_t *out)
{
  return aes_wrap(kek, kek_len, 4, wkey, out);
}


int
yacl_aes_unwrap(const uint8_t *kek, size_t kek_len,
                const uint8_t *cipher, uint8_t *plain)
{
  return aes_unwrap(kek, kek_len, 4, cipher, plain);
}


int
yacl_aes_gcm_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *nonce, size_t nonce_len,
                     uint8_t *tag, size_t tag_len,
                     uint8_t *ciphertext, size_t c_len)

{
  if (crypto_aead_aes256gcm_NPUBBYTES != nonce_len)
    return -1;

  if (plaintext_len != c_len)
    return -1;

  if (crypto_aead_aes256gcm_KEYBYTES != key_len)
    return -1;

  if (crypto_aead_aes256gcm_ABYTES != tag_len)
    return -1;

#ifdef HAVE_LIBSODIUM
#ifdef HAVE_SODIUM_GCM
  if (crypto_aead_aes256gcm_is_available())
    {
      return crypto_aead_aes256gcm_encrypt_detached(ciphertext,
                                                    tag,
                                                    NULL,
                                                    plaintext,
                                                    tag_len,
                                                    aad,
                                                    aad_len,
                                                    NULL,
                                                    nonce,
                                                    key);
    }
#endif
#endif

  return aes_gcm_ae(key, key_len,
                    nonce, nonce_len,
                    plaintext, plaintext_len,
                    aad, aad_len,
                    ciphertext,
                    tag);

}


int
yacl_aes_gcm_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *tag, size_t tag_len,
                     uint8_t *plaintext, size_t plaintext_len)
{
  if (crypto_aead_aes256gcm_NPUBBYTES != nonce_len)
    return -1;

  if (plaintext_len != ciphertext_len)
    return -1;

  if (crypto_aead_aes256gcm_KEYBYTES != key_len)
    return -1;

  if (crypto_aead_aes256gcm_ABYTES != tag_len)
    return -1;

#ifdef HAVE_LIBSODIUM
#ifdef HAVE_SODIUM_GCM
  if (crypto_aead_aes256gcm_is_available())
    {
      return crypto_aead_aes256gcm_decrypt_detached(plaintext,
                                                    NULL,
                                                    ciphertext,
                                                    ciphertext_len,
                                                    tag,
                                                    aad,
                                                    aad_len,
                                                    nonce,
                                                    key);
    }
#endif
#endif

  return aes_gcm_ad(key, key_len,
                    nonce, nonce_len,
                    ciphertext, ciphertext_len,
                    aad, aad_len,
                    tag,
                    plaintext);
}
