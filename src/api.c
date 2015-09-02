/* -*- mode: c; c-file-style: "gnu" -*- */
#include "config.h"
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
