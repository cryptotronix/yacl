/* -*- mode: c; c-file-style: "gnu" -*- */

#ifndef LIBYACL_H_
#define LIBYACL_H_

#include <stdint.h>
#include <stddef.h>

/* --- Digest functions --- */
#define YACL_SHA256_LEN 32

int
yacl_sha256 (const uint8_t *in, size_t len, uint8_t out[YACL_SHA256_LEN]);

int
yacl_hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t mac[YACL_SHA256_LEN]);

/* --- ECC functions ---*/

#define YACL_P256_COORD_SIZE 32

int
yacl_create_key_pair(uint8_t public_key[YACL_P256_COORD_SIZE*2],
                     uint8_t private_key[YACL_P256_COORD_SIZE]);

int
yacl_ecdsa_sign(const uint8_t private_key[YACL_P256_COORD_SIZE],
                const uint8_t message_hash[YACL_P256_COORD_SIZE],
                uint8_t signature[YACL_P256_COORD_SIZE*2]);

int
yacl_ecdsa_verify(const uint8_t public_key[YACL_P256_COORD_SIZE*2],
                  const uint8_t hash[YACL_P256_COORD_SIZE],
                  const uint8_t signature[YACL_P256_COORD_SIZE*2]);


/* --- Utils --- */
int
yacl_memcmp_ct (const void *a, const void *b, size_t size);

#endif
