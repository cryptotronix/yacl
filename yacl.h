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

/* --- HKDF --- */
/* hkdf functions */

int
yacl_hkdf_256_extract( const uint8_t *salt, int salt_len,
                       const uint8_t *ikm, int ikm_len,
                       uint8_t prk[YACL_SHA256_LEN]);


int
yacl_hkdf_256_expand(const uint8_t prk[ ], int prk_len,
                     const unsigned char *info, int info_len,
                     uint8_t okm[ ], int okm_len);

/*
 *  hkdf
 *
 *  Description:
 *      This function will generate keying material using HKDF-256.
 *
 *  Parameters:
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
 *      info[ ]: [in]
 *          The optional context and application specific information.
 *          If info == NULL or a zero-length string, it is ignored.
 *      info_len: [in]
 *          The length of the optional context and application specific
 *          information.  (Ignored if info == NULL.)
 *      okm[ ]: [out]
 *          Where the HKDF is to be stored.
 *      okm_len: [in]
 *          The length of the buffer to hold okm.
 *          okm_len must be <= 255 * USHABlockSize(whichSha)
 *
 *  Notes:
 *      Calls hkdf_extract() and hkdf_expand().
 *
 *  Returns:
 *      sha 0 on success otherwise non-zero
 *
 */
int
yacl_hkdf_256(const unsigned char *salt, int salt_len,
              const unsigned char *ikm, int ikm_len,
              const unsigned char *info, int info_len,
              uint8_t okm[ ], int okm_len);


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


int
yacl_hash_ecdsa_sign(const uint8_t *data, size_t len,
                     const uint8_t private_key[YACL_P256_COORD_SIZE],
                     uint8_t signature[YACL_P256_COORD_SIZE*2]);

int
yacl_hash_verify(const uint8_t *data, size_t len,
                 const uint8_t public_key[YACL_P256_COORD_SIZE*2],
                 const uint8_t signature[YACL_P256_COORD_SIZE*2]);

/* --- Utils --- */
int
yacl_memcmp_ct (const void *a, const void *b, size_t size);

int
yacl_get_random(uint8_t *dest, size_t size);
#endif
