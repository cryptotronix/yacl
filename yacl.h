/* -*- mode: c; c-file-style: "gnu" -*- */

#ifndef LIBYACL_H_
#define LIBYACL_H_

#include <stdint.h>
#include <stddef.h>

int
yacl_init (void);

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

int
yacl_ecdh (const uint8_t public_key[YACL_P256_COORD_SIZE*2],
           const uint8_t private_key[YACL_P256_COORD_SIZE],
           uint8_t secret[YACL_P256_COORD_SIZE]);

/* --- Utils --- */

int
yacl_get_random(uint8_t *dest, size_t size);

/* --- libsodium wrappers (uses libsodium if available) --- */

void yacl_memzero(void * const pnt, const size_t len);

/*
 * WARNING: yacl_memcmp() must be used to verify if two secret keys
 * are equal, in constant time.
 * It returns 0 if the keys are equal, and -1 if they differ.
 * This function is not designed for lexicographical comparisons.
 */

int yacl_memcmp(const void * const b1_, const void * const b2_, size_t len)
            __attribute__ ((warn_unused_result));

/*
 * yacl_compare() returns -1 if b1_ < b2_, 1 if b1_ > b2_ and 0 if b1_ == b2_
 * It is suitable for lexicographical comparisons, or to compare nonces
 * and counters stored in little-endian format.
 * However, it is slower than yacl_memcmp().
 */

int yacl_compare(const unsigned char *b1_, const unsigned char *b2_,
                   size_t len)
            __attribute__ ((warn_unused_result));


int yacl_is_zero(const unsigned char *n, const size_t nlen);


void yacl_increment(unsigned char *n, const size_t nlen);


void yacl_add(unsigned char *a, const unsigned char *b, const size_t len);


char *yacl_bin2hex(char * const hex, const size_t hex_maxlen,
                     const unsigned char * const bin, const size_t bin_len);


int yacl_hex2bin(unsigned char * const bin, const size_t bin_maxlen,
                   const char * const hex, const size_t hex_len,
                   const char * const ignore, size_t * const bin_len,
                   const char ** const hex_end);


int yacl_mlock(void * const addr, const size_t len);


int yacl_munlock(void * const addr, const size_t len);

/* WARNING: yacl_malloc() and yacl_allocarray() are not general-purpose
 * allocation functions.
 *
 * They return a pointer to a region filled with 0xd0 bytes, immediately
 * followed by a guard page.
 * As a result, accessing a single byte after the requested allocation size
 * will intentionally trigger a segmentation fault.
 *
 * A canary and an additional guard page placed before the beginning of the
 * region may also kill the process if a buffer underflow is detected.
 *
 * The memory layout is:
 * [unprotected region size (read only)][guard page (no access)][unprotected pages (read/write)][guard page (no access)]
 * With the layout of the unprotected pages being:
 * [optional padding][16-bytes canary][user region]
 *
 * However:
 * - These functions are significantly slower than standard functions
 * - Each allocation requires 3 or 4 additional pages
 * - The returned address will not be aligned if the allocation size is not
 *   a multiple of the required alignment. For this reason, these functions
 *   are designed to store data, such as secret keys and messages.
 *
 * yacl_malloc() can be used to allocate any libsodium data structure,
 * with the exception of crypto_generichash_state.
 *
 * The crypto_generichash_state structure is packed and its length is
 * either 357 or 361 bytes. For this reason, when using yacl_malloc() to
 * allocate a crypto_generichash_state structure, padding must be added in
 * order to ensure proper alignment:
 * state = yacl_malloc((crypto_generichash_statebytes() + (size_t) 63U)
 *                       & ~(size_t) 63U);
 */


void *yacl_malloc(const size_t size)
            __attribute__ ((malloc));


void *yacl_allocarray(size_t count, size_t size)
            __attribute__ ((malloc));


void yacl_free(void *ptr);


int yacl_mprotect_noaccess(void *ptr);


int yacl_mprotect_readonly(void *ptr);


int yacl_mprotect_readwrite(void *ptr);


#endif
