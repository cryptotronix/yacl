/* -*- mode: c; c-file-style: "gnu" -*- */
#include "config.h"
#include <sys/types.h>
#include "../yacl.h"
#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#else
#include "libsodium/sodium.h"
#endif

void
yacl_memzero(void * const pnt, const size_t len)
{
    sodium_memzero(pnt, len);
}

int
yacl_memcmp(const void * const b1_, const void * const b2_, size_t len)
{
    return sodium_memcmp(b1_, b2_, len);
}

#ifndef HAVE_SODIUM_COMPARE
#ifdef HAVE_WEAK_SYMBOLS
__attribute__ ((weak)) void
_sodium_dummy_symbol_to_prevent_compare_lto(const unsigned char *b1,
                                            const unsigned char *b2,
                                            const size_t len)
{
    (void) b1;
    (void) b2;
    (void) len;
}
#endif
#endif


int
yacl_compare(const unsigned char *b1_, const unsigned char *b2_,
                   size_t len)
{
#ifdef HAVE_SODIUM_COMPARE
    return sodium_compare (b1_, b2_, len);
#else
#ifdef HAVE_WEAK_SYMBOLS
    const unsigned char *b1 = b1_;
    const unsigned char *b2 = b2_;
#else
    const volatile unsigned char * volatile b1 =
        (const volatile unsigned char * volatile) b1_;
    const volatile unsigned char * volatile b2 =
        (const volatile unsigned char * volatile) b2_;
#endif
    unsigned char gt = 0U;
    unsigned char eq = 1U;
    size_t        i;

#if HAVE_WEAK_SYMBOLS
    _sodium_dummy_symbol_to_prevent_compare_lto(b1, b2, len);
#endif
    i = len;
    while (i != 0U) {
        i--;
        gt |= ((b2[i] - b1[i]) >> 8) & eq;
        eq &= ((b2[i] ^ b1[i]) - 1) >> 8;
    }
    return (int) (gt + gt + eq) - 1;
#endif
}


int
yacl_is_zero(const unsigned char *n, const size_t nlen)
{
#ifdef HAVE_SODIUM_IS_ZERO
    sodium_is_zero(n, nlen);
#else
    size_t        i;
    unsigned char d = 0U;

    for (i = 0U; i < nlen; i++) {
        d |= n[i];
    }
    return 1 & ((d - 1) >> 8);
#endif
}


void
yacl_increment(unsigned char *n, const size_t nlen)
{
#ifdef HAVE_SODIUM_INCREMENT
    sodium_increment(n, nlen);
#else
    size_t        i = 0U;
    uint_fast16_t c = 1U;

#ifdef HAVE_AMD64_ASM
    uint64_t      t64, t64_2;
    uint32_t      t32;

    if (nlen == 12U) {
        __asm__ __volatile__("xorq %[t64], %[t64] \n"
                             "xorl %[t32], %[t32] \n"
                             "stc \n"
                             "adcq %[t64], (%[out]) \n"
                             "adcl %[t32], 8(%[out]) \n"
                             : [t64] "=&r"(t64), [t32] "=&r" (t32)
                             : [out] "D"(n)
                             : "memory", "flags", "cc");
        return;
    } else if (nlen == 24U) {
        __asm__ __volatile__("movq $1, %[t64] \n"
                             "xorq %[t64_2], %[t64_2] \n"
                             "addq %[t64], (%[out]) \n"
                             "adcq %[t64_2], 8(%[out]) \n"
                             "adcq %[t64_2], 16(%[out]) \n"
                             : [t64] "=&r"(t64), [t64_2] "=&r" (t64_2)
                             : [out] "D"(n)
                             : "memory", "flags", "cc");
        return;
    } else if (nlen == 8U) {
        __asm__ __volatile__("incq (%[out]) \n"
                             :
                             : [out] "D"(n)
                             : "memory", "flags", "cc");
        return;
    }
#endif
    for (; i < nlen; i++) {
        c += (uint_fast16_t) n[i];
        n[i] = (unsigned char) c;
        c >>= 8;
    }
#endif /* HAVE_SODIUM_INCREMENT */
}


void
yacl_add(unsigned char *a, const unsigned char *b, const size_t len)
{
#ifdef HAVE_SODIUM_ADD
    sodium_add(a, b, len);
#else
    size_t        i = 0U;
    uint_fast16_t c = 0U;

#ifdef HAVE_AMD64_ASM
    uint64_t      t64, t64_2, t64_3;
    uint32_t      t32;

    if (len == 12U) {
        __asm__ __volatile__("movq (%[in]), %[t64] \n"
                             "movl 8(%[in]), %[t32] \n"
                             "addq %[t64], (%[out]) \n"
                             "adcl %[t32], 8(%[out]) \n"
                             : [t64] "=&r"(t64), [t32] "=&r" (t32)
                             : [in] "S"(b), [out] "D"(a)
                             : "memory", "flags", "cc");
        return;
    } else if (len == 24U) {
        __asm__ __volatile__("movq (%[in]), %[t64] \n"
                             "movq 8(%[in]), %[t64_2] \n"
                             "movq 16(%[in]), %[t64_3] \n"
                             "addq %[t64], (%[out]) \n"
                             "adcq %[t64_2], 8(%[out]) \n"
                             "adcq %[t64_3], 16(%[out]) \n"
                             : [t64] "=&r"(t64), [t64_2] "=&r"(t64_2), [t64_3] "=&r"(t64_3)
                             : [in] "S"(b), [out] "D"(a)
                             : "memory", "flags", "cc");
        return;
    } else if (len == 8U) {
        __asm__ __volatile__("movq (%[in]), %[t64] \n"
                             "addq %[t64], (%[out]) \n"
                             : [t64] "=&r"(t64)
                             : [in] "S"(b), [out] "D"(a)
                             : "memory", "flags", "cc");
        return;
    }
#endif
    for (; i < len; i++) {
        c += (uint_fast16_t) a[i] + (uint_fast16_t) b[i];
        a[i] = (unsigned char) c;
        c >>= 8;
    }
#endif
}

char *
yacl_bin2hex(char * const hex, const size_t hex_maxlen,
             const unsigned char * const bin, const size_t bin_len)
{
    return sodium_bin2hex(hex, hex_maxlen, bin,  bin_len);
}

int
yacl_hex2bin(unsigned char * const bin, const size_t bin_maxlen,
             const char * const hex, const size_t hex_len,
             const char * const ignore, size_t * const bin_len,
             const char ** const hex_end)
{
    return sodium_hex2bin(bin, bin_maxlen, hex, hex_len, ignore, bin_len,
                          hex_end);
}

int
yacl_mlock(void * const addr, const size_t len)
{
    return sodium_mlock(addr,  len);
}

int
yacl_munlock(void * const addr, const size_t len)
{
    return sodium_munlock(addr,  len);
}

void *
yacl_malloc(const size_t size)
{
    return sodium_malloc (size);
}

void *
yacl_allocarray(size_t count, size_t size)
{
    return sodium_allocarray(count, size);
}

void
yacl_free(void *ptr)
{
    sodium_free (ptr);
}

int
yacl_mprotect_noaccess(void *ptr)
{
    return sodium_mprotect_noaccess(ptr);
}

int
yacl_mprotect_readonly(void *ptr)
{
    return sodium_mprotect_readonly(ptr);
}

int
yacl_mprotect_readwrite(void *ptr)
{
    return sodium_mprotect_readwrite(ptr);
}

/* -------- */
