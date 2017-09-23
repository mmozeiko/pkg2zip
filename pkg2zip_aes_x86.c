#include "pkg2zip_aes.h"

#include <string.h>
#include <wmmintrin.h> // AESNI
#include <tmmintrin.h> // SSSE3

#define AES128_INIT(ctx, x, rcon)           \
{                                           \
    __m128i a, b;                           \
    _mm_store_si128(ctx, x);                \
    a = _mm_aeskeygenassist_si128(x, rcon); \
    a = _mm_shuffle_epi32(a, 0xff);         \
    b = _mm_slli_si128(x, 4);               \
    x = _mm_xor_si128(x, b);                \
    b = _mm_slli_si128(b, 4);               \
    x = _mm_xor_si128(x, b);                \
    b = _mm_slli_si128(b, 4);               \
    x = _mm_xor_si128(x, b);                \
    x = _mm_xor_si128(x, a);                \
}

void aes128_init_x86(aes128_key* context, const uint8_t* key)
{
    __m128i* ctx = (__m128i*)context->key;

    __m128i x = _mm_loadu_si128((const __m128i*)key);
    AES128_INIT(ctx + 0, x, 0x01);
    AES128_INIT(ctx + 1, x, 0x02);
    AES128_INIT(ctx + 2, x, 0x04);
    AES128_INIT(ctx + 3, x, 0x08);
    AES128_INIT(ctx + 4, x, 0x10);
    AES128_INIT(ctx + 5, x, 0x20);
    AES128_INIT(ctx + 6, x, 0x40);
    AES128_INIT(ctx + 7, x, 0x80);
    AES128_INIT(ctx + 8, x, 0x1b);
    AES128_INIT(ctx + 9, x, 0x36);
    _mm_storeu_si128(ctx + 10, x);
}

static __m128i aes128_encrypt_x86(__m128i input, const __m128i* key)
{
    __m128i tmp = _mm_xor_si128(input, key[0]);
    tmp = _mm_aesenc_si128(tmp, key[1]);
    tmp = _mm_aesenc_si128(tmp, key[2]);
    tmp = _mm_aesenc_si128(tmp, key[3]);
    tmp = _mm_aesenc_si128(tmp, key[4]);
    tmp = _mm_aesenc_si128(tmp, key[5]);
    tmp = _mm_aesenc_si128(tmp, key[6]);
    tmp = _mm_aesenc_si128(tmp, key[7]);
    tmp = _mm_aesenc_si128(tmp, key[8]);
    tmp = _mm_aesenc_si128(tmp, key[9]);
    return _mm_aesenclast_si128(tmp, key[10]);
}

void aes128_ecb_encrypt_x86(const aes128_key* context, const uint8_t* input, uint8_t* output)
{
    const __m128i* key = (__m128i*)context->key;
    __m128i tmp = aes128_encrypt_x86(_mm_loadu_si128((const __m128i*)input), key);
    _mm_storeu_si128((__m128i*)output, tmp);
}

static __m128i ctr_increment(__m128i counter)
{
    __m128i swap = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    __m128i tmp = _mm_shuffle_epi8(counter, swap);
    tmp = _mm_add_epi64(tmp, _mm_set_epi32(0, 0, 0, 1));
    return _mm_shuffle_epi8(tmp, swap);
}

void aes128_ctr_xor_x86(const aes128_key* context, const uint8_t* iv, uint8_t* buffer, size_t size)
{
    const __m128i* key = (__m128i*)context->key;
    __m128i counter = _mm_loadu_si128((const __m128i*)iv);

    while (size >= 16)
    {
        __m128i block = aes128_encrypt_x86(counter, key);
        __m128i tmp = _mm_xor_si128(_mm_loadu_si128((const __m128i*)buffer), block);
        _mm_storeu_si128((__m128i*)buffer, tmp);

        counter = ctr_increment(counter);

        buffer += 16;
        size -= 16;
    }

    if (size != 0)
    {
        uint8_t full[16];
        memcpy(full, buffer, size);
        memset(full + size, 0, 16 - size);

        __m128i block = aes128_encrypt_x86(counter, key);
        __m128i tmp = _mm_xor_si128(_mm_loadu_si128((const __m128i*)full), block);
        _mm_storeu_si128((__m128i*)full, tmp);

        memcpy(buffer, full, size);
    }
}
