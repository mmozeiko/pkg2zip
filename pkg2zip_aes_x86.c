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

void aes128_init_x86(aes128_key* ctx, const uint8_t* key)
{
    __m128i* ekey = (__m128i*)ctx->key;

    __m128i x = _mm_loadu_si128((const __m128i*)key);
    AES128_INIT(ekey + 0, x, 0x01);
    AES128_INIT(ekey + 1, x, 0x02);
    AES128_INIT(ekey + 2, x, 0x04);
    AES128_INIT(ekey + 3, x, 0x08);
    AES128_INIT(ekey + 4, x, 0x10);
    AES128_INIT(ekey + 5, x, 0x20);
    AES128_INIT(ekey + 6, x, 0x40);
    AES128_INIT(ekey + 7, x, 0x80);
    AES128_INIT(ekey + 8, x, 0x1b);
    AES128_INIT(ekey + 9, x, 0x36);
    _mm_store_si128(ekey + 10, x);
}

void aes128_init_dec_x86(aes128_key* ctx, const uint8_t* key)
{
    aes128_key enc;
    aes128_init_x86(&enc, key);

    const __m128i* ekey = (__m128i*)&enc.key;
    __m128i* dkey = (__m128i*)&ctx->key;

    _mm_store_si128(dkey + 10, _mm_load_si128(ekey + 0));
    for (size_t i = 1; i < 10; i++)
    {
        _mm_store_si128(dkey + 10 - i, _mm_aesimc_si128(_mm_load_si128(ekey + i)));
    }
    _mm_store_si128(dkey + 0, _mm_load_si128(ekey + 10));
}

static __m128i aes128_encrypt_x86(__m128i input, const __m128i* key)
{
    __m128i tmp = _mm_xor_si128(input, _mm_load_si128(key + 0));
    tmp = _mm_aesenc_si128(tmp, _mm_load_si128(key + 1));
    tmp = _mm_aesenc_si128(tmp, _mm_load_si128(key + 2));
    tmp = _mm_aesenc_si128(tmp, _mm_load_si128(key + 3));
    tmp = _mm_aesenc_si128(tmp, _mm_load_si128(key + 4));
    tmp = _mm_aesenc_si128(tmp, _mm_load_si128(key + 5));
    tmp = _mm_aesenc_si128(tmp, _mm_load_si128(key + 6));
    tmp = _mm_aesenc_si128(tmp, _mm_load_si128(key + 7));
    tmp = _mm_aesenc_si128(tmp, _mm_load_si128(key + 8));
    tmp = _mm_aesenc_si128(tmp, _mm_load_si128(key + 9));
    return _mm_aesenclast_si128(tmp, _mm_load_si128(key + 10));
}

static __m128i aes128_decrypt_x86(__m128i input, const __m128i* key)
{
    __m128i tmp = _mm_xor_si128(input, _mm_load_si128(key + 0));
    tmp = _mm_aesdec_si128(tmp, _mm_load_si128(key + 1));
    tmp = _mm_aesdec_si128(tmp, _mm_load_si128(key + 2));
    tmp = _mm_aesdec_si128(tmp, _mm_load_si128(key + 3));
    tmp = _mm_aesdec_si128(tmp, _mm_load_si128(key + 4));
    tmp = _mm_aesdec_si128(tmp, _mm_load_si128(key + 5));
    tmp = _mm_aesdec_si128(tmp, _mm_load_si128(key + 6));
    tmp = _mm_aesdec_si128(tmp, _mm_load_si128(key + 7));
    tmp = _mm_aesdec_si128(tmp, _mm_load_si128(key + 8));
    tmp = _mm_aesdec_si128(tmp, _mm_load_si128(key + 9));
    return _mm_aesdeclast_si128(tmp, _mm_load_si128(key + 10));
}

void aes128_ecb_encrypt_x86(const aes128_key* ctx, const uint8_t* input, uint8_t* output)
{
    const __m128i* key = (__m128i*)ctx->key;
    __m128i tmp = aes128_encrypt_x86(_mm_loadu_si128((const __m128i*)input), key);
    _mm_storeu_si128((__m128i*)output, tmp);
}

void aes128_ecb_decrypt_x86(const aes128_key* ctx, const uint8_t* input, uint8_t* output)
{
    const __m128i* key = (__m128i*)ctx->key;
    __m128i tmp = aes128_decrypt_x86(_mm_loadu_si128((const __m128i*)input), key);
    _mm_storeu_si128((__m128i*)output, tmp);
}

static __m128i ctr_increment(__m128i counter)
{
    __m128i swap = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    __m128i tmp = _mm_shuffle_epi8(counter, swap);
    tmp = _mm_add_epi64(tmp, _mm_set_epi32(0, 0, 0, 1));
    return _mm_shuffle_epi8(tmp, swap);
}

void aes128_ctr_xor_x86(const aes128_key* ctx, const uint8_t* iv, uint8_t* buffer, size_t size)
{
    const __m128i* key = (__m128i*)ctx->key;
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

void aes128_cmac_process_x86(const aes128_key* ctx, uint8_t* block, const uint8_t* buffer, uint32_t size)
{
    const __m128i* key = (__m128i*)ctx->key;
    __m128i* data = (__m128i*)buffer;

    __m128i tmp = _mm_loadu_si128((__m128i*)block);
    for (uint32_t i = 0; i < size; i += 16)
    {
        __m128i input = _mm_loadu_si128(data++);
        tmp = _mm_xor_si128(tmp, input);
        tmp = aes128_encrypt_x86(tmp, key);
    }
    _mm_storeu_si128((__m128i*)block, tmp);
}

void aes128_psp_decrypt_x86(const aes128_key* ctx, const uint8_t* prev, const uint8_t* block, uint8_t* buffer, uint32_t size)
{
    const __m128i* key = (__m128i*)ctx->key;
    __m128i one = _mm_setr_epi32(0, 0, 0, 1);

    __m128i x = _mm_load_si128((__m128i*)prev);
    __m128i y = _mm_load_si128((__m128i*)block);

    __m128i* data = (__m128i*)buffer;

    for (uint32_t i = 0; i < size; i += 16)
    {
        y = _mm_add_epi32(y, one);

        __m128i out = aes128_decrypt_x86(y, key);

        out = _mm_xor_si128(out, _mm_loadu_si128(data));
        out = _mm_xor_si128(out, x);
        _mm_storeu_si128(data++, out);
        x = y;
    }
}
