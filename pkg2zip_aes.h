#pragma once

#include <stdint.h>
#include <stddef.h>

#if defined(_MSC_VER)
#  define MSVC_ALIGN(x) __declspec(align(x))
#  define GCC_ALIGN(x)
#else
#  define MSVC_ALIGN(x)
#  define GCC_ALIGN(x) __attribute__((aligned(x)))
#endif

typedef struct {
    MSVC_ALIGN(16) uint32_t key[44] GCC_ALIGN(16);
} aes128_key;

void aes128_init(aes128_key* context, const uint8_t* key);
void aes128_ecb_encrypt(const aes128_key* context, const uint8_t* input, uint8_t* output);
void aes128_ctr_xor(const aes128_key* context, const uint8_t* iv, uint64_t block, uint8_t* buffer, size_t size);
