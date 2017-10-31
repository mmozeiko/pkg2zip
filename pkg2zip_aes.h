#pragma once

#include "pkg2zip_utils.h"

typedef struct {
    MSVC_ALIGN(16) uint32_t key[44] GCC_ALIGN(16);
} aes128_key;

void aes128_init(aes128_key* context, const uint8_t* key);
void aes128_ecb_encrypt(const aes128_key* context, const uint8_t* input, uint8_t* output);
void aes128_ctr_xor(const aes128_key* context, const uint8_t* iv, uint64_t block, uint8_t* buffer, size_t size);
