#pragma once

#include "pkg2zip_utils.h"

typedef struct aes128_key {
    uint32_t PKG_ALIGN(16) key[44];
} aes128_key;

void aes128_init(aes128_key* ctx, const uint8_t* key);
void aes128_init_dec(aes128_key* ctx, const uint8_t* key);

void aes128_ecb_encrypt(const aes128_key* ctx, const uint8_t* input, uint8_t* output);
void aes128_ecb_decrypt(const aes128_key* ctx, const uint8_t* input, uint8_t* output);

void aes128_ctr_xor(const aes128_key* ctx, const uint8_t* iv, uint64_t block, uint8_t* buffer, size_t size);

void aes128_cmac(const uint8_t* key, const uint8_t* buffer, uint32_t size, uint8_t* mac);

void aes128_psp_decrypt(const aes128_key* ctx, const uint8_t* iv, uint32_t index, uint8_t* buffer, uint32_t size);
