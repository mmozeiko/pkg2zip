#pragma once

#include "pkg2zip_utils.h"

typedef struct {
    uint32_t PKG_ALIGN(16) crc[4 * 5];
} crc32_ctx;

void crc32_init(crc32_ctx* ctx);
void crc32_update(crc32_ctx* ctx, const void* buffer, size_t size);
uint32_t crc32_done(crc32_ctx* ctx);

// returns crc32(x||y)
// where a=crc32(x) and b=crc32(y)
// crc32(x||y) = crc32(x||z) ^ crc32(y), where z=00...00 (same length as y)
uint32_t crc32_combine(uint32_t a, uint32_t b, uint32_t blen);
