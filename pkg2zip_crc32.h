#pragma once

#include "pkg2zip_utils.h"

typedef struct {
    uint32_t PKG_ALIGN(16) crc[4 * 5];
} crc32_ctx;

void crc32_init(crc32_ctx* ctx);
void crc32_update(crc32_ctx* ctx, const void* buffer, size_t size);
uint32_t crc32_done(crc32_ctx* ctx);
