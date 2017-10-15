#pragma once

#include "pkg2zip_sys.h"

#include <stddef.h>
#include <stdint.h>

#define ZIP_MAX_FILES (32*1024)
#define ZIP_MAX_FILENAME 1024

typedef struct {
    sys_file file;
    uint64_t total;
    uint32_t count;
    uint16_t time;
    uint16_t date;
    uint64_t offset[ZIP_MAX_FILES];
    uint64_t size[ZIP_MAX_FILES];
    uint32_t crc32[ZIP_MAX_FILES];
} zip;

void zip_create(zip* z, const char* name);
void zip_add_folder(zip* z, const char* name);
void zip_begin_file(zip* z, const char* name);
void zip_write_file(zip* z, const void* data, uint32_t size);
void zip_end_file(zip* z);
void zip_close(zip* z);
