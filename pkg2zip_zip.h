#pragma once

#include "pkg2zip_sys.h"
#include "pkg2zip_crc32.h"
#include "miniz_tdef.h"

#include <stddef.h>
#include <stdint.h>

#define ZIP_MAX_FILENAME 1024

typedef struct zip_file zip_file;

typedef struct {
    sys_file file;
    uint64_t total;
    uint32_t count;
    uint32_t max;
    uint16_t time;
    uint16_t date;
    tdefl_compressor tdefl;
    crc32_ctx crc32;
    int crc32_set;
    uint32_t allocated; // bytes
    zip_file* files;
    zip_file* current;
} zip;

void zip_create(zip* z, const char* name);
void zip_add_folder(zip* z, const char* name);
uint64_t zip_begin_file(zip* z, const char* name, int compress);
void zip_write_file(zip* z, const void* data, uint32_t size);
void zip_end_file(zip* z);
void zip_close(zip* z);

// hacky solution to be able to write cso header after the data is written
void zip_write_file_at(zip* z, uint64_t offset, const void* data, uint32_t size);
void zip_set_offset(zip* z, uint64_t offset);
void zip_set_crc32(zip* z, uint32_t crc);
uint32_t zip_get_crc32(zip* z);
