#pragma once

#include <stdint.h>

void out_begin(const char* name, int zipped);
void out_end(void);
void out_add_folder(const char* path);
uint64_t out_begin_file(const char* name, int compress);
void out_end_file(void);
void out_write(const void* buffer, uint32_t size);

// hacky solution to be able to write cso header after the data is written
void out_write_at(uint64_t offset, const void* buffer, uint32_t size);
void out_set_offset(uint64_t offset);
uint32_t out_zip_get_crc32(void);
void out_zip_set_crc32(uint32_t crc);
