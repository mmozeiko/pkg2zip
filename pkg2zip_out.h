#pragma once

#include <stdint.h>

void out_begin(const char* name, int zipped);
void out_end(void);
void out_add_folder(const char* path);
void out_begin_file(const char* name, int compress);
void out_end_file(void);
void out_write(const void* buffer, uint32_t size);
