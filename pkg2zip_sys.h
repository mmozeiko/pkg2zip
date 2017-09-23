#pragma once

#include <stddef.h>
#include <stdint.h>

typedef void* sys_file;

sys_file sys_open(const char* fname, uint64_t* size);
sys_file sys_create(const char* fname);
void sys_close(sys_file file);
void sys_read(sys_file file, uint64_t offset, void* buffer, uint32_t size);
void sys_write(sys_file file, uint64_t offset, const void* buffer, uint32_t size);

void sys_rename(const char* src, const char* dst);
