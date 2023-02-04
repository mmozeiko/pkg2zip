#pragma once

#include "pkg2zip_utils.h"

// correctly outputs utf8 string
void sys_output_init(void);
void sys_output_done(void);
void sys_output(const char* msg, ...);
void NORETURN sys_error(const char* msg, ...);

void sys_output_progress_init(uint64_t size);
void sys_output_progress(uint64_t progress);

typedef void* sys_file;

void sys_mkdir(const char* path);

sys_file sys_open(const char* fname, uint64_t* size);
sys_file sys_create(const char* fname);
void sys_close(sys_file file);
void sys_read(sys_file file, uint64_t offset, void* buffer, uint32_t size);
void sys_write(sys_file file, uint64_t offset, const void* buffer, uint32_t size);

// if !ptr && size => malloc
// if ptr && !size => free
// if ptr && size => realloc
void* sys_realloc(void* ptr, size_t size);

void sys_vstrncat(char* dst, size_t n, const char* format, ...);

int sys_test_dir(const char* const path);