#include "pkg2zip_aes.h"
#include "pkg2zip_sys.h"

void unpack_psp_eboot(const char* path, const aes128_key* pkg_key, const uint8_t* pkg_iv, sys_file* pkg, uint64_t enc_offset, uint64_t item_offset, uint64_t item_size, int cso);
void unpack_psp_key(const char* path, const aes128_key* pkg_key, const uint8_t* pkg_iv, sys_file* pkg, uint64_t enc_offset, uint64_t item_offset, uint64_t item_size);
void unpack_psp_edat(const char* path, const aes128_key* pkg_key, const uint8_t* pkg_iv, sys_file* pkg, uint64_t enc_offset, uint64_t item_offset, uint64_t item_size);
void unpack_keys_bin(const char* path, const aes128_key* pkg_key, const uint8_t* pkg_iv, sys_file* pkg, uint64_t enc_offset, uint64_t item_offset, uint64_t item_size);
void get_psp_theme_title(char* title, const aes128_key* pkg_key, const uint8_t* pkg_iv, sys_file* pkg, uint64_t enc_offset, uint64_t item_offset);
