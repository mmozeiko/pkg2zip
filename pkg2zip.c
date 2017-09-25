#include "pkg2zip_aes.h"
#include "pkg2zip_zip.h"
#include "pkg2zip_utils.h"
#include "pkg2zip_zrif.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define PKG_HEADER_SIZE 192
#define PKG_HEADER_EXT_SIZE 64

// http://vitadevwiki.com/vita/Packages_(.PKG)#Keys
static const uint8_t pkg_psp_key[] = { 0x07, 0xf2, 0xc6, 0x82, 0x90, 0xb5, 0x0d, 0x2c, 0x33, 0x81, 0x8d, 0x70, 0x9b, 0x60, 0xe6, 0x2b };
static const uint8_t pkg_vita_2[] = { 0xe3, 0x1a, 0x70, 0xc9, 0xce, 0x1d, 0xd7, 0x2b, 0xf3, 0xc0, 0x62, 0x29, 0x63, 0xf2, 0xec, 0xcb };
static const uint8_t pkg_vita_3[] = { 0x42, 0x3a, 0xca, 0x3a, 0x2b, 0xd5, 0x64, 0x9f, 0x96, 0x86, 0xab, 0xad, 0x6f, 0xd8, 0x80, 0x1f };
static const uint8_t pkg_vita_4[] = { 0xaf, 0x07, 0xfd, 0x59, 0x65, 0x25, 0x27, 0xba, 0xf1, 0x33, 0x89, 0x66, 0x8b, 0x17, 0xd9, 0xea };

static const uint8_t rif_header[] = { 0, 1, 0, 1, 0, 1, 0, 2, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01 };

// http://vitadevwiki.com/vita/System_File_Object_(SFO)_(PSF)#Internal_Structure
// https://github.com/TheOfficialFloW/VitaShell/blob/1.74/sfo.h#L29
static void parse_sfo(sys_file f, uint64_t sfo_offset, uint32_t sfo_size, char* title, char* content)
{
    uint8_t sfo[16 * 1024];
    if (sfo_size < 16)
    {
        fatal("ERROR: sfo information is too small\n");
    }
    if (sfo_size > sizeof(sfo))
    {
        fatal("ERROR: sfo information is too big, pkg file is probably corrupted\n");
    }
    sys_read(f, sfo_offset, sfo, sfo_size);

    if (get32le(sfo) != 0x46535000)
    {
        fatal("ERROR: incorrect sfo signature\n");
    }

    uint32_t keys = get32le(sfo + 8);
    uint32_t values = get32le(sfo + 12);
    uint32_t count = get32le(sfo + 16);

    int title_index = -1;
    int content_index = -1;
    for (uint32_t i=0; i<count; i++)
    {
        if (i*16 + 20 + 2 > sfo_size)
        {
            fatal("ERROR: sfo information is too small\n");
        }

        char* key = (char*)sfo + keys + get16le(sfo + i*16 + 20);
        if (strcmp(key, "TITLE") == 0)
        {
            if (title_index < 0)
            {
                title_index = (int)i;
            }
        }
        else if (strcmp(key, "STITLE") == 0)
        {
            title_index = (int)i;
        }
        else if (strcmp(key, "CONTENT_ID") == 0)
        {
            content_index = (int)i;
        }
    }

    if (title_index < 0 || content_index < 0)
    {
        fatal("ERROR: sfo information doesn't have game title or content id, pkg is probably corrupted\n");
    }

    const char* value = (char*)sfo + values + get32le(sfo + title_index*16 + 20 + 12);
    size_t i;
    size_t max = 255;
    for (i=0; i<max && *value; i++, value++)
    {
        if (*value >= 32 && *value < 127 && strchr("<>\"/\\|?*", *value) == NULL)
        {
            if (*value == ':')
            {
                *title++ = ' ';
                *title++ = '-';
                max--;
            }
            else
            {
                *title++ = *value;
            }
        }
        else if (*value == 10)
        {
            *title++ = ' ';
        }
    }
    *title = 0;

    value = (char*)sfo + values + get32le(sfo + content_index * 16 + 20 + 12);
    while (*value)
    {
        *content++ = *value++;
    }
    *content = 0;
}

static const char* get_region(const char* id)
{
    if (memcmp(id, "PCSE", 4) == 0 || memcmp(id, "PCSA", 4) == 0)
    {
        return "USA";
    }
    else if (memcmp(id, "PCSF", 4) == 0 || memcmp(id, "PCSB", 4) == 0)
    {
        return "EUR";
    }
    else if (memcmp(id, "PCSC", 4) == 0 || memcmp(id, "VCJS", 4) == 0 || 
             memcmp(id, "PCSG", 4) == 0 || memcmp(id, "VLJS", 4) == 0 ||
             memcmp(id, "VLJM", 4) == 0)
    {
        return "JPN";
    }
    else if (memcmp(id, "VCAS", 4) == 0 || memcmp(id, "PCSH", 4) == 0 ||
             memcmp(id, "VLAS", 4) == 0 || memcmp(id, "PCSD", 4) == 0)
    {
        return "ASA";
    }
    else
    {
        return "unknown region";
    }
}

int main(int argc, char* argv[])
{
    printf("pkg2zip v1.2\n");
    if (argc < 2 || argc > 3)
    {
        fatal("Usage: %s file.pkg [NoNpDrmKey]\n", argv[0]);
    }

    printf("[*] loading...\n");

    uint64_t pkg_size;
    sys_file pkg = sys_open(argv[1], &pkg_size);

    uint8_t pkg_header[PKG_HEADER_SIZE + PKG_HEADER_EXT_SIZE];
    sys_read(pkg, 0, pkg_header, sizeof(pkg_header));

    if (get32be(pkg_header) != 0x7f504b47 || get32be(pkg_header + PKG_HEADER_SIZE) != 0x7F657874)
    {
        fatal("ERROR: not a pkg file\n");
    }

    // http://www.psdevwiki.com/ps3/PKG_files
    uint64_t meta_offset = get32be(pkg_header + 8);
    uint32_t meta_count = get32be(pkg_header + 12);
    uint32_t item_count = get32be(pkg_header + 20);
    uint64_t total_size = get64be(pkg_header + 24);
    uint64_t enc_offset = get64be(pkg_header + 32);
    const uint8_t* iv = pkg_header + 0x70;
    int key_type = pkg_header[0xe7] & 7;

    if (pkg_size < total_size)
    {
        fatal("ERROR: pkg file is too small\n");
    }
    if (item_count > ZIP_MAX_FILES)
    {
        fatal("ERROR: pkg has too many files");
    }
    if (pkg_size < enc_offset + item_count * 32)
    {
        fatal("ERROR: pkg file is too small\n");
    }

    uint32_t drm_type = 0;
    uint32_t content_type = 0;
    uint32_t sfo_offset = 0;
    uint32_t sfo_size = 0;
    uint32_t items_offset = 0;
    uint32_t items_size = 0;

    for (uint32_t i = 0; i < meta_count; i++)
    {
        uint8_t block[16];
        sys_read(pkg, meta_offset, block, sizeof(block));

        uint32_t type = get32be(block + 0);
        uint32_t size = get32be(block + 4);

        if (type == 1)
        {
            drm_type = get32be(block + 8);
        }
        else if (type == 2)
        {
            content_type = get32be(block + 8);
        }
        else if (type == 13)
        {
            items_offset = get32be(block + 8);
            items_size = get32be(block + 12);
        }
        else if (type == 14)
        {
            sfo_offset = get32be(block + 8);
            sfo_size = get32be(block + 12);
        }

        meta_offset += 2 * sizeof(uint32_t) + size;
    }

    int dlc = content_type == 0x16; // 0x15 = APP

    uint8_t main_key[16];
    if (key_type == 1)
    {
        memcpy(main_key, pkg_psp_key, sizeof(main_key));
    }
    else if (key_type == 2)
    {
        aes128_key key;
        aes128_init(&key, pkg_vita_2);
        aes128_ecb_encrypt(&key, iv, main_key);
    }
    else if (key_type == 3)
    {
        aes128_key key;
        aes128_init(&key, pkg_vita_3);
        aes128_ecb_encrypt(&key, iv, main_key);
    }
    else if (key_type == 4)
    {
        aes128_key key;
        aes128_init(&key, pkg_vita_4);
        aes128_ecb_encrypt(&key, iv, main_key);
    }

    char content[256];
    char title[256];
    parse_sfo(pkg, sfo_offset, sfo_size, title, content);
    const char* id = content + 7;
    const char* id2 = id + 13;

    char path[1024];
    if (dlc)
    {
        snprintf(path, sizeof(path), "%s [%.9s] [%s] [DLC].zip", title, id, get_region(id));
    }
    else
    {
        snprintf(path, sizeof(path), "%s [%.9s] [%s].zip", title, id, get_region(id));
    }
    printf("[*] creating '%s' archive\n", path);

    zip z;
    zip_create(&z, path);

    if (dlc)
    {
        snprintf(path, sizeof(path), "addcont/");
        zip_add_folder(&z, path);

        snprintf(path, sizeof(path), "addcont/%.9s/", id);
        zip_add_folder(&z, path);
    }
    else
    {
        snprintf(path, sizeof(path), "app/");
        zip_add_folder(&z, path);

        snprintf(path, sizeof(path), "app/%.9s/", id);
        zip_add_folder(&z, path);
    }

    printf("[*] decrypting...\n");
    aes128_key key;
    aes128_init(&key, main_key);

    uint8_t work_sku_flag = (drm_type == 3 || drm_type == 13) ? 3 : 0;

    for (uint32_t item_index=0; item_index<item_count; item_index++)
    {
        uint8_t item[32];
        uint64_t offset = items_offset + item_index * 32;
        sys_read(pkg, enc_offset + offset, item, sizeof(item));
        aes128_ctr_xor(&key, iv, offset/16, item, sizeof(item));

        uint32_t name_offset = get32be(item + 0);
        uint32_t name_size = get32be(item + 4);
        uint64_t data_offset = get64be(item + 8);
        uint64_t data_size = get64be(item + 16);
        uint8_t flags = item[27];

        assert(name_offset % 16 == 0);
        assert(data_offset % 16 == 0);

        if (pkg_size < enc_offset + name_offset + name_size ||
            pkg_size < enc_offset + data_offset + data_size)
        {
            fatal("ERROR: pkg file is too short, possible corrupted\n");
        }

        char name[ZIP_MAX_FILENAME];
        sys_read(pkg, enc_offset + name_offset, name, name_size);
        aes128_ctr_xor(&key, iv, name_offset/16, (uint8_t*)name, name_size);
        name[name_size] = 0;

        printf("[%u/%u] %s\n", item_index+1, item_count, name);

        if (flags == 4 || flags == 18)
        {
            if (dlc)
            {
                if (memcmp("sce_sys/package", name, name_size) == 0)
                {
                    continue;
                }
                snprintf(path, sizeof(path), "addcont/%.9s/%s/%s/", id, id2, name);
            }
            else
            {
                snprintf(path, sizeof(path), "app/%.9s/%s/", id, name);
            }
            zip_add_folder(&z, path);
        }
        else if (flags <= 3 || (flags >= 14 && flags <= 17) ||
                 flags == 19 || flags == 21 || flags == 22)
        {
            if (memcmp("sce_pfs/pflist", name, name_size) == 0)
            {
                continue;
            }
            if (dlc)
            {
                if (strncmp("sce_sys/package/", name, 16) == 0)
                {
                    continue;
                }
                snprintf(path, sizeof(path), "addcont/%.9s/%s/%s", id, id2, name);
            }
            else
            {
                snprintf(path, sizeof(path), "app/%.9s/%s", id, name);
            }

            uint64_t offset = data_offset;

            zip_begin_file(&z, path);
            while (data_size != 0)
            {
                uint8_t buffer[1 << 16];
                uint32_t size = (uint32_t)min64(data_size, sizeof(buffer));
                sys_read(pkg, enc_offset + offset, buffer, size);
                aes128_ctr_xor(&key, iv, offset / 16, buffer, size);

                if (memcmp("sce_sys/package/temp.bin", name, name_size) == 0)
                {
                    // process data at beginning of file
                    if (offset == data_offset)
                    {
                        // https://github.com/TheOfficialFloW/NoNpDrm/blob/v1.1/src/main.c#L116
                        uint32_t sku_flag = get32be(buffer + 252);
                        if (sku_flag == 1 || sku_flag == 3)
                        {
                            work_sku_flag = 3;
                        }
                    }
                }
                zip_write_file(&z, buffer, size);
                offset += size;
                data_size -= size;
            }

            zip_end_file(&z);
        }
    }

    if (!dlc)
    {
        printf("[*] creating head.bin\n");
        snprintf(path, sizeof(path), "app/%.9s/sce_sys/package/head.bin", id);

        zip_begin_file(&z, path);
        uint64_t head_size = enc_offset + items_size;
        uint64_t head_offset = 0;
        while (head_size != 0)
        {
            uint8_t buffer[1 << 16];
            uint32_t size = (uint32_t)min64(head_size, sizeof(buffer));
            sys_read(pkg, head_offset, buffer, size);
            zip_write_file(&z, buffer, size);
            head_size -= size;
            head_offset += size;
        }
        zip_end_file(&z);

        printf("[*] creating tail.bin\n");
        snprintf(path, sizeof(path), "app/%.9s/sce_sys/package/tail.bin", id);

        uint8_t tail[480];
        zip_begin_file(&z, path);
        sys_read(pkg, total_size - sizeof(tail), tail, sizeof(tail));
        zip_write_file(&z, tail, sizeof(tail));
        zip_end_file(&z);
    }

    if (dlc)
    {
        zip_add_folder(&z, "license/");
        zip_add_folder(&z, "license/addcont/");

        snprintf(path, sizeof(path), "license/addcont/%.9s/", id);
        zip_add_folder(&z, path);

        snprintf(path, sizeof(path), "license/addcont/%.9s/%s/", id, id2);
        zip_add_folder(&z, path);

        snprintf(path, sizeof(path), "license/addcont/%.9s/%s/6488b73b912a753a492e2714e9b38bc7.rif", id, id2);
    }
    else
    {
        snprintf(path, sizeof(path), "app/%.9s/sce_sys/package/work.bin", id);
    }

    // https://github.com/TheOfficialFloW/NoNpDrm/blob/v1.1/src/main.c#L42
    uint8_t rif[512] = { 0 };
    if (argc == 3)
    {
        if (strlen(argv[2]) == 32)
        {
            printf("[*] generating rif file with '%s' key\n", argv[2]);

            memcpy(rif, rif_header, sizeof(rif_header));
            memcpy(rif + 0x10, id, 0x30);
            get_hex_bytes16(argv[2], rif + 0x50);
            rif[255] = work_sku_flag;
        }
        else
        {
            printf("[*] saving zRIF to rif file\n");
            zrif_decode(argv[2], rif);

            if (strncmp((char*)rif + 0x10, content, 0x30) != 0)
            {
                fatal("ERROR: zRIF content id '%s' doesn't match pkg '%s'\n", rif + 0x10, content);
            }
        }
    }

    zip_begin_file(&z, path);
    zip_write_file(&z, rif, sizeof(rif));
    zip_end_file(&z);

    zip_close(&z);

    printf("[*] done!\n");
}
