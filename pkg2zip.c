#include "pkg2zip_aes.h"
#include "pkg2zip_zip.h"
#include "pkg2zip_utils.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static const uint8_t pkg_psp_key[] = {
    0x07, 0xf2, 0xc6, 0x82, 0x90, 0xb5, 0x0d, 0x2c, 0x33, 0x81, 0x8d, 0x70, 0x9b, 0x60, 0xe6, 0x2b,
};

static const uint8_t pkg_vita_2[] = {
    0xe3, 0x1a, 0x70, 0xc9, 0xce, 0x1d, 0xd7, 0x2b, 0xf3, 0xc0, 0x62, 0x29, 0x63, 0xf2, 0xec, 0xcb,
};

static const uint8_t pkg_vita_3[] = {
    0x42, 0x3a, 0xca, 0x3a, 0x2b, 0xd5, 0x64, 0x9f, 0x96, 0x86, 0xab, 0xad, 0x6f, 0xd8, 0x80, 0x1f,
};

static const uint8_t pkg_vita_4[] = {
    0xaf, 0x07, 0xfd, 0x59, 0x65, 0x25, 0x27, 0xba, 0xf1, 0x33, 0x89, 0x66, 0x8b, 0x17, 0xd9, 0xea,
};

static const uint8_t rif_header[] = {
    0, 1, 0, 1, 0, 1, 0, 2, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
};

static void get_title(const uint8_t* data, size_t data_size, char* title)
{
    if (data_size < 16)
    {
        fatal("ERROR: wrong param.sfo size\n");
    }

    uint32_t magic = get32le(data);
    if (magic != 0x46535000)
    {
        fatal("ERROR: incorrect param.sfo signature\n");
    }

    // https://github.com/TheOfficialFloW/VitaShell/blob/1.74/sfo.h#L29
    uint32_t keys = get32le(data + 8);
    uint32_t values = get32le(data + 12);
    size_t count = get32le(data + 16);

    int index = -1;

    for (size_t i=0; i<count; i++)
    {
        if (i*16 + 20 + 2 > data_size)
        {
            fatal("ERROR: truncated param.sfo size\n");
        }

        char* key = (char*)data + keys + get16le(data + i*16 + 20);
        if (strcmp(key, "TITLE") == 0)
        {
            if (index < 0)
            {
                index = (int)i;
            }
        }
        else if (strcmp(key, "STITLE") == 0)
        {
            index = (int)i;
            break;
        }
    }

    if (index >= 0)
    {
        const char* value = (char*)data + values + get32le(data + index*16 + 20 + 12);
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
    }
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
             memcmp(id, "VLAS", 4) == 0)
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
    printf("pkg2zip v1.1\n");
    if (argc < 2 || argc > 3)
    {
        fatal("Usage: %s file.pkg [NoNpDrmKey]\n", argv[0]);
    }

    printf("[*] loading...\n");

    uint64_t pkg_size;
    sys_file pkg = sys_open(argv[1], &pkg_size);

    uint8_t pkg_header[256];
    sys_read(pkg, 0, pkg_header, sizeof(pkg_header));

    if (get32be(pkg_header) != 0x7f504b47)
    {
        fatal("ERROR: pkg file is corrupted\n");
    }

    uint32_t item_count = get32be(pkg_header + 20);
    uint64_t enc_offset = get64be(pkg_header + 32);

    if (item_count > ZIP_MAX_FILES)
    {
        fatal("ERROR: pkg has too many files");
    }

    if (pkg_size < enc_offset + item_count * 32)
    {
        fatal("ERROR: pkg file is truncated\n");
    }

    const char* id = (char*)pkg_header + 0x37;
    const uint8_t* iv = pkg_header + 0x70;
    int key_type = pkg_header[0xe7] & 7;

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

    uint8_t items[32 * ZIP_MAX_FILES];
    uint32_t items_size = 32 * item_count;

    sys_read(pkg, enc_offset, items, items_size);

    uint8_t temp_flag = 0;
    size_t head_size = enc_offset;
    char title[256] = "unknown title";

    char path[1024];
    snprintf(path, sizeof(path), ".~%.*s.zip", 9, id);

    printf("[*] creating temporary '%s' archive\n", path);

    zip z;
    zip_create(&z, path);

    snprintf(path, sizeof(path), "app/");
    zip_add_folder(&z, path);

    snprintf(path, sizeof(path), "app/%.9s/", id);
    zip_add_folder(&z, path);

    printf("[*] decrypting...\n");
    aes128_key key;
    aes128_init(&key, main_key);
    aes128_ctr_xor(&key, iv, 0, items, items_size);

    for (uint32_t item_index=0; item_index<item_count; item_index++)
    {
        uint8_t* item = items + item_index * 32;

        uint32_t name_offset = get32be(item + 0);
        uint32_t name_size = get32be(item + 4);
        uint64_t data_offset = get64be(item + 8);
        uint64_t data_size = get64be(item + 16);
        uint8_t flags = item[27];

        if (item_index == 0)
        {
            head_size += data_offset;
        }

        assert(name_offset % 16 == 0);
        assert(data_offset % 16 == 0);

        if (pkg_size < enc_offset + name_offset + name_size ||
            pkg_size < enc_offset + data_offset + data_size)
        {
            fatal("ERROR: pkg file is truncated\n");
        }

        char name[ZIP_MAX_FILENAME];
        sys_read(pkg, enc_offset + name_offset, name, name_size);
        aes128_ctr_xor(&key, iv, name_offset/16, (uint8_t*)name, name_size);
        name[name_size] = 0;

        printf("[%u/%u] %s\n", item_index+1, item_count, name);

        if (flags == 4 || flags == 18)
        {
            snprintf(path, sizeof(path), "app/%.9s/%s/", id, name);
            zip_add_folder(&z, path);
        }
        else if (flags <= 3 || (flags >= 14 && flags <= 17) ||
                 flags == 19 || flags == 21 || flags == 22)
        {
            if (memcmp("sce_pfs/pflist", name, name_size) != 0)
            {
                snprintf(path, sizeof(path), "app/%.9s/%s", id, name);

                uint64_t offset = data_offset;

                zip_begin_file(&z, path);
                while (data_size != 0)
                {
                    uint8_t buffer[1 << 16];
                    uint32_t size = (uint32_t)min64(data_size, sizeof(buffer));
                    sys_read(pkg, enc_offset + offset, buffer, size);
                    aes128_ctr_xor(&key, iv, offset / 16, buffer, size);

                    // process data at beginning of file
                    if (offset == data_offset)
                    {
                        if (memcmp("sce_sys/package/temp.bin", name, name_size) == 0)
                        {
                            // https://github.com/TheOfficialFloW/NoNpDrm/blob/v1.1/src/main.c#L116
                            uint32_t sku_flag = get32be(buffer + 252);
                            if (sku_flag == 1 || sku_flag == 3)
                            {
                                temp_flag = 3;
                            }
                        }
                        else if (memcmp("sce_sys/param.sfo", name, name_size) == 0)
                        {
                            get_title(buffer, size, title);
                        }
                    }
                    zip_write_file(&z, buffer, size);
                    offset += size;
                    data_size -= size;
                }

                zip_end_file(&z);
            }
        }
    }

    printf("[*] creating head.bin\n");
    snprintf(path, sizeof(path), "app/%.9s/sce_sys/package/head.bin", id);

    zip_begin_file(&z, path);
    size_t head_offset = 0;
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
    sys_read(pkg, pkg_size - sizeof(tail), tail, sizeof(tail));
    zip_write_file(&z, tail, sizeof(tail));
    zip_end_file(&z);

    printf("[*] creating work.bin\n");
    snprintf(path, sizeof(path), "app/%.9s/sce_sys/package/work.bin", id);

    // https://github.com/TheOfficialFloW/NoNpDrm/blob/v1.1/src/main.c#L42
    uint8_t work[512] = { 0 };
    memcpy(work, rif_header, sizeof(rif_header));
    memcpy(work + 0x10, pkg_header + 0x30, 0x30);
    if (argc == 3)
    {
        printf("[*] embedding '%s' key\n", argv[2]);
        get_hex_bytes16(argv[2], work + 0x50);
    }
    work[255] = temp_flag;
    zip_begin_file(&z, path);
    zip_write_file(&z, work, sizeof(work));
    zip_end_file(&z);

    zip_close(&z);

    snprintf(path, sizeof(path), ".~%.*s.zip", 9, id);

    char target[1024];
    snprintf(target, sizeof(target), "%s [%.9s] [%s].zip", title, id, get_region(id));

    printf("[*] renaming to '%s'\n", target);
    sys_rename(path, target);

    printf("[*] done!\n");
}
