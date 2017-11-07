#include "pkg2zip_psp.h"
#include "pkg2zip_out.h"
#include "pkg2zip_utils.h"

#include <assert.h>
#include <string.h>

#define PSP_ISO_BLOCK_SIZE 16
#define PSP_ISO_SECTOR_SIZE 2048

// https://vitadevwiki.com/vita/Keys_NonVita#PSPAESKirk4.2F7
static const uint8_t kirk7_key38[] = { 0x12, 0x46, 0x8d, 0x7e, 0x1c, 0x42, 0x20, 0x9b, 0xba, 0x54, 0x26, 0x83, 0x5e, 0xb0, 0x33, 0x03 };
static const uint8_t kirk7_key39[] = { 0xc4, 0x3b, 0xb6, 0xd6, 0x53, 0xee, 0x67, 0x49, 0x3e, 0xa9, 0x5f, 0xbc, 0x0c, 0xed, 0x6f, 0x8a };
static const uint8_t kirk7_key63[] = { 0x9c, 0x9b, 0x13, 0x72, 0xf8, 0xc6, 0x40, 0xcf, 0x1c, 0x62, 0xf5, 0xd5, 0x92, 0xdd, 0xb5, 0x82 };

// https://vitadevwiki.com/vita/Keys_NonVita#PSPAMHashKey
static const uint8_t amctl_hashkey_3[] = { 0xe3, 0x50, 0xed, 0x1d, 0x91, 0x0a, 0x1f, 0xd0, 0x29, 0xbb, 0x1c, 0x3e, 0xf3, 0x40, 0x77, 0xfb };
static const uint8_t amctl_hashkey_4[] = { 0x13, 0x5f, 0xa4, 0x7c, 0xab, 0x39, 0x5b, 0xa4, 0x76, 0xb8, 0xcc, 0xa9, 0x8f, 0x3a, 0x04, 0x45 };
static const uint8_t amctl_hashkey_5[] = { 0x67, 0x8d, 0x7f, 0xa3, 0x2a, 0x9c, 0xa0, 0xd1, 0x50, 0x8a, 0xd8, 0x38, 0x5e, 0x4b, 0x01, 0x7e };

// lzrc decompression code from libkirk by tpu
typedef struct {
    // input stream
    const uint8_t* input;
    uint32_t in_ptr;
    uint32_t in_len;

    // output stream
    uint8_t* output;
    uint32_t out_ptr;
    uint32_t out_len;

    // range decode
    uint32_t range;
    uint32_t code;
    uint32_t out_code;
    uint8_t lc;

    uint8_t bm_literal[8][256];
    uint8_t bm_dist_bits[8][39];
    uint8_t bm_dist[18][8];
    uint8_t bm_match[8][8];
    uint8_t bm_len[8][31];
} lzrc_decode;

static void rc_init(lzrc_decode* rc, void* out, int out_len, const void* in, int in_len)
{
    if (in_len < 5)
    {
        fatal("ERROR: internal error - lzrc input underflow! pkg may be corrupted?\n");
    }

    rc->input = in;
    rc->in_len = in_len;
    rc->in_ptr = 5;

    rc->output = out;
    rc->out_len = out_len;
    rc->out_ptr = 0;

    rc->range = 0xffffffff;
    rc->lc = rc->input[0];
    rc->code = get32be(rc->input + 1);
    rc->out_code = 0xffffffff;

    memset(rc->bm_literal, 0x80, sizeof(rc->bm_literal));
    memset(rc->bm_dist_bits, 0x80, sizeof(rc->bm_dist_bits));
    memset(rc->bm_dist, 0x80, sizeof(rc->bm_dist));
    memset(rc->bm_match, 0x80, sizeof(rc->bm_match));
    memset(rc->bm_len, 0x80, sizeof(rc->bm_len));
}

static void normalize(lzrc_decode* rc)
{
    if (rc->range < 0x01000000)
    {
        rc->range <<= 8;
        rc->code = (rc->code << 8) + rc->input[rc->in_ptr];
        rc->in_ptr++;
    }
}

static int rc_bit(lzrc_decode* rc, uint8_t *prob)
{
    uint32_t bound;

    normalize(rc);

    bound = (rc->range >> 8) * (*prob);
    *prob -= *prob >> 3;

    if (rc->code < bound)
    {
        rc->range = bound;
        *prob += 31;
        return 1;
    }
    else
    {
        rc->code -= bound;
        rc->range -= bound;
        return 0;
    }
}

static int rc_bittree(lzrc_decode* rc, uint8_t *probs, int limit)
{
    int number = 1;

    do
    {
        number = (number << 1) + rc_bit(rc, probs + number);
    }
    while (number < limit);

    return number;
}

static int rc_number(lzrc_decode* rc, uint8_t *prob, uint32_t n)
{
    int number = 1;

    if (n > 3)
    {
        number = (number << 1) + rc_bit(rc, prob + 3);
        if (n > 4)
        {
            number = (number << 1) + rc_bit(rc, prob + 3);
            if (n > 5)
            {
                // direct bits
                normalize(rc);

                for (uint32_t i = 0; i < n - 5; i++)
                {
                    rc->range >>= 1;
                    number <<= 1;
                    if (rc->code < rc->range)
                    {
                        number += 1;
                    }
                    else
                    {
                        rc->code -= rc->range;
                    }
                }
            }
        }
    }

    if (n > 0)
    {
        number = (number << 1) + rc_bit(rc, prob);
        if (n > 1)
        {
            number = (number << 1) + rc_bit(rc, prob + 1);
            if (n > 2)
            {
                number = (number << 1) + rc_bit(rc, prob + 2);
            }
        }
    }

    return number;
}

static int lzrc_decompress(void* out, int out_len, const void* in, int in_len)
{
    lzrc_decode rc;
    rc_init(&rc, out, out_len, in, in_len);

    if (rc.lc & 0x80)
    {
        // plain text
        memcpy(rc.output, rc.input + 5, rc.code);
        return rc.code;
    }

    int rc_state = 0;
    uint8_t last_byte = 0;

    for (;;)
    {
        uint32_t match_step = 0;

        int bit = rc_bit(&rc, &rc.bm_match[rc_state][match_step]);
        if (bit == 0) // literal
        {
            if (rc_state > 0)
            {
                rc_state -= 1;
            }

            int byte = rc_bittree(&rc, &rc.bm_literal[((last_byte >> rc.lc) & 0x07)][0], 0x100);
            byte -= 0x100;

            if (rc.out_ptr == rc.out_len)
            {
                fatal("ERROR: internal error - lzrc output overflow! pkg may be corrupted?\n");
            }
            rc.output[rc.out_ptr++] = (uint8_t)byte;
            last_byte = (uint8_t)byte;
        }
        else // match
        {
            // find bits of match length
            uint32_t len_bits = 0;
            for (int i = 0; i < 7; i++)
            {
                match_step += 1;
                bit = rc_bit(&rc, &rc.bm_match[rc_state][match_step]);
                if (bit == 0)
                {
                    break;
                }
                len_bits += 1;
            }

            // find match length
            uint32_t match_len;
            if (len_bits == 0)
            {
                match_len = 1;
            }
            else
            {
                uint32_t len_state = ((len_bits - 1) << 2) + ((rc.out_ptr << (len_bits - 1)) & 0x03);
                match_len = rc_number(&rc, &rc.bm_len[rc_state][len_state], len_bits);
                if (match_len == 0xFF)
                {
                    // end of stream
                    return rc.out_ptr;
                }
            }

            // find number of bits of match distance
            uint32_t dist_state = 0;
            uint32_t limit = 8;
            if (match_len > 2)
            {
                dist_state += 7;
                limit = 44;
            }
            int dist_bits = rc_bittree(&rc, &rc.bm_dist_bits[len_bits][dist_state], limit);
            dist_bits -= limit;

            // find match distance
            uint32_t match_dist;
            if (dist_bits > 0)
            {
                match_dist = rc_number(&rc, &rc.bm_dist[dist_bits][0], dist_bits);
            }
            else
            {
                match_dist = 1;
            }

            // copy match bytes
            if (match_dist > rc.out_ptr)
            {
                fatal("ERROR: internal error - lzrc match_dist out of range! pkg may be corrupted?\n");
            }

            if (rc.out_ptr + match_len + 1 > rc.out_len)
            {
                fatal("ERROR: internal error - lzrc output overflow! pkg may be corrupted?\n");
            }

            const uint8_t* match_src = rc.output + rc.out_ptr - match_dist;
            for (uint32_t i = 0; i <= match_len; i++)
            {
                rc.output[rc.out_ptr++] = *match_src++;
            }
            last_byte = match_src[-1];

            rc_state = 6 + ((rc.out_ptr + 1) & 1);
        }
    }
}

static void init_psp_decrypt(aes128_key* key, uint8_t* iv, int eboot, const uint8_t* mac, const uint8_t* header, uint32_t offset1, uint32_t offset2)
{
    uint8_t tmp[16];
    aes128_init_dec(key, kirk7_key63);
    if (eboot)
    {
        aes128_ecb_decrypt(key, header + offset1, tmp);
    }
    else
    {
        memcpy(tmp, header + offset1, 16);
    }

    aes128_key aes;
    aes128_init_dec(&aes, kirk7_key38);
    aes128_ecb_decrypt(&aes, tmp, tmp);

    for (size_t i = 0; i < 16; i++)
    {
        iv[i] = mac[i] ^ tmp[i] ^ header[offset2 + i] ^ amctl_hashkey_3[i] ^ amctl_hashkey_5[i];
    }
    aes128_init_dec(&aes, kirk7_key39);
    aes128_ecb_decrypt(&aes, iv, iv);

    for (size_t i = 0; i < 16; i++)
    {
        iv[i] ^= amctl_hashkey_4[i];
    }
}

void unpack_psp_eboot(const char* path, const aes128_key* pkg_key, const uint8_t* pkg_iv, sys_file* pkg, uint64_t enc_offset, uint64_t item_offset, uint64_t item_size)
{
    if (item_size < 0x28)
    {
        fatal("ERROR: eboot.pbp file is to short!");
    }

    uint8_t eboot_header[0x28];
    sys_read(pkg, enc_offset + item_offset, eboot_header, sizeof(eboot_header));
    aes128_ctr_xor(pkg_key, pkg_iv, item_offset / 16, eboot_header, sizeof(eboot_header));

    if (memcmp(eboot_header, "\x00PBP", 4) != 0)
    {
        fatal("ERROR: wrong eboot.pbp header signature!");
    }

    uint32_t psar_offset = get32le(eboot_header + 0x24);
    if (psar_offset + 256 > item_size)
    {
        fatal("ERROR: eboot.pbp file is to short!");
    }
    assert(psar_offset % 16 == 0);

    uint8_t psar_header[256];
    sys_read(pkg, enc_offset + item_offset + psar_offset, psar_header, sizeof(psar_header));
    aes128_ctr_xor(pkg_key, pkg_iv, (item_offset + psar_offset) / 16, psar_header, sizeof(psar_header));

    if (memcmp(psar_header, "NPUMDIMG", 8) != 0)
    {
        fatal("ERROR: wrong data.psar header signature!");
    }

    uint32_t iso_block = get32le(psar_header + 0x0c);
    if (iso_block != PSP_ISO_BLOCK_SIZE)
    {
        fatal("ERROR: unsupported data.psar block size %u, only %u supported!", iso_block, PSP_ISO_BLOCK_SIZE);
    }

    uint8_t mac[16];
    aes128_cmac(kirk7_key38, psar_header, 0xc0, mac);

    aes128_key psp_key;
    uint8_t psp_iv[16];
    init_psp_decrypt(&psp_key, psp_iv, 1, mac, psar_header, 0xc0, 0xa0);
    aes128_psp_decrypt(&psp_key, psp_iv, 0, psar_header + 0x40, 0x60);

    uint32_t iso_start = get32le(psar_header + 0x54);
    uint32_t iso_end = get32le(psar_header + 0x64);
    uint32_t iso_total = iso_end - iso_start - 1;
    uint32_t block_count = (iso_total + PSP_ISO_BLOCK_SIZE - 1) / PSP_ISO_BLOCK_SIZE;

    uint32_t iso_table = get32le(psar_header + 0x6c);

    if (iso_table + block_count * 32 > item_size)
    {
        fatal("ERROR: offset table in data.psar file is too large!");
    }

    out_begin_file(path, 1);
    for (uint32_t i = 0; i < block_count; i++)
    {
        uint64_t table_offset = item_offset + psar_offset + iso_table + 32 * i;

        uint8_t table[32];
        sys_read(pkg, enc_offset + table_offset, table, sizeof(table));
        aes128_ctr_xor(pkg_key, pkg_iv, table_offset / 16, table, sizeof(table));

        uint32_t t[8];
        for (size_t k = 0; k < 8; k++)
        {
            t[k] = get32le(table + k * 4);
        }

        uint32_t block_offset = t[4] ^ t[2] ^ t[3];
        uint32_t block_size = t[5] ^ t[1] ^ t[2];
        uint32_t block_flags = t[6] ^ t[0] ^ t[3];

        if (psar_offset + block_size > item_size)
        {
            fatal("ERROR: iso block size/offset is to large!");
        }

        uint8_t data[PSP_ISO_BLOCK_SIZE * PSP_ISO_SECTOR_SIZE];

        uint64_t abs_offset = item_offset + psar_offset + block_offset;
        sys_read(pkg, enc_offset + abs_offset, data, block_size);
        aes128_ctr_xor(pkg_key, pkg_iv, abs_offset / 16, data, block_size);

        if ((block_flags & 4) == 0)
        {
            aes128_psp_decrypt(&psp_key, psp_iv, block_offset / 16, data, block_size);
        }

        uint32_t out_size;
        if (block_size == sizeof(data))
        {
            out_write(data, (uint32_t)block_size);
        }
        else
        {
            uint8_t uncompressed[PSP_ISO_BLOCK_SIZE * PSP_ISO_SECTOR_SIZE];
            out_size = lzrc_decompress(uncompressed, sizeof(uncompressed), data, block_size);
            if (out_size != sizeof(uncompressed))
            {
                fatal("ERROR: internal error - lzrc decompression failed! pkg may be corrupted?");
            }
            out_write(uncompressed, (uint32_t)out_size);
        }
    }

    out_end_file();
}

void unpack_psp_key(const char* path, const aes128_key* pkg_key, const uint8_t* pkg_iv, sys_file* pkg, uint64_t enc_offset, uint64_t item_offset, uint64_t item_size)
{
    if (item_size < 0x90 + 0xa0)
    {
        fatal("ERROR: PSP-KEY.EDAT file is to short!");
    }

    uint8_t key_header[0xa0];
    sys_read(pkg, enc_offset + item_offset + 0x90, key_header, sizeof(key_header));
    aes128_ctr_xor(pkg_key, pkg_iv, (item_offset + 0x90) / 16, key_header, sizeof(key_header));

    if (memcmp(key_header, "\x00PGD", 4) != 0)
    {
        fatal("ERROR: wrong PSP-KEY.EDAT header signature!");
    }

    uint32_t key_index = get32le(key_header + 4);
    uint32_t drm_type = get32le(key_header + 8);
    if (key_index != 1 || drm_type != 1)
    {
        fatal("ERROR: unsupported PSP-KEY.EDAT file, key/drm type is wrong!");
    }

    uint8_t mac[16];
    aes128_cmac(kirk7_key38, key_header, 0x70, mac);

    aes128_key psp_key;
    uint8_t psp_iv[16];
    init_psp_decrypt(&psp_key, psp_iv, 0, mac, key_header, 0x70, 0x10);
    aes128_psp_decrypt(&psp_key, psp_iv, 0, key_header + 0x30, 0x30);

    uint32_t data_size = get32le(key_header + 0x44);
    uint32_t data_offset = get32le(key_header + 0x4c);

    if (data_size != 0x10 || data_offset != 0x90)
    {
        fatal("ERROR: unsupported PSP-KEY.EDAT file, data/offset is wrong!");
    }

    init_psp_decrypt(&psp_key, psp_iv, 0, mac, key_header, 0x70, 0x30);
    aes128_psp_decrypt(&psp_key, psp_iv, 0, key_header + 0x90, 0x10);

    out_begin_file(path, 0);
    out_write(key_header + 0x90, 0x10);
    out_end_file();
}
