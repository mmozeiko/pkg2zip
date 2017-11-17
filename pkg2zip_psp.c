#include "pkg2zip_psp.h"
#include "pkg2zip_out.h"
#include "pkg2zip_crc32.h"
#include "pkg2zip_utils.h"
#include "miniz_tdef.h"

#include <assert.h>
#include <string.h>

#define ISO_SECTOR_SIZE 2048

#define CSO_HEADER_SIZE 24

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
        sys_error("ERROR: internal error - lzrc input underflow! pkg may be corrupted?\n");
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
                sys_error("ERROR: internal error - lzrc output overflow! pkg may be corrupted?\n");
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
                sys_error("ERROR: internal error - lzrc match_dist out of range! pkg may be corrupted?\n");
            }

            if (rc.out_ptr + match_len + 1 > rc.out_len)
            {
                sys_error("ERROR: internal error - lzrc output overflow! pkg may be corrupted?\n");
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

void unpack_psp_eboot(const char* path, const aes128_key* pkg_key, const uint8_t* pkg_iv, sys_file* pkg, uint64_t enc_offset, uint64_t item_offset, uint64_t item_size, int cso)
{
    if (item_size < 0x28)
    {
        sys_error("ERROR: eboot.pbp file is to short!\n");
    }

    uint8_t eboot_header[0x28];
    sys_read(pkg, enc_offset + item_offset, eboot_header, sizeof(eboot_header));
    aes128_ctr_xor(pkg_key, pkg_iv, item_offset / 16, eboot_header, sizeof(eboot_header));

    if (memcmp(eboot_header, "\x00PBP", 4) != 0)
    {
        sys_error("ERROR: wrong eboot.pbp header signature!\n");
    }

    uint32_t psar_offset = get32le(eboot_header + 0x24);
    if (psar_offset + 256 > item_size)
    {
        sys_error("ERROR: eboot.pbp file is to short!\n");
    }
    assert(psar_offset % 16 == 0);

    uint8_t psar_header[256];
    sys_read(pkg, enc_offset + item_offset + psar_offset, psar_header, sizeof(psar_header));
    aes128_ctr_xor(pkg_key, pkg_iv, (item_offset + psar_offset) / 16, psar_header, sizeof(psar_header));

    if (memcmp(psar_header, "NPUMDIMG", 8) != 0)
    {
        sys_error("ERROR: wrong data.psar header signature!\n");
    }

    uint32_t iso_block = get32le(psar_header + 0x0c);
    if (iso_block > 16)
    {
        sys_error("ERROR: unsupported data.psar block size %u, max %u supported!\b", iso_block, 16);
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
    uint32_t block_count = (iso_total + iso_block - 1) / iso_block;

    uint32_t iso_table = get32le(psar_header + 0x6c);

    if (iso_table + block_count * 32 > item_size)
    {
        sys_error("ERROR: offset table in data.psar file is too large!\n");
    }

    mz_uint cso_compress_flags = 0;
    uint32_t cso_index = 0;
    uint32_t cso_offset = 0;
    uint64_t cso_size = 0;
    uint32_t* cso_block = NULL;
    uint32_t initial_size = 0;

    uint64_t file_offset = out_begin_file(path, !cso);
    if (cso)
    {
        cso_size = block_count * iso_block * ISO_SECTOR_SIZE;
        cso_compress_flags = tdefl_create_comp_flags_from_zip_params(cso, -MZ_DEFAULT_WINDOW_BITS, MZ_DEFAULT_STRATEGY);

        uint32_t cso_block_count = (uint32_t)(1 + (cso_size + ISO_SECTOR_SIZE - 1) / ISO_SECTOR_SIZE);
        cso_block = sys_realloc(NULL, cso_block_count * sizeof(uint32_t));

        initial_size = CSO_HEADER_SIZE + cso_block_count * sizeof(uint32_t);
        out_set_offset(file_offset + initial_size);

        cso_offset = initial_size;
    }

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
            sys_error("ERROR: iso block size/offset is to large!\n");
        }

        uint8_t PKG_ALIGN(16) data[16 * ISO_SECTOR_SIZE];

        uint64_t abs_offset = item_offset + psar_offset + block_offset;
        sys_output_progress(enc_offset + abs_offset);
        sys_read(pkg, enc_offset + abs_offset, data, block_size);
        aes128_ctr_xor(pkg_key, pkg_iv, abs_offset / 16, data, block_size);

        if ((block_flags & 4) == 0)
        {
            aes128_psp_decrypt(&psp_key, psp_iv, block_offset / 16, data, block_size);
        }

        uint32_t out_size;
        if (block_size == iso_block * ISO_SECTOR_SIZE)
        {
            if (cso)
            {
                for (size_t n = 0; n < iso_block * ISO_SECTOR_SIZE; n += ISO_SECTOR_SIZE)
                {
                    cso_block[cso_index] = cso_offset;

                    uint8_t PKG_ALIGN(16) output[ISO_SECTOR_SIZE];
                    size_t insize = ISO_SECTOR_SIZE;
                    size_t outsize = sizeof(output);

                    tdefl_compressor c;
                    tdefl_init(&c, cso_compress_flags);
                    tdefl_status st = tdefl_compress(&c, data + n, &insize, output, &outsize, TDEFL_FINISH);
                    if (st == TDEFL_STATUS_DONE)
                    {
                        out_write(output, (uint32_t)outsize);
                        cso_offset += (uint32_t)outsize;
                    }
                    else
                    {
                        cso_block[cso_index] |= 0x80000000;
                        out_write(data + n, ISO_SECTOR_SIZE);
                        cso_offset += ISO_SECTOR_SIZE;
                    }
                    cso_index++;
                }
            }
            else
            {
                out_write(data, (uint32_t)block_size);
            }
        }
        else
        {
            uint8_t PKG_ALIGN(16) uncompressed[16 * ISO_SECTOR_SIZE];
            out_size = lzrc_decompress(uncompressed, sizeof(uncompressed), data, block_size);
            if (out_size != iso_block * ISO_SECTOR_SIZE)
            {
                sys_error("ERROR: internal error - lzrc decompression failed! pkg may be corrupted?\n");
            }
            if (cso)
            {
                for (size_t n = 0; n < iso_block * ISO_SECTOR_SIZE; n += ISO_SECTOR_SIZE)
                {
                    cso_block[cso_index] = cso_offset;

                    uint8_t output[ISO_SECTOR_SIZE];
                    size_t insize = ISO_SECTOR_SIZE;
                    size_t outsize = sizeof(output);

                    tdefl_compressor c;
                    tdefl_init(&c, cso_compress_flags);
                    tdefl_status st = tdefl_compress(&c, uncompressed + n, &insize, output, &outsize, TDEFL_FINISH);
                    if (st == TDEFL_STATUS_DONE)
                    {
                        out_write(output, (uint32_t)outsize);
                        cso_offset += (uint32_t)outsize;
                    }
                    else
                    {
                        cso_block[cso_index] |= 0x80000000;
                        out_write(uncompressed + n, ISO_SECTOR_SIZE);
                        cso_offset += ISO_SECTOR_SIZE;
                    }
                    cso_index++;
                }
            }
            else
            {
                out_write(uncompressed, (uint32_t)out_size);
            }
        }
    }

    if (cso)
    {
        cso_block[cso_index++] = cso_offset;

        uint8_t cso_header[CSO_HEADER_SIZE] = { 0x43, 0x49, 0x53, 0x4f };
        // header size
        set32le(cso_header + 4, sizeof(cso_header));
        // original size
        set64le(cso_header + 8, cso_size);
        // block size
        set32le(cso_header + 16, ISO_SECTOR_SIZE);
        // version
        cso_header[20] = 1;

        out_write_at(file_offset, cso_header, sizeof(cso_header));
        out_write_at(file_offset + sizeof(cso_header), cso_block, cso_index * sizeof(uint32_t));

        crc32_ctx cheader;
        crc32_init(&cheader);
        crc32_update(&cheader, cso_header, sizeof(cso_header));
        crc32_update(&cheader, cso_block, cso_index * sizeof(uint32_t));

        uint32_t header_crc32 = crc32_done(&cheader);
        uint32_t data_crc32 = out_zip_get_crc32();
        uint32_t data_len = (uint32_t)(cso_offset - initial_size);

        uint32_t crc32 = crc32_combine(header_crc32, data_crc32, data_len);
        out_zip_set_crc32(crc32);

        sys_realloc(cso_block, 0);
    }

    out_end_file();
}

void unpack_psp_key(const char* path, const aes128_key* pkg_key, const uint8_t* pkg_iv, sys_file* pkg, uint64_t enc_offset, uint64_t item_offset, uint64_t item_size)
{
    if (item_size < 0x90 + 0xa0)
    {
        sys_error("ERROR: PSP-KEY.EDAT file is to short!\n");
    }

    uint8_t key_header[0xa0];
    sys_read(pkg, enc_offset + item_offset + 0x90, key_header, sizeof(key_header));
    aes128_ctr_xor(pkg_key, pkg_iv, (item_offset + 0x90) / 16, key_header, sizeof(key_header));

    if (memcmp(key_header, "\x00PGD", 4) != 0)
    {
        sys_error("ERROR: wrong PSP-KEY.EDAT header signature!\n");
    }

    uint32_t key_index = get32le(key_header + 4);
    uint32_t drm_type = get32le(key_header + 8);
    if (key_index != 1 || drm_type != 1)
    {
        sys_error("ERROR: unsupported PSP-KEY.EDAT file, key/drm type is wrong!\n");
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
        sys_error("ERROR: unsupported PSP-KEY.EDAT file, data/offset is wrong!\n");
    }

    init_psp_decrypt(&psp_key, psp_iv, 0, mac, key_header, 0x70, 0x30);
    aes128_psp_decrypt(&psp_key, psp_iv, 0, key_header + 0x90, 0x10);

    out_begin_file(path, 0);
    out_write(key_header + 0x90, 0x10);
    out_end_file();
}
