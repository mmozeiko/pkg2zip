#include "miniz_tdef.h"

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__i386) || defined(__i486__) || defined(__i486) || defined(i386) || defined(__ia64__) || defined(__x86_64__)
/* MINIZ_X86_OR_X64_CPU is only used to help set the below macros. */
#define MINIZ_X86_OR_X64_CPU 1
#else
#define MINIZ_X86_OR_X64_CPU 0
#endif

#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || MINIZ_X86_OR_X64_CPU
/* Set MINIZ_LITTLE_ENDIAN to 1 if the processor is little endian. */
#define MINIZ_LITTLE_ENDIAN 1
#else
#define MINIZ_LITTLE_ENDIAN 0
#endif

#if MINIZ_X86_OR_X64_CPU
/* Set MINIZ_USE_UNALIGNED_LOADS_AND_STORES to 1 on CPU's that permit efficient integer loads and stores from unaligned addresses. */
#define MINIZ_USE_UNALIGNED_LOADS_AND_STORES 1
#else
#define MINIZ_USE_UNALIGNED_LOADS_AND_STORES 0
#endif

#if defined(_M_X64) || defined(_WIN64) || defined(__MINGW64__) || defined(_LP64) || defined(__LP64__) || defined(__ia64__) || defined(__x86_64__)
/* Set MINIZ_HAS_64BIT_REGISTERS to 1 if operations on 64-bit integers are reasonably fast (and don't involve compiler generated calls to helper functions). */
#define MINIZ_HAS_64BIT_REGISTERS 1
#else
#define MINIZ_HAS_64BIT_REGISTERS 0
#endif

// ------------------- Low-level Compression (independent from all decompression API's)

// Purposely making these tables static for faster init and thread safety.
static const mz_uint16 s_tdefl_len_sym[256] =
    {
        257, 258, 259, 260, 261, 262, 263, 264, 265, 265, 266, 266, 267, 267, 268, 268, 269, 269, 269, 269, 270, 270, 270, 270, 271, 271, 271, 271, 272, 272, 272, 272,
        273, 273, 273, 273, 273, 273, 273, 273, 274, 274, 274, 274, 274, 274, 274, 274, 275, 275, 275, 275, 275, 275, 275, 275, 276, 276, 276, 276, 276, 276, 276, 276,
        277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278,
        279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280,
        281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281,
        282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282,
        283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283,
        284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 285
    };

static const mz_uint8 s_tdefl_len_extra[256] =
    {
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0
    };

static const mz_uint8 s_tdefl_small_dist_sym[512] =
    {
        0, 1, 2, 3, 4, 4, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11,
        11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13,
        13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
        14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
        14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
        15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
        16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
        16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
        16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
        17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
        17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
        17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17
    };

static const mz_uint8 s_tdefl_small_dist_extra[512] =
    {
        0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7
    };

static const mz_uint8 s_tdefl_large_dist_sym[128] =
    {
        0, 0, 18, 19, 20, 20, 21, 21, 22, 22, 22, 22, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
        26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29
    };

static const mz_uint8 s_tdefl_large_dist_extra[128] =
    {
        0, 0, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
        12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
        13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13
    };

// Radix sorts tdefl_sym_freq[] array by 16-bit key m_key. Returns ptr to sorted values.
typedef struct
{
    mz_uint16 m_key, m_sym_index;
} tdefl_sym_freq;
static tdefl_sym_freq *tdefl_radix_sort_syms(mz_uint num_syms, tdefl_sym_freq *pSyms0, tdefl_sym_freq *pSyms1)
{
    mz_uint32 total_passes = 2, pass_shift, pass, i, hist[256 * 2];
    tdefl_sym_freq *pCur_syms = pSyms0, *pNew_syms = pSyms1;
    MZ_CLEAR_OBJ(hist);
    for (i = 0; i < num_syms; i++)
    {
        mz_uint freq = pSyms0[i].m_key;
        hist[freq & 0xFF]++;
        hist[256 + ((freq >> 8) & 0xFF)]++;
    }
    while ((total_passes > 1) && (num_syms == hist[(total_passes - 1) * 256]))
        total_passes--;
    for (pass_shift = 0, pass = 0; pass < total_passes; pass++, pass_shift += 8)
    {
        const mz_uint32 *pHist = &hist[pass << 8];
        mz_uint offsets[256], cur_ofs = 0;
        for (i = 0; i < 256; i++)
        {
            offsets[i] = cur_ofs;
            cur_ofs += pHist[i];
        }
        for (i = 0; i < num_syms; i++)
            pNew_syms[offsets[(pCur_syms[i].m_key >> pass_shift) & 0xFF]++] = pCur_syms[i];
        {
            tdefl_sym_freq *t = pCur_syms;
            pCur_syms = pNew_syms;
            pNew_syms = t;
        }
    }
    return pCur_syms;
}

// tdefl_calculate_minimum_redundancy() originally written by: Alistair Moffat, alistair@cs.mu.oz.au, Jyrki Katajainen, jyrki@diku.dk, November 1996.
static void tdefl_calculate_minimum_redundancy(tdefl_sym_freq *A, int n)
{
    int root, leaf, next, avbl, used, dpth;
    if (n == 0)
        return;
    else if (n == 1)
    {
        A[0].m_key = 1;
        return;
    }
    A[0].m_key += A[1].m_key;
    root = 0;
    leaf = 2;
    for (next = 1; next < n - 1; next++)
    {
        if (leaf >= n || A[root].m_key < A[leaf].m_key)
        {
            A[next].m_key = A[root].m_key;
            A[root++].m_key = (mz_uint16)next;
        }
        else
            A[next].m_key = A[leaf++].m_key;
        if (leaf >= n || (root < next && A[root].m_key < A[leaf].m_key))
        {
            A[next].m_key = (mz_uint16)(A[next].m_key + A[root].m_key);
            A[root++].m_key = (mz_uint16)next;
        }
        else
            A[next].m_key = (mz_uint16)(A[next].m_key + A[leaf++].m_key);
    }
    A[n - 2].m_key = 0;
    for (next = n - 3; next >= 0; next--)
        A[next].m_key = A[A[next].m_key].m_key + 1;
    avbl = 1;
    used = dpth = 0;
    root = n - 2;
    next = n - 1;
    while (avbl > 0)
    {
        while (root >= 0 && (int)A[root].m_key == dpth)
        {
            used++;
            root--;
        }
        while (avbl > used)
        {
            A[next--].m_key = (mz_uint16)(dpth);
            avbl--;
        }
        avbl = 2 * used;
        dpth++;
        used = 0;
    }
}

// Limits canonical Huffman code table's max code size.
enum
{
    TDEFL_MAX_SUPPORTED_HUFF_CODESIZE = 32
};
static void tdefl_huffman_enforce_max_code_size(int *pNum_codes, int code_list_len, int max_code_size)
{
    int i;
    mz_uint32 total = 0;
    if (code_list_len <= 1)
        return;
    for (i = max_code_size + 1; i <= TDEFL_MAX_SUPPORTED_HUFF_CODESIZE; i++)
        pNum_codes[max_code_size] += pNum_codes[i];
    for (i = max_code_size; i > 0; i--)
        total += (((mz_uint32)pNum_codes[i]) << (max_code_size - i));
    while (total != (1UL << max_code_size))
    {
        pNum_codes[max_code_size]--;
        for (i = max_code_size - 1; i > 0; i--)
            if (pNum_codes[i])
            {
                pNum_codes[i]--;
                pNum_codes[i + 1] += 2;
                break;
            }
        total--;
    }
}

static void tdefl_optimize_huffman_table(tdefl_compressor *d, int table_num, int table_len, int code_size_limit, int static_table)
{
    int i, j, l, num_codes[1 + TDEFL_MAX_SUPPORTED_HUFF_CODESIZE];
    mz_uint next_code[TDEFL_MAX_SUPPORTED_HUFF_CODESIZE + 1];
    MZ_CLEAR_OBJ(num_codes);
    if (static_table)
    {
        for (i = 0; i < table_len; i++)
            num_codes[d->m_huff_code_sizes[table_num][i]]++;
    }
    else
    {
        tdefl_sym_freq syms0[TDEFL_MAX_HUFF_SYMBOLS], syms1[TDEFL_MAX_HUFF_SYMBOLS], *pSyms;
        int num_used_syms = 0;
        const mz_uint16 *pSym_count = &d->m_huff_count[table_num][0];
        for (i = 0; i < table_len; i++)
            if (pSym_count[i])
            {
                syms0[num_used_syms].m_key = (mz_uint16)pSym_count[i];
                syms0[num_used_syms++].m_sym_index = (mz_uint16)i;
            }

        pSyms = tdefl_radix_sort_syms(num_used_syms, syms0, syms1);
        tdefl_calculate_minimum_redundancy(pSyms, num_used_syms);

        for (i = 0; i < num_used_syms; i++)
            num_codes[pSyms[i].m_key]++;

        tdefl_huffman_enforce_max_code_size(num_codes, num_used_syms, code_size_limit);

        MZ_CLEAR_OBJ(d->m_huff_code_sizes[table_num]);
        MZ_CLEAR_OBJ(d->m_huff_codes[table_num]);
        for (i = 1, j = num_used_syms; i <= code_size_limit; i++)
            for (l = num_codes[i]; l > 0; l--)
                d->m_huff_code_sizes[table_num][pSyms[--j].m_sym_index] = (mz_uint8)(i);
    }

    next_code[1] = 0;
    for (j = 0, i = 2; i <= code_size_limit; i++)
        next_code[i] = j = ((j + num_codes[i - 1]) << 1);

    for (i = 0; i < table_len; i++)
    {
        mz_uint rev_code = 0, code, code_size;
        if ((code_size = d->m_huff_code_sizes[table_num][i]) == 0)
            continue;
        code = next_code[code_size]++;
        for (l = code_size; l > 0; l--, code >>= 1)
            rev_code = (rev_code << 1) | (code & 1);
        d->m_huff_codes[table_num][i] = (mz_uint16)rev_code;
    }
}

#define TDEFL_PUT_BITS(b, l)                                       \
    do                                                             \
    {                                                              \
        mz_uint bits = b;                                          \
        mz_uint len = l;                                           \
        MZ_ASSERT(bits <= ((1U << len) - 1U));                     \
        d->m_bit_buffer |= (bits << d->m_bits_in);                 \
        d->m_bits_in += len;                                       \
        while (d->m_bits_in >= 8)                                  \
        {                                                          \
            if (d->m_pOutput_buf < d->m_pOutput_buf_end)           \
                *d->m_pOutput_buf++ = (mz_uint8)(d->m_bit_buffer); \
            d->m_bit_buffer >>= 8;                                 \
            d->m_bits_in -= 8;                                     \
        }                                                          \
    }                                                              \
    MZ_MACRO_END

#define TDEFL_RLE_PREV_CODE_SIZE()                                                                                       \
    {                                                                                                                    \
        if (rle_repeat_count)                                                                                            \
        {                                                                                                                \
            if (rle_repeat_count < 3)                                                                                    \
            {                                                                                                            \
                d->m_huff_count[2][prev_code_size] = (mz_uint16)(d->m_huff_count[2][prev_code_size] + rle_repeat_count); \
                while (rle_repeat_count--)                                                                               \
                    packed_code_sizes[num_packed_code_sizes++] = prev_code_size;                                         \
            }                                                                                                            \
            else                                                                                                         \
            {                                                                                                            \
                d->m_huff_count[2][16] = (mz_uint16)(d->m_huff_count[2][16] + 1);                                        \
                packed_code_sizes[num_packed_code_sizes++] = 16;                                                         \
                packed_code_sizes[num_packed_code_sizes++] = (mz_uint8)(rle_repeat_count - 3);                           \
            }                                                                                                            \
            rle_repeat_count = 0;                                                                                        \
        }                                                                                                                \
    }

#define TDEFL_RLE_ZERO_CODE_SIZE()                                                         \
    {                                                                                      \
        if (rle_z_count)                                                                   \
        {                                                                                  \
            if (rle_z_count < 3)                                                           \
            {                                                                              \
                d->m_huff_count[2][0] = (mz_uint16)(d->m_huff_count[2][0] + rle_z_count);  \
                while (rle_z_count--)                                                      \
                    packed_code_sizes[num_packed_code_sizes++] = 0;                        \
            }                                                                              \
            else if (rle_z_count <= 10)                                                    \
            {                                                                              \
                d->m_huff_count[2][17] = (mz_uint16)(d->m_huff_count[2][17] + 1);          \
                packed_code_sizes[num_packed_code_sizes++] = 17;                           \
                packed_code_sizes[num_packed_code_sizes++] = (mz_uint8)(rle_z_count - 3);  \
            }                                                                              \
            else                                                                           \
            {                                                                              \
                d->m_huff_count[2][18] = (mz_uint16)(d->m_huff_count[2][18] + 1);          \
                packed_code_sizes[num_packed_code_sizes++] = 18;                           \
                packed_code_sizes[num_packed_code_sizes++] = (mz_uint8)(rle_z_count - 11); \
            }                                                                              \
            rle_z_count = 0;                                                               \
        }                                                                                  \
    }

static mz_uint8 s_tdefl_packed_code_size_syms_swizzle[] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

static void tdefl_start_dynamic_block(tdefl_compressor *d)
{
    int num_lit_codes, num_dist_codes, num_bit_lengths;
    mz_uint i, total_code_sizes_to_pack, num_packed_code_sizes, rle_z_count, rle_repeat_count, packed_code_sizes_index;
    mz_uint8 code_sizes_to_pack[TDEFL_MAX_HUFF_SYMBOLS_0 + TDEFL_MAX_HUFF_SYMBOLS_1], packed_code_sizes[TDEFL_MAX_HUFF_SYMBOLS_0 + TDEFL_MAX_HUFF_SYMBOLS_1], prev_code_size = 0xFF;

    d->m_huff_count[0][256] = 1;

    tdefl_optimize_huffman_table(d, 0, TDEFL_MAX_HUFF_SYMBOLS_0, 15, MZ_FALSE);
    tdefl_optimize_huffman_table(d, 1, TDEFL_MAX_HUFF_SYMBOLS_1, 15, MZ_FALSE);

    for (num_lit_codes = 286; num_lit_codes > 257; num_lit_codes--)
        if (d->m_huff_code_sizes[0][num_lit_codes - 1])
            break;
    for (num_dist_codes = 30; num_dist_codes > 1; num_dist_codes--)
        if (d->m_huff_code_sizes[1][num_dist_codes - 1])
            break;

    memcpy(code_sizes_to_pack, &d->m_huff_code_sizes[0][0], num_lit_codes);
    memcpy(code_sizes_to_pack + num_lit_codes, &d->m_huff_code_sizes[1][0], num_dist_codes);
    total_code_sizes_to_pack = num_lit_codes + num_dist_codes;
    num_packed_code_sizes = 0;
    rle_z_count = 0;
    rle_repeat_count = 0;

    memset(&d->m_huff_count[2][0], 0, sizeof(d->m_huff_count[2][0]) * TDEFL_MAX_HUFF_SYMBOLS_2);
    for (i = 0; i < total_code_sizes_to_pack; i++)
    {
        mz_uint8 code_size = code_sizes_to_pack[i];
        if (!code_size)
        {
            TDEFL_RLE_PREV_CODE_SIZE();
            if (++rle_z_count == 138)
            {
                TDEFL_RLE_ZERO_CODE_SIZE();
            }
        }
        else
        {
            TDEFL_RLE_ZERO_CODE_SIZE();
            if (code_size != prev_code_size)
            {
                TDEFL_RLE_PREV_CODE_SIZE();
                d->m_huff_count[2][code_size] = (mz_uint16)(d->m_huff_count[2][code_size] + 1);
                packed_code_sizes[num_packed_code_sizes++] = code_size;
            }
            else if (++rle_repeat_count == 6)
            {
                TDEFL_RLE_PREV_CODE_SIZE();
            }
        }
        prev_code_size = code_size;
    }
    if (rle_repeat_count)
    {
        TDEFL_RLE_PREV_CODE_SIZE();
    }
    else
    {
        TDEFL_RLE_ZERO_CODE_SIZE();
    }

    tdefl_optimize_huffman_table(d, 2, TDEFL_MAX_HUFF_SYMBOLS_2, 7, MZ_FALSE);

    TDEFL_PUT_BITS(2, 2);

    TDEFL_PUT_BITS(num_lit_codes - 257, 5);
    TDEFL_PUT_BITS(num_dist_codes - 1, 5);

    for (num_bit_lengths = 18; num_bit_lengths >= 0; num_bit_lengths--)
        if (d->m_huff_code_sizes[2][s_tdefl_packed_code_size_syms_swizzle[num_bit_lengths]])
            break;
    num_bit_lengths = MZ_MAX(4, (num_bit_lengths + 1));
    TDEFL_PUT_BITS(num_bit_lengths - 4, 4);
    for (i = 0; (int)i < num_bit_lengths; i++)
        TDEFL_PUT_BITS(d->m_huff_code_sizes[2][s_tdefl_packed_code_size_syms_swizzle[i]], 3);

    for (packed_code_sizes_index = 0; packed_code_sizes_index < num_packed_code_sizes;)
    {
        mz_uint code = packed_code_sizes[packed_code_sizes_index++];
        MZ_ASSERT(code < TDEFL_MAX_HUFF_SYMBOLS_2);
        TDEFL_PUT_BITS(d->m_huff_codes[2][code], d->m_huff_code_sizes[2][code]);
        if (code >= 16)
            TDEFL_PUT_BITS(packed_code_sizes[packed_code_sizes_index++], "\02\03\07"[code - 16]);
    }
}

static void tdefl_start_static_block(tdefl_compressor *d)
{
    mz_uint i;
    mz_uint8 *p = &d->m_huff_code_sizes[0][0];

    for (i = 0; i <= 143; ++i)
        *p++ = 8;
    for (; i <= 255; ++i)
        *p++ = 9;
    for (; i <= 279; ++i)
        *p++ = 7;
    for (; i <= 287; ++i)
        *p++ = 8;

    memset(d->m_huff_code_sizes[1], 5, 32);

    tdefl_optimize_huffman_table(d, 0, 288, 15, MZ_TRUE);
    tdefl_optimize_huffman_table(d, 1, 32, 15, MZ_TRUE);

    TDEFL_PUT_BITS(1, 2);
}

static const mz_uint mz_bitmasks[17] = { 0x0000, 0x0001, 0x0003, 0x0007, 0x000F, 0x001F, 0x003F, 0x007F, 0x00FF, 0x01FF, 0x03FF, 0x07FF, 0x0FFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF };

#if MINIZ_USE_UNALIGNED_LOADS_AND_STORES && MINIZ_LITTLE_ENDIAN && MINIZ_HAS_64BIT_REGISTERS
static mz_bool tdefl_compress_lz_codes(tdefl_compressor *d)
{
    mz_uint flags;
    mz_uint8 *pLZ_codes;
    mz_uint8 *pOutput_buf = d->m_pOutput_buf;
    mz_uint8 *pLZ_code_buf_end = d->m_pLZ_code_buf;
    mz_uint64 bit_buffer = d->m_bit_buffer;
    mz_uint bits_in = d->m_bits_in;

#define TDEFL_PUT_BITS_FAST(b, l)                    \
    {                                                \
        bit_buffer |= (((mz_uint64)(b)) << bits_in); \
        bits_in += (l);                              \
    }

    flags = 1;
    for (pLZ_codes = d->m_lz_code_buf; pLZ_codes < pLZ_code_buf_end; flags >>= 1)
    {
        if (flags == 1)
            flags = *pLZ_codes++ | 0x100;

        if (flags & 1)
        {
            mz_uint s0, s1, n0, n1, sym, num_extra_bits;
            mz_uint match_len = pLZ_codes[0], match_dist = *(const mz_uint16 *)(pLZ_codes + 1);
            pLZ_codes += 3;

            MZ_ASSERT(d->m_huff_code_sizes[0][s_tdefl_len_sym[match_len]]);
            TDEFL_PUT_BITS_FAST(d->m_huff_codes[0][s_tdefl_len_sym[match_len]], d->m_huff_code_sizes[0][s_tdefl_len_sym[match_len]]);
            TDEFL_PUT_BITS_FAST(match_len & mz_bitmasks[s_tdefl_len_extra[match_len]], s_tdefl_len_extra[match_len]);

            // This sequence coaxes MSVC into using cmov's vs. jmp's.
            s0 = s_tdefl_small_dist_sym[match_dist & 511];
            n0 = s_tdefl_small_dist_extra[match_dist & 511];
            s1 = s_tdefl_large_dist_sym[match_dist >> 8];
            n1 = s_tdefl_large_dist_extra[match_dist >> 8];
            sym = (match_dist < 512) ? s0 : s1;
            num_extra_bits = (match_dist < 512) ? n0 : n1;

            MZ_ASSERT(d->m_huff_code_sizes[1][sym]);
            TDEFL_PUT_BITS_FAST(d->m_huff_codes[1][sym], d->m_huff_code_sizes[1][sym]);
            TDEFL_PUT_BITS_FAST(match_dist & mz_bitmasks[num_extra_bits], num_extra_bits);
        }
        else
        {
            mz_uint lit = *pLZ_codes++;
            MZ_ASSERT(d->m_huff_code_sizes[0][lit]);
            TDEFL_PUT_BITS_FAST(d->m_huff_codes[0][lit], d->m_huff_code_sizes[0][lit]);

            if (((flags & 2) == 0) && (pLZ_codes < pLZ_code_buf_end))
            {
                flags >>= 1;
                lit = *pLZ_codes++;
                MZ_ASSERT(d->m_huff_code_sizes[0][lit]);
                TDEFL_PUT_BITS_FAST(d->m_huff_codes[0][lit], d->m_huff_code_sizes[0][lit]);

                if (((flags & 2) == 0) && (pLZ_codes < pLZ_code_buf_end))
                {
                    flags >>= 1;
                    lit = *pLZ_codes++;
                    MZ_ASSERT(d->m_huff_code_sizes[0][lit]);
                    TDEFL_PUT_BITS_FAST(d->m_huff_codes[0][lit], d->m_huff_code_sizes[0][lit]);
                }
            }
        }

        if (pOutput_buf >= d->m_pOutput_buf_end)
            return MZ_FALSE;

        *(mz_uint64 *)pOutput_buf = bit_buffer;
        pOutput_buf += (bits_in >> 3);
        bit_buffer >>= (bits_in & ~7);
        bits_in &= 7;
    }

#undef TDEFL_PUT_BITS_FAST

    d->m_pOutput_buf = pOutput_buf;
    d->m_bits_in = 0;
    d->m_bit_buffer = 0;

    while (bits_in)
    {
        mz_uint32 n = MZ_MIN(bits_in, 16);
        TDEFL_PUT_BITS((mz_uint)bit_buffer & mz_bitmasks[n], n);
        bit_buffer >>= n;
        bits_in -= n;
    }

    TDEFL_PUT_BITS(d->m_huff_codes[0][256], d->m_huff_code_sizes[0][256]);

    return (d->m_pOutput_buf < d->m_pOutput_buf_end);
}
#else
static mz_bool tdefl_compress_lz_codes(tdefl_compressor *d)
{
    mz_uint flags;
    mz_uint8 *pLZ_codes;

    flags = 1;
    for (pLZ_codes = d->m_lz_code_buf; pLZ_codes < d->m_pLZ_code_buf; flags >>= 1)
    {
        if (flags == 1)
            flags = *pLZ_codes++ | 0x100;
        if (flags & 1)
        {
            mz_uint sym, num_extra_bits;
            mz_uint match_len = pLZ_codes[0], match_dist = (pLZ_codes[1] | (pLZ_codes[2] << 8));
            pLZ_codes += 3;

            MZ_ASSERT(d->m_huff_code_sizes[0][s_tdefl_len_sym[match_len]]);
            TDEFL_PUT_BITS(d->m_huff_codes[0][s_tdefl_len_sym[match_len]], d->m_huff_code_sizes[0][s_tdefl_len_sym[match_len]]);
            TDEFL_PUT_BITS(match_len & mz_bitmasks[s_tdefl_len_extra[match_len]], s_tdefl_len_extra[match_len]);

            if (match_dist < 512)
            {
                sym = s_tdefl_small_dist_sym[match_dist];
                num_extra_bits = s_tdefl_small_dist_extra[match_dist];
            }
            else
            {
                sym = s_tdefl_large_dist_sym[match_dist >> 8];
                num_extra_bits = s_tdefl_large_dist_extra[match_dist >> 8];
            }
            MZ_ASSERT(d->m_huff_code_sizes[1][sym]);
            TDEFL_PUT_BITS(d->m_huff_codes[1][sym], d->m_huff_code_sizes[1][sym]);
            TDEFL_PUT_BITS(match_dist & mz_bitmasks[num_extra_bits], num_extra_bits);
        }
        else
        {
            mz_uint lit = *pLZ_codes++;
            MZ_ASSERT(d->m_huff_code_sizes[0][lit]);
            TDEFL_PUT_BITS(d->m_huff_codes[0][lit], d->m_huff_code_sizes[0][lit]);
        }
    }

    TDEFL_PUT_BITS(d->m_huff_codes[0][256], d->m_huff_code_sizes[0][256]);

    return (d->m_pOutput_buf < d->m_pOutput_buf_end);
}
#endif // MINIZ_USE_UNALIGNED_LOADS_AND_STORES && MINIZ_LITTLE_ENDIAN && MINIZ_HAS_64BIT_REGISTERS

static mz_bool tdefl_compress_block(tdefl_compressor *d, mz_bool static_block)
{
    if (static_block)
        tdefl_start_static_block(d);
    else
        tdefl_start_dynamic_block(d);
    return tdefl_compress_lz_codes(d);
}

static int tdefl_flush_block(tdefl_compressor *d, int flush)
{
    mz_uint saved_bit_buf, saved_bits_in;
    mz_uint8 *pSaved_output_buf;
    mz_bool comp_block_succeeded = MZ_FALSE;
    int n, use_raw_block = ((d->m_flags & TDEFL_FORCE_ALL_RAW_BLOCKS) != 0) && (d->m_lookahead_pos - d->m_lz_code_buf_dict_pos) <= d->m_dict_size;
    mz_uint8 *pOutput_buf_start = ((*d->m_pOut_buf_size - d->m_out_buf_ofs) >= TDEFL_OUT_BUF_SIZE) ? ((mz_uint8 *)d->m_pOut_buf + d->m_out_buf_ofs) : d->m_output_buf;

    d->m_pOutput_buf = pOutput_buf_start;
    d->m_pOutput_buf_end = d->m_pOutput_buf + TDEFL_OUT_BUF_SIZE - 16;

    MZ_ASSERT(!d->m_output_flush_remaining);
    d->m_output_flush_ofs = 0;
    d->m_output_flush_remaining = 0;

    *d->m_pLZ_flags = (mz_uint8)(*d->m_pLZ_flags >> d->m_num_flags_left);
    d->m_pLZ_code_buf -= (d->m_num_flags_left == 8);

    if ((d->m_flags & TDEFL_WRITE_ZLIB_HEADER) && (!d->m_block_index))
    {
        TDEFL_PUT_BITS(0x78, 8);
        TDEFL_PUT_BITS(0x01, 8);
    }

    TDEFL_PUT_BITS(flush == TDEFL_FINISH, 1);

    pSaved_output_buf = d->m_pOutput_buf;
    saved_bit_buf = d->m_bit_buffer;
    saved_bits_in = d->m_bits_in;

    if (!use_raw_block)
        comp_block_succeeded = tdefl_compress_block(d, (d->m_flags & TDEFL_FORCE_ALL_STATIC_BLOCKS) || (d->m_total_lz_bytes < 48));

    // If the block gets expanded, forget the current contents of the output buffer and send a raw block instead.
    if (((use_raw_block) || ((d->m_total_lz_bytes) && ((d->m_pOutput_buf - pSaved_output_buf + 1U) >= d->m_total_lz_bytes))) &&
        ((d->m_lookahead_pos - d->m_lz_code_buf_dict_pos) <= d->m_dict_size))
    {
        mz_uint i;
        d->m_pOutput_buf = pSaved_output_buf;
        d->m_bit_buffer = saved_bit_buf, d->m_bits_in = saved_bits_in;
        TDEFL_PUT_BITS(0, 2);
        if (d->m_bits_in)
        {
            TDEFL_PUT_BITS(0, 8 - d->m_bits_in);
        }
        for (i = 2; i; --i, d->m_total_lz_bytes ^= 0xFFFF)
        {
            TDEFL_PUT_BITS(d->m_total_lz_bytes & 0xFFFF, 16);
        }
        for (i = 0; i < d->m_total_lz_bytes; ++i)
        {
            TDEFL_PUT_BITS(d->m_dict[(d->m_lz_code_buf_dict_pos + i) & TDEFL_LZ_DICT_SIZE_MASK], 8);
        }
    }
    // Check for the extremely unlikely (if not impossible) case of the compressed block not fitting into the output buffer when using dynamic codes.
    else if (!comp_block_succeeded)
    {
        d->m_pOutput_buf = pSaved_output_buf;
        d->m_bit_buffer = saved_bit_buf, d->m_bits_in = saved_bits_in;
        tdefl_compress_block(d, MZ_TRUE);
    }

    if (flush)
    {
        if (flush == TDEFL_FINISH)
        {
            if (d->m_bits_in)
            {
                TDEFL_PUT_BITS(0, 8 - d->m_bits_in);
            }
            if (d->m_flags & TDEFL_WRITE_ZLIB_HEADER)
            {
                mz_uint i, a = d->m_adler32;
                for (i = 0; i < 4; i++)
                {
                    TDEFL_PUT_BITS((a >> 24) & 0xFF, 8);
                    a <<= 8;
                }
            }
        }
        else
        {
            mz_uint i, z = 0;
            TDEFL_PUT_BITS(0, 3);
            if (d->m_bits_in)
            {
                TDEFL_PUT_BITS(0, 8 - d->m_bits_in);
            }
            for (i = 2; i; --i, z ^= 0xFFFF)
            {
                TDEFL_PUT_BITS(z & 0xFFFF, 16);
            }
        }
    }

    MZ_ASSERT(d->m_pOutput_buf < d->m_pOutput_buf_end);

    memset(&d->m_huff_count[0][0], 0, sizeof(d->m_huff_count[0][0]) * TDEFL_MAX_HUFF_SYMBOLS_0);
    memset(&d->m_huff_count[1][0], 0, sizeof(d->m_huff_count[1][0]) * TDEFL_MAX_HUFF_SYMBOLS_1);

    d->m_pLZ_code_buf = d->m_lz_code_buf + 1;
    d->m_pLZ_flags = d->m_lz_code_buf;
    d->m_num_flags_left = 8;
    d->m_lz_code_buf_dict_pos += d->m_total_lz_bytes;
    d->m_total_lz_bytes = 0;
    d->m_block_index++;

    if ((n = (int)(d->m_pOutput_buf - pOutput_buf_start)) != 0)
    {
        if (pOutput_buf_start == d->m_output_buf)
        {
            int bytes_to_copy = (int)MZ_MIN((size_t)n, (size_t)(*d->m_pOut_buf_size - d->m_out_buf_ofs));
            memcpy((mz_uint8 *)d->m_pOut_buf + d->m_out_buf_ofs, d->m_output_buf, bytes_to_copy);
            d->m_out_buf_ofs += bytes_to_copy;
            if ((n -= bytes_to_copy) != 0)
            {
                d->m_output_flush_ofs = bytes_to_copy;
                d->m_output_flush_remaining = n;
            }
        }
        else
        {
            d->m_out_buf_ofs += n;
        }
    }

    return d->m_output_flush_remaining;
}

#if MINIZ_USE_UNALIGNED_LOADS_AND_STORES
static MZ_FORCEINLINE mz_uint16 TDEFL_READ_UNALIGNED_WORD(const void* p)
{
    return *(const mz_uint16 *)p;
}

static MZ_FORCEINLINE mz_uint32 TDEFL_READ_UNALIGNED_DWORD(const void* p)
{
    return *(const mz_uint32 *)p;
}

static MZ_FORCEINLINE void tdefl_find_match(tdefl_compressor *d, mz_uint lookahead_pos, mz_uint max_dist, mz_uint max_match_len, mz_uint *pMatch_dist, mz_uint *pMatch_len)
{
    mz_uint dist, pos = lookahead_pos & TDEFL_LZ_DICT_SIZE_MASK, match_len = *pMatch_len, probe_pos = pos, next_probe_pos, probe_len;
    mz_uint num_probes_left = d->m_max_probes[match_len >= 32];
    const mz_uint16 *s = (const mz_uint16 *)(d->m_dict + pos), *p, *q;
    mz_uint16 c01 = TDEFL_READ_UNALIGNED_WORD(&d->m_dict[pos + match_len - 1]), s01 = TDEFL_READ_UNALIGNED_WORD(s);
    MZ_ASSERT(max_match_len <= TDEFL_MAX_MATCH_LEN);
    if (max_match_len <= match_len)
        return;
    for (;;)
    {
        for (;;)
        {
            if (--num_probes_left == 0)
                return;
#define TDEFL_PROBE                                                                             \
    next_probe_pos = d->m_next[probe_pos];                                                      \
    if ((!next_probe_pos) || ((dist = (mz_uint16)(lookahead_pos - next_probe_pos)) > max_dist)) \
        return;                                                                                 \
    probe_pos = next_probe_pos & TDEFL_LZ_DICT_SIZE_MASK;                                       \
    if (TDEFL_READ_UNALIGNED_WORD(&d->m_dict[probe_pos + match_len - 1]) == c01)                \
        break;
            TDEFL_PROBE;
            TDEFL_PROBE;
            TDEFL_PROBE;
        }
        if (!dist)
            break;
        q = (const mz_uint16 *)(d->m_dict + probe_pos);
        if (TDEFL_READ_UNALIGNED_WORD(q) != s01)
            continue;
        p = s;
        probe_len = 32;
        do
        {
        } while ((TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) && (TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) &&
                 (TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) && (TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) && (--probe_len > 0));
        if (!probe_len)
        {
            *pMatch_dist = dist;
            *pMatch_len = MZ_MIN(max_match_len, (mz_uint)TDEFL_MAX_MATCH_LEN);
            break;
        }
        else if ((probe_len = ((mz_uint)(p - s) * 2) + (mz_uint)(*(const mz_uint8 *)p == *(const mz_uint8 *)q)) > match_len)
        {
            *pMatch_dist = dist;
            if ((*pMatch_len = match_len = MZ_MIN(max_match_len, probe_len)) == max_match_len)
                break;
            c01 = TDEFL_READ_UNALIGNED_WORD(&d->m_dict[pos + match_len - 1]);
        }
    }
}
#else
static MZ_FORCEINLINE void tdefl_find_match(tdefl_compressor *d, mz_uint lookahead_pos, mz_uint max_dist, mz_uint max_match_len, mz_uint *pMatch_dist, mz_uint *pMatch_len)
{
    mz_uint dist, pos = lookahead_pos & TDEFL_LZ_DICT_SIZE_MASK, match_len = *pMatch_len, probe_pos = pos, next_probe_pos, probe_len;
    mz_uint num_probes_left = d->m_max_probes[match_len >= 32];
    const mz_uint8 *s = d->m_dict + pos, *p, *q;
    mz_uint8 c0 = d->m_dict[pos + match_len], c1 = d->m_dict[pos + match_len - 1];
    MZ_ASSERT(max_match_len <= TDEFL_MAX_MATCH_LEN);
    if (max_match_len <= match_len)
        return;
    for (;;)
    {
        for (;;)
        {
            if (--num_probes_left == 0)
                return;
#define TDEFL_PROBE                                                                               \
    next_probe_pos = d->m_next[probe_pos];                                                        \
    if ((!next_probe_pos) || ((dist = (mz_uint16)(lookahead_pos - next_probe_pos)) > max_dist))   \
        return;                                                                                   \
    probe_pos = next_probe_pos & TDEFL_LZ_DICT_SIZE_MASK;                                         \
    if ((d->m_dict[probe_pos + match_len] == c0) && (d->m_dict[probe_pos + match_len - 1] == c1)) \
        break;
            TDEFL_PROBE;
            TDEFL_PROBE;
            TDEFL_PROBE;
        }
        if (!dist)
            break;
        p = s;
        q = d->m_dict + probe_pos;
        for (probe_len = 0; probe_len < max_match_len; probe_len++)
            if (*p++ != *q++)
                break;
        if (probe_len > match_len)
        {
            *pMatch_dist = dist;
            if ((*pMatch_len = match_len = probe_len) == max_match_len)
                return;
            c0 = d->m_dict[pos + match_len];
            c1 = d->m_dict[pos + match_len - 1];
        }
    }
}
#endif // #if MINIZ_USE_UNALIGNED_LOADS_AND_STORES

#if MINIZ_USE_UNALIGNED_LOADS_AND_STORES && MINIZ_LITTLE_ENDIAN
static mz_bool tdefl_compress_fast(tdefl_compressor *d)
{
    // Faster, minimally featured LZRW1-style match+parse loop with better register utilization. Intended for applications where raw throughput is valued more highly than ratio.
    mz_uint lookahead_pos = d->m_lookahead_pos, lookahead_size = d->m_lookahead_size, dict_size = d->m_dict_size, total_lz_bytes = d->m_total_lz_bytes, num_flags_left = d->m_num_flags_left;
    mz_uint8 *pLZ_code_buf = d->m_pLZ_code_buf, *pLZ_flags = d->m_pLZ_flags;
    mz_uint cur_pos = lookahead_pos & TDEFL_LZ_DICT_SIZE_MASK;

    while ((d->m_src_buf_left) || ((d->m_flush) && (lookahead_size)))
    {
        const mz_uint TDEFL_COMP_FAST_LOOKAHEAD_SIZE = 4096;
        mz_uint dst_pos = (lookahead_pos + lookahead_size) & TDEFL_LZ_DICT_SIZE_MASK;
        mz_uint num_bytes_to_process = (mz_uint)MZ_MIN(d->m_src_buf_left, TDEFL_COMP_FAST_LOOKAHEAD_SIZE - lookahead_size);
        d->m_src_buf_left -= num_bytes_to_process;
        lookahead_size += num_bytes_to_process;

        while (num_bytes_to_process)
        {
            mz_uint32 n = MZ_MIN(TDEFL_LZ_DICT_SIZE - dst_pos, num_bytes_to_process);
            memcpy(d->m_dict + dst_pos, d->m_pSrc, n);
            if (dst_pos < (TDEFL_MAX_MATCH_LEN - 1))
                memcpy(d->m_dict + TDEFL_LZ_DICT_SIZE + dst_pos, d->m_pSrc, MZ_MIN(n, (TDEFL_MAX_MATCH_LEN - 1) - dst_pos));
            d->m_pSrc += n;
            dst_pos = (dst_pos + n) & TDEFL_LZ_DICT_SIZE_MASK;
            num_bytes_to_process -= n;
        }

        dict_size = MZ_MIN(TDEFL_LZ_DICT_SIZE - lookahead_size, dict_size);
        if ((!d->m_flush) && (lookahead_size < TDEFL_COMP_FAST_LOOKAHEAD_SIZE))
            break;

        while (lookahead_size >= 4)
        {
            mz_uint cur_match_dist, cur_match_len = 1;
            mz_uint8 *pCur_dict = d->m_dict + cur_pos;
            mz_uint first_trigram = (*(const mz_uint32 *)pCur_dict) & 0xFFFFFF;
            mz_uint hash = (first_trigram ^ (first_trigram >> (24 - (TDEFL_LZ_HASH_BITS - 8)))) & TDEFL_LEVEL1_HASH_SIZE_MASK;
            mz_uint probe_pos = d->m_hash[hash];
            d->m_hash[hash] = (mz_uint16)lookahead_pos;

            if (((cur_match_dist = (mz_uint16)(lookahead_pos - probe_pos)) <= dict_size) && ((TDEFL_READ_UNALIGNED_DWORD(d->m_dict + (probe_pos &= TDEFL_LZ_DICT_SIZE_MASK)) & 0xFFFFFF) == first_trigram))
            {
                const mz_uint16 *p = (const mz_uint16 *)pCur_dict;
                const mz_uint16 *q = (const mz_uint16 *)(d->m_dict + probe_pos);
                mz_uint32 probe_len = 32;
                do
                {
                } while ((TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) && (TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) &&
                         (TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) && (TDEFL_READ_UNALIGNED_WORD(++p) == TDEFL_READ_UNALIGNED_WORD(++q)) && (--probe_len > 0));
                cur_match_len = ((mz_uint)(p - (const mz_uint16 *)pCur_dict) * 2) + (mz_uint)(*(const mz_uint8 *)p == *(const mz_uint8 *)q);
                if (!probe_len)
                    cur_match_len = cur_match_dist ? TDEFL_MAX_MATCH_LEN : 0;

                if ((cur_match_len < TDEFL_MIN_MATCH_LEN) || ((cur_match_len == TDEFL_MIN_MATCH_LEN) && (cur_match_dist >= 8U * 1024U)))
                {
                    cur_match_len = 1;
                    *pLZ_code_buf++ = (mz_uint8)first_trigram;
                    *pLZ_flags = (mz_uint8)(*pLZ_flags >> 1);
                    d->m_huff_count[0][(mz_uint8)first_trigram]++;
                }
                else
                {
                    mz_uint32 s0, s1;
                    cur_match_len = MZ_MIN(cur_match_len, lookahead_size);

                    MZ_ASSERT((cur_match_len >= TDEFL_MIN_MATCH_LEN) && (cur_match_dist >= 1) && (cur_match_dist <= TDEFL_LZ_DICT_SIZE));

                    cur_match_dist--;

                    pLZ_code_buf[0] = (mz_uint8)(cur_match_len - TDEFL_MIN_MATCH_LEN);
                    *(mz_uint16 *)(&pLZ_code_buf[1]) = (mz_uint16)cur_match_dist;
                    pLZ_code_buf += 3;
                    *pLZ_flags = (mz_uint8)((*pLZ_flags >> 1) | 0x80);

                    s0 = s_tdefl_small_dist_sym[cur_match_dist & 511];
                    s1 = s_tdefl_large_dist_sym[cur_match_dist >> 8];
                    d->m_huff_count[1][(cur_match_dist < 512) ? s0 : s1]++;

                    d->m_huff_count[0][s_tdefl_len_sym[cur_match_len - TDEFL_MIN_MATCH_LEN]]++;
                }
            }
            else
            {
                *pLZ_code_buf++ = (mz_uint8)first_trigram;
                *pLZ_flags = (mz_uint8)(*pLZ_flags >> 1);
                d->m_huff_count[0][(mz_uint8)first_trigram]++;
            }

            if (--num_flags_left == 0)
            {
                num_flags_left = 8;
                pLZ_flags = pLZ_code_buf++;
            }

            total_lz_bytes += cur_match_len;
            lookahead_pos += cur_match_len;
            dict_size = MZ_MIN(dict_size + cur_match_len, (mz_uint)TDEFL_LZ_DICT_SIZE);
            cur_pos = (cur_pos + cur_match_len) & TDEFL_LZ_DICT_SIZE_MASK;
            MZ_ASSERT(lookahead_size >= cur_match_len);
            lookahead_size -= cur_match_len;

            if (pLZ_code_buf > &d->m_lz_code_buf[TDEFL_LZ_CODE_BUF_SIZE - 8])
            {
                int n;
                d->m_lookahead_pos = lookahead_pos;
                d->m_lookahead_size = lookahead_size;
                d->m_dict_size = dict_size;
                d->m_total_lz_bytes = total_lz_bytes;
                d->m_pLZ_code_buf = pLZ_code_buf;
                d->m_pLZ_flags = pLZ_flags;
                d->m_num_flags_left = num_flags_left;
                if ((n = tdefl_flush_block(d, 0)) != 0)
                    return (n < 0) ? MZ_FALSE : MZ_TRUE;
                total_lz_bytes = d->m_total_lz_bytes;
                pLZ_code_buf = d->m_pLZ_code_buf;
                pLZ_flags = d->m_pLZ_flags;
                num_flags_left = d->m_num_flags_left;
            }
        }

        while (lookahead_size)
        {
            mz_uint8 lit = d->m_dict[cur_pos];

            total_lz_bytes++;
            *pLZ_code_buf++ = lit;
            *pLZ_flags = (mz_uint8)(*pLZ_flags >> 1);
            if (--num_flags_left == 0)
            {
                num_flags_left = 8;
                pLZ_flags = pLZ_code_buf++;
            }

            d->m_huff_count[0][lit]++;

            lookahead_pos++;
            dict_size = MZ_MIN(dict_size + 1, (mz_uint)TDEFL_LZ_DICT_SIZE);
            cur_pos = (cur_pos + 1) & TDEFL_LZ_DICT_SIZE_MASK;
            lookahead_size--;

            if (pLZ_code_buf > &d->m_lz_code_buf[TDEFL_LZ_CODE_BUF_SIZE - 8])
            {
                int n;
                d->m_lookahead_pos = lookahead_pos;
                d->m_lookahead_size = lookahead_size;
                d->m_dict_size = dict_size;
                d->m_total_lz_bytes = total_lz_bytes;
                d->m_pLZ_code_buf = pLZ_code_buf;
                d->m_pLZ_flags = pLZ_flags;
                d->m_num_flags_left = num_flags_left;
                if ((n = tdefl_flush_block(d, 0)) != 0)
                    return (n < 0) ? MZ_FALSE : MZ_TRUE;
                total_lz_bytes = d->m_total_lz_bytes;
                pLZ_code_buf = d->m_pLZ_code_buf;
                pLZ_flags = d->m_pLZ_flags;
                num_flags_left = d->m_num_flags_left;
            }
        }
    }

    d->m_lookahead_pos = lookahead_pos;
    d->m_lookahead_size = lookahead_size;
    d->m_dict_size = dict_size;
    d->m_total_lz_bytes = total_lz_bytes;
    d->m_pLZ_code_buf = pLZ_code_buf;
    d->m_pLZ_flags = pLZ_flags;
    d->m_num_flags_left = num_flags_left;
    return MZ_TRUE;
}
#endif // MINIZ_USE_UNALIGNED_LOADS_AND_STORES && MINIZ_LITTLE_ENDIAN

static MZ_FORCEINLINE void tdefl_record_literal(tdefl_compressor *d, mz_uint8 lit)
{
    d->m_total_lz_bytes++;
    *d->m_pLZ_code_buf++ = lit;
    *d->m_pLZ_flags = (mz_uint8)(*d->m_pLZ_flags >> 1);
    if (--d->m_num_flags_left == 0)
    {
        d->m_num_flags_left = 8;
        d->m_pLZ_flags = d->m_pLZ_code_buf++;
    }
    d->m_huff_count[0][lit]++;
}

static MZ_FORCEINLINE void tdefl_record_match(tdefl_compressor *d, mz_uint match_len, mz_uint match_dist)
{
    mz_uint32 s0, s1;

    MZ_ASSERT((match_len >= TDEFL_MIN_MATCH_LEN) && (match_dist >= 1) && (match_dist <= TDEFL_LZ_DICT_SIZE));

    d->m_total_lz_bytes += match_len;

    d->m_pLZ_code_buf[0] = (mz_uint8)(match_len - TDEFL_MIN_MATCH_LEN);

    match_dist -= 1;
    d->m_pLZ_code_buf[1] = (mz_uint8)(match_dist & 0xFF);
    d->m_pLZ_code_buf[2] = (mz_uint8)(match_dist >> 8);
    d->m_pLZ_code_buf += 3;

    *d->m_pLZ_flags = (mz_uint8)((*d->m_pLZ_flags >> 1) | 0x80);
    if (--d->m_num_flags_left == 0)
    {
        d->m_num_flags_left = 8;
        d->m_pLZ_flags = d->m_pLZ_code_buf++;
    }

    s0 = s_tdefl_small_dist_sym[match_dist & 511];
    s1 = s_tdefl_large_dist_sym[(match_dist >> 8) & 127];
    d->m_huff_count[1][(match_dist < 512) ? s0 : s1]++;

    if (match_len >= TDEFL_MIN_MATCH_LEN)
        d->m_huff_count[0][s_tdefl_len_sym[match_len - TDEFL_MIN_MATCH_LEN]]++;
}

static mz_bool tdefl_compress_normal(tdefl_compressor *d)
{
    const mz_uint8 *pSrc = d->m_pSrc;
    size_t src_buf_left = d->m_src_buf_left;
    tdefl_flush flush = d->m_flush;

    while ((src_buf_left) || ((flush) && (d->m_lookahead_size)))
    {
        mz_uint len_to_move, cur_match_dist, cur_match_len, cur_pos;
        // Update dictionary and hash chains. Keeps the lookahead size equal to TDEFL_MAX_MATCH_LEN.
        if ((d->m_lookahead_size + d->m_dict_size) >= (TDEFL_MIN_MATCH_LEN - 1))
        {
            mz_uint dst_pos = (d->m_lookahead_pos + d->m_lookahead_size) & TDEFL_LZ_DICT_SIZE_MASK, ins_pos = d->m_lookahead_pos + d->m_lookahead_size - 2;
            mz_uint hash = (d->m_dict[ins_pos & TDEFL_LZ_DICT_SIZE_MASK] << TDEFL_LZ_HASH_SHIFT) ^ d->m_dict[(ins_pos + 1) & TDEFL_LZ_DICT_SIZE_MASK];
            mz_uint num_bytes_to_process = (mz_uint)MZ_MIN(src_buf_left, TDEFL_MAX_MATCH_LEN - d->m_lookahead_size);
            const mz_uint8 *pSrc_end = pSrc + num_bytes_to_process;
            src_buf_left -= num_bytes_to_process;
            d->m_lookahead_size += num_bytes_to_process;
            while (pSrc != pSrc_end)
            {
                mz_uint8 c = *pSrc++;
                d->m_dict[dst_pos] = c;
                if (dst_pos < (TDEFL_MAX_MATCH_LEN - 1))
                    d->m_dict[TDEFL_LZ_DICT_SIZE + dst_pos] = c;
                hash = ((hash << TDEFL_LZ_HASH_SHIFT) ^ c) & (TDEFL_LZ_HASH_SIZE - 1);
                d->m_next[ins_pos & TDEFL_LZ_DICT_SIZE_MASK] = d->m_hash[hash];
                d->m_hash[hash] = (mz_uint16)(ins_pos);
                dst_pos = (dst_pos + 1) & TDEFL_LZ_DICT_SIZE_MASK;
                ins_pos++;
            }
        }
        else
        {
            while ((src_buf_left) && (d->m_lookahead_size < TDEFL_MAX_MATCH_LEN))
            {
                mz_uint8 c = *pSrc++;
                mz_uint dst_pos = (d->m_lookahead_pos + d->m_lookahead_size) & TDEFL_LZ_DICT_SIZE_MASK;
                src_buf_left--;
                d->m_dict[dst_pos] = c;
                if (dst_pos < (TDEFL_MAX_MATCH_LEN - 1))
                    d->m_dict[TDEFL_LZ_DICT_SIZE + dst_pos] = c;
                if ((++d->m_lookahead_size + d->m_dict_size) >= TDEFL_MIN_MATCH_LEN)
                {
                    mz_uint ins_pos = d->m_lookahead_pos + (d->m_lookahead_size - 1) - 2;
                    mz_uint hash = ((d->m_dict[ins_pos & TDEFL_LZ_DICT_SIZE_MASK] << (TDEFL_LZ_HASH_SHIFT * 2)) ^ (d->m_dict[(ins_pos + 1) & TDEFL_LZ_DICT_SIZE_MASK] << TDEFL_LZ_HASH_SHIFT) ^ c) & (TDEFL_LZ_HASH_SIZE - 1);
                    d->m_next[ins_pos & TDEFL_LZ_DICT_SIZE_MASK] = d->m_hash[hash];
                    d->m_hash[hash] = (mz_uint16)(ins_pos);
                }
            }
        }
        d->m_dict_size = MZ_MIN(TDEFL_LZ_DICT_SIZE - d->m_lookahead_size, d->m_dict_size);
        if ((!flush) && (d->m_lookahead_size < TDEFL_MAX_MATCH_LEN))
            break;

        // Simple lazy/greedy parsing state machine.
        len_to_move = 1;
        cur_match_dist = 0;
        cur_match_len = d->m_saved_match_len ? d->m_saved_match_len : (TDEFL_MIN_MATCH_LEN - 1);
        cur_pos = d->m_lookahead_pos & TDEFL_LZ_DICT_SIZE_MASK;
        if (d->m_flags & (TDEFL_RLE_MATCHES | TDEFL_FORCE_ALL_RAW_BLOCKS))
        {
            if ((d->m_dict_size) && (!(d->m_flags & TDEFL_FORCE_ALL_RAW_BLOCKS)))
            {
                mz_uint8 c = d->m_dict[(cur_pos - 1) & TDEFL_LZ_DICT_SIZE_MASK];
                cur_match_len = 0;
                while (cur_match_len < d->m_lookahead_size)
                {
                    if (d->m_dict[cur_pos + cur_match_len] != c)
                        break;
                    cur_match_len++;
                }
                if (cur_match_len < TDEFL_MIN_MATCH_LEN)
                    cur_match_len = 0;
                else
                    cur_match_dist = 1;
            }
        }
        else
        {
            tdefl_find_match(d, d->m_lookahead_pos, d->m_dict_size, d->m_lookahead_size, &cur_match_dist, &cur_match_len);
        }
        if (((cur_match_len == TDEFL_MIN_MATCH_LEN) && (cur_match_dist >= 8U * 1024U)) || (cur_pos == cur_match_dist) || ((d->m_flags & TDEFL_FILTER_MATCHES) && (cur_match_len <= 5)))
        {
            cur_match_dist = cur_match_len = 0;
        }
        if (d->m_saved_match_len)
        {
            if (cur_match_len > d->m_saved_match_len)
            {
                tdefl_record_literal(d, (mz_uint8)d->m_saved_lit);
                if (cur_match_len >= 128)
                {
                    tdefl_record_match(d, cur_match_len, cur_match_dist);
                    d->m_saved_match_len = 0;
                    len_to_move = cur_match_len;
                }
                else
                {
                    d->m_saved_lit = d->m_dict[cur_pos];
                    d->m_saved_match_dist = cur_match_dist;
                    d->m_saved_match_len = cur_match_len;
                }
            }
            else
            {
                tdefl_record_match(d, d->m_saved_match_len, d->m_saved_match_dist);
                len_to_move = d->m_saved_match_len - 1;
                d->m_saved_match_len = 0;
            }
        }
        else if (!cur_match_dist)
            tdefl_record_literal(d, d->m_dict[MZ_MIN(cur_pos, sizeof(d->m_dict) - 1)]);
        else if ((d->m_greedy_parsing) || (d->m_flags & TDEFL_RLE_MATCHES) || (cur_match_len >= 128))
        {
            tdefl_record_match(d, cur_match_len, cur_match_dist);
            len_to_move = cur_match_len;
        }
        else
        {
            d->m_saved_lit = d->m_dict[MZ_MIN(cur_pos, sizeof(d->m_dict) - 1)];
            d->m_saved_match_dist = cur_match_dist;
            d->m_saved_match_len = cur_match_len;
        }
        // Move the lookahead forward by len_to_move bytes.
        d->m_lookahead_pos += len_to_move;
        MZ_ASSERT(d->m_lookahead_size >= len_to_move);
        d->m_lookahead_size -= len_to_move;
        d->m_dict_size = MZ_MIN(d->m_dict_size + len_to_move, (mz_uint)TDEFL_LZ_DICT_SIZE);
        // Check if it's time to flush the current LZ codes to the internal output buffer.
        if ((d->m_pLZ_code_buf > &d->m_lz_code_buf[TDEFL_LZ_CODE_BUF_SIZE - 8]) ||
            ((d->m_total_lz_bytes > 31 * 1024) && (((((mz_uint)(d->m_pLZ_code_buf - d->m_lz_code_buf) * 115) >> 7) >= d->m_total_lz_bytes) || (d->m_flags & TDEFL_FORCE_ALL_RAW_BLOCKS))))
        {
            int n;
            d->m_pSrc = pSrc;
            d->m_src_buf_left = src_buf_left;
            if ((n = tdefl_flush_block(d, 0)) != 0)
                return (n < 0) ? MZ_FALSE : MZ_TRUE;
        }
    }

    d->m_pSrc = pSrc;
    d->m_src_buf_left = src_buf_left;
    return MZ_TRUE;
}

static tdefl_status tdefl_flush_output_buffer(tdefl_compressor *d)
{
    if (d->m_pIn_buf_size)
    {
        *d->m_pIn_buf_size = d->m_pSrc - (const mz_uint8 *)d->m_pIn_buf;
    }

    if (d->m_pOut_buf_size)
    {
        size_t n = MZ_MIN(*d->m_pOut_buf_size - d->m_out_buf_ofs, d->m_output_flush_remaining);
        memcpy((mz_uint8 *)d->m_pOut_buf + d->m_out_buf_ofs, d->m_output_buf + d->m_output_flush_ofs, n);
        d->m_output_flush_ofs += (mz_uint)n;
        d->m_output_flush_remaining -= (mz_uint)n;
        d->m_out_buf_ofs += n;

        *d->m_pOut_buf_size = d->m_out_buf_ofs;
    }

    return (d->m_finished && !d->m_output_flush_remaining) ? TDEFL_STATUS_DONE : TDEFL_STATUS_OKAY;
}

tdefl_status tdefl_compress(tdefl_compressor *d, const void *pIn_buf, size_t *pIn_buf_size, void *pOut_buf, size_t *pOut_buf_size, tdefl_flush flush)
{
    if (!d)
    {
        if (pIn_buf_size)
            *pIn_buf_size = 0;
        if (pOut_buf_size)
            *pOut_buf_size = 0;
        return TDEFL_STATUS_BAD_PARAM;
    }

    d->m_pIn_buf = pIn_buf;
    d->m_pIn_buf_size = pIn_buf_size;
    d->m_pOut_buf = pOut_buf;
    d->m_pOut_buf_size = pOut_buf_size;
    d->m_pSrc = (const mz_uint8 *)(pIn_buf);
    d->m_src_buf_left = pIn_buf_size ? *pIn_buf_size : 0;
    d->m_out_buf_ofs = 0;
    d->m_flush = flush;

    if (((0) == ((pOut_buf != NULL) || (pOut_buf_size != NULL))) || (d->m_prev_return_status != TDEFL_STATUS_OKAY) ||
        (d->m_wants_to_finish && (flush != TDEFL_FINISH)) || (pIn_buf_size && *pIn_buf_size && !pIn_buf) || (pOut_buf_size && *pOut_buf_size && !pOut_buf))
    {
        if (pIn_buf_size)
            *pIn_buf_size = 0;
        if (pOut_buf_size)
            *pOut_buf_size = 0;
        return (d->m_prev_return_status = TDEFL_STATUS_BAD_PARAM);
    }
    d->m_wants_to_finish |= (flush == TDEFL_FINISH);

    if ((d->m_output_flush_remaining) || (d->m_finished))
        return (d->m_prev_return_status = tdefl_flush_output_buffer(d));

#if MINIZ_USE_UNALIGNED_LOADS_AND_STORES && MINIZ_LITTLE_ENDIAN
    if (((d->m_flags & TDEFL_MAX_PROBES_MASK) == 1) &&
        ((d->m_flags & TDEFL_GREEDY_PARSING_FLAG) != 0) &&
        ((d->m_flags & (TDEFL_FILTER_MATCHES | TDEFL_FORCE_ALL_RAW_BLOCKS | TDEFL_RLE_MATCHES)) == 0))
    {
        if (!tdefl_compress_fast(d))
            return d->m_prev_return_status;
    }
    else
#endif // #if MINIZ_USE_UNALIGNED_LOADS_AND_STORES && MINIZ_LITTLE_ENDIAN
    {
        if (!tdefl_compress_normal(d))
            return d->m_prev_return_status;
    }

    if ((d->m_flags & (TDEFL_WRITE_ZLIB_HEADER | TDEFL_COMPUTE_ADLER32)) && (pIn_buf))
        d->m_adler32 = (mz_uint32)mz_adler32(d->m_adler32, (const mz_uint8 *)pIn_buf, d->m_pSrc - (const mz_uint8 *)pIn_buf);

    if ((flush) && (!d->m_lookahead_size) && (!d->m_src_buf_left) && (!d->m_output_flush_remaining))
    {
        if (tdefl_flush_block(d, flush) < 0)
            return d->m_prev_return_status;
        d->m_finished = (flush == TDEFL_FINISH);
        if (flush == TDEFL_FULL_FLUSH)
        {
            MZ_CLEAR_OBJ(d->m_hash);
            MZ_CLEAR_OBJ(d->m_next);
            d->m_dict_size = 0;
        }
    }

    return (d->m_prev_return_status = tdefl_flush_output_buffer(d));
}

tdefl_status tdefl_init(tdefl_compressor *d, int flags)
{
    d->m_flags = (mz_uint)(flags);
    d->m_max_probes[0] = 1 + ((flags & 0xFFF) + 2) / 3;
    d->m_greedy_parsing = (flags & TDEFL_GREEDY_PARSING_FLAG) != 0;
    d->m_max_probes[1] = 1 + (((flags & 0xFFF) >> 2) + 2) / 3;
    if (!(flags & TDEFL_NONDETERMINISTIC_PARSING_FLAG))
        MZ_CLEAR_OBJ(d->m_hash);
    d->m_lookahead_pos = d->m_lookahead_size = d->m_dict_size = d->m_total_lz_bytes = d->m_lz_code_buf_dict_pos = d->m_bits_in = 0;
    d->m_output_flush_ofs = d->m_output_flush_remaining = d->m_finished = d->m_block_index = d->m_bit_buffer = d->m_wants_to_finish = 0;
    d->m_pLZ_code_buf = d->m_lz_code_buf + 1;
    d->m_pLZ_flags = d->m_lz_code_buf;
    d->m_num_flags_left = 8;
    d->m_pOutput_buf = d->m_output_buf;
    d->m_pOutput_buf_end = d->m_output_buf;
    d->m_prev_return_status = TDEFL_STATUS_OKAY;
    d->m_saved_match_dist = d->m_saved_match_len = d->m_saved_lit = 0;
    d->m_adler32 = 1;
    d->m_pIn_buf = NULL;
    d->m_pOut_buf = NULL;
    d->m_pIn_buf_size = NULL;
    d->m_pOut_buf_size = NULL;
    d->m_flush = TDEFL_NO_FLUSH;
    d->m_pSrc = NULL;
    d->m_src_buf_left = 0;
    d->m_out_buf_ofs = 0;
    memset(&d->m_huff_count[0][0], 0, sizeof(d->m_huff_count[0][0]) * TDEFL_MAX_HUFF_SYMBOLS_0);
    memset(&d->m_huff_count[1][0], 0, sizeof(d->m_huff_count[1][0]) * TDEFL_MAX_HUFF_SYMBOLS_1);
    return TDEFL_STATUS_OKAY;
}

static const mz_uint s_tdefl_num_probes[11] = { 0, 1, 6, 32, 16, 32, 128, 256, 512, 768, 1500 };

// level may actually range from [0,10] (10 is a "hidden" max level, where we want a bit more compression and it's fine if throughput to fall off a cliff on some files).
mz_uint tdefl_create_comp_flags_from_zip_params(int level, int window_bits, int strategy)
{
    mz_uint comp_flags = s_tdefl_num_probes[(level >= 0) ? MZ_MIN(10, level) : MZ_DEFAULT_LEVEL] | ((level <= 3) ? TDEFL_GREEDY_PARSING_FLAG : 0);
    if (window_bits > 0)
        comp_flags |= TDEFL_WRITE_ZLIB_HEADER;

    if (!level)
        comp_flags |= TDEFL_FORCE_ALL_RAW_BLOCKS;
    else if (strategy == MZ_FILTERED)
        comp_flags |= TDEFL_FILTER_MATCHES;
    else if (strategy == MZ_HUFFMAN_ONLY)
        comp_flags &= ~TDEFL_MAX_PROBES_MASK;
    else if (strategy == MZ_FIXED)
        comp_flags |= TDEFL_FORCE_ALL_STATIC_BLOCKS;
    else if (strategy == MZ_RLE)
        comp_flags |= TDEFL_RLE_MATCHES;

    return comp_flags;
}

mz_uint32 mz_adler32(mz_uint32 adler, const unsigned char *ptr, size_t buf_len)
{
    mz_uint32 i, s1 = (mz_uint32)(adler & 0xffff), s2 = (mz_uint32)(adler >> 16);
    size_t block_len = buf_len % 5552;
    if (!ptr)
        return MZ_ADLER32_INIT;
    while (buf_len)
    {
        for (i = 0; i + 7 < block_len; i += 8, ptr += 8)
        {
            s1 += ptr[0], s2 += s1;
            s1 += ptr[1], s2 += s1;
            s1 += ptr[2], s2 += s1;
            s1 += ptr[3], s2 += s1;
            s1 += ptr[4], s2 += s1;
            s1 += ptr[5], s2 += s1;
            s1 += ptr[6], s2 += s1;
            s1 += ptr[7], s2 += s1;
        }
        for (; i < block_len; ++i)
            s1 += *ptr++, s2 += s1;
        s1 %= 65521U, s2 %= 65521U;
        buf_len -= block_len;
        block_len = 5552;
    }
    return (s2 << 16) + s1;
}
