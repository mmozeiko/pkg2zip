#if defined(__MINGW32__) && !defined(__x86_64__)
#  define _USE_32BIT_TIME_T
#  define __CRT__NO_INLINE
#endif

#include "pkg2zip_zip.h"
#include "pkg2zip_out.h"
#include "pkg2zip_crc32.h"
#include "pkg2zip_utils.h"

#include <string.h>
#include <time.h>

#define ZIP_MEMORY_BLOCK (1024 * 1024)

// https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT

#define ZIP_VERSION 45
#define ZIP_METHOD_STORE 0
#define ZIP_METHOD_DEFLATE 8
#define ZIP_UTF8_FLAG (1 << 11)

#define ZIP_DOS_ATTRIBUTE_DIRECTORY 0x10
#define ZIP_DOS_ATTRIBUTE_ARCHIVE   0x20

#define ZIP_LOCAL_HEADER_SIZE 30
#define ZIP_GLOBAL_HEADER_SIZE 46
#define ZIP64_EOC_DIR_SIZE 56
#define ZIP64_EOC_DIR_LOCATOR_SIZE 20
#define ZIP_EOC_DIR_SIZE 22

#define ZIP_LOCAL_HEADER_CRC32_OFFSET 14
#define ZIP_LOCAL_HEADER_FILENAME_LENGTH_OFFSET 26

struct zip_file
{
    uint64_t offset;
    uint64_t size;
    uint64_t compressed;
    uint32_t crc32;
    int compress;
};

static zip_file* zip_new_file(zip* z)
{
    if (z->count == z->max)
    {
        z->allocated += ZIP_MEMORY_BLOCK;
        z->files = sys_realloc(z->files, z->allocated);
        z->max = z->allocated / sizeof(zip_file);
    }

    return z->files + z->count++;
}

void zip_create(zip* z, const char* name)
{
    z->file = sys_create(name);
    z->total = 0;
    z->count = 0;
    z->max = 0;
    z->allocated = 0;
    z->files = NULL;
    z->current = NULL;

    time_t t = time(NULL);
    struct tm* tm = localtime(&t);
    z->date = (uint16_t)(((tm->tm_year + 1900 - 1980) << 9) + ((tm->tm_mon + 1) << 5) + tm->tm_mday);
    z->time = (uint16_t)((tm->tm_hour << 11) + (tm->tm_min << 5) + (tm->tm_sec / 2));
}

void zip_add_folder(zip* z, const char* name)
{
    size_t name_length = strlen(name) + 1;
    if (name_length > ZIP_MAX_FILENAME)
    {
        sys_error("ERROR: dirname too long\n");
    }

    zip_file* f = zip_new_file(z);
    f->offset = z->total;
    f->size = 0;
    f->compressed = 0;
    f->crc32 = 0;
    f->compress = 0;

    uint8_t header[ZIP_LOCAL_HEADER_SIZE] = { 0x50, 0x4b, 0x03, 0x04 };
    // version needed to extract
    set16le(header + 4, ZIP_VERSION);
    // general purpose bit flag
    set16le(header + 6, ZIP_UTF8_FLAG);
    // compression method
    set16le(header + 8, ZIP_METHOD_STORE);
    // last mod file time
    set16le(header + 10, z->time);
    // last mod file date
    set16le(header + 12, z->date);
    // file name length
    set16le(header + 26, (uint16_t)name_length);

    sys_write(z->file, z->total, header, sizeof(header));
    z->total += sizeof(header);

    sys_write(z->file, z->total, name, (uint16_t)name_length);
    z->total += name_length - 1;

    char slash = '/';
    sys_write(z->file, z->total, &slash, 1);
    z->total += 1;
}

uint64_t zip_begin_file(zip* z, const char* name, int compress)
{
    size_t name_length = strlen(name);
    if (name_length > ZIP_MAX_FILENAME)
    {
        sys_error("ERROR: filename too long\n");
    }

    zip_file* f = zip_new_file(z);
    f->offset = z->total;
    f->size = 0;
    f->compressed = 0;
    f->compress = compress;
    z->current = f;

    crc32_init(&z->crc32);
    z->crc32_set = 0;

    uint8_t header[ZIP_LOCAL_HEADER_SIZE] = { 0x50, 0x4b, 0x03, 0x04 };
    // version needed to extract
    set16le(header + 4, ZIP_VERSION);
    // general purpose bit flag
    set16le(header + 6, ZIP_UTF8_FLAG);
    // compression method
    set16le(header + 8, compress ? ZIP_METHOD_DEFLATE : ZIP_METHOD_STORE);
    // last mod file time
    set16le(header + 10, z->time);
    // last mod file date
    set16le(header + 12, z->date);
    // file name length
    set16le(header + 26, (uint16_t)name_length);

    sys_write(z->file, z->total, header, sizeof(header));
    z->total += sizeof(header);

    sys_write(z->file, z->total, name, (uint16_t)name_length);
    z->total += name_length;

    if (compress)
    {
        int flags = tdefl_create_comp_flags_from_zip_params(MZ_BEST_SPEED, -MZ_DEFAULT_WINDOW_BITS, MZ_DEFAULT_STRATEGY);
        tdefl_init(&z->tdefl, flags);
    }

    return z->total - f->offset;
}

void zip_write_file(zip* z, const void* data, uint32_t size)
{
    z->current->size += size;
    crc32_update(&z->crc32, data, size);

    if (z->current->compress)
    {
        const uint8_t* data8 = data;
        while (size != 0)
        {
            uint8_t buffer[4096];

            size_t isize = size;
            size_t osize = sizeof(buffer);
            tdefl_compress(&z->tdefl, data8, &isize, buffer, &osize, TDEFL_NO_FLUSH);

            if (osize != 0)
            {
                sys_write(z->file, z->total, buffer, (uint32_t)osize);
                z->current->compressed += osize;
                z->total += osize;
            }
            data8 += isize;
            size -= (uint32_t)isize;
        }
    }
    else
    {
        sys_write(z->file, z->total, data, size);
        z->current->compressed += size;
        z->total += size;
    }
}

void zip_end_file(zip* z)
{
    if (z->current->compress)
    {
        for (;;)
        {
            uint8_t buffer[4096];

            size_t isize = 0;
            size_t osize = sizeof(buffer);
            tdefl_status st = tdefl_compress(&z->tdefl, NULL, &isize, buffer, &osize, TDEFL_FINISH);

            if (osize != 0)
            {
                sys_write(z->file, z->total, buffer, (uint32_t)osize);
                z->current->compressed += osize;
                z->total += osize;
            }
            if (st == TDEFL_STATUS_DONE)
            {
                break;
            }
        }
    }

    if (!z->crc32_set)
    {
        z->current->crc32 = crc32_done(&z->crc32);
    }

    if (z->current->size != 0)
    {
        uint8_t update[3 * sizeof(uint32_t)];
        // crc-32
        set32le(update + 0, z->current->crc32);
        // compressed size
        set32le(update + 4, (uint32_t)min64(z->current->compressed, 0xffffffff));
        // uncompressed size
        set32le(update + 8, (uint32_t)min64(z->current->size, 0xffffffff));

        sys_write(z->file, z->current->offset + ZIP_LOCAL_HEADER_CRC32_OFFSET, update, sizeof(update));
    }

    z->current = NULL;
}

void zip_close(zip* z)
{
    uint64_t central_dir_offset = z->total;

    // central directory headers
    for (uint32_t i = 0; i < z->count; i++)
    {
        const zip_file* f = z->files + i;

        uint8_t local[ZIP_LOCAL_HEADER_SIZE];
        sys_read(z->file, f->offset, local, sizeof(local));

        uint32_t filename_length = get16le(local + ZIP_LOCAL_HEADER_FILENAME_LENGTH_OFFSET);

        uint8_t global[ZIP_GLOBAL_HEADER_SIZE + ZIP_MAX_FILENAME] = { 0x50, 0x4b, 0x01, 0x02 };
        sys_read(z->file, f->offset + sizeof(local), global + ZIP_GLOBAL_HEADER_SIZE, filename_length);
        int is_folder = global[ZIP_GLOBAL_HEADER_SIZE + filename_length - 1] == '/';

        uint8_t extra[28];
        uint16_t extra_size = 0;
        uint64_t size = f->size;
        uint64_t compressed = f->compressed;
        uint64_t offset = f->offset;
        uint32_t attributes = ZIP_DOS_ATTRIBUTE_ARCHIVE;
        if (is_folder)
        {
            attributes |= ZIP_DOS_ATTRIBUTE_DIRECTORY;
            if (offset > 0xffffffff)
            {
                extra_size += sizeof(uint64_t);
            }
        }
        else
        {
            if (size > 0xffffffff)
            {
                extra_size += sizeof(uint64_t);
            }
            if (compressed > 0xffffffff)
            {
                extra_size += sizeof(uint64_t);
            }
            if (offset > 0xffffffff)
            {
                extra_size += sizeof(uint64_t);
            }
        }

        if (extra_size)
        {
            extra_size += 2 * sizeof(uint16_t);
        }

        // version made by
        set16le(global + 4, ZIP_VERSION);
        // version needed to extract
        set16le(global + 6, ZIP_VERSION);
        // general purpose bit flag
        set16le(global + 8, ZIP_UTF8_FLAG);
        // compression method
        set16le(global + 10, f->compress ? ZIP_METHOD_DEFLATE : ZIP_METHOD_STORE);
        // last mod file time
        set16le(global + 12, z->time);
        // last mod file date
        set16le(global + 14, z->date);
        // crc-32
        set32le(global + 16, f->crc32);
        // compressed size
        set32le(global + 20, (uint32_t)min64(compressed, 0xffffffff));
        // uncompressed size
        set32le(global + 24, (uint32_t)min64(size, 0xffffffff));
        // file name length
        set16le(global + 28, (uint16_t)filename_length);
        // extra field length
        set16le(global + 30, extra_size);
        // external file attributes
        set32le(global + 38, attributes);
        // relative offset of local header 4 bytes
        set32le(global + 42, (uint32_t)min64(offset, 0xffffffff));

        sys_write(z->file, z->total, global, ZIP_GLOBAL_HEADER_SIZE + filename_length);
        z->total += ZIP_GLOBAL_HEADER_SIZE + filename_length;

        // zip64 Extended Information Extra Field
        set16le(extra + 0, 1);
        // size of this "extra" block
        uint32_t extra_offset = 2 * sizeof(uint16_t);
        set16le(extra + 2, (uint16_t)(extra_size - extra_offset));
        if (compressed > 0xffffffff)
        {
            // size of compressed data
            set64le(extra + extra_offset, compressed);
            extra_offset += sizeof(uint64_t);
        }
        if (size > 0xffffffff)
        {
            // original uncompressed file size
            set64le(extra + extra_offset, size);
            extra_offset += sizeof(uint64_t);
        }
        if (offset > 0xffffffff)
        {
            // offset of local header record
            set64le(extra + extra_offset, offset);
            extra_offset += sizeof(uint64_t);
        }

        if (extra_size > 2 * sizeof(uint16_t))
        {
            sys_write(z->file, z->total, extra, extra_size);
            z->total += extra_size;
        }
    }

    uint64_t end_of_central_dir_offset = z->total;
    uint64_t central_dir_size = end_of_central_dir_offset - central_dir_offset;

    // zip64 end of central directory record
    {
        uint8_t header[ZIP64_EOC_DIR_SIZE] = { 0x50, 0x4b, 0x06, 0x06 };
        // size of zip64 end of central directory record
        set64le(header + 4, sizeof(header) - sizeof(uint32_t) - sizeof(uint64_t));
        // version made by
        set16le(header + 12, ZIP_VERSION);
        // version needed to extract
        set16le(header + 14, ZIP_VERSION);
        // total number of entries in the central directory on this disk
        set64le(header + 24, z->count);
        // total number of entries in the central directory
        set64le(header + 32, z->count);
        // size of the central directory
        set64le(header + 40, central_dir_size);
        // offset of start of central directory with respect to the starting disk number
        set64le(header + 48, central_dir_offset);

        sys_write(z->file, z->total, header, sizeof(header));
        z->total += sizeof(header);
    }

    // zip64 end of central directory locator
    {
        uint8_t header[ZIP64_EOC_DIR_LOCATOR_SIZE] = { 0x50, 0x4b, 0x06, 0x07 };
        // relative offset of the zip64 end of central directory record 8 bytes
        set64le(header + 8, end_of_central_dir_offset);
        // total number of disks
        set32le(header + 16, 1);

        sys_write(z->file, z->total, header, sizeof(header));
        z->total += sizeof(header);
    }

    // end of central directory record
    {
        uint8_t header[ZIP_EOC_DIR_SIZE] = { 0x50, 0x4b, 0x05, 0x06 };
        // total number of entries in the central directory on this disk
        set16le(header + 8, (uint16_t)min32(z->count, 0xffff));
        // total number of entries in the central directory
        set16le(header + 10, (uint16_t)min32(z->count, 0xffff));
        // size of the central directory
        set32le(header + 12, (uint32_t)min64(central_dir_size, 0xffffffff));
        // offset of start of central directory with respect to the starting disk number
        set32le(header + 16, (uint32_t)min64(central_dir_offset, 0xffffffff));

        sys_write(z->file, z->total, header, sizeof(header));
        z->total += sizeof(header);
    }

    sys_close(z->file);

    sys_realloc(z->files, 0);
}

void zip_write_file_at(zip* z, uint64_t offset, const void* data, uint32_t size)
{
    if (z->current->compress)
    {
        sys_error("ERROR: cannot write at specific offset for compressed files\n");
    }

    sys_write(z->file, z->current->offset + offset, data, size);
    z->current->size += size;
    z->current->compressed += size;
}

void zip_set_offset(zip* z, uint64_t offset)
{
    z->total = z->current->offset + offset;
}

void zip_set_crc32(zip* z, uint32_t crc)
{
    z->current->crc32 = crc;
    z->crc32_set = 1;
}

uint32_t zip_get_crc32(zip* z)
{
    return crc32_done(&z->crc32);
}
