#if defined(__MINGW32__) && !defined(__x86_64__)
#  define _USE_32BIT_TIME_T
#  define __CRT__NO_INLINE
#endif

#include "pkg2zip_zip.h"
#include "pkg2zip_utils.h"

#include <string.h>
#include <time.h>

#define ZIP_MEMORY_BLOCK (1024 * 1024)

#define ZIP_VERSION 45
#define ZIP_METHOD_STORE 0
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

static const uint32_t crc32[256] =
{
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
};

struct zip_file
{
    uint64_t offset;
    uint64_t size;
    uint32_t crc32;
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
        fatal("ERROR: dirname too long\n");
    }

    zip_file* f = zip_new_file(z);
    f->offset = z->total;
    f->size = 0;
    f->crc32 = 0;

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

void zip_begin_file(zip* z, const char* name)
{
    size_t name_length = strlen(name);
    if (name_length > ZIP_MAX_FILENAME)
    {
        fatal("ERROR: filename too long\n");
    }

    zip_file* f = zip_new_file(z);
    f->offset = z->total;
    f->size = 0;
    f->crc32 = 0xffffffff;
    z->current = f;

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
    z->total += name_length;
}

void zip_write_file(zip* z, const void* data, uint32_t size)
{
    sys_write(z->file, z->total, data, size);
    z->total += size;
    z->current->size += size;

    const uint8_t* bytes = data;
    uint32_t tmp = z->current->crc32;
    for (uint32_t i = 0; i < size; i++)
    {
        tmp = (tmp >> 8) ^ crc32[(uint8_t)(tmp ^ bytes[i])];
    }
    z->current->crc32 = tmp;
}

void zip_end_file(zip* z)
{
    z->current->crc32 ^= 0xffffffff;

    uint64_t size = z->current->size;
    if (size > 0)
    {
        uint8_t update[3 * sizeof(uint32_t)];
        // crc-32
        set32le(update + 0, z->current->crc32);
        // compressed size
        set32le(update + 4, (uint32_t)min64(size, 0xffffffff));
        // uncompressed size
        set32le(update + 8, (uint32_t)min64(size, 0xffffffff));

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
                extra_size += 2 * sizeof(uint64_t);
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
        set16le(global + 10, ZIP_METHOD_STORE);
        // last mod file time
        set16le(global + 12, z->time);
        // last mod file date
        set16le(global + 14, z->date);
        // crc-32
        set32le(global + 16, f->crc32);
        // compressed size
        set32le(global + 20, (uint32_t)min64(size, 0xffffffff));
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
        if (size > 0xffffffff)
        {
            // original uncompressed file size
            set64le(extra + extra_offset, size);
            extra_offset += sizeof(uint64_t);
            // size of compressed data
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
