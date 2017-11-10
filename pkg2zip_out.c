#include "pkg2zip_out.h"
#include "pkg2zip_sys.h"
#include "pkg2zip_zip.h"

static zip out_zip;
static int out_zipped;
static sys_file out_file;
static uint64_t out_file_offset;

void out_begin(const char* name, int zipped)
{
    if (zipped)
    {
        zip_create(&out_zip, name);
    }
    out_zipped = zipped;
}

void out_end(void)
{
    if (out_zipped)
    {
        zip_close(&out_zip);
    }
}

void out_add_folder(const char* path)
{
    if (out_zipped)
    {
        zip_add_folder(&out_zip, path);
    }
    else
    {
        sys_mkdir(path);
    }
}

uint64_t out_begin_file(const char* name, int compress)
{
    if (out_zipped)
    {
        return zip_begin_file(&out_zip, name, compress);
    }
    else
    {
        out_file = sys_create(name);
        out_file_offset = 0;
        return 0;
    }
}

void out_end_file(void)
{
    if (out_zipped)
    {
        zip_end_file(&out_zip);
    }
    else
    {
        sys_close(out_file);
    }
}

void out_write(const void* buffer, uint32_t size)
{
    if (out_zipped)
    {
        zip_write_file(&out_zip, buffer, size);
    }
    else
    {
        sys_write(out_file, out_file_offset, buffer, size);
        out_file_offset += size;
    }
}

void out_write_at(uint64_t offset, const void* buffer, uint32_t size)
{
    if (out_zipped)
    {
        zip_write_file_at(&out_zip, offset, buffer, size);
    }
    else
    {
        sys_write(out_file, offset, buffer, size);
    }
}

void out_set_offset(uint64_t offset)
{
    if (out_zipped)
    {
        zip_set_offset(&out_zip, offset);
    }
    else
    {
        out_file_offset = offset;

    }
}

uint32_t out_zip_get_crc32(void)
{
    if (out_zipped)
    {
        return zip_get_crc32(&out_zip);
    }
    return 0;
}

void out_zip_set_crc32(uint32_t crc)
{
    if (out_zipped)
    {
        zip_set_crc32(&out_zip, crc);
    }
}
