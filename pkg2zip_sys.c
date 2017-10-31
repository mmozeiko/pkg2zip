#include "pkg2zip_sys.h"
#include "pkg2zip_utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static void sys_mkdir_real(const char* path)
{
    WCHAR wpath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH);

    if (CreateDirectoryW(wpath, NULL) == 0)
    {
        if (GetLastError() != ERROR_ALREADY_EXISTS)
        {
            fatal("ERROR: cannot create '%s' folder\n", path);
        }
    }
}

sys_file sys_open(const char* fname, uint64_t* size)
{
    WCHAR path[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, fname, -1, path, MAX_PATH);

    HANDLE handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE)
    {
        fatal("ERROR: cannot open '%s' file\n", fname);
    }

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(handle, &sz))
    {
        fatal("ERROR: cannot get size of '%s' file\n", fname);
    }
    *size = sz.QuadPart;

    return handle;
}

sys_file sys_create(const char* fname)
{
    WCHAR path[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, fname, -1, path, MAX_PATH);

    HANDLE handle = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE)
    {
        fatal("ERROR: cannot create '%s' file\n", fname);
    }

    return handle;
}

void sys_close(sys_file file)
{
    if (!CloseHandle(file))
    {
        fatal("ERROR: failed to close file\n");
    }
}

void sys_read(sys_file file, uint64_t offset, void* buffer, uint32_t size)
{
    DWORD read;
    OVERLAPPED ov;
    ov.hEvent = NULL;
    ov.Offset = (uint32_t)offset;
    ov.OffsetHigh = (uint32_t)(offset >> 32);
    if (!ReadFile(file, buffer, size, &read, &ov) || read != size)
    {
        fatal("ERROR: failed to read %u bytes from file\n", size);
    }
}

void sys_write(sys_file file, uint64_t offset, const void* buffer, uint32_t size)
{
    DWORD written;
    OVERLAPPED ov;
    ov.hEvent = NULL;
    ov.Offset = (uint32_t)offset;
    ov.OffsetHigh = (uint32_t)(offset >> 32);
    if (!WriteFile(file, buffer, size, &written, &ov) || written != size)
    {
        fatal("ERROR: failed to write %u bytes to file\n", size);
    }
}

#else

#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

static void sys_mkdir_real(const char* path)
{
    if (mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0)
    {
        if (errno != EEXIST)
        {
            fatal("ERROR: cannot create '%s' folder\n", path);
        }
    }
}

sys_file sys_open(const char* fname, uint64_t* size)
{
    int fd = open(fname, O_RDONLY);
    if (fd < 0)
    {
        fatal("ERROR: cannot open '%s' file\n", fname);
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        fatal("ERROR: cannot get size of '%s' file\n", fname);
    }
    *size = st.st_size;

    return (void*)(intptr_t)fd;
}

sys_file sys_create(const char* fname)
{
    int fd = open(fname, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0)
    {
        fatal("ERROR: cannot create '%s' file\n", fname);
    }

    return (void*)(intptr_t)fd;
}

void sys_close(sys_file file)
{
    if (close((int)(intptr_t)file) != 0)
    {
        fatal("ERROR: failed to close file\n");
    }
}

void sys_read(sys_file file, uint64_t offset, void* buffer, uint32_t size)
{
    ssize_t read = pread((int)(intptr_t)file, buffer, size, offset);
    if (read != size)
    {
        fatal("ERROR: failed to read %u bytes from file\n", size);
    }
}

void sys_write(sys_file file, uint64_t offset, const void* buffer, uint32_t size)
{
    ssize_t wrote = pwrite((int)(intptr_t)file, buffer, size, offset);
    if (wrote != size)
    {
        fatal("ERROR: failed to read %u bytes from file\n", size);
    }
}

#endif

void sys_mkdir(const char* path)
{
    char* last = strrchr(path, '/');
    if (last)
    {
        *last = 0;
        sys_mkdir(path);
        *last = '/';
    }
    sys_mkdir_real(path);
}

void* sys_realloc(void* ptr, size_t size)
{
    void* result = NULL;
    if (!ptr && size)
    {
        result = malloc(size);
    }
    else if (ptr && !size)
    {
        free(ptr);
        return NULL;
    }
    else if (ptr && size)
    {
        result = realloc(ptr, size);
    }
    else
    {
        fatal("error using sys_realloc function");
    }

    if (!result)
    {
        fatal("out of memory");
    }

    return result;
}

void sys_vstrncat(char* dst, size_t n, const char* format, ...)
{
    char temp[1024];

    va_list args;
    va_start(args, format);
    vsnprintf(temp, sizeof(temp), format, args);
    va_end(args);

    strncat(dst, temp, n - strlen(dst) - 1);
}