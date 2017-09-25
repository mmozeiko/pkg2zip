#include "pkg2zip_utils.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

void fatal(const char* msg, ...)
{
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);

    exit(EXIT_FAILURE);
}

static int hex2byte(char ch)
{
    if (ch >= '0' && ch <= '9')
    {
        return ch - '0';
    }
    else if (ch >= 'A' && ch <= 'Z')
    {
        return ch - 'A' + 10;
    }
    else if (ch >= 'a' && ch <= 'z')
    {
        return ch - 'a' + 10;
    }
    else
    {
        fatal("ERROR: invalid '%c' hex character\n", ch);
    }
}

void get_hex_bytes16(const char* str, uint8_t* bytes)
{
    for (size_t i = 0; i < 16; i++)
    {
        bytes[i] = (uint8_t)((hex2byte(str[0]) << 4) + hex2byte(str[1]));
        str += 2;
    }
}