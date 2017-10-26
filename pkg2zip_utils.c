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
