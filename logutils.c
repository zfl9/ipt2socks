#define _GNU_SOURCE
#include "logutils.h"
#include <string.h>

#define ERRSTR_BUFLEN 256
static __thread char g_errstr_buffer[ERRSTR_BUFLEN];

const char* my_strerror(int errnum) {
    strerror_r(errnum, g_errstr_buffer, ERRSTR_BUFLEN);
    return g_errstr_buffer;
}
