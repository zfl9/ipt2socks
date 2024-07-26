#define _GNU_SOURCE
#include "co.h"
#include <stdlib.h>

void co_sentinel_cb(void *restrict co, void *) {
    return free(co); // free the `NULL` is a no-op.
}
