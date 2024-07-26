#define _GNU_SOURCE
#include "co.h"
#include <stdlib.h>

void co_sentinel(void *restrict co, void *arg) {
    (void)arg;
    return free(co); // free the `NULL` is a no-op.
}
