#include "log.h"

const struct tm *get_tm(void) {
    time_t t = time(NULL);
    return localtime(&t);
}
