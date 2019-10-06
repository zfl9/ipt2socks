#define _GNU_SOURCE
#include "logutils.h"
#include "lrucache.h"
#include "netutils.h"
#include "protocol.h"
#undef _GNU_SOURCE

int main() {
    LOGINF("[main] hello, world!");
    return 0;
}
