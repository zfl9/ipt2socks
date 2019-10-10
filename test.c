#include "logutils.h"

int main() {
    char strarray[10];
    LOGINF("%p", strarray);
    LOGINF("%p", &strarray);
    LOGINF("%p", strarray + 10);
    LOGINF("%p", &strarray + 10);
    LOGINF("%zu", strarray + 10 - strarray);
    LOGINF("%zu", &strarray + 10 - &strarray);
    return 0;
}
