#define _GNU_SOURCE
#include "lrucache.h"
#include <stdlib.h>
#include <string.h>
#undef _GNU_SOURCE

/* lrucache maxsize (private variable) */
static uint16_t lrucache_maxsize = LRUCACHE_MAXSIZE_DEFAULT;

/* get the maxsize of lrucache (globalvar) */
uint16_t lrucache_get_maxsize(void) {
    return lrucache_maxsize;
}

/* set the maxsize of lrucache (globalvar) */
void lrucache_set_maxsize(uint16_t maxsize) {
    lrucache_maxsize = maxsize;
}

/* store a new key-value pair in the lrucache */
lruentry_t* lrucache_put(lrucache_t **cache, ip_port_t *key, void *value, lruvalue_free_cb freecb) {
    lruentry_t *entry = malloc(sizeof(lruentry_t));
    memcpy(&entry->key, key, sizeof(ip_port_t));
    entry->value = value;
    HASH_ADD(hh, *cache, key, sizeof(ip_port_t), entry);
    if (HASH_COUNT(*cache) > lrucache_maxsize) {
        lruentry_t *currentry = NULL, *tempentry = NULL;
        HASH_ITER(hh, *cache, currentry, tempentry) {
            HASH_DEL(*cache, currentry);
            freecb(currentry->value);
            free(currentry);
            break;
        }
    }
    return entry;
}

/* get the key-value pairs associated with a given key */
lruentry_t* lrucache_get(lrucache_t **cache, ip_port_t *key) {
    lruentry_t *entry = NULL;
    HASH_FIND(hh, *cache, key, sizeof(ip_port_t), entry);
    if (!entry) return NULL;
    HASH_DEL(*cache, entry);
    HASH_ADD(hh, *cache, key, sizeof(ip_port_t), entry);
    return entry;
}

/* move the given key-value pair to the end of the lrucache */
void lrucache_use(lrucache_t **cache, lruentry_t *entry) {
    HASH_DEL(*cache, entry);
    HASH_ADD(hh, *cache, key, sizeof(ip_port_t), entry);
}

/* remove the given key-value pair from lrucache */
void lrucache_del(lrucache_t **cache, lruentry_t *entry) {
    HASH_DEL(*cache, entry);
    free(entry);
}
