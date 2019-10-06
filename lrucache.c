#define _GNU_SOURCE
#include "lrucache.h"
#include <stdlib.h>
#include <string.h>
#undef _GNU_SOURCE

/* lrucache maxsize (private variable) */
static size_t lrucache_maxsize = LRUCACHE_MAXSIZE_DEFAULT;

/* get the maxsize of lrucache (globalvar) */
size_t lrucache_get_maxsize(void) {
    return lrucache_maxsize;
}

/* set the maxsize of lrucache (globalvar) */
void lrucache_set_maxsize(size_t maxsize) {
    lrucache_maxsize = maxsize;
}

/* create a new empty lrucache (head is NULL) */
lrucache_t* lrucache_new(void) {
    return calloc(1, sizeof(lrucache_t));
}

/* store a new key-value pair in the lrucache */
lruentry_t* lrucache_put(lrucache_t *cache, ip_port_t *key, void *value, lruvalue_free_cb freecb) {
    lruentry_t *entry = malloc(sizeof(lruentry_t));
    memcpy(&entry->key, key, sizeof(ip_port_t));
    entry->value = value;
    HASH_ADD(hh, cache->head, key, sizeof(ip_port_t), entry);
    if (HASH_COUNT(cache->head) > lrucache_maxsize) {
        lruentry_t *currentry = NULL, *tempentry = NULL;
        HASH_ITER(hh, cache->head, currentry, tempentry) {
            HASH_DEL(cache->head, currentry);
            freecb(currentry->value);
            free(currentry);
            break;
        }
    }
    return entry;
}

/* get the key-value pairs associated with a given key */
lruentry_t* lrucache_get(lrucache_t *cache, ip_port_t *key) {
    lruentry_t *entry = NULL;
    HASH_FIND(hh, cache->head, key, sizeof(ip_port_t), entry);
    if (!entry) return NULL;
    HASH_DEL(cache->head, entry);
    HASH_ADD(hh, cache->head, key, sizeof(ip_port_t), entry);
    return entry;
}

/* move the given key-value pair to the end of the lrucache */
void lrucache_use(lrucache_t *cache, lruentry_t *entry) {
    HASH_DEL(cache->head, entry);
    HASH_ADD(hh, cache->head, key, sizeof(ip_port_t), entry);
}

/* remove the given key-value pair from lrucache */
void lrucache_del(lrucache_t *cache, lruentry_t *entry) {
    HASH_DEL(cache->head, entry);
    free(entry);
}

/* remove all key-value pairs (including lrucache) */
void lrucache_free(lrucache_t *cache, lruvalue_free_cb freecb) {
    lruentry_t *currentry = NULL, *tempentry = NULL;
    HASH_ITER(hh, cache->head, currentry, tempentry) {
        HASH_DEL(cache->head, currentry);
        freecb(currentry->value);
        free(currentry);
    }
    free(cache);
}
