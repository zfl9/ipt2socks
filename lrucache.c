#define _GNU_SOURCE
#include "lrucache.h"
#include <stdlib.h>
#include <string.h>
#undef _GNU_SOURCE

/* get the maxsize of lrucache (globalvar) */
size_t lrucache_get_maxsize(void);

/* set the maxsize of lrucache (globalvar) */
void lrucache_set_maxsize(size_t maxsize);

/* create a new empty lrucache (head is NULL) */
lrucache_t* lrucache_new(void);

/* store a new key-value pair in the lrucache */
lruentry_t* lrucache_put(lrucache_t *cache, ip_port_t *key, void *value, lruvalue_free_cb freecb);

/* get the key-value pairs associated with a given key */
lruentry_t* lrucache_get(lrucache_t *cache, ip_port_t *key);

/* move the given key-value pair to the end of the lrucache */
void lrucache_use(lrucache_t *cache, lruentry_t *entry);

/* remove the given key-value pair from lrucache */
void lrucache_del(lrucache_t *cache, lruentry_t *entry);

/* remove all key-value pairs (including lrucache) */
void lrucache_free(lrucache_t *cache, lruvalue_free_cb freecb);
