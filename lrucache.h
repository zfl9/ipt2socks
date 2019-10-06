#ifndef IPT2SOCKS_LRUCACHE_H
#define IPT2SOCKS_LRUCACHE_H

#define _GNU_SOURCE
#include "uthash.h"
#include "netutils.h"
#undef _GNU_SOURCE

/* default max number of entries */
#define LRUCACHE_MAXSIZE_DEFAULT 256

/* lruentry structure typedef */
typedef struct {
    ip_port_t       key;
    void           *value;
    UT_hash_handle  hh;
} lruentry_t;

/* lrucache structure typedef */
typedef struct {
    lruentry_t *head;
} lrucache_t;

/* lruvalue free callback typedef */
typedef void (*lruvalue_free_cb)(void *value);

/* get the maxsize of lrucache (globalvar) */
uint16_t lrucache_get_maxsize(void);

/* set the maxsize of lrucache (globalvar) */
void lrucache_set_maxsize(uint16_t maxsize);

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

#endif
