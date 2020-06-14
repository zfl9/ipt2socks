#define _GNU_SOURCE
#include "lrucache.h"

static uint16_t g_lrucache_maxsize = 256;

uint16_t lrucache_get_maxsize(void) {
    return g_lrucache_maxsize;
}
void lrucache_set_maxsize(uint16_t maxsize) {
    g_lrucache_maxsize = maxsize;
}

udp_socks5ctx_t* udp_socks5ctx_add(udp_socks5ctx_t **cache, udp_socks5ctx_t *entry) {
    MYHASH_ADD(*cache, entry, &entry->key_ipport, sizeof(entry->key_ipport));
    if (MYHASH_CNT(*cache) > g_lrucache_maxsize) {
        udp_socks5ctx_t *curentry = NULL, *tmpentry = NULL;
        MYHASH_FOR(*cache, curentry, tmpentry) {
            MYHASH_DEL(*cache, curentry);
            return curentry;
        }
    }
    return NULL;
}
udp_tproxyctx_t* udp_tproxyctx_add(udp_tproxyctx_t **cache, udp_tproxyctx_t *entry) {
    MYHASH_ADD(*cache, entry, &entry->key_ipport, sizeof(entry->key_ipport));
    if (MYHASH_CNT(*cache) > g_lrucache_maxsize) {
        udp_tproxyctx_t *curentry = NULL, *tmpentry = NULL;
        MYHASH_FOR(*cache, curentry, tmpentry) {
            MYHASH_DEL(*cache, curentry);
            return curentry;
        }
    }
    return NULL;
}

udp_socks5ctx_t* udp_socks5ctx_get(udp_socks5ctx_t **cache, const ip_port_t *keyptr) {
    udp_socks5ctx_t *entry = NULL;
    MYHASH_GET(*cache, entry, keyptr, sizeof(ip_port_t));
    if (entry) {
        MYHASH_DEL(*cache, entry);
        MYHASH_ADD(*cache, entry, &entry->key_ipport, sizeof(entry->key_ipport));
    }
    return entry;
}
udp_tproxyctx_t* udp_tproxyctx_get(udp_tproxyctx_t **cache, const ip_port_t *keyptr) {
    udp_tproxyctx_t *entry = NULL;
    MYHASH_GET(*cache, entry, keyptr, sizeof(ip_port_t));
    if (entry) {
        MYHASH_DEL(*cache, entry);
        MYHASH_ADD(*cache, entry, &entry->key_ipport, sizeof(entry->key_ipport));
    }
    return entry;
}

void udp_socks5ctx_use(udp_socks5ctx_t **cache, udp_socks5ctx_t *entry) {
    MYHASH_DEL(*cache, entry);
    MYHASH_ADD(*cache, entry, &entry->key_ipport, sizeof(entry->key_ipport));
}
void udp_tproxyctx_use(udp_tproxyctx_t **cache, udp_tproxyctx_t *entry) {
    MYHASH_DEL(*cache, entry);
    MYHASH_ADD(*cache, entry, &entry->key_ipport, sizeof(entry->key_ipport));
}

void udp_socks5ctx_del(udp_socks5ctx_t **cache, udp_socks5ctx_t *entry) {
    MYHASH_DEL(*cache, entry);
}
void udp_tproxyctx_del(udp_tproxyctx_t **cache, udp_tproxyctx_t *entry) {
    MYHASH_DEL(*cache, entry);
}
