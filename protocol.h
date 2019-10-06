#ifndef IPT2SOCKS_PROTOCOL_H
#define IPT2SOCKS_PROTOCOL_H

#define _GNU_SOURCE
#include "netutils.h"
#undef _GNU_SOURCE

typedef struct {
    uint8_t version;
    uint8_t mlength;
    uint8_t method;
} __attribute__((packed)) socks5_authreq_t;

typedef struct {
    uint8_t version;
    uint8_t method;
} __attribute__((packed)) socks5_authresp_t;

typedef struct {
    uint8_t   version;
    uint8_t   command;
    uint8_t   reserved;
    uint8_t   addrtype;
    ipaddr4_t ip4addr;
    portno_t  portnum;
} __attribute__((packed)) socks5_ipv4req_t;

typedef struct {
    uint8_t   version;
    uint8_t   command;
    uint8_t   reserved;
    uint8_t   addrtype;
    ipaddr6_t ip6addr;
    portno_t  portnum;
} __attribute__((packed)) socks5_ipv6req_t;

typedef struct {
    uint8_t   version;
    uint8_t   respcode;
    uint8_t   reserved;
    uint8_t   addrtype;
    ipaddr4_t ip4addr;
    portno_t  portnum;
} __attribute__((packed)) socks5_ipv4resp_t;

typedef struct {
    uint8_t   version;
    uint8_t   respcode;
    uint8_t   reserved;
    uint8_t   addrtype;
    ipaddr6_t ip6addr;
    portno_t  portnum;
} __attribute__((packed)) socks5_ipv6resp_t;

typedef struct {
    uint16_t  reserved;
    uint8_t   fragment;
    uint8_t   addrtype;
    ipaddr4_t ip4addr;
    portno_t  portnum;
    uint8_t   payload[];
} __attribute__((packed)) socks5_udp4msg_t;

typedef struct {
    uint16_t  reserved;
    uint8_t   fragment;
    uint8_t   addrtype;
    ipaddr6_t ip6addr;
    portno_t  portnum;
    uint8_t   payload[];
} __attribute__((packed)) socks5_udp6msg_t;

#endif
