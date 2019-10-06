#ifndef IPT2SOCKS_PROTOCOL_H
#define IPT2SOCKS_PROTOCOL_H

#define _GNU_SOURCE
#include "netutils.h"
#undef _GNU_SOURCE

/* socks5 authentication request */
typedef struct {
    uint8_t version; /* 0x05 */
    uint8_t mlength; /* 0x01 */
    uint8_t method; /* 0x00 */
} __attribute__((packed)) socks5_authreq_t;

/* socks5 authentication response */
typedef struct {
    uint8_t version; /* 0x05 */
    uint8_t method; /* 0x00 */
} __attribute__((packed)) socks5_authresp_t;

/* socks5 ipv4-proxy request */
typedef struct {
    uint8_t   version;
    uint8_t   command;
    uint8_t   reserved;
    uint8_t   addrtype;
    ipaddr4_t ipaddr4;
    portno_t  portnum;
} __attribute__((packed)) socks5_ipv4req_t;

/* socks5 ipv6-proxy request */
typedef struct {
    uint8_t   version;
    uint8_t   command;
    uint8_t   reserved;
    uint8_t   addrtype;
    ipaddr6_t ipaddr6;
    portno_t  portnum;
} __attribute__((packed)) socks5_ipv6req_t;

/* socks5 ipv4-proxy response */
typedef struct {
    uint8_t   version;
    uint8_t   respcode;
    uint8_t   reserved;
    uint8_t   addrtype;
    ipaddr4_t ipaddr4;
    portno_t  portnum;
} __attribute__((packed)) socks5_ipv4resp_t;

/* socks5 ipv6-proxy response */
typedef struct {
    uint8_t   version;
    uint8_t   respcode;
    uint8_t   reserved;
    uint8_t   addrtype;
    ipaddr6_t ipaddr6;
    portno_t  portnum;
} __attribute__((packed)) socks5_ipv6resp_t;

/* socks5 ipv4-udp message header */
typedef struct {
    uint16_t  reserved;
    uint8_t   fragment;
    uint8_t   addrtype;
    ipaddr4_t ipaddr4;
    portno_t  portnum;
    uint8_t   payload[]; /* sizeof = 0 */
} __attribute__((packed)) socks5_udp4msg_t;

/* socks5 ipv6-udp message header */
typedef struct {
    uint16_t  reserved;
    uint8_t   fragment;
    uint8_t   addrtype;
    ipaddr6_t ipaddr6;
    portno_t  portnum;
    uint8_t   payload[]; /* sizeof = 0 */
} __attribute__((packed)) socks5_udp6msg_t;

#endif
