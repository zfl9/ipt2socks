#ifndef IPT2SOCKS_PROTOCOL_H
#define IPT2SOCKS_PROTOCOL_H

#define _GNU_SOURCE
#include "netutils.h"
#undef _GNU_SOURCE

/* socks5 protocol version number */
#define SOCKS5_VERSION 0x05

/* method code constant definition */
#define SOCKS5_METHOD_NOAUTH 0x00
#define SOCKS5_METHOD_UNACCEPTABLE 0xff

/* command type constant definition */
#define SOCKS5_COMMAND_CONNECT 0x01
#define SOCKS5_COMMAND_UDPASSOCIATE 0x03

/* address type constant definition */
#define SOCKS5_ADDRTYPE_IPV4 0x01
#define SOCKS5_ADDRTYPE_IPV6 0x04

/* response code constant definition */
#define SOCKS5_RESPCODE_SUCCEEDED 0x00
#define SOCKS5_RESPCODE_SVRGENERR 0x01
#define SOCKS5_RESPCODE_NOTALLOWED 0x02
#define SOCKS5_RESPCODE_NETUNREACH 0x03
#define SOCKS5_RESPCODE_HOSTUNREACH 0x04
#define SOCKS5_RESPCODE_CONNREFUSED 0x05
#define SOCKS5_RESPCODE_TTLEXPIRED 0x06
#define SOCKS5_RESPCODE_COMMANDNOTSPT 0x07
#define SOCKS5_RESPCODE_ADDRTYPENOTSPT 0x08
#define SOCKS5_RESPCODE_09FFUNASSIGNED 0x09

/* get a string description of the given response code */
static inline const char* socks5_rcode2string(uint8_t rcode) {
    switch (rcode) {
        case SOCKS5_RESPCODE_SUCCEEDED: return "Succeeded";
        case SOCKS5_RESPCODE_SVRGENERR: return "General server failure";
        case SOCKS5_RESPCODE_NOTALLOWED: return "Not allowed by ruleset";
        case SOCKS5_RESPCODE_NETUNREACH: return "Network unreachable";
        case SOCKS5_RESPCODE_HOSTUNREACH: return "Host unreachable";
        case SOCKS5_RESPCODE_CONNREFUSED: return "Connection refused";
        case SOCKS5_RESPCODE_TTLEXPIRED: return "TTL expired";
        case SOCKS5_RESPCODE_COMMANDNOTSPT: return "Command not supported";
        case SOCKS5_RESPCODE_ADDRTYPENOTSPT: return "Address type not supported";
    }
    return "Unknown response code";
}

/* socks5 udp message payload maxsize */
#define SOCKS5_UDP4_PAYLOAD_MAXSIZE (UDP_PACKET_MAXSIZE - sizeof(socks5_udp4msg_t))
#define SOCKS5_UDP6_PAYLOAD_MAXSIZE (UDP_PACKET_MAXSIZE - sizeof(socks5_udp6msg_t))

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
    uint8_t   reserved; /* 0x00 */
    uint8_t   addrtype;
    ipaddr4_t ipaddr4;
    portno_t  portnum;
} __attribute__((packed)) socks5_ipv4req_t;

/* socks5 ipv6-proxy request */
typedef struct {
    uint8_t   version;
    uint8_t   command;
    uint8_t   reserved; /* 0x00 */
    uint8_t   addrtype;
    ipaddr6_t ipaddr6;
    portno_t  portnum;
} __attribute__((packed)) socks5_ipv6req_t;

/* socks5 ipv4-proxy response */
typedef struct {
    uint8_t   version;
    uint8_t   respcode;
    uint8_t   reserved; /* 0x00 */
    uint8_t   addrtype;
    ipaddr4_t ipaddr4;
    portno_t  portnum;
} __attribute__((packed)) socks5_ipv4resp_t;

/* socks5 ipv6-proxy response */
typedef struct {
    uint8_t   version;
    uint8_t   respcode;
    uint8_t   reserved; /* 0x00 */
    uint8_t   addrtype;
    ipaddr6_t ipaddr6;
    portno_t  portnum;
} __attribute__((packed)) socks5_ipv6resp_t;

/* socks5 ipv4-udp message header */
typedef struct {
    uint16_t  reserved; /* 0x0000 */
    uint8_t   fragment;
    uint8_t   addrtype;
    ipaddr4_t ipaddr4;
    portno_t  portnum;
    uint8_t   payload[]; /* sizeof = 0 */
} __attribute__((packed)) socks5_udp4msg_t;

/* socks5 ipv6-udp message header */
typedef struct {
    uint16_t  reserved; /* 0x0000 */
    uint8_t   fragment;
    uint8_t   addrtype;
    ipaddr6_t ipaddr6;
    portno_t  portnum;
    uint8_t   payload[]; /* sizeof = 0 */
} __attribute__((packed)) socks5_udp6msg_t;

#endif
