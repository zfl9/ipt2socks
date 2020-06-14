#ifndef IPT2SOCKS_PROTOCOL_H
#define IPT2SOCKS_PROTOCOL_H

#define _GNU_SOURCE
#include "netutils.h"

/* socks5 protocol version number */
#define SOCKS5_VERSION 0x05

/* method code constant definition */
#define SOCKS5_METHOD_NOAUTH 0x00
#define SOCKS5_METHOD_USRPWD 0x02

/* usrpwd-auth constant definition */
#define SOCKS5_USRPWD_VERSION 0x01
#define SOCKS5_USRPWD_AUTHSUCC 0x00
#define SOCKS5_USRPWD_USRMAXLEN 255
#define SOCKS5_USRPWD_PWDMAXLEN 255
#define SOCKS5_USRPWD_REQMAXLEN (1 + 1 + SOCKS5_USRPWD_USRMAXLEN + 1 + SOCKS5_USRPWD_PWDMAXLEN)

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

/* socks5 username-password request */
typedef struct {
    uint8_t version; /* 0x01 */
    // USERNAME_LEN, sizeof=1, range=1~255
    // USERNAME_STR, sizeof=1~255, without '\0'
    // PASSWORD_LEN, sizeof=1, range=1~255
    // PASSWORD_STR, sizeof=1~255, without '\0'
} __attribute__((packed)) socks5_usrpwdreq_t;

/* socks5 username-password response */
typedef struct {
    uint8_t version; /* 0x01 */
    uint8_t respcode; /* 0x00=SUCC, other=FAIL */
} __attribute__((packed)) socks5_usrpwdresp_t;

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
    uint8_t   fragment; /* 0x00 */
    uint8_t   addrtype;
    ipaddr4_t ipaddr4;
    portno_t  portnum;
    uint8_t   payload[]; /* sizeof = 0 */
} __attribute__((packed)) socks5_udp4msg_t;

/* socks5 ipv6-udp message header */
typedef struct {
    uint16_t  reserved; /* 0x0000 */
    uint8_t   fragment; /* 0x00 */
    uint8_t   addrtype;
    ipaddr6_t ipaddr6;
    portno_t  portnum;
    uint8_t   payload[]; /* sizeof = 0 */
} __attribute__((packed)) socks5_udp6msg_t;

extern socks5_authreq_t g_socks5_auth_request;

extern char     g_socks5_usrpwd_request[];
extern uint16_t g_socks5_usrpwd_requestlen;

extern const socks5_ipv4req_t G_SOCKS5_UDP4_REQUEST;
extern const socks5_ipv6req_t G_SOCKS5_UDP6_REQUEST;

void socks5_usrpwd_request_make(const char *username, const char *password);
void socks5_proxy_request_make(socks5_ipv4req_t *request, const void *skaddr);

bool socks5_auth_response_check(const char *funcname, const socks5_authresp_t *response);
bool socks5_usrpwd_response_check(const char *funcname, const socks5_usrpwdresp_t *response);
bool socks5_proxy_response_check(const char *funcname, const socks5_ipv4resp_t *response);

#endif
