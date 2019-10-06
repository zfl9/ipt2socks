#define _GNU_SOURCE
#include "logutils.h"
#include "lrucache.h"
#include "netutils.h"
#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#undef _GNU_SOURCE

/* option flags */
enum {
    OPTION_TCP     = 1 << 0, /* enable tcp */
    OPTION_UDP     = 1 << 1, /* enable udp */
    OPTION_IPV4    = 1 << 2, /* enable ipv4 */
    OPTION_IPV6    = 1 << 3, /* enable ipv6 */
    OPTION_DNAT    = 1 << 4, /* use REDIRECT instead of TPROXY (for tcp) */
    OPTION_DEFAULT = OPTION_TCP | OPTION_UDP | OPTION_IPV4 | OPTION_IPV6, /* default behavior */
};

/* if verbose logging */
#define IF_VERBOSE if (g_verbose)

/* number of threads */
#define THREAD_NUMBERS_DEFAULT 1

/* udp idle timeout(sec) */
#define UDP_IDLE_TIMEO_DEFAULT 300

/* tcp socket buffer size */
#define TCP_SKBUFSIZE_MINIMUM 1024
#define TCP_SKBUFSIZE_DEFAULT 8192

/* ipt2socks bind address */
#define BIND_IPV4_DEFAULT IP4STR_LOOPBACK
#define BIND_IPV6_DEFAULT IP6STR_LOOPBACK
#define BIND_PORT_DEFAULT 60080

/* ipt2socks version string */
#define IPT2SOCKS_VERSION "ipt2socks v1.0-beta.1 <https://github.com/zfl9/ipt2socks>"

static void print_command_help(void) {
    printf("usage: ipt2socks <options...>. the existing options are as follows:\n"
           " -s, --server-addr <addr>           socks5 server ip address, <required>\n"
           " -p, --server-port <port>           socks5 server port number, <required>\n"
           " -b, --listen-addr4 <addr>          listen ipv4 address, default: 127.0.0.1\n" 
           " -B, --listen-addr6 <addr>          listen ipv6 address, default: ::1\n"
           " -l, --listen-port <port>           listen port number, default: 60080\n"
           " -j, --thread-nums <num>            number of worker threads, default: 1\n"
           " -n, --nofile-limit <num>           set nofile limit, maybe need root priv\n"
           " -o, --udp-timeout <sec>            udp socket idle timeout, default: 300\n"
           " -c, --cache-size <size>            max size of udp lrucache, default: 256\n"
           " -f, --buffer-size <size>           buffer size of tcp socket, default: 8192\n"
           " -R, --redirect                     use redirect instead of tproxy (for tcp)\n"
           " -T, --tcp-only                     listen tcp only, aka: disable udp proxy\n"
           " -U, --udp-only                     listen udp only, aka: disable tcp proxy\n"
           " -4, --ipv4-only                    listen ipv4 only, aka: disable ipv6 proxy\n"
           " -6, --ipv6-only                    listen ipv6 only, aka: disable ipv4 proxy\n"
           " -v, --verbose                      print verbose log, default: <disabled>\n"
           " -V, --version                      print ipt2socks version number and exit\n"
           " -h, --help                         print ipt2socks help information and exit\n"
    );
}

int main() {
    print_command_help();
    return 0;
}
