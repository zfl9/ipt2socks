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

static bool     g_verbose    = false;
static uint8_t  g_options    = OPTION_DEFAULT;
static uint8_t  g_nthreads   = THREAD_NUMBERS_DEFAULT;
static uint32_t g_tcpbufsiz  = TCP_SKBUFSIZE_DEFAULT;
static uint16_t g_udpidletmo = UDP_IDLE_TIMEO_DEFAULT;

static char      g_bind_ipstr4[IP4STRLEN] = BIND_IPV4_DEFAULT;
static char      g_bind_ipstr6[IP6STRLEN] = BIND_IPV6_DEFAULT;
static portno_t  g_bind_portno            = BIND_PORT_DEFAULT;
static skaddr4_t g_bind_skaddr4           = {0};
static skaddr6_t g_bind_skaddr6           = {0};

static bool      g_server_isipv4           = true;
static char      g_server_ipstr[IP6STRLEN] = {0};
static char      g_server_portno           = 0;
static skaddr6_t g_server_skaddr           = {0};

static uv_poll_t*  g_udp_listener = NULL;
static lrucache_t* g_udp_cltcache = NULL;
static lrucache_t* g_udp_svrcache = NULL;

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

static void parse_command_args(int argc, char* argv[]) {
    const char *optstr = ":s:p:b:B:l:j:n:o:c:f:RTU46vVh";
    const struct option options[] = {
        {"server-addr",   required_argument, NULL, 's'},
        {"server-port",   required_argument, NULL, 'p'},
        {"listen-addr4",  required_argument, NULL, 'b'},
        {"listen-addr6",  required_argument, NULL, 'B'},
        {"listen-port",   required_argument, NULL, 'l'},
        {"thread-nums",   required_argument, NULL, 'j'},
        {"nofile-limit",  required_argument, NULL, 'n'},
        {"udp-timeout",   required_argument, NULL, 'o'},
        {"cache-size",    required_argument, NULL, 'c'},
        {"buffer-size",   required_argument, NULL, 'f'},
        {"redirect",      no_argument,       NULL, 'R'},
        {"tcp-only",      no_argument,       NULL, 'T'},
        {"udp-only",      no_argument,       NULL, 'U'},
        {"ipv4-only",     no_argument,       NULL, '4'},
        {"ipv6-only",     no_argument,       NULL, '6'},
        {"verbose",       no_argument,       NULL, 'v'},
        {"version",       no_argument,       NULL, 'V'},
        {"help",          no_argument,       NULL, 'h'},
        {NULL,            0,                 NULL,   0},
    };

    opterr = 0;
    int optindex = -1;
    int shortopt = -1;
    while ((shortopt = getopt_long(argc, argv, optstr, options, &optindex)) != -1) {
        switch (shortopt) {
            case 's':
                if (strlen(optarg) + 1 > DOMAIN_NAME_STRLEN) {
                    printf("[parse_command_args] domain name max length is 253: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                strcpy(g_svr_vhost, optarg);
                break;
            case 'S':
                if (get_ipstr_family(optarg) == -1 && strlen(optarg) + 1 > DOMAIN_NAME_STRLEN) {
                    printf("[parse_command_args] domain name max length is 253: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                opt_server_addr = optarg;
                break;
            case 'P':
                if (strlen(optarg) + 1 > PORTSTR_MAXLEN) {
                    printf("[parse_command_args] port number max length is 5: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                g_svr_port = strtol(optarg, NULL, 10);
                if (g_svr_port == 0) {
                    printf("[parse_command_args] invalid server port number: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'p':
                if (strlen(optarg) > HTTP_REQUEST_BUFLEN / 4) {
                    printf("[parse_command_args] http uri path is too long: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                opt_server_path = optarg;
                break;
            case 'k':
                if (strlen(optarg) > HTTP_REQUEST_BUFLEN / 4) {
                    printf("[parse_command_args] http password is too long: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                opt_server_passwd = optarg;
                break;
            case 'm':
                if (strcmp(SSL_CIPHER_CHACHA20_ALIAS,  optarg) == 0) { g_ssl_cipher = SSL_CIPHER_CHACHA20_VALUE;  break; }
                if (strcmp(SSL_CIPHER_AES128GCM_ALIAS, optarg) == 0) { g_ssl_cipher = SSL_CIPHER_AES128GCM_VALUE; break; }
                if (strcmp(SSL_CIPHER_AES256GCM_ALIAS, optarg) == 0) { g_ssl_cipher = SSL_CIPHER_AES256GCM_VALUE; break; }
                printf("[parse_command_args] unknown openssl cipher name: %s\n", optarg);
                goto PRINT_HELP_AND_EXIT;
            case 'C':
                if (strlen(optarg) + 1 > PATH_MAX) {
                    printf("[parse_command_args] file path max length is 4095: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                opt_cafile_path = optarg;
                break;
            case 'b':
                if (strlen(optarg) + 1 > INET_ADDRSTRLEN) {
                    printf("[parse_command_args] ipv4 address max length is 15: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                if (get_ipstr_family(optarg) != AF_INET) {
                    printf("[parse_command_args] invalid listen ipv4 address: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                strcpy(g_bind_ipstr4, optarg);
                break;
            case 'B':
                if (strlen(optarg) + 1 > INET6_ADDRSTRLEN) {
                    printf("[parse_command_args] ipv6 address max length is 45: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                if (get_ipstr_family(optarg) != AF_INET6) {
                    printf("[parse_command_args] invalid listen ipv6 address: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                strcpy(g_bind_ipstr6, optarg);
                break;
            case 'l':
                if (strlen(optarg) + 1 > PORTSTR_MAXLEN) {
                    printf("[parse_command_args] port number max length is 5: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                g_bind_port = strtol(optarg, NULL, 10);
                if (g_bind_port == 0) {
                    printf("[parse_command_args] invalid listen port number: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'j':
                g_process_num = strtol(optarg, NULL, 10);
                if (g_process_num == 0) {
                    printf("[parse_command_args] invalid number of work processes: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'n':
                set_nofile_limit(strtol(optarg, NULL, 10));
                break;
            case 'a':
                g_udp_ack_wait_sec = strtol(optarg, NULL, 10);
                if (g_udp_ack_wait_sec == 0) {
                    printf("[parse_command_args] invalid udp tunnel ack timeout val: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'o':
                g_udp_idle_timeout = strtol(optarg, NULL, 10);
                if (g_udp_idle_timeout == 0) {
                    printf("[parse_command_args] invalid udp socket idle timeout val: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'c':
                if (strtol(optarg, NULL, 10) < 1) {
                    printf("[parse_command_args] invalid maxsize of the udp lrucache: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                lrucache_set_maxsize(strtol(optarg, NULL, 10));
                break;
            case 'F':
                g_bev_buffsize = strtol(optarg, NULL, 10);
                if (g_bev_buffsize < BEV_BUFFER_SIZE_MINIMUM) {
                    printf("[parse_command_args] buffer should have at least 1024 bytes: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'G':
                if (strlen(optarg) + 1 > PATH_MAX) {
                    printf("[parse_command_args] the path to the logfile is too long: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                strcpy(g_logfile, optarg);
                break;
            case 'D':
                if (strlen(optarg) + 1 > PATH_MAX) {
                    printf("[parse_command_args] the path to the pidfile is too long: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                strcpy(g_pidfile, optarg);
                break;
            case 'R':
                g_flags |= OPTION_DNAT;
                break;
            case 'T':
                g_flags &= ~OPTION_UDP;
                break;
            case 'U':
                g_flags &= ~OPTION_TCP;
                break;
            case '4':
                g_flags &= ~OPTION_IPV6;
                break;
            case '6':
                g_flags &= ~OPTION_IPV4;
                break;
            case 'd':
                g_daemon = true;
                break;
            case 'v':
                g_verbose = true;
                break;
            case 'V':
                printf(TLS_CLIENT_VERSION"\n");
                exit(0);
            case 'h':
                print_command_help();
                exit(0);
            case ':':
                printf("[parse_command_args] missing optarg: '%s'\n", argv[optind - 1]);
                goto PRINT_HELP_AND_EXIT;
            case '?':
                if (optopt) {
                    printf("[parse_command_args] unknown option: '-%c'\n", optopt);
                } else {
                    char *longopt = argv[optind - 1];
                    char *equalsign = strchr(longopt, '=');
                    if (equalsign) *equalsign = 0;
                    printf("[parse_command_args] unknown option: '%s'\n", longopt);
                }
                goto PRINT_HELP_AND_EXIT;
        }
    }
}

int main() {
    print_command_help();
    return 0;
}
