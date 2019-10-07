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
    OPTION_TCP     = 0x01 << 0, /* enable tcp */
    OPTION_UDP     = 0x01 << 1, /* enable udp */
    OPTION_IPV4    = 0x01 << 2, /* enable ipv4 */
    OPTION_IPV6    = 0x01 << 3, /* enable ipv6 */
    OPTION_DNAT    = 0x01 << 4, /* use REDIRECT instead of TPROXY (for tcp) */
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

/* function declaration in advance */
static void* run_event_loop(void *is_main_thread);

static void tcp_accept_cb(uv_stream_t *listener, int status);

/* static global variable definition */
static bool        g_verbose                 = false;
static uint8_t     g_options                 = OPTION_DEFAULT;
static uint8_t     g_nthreads                = THREAD_NUMBERS_DEFAULT;
static uint32_t    g_tcpbufsiz               = TCP_SKBUFSIZE_DEFAULT;
static uint16_t    g_udpidletmo              = UDP_IDLE_TIMEO_DEFAULT;

static char        g_bind_ipstr4[IP4STRLEN]  = BIND_IPV4_DEFAULT;
static char        g_bind_ipstr6[IP6STRLEN]  = BIND_IPV6_DEFAULT;
static portno_t    g_bind_portno             = BIND_PORT_DEFAULT;
static skaddr4_t   g_bind_skaddr4            = {0};
static skaddr6_t   g_bind_skaddr6            = {0};

static bool        g_server_isipv4           = true;
static char        g_server_ipstr[IP6STRLEN] = {0};
static portno_t    g_server_portno           = 0;
static skaddr6_t   g_server_skaddr           = {0};

static uv_poll_t*  g_udp_listener4           = NULL;
static uv_poll_t*  g_udp_listener6           = NULL;
static lrucache_t* g_udp_clntcache           = NULL;
static lrucache_t* g_udp_servcache           = NULL;

/* print command help information */
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

/* parsing command line arguments */
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
                if (strlen(optarg) + 1 > IP6STRLEN) {
                    printf("[parse_command_args] ip address max length is 45: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                if (get_ipstr_family(optarg) == -1) {
                    printf("[parse_command_args] invalid server ip address: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                g_server_isipv4 = get_ipstr_family(optarg) == AF_INET;
                strcpy(g_server_ipstr, optarg);
                break;
            case 'p':
                if (strlen(optarg) + 1 > PORTSTRLEN) {
                    printf("[parse_command_args] port number max length is 5: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                g_server_portno = strtol(optarg, NULL, 10);
                if (g_server_portno == 0) {
                    printf("[parse_command_args] invalid server port number: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'b':
                if (strlen(optarg) + 1 > IP4STRLEN) {
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
                if (strlen(optarg) + 1 > IP6STRLEN) {
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
                if (strlen(optarg) + 1 > PORTSTRLEN) {
                    printf("[parse_command_args] port number max length is 5: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                g_bind_portno = strtol(optarg, NULL, 10);
                if (g_bind_portno == 0) {
                    printf("[parse_command_args] invalid listen port number: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'j':
                g_nthreads = strtol(optarg, NULL, 10);
                if (g_nthreads == 0) {
                    printf("[parse_command_args] invalid number of worker threads: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'n':
                set_nofile_limit(strtol(optarg, NULL, 10));
                break;
            case 'o':
                g_udpidletmo = strtol(optarg, NULL, 10);
                if (g_udpidletmo == 0) {
                    printf("[parse_command_args] invalid udp socket idle timeout: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'c':
                if (strtol(optarg, NULL, 10) == 0) {
                    printf("[parse_command_args] invalid maxsize of udp lrucache: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                lrucache_set_maxsize(strtol(optarg, NULL, 10));
                break;
            case 'f':
                g_tcpbufsiz = strtol(optarg, NULL, 10);
                if (g_tcpbufsiz < TCP_SKBUFSIZE_MINIMUM) {
                    printf("[parse_command_args] buffer should have at least 1024B: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'R':
                g_options |= OPTION_DNAT;
                break;
            case 'T':
                g_options &= ~OPTION_UDP;
                break;
            case 'U':
                g_options &= ~OPTION_TCP;
                break;
            case '4':
                g_options &= ~OPTION_IPV6;
                break;
            case '6':
                g_options &= ~OPTION_IPV4;
                break;
            case 'v':
                g_verbose = true;
                break;
            case 'V':
                printf(IPT2SOCKS_VERSION"\n");
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

    if (strlen(g_server_ipstr) == 0) {
        printf("[parse_command_args] missing option: '-s/--server-addr'\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (g_server_portno == 0) {
        printf("[parse_command_args] missing option: '-p/--server-port'\n");
        goto PRINT_HELP_AND_EXIT;
    }

    if (!(g_options & (OPTION_TCP | OPTION_UDP))) {
        printf("[parse_command_args] both tcp and udp are disabled, nothing to do\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (!(g_options & (OPTION_IPV4 | OPTION_IPV6))) {
        printf("[parse_command_args] both ipv4 and ipv6 are disabled, nothing to do\n");
        goto PRINT_HELP_AND_EXIT;
    }

    if (!(g_options & OPTION_TCP)) g_nthreads = 1;

    if (g_options & OPTION_DNAT) {
        strcpy(g_bind_ipstr4, IP4STR_WILDCARD);
        strcpy(g_bind_ipstr6, IP6STR_WILDCARD);
    }

    build_ipv4_addr(&g_bind_skaddr4, g_bind_ipstr4, g_bind_portno);
    build_ipv6_addr(&g_bind_skaddr6, g_bind_ipstr6, g_bind_portno);

    if (g_server_isipv4) {
        build_ipv4_addr((void *)&g_server_skaddr, g_server_ipstr, g_server_portno);
    } else {
        build_ipv6_addr((void *)&g_server_skaddr, g_server_ipstr, g_server_portno);
    }
    return;

PRINT_HELP_AND_EXIT:
    print_command_help();
    exit(1);
}

/* main entry */
int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 256);
    parse_command_args(argc, argv);

    LOGINF("[main] server address: %s#%hu", g_server_ipstr, g_server_portno);
    if (g_options & OPTION_IPV4) LOGINF("[main] listen address: %s#%hu", g_bind_ipstr4, g_bind_portno);
    if (g_options & OPTION_IPV6) LOGINF("[main] listen address: %s#%hu", g_bind_ipstr6, g_bind_portno);
    LOGINF("[main] number of worker threads: %hhu", g_nthreads);
    LOGINF("[main] udp socket idle timeout: %hu", g_udpidletmo);
    LOGINF("[main] udp cache maximum size: %hu", lrucache_get_maxsize());
    LOGINF("[main] tcp socket buffer size: %u", g_tcpbufsiz);
    if (g_options & OPTION_TCP) LOGINF("[main] enable tcp transparent proxy");
    if (g_options & OPTION_UDP) LOGINF("[main] enable udp transparent proxy");
    if (g_options & OPTION_DNAT) LOGINF("[main] use redirect instead of tproxy");
    IF_VERBOSE LOGINF("[main] verbose mode (affect performance)");

    for (int i = 0; i < g_nthreads - 1; ++i) {
        if (pthread_create(&(pthread_t){0}, NULL, run_event_loop, NULL)) {
            LOGERR("[main] failed to create thread: (%d) %s", errno, errstring(errno));
            return errno;
        }
    }
    run_event_loop((void *)1); /* blocking here */

    return 0;
}

/* event loop */
static void* run_event_loop(void *is_main_thread) {
    uv_loop_t *evloop = &(uv_loop_t){0};
    uv_loop_init(evloop);

    if (g_options & OPTION_TCP) {
        if (g_options & OPTION_IPV4) {
            uv_tcp_t *tcplistener = malloc(sizeof(uv_tcp_t));
            tcplistener->data = (void *)1; /* is_ipv4 */
            uv_tcp_init(evloop, tcplistener);
            uv_tcp_open(tcplistener, (g_options & OPTION_DNAT) ? new_tcp4_bindsock() : new_tcp4_bindsock_tproxy());
            int retval = uv_tcp_bind(tcplistener, (void *)&g_bind_skaddr4, 0);
            if (retval < 0) {
                LOGERR("[run_event_loop] failed to bind address for tcp4 socket: (%d) %s", -retval, uv_strerror(retval));
                exit(-retval);
            }
            retval = uv_listen((void *)tcplistener, SOMAXCONN, tcp_accept_cb);
            if (retval < 0) {
                LOGERR("[run_event_loop] failed to listen address for tcp4 socket: (%d) %s", -retval, uv_strerror(retval));
                exit(-retval);
            }
        }
        if (g_options & OPTION_IPV6) {
            uv_tcp_t *tcplistener = malloc(sizeof(uv_tcp_t));
            tcplistener->data = NULL; /* is_ipv4 */
            uv_tcp_init(evloop, tcplistener);
            uv_tcp_open(tcplistener, (g_options & OPTION_DNAT) ? new_tcp6_bindsock() : new_tcp6_bindsock_tproxy());
            int retval = uv_tcp_bind(tcplistener, (void *)&g_bind_skaddr6, 0);
            if (retval < 0) {
                LOGERR("[run_event_loop] failed to bind address for tcp6 socket: (%d) %s", -retval, uv_strerror(retval));
                exit(-retval);
            }
            retval = uv_listen((void *)tcplistener, SOMAXCONN, tcp_accept_cb);
            if (retval < 0) {
                LOGERR("[run_event_loop] failed to listen address for tcp6 socket: (%d) %s", -retval, uv_strerror(retval));
                exit(-retval);
            }
        }
    }

    if ((g_options & OPTION_UDP) && is_main_thread) {
        // TODO
    }

    uv_run(evloop, UV_RUN_DEFAULT);
    return NULL;
}

static void tcp_accept_cb(uv_stream_t *listener, int status) {
    // TODO
}
