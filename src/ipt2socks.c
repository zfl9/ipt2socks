#define _GNU_SOURCE
#include "logutils.h"
#include "lrucache.h"
#include "netutils.h"
#include "protocol.h"
#include "../libev/ev.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

/* splice() api */
#ifndef SPLICE_F_MOVE
  #include <sys/syscall.h>

  #undef  SPLICE_F_MOVE
  #define SPLICE_F_MOVE 1

  #undef  SPLICE_F_NONBLOCK
  #define SPLICE_F_NONBLOCK 2

  #define splice(fdin, offin, fdout, offout, len, flags) syscall(__NR_splice, fdin, offin, fdout, offout, len, flags)
#endif

#define IF_VERBOSE if (g_verbose)

#define TCP_SPLICE_MAXLEN 65535 /* uint16_t: 0~65535 */

#define IPT2SOCKS_VERSION "ipt2socks v1.1.4 <https://github.com/zfl9/ipt2socks>"

enum {
    OPT_ENABLE_TCP         = 0x01 << 0, // enable tcp proxy
    OPT_ENABLE_UDP         = 0x01 << 1, // enable udp proxy
    OPT_ENABLE_IPV4        = 0x01 << 2, // enable ipv4 proxy
    OPT_ENABLE_IPV6        = 0x01 << 3, // enable ipv6 proxy
    OPT_TCP_USE_REDIRECT   = 0x01 << 4, // use redirect instead of tproxy (used by tcp)
    OPT_ALWAYS_REUSE_PORT  = 0x01 << 5, // always enable so_reuseport (since linux 3.9+)
    OPT_ENABLE_TFO_ACCEPT  = 0x01 << 6, // enable tcp_fastopen for listen socket (server tfo)
    OPT_ENABLE_TFO_CONNECT = 0x01 << 7, // enable tcp_fastopen for connect socket (client tfo)
};

typedef struct {
    evio_t   client_watcher;   // .data: socks5 mesg
    evio_t   socks5_watcher;   // .data: socks5 mesg
    int      client_pipefd[2]; // client pipe buffer
    int      socks5_pipefd[2]; // socks5 pipe buffer
    uint16_t client_length;    // nrecv/nsend, npipe
    uint16_t socks5_length;    // nrecv/nsend, npipe
} tcp_context_t;

static void* run_event_loop(void *is_main_thread);

static void tcp_tproxy_accept_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_connect_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_send_authreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_recv_authresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_send_usrpwdreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_send_proxyreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_recv_proxyresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_stream_payload_forward_cb(evloop_t *evloop, evio_t *watcher, int revents);

static void udp_tproxy_recvmsg_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_connect_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_send_authreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_authresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_send_usrpwdreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_send_proxyreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_proxyresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_tcpmessage_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_udpmessage_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_context_timeout_cb(evloop_t *evloop, evtimer_t *watcher, int revents);
static void udp_tproxy_context_timeout_cb(evloop_t *evloop, evtimer_t *watcher, int revents);

static bool     g_verbose  = false;
static uint16_t g_options  = OPT_ENABLE_TCP | OPT_ENABLE_UDP | OPT_ENABLE_IPV4 | OPT_ENABLE_IPV6;
static uint8_t  g_nthreads = 1;

static char      g_bind_ipstr4[IP4STRLEN] = IP4STR_LOOPBACK;
static char      g_bind_ipstr6[IP6STRLEN] = IP6STR_LOOPBACK;
static portno_t  g_bind_portno            = 60080;
static skaddr4_t g_bind_skaddr4           = {0};
static skaddr6_t g_bind_skaddr6           = {0};

static char      g_server_ipstr[IP6STRLEN] = "127.0.0.1";
static portno_t  g_server_portno           = 1080;
static skaddr6_t g_server_skaddr           = {0};

static uint8_t g_tcp_syncnt_max = 0; // 0: use default syncnt

static uint16_t         g_udp_idletimeout_sec                   = 60;
static udp_socks5ctx_t *g_udp_socks5ctx_table                   = NULL;
static udp_tproxyctx_t *g_udp_tproxyctx_table                   = NULL;
static char             g_udp_dgram_buffer[UDP_DATAGRAM_MAXSIZ] = {0};

static void print_command_help(void) {
    printf("usage: ipt2socks <options...>. the existing options are as follows:\n"
           " -s, --server-addr <addr>           socks5 server ip, default: 127.0.0.1\n"
           " -p, --server-port <port>           socks5 server port, default: 1080\n"
           " -a, --auth-username <user>         username for socks5 authentication\n"
           " -k, --auth-password <passwd>       password for socks5 authentication\n"
           " -b, --listen-addr4 <addr>          listen ipv4 address, default: 127.0.0.1\n"
           " -B, --listen-addr6 <addr>          listen ipv6 address, default: ::1\n"
           " -l, --listen-port <port>           listen port number, default: 60080\n"
           " -S, --tcp-syncnt <cnt>             change the number of tcp syn retransmits\n"
           " -c, --cache-size <size>            udp context cache maxsize, default: 256\n"
           " -o, --udp-timeout <sec>            udp context idle timeout, default: 60\n"
           " -j, --thread-nums <num>            number of the worker threads, default: 1\n"
           " -n, --nofile-limit <num>           set nofile limit, may need root privilege\n"
           " -u, --run-user <user>              run as the given user, need root privilege\n"
           " -T, --tcp-only                     listen tcp only, aka: disable udp proxy\n"
           " -U, --udp-only                     listen udp only, aka: disable tcp proxy\n"
           " -4, --ipv4-only                    listen ipv4 only, aka: disable ipv6 proxy\n"
           " -6, --ipv6-only                    listen ipv6 only, aka: disable ipv4 proxy\n"
           " -R, --redirect                     use redirect instead of tproxy for tcp\n"
           " -r, --reuse-port                   enable so_reuseport for single thread\n"
           " -w, --tfo-accept                   enable tcp_fastopen for server socket\n"
           " -W, --tfo-connect                  enable tcp_fastopen for client socket\n"
           " -v, --verbose                      print verbose log, affect performance\n"
           " -V, --version                      print ipt2socks version number and exit\n"
           " -h, --help                         print ipt2socks help information and exit\n"
    );
}

static void parse_command_args(int argc, char* argv[]) {
    opterr = 0; /* disable errmsg print, can get error by retval '?' */
    const char *optstr = ":s:p:a:k:b:B:l:S:c:o:j:n:u:TU46RrwWvVh";
    const struct option options[] = {
        {"server-addr",   required_argument, NULL, 's'},
        {"server-port",   required_argument, NULL, 'p'},
        {"auth-username", required_argument, NULL, 'a'},
        {"auth-password", required_argument, NULL, 'k'},
        {"listen-addr4",  required_argument, NULL, 'b'},
        {"listen-addr6",  required_argument, NULL, 'B'},
        {"listen-port",   required_argument, NULL, 'l'},
        {"tcp-syncnt",    required_argument, NULL, 'S'},
        {"cache-size",    required_argument, NULL, 'c'},
        {"udp-timeout",   required_argument, NULL, 'o'},
        {"thread-nums",   required_argument, NULL, 'j'},
        {"nofile-limit",  required_argument, NULL, 'n'},
        {"run-user",      required_argument, NULL, 'u'},
        {"tcp-only",      no_argument,       NULL, 'T'},
        {"udp-only",      no_argument,       NULL, 'U'},
        {"ipv4-only",     no_argument,       NULL, '4'},
        {"ipv6-only",     no_argument,       NULL, '6'},
        {"redirect",      no_argument,       NULL, 'R'},
        {"reuse-port",    no_argument,       NULL, 'r'},
        {"tfo-accept",    no_argument,       NULL, 'w'},
        {"tfo-connect",   no_argument,       NULL, 'W'},
        {"verbose",       no_argument,       NULL, 'v'},
        {"version",       no_argument,       NULL, 'V'},
        {"help",          no_argument,       NULL, 'h'},
        {NULL,            0,                 NULL,   0},
    };

    const char *optval_auth_username = NULL;
    const char *optval_auth_password = NULL;

    int shortopt = -1;
    while ((shortopt = getopt_long(argc, argv, optstr, options, NULL)) != -1) {
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
                strcpy(g_server_ipstr, optarg);
                break;
            case 'p':
                if (strlen(optarg) + 1 > PORTSTRLEN) {
                    printf("[parse_command_args] port number max length is 5: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                g_server_portno = strtoul(optarg, NULL, 10);
                if (g_server_portno == 0) {
                    printf("[parse_command_args] invalid server port number: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'a':
                if (strlen(optarg) > SOCKS5_USRPWD_USRMAXLEN) {
                    printf("[parse_command_args] socks5 username max length is 255: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                optval_auth_username = optarg;
                break;
            case 'k':
                if (strlen(optarg) > SOCKS5_USRPWD_PWDMAXLEN) {
                    printf("[parse_command_args] socks5 password max length is 255: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                optval_auth_password = optarg;
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
                g_bind_portno = strtoul(optarg, NULL, 10);
                if (g_bind_portno == 0) {
                    printf("[parse_command_args] invalid listen port number: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'S':
                g_tcp_syncnt_max = strtoul(optarg, NULL, 10);
                if (g_tcp_syncnt_max == 0) {
                    printf("[parse_command_args] invalid number of syn retransmits: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'c':
                if (strtoul(optarg, NULL, 10) == 0) {
                    printf("[parse_command_args] invalid maxsize of udp lrucache: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                lrucache_set_maxsize(strtoul(optarg, NULL, 10));
                break;
            case 'o':
                g_udp_idletimeout_sec = strtoul(optarg, NULL, 10);
                if (g_udp_idletimeout_sec == 0) {
                    printf("[parse_command_args] invalid udp socket idle timeout: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'j':
                g_nthreads = strtoul(optarg, NULL, 10);
                if (g_nthreads == 0) {
                    printf("[parse_command_args] invalid number of worker threads: %s\n", optarg);
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'n':
                set_nofile_limit(strtoul(optarg, NULL, 10));
                break;
            case 'u':
                run_as_user(optarg, argv);
                break;
            case 'T':
                g_options &= ~OPT_ENABLE_UDP;
                break;
            case 'U':
                g_options &= ~OPT_ENABLE_TCP;
                break;
            case '4':
                g_options &= ~OPT_ENABLE_IPV6;
                break;
            case '6':
                g_options &= ~OPT_ENABLE_IPV4;
                break;
            case 'R':
                g_options |= OPT_TCP_USE_REDIRECT;
                strcpy(g_bind_ipstr4, IP4STR_WILDCARD);
                strcpy(g_bind_ipstr6, IP6STR_WILDCARD);
                break;
            case 'r':
                g_options |= OPT_ALWAYS_REUSE_PORT;
                break;
            case 'w':
                g_options |= OPT_ENABLE_TFO_ACCEPT;
                break;
            case 'W':
                g_options |= OPT_ENABLE_TFO_CONNECT;
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

    if (!(g_options & (OPT_ENABLE_TCP | OPT_ENABLE_UDP))) {
        printf("[parse_command_args] both tcp and udp are disabled, nothing to do\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (!(g_options & (OPT_ENABLE_IPV4 | OPT_ENABLE_IPV6))) {
        printf("[parse_command_args] both ipv4 and ipv6 are disabled, nothing to do\n");
        goto PRINT_HELP_AND_EXIT;
    }

    if (optval_auth_username && !optval_auth_password) {
        printf("[parse_command_args] username specified, but password is not provided\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (!optval_auth_username && optval_auth_password) {
        printf("[parse_command_args] password specified, but username is not provided\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (optval_auth_username && optval_auth_password) {
        socks5_usrpwd_request_make(optval_auth_username, optval_auth_password);
    }

    if (!(g_options & OPT_ENABLE_TCP)) g_nthreads = 1;

    build_socket_addr(AF_INET, &g_bind_skaddr4, g_bind_ipstr4, g_bind_portno);
    build_socket_addr(AF_INET6, &g_bind_skaddr6, g_bind_ipstr6, g_bind_portno);
    build_socket_addr(get_ipstr_family(g_server_ipstr), &g_server_skaddr, g_server_ipstr, g_server_portno);
    return;

PRINT_HELP_AND_EXIT:
    print_command_help();
    exit(1);
}

int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 256);
    parse_command_args(argc, argv);

    LOGINF("[main] server address: %s#%hu", g_server_ipstr, g_server_portno);
    if (g_options & OPT_ENABLE_IPV4) LOGINF("[main] listen address: %s#%hu", g_bind_ipstr4, g_bind_portno);
    if (g_options & OPT_ENABLE_IPV6) LOGINF("[main] listen address: %s#%hu", g_bind_ipstr6, g_bind_portno);
    if (g_tcp_syncnt_max) LOGINF("[main] max number of syn retries: %hhu", g_tcp_syncnt_max);
    LOGINF("[main] udp session cache capacity: %hu", lrucache_get_maxsize());
    LOGINF("[main] udp session idle timeout: %hu", g_udp_idletimeout_sec);
    LOGINF("[main] number of worker threads: %hhu", g_nthreads);
    LOGINF("[main] max file descriptor limit: %zu", get_nofile_limit());
    if (g_options & OPT_ENABLE_TCP) LOGINF("[main] enable tcp transparent proxy");
    if (g_options & OPT_ENABLE_UDP) LOGINF("[main] enable udp transparent proxy");
    if (g_options & OPT_TCP_USE_REDIRECT) LOGINF("[main] use redirect instead of tproxy");
    if (g_options & OPT_ALWAYS_REUSE_PORT) LOGINF("[main] always enable reuseport feature");
    if (g_options & OPT_ENABLE_TFO_ACCEPT) LOGINF("[main] enable tfo for tcp server socket");
    if (g_options & OPT_ENABLE_TFO_CONNECT) LOGINF("[main] enable tfo for tcp client socket");
    IF_VERBOSE LOGINF("[main] verbose mode (affect performance)");

    for (int i = 0; i < g_nthreads - 1; ++i) {
        if (pthread_create(&(pthread_t){0}, NULL, run_event_loop, NULL)) {
            LOGERR("[main] create worker thread: %s", strerror(errno));
            return errno;
        }
    }
    run_event_loop((void *)1);

    return 0;
}

static void* run_event_loop(void *is_main_thread) {
    evloop_t *evloop = ev_loop_new(0);

    if (g_options & OPT_ENABLE_TCP) {
        bool is_tproxy = !(g_options & OPT_TCP_USE_REDIRECT);
        bool is_tfo_accept = g_options & OPT_ENABLE_TFO_ACCEPT;
        bool is_reuse_port = g_nthreads > 1 || (g_options & OPT_ALWAYS_REUSE_PORT);

        if (g_options & OPT_ENABLE_IPV4) {
            int sockfd = new_tcp_listen_sockfd(AF_INET, is_tproxy, is_reuse_port, is_tfo_accept);

            if (bind(sockfd, (void *)&g_bind_skaddr4, sizeof(skaddr4_t)) < 0) {
                LOGERR("[run_event_loop] bind tcp4 address: %s", strerror(errno));
                exit(errno);
            }
            if (listen(sockfd, SOMAXCONN) < 0) {
                LOGERR("[run_event_loop] listen tcp4 socket: %s", strerror(errno));
                exit(errno);
            }

            evio_t *watcher = malloc(sizeof(*watcher));
            watcher->data = (void *)1; /* indicates it is ipv4 */
            ev_io_init(watcher, tcp_tproxy_accept_cb, sockfd, EV_READ);
            ev_io_start(evloop, watcher);
        }

        if (g_options & OPT_ENABLE_IPV6) {
            int sockfd = new_tcp_listen_sockfd(AF_INET6, is_tproxy, is_reuse_port, is_tfo_accept);

            if (bind(sockfd, (void *)&g_bind_skaddr6, sizeof(skaddr6_t)) < 0) {
                LOGERR("[run_event_loop] bind tcp6 address: %s", strerror(errno));
                exit(errno);
            }
            if (listen(sockfd, SOMAXCONN) < 0) {
                LOGERR("[run_event_loop] listen tcp6 socket: %s", strerror(errno));
                exit(errno);
            }

            evio_t *watcher = malloc(sizeof(*watcher));
            watcher->data = NULL; /* indicates it not ipv4 */
            ev_io_init(watcher, tcp_tproxy_accept_cb, sockfd, EV_READ);
            ev_io_start(evloop, watcher);
        }
    }

    if ((g_options & OPT_ENABLE_UDP) && is_main_thread) {
        if (g_options & OPT_ENABLE_IPV4) {
            int sockfd = new_udp_tprecv_sockfd(AF_INET);

            if (bind(sockfd, (void *)&g_bind_skaddr4, sizeof(skaddr4_t)) < 0) {
                LOGERR("[run_event_loop] bind udp4 address: %s", strerror(errno));
                exit(errno);
            }

            evio_t *watcher = malloc(sizeof(*watcher));
            watcher->data = (void *)1; /* indicates it is ipv4 */
            ev_io_init(watcher, udp_tproxy_recvmsg_cb, sockfd, EV_READ);
            ev_io_start(evloop, watcher);
        }

        if (g_options & OPT_ENABLE_IPV6) {
            int sockfd = new_udp_tprecv_sockfd(AF_INET6);

            if (bind(sockfd, (void *)&g_bind_skaddr6, sizeof(skaddr6_t)) < 0) {
                LOGERR("[run_event_loop] bind udp6 address: %s", strerror(errno));
                exit(errno);
            }

            evio_t *watcher = malloc(sizeof(*watcher));
            watcher->data = NULL; /* indicates it not ipv4 */
            ev_io_init(watcher, udp_tproxy_recvmsg_cb, sockfd, EV_READ);
            ev_io_start(evloop, watcher);
        }
    }

    ev_run(evloop, 0);
    return NULL;
}

static void tcp_tproxy_accept_cb(evloop_t *evloop, evio_t *accept_watcher, int revents __attribute__((unused))) {
    bool isipv4 = accept_watcher->data;
    skaddr6_t skaddr; char ipstr[IP6STRLEN]; portno_t portno;

    int client_sockfd = tcp_accept(accept_watcher->fd, (void *)&skaddr, &(socklen_t){sizeof(skaddr)});
    if (client_sockfd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[tcp_tproxy_accept_cb] accept tcp%s socket: %s", isipv4 ? "4" : "6", strerror(errno));
        }
        return;
    }
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF("[tcp_tproxy_accept_cb] source socket address: %s#%hu", ipstr, portno);
    }

    if (!get_tcp_orig_dstaddr(isipv4 ? AF_INET : AF_INET6, client_sockfd, &skaddr, !(g_options & OPT_TCP_USE_REDIRECT))) {
        tcp_close_by_rst(client_sockfd);
        return;
    }
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF("[tcp_tproxy_accept_cb] target socket address: %s#%hu", ipstr, portno);
    }

    int socks5_sockfd = new_tcp_connect_sockfd(g_server_skaddr.sin6_family, g_tcp_syncnt_max);
    const void *tfo_data = (g_options & OPT_ENABLE_TFO_CONNECT) ? &g_socks5_auth_request : NULL;
    uint16_t tfo_datalen = (g_options & OPT_ENABLE_TFO_CONNECT) ? sizeof(socks5_authreq_t) : 0;
    ssize_t tfo_nsend = -1; /* if tfo connect succeed: tfo_nsend >= 0 */

    if (!tcp_connect(socks5_sockfd, &g_server_skaddr, tfo_data, tfo_datalen, &tfo_nsend)) {
        LOGERR("[tcp_tproxy_accept_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        tcp_close_by_rst(client_sockfd);
        close(socks5_sockfd);
        return;
    }
    IF_VERBOSE {
        if (tfo_nsend >= 0) {
            LOGINF("[tcp_tproxy_accept_cb] tfo send to %s#%hu, nsend:%zd", g_server_ipstr, g_server_portno, tfo_nsend);
        } else {
            LOGINF("[tcp_tproxy_accept_cb] try to connect to %s#%hu ...", g_server_ipstr, g_server_portno);
        }
    }

    tcp_context_t *context = malloc(sizeof(*context));

    /* if (watcher->events & EV_CUSTOM); then it is client watcher; fi */
    evio_t *watcher = &context->client_watcher;
    ev_io_init(watcher, tcp_stream_payload_forward_cb, client_sockfd, EV_READ | EV_CUSTOM);

    /* build the ipv4/ipv6 proxy request (send to the socks5 proxy server) */
    context->client_watcher.data = malloc(isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t));
    context->client_length = isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t);
    socks5_proxy_request_make(context->client_watcher.data, &skaddr);

    watcher = &context->socks5_watcher;
    if (tfo_nsend >= 0 && (size_t)tfo_nsend >= tfo_datalen) {
        ev_io_init(watcher, tcp_socks5_recv_authresp_cb, socks5_sockfd, EV_READ);
        tfo_nsend = 0; /* reset to zero for next send */
    } else {
        ev_io_init(watcher, tfo_nsend >= 0 ? tcp_socks5_send_authreq_cb : tcp_socks5_connect_cb, socks5_sockfd, EV_WRITE);
        tfo_nsend = tfo_nsend >= 0 ? tfo_nsend : 0;
    }
    ev_io_start(evloop, watcher);

    context->socks5_watcher.data = malloc(sizeof(socks5_ipv6resp_t));
    context->socks5_length = (size_t)tfo_nsend;
}

static inline tcp_context_t* get_tcpctx_by_watcher(evio_t *watcher) {
    if (watcher->events & EV_CUSTOM) {
        return (void *)watcher - offsetof(tcp_context_t, client_watcher);
    } else {
        return (void *)watcher - offsetof(tcp_context_t, socks5_watcher);
    }
}

static inline void tcp_context_release(evloop_t *evloop, tcp_context_t *context, bool is_tcp_reset) {
    evio_t *client_watcher = &context->client_watcher;
    evio_t *socks5_watcher = &context->socks5_watcher;
    ev_io_stop(evloop, client_watcher);
    ev_io_stop(evloop, socks5_watcher);
    if (is_tcp_reset) {
        tcp_close_by_rst(client_watcher->fd);
        tcp_close_by_rst(socks5_watcher->fd);
    } else {
        close(client_watcher->fd);
        close(socks5_watcher->fd);
    }
    if (client_watcher->data || socks5_watcher->data) {
        free(client_watcher->data);
        free(socks5_watcher->data);
    } else {
        close(context->client_pipefd[0]);
        close(context->client_pipefd[1]);
        close(context->socks5_pipefd[0]);
        close(context->socks5_pipefd[1]);
    }
    free(context);
}

static void tcp_socks5_connect_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (tcp_has_error(socks5_watcher->fd)) {
        LOGERR("[tcp_socks5_connect_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        tcp_context_release(evloop, get_tcpctx_by_watcher(socks5_watcher), true);
        return;
    }
    IF_VERBOSE LOGINF("[tcp_socks5_connect_cb] connect to %s#%hu succeeded", g_server_ipstr, g_server_portno);
    ev_set_cb(socks5_watcher, tcp_socks5_send_authreq_cb);
    ev_invoke(evloop, socks5_watcher, EV_WRITE);
}

/* return: -1(error_occurred); 0(partial_sent); 1(completely_sent) */
static int tcp_socks5_send_request(const char *funcname, evloop_t *evloop, evio_t *socks5_watcher, const void *data, size_t datalen) {
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    ssize_t nsend = send(socks5_watcher->fd, data + context->socks5_length, datalen - context->socks5_length, 0);
    if (nsend < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] send to %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            tcp_context_release(evloop, context, true);
            return -1;
        }
        return 0;
    }
    IF_VERBOSE LOGINF("[%s] send to %s#%hu, nsend:%zd", funcname, g_server_ipstr, g_server_portno, nsend);
    context->socks5_length += (size_t)nsend;
    if (context->socks5_length >= datalen) {
        context->socks5_length = 0;
        return 1;
    }
    return 0;
}

/* return: -1(error_occurred); 0(partial_recv); 1(completely_recv) */
static int tcp_socks5_recv_response(const char *funcname, evloop_t *evloop, evio_t *socks5_watcher, void *data, size_t datalen) {
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    ssize_t nrecv = recv(socks5_watcher->fd, data + context->socks5_length, datalen - context->socks5_length, 0);
    if (nrecv < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] recv from %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            tcp_context_release(evloop, context, true);
            return -1;
        }
        return 0;
    }
    if (nrecv == 0) {
        LOGERR("[%s] recv from %s#%hu: connection is closed", funcname, g_server_ipstr, g_server_portno);
        tcp_context_release(evloop, context, true);
        return -1;
    }
    IF_VERBOSE LOGINF("[%s] recv from %s#%hu, nrecv:%zd", funcname, g_server_ipstr, g_server_portno, nrecv);
    context->socks5_length += (size_t)nrecv;
    if (context->socks5_length >= datalen) {
        context->socks5_length = 0;
        return 1;
    }
    return 0;
}

static void tcp_socks5_send_authreq_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (tcp_socks5_send_request("tcp_socks5_send_authreq_cb", evloop, socks5_watcher, &g_socks5_auth_request, sizeof(socks5_authreq_t)) != 1) {
        return;
    }
    ev_io_stop(evloop, socks5_watcher);
    ev_io_init(socks5_watcher, tcp_socks5_recv_authresp_cb, socks5_watcher->fd, EV_READ);
    ev_io_start(evloop, socks5_watcher);
}

static void tcp_socks5_recv_authresp_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (tcp_socks5_recv_response("tcp_socks5_recv_authresp_cb", evloop, socks5_watcher, socks5_watcher->data, sizeof(socks5_authresp_t)) != 1) {
        return;
    }
    if (!socks5_auth_response_check("tcp_socks5_recv_authresp_cb", socks5_watcher->data)) {
        tcp_context_release(evloop, get_tcpctx_by_watcher(socks5_watcher), true);
        return;
    }
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    const void *data = g_socks5_usrpwd_requestlen ? &g_socks5_usrpwd_request : context->client_watcher.data;
    uint16_t datalen = g_socks5_usrpwd_requestlen ? g_socks5_usrpwd_requestlen : context->client_length;
    int ret = tcp_socks5_send_request("tcp_socks5_recv_authresp_cb", evloop, socks5_watcher, data, datalen);
    if (ret == 1) {
        ev_set_cb(socks5_watcher, g_socks5_usrpwd_requestlen ? tcp_socks5_recv_usrpwdresp_cb : tcp_socks5_recv_proxyresp_cb);
        if (!g_socks5_usrpwd_requestlen) context->client_length = sizeof(socks5_ipv4resp_t); // response_length
    } else if (ret == 0) {
        ev_io_stop(evloop, socks5_watcher);
        ev_io_init(socks5_watcher, g_socks5_usrpwd_requestlen ? tcp_socks5_send_usrpwdreq_cb : tcp_socks5_send_proxyreq_cb, socks5_watcher->fd, EV_WRITE);
        ev_io_start(evloop, socks5_watcher);
    }
}

static void tcp_socks5_send_usrpwdreq_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (tcp_socks5_send_request("tcp_socks5_send_usrpwdreq_cb", evloop, socks5_watcher, &g_socks5_usrpwd_request, g_socks5_usrpwd_requestlen) != 1) {
        return;
    }
    ev_io_stop(evloop, socks5_watcher);
    ev_io_init(socks5_watcher, tcp_socks5_recv_usrpwdresp_cb, socks5_watcher->fd, EV_READ);
    ev_io_start(evloop, socks5_watcher);
}

static void tcp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (tcp_socks5_recv_response("tcp_socks5_recv_usrpwdresp_cb", evloop, socks5_watcher, socks5_watcher->data, sizeof(socks5_usrpwdresp_t)) != 1) {
        return;
    }
    if (!socks5_usrpwd_response_check("tcp_socks5_recv_usrpwdresp_cb", socks5_watcher->data)) {
        tcp_context_release(evloop, get_tcpctx_by_watcher(socks5_watcher), true);
        return;
    }
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    int ret = tcp_socks5_send_request("tcp_socks5_recv_usrpwdresp_cb", evloop, socks5_watcher, context->client_watcher.data, context->client_length);
    if (ret == 1) {
        ev_set_cb(socks5_watcher, tcp_socks5_recv_proxyresp_cb);
        context->client_length = sizeof(socks5_ipv4resp_t); // response_length
    } else if (ret == 0) {
        ev_io_stop(evloop, socks5_watcher);
        ev_io_init(socks5_watcher, tcp_socks5_send_proxyreq_cb, socks5_watcher->fd, EV_WRITE);
        ev_io_start(evloop, socks5_watcher);
    }
}

static void tcp_socks5_send_proxyreq_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    if (tcp_socks5_send_request("tcp_socks5_send_proxyreq_cb", evloop, socks5_watcher, context->client_watcher.data, context->client_length) != 1) {
        return;
    }
    ev_io_stop(evloop, socks5_watcher);
    ev_io_init(socks5_watcher, tcp_socks5_recv_proxyresp_cb, socks5_watcher->fd, EV_READ);
    ev_io_start(evloop, socks5_watcher);
    context->client_length = sizeof(socks5_ipv4resp_t); // response_length
}

static void tcp_socks5_recv_proxyresp_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    if (tcp_socks5_recv_response("tcp_socks5_recv_proxyresp_cb", evloop, socks5_watcher, socks5_watcher->data, context->client_length) != 1) {
        return;
    }
    if (context->client_length == sizeof(socks5_ipv4resp_t)) {
        if (!socks5_proxy_response_check("tcp_socks5_recv_proxyresp_cb", socks5_watcher->data)) {
            tcp_context_release(evloop, context, true);
            return;
        }
        if (((socks5_ipv4resp_t *)socks5_watcher->data)->addrtype == SOCKS5_ADDRTYPE_IPV6) {
            context->client_length = sizeof(socks5_ipv6resp_t); // response_length
            context->socks5_length = sizeof(socks5_ipv4resp_t); // response_nrecv
            return;
        }
    }
    context->client_length = 0;

    free(socks5_watcher->data);
    socks5_watcher->data = NULL;

    free(context->client_watcher.data);
    context->client_watcher.data = NULL;

    new_nonblock_pipefd(context->client_pipefd);
    new_nonblock_pipefd(context->socks5_pipefd);

    ev_io_start(evloop, &context->client_watcher);
    ev_set_cb(socks5_watcher, tcp_stream_payload_forward_cb);
    IF_VERBOSE LOGINF("[tcp_socks5_recv_proxyresp_cb] tunnel is ready, start forwarding ...");
}

static void tcp_stream_payload_forward_cb(evloop_t *evloop, evio_t *self_watcher, int revents) {
    bool self_is_client = self_watcher->events & EV_CUSTOM;
    tcp_context_t *context = get_tcpctx_by_watcher(self_watcher);
    evio_t *peer_watcher = self_is_client ? &context->socks5_watcher : &context->client_watcher;

    if (revents & EV_READ) {
        int *self_pipefd = self_is_client ? context->client_pipefd : context->socks5_pipefd;
        ssize_t nrecv = splice(self_watcher->fd, NULL, self_pipefd[1], NULL, TCP_SPLICE_MAXLEN, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (nrecv < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOGERR("[tcp_stream_payload_forward_cb] recv from %s stream: %s", self_is_client ? "client" : "socks5", strerror(errno));
                tcp_context_release(evloop, context, true);
                return;
            }
            goto DO_WRITE; // EAGAIN
        }
        if (nrecv == 0) {
            IF_VERBOSE LOGINF("[tcp_stream_payload_forward_cb] recv FIN from %s stream, release ctx", self_is_client ? "client" : "socks5");
            tcp_context_release(evloop, context, false);
            return;
        }

        ssize_t nsend = splice(self_pipefd[0], NULL, peer_watcher->fd, NULL, nrecv, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (nsend < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOGERR("[tcp_stream_payload_forward_cb] send to %s stream: %s", self_is_client ? "socks5" : "client", strerror(errno));
                tcp_context_release(evloop, context, true);
                return;
            }
            nsend = 0; // EAGAIN
        }
        if (nsend < nrecv) {
            *(self_is_client ? &context->client_length : &context->socks5_length) = (size_t)(nrecv - nsend); // remain_length

            ev_io_stop(evloop, self_watcher);
            ev_io_modify(self_watcher, self_watcher->events & ~EV_READ);
            if (self_watcher->events & EV_WRITE) ev_io_start(evloop, self_watcher);

            ev_io_stop(evloop, peer_watcher);
            ev_io_modify(peer_watcher, peer_watcher->events | EV_WRITE);
            ev_io_start(evloop, peer_watcher);
        }
    }

DO_WRITE:
    if (revents & EV_WRITE) {
        int *peer_pipefd = self_is_client ? context->socks5_pipefd : context->client_pipefd;
        uint16_t remain_length = self_is_client ? context->socks5_length : context->client_length;

        ssize_t nsend = splice(peer_pipefd[0], NULL, self_watcher->fd, NULL, remain_length, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (nsend < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOGERR("[tcp_stream_payload_forward_cb] send to %s stream: %s", self_is_client ? "client" : "socks5", strerror(errno));
                tcp_context_release(evloop, context, true);
            }
            return;
        }
        if (nsend == 0) return; // IGNORE

        remain_length -= (size_t)nsend;
        *(self_is_client ? &context->socks5_length : &context->client_length) = remain_length;

        if (remain_length <= 0) {
            ev_io_stop(evloop, self_watcher);
            ev_io_modify(self_watcher, self_watcher->events & ~EV_WRITE);
            if (self_watcher->events & EV_READ) ev_io_start(evloop, self_watcher);

            ev_io_stop(evloop, peer_watcher);
            ev_io_modify(peer_watcher, peer_watcher->events | EV_READ);
            ev_io_start(evloop, peer_watcher);
        }
    }
}

static void udp_tproxy_recvmsg_cb(evloop_t *evloop, evio_t *tprecv_watcher, int revents __attribute__((unused))) {
    bool isipv4 = tprecv_watcher->data;
    char msg_control_buffer[UDP_CTRLMESG_BUFSIZ] = {0};
    skaddr6_t skaddr; char ipstr[IP6STRLEN]; portno_t portno;
    size_t headerlen = isipv4 ? sizeof(socks5_udp4msg_t) : sizeof(socks5_udp6msg_t);

    struct msghdr msg = {
        .msg_name = &skaddr,
        .msg_namelen = sizeof(skaddr),
        .msg_iov = &(struct iovec){
            .iov_base = (void *)g_udp_dgram_buffer + headerlen,
            .iov_len = UDP_DATAGRAM_MAXSIZ - headerlen,
        },
        .msg_iovlen = 1,
        .msg_control = msg_control_buffer,
        .msg_controllen = UDP_CTRLMESG_BUFSIZ,
        .msg_flags = 0,
    };

    ssize_t nrecv = recvmsg(tprecv_watcher->fd, &msg, 0);
    if (nrecv < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_tproxy_recvmsg_cb] recv from udp%s socket: %s", isipv4 ? "4" : "6", strerror(errno));
        }
        return;
    }
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF("[udp_tproxy_recvmsg_cb] recv from %s#%hu, nrecv:%zd", ipstr, portno, nrecv);
    }

    ip_port_t key_ipport = {.ip = {0}, .port = 0};
    if (isipv4) {
        key_ipport.ip.ip4 = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
        key_ipport.port = ((skaddr4_t *)&skaddr)->sin_port;
    } else {
        memcpy(&key_ipport.ip.ip6, &skaddr.sin6_addr.s6_addr, IP6BINLEN);
        key_ipport.port = skaddr.sin6_port;
    }

    if (!get_udp_orig_dstaddr(isipv4 ? AF_INET : AF_INET6, &msg, &skaddr)) {
        LOGERR("[udp_tproxy_recvmsg_cb] destination address not found in udp msg");
        return;
    }

    socks5_udp4msg_t *udp4msg = (void *)g_udp_dgram_buffer;
    udp4msg->reserved = 0;
    udp4msg->fragment = 0;
    udp4msg->addrtype = isipv4 ? SOCKS5_ADDRTYPE_IPV4 : SOCKS5_ADDRTYPE_IPV6;
    if (isipv4) {
        udp4msg->ipaddr4 = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
        udp4msg->portnum = ((skaddr4_t *)&skaddr)->sin_port;
    } else {
        socks5_udp6msg_t *udp6msg = (void *)g_udp_dgram_buffer;
        memcpy(&udp6msg->ipaddr6, &skaddr.sin6_addr.s6_addr, IP6BINLEN);
        udp6msg->portnum = skaddr.sin6_port;
    }

    udp_socks5ctx_t *context = udp_socks5ctx_get(&g_udp_socks5ctx_table, &key_ipport);
    if (!context) {
        int tcp_sockfd = new_tcp_connect_sockfd(g_server_skaddr.sin6_family, g_tcp_syncnt_max);
        const void *tfo_data = (g_options & OPT_ENABLE_TFO_CONNECT) ? &g_socks5_auth_request : NULL;
        uint16_t tfo_datalen = (g_options & OPT_ENABLE_TFO_CONNECT) ? sizeof(socks5_authreq_t) : 0;
        ssize_t tfo_nsend = -1; /* if tfo connect succeed: tfo_nsend >= 0 */

        if (!tcp_connect(tcp_sockfd, &g_server_skaddr, tfo_data, tfo_datalen, &tfo_nsend)) {
            LOGERR("[udp_tproxy_recvmsg_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
            close(tcp_sockfd);
            return;
        }
        IF_VERBOSE {
            if (tfo_nsend >= 0) {
                LOGINF("[udp_tproxy_recvmsg_cb] tfo send to %s#%hu, nsend:%zd", g_server_ipstr, g_server_portno, tfo_nsend);
            } else {
                LOGINF("[udp_tproxy_recvmsg_cb] try to connect to %s#%hu ...", g_server_ipstr, g_server_portno);
            }
        }

        context = malloc(sizeof(*context));
        memcpy(&context->key_ipport, &key_ipport, sizeof(key_ipport));

        evio_t *watcher = &context->tcp_watcher;
        if (tfo_nsend >= 0 && (size_t)tfo_nsend >= tfo_datalen) {
            ev_io_init(watcher, udp_socks5_recv_authresp_cb, tcp_sockfd, EV_READ);
            tfo_nsend = 0;
        } else {
            ev_io_init(watcher, tfo_nsend >= 0 ? udp_socks5_send_authreq_cb : udp_socks5_connect_cb, tcp_sockfd, EV_WRITE);
            tfo_nsend = tfo_nsend >= 0 ? tfo_nsend : 0;
        }
        ev_io_start(evloop, watcher);
        context->tcp_watcher.data = malloc(2 + sizeof(socks5_ipv6resp_t));
        *(uint16_t *)context->tcp_watcher.data = tfo_nsend; /* nsend or nrecv */

        /* tunnel not ready if udp_watcher->data != NULL */
        context->udp_watcher.data = malloc(2 + headerlen + nrecv);
        *(uint16_t *)context->udp_watcher.data = headerlen + nrecv;
        memcpy(context->udp_watcher.data + 2, g_udp_dgram_buffer, headerlen + nrecv);

        evtimer_t *timer = &context->idle_timer;
        ev_timer_init(timer, udp_socks5_context_timeout_cb, 0, g_udp_idletimeout_sec);
        timer->data = (void *)sizeof(socks5_ipv4resp_t); // response_length

        udp_socks5ctx_t *del_context = udp_socks5ctx_add(&g_udp_socks5ctx_table, context);
        if (del_context) ev_invoke(evloop, &del_context->idle_timer, EV_CUSTOM);
        return;
    }
    if (context->udp_watcher.data) {
        IF_VERBOSE LOGINF("[udp_tproxy_recvmsg_cb] tunnel is not ready, discard this msg");
        return;
    }

    ev_timer_again(evloop, &context->idle_timer);
    nrecv = send(context->udp_watcher.fd, g_udp_dgram_buffer, headerlen + nrecv, 0);
    if (nrecv < 0) {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGERR("[udp_tproxy_recvmsg_cb] send to %s#%hu: %s", ipstr, portno, strerror(errno));
        return;
    }
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF("[udp_tproxy_recvmsg_cb] send to %s#%hu, nsend:%zd", ipstr, portno, nrecv);
    }
}

static inline udp_socks5ctx_t* get_udpsk5ctx_by_tcp(evio_t *tcp_watcher) {
    return (void *)tcp_watcher - offsetof(udp_socks5ctx_t, tcp_watcher);
}

static inline void udp_socks5ctx_release(evloop_t *evloop, udp_socks5ctx_t *context) {
    ev_invoke(evloop, &context->idle_timer, EV_CUSTOM);
}

static void udp_socks5_connect_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    if (tcp_has_error(tcp_watcher->fd)) {
        LOGERR("[udp_socks5_connect_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
        return;
    }
    IF_VERBOSE LOGINF("[udp_socks5_connect_cb] connect to %s#%hu succeeded", g_server_ipstr, g_server_portno);
    ev_set_cb(tcp_watcher, udp_socks5_send_authreq_cb);
    ev_invoke(evloop, tcp_watcher, EV_WRITE);
}

/* return: -1(error_occurred); 0(partial_sent); 1(completely_sent) */
static int udp_socks5_send_request(const char *funcname, evloop_t *evloop, evio_t *tcp_watcher, const void *data, size_t datalen) {
    uint16_t *nsend = tcp_watcher->data;
    ssize_t n = send(tcp_watcher->fd, data + *nsend, datalen - *nsend, 0);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] send to %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
            return -1;
        }
        return 0;
    }
    IF_VERBOSE LOGINF("[%s] send to %s#%hu, nsend:%zd", funcname, g_server_ipstr, g_server_portno, n);
    *nsend += (size_t)n;
    if (*nsend >= datalen) {
        *nsend = 0;
        return 1;
    }
    return 0;
}

/* return: -1(error_occurred); 0(partial_recv); 1(completely_recv) */
static int udp_socks5_recv_response(const char *funcname, evloop_t *evloop, evio_t *tcp_watcher, void *data, size_t datalen) {
    uint16_t *nrecv = tcp_watcher->data;
    ssize_t n = recv(tcp_watcher->fd, data + *nrecv, datalen - *nrecv, 0);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] recv from %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
            return -1;
        }
        return 0;
    }
    if (n == 0) {
        LOGERR("[%s] recv from %s#%hu: connection is closed", funcname, g_server_ipstr, g_server_portno);
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
        return -1;
    }
    IF_VERBOSE LOGINF("[%s] recv from %s#%hu, nrecv:%zd", funcname, g_server_ipstr, g_server_portno, n);
    *nrecv += (size_t)n;
    if (*nrecv >= datalen) {
        *nrecv = 0;
        return 1;
    }
    return 0;
}

static void udp_socks5_send_authreq_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    if (udp_socks5_send_request("udp_socks5_send_authreq_cb", evloop, tcp_watcher, &g_socks5_auth_request, sizeof(socks5_authreq_t)) != 1) {
        return;
    }
    ev_io_stop(evloop, tcp_watcher);
    ev_io_init(tcp_watcher, udp_socks5_recv_authresp_cb, tcp_watcher->fd, EV_READ);
    ev_io_start(evloop, tcp_watcher);
}

static void udp_socks5_recv_authresp_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    if (udp_socks5_recv_response("udp_socks5_recv_authresp_cb", evloop, tcp_watcher, tcp_watcher->data + 2, sizeof(socks5_authresp_t)) != 1) {
        return;
    }
    if (!socks5_auth_response_check("udp_socks5_recv_authresp_cb", tcp_watcher->data + 2)) {
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
        return;
    }
    const void *data; uint16_t datalen;
    if (g_socks5_usrpwd_requestlen) {
        data = &g_socks5_usrpwd_request;
        datalen = g_socks5_usrpwd_requestlen;
    } else {
        udp_socks5ctx_t *context = get_udpsk5ctx_by_tcp(tcp_watcher);
        bool isipv4 = ((socks5_udp4msg_t *)(context->udp_watcher.data + 2))->addrtype == SOCKS5_ADDRTYPE_IPV4;
        data = isipv4 ? (void *)&G_SOCKS5_UDP4_REQUEST : (void *)&G_SOCKS5_UDP6_REQUEST;
        datalen = isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t);
    }
    int ret = udp_socks5_send_request("udp_socks5_recv_authresp_cb", evloop, tcp_watcher, data, datalen);
    if (ret == 1) {
        ev_set_cb(tcp_watcher, g_socks5_usrpwd_requestlen ? udp_socks5_recv_usrpwdresp_cb : udp_socks5_recv_proxyresp_cb);
    } else if (ret == 0) {
        ev_io_stop(evloop, tcp_watcher);
        ev_io_init(tcp_watcher, g_socks5_usrpwd_requestlen ? udp_socks5_send_usrpwdreq_cb : udp_socks5_send_proxyreq_cb, tcp_watcher->fd, EV_WRITE);
        ev_io_start(evloop, tcp_watcher);
    }
}

static void udp_socks5_send_usrpwdreq_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    if (udp_socks5_send_request("udp_socks5_send_usrpwdreq_cb", evloop, tcp_watcher, &g_socks5_usrpwd_request, g_socks5_usrpwd_requestlen) != 1) {
        return;
    }
    ev_io_stop(evloop, tcp_watcher);
    ev_io_init(tcp_watcher, udp_socks5_recv_usrpwdresp_cb, tcp_watcher->fd, EV_READ);
    ev_io_start(evloop, tcp_watcher);
}

static void udp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    if (udp_socks5_recv_response("udp_socks5_recv_usrpwdresp_cb", evloop, tcp_watcher, tcp_watcher->data + 2, sizeof(socks5_usrpwdresp_t)) != 1) {
        return;
    }
    if (!socks5_usrpwd_response_check("udp_socks5_recv_usrpwdresp_cb", tcp_watcher->data + 2)) {
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
        return;
    }
    udp_socks5ctx_t *context = get_udpsk5ctx_by_tcp(tcp_watcher);
    bool isipv4 = ((socks5_udp4msg_t *)(context->udp_watcher.data + 2))->addrtype == SOCKS5_ADDRTYPE_IPV4;
    const void *data = isipv4 ? (void *)&G_SOCKS5_UDP4_REQUEST : (void *)&G_SOCKS5_UDP6_REQUEST;
    uint16_t datalen = isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t);
    int ret = udp_socks5_send_request("udp_socks5_recv_usrpwdresp_cb", evloop, tcp_watcher, data, datalen);
    if (ret == 1) {
        ev_set_cb(tcp_watcher, udp_socks5_recv_proxyresp_cb);
    } else if (ret == 0) {
        ev_io_stop(evloop, tcp_watcher);
        ev_io_init(tcp_watcher, udp_socks5_send_proxyreq_cb, tcp_watcher->fd, EV_WRITE);
        ev_io_start(evloop, tcp_watcher);
    }
}

static void udp_socks5_send_proxyreq_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    udp_socks5ctx_t *context = get_udpsk5ctx_by_tcp(tcp_watcher);
    bool isipv4 = ((socks5_udp4msg_t *)(context->udp_watcher.data + 2))->addrtype == SOCKS5_ADDRTYPE_IPV4;
    const void *request = isipv4 ? (void *)&G_SOCKS5_UDP4_REQUEST : (void *)&G_SOCKS5_UDP6_REQUEST;
    uint16_t requestlen = isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t);
    if (udp_socks5_send_request("udp_socks5_send_proxyreq_cb", evloop, tcp_watcher, request, requestlen) != 1) {
        return;
    }
    ev_io_stop(evloop, tcp_watcher);
    ev_io_init(tcp_watcher, udp_socks5_recv_proxyresp_cb, tcp_watcher->fd, EV_READ);
    ev_io_start(evloop, tcp_watcher);
}

static void udp_socks5_recv_proxyresp_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    udp_socks5ctx_t *context = get_udpsk5ctx_by_tcp(tcp_watcher);
    if (udp_socks5_recv_response("udp_socks5_recv_proxyresp_cb", evloop, tcp_watcher, tcp_watcher->data + 2, (uintptr_t)context->idle_timer.data) != 1) {
        return;
    }
    if ((uintptr_t)context->idle_timer.data == sizeof(socks5_ipv4resp_t)) {
        if (!socks5_proxy_response_check("udp_socks5_recv_proxyresp_cb", tcp_watcher->data + 2)) {
            udp_socks5ctx_release(evloop, context);
            return;
        }
        if (((socks5_ipv4resp_t *)(tcp_watcher->data + 2))->addrtype == SOCKS5_ADDRTYPE_IPV6) {
            context->idle_timer.data = (void *)sizeof(socks5_ipv6resp_t); // response_length
            *(uint16_t *)tcp_watcher->data = sizeof(socks5_ipv4resp_t); // response_nrecv
            return;
        }
    }
    bool resp_isipv4 = (uintptr_t)context->idle_timer.data == sizeof(socks5_ipv4resp_t);

    /* the udp relay port (from the assoc response) */
    portno_t relay_port = resp_isipv4 ?
        ((socks5_ipv4resp_t *)(tcp_watcher->data + 2))->portnum :
        ((socks5_ipv6resp_t *)(tcp_watcher->data + 2))->portnum;

    /* the address is usually the same as the socks5 server address (except for the port) */
    skaddr6_t relay_addr;
    memcpy(&relay_addr, &g_server_skaddr, sizeof(g_server_skaddr));

    /* update the port to the udp relay port */
    bool relay_isipv4 = relay_addr.sin6_family == AF_INET;
    if (relay_isipv4)
        ((skaddr4_t *)&relay_addr)->sin_port = relay_port;
    else
        relay_addr.sin6_port = relay_port;

    /* connect to the socks5 udp relay endpoint */
    int udp_sockfd = new_udp_normal_sockfd(relay_addr.sin6_family);
    if (connect(udp_sockfd, (void *)&relay_addr, relay_isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t)) < 0) {
        char ipstr[IP6STRLEN]; portno_t portno;
        parse_socket_addr(&relay_addr, ipstr, &portno);
        LOGERR("[udp_socks5_recv_proxyresp_cb] connect to udp://%s#%u: %s", ipstr, (unsigned)portno, strerror(errno));
        udp_socks5ctx_release(evloop, context);
        close(udp_sockfd);
        return;
    }

    ssize_t nsend = send(udp_sockfd, context->udp_watcher.data + 2, *(uint16_t *)context->udp_watcher.data, 0);
    if (nsend < 0 || g_verbose) {
        char ipstr[IP6STRLEN]; portno_t portno;
        if (((socks5_udp4msg_t *)(context->udp_watcher.data + 2))->addrtype == SOCKS5_ADDRTYPE_IPV4) {
            socks5_udp4msg_t *udp4msg = context->udp_watcher.data + 2;
            inet_ntop(AF_INET, &udp4msg->ipaddr4, ipstr, IP6STRLEN);
            portno = ntohs(udp4msg->portnum);
        } else {
            socks5_udp6msg_t *udp6msg = context->udp_watcher.data + 2;
            inet_ntop(AF_INET6, &udp6msg->ipaddr6, ipstr, IP6STRLEN);
            portno = ntohs(udp6msg->portnum);
        }
        if (nsend < 0) {
            LOGERR("[udp_socks5_recv_proxyresp_cb] send to %s#%hu: %s", ipstr, portno, strerror(errno));
        } else {
            LOGINF("[udp_socks5_recv_proxyresp_cb] send to %s#%hu, nsend:%zd", ipstr, portno, nsend);
        }
    }

    ev_set_cb(tcp_watcher, udp_socks5_recv_tcpmessage_cb);
    free(tcp_watcher->data);
    tcp_watcher->data = NULL;

    evio_t *watcher = &context->udp_watcher;
    ev_io_init(watcher, udp_socks5_recv_udpmessage_cb, udp_sockfd, EV_READ);
    ev_io_start(evloop, watcher);
    free(watcher->data); /* udp_watcher->data */
    watcher->data = NULL; /* udp_watcher->data */

    ev_timer_again(evloop, &context->idle_timer);
    udp_socks5ctx_use(&g_udp_socks5ctx_table, context);
}

static void udp_socks5_recv_tcpmessage_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    ssize_t nrecv = recv(tcp_watcher->fd, (char [1]){0}, 1, 0);
    if (nrecv > 0) {
        LOGERR("[udp_socks5_recv_tcpmessage_cb] recv unknown msg from socks5 server, release ctx");
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
    } else if (nrecv == 0) {
        IF_VERBOSE LOGINF("[udp_socks5_recv_tcpmessage_cb] recv FIN from socks5 server, release ctx");
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        LOGERR("[udp_socks5_recv_tcpmessage_cb] recv from socks5 server: %s", strerror(errno));
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
    }
}

static void udp_socks5_recv_udpmessage_cb(evloop_t *evloop, evio_t *udp_watcher, int revents __attribute__((unused))) {
    ssize_t nrecv = recv(udp_watcher->fd, g_udp_dgram_buffer, UDP_DATAGRAM_MAXSIZ, 0);
    if (nrecv < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_socks5_recv_udpmessage_cb] recv from socks5 server: %s", strerror(errno));
        }
        return;
    }
    if ((size_t)nrecv < sizeof(socks5_udp4msg_t)) {
        LOGERR("[udp_socks5_recv_udpmessage_cb] recv from socks5 server: message too small");
        return;
    }
    socks5_udp4msg_t *udp4msg = (void *)g_udp_dgram_buffer;
    bool isipv4 = udp4msg->addrtype == SOCKS5_ADDRTYPE_IPV4;
    if (!isipv4 && (size_t)nrecv < sizeof(socks5_udp6msg_t)) {
        LOGERR("[udp_socks5_recv_udpmessage_cb] recv from socks5 server: message too small");
        return;
    }

    udp_socks5ctx_t *socks5ctx = (void *)udp_watcher - offsetof(udp_socks5ctx_t, udp_watcher);
    udp_socks5ctx_use(&g_udp_socks5ctx_table, socks5ctx);
    ev_timer_again(evloop, &socks5ctx->idle_timer);

    ip_port_t fromipport = {.ip = {0}, .port = 0};
    if (isipv4) {
        fromipport.ip.ip4 = udp4msg->ipaddr4;
        fromipport.port = udp4msg->portnum;
    } else {
        socks5_udp6msg_t *udp6msg = (void *)g_udp_dgram_buffer;
        memcpy(&fromipport.ip.ip6, &udp6msg->ipaddr6, IP6BINLEN);
        fromipport.port = udp6msg->portnum;
    }

    char ipstr[IP6STRLEN]; portno_t portno;
    IF_VERBOSE {
        inet_ntop(isipv4 ? AF_INET : AF_INET6, isipv4 ? (void *)&fromipport.ip.ip4 : (void *)&fromipport.ip.ip6, ipstr, IP6STRLEN);
        portno = ntohs(fromipport.port);
        LOGINF("[udp_socks5_recv_udpmessage_cb] recv from %s#%hu, nrecv:%zd", ipstr, portno, nrecv);
    }

    udp_tproxyctx_t *tproxyctx = udp_tproxyctx_get(&g_udp_tproxyctx_table, &fromipport);
    if (!tproxyctx) {
        skaddr6_t fromskaddr = {0};
        if (isipv4) {
            skaddr4_t *addr = (void *)&fromskaddr;
            addr->sin_family = AF_INET;
            addr->sin_addr.s_addr = fromipport.ip.ip4;
            addr->sin_port = fromipport.port;
        } else {
            fromskaddr.sin6_family = AF_INET6;
            memcpy(&fromskaddr.sin6_addr.s6_addr, &fromipport.ip.ip6, IP6BINLEN);
            fromskaddr.sin6_port = fromipport.port;
        }
        int tproxy_sockfd = new_udp_tpsend_sockfd(isipv4 ? AF_INET : AF_INET6);
        if (bind(tproxy_sockfd, (void *)&fromskaddr, isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t)) < 0) {
            LOGERR("[udp_socks5_recv_udpmessage_cb] bind tproxy reply address: %s", strerror(errno));
            close(tproxy_sockfd);
            return;
        }
        tproxyctx = malloc(sizeof(*tproxyctx));
        memcpy(&tproxyctx->key_ipport, &fromipport, sizeof(fromipport));
        tproxyctx->udp_sockfd = tproxy_sockfd;
        evtimer_t *timer = &tproxyctx->idle_timer;
        ev_timer_init(timer, udp_tproxy_context_timeout_cb, 0, g_udp_idletimeout_sec);
        udp_tproxyctx_t *del_context = udp_tproxyctx_add(&g_udp_tproxyctx_table, tproxyctx);
        if (del_context) ev_invoke(evloop, &del_context->idle_timer, EV_CUSTOM);
    }
    ev_timer_again(evloop, &tproxyctx->idle_timer);

    ip_port_t *toipport = &socks5ctx->key_ipport;
    skaddr6_t toskaddr = {0};
    if (isipv4) {
        skaddr4_t *addr = (void *)&toskaddr;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = toipport->ip.ip4;
        addr->sin_port = toipport->port;
    } else {
        toskaddr.sin6_family = AF_INET6;
        memcpy(&toskaddr.sin6_addr.s6_addr, &toipport->ip.ip6, IP6BINLEN);
        toskaddr.sin6_port = toipport->port;
    }

    size_t headerlen = isipv4 ? sizeof(socks5_udp4msg_t) : sizeof(socks5_udp6msg_t);
    nrecv = sendto(tproxyctx->udp_sockfd, (void *)g_udp_dgram_buffer + headerlen, nrecv - headerlen, 0, (void *)&toskaddr, isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t));
    if (nrecv < 0) {
        parse_socket_addr(&toskaddr, ipstr, &portno);
        LOGERR("[udp_socks5_recv_udpmessage_cb] send to %s#%hu: %s", ipstr, portno, strerror(errno));
        return;
    }
    IF_VERBOSE {
        parse_socket_addr(&toskaddr, ipstr, &portno);
        LOGINF("[udp_socks5_recv_udpmessage_cb] send to %s#%hu, nsend:%zd", ipstr, portno, nrecv);
    }
}

static void udp_socks5_context_timeout_cb(evloop_t *evloop, evtimer_t *idle_timer, int revents) {
    IF_VERBOSE LOGINF("[udp_socks5_context_timeout_cb] context will be released, reason: %s", revents & EV_CUSTOM ? "manual" : "timeout");

    udp_socks5ctx_t *context = (void *)idle_timer - offsetof(udp_socks5ctx_t, idle_timer);
    udp_socks5ctx_del(&g_udp_socks5ctx_table, context);

    ev_timer_stop(evloop, idle_timer);

    ev_io_stop(evloop, &context->tcp_watcher);
    close(context->tcp_watcher.fd);
    free(context->tcp_watcher.data);

    if (context->udp_watcher.data) {
        free(context->udp_watcher.data);
    } else {
        ev_io_stop(evloop, &context->udp_watcher);
        close(context->udp_watcher.fd);
    }

    free(context);
}

static void udp_tproxy_context_timeout_cb(evloop_t *evloop, evtimer_t *idle_timer, int revents) {
    IF_VERBOSE LOGINF("[udp_tproxy_context_timeout_cb] context will be released, reason: %s", revents & EV_CUSTOM ? "manual" : "timeout");

    udp_tproxyctx_t *context = (void *)idle_timer - offsetof(udp_tproxyctx_t, idle_timer);
    udp_tproxyctx_del(&g_udp_tproxyctx_table, context);

    ev_timer_stop(evloop, idle_timer);
    close(context->udp_sockfd);
    free(context);
}
