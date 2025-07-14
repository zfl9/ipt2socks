#include "sock.hpp"
#include "log.h"
#include <errno.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

namespace {
    void setsockopt_int(int fd, int level, int opt, int value, const char *optname) {
        if (::setsockopt(fd, level, opt, &value, sizeof(value)) < 0) [[unlikely]]
            log_error("setsockopt(fd:%d, level:%d, opt:%s, value:%d) failed: (%d) %m", fd, level, optname, value, errno);
    }

    void setup_for_listen(int fd, int family, int v6only, bool reuse_port) noexcept {
        if (v6only >= 0 && family == AF_INET6)
            setsockopt_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, v6only, "IPV6_V6ONLY");

        setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1, "SO_REUSEADDR");

        if (reuse_port)
            setsockopt_int(fd, SOL_SOCKET, SO_REUSEPORT, 1, "SO_REUSEPORT");
    }

    static void setup_for_tcpconn(int fd, bool keepalive) noexcept {
        setsockopt_int(fd, IPPROTO_TCP, TCP_NODELAY, 1, "TCP_NODELAY");

        if (keepalive) {
            setsockopt_int(fd, SOL_SOCKET, SO_KEEPALIVE, 1, "SO_KEEPALIVE");
            setsockopt_int(fd, IPPROTO_TCP, TCP_KEEPIDLE, 60, "TCP_KEEPIDLE");
            setsockopt_int(fd, IPPROTO_TCP, TCP_KEEPCNT, 3, "TCP_KEEPCNT");
            setsockopt_int(fd, IPPROTO_TCP, TCP_KEEPINTVL, 5, "TCP_KEEPINTVL");
        }
    }
}

int sock::create_sock(int family, int type) noexcept {
    int fd = ::socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) [[unlikely]]
        log_error("socket(family:%d, type:%d) failed: (%d) %m", family, type, errno);
    return fd;
}

int sock::create_listen_sock(int family, int type, int v6only, bool reuse_port) noexcept {
    int fd = create_sock(family, type);
    if (fd >= 0) [[likely]]
        setup_for_listen(fd, family, v6only, reuse_port);
    return fd;
}

int sock::create_tcpconn_sock(int family, int type, bool keepalive) noexcept {
    int fd = create_sock(family, type);
    if (fd >= 0) [[likely]]
        setup_for_tcpconn(fd, keepalive);
    return fd;
}
