#include "Sock.hpp"
#include "EvLoop.hpp"
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

// int Fd::new_sock(int family, int type) noexcept {
//     int fd = ::socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
//     if (fd < 0) [[unlikely]]
//         log_error("socket(family:%d, type:%d) failed: (%d) %m", family, type, errno);
//     return fd;
// }

// int Fd::new_listen_sock(int family, int type, int v6only, bool reuse_port) noexcept {
//     int fd = new_sock(family, type);
//     if (fd >= 0) [[likely]]
//         setup_for_listen(fd, family, v6only, reuse_port);
//     return fd;
// }

// int Fd::new_tcpconn_sock(int family, int type, bool keepalive) noexcept {
//     int fd = new_sock(family, type);
//     if (fd >= 0) [[likely]]
//         setup_for_tcpconn(fd, keepalive);
//     return fd;
// }

Fd::AcceptAwaitable::AcceptAwaitable(Fd *fdobj, sockaddr *addr, socklen_t *addrlen) noexcept
    : _fdobj{fdobj}, _addr{addr}, _addrlen{addrlen}
{}

bool Fd::AcceptAwaitable::await_ready() noexcept {
    _cfd = ::accept4(_fdobj->_fd, _addr, _addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
    return _cfd >= 0;
}

void Fd::AcceptAwaitable::await_suspend(std::coroutine_handle<> caller) noexcept {
    _caller = caller;
}

int Fd::AcceptAwaitable::await_resume() const noexcept {
    //
}

Fd::ConnectAwaitable::ConnectAwaitable(Fd *fdobj, const sockaddr *addr, socklen_t addrlen) noexcept
    : _fdobj{fdobj}
{
    //
}
bool Fd::ConnectAwaitable::await_ready() noexcept {
    //
}
void Fd::ConnectAwaitable::await_suspend(std::coroutine_handle<> caller) noexcept {
    //
}
bool Fd::ConnectAwaitable::await_resume() const noexcept {
    //
}

Fd::RecvAwaitable::RecvAwaitable(int fd, void *buf, size_t len, int flags) noexcept {
    //
}
bool Fd::RecvAwaitable::await_ready() noexcept {
    //
}
void Fd::RecvAwaitable::await_suspend(std::coroutine_handle<> caller) noexcept {
    //
}
ssize_t Fd::RecvAwaitable::await_resume() const noexcept {
    //
}

Fd::recvfrom::recvfrom(int fd, void *buf, size_t len, sockaddr *addr, socklen_t *addrlen, int flags) noexcept {
    //
}
bool Fd::recvfrom::await_ready() noexcept {
    //
}
void Fd::recvfrom::await_suspend(std::coroutine_handle<> caller) noexcept {
    //
}
ssize_t Fd::recvfrom::await_resume() const noexcept {
    //
}

Fd::recvmsg::recvmsg(int fd, msghdr *msg, int flags) noexcept {
    //
}
bool Fd::recvmsg::await_ready() noexcept {
    //
}
void Fd::recvmsg::await_suspend(std::coroutine_handle<> caller) noexcept {
    //
}
ssize_t Fd::recvmsg::await_resume() const noexcept {
    //
}

Fd::recvmmsg::recvmmsg(int fd, mmsghdr *msgv, unsigned int vlen, int flags) noexcept {
}
bool Fd::recvmmsg::await_ready() noexcept {
}
void Fd::recvmmsg::await_suspend(std::coroutine_handle<> caller) noexcept {
}
ssize_t Fd::recvmmsg::await_resume() const noexcept {
}

Fd::send::send(int fd, const void *buf, size_t len, int flags) noexcept {
}
bool Fd::send::await_ready() noexcept {
}
void Fd::send::await_suspend(std::coroutine_handle<> caller) noexcept {
}
ssize_t Fd::send::await_resume() const noexcept {

}

Fd::sendto::sendto(int fd, const void *buf, size_t len, const sockaddr *addr, socklen_t addrlen, int flags) noexcept {
}
bool Fd::sendto::await_ready() noexcept {
}
void Fd::sendto::await_suspend(std::coroutine_handle<> caller) noexcept {
}
ssize_t Fd::sendto::await_resume() const noexcept {
}

Fd::sendmsg::sendmsg(int fd, const msghdr *msg, int flags) noexcept {
}
bool Fd::sendmsg::await_ready() noexcept {
}
void Fd::sendmsg::await_suspend(std::coroutine_handle<> caller) noexcept {
}
ssize_t Fd::sendmsg::await_resume() const noexcept {

}

Fd::sendmmsg::sendmmsg(int fd, mmsghdr *msgv, unsigned int vlen, int flags) noexcept {
}
bool Fd::sendmmsg::await_ready() noexcept {
}
void Fd::sendmmsg::await_suspend(std::coroutine_handle<> caller) noexcept {
}
ssize_t Fd::sendmmsg::await_resume() const noexcept {
}
