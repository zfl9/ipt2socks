#pragma once

#define _GNU_SOURCE
#include "co.h"
#include "../libev/ev.h"
#include <stdint.h>
#include <sys/socket.h>

#define ev_io_init_fd(io, fd) ev_io_init(io, NULL, fd, 0)

struct async_accept {
    co_fields();
    int fd; // fd or -errno
};
struct async_accept_arg {
    ev_io *io;
    struct sockaddr *restrict addr;
    socklen_t *restrict addrlen;
    int flags; // SOCK_NONBLOCK, SOCK_CLOEXEC
};
void async_accept(struct async_accept *restrict c, void *arg);

struct async_connect {
    co_fields();
    int err; // 0 or -errno
};
struct async_connect_arg {
    ev_io *io;
    const struct sockaddr *restrict addr;
    socklen_t addrlen;
};
void async_connect(struct async_connect *restrict c, void *arg);

struct async_recv {
    co_fields();
    int32_t nbytes;
};
struct async_recv_arg {
    ev_io *io;
    void *restrict buf;
    size_t len;
    int flags;
    struct sockaddr *restrict addr;
    socklen_t *restrict addrlen;
};
void async_recv(struct async_recv *restrict c, void *arg);

struct async_send {
    co_fields();
    int32_t nbytes;
};
struct async_send_arg {
    ev_io *io;
    const void *restrict buf;
    size_t len;
    int flags;
    const struct sockaddr *restrict addr;
    socklen_t addrlen;
};
void async_send(struct async_send *restrict c, void *arg);

struct async_recvmsg {
    co_fields();
    int32_t nbytes;
};
struct async_recvmsg_arg {
    ev_io *io;
    struct msghdr *restrict msg;
    int flags;
};
void async_recvmsg(struct async_recvmsg *restrict c, void *arg);

struct async_sendmsg {
    co_fields();
    int32_t nbytes;
};
struct async_sendmsg_arg {
    ev_io *io;
    const struct msghdr *restrict msg;
    int flags;
};
void async_sendmsg(struct async_sendmsg *restrict c, void *arg);
