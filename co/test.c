#define _GNU_SOURCE
#include "co.h"
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

static ev_loop *loop;

// =============================================

struct co_sleep {
    co_fields();
};

struct co_sleep_arg {
    ev_timer *timer;
    int seconds;
};

static void co_sleep(struct co_sleep *restrict c, void *arg);

static void co_sleep_cb(ev_loop *loop, ev_timer *timer, int revents) {
    return co_sleep(timer->data, timer);
}

static void co_sleep(struct co_sleep *restrict c, void *arg) {
    co_begin(co_sleep);

    struct co_sleep_arg *p = arg;
    ev_timer *timer = p->timer;

    timer->data = c;
    ev_timer_init(timer, co_sleep_cb, p->seconds, 0);
    ev_timer_start(loop, timer);

    co_suspend();

    timer = (void *)arg;
    ev_timer_stop(loop, timer);

    co_end();
}

// =============================================

struct co_connect {
    co_fields();
    int res;
};

struct co_connect_arg {
    ev_io *io;
    const char *ip;
    int port;
};

static void co_connect(struct co_connect *restrict c, void *arg);

static void co_connect_cb(ev_loop *loop, ev_io *io, int revents) {
    return co_connect(io->data, io);
}

#define ev_io_start(loop, io) ({ \
    LOGINF("ev_io_start fd:%d events:%d", (io)->fd, (io)->events); \
    ev_io_start(loop, io); \
})

#define ev_io_stop(loop, io) ({ \
    LOGINF("ev_io_stop fd:%d events:%d", (io)->fd, (io)->events); \
    ev_io_stop(loop, io); \
})

static void co_connect(struct co_connect *restrict c, void *arg) {
    co_begin(co_connect);

    struct co_connect_arg *p = arg;

    skaddr4_t addr;
    build_socket_addr(AF_INET, &addr, p->ip, p->port);

    int fd = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
    assert(fd >= 0);

    int res = connect(fd, &addr, sizeof(addr));
    if (res == 0) {
        //
    } else if (errno != EINPROGRESS) {
        res = -errno;
    } else {
        ev_io *io = p->io;

        io->data = c;
        ev_io_init(io, co_connect_cb, fd, EV_WRITE);
        ev_io_start(loop, io);

        co_suspend();

        io = (void *)arg;
        fd = io->fd;
        ev_io_stop(loop, io);

        socklen_t optlen = sizeof(res);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &res, &optlen) < 0) {
            res = -errno;
        } else if (res) {
            res = -res;
        }
    }

    c->res = res;
    co_end();
}

// =============================================

struct co_send {
    co_fields();
    const void *data;
    size_t len;
};

struct co_send_arg {
    ev_io *io;
    const void *data;
    size_t len;
};

static void co_send(struct co_send *restrict c, void *arg);

static void co_send_cb(ev_loop *loop, ev_io *io, int revents) {
    return co_send(io->data, io);
}

static void co_send(struct co_send *restrict c, void *arg) {
    co_begin(co_send);

    struct co_send_arg *p = arg;
    c->data = p->data;
    c->len = p->len;

    ev_io *io = p->io;
    int fd = io->fd;

    int res;
    while (c->len > 0) {
        ssize_t n = send(fd, c->data, c->len, 0);
        if (n >= 0) {
            c->data += n;
            c->len -= n;
        } else if (errno != EAGAIN) {
            res = -errno;
            goto end;
        }
        if (c->len > 0) {
            io->data = c;
            ev_io_init(io, co_send_cb, fd, EV_WRITE);
            ev_io_start(loop, io);

            co_suspend();

            io = (void *)arg;
            fd = io->fd;
            ev_io_stop(loop, io);
        }
    }
    res = 0;

end:
    c->len = res;
    co_end();
}

// =============================================

struct worker {
    co_fields(
        co_nested(co_connect);
        co_nested(co_sleep);
        co_nested(co_send);
    );
    ev_io io;
    ev_timer timer;
    const char *ip;
    int port;
    const char *msg;
    int i;
};

struct worker_arg {
    const char *ip;
    int port;
    const char *msg;
};

static void worker(struct worker *restrict c, void *arg) {
    co_begin(worker);

    struct worker_arg *p = arg;
    c->ip = p->ip;
    c->port = p->port;
    c->msg = p->msg;

    LOGINF("connecting to %s:%d", c->ip, c->port);
    co_call(co_connect, 
        .io = &c->io,
        .ip = c->ip,
        .port = c->port,
    );

    int res;
    if ((res = co_at(co_connect)->res) < 0) {
        LOGERR("connect to %s:%d failed: (%d) %s", c->ip, c->port, -res, strerror(-res));
        goto end;
    }
    LOGINF("connected to %s:%d (fd:%d)", c->ip, c->port, c->io.fd);

    for (c->i = 0; c->i < 10; c->i++) {
        LOGINF("^%d [%s:%d fd:%d] sleep 2 seconds ...", c->i, c->ip, c->port, c->io.fd);
        co_call(co_sleep, 
            .timer = &c->timer,
            .seconds = 2,
        );
        LOGINF("^%d [%s:%d fd:%d] send data %s ...", c->i, c->ip, c->port, c->io.fd, c->msg);
        co_call(co_send,
            .io = &c->io,
            .data = c->msg,
            .len = strlen(c->msg),
        );
        LOGINF("^%d [%s:%d fd:%d] send data %s END", c->i, c->ip, c->port, c->io.fd, c->msg);
    }

    // free resources
    // TODO

end:
    co_end();
}

// =============================================

struct multi_worker {
    co_fields();
    struct worker workers[3];
};

struct multi_worker_arg {};

static void multi_worker(struct multi_worker *restrict c, void *arg) {
    co_begin(multi_worker);

    co_async(&c->workers[0], worker, 
        .ip = "127.0.0.1",
        .port = 8800,
        .msg = "from worker0",
    );
    co_async(&c->workers[1], worker,
        .ip = "127.0.0.1",
        .port = 8801,
        .msg = "from worker1",
    );
    co_async(&c->workers[2], worker,
        .ip = "127.0.0.1",
        .port = 8802,
        .msg = "from worker2",
    );

    co_await(&c->workers[0]);
    co_await(&c->workers[1]);
    co_await(&c->workers[2]);

    co_end();
}

int main(void) {
    loop = ev_default_loop(0);

    struct worker workers[3];
    co_async(&workers[0], worker, 
        .ip = "127.0.0.1",
        .port = 8800,
        .msg = "from worker0",
    );
    co_async(&workers[1], worker,
        .ip = "127.0.0.1",
        .port = 8801,
        .msg = "from worker1",
    );
    co_async(&workers[2], worker,
        .ip = "127.0.0.1",
        .port = 8802,
        .msg = "from worker2",
    );

    struct multi_worker m_worker;
    co_async(&m_worker, multi_worker);

    return ev_run(loop, 0);
}
