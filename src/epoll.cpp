#include "epoll.hpp"
#include "fd.hpp"
#include "log.h"
#include <utility>
#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <sys/epoll.h>
#include <time.h>

Epoll::Epoll() noexcept {
    _epfd = ::epoll_create1(EPOLL_CLOEXEC);
    if (_epfd < 0) [[unlikely]]
        log_error("epoll_create failed: (%d) %m", errno);

    time_fetch();
}

Epoll::~Epoll() noexcept {
    if (_epfd >= 0)
        ::close(_epfd);
}

void Epoll::time_fetch() noexcept {
    struct timespec t;
    ::clock_gettime(CLOCK_MONOTONIC, &t);
    _time_ms = (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}

void Epoll::loop_run() noexcept {
    constexpr int MAX_EVENTS = 64;
    epoll_event events[MAX_EVENTS];

    // for (;;) {
    while (!_stop) {
        time_fetch();
        timer_process();
        fdobj_commit();

        // waiting for I/O ready
        int num_events = ::epoll_wait(_epfd, events, MAX_EVENTS, timer_timeout());
        if (num_events < 0) {
            if (errno == EINTR) {
                num_events = 0;
            } else [[unlikely]] {
                log_error("epoll_wait(%d) failed: (%d) %m", _epfd, errno);
                return;
            }
        }

        // handling I/O events
        for (int i = 0; i < num_events; ++i) {
            if (i % 10 == 0)
                time_fetch();

            auto *ev = &events[i];
            auto ready_events = ev->events;
            auto *fdobj = static_cast<FdObj *>(ev->data.ptr);

            if (ready_events & (EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLERR | EPOLLHUP))
                fdobj->on_readable();
            if (ready_events & (EPOLLOUT | EPOLLERR | EPOLLHUP))
                fdobj->on_writable();
        }
    }
}

int Epoll::timer_timeout() const noexcept {
    // todo
    return -1;
}

void Epoll::timer_process() noexcept {
    // todo
}

void Epoll::fdobj_add(FdObj *fdobj) noexcept {
    log_info("%p", fdobj);

    assert(!fdobj->_defer_prev);
    assert(!fdobj->_defer_next);

    if (auto head = _fdobj_list) {
        fdobj->_defer_next = head;
        head->_defer_prev = fdobj;
    }
    _fdobj_list = fdobj;
}

void Epoll::fdobj_del(FdObj *fdobj) noexcept {
    log_info("%p", fdobj);

    if (auto prev = fdobj->_defer_prev)
        prev->_defer_next = fdobj->_defer_next;

    if (auto next = fdobj->_defer_next)
        next->_defer_prev = fdobj->_defer_prev;

    if (_fdobj_list == fdobj)
        _fdobj_list = fdobj->_defer_next;

    fdobj->_defer_prev = fdobj->_defer_next = nullptr;
}

void Epoll::fdobj_commit() noexcept {
    auto fdobj = _fdobj_list;
    _fdobj_list = nullptr;

    while (fdobj) {
        auto next = fdobj->_defer_next;
        fdobj->_defer_prev = fdobj->_defer_next = nullptr;

        switch (auto res = fdobj->commit(); res.op) {
            case FdObj::Op::update_event: {
                log_info("%p r:%d w:%d e:%d [update]", fdobj, res.read, res.write, res.exist);
                uint32_t events = 0;
                if (res.read) events |= EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLET;
                if (res.write) events |= EPOLLOUT | EPOLLET;
                if (events) {
                    ep_add(fdobj, events, res.exist);
                } else { // no events
                    assert(res.exist);
                    ep_del(fdobj);
                }
                break;
            }

            case FdObj::Op::destroy: {
                log_info("%p r:%d w:%d e:%d [destroy]", fdobj, res.read, res.write, res.exist);
                assert(!res.read);
                assert(!res.write);
                if (res.exist) ep_del(fdobj);
                delete fdobj;
                break;
            }

            default:
                std::unreachable();
        }

        fdobj = next;
    }
}

void Epoll::ep_add(FdObj *fdobj, uint32_t events, bool exist) const noexcept {
    auto op = exist ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
    epoll_event ev{
        .events = events,
        .data = {.ptr = fdobj},
    };
    if (::epoll_ctl(_epfd, op, fdobj->_fd, &ev) < 0) [[unlikely]]
        log_error("epoll_ctl(epfd:%d, op:%d, fd:%d, events:%u) failed: (%d) %m", _epfd, op, fdobj->_fd, (unsigned)events, errno);
}

void Epoll::ep_del(FdObj *fdobj) const noexcept {
    auto op = EPOLL_CTL_DEL;
    if (::epoll_ctl(_epfd, op, fdobj->_fd, nullptr) < 0) [[unlikely]]
        log_error("epoll_ctl(epfd:%d, op:%d, fd:%d, events:%u) failed: (%d) %m", _epfd, op, fdobj->_fd, 0U, errno);
}
