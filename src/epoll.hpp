#pragma once

#include <cstdint>

struct FdObj;

struct Epoll {
    static void run() noexcept {
        return instance()->loop_run();
    }

    static void stop() noexcept {
        instance()->_stop = true;
    }

private:
    friend struct FdObj;

    static void add_fdobj(FdObj *fdobj) noexcept {
        return instance()->fdobj_add(fdobj);
    }
    static void del_fdobj(FdObj *fdobj) noexcept {
        return instance()->fdobj_del(fdobj);
    }

    // =============== internal ===============

    static Epoll *instance() noexcept {
        static thread_local Epoll epoll{};
        return &epoll;
    }

    Epoll() noexcept;
    ~Epoll() noexcept;

    void time_fetch() noexcept;
    void loop_run() noexcept;

    void timer_process() noexcept;
    int timer_timeout() const noexcept;

    void fdobj_add(FdObj *fdobj) noexcept;
    void fdobj_del(FdObj *fdobj) noexcept;
    void fdobj_commit() noexcept;

    void ep_add(FdObj *fdobj, uint32_t events, bool exist) const noexcept;
    void ep_del(FdObj *fdobj) const noexcept;

    // timer manager
    

    FdObj *_fdobj_list = nullptr;
    uint64_t _time_ms;
    int _epfd;
    bool _stop = false;
};
