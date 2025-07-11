#pragma once

#include "log.h"
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <coroutine>
#include <utility>
#include <cassert>

/* socket operations return an awaitable object */
// namespace co_sock {
    // int new_sock(int family, int type) noexcept;
    // int new_listen_sock(int family, int type, int v6only = -1, bool reuse_port = false) noexcept;
    // int new_tcpconn_sock(int family, int type, bool keepalive = true) noexcept;
// }

struct FdRef;

struct Fd {
    static FdRef create(int fd) noexcept;

    int fd() const noexcept {
        return _fd;
    }

    struct AcceptAwaitable {
        std::coroutine_handle<> _caller{};
        Fd *_fdobj;
        sockaddr *_addr;
        socklen_t *_addrlen;
        int _cfd = -1;
        AcceptAwaitable(Fd *fdobj, sockaddr *addr, socklen_t *addrlen) noexcept;
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        int await_resume() const noexcept; // cfd
    };
    AcceptAwaitable accept(sockaddr *addr = nullptr, socklen_t *addrlen = nullptr) noexcept {
        return {this, addr, addrlen};
    }

    struct ConnectAwaitable {
        std::coroutine_handle<> _caller;
        Fd *_fdobj;
        bool _ok;
        ConnectAwaitable(Fd *fdobj, const sockaddr *addr, socklen_t addrlen) noexcept;
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        bool await_resume() const noexcept; // ok
    };
    ConnectAwaitable connect(const sockaddr *addr, socklen_t addrlen) noexcept {
        return {this, addr, addrlen};
    }

    struct RecvAwaitable {
        std::coroutine_handle<> _caller;
        void *_buf;
        size_t _len;
        ssize_t _nbyte;
        int _fd;
        int _flags;
        explicit RecvAwaitable(int fd, void *buf, size_t len, int flags = 0) noexcept;
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nbyte
    };

    struct recvfrom {
        std::coroutine_handle<> _caller;
        sockaddr *_addr;
        socklen_t *_addrlen;
        void *_buf;
        size_t _len;
        ssize_t _nbyte;
        int _fd;
        int _flags;
        explicit recvfrom(int fd, void *buf, size_t len, sockaddr *addr, socklen_t *addrlen, int flags = 0) noexcept;
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nbyte
    };

    struct recvmsg {
        std::coroutine_handle<> _caller;
        msghdr *_msg;
        ssize_t _nbyte;
        int _fd;
        int _flags;
        explicit recvmsg(int fd, msghdr *msg, int flags = 0) noexcept;
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nbyte
    };

    struct recvmmsg {
        std::coroutine_handle<> _caller;
        mmsghdr *_msgv;
        unsigned int _vlen;
        int _nmsg;
        int _fd;
        int _flags;
        explicit recvmmsg(int fd, mmsghdr *msgv, unsigned int vlen, int flags = 0) noexcept;
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nmsg
    };

    struct send {
        std::coroutine_handle<> _caller;
        const void *_buf;
        size_t _len;
        ssize_t _nbyte;
        int _fd;
        int _flags;
        explicit send(int fd, const void *buf, size_t len, int flags = 0) noexcept;
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nbyte
    };

    struct sendto {
        std::coroutine_handle<> _caller;
        const sockaddr *_addr;
        void *_buf;
        size_t _len;
        ssize_t _nbyte;
        socklen_t _addrlen;
        int _fd;
        int _flags;
        explicit sendto(int fd, const void *buf, size_t len, const sockaddr *addr, socklen_t addrlen, int flags = 0) noexcept;
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nbyte
    };

    struct sendmsg {
        std::coroutine_handle<> _caller;
        const msghdr *_msg;
        ssize_t _nbyte;
        int _fd;
        int _flags;
        explicit sendmsg(int fd, const msghdr *msg, int flags = 0) noexcept;
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nbyte
    };

    struct sendmmsg {
        std::coroutine_handle<> _caller;
        mmsghdr *_msgv;
        unsigned int _vlen;
        int _nmsg;
        int _fd;
        int _flags;
        explicit sendmmsg(int fd, mmsghdr *msgv, unsigned int vlen, int flags = 0) noexcept;
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nmsg
    };

private:
    enum class State : uint8_t {
        ok,
        dirty, // `_events` has changed and needs to be synchronized to the epoll
        zombie, // the event loop is responsible for destruction (releasing resources)
    };

    using Callback = void (*)(Fd *sock, void *userdata) noexcept;

    explicit Fd(int fd) noexcept : _fd{fd} {
        assert(_fd >= 0);
    }

    // called by EvLoop
    ~Fd() noexcept {
        assert(_state == State::zombie);
        close_fd();
    }

    // called by FdRef
    void ref() noexcept {
        ++_ref_count;
    }

    // called by FdRef
    void unref() noexcept {
        if (--_ref_count == 0)
            set_state(State::zombie);
    }

    void set_state(State to_state) noexcept;

    void close_fd() noexcept {
        if (_fd >= 0) {
            ::close(_fd);
            _fd = -1;
        }
    }

    union ReadCtx {
        std::coroutine_handle<> caller;
    } _read_ctx{};

    union WriteCtx {
        std::coroutine_handle<> caller;
    } _write_ctx{};

    Callback _read_cb = nullptr;
    Callback _write_cb = nullptr;
    void *_read_cbdata = nullptr;
    void *_write_cbdata = nullptr;

    Fd *_prev = nullptr;
    Fd *_next = nullptr;

    uint32_t _ref_count = 0; // ref by FdRef
    uint32_t _epoll_events = 0; // events registered in epoll
    uint32_t _events = 0; // modified events
    int _fd;
    State _state = State::ok;

    friend struct FdRef;
    friend struct EvLoop; 
};

// smart pointer based on reference counting (non thread safe)
struct FdRef {
    FdRef(const FdRef &other) noexcept : _obj{other._obj} {
        if (_obj) _obj->ref();
    }
    FdRef(FdRef &&other) noexcept : _obj{other._obj} {
        other._obj = nullptr;
    }

    FdRef &operator=(const FdRef &other) noexcept {
        if (&other != this) {
            if (_obj) _obj->unref();
            _obj = other._obj;
            if (_obj) _obj->ref();
        }
        return *this;
    }
    FdRef &operator=(FdRef &&other) noexcept {
        if (&other != this) {
            if (_obj) _obj->unref();
            _obj = other._obj;
            other._obj = nullptr;
        }
        return *this;
    }
    FdRef &operator=(std::nullptr_t) noexcept {
        if (_obj) {
            _obj->unref();
            _obj = nullptr;
        }
        return *this;
    }

    Fd *operator->() const noexcept {
        return _obj;
    }
    Fd &operator*() const noexcept {
        return *_obj;
    }
    explicit operator bool() const noexcept {
        return _obj != nullptr;
    }

    uint32_t ref_count() const noexcept {
        return _obj ? _obj->_ref_count : 0;
    }

    ~FdRef() noexcept {
        if (_obj) _obj->unref();
    }

private:
    friend struct Fd; // used to construct from a raw pointer
    friend struct EvLoop; // used to construct from a raw pointer

    explicit FdRef(Fd *obj) noexcept : _obj{obj} {
        if (_obj) _obj->ref();
    }

    Fd *_obj;
};

inline FdRef Fd::create(int fd) noexcept {
    return FdRef{new Fd{fd}};
}
