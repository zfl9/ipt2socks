#pragma once

#include <coroutine>
#include <variant>
#include <cstdint>
#include <cassert>
#include <unistd.h>
#include <sys/socket.h>

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
        explicit AcceptAwaitable(Fd *fdobj, sockaddr *addr, socklen_t *addrlen) noexcept
            : _fdobj{fdobj}, _addr{addr}, _addrlen{addrlen} {}
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        int await_resume() const noexcept; // cfd
        void callback() noexcept;
    };
    AcceptAwaitable &accept(sockaddr *addr = nullptr, socklen_t *addrlen = nullptr) noexcept {
        return _read_awaitable.emplace<AcceptAwaitable>(this, addr, addrlen);
    }

    struct ConnectAwaitable {
        std::coroutine_handle<> _caller{};
        Fd *_fdobj;
        const sockaddr *_addr;
        socklen_t _addrlen;
        bool _ok{false};
        ConnectAwaitable(Fd *fdobj, const sockaddr *addr, socklen_t addrlen) noexcept
            : _fdobj{fdobj}, _addr{addr}, _addrlen{addrlen} {} 
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        bool await_resume() const noexcept; // ok
        void callback() noexcept;
    };
    ConnectAwaitable &connect(const sockaddr *addr, socklen_t addrlen) noexcept {
        return _write_awaitable.emplace<ConnectAwaitable>(this, addr, addrlen);
    }

    struct RecvAwaitable {
        std::coroutine_handle<> _caller{};
        Fd *_fdobj;
        void *_buf;
        size_t _len;
        ssize_t _nbyte{0};
        int _flags;
        explicit RecvAwaitable(Fd *fdobj, void *buf, size_t len, int flags) noexcept
            : _fdobj{fdobj}, _buf{buf}, _len{len}, _flags{flags} {}
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nbyte
        void callback() noexcept;
    };
    RecvAwaitable &recv(void *buf, size_t len, int flags = 0) noexcept {
        return _read_awaitable.emplace<RecvAwaitable>(this, buf, len, flags);
    }

    struct RecvfromAwaitable {
        std::coroutine_handle<> _caller{};
        Fd *_fdobj;
        sockaddr *_addr;
        socklen_t *_addrlen;
        void *_buf;
        size_t _len;
        ssize_t _nbyte{0};
        int _flags;
        explicit RecvfromAwaitable(Fd *fdobj, void *buf, size_t len, sockaddr *addr, socklen_t *addrlen, int flags) noexcept 
            : _fdobj{fdobj}, _addr{addr}, _addrlen{addrlen}, _buf{buf}, _len{len}, _flags{flags} {}
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nbyte
        void callback() noexcept;
    };
    RecvfromAwaitable &recvfrom(void *buf, size_t len, sockaddr *addr, socklen_t *addrlen, int flags = 0) noexcept {
        return _read_awaitable.emplace<RecvfromAwaitable>(this, buf, len, addr, addrlen, flags);
    }

    struct RecvmsgAwaitable {
        std::coroutine_handle<> _caller{};
        Fd *_fdobj;
        msghdr *_msg;
        ssize_t _nbyte{0};
        int _flags;
        explicit RecvmsgAwaitable(Fd *fdobj, msghdr *msg, int flags) noexcept
            : _fdobj{fdobj}, _msg{msg}, _flags{flags} {}
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nbyte
        void callback() noexcept;
    };
    RecvmsgAwaitable &recvmsg(msghdr *msg, int flags = 0) noexcept {
        return _read_awaitable.emplace<RecvmsgAwaitable>(this, msg, flags);
    }

    struct RecvmmsgAwaitable {
        std::coroutine_handle<> _caller{};
        Fd *_fdobj;
        mmsghdr *_msgv;
        unsigned int _vlen;
        int _nmsg{0};
        int _flags;
        explicit RecvmmsgAwaitable(Fd *fdobj, mmsghdr *msgv, unsigned int vlen, int flags) noexcept
            : _fdobj{fdobj}, _msgv{msgv}, _vlen{vlen}, _flags{flags} {}
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nmsg
        void callback() noexcept;
    };
    RecvmmsgAwaitable &recvmmsg(mmsghdr *msgv, unsigned int vlen, int flags = 0) noexcept {
        return _read_awaitable.emplace<RecvmmsgAwaitable>(this, msgv, vlen, flags);
    }

    struct SendAwaitable {
        std::coroutine_handle<> _caller{};
        Fd *_fdobj;
        const void *_buf;
        size_t _len;
        ssize_t _nbyte{0};
        int _flags;
        explicit SendAwaitable(Fd *fdobj, const void *buf, size_t len, int flags) noexcept
            : _fdobj{fdobj}, _buf{buf}, _len{len}, _flags{flags} {}
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nbyte
        void callback() noexcept;
    };
    SendAwaitable &send(const void *buf, size_t len, int flags = 0) noexcept {
        return _write_awaitable.emplace<SendAwaitable>(this, buf, len, flags);
    }

    struct SendtoAwaitable {
        std::coroutine_handle<> _caller{};
        Fd *_fdobj;
        const sockaddr *_addr;
        const void *_buf;
        size_t _len;
        ssize_t _nbyte{0};
        socklen_t _addrlen;
        int _flags;
        explicit SendtoAwaitable(Fd *fdobj, const void *buf, size_t len, const sockaddr *addr, socklen_t addrlen, int flags) noexcept
            : _fdobj{fdobj}, _addr{addr}, _buf{buf}, _len{len}, _addrlen{addrlen}, _flags{flags} {}
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nbyte
        void callback() noexcept;
    };
    SendtoAwaitable &sendto(const void *buf, size_t len, const sockaddr *addr, socklen_t addrlen, int flags = 0) noexcept {
        return _write_awaitable.emplace<SendtoAwaitable>(this, buf, len, addr, addrlen, flags);
    }

    struct SendmsgAwaitable {
        std::coroutine_handle<> _caller{};
        Fd *_fdobj;
        const msghdr *_msg;
        ssize_t _nbyte{};
        int _flags;
        explicit SendmsgAwaitable(Fd *fdobj, const msghdr *msg, int flags) noexcept
            : _fdobj{fdobj}, _msg{msg}, _flags(flags) {}
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nbyte
        void callback() noexcept;
    };
    SendmsgAwaitable &sendmsg(const msghdr *msg, int flags = 0) noexcept {
        return _write_awaitable.emplace<SendmsgAwaitable>(this, msg, flags);
    }

    struct SendmmsgAwaitable {
        std::coroutine_handle<> _caller{};
        Fd *_fdobj;
        mmsghdr *_msgv;
        unsigned int _vlen;
        int _nmsg{};
        int _flags;
        explicit SendmmsgAwaitable(Fd *fdobj, mmsghdr *msgv, unsigned int vlen, int flags) noexcept
            : _fdobj{fdobj}, _msgv{msgv}, _vlen{vlen}, _flags{flags} {}
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) noexcept;
        ssize_t await_resume() const noexcept; // nmsg
        void callback() noexcept;
    };
    SendmmsgAwaitable &sendmmsg(mmsghdr *msgv, unsigned int vlen, int flags = 0) noexcept {
        return _write_awaitable.emplace<SendmmsgAwaitable>(this, msgv, vlen, flags);
    }

private:
    enum class State : uint8_t {
        ok,
        dirty, // `_events` has changed and needs to be synchronized to the epoll
        zombie, // the event loop is responsible for destruction (releasing resources)
    };

    using Callback = void (*)(Fd *sock) noexcept;

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

    friend struct FdRef;
    friend struct EvLoop; 

    std::variant<
        std::monostate,
        AcceptAwaitable,
        RecvAwaitable,
        RecvfromAwaitable,
        RecvmsgAwaitable,
        RecvmmsgAwaitable> _read_awaitable{};

    std::variant<
        std::monostate,
        ConnectAwaitable,
        SendAwaitable,
        SendtoAwaitable,
        SendmsgAwaitable,
        SendmmsgAwaitable> _write_awaitable{};

    Callback _read_callback = nullptr;
    Callback _write_callback = nullptr;

    Fd *_prev = nullptr;
    Fd *_next = nullptr;

    uint32_t _ref_count = 0; // ref by FdRef
    uint32_t _epoll_events = 0; // events registered in epoll
    uint32_t _events = 0; // modified events
    int _fd;
    State _state = State::ok;
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
