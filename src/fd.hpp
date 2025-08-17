#pragma once

#include <coroutine>
#include <variant>
#include <cstdint>
#include <cassert>
#include <unistd.h>
#include <sys/socket.h>

struct FdRef;

struct FdObj {
    int fd() const noexcept { return _fd; }

    enum class AwaitableTag {reader, writer};

    template<typename Impl, AwaitableTag tag>
    struct Awaitable {
        std::coroutine_handle<> _caller{};
        FdObj *_fdobj;

        explicit Awaitable(FdObj *fdobj) noexcept : _fdobj{fdobj} {};

        auto impl() noexcept { return static_cast<Impl *>(this); }
        auto impl() const noexcept { return static_cast<const Impl *>(this); }

        bool await_ready() noexcept {
            if constexpr (tag == AwaitableTag::reader)
                assert(impl() == &std::get<Impl>(_fdobj->_reader));
            else
                assert(impl() == &std::get<Impl>(_fdobj->_writer));
            return impl()->ready();
        }
        void await_suspend(std::coroutine_handle<> caller) noexcept {
            _caller = caller;
            if constexpr (tag == AwaitableTag::reader) {
                _fdobj->set_read_callback([](FdObj *fdobj) noexcept {
                    std::get<Impl>(fdobj->_reader).callback();
                });
            } else {
                _fdobj->set_write_callback([](FdObj *fdobj) noexcept {
                    std::get<Impl>(fdobj->_writer).callback();
                });
            }
        }
        auto await_resume() const noexcept {
            return impl()->_result;
        }
        void callback() noexcept {
            if (impl()->ready()) {
                if constexpr (tag == AwaitableTag::reader)
                    _fdobj->del_read_callback();
                else
                    _fdobj->del_write_callback();
                _caller.resume();
            }
        }
    };

    struct AcceptAwaitable : Awaitable<AcceptAwaitable, AwaitableTag::reader> {
        sockaddr *_addr;
        socklen_t *_addrlen;
        int _result = -1;
        explicit AcceptAwaitable(FdObj *fdobj, sockaddr *addr, socklen_t *addrlen) noexcept
            : Awaitable{fdobj}, _addr{addr}, _addrlen{addrlen} {}
        bool ready() noexcept;
    };
    AcceptAwaitable &accept(sockaddr *addr = nullptr, socklen_t *addrlen = nullptr) noexcept {
        return _reader.emplace<AcceptAwaitable>(this, addr, addrlen);
    }

    struct ConnectAwaitable : Awaitable<ConnectAwaitable, AwaitableTag::writer> {
        const sockaddr *_addr;
        socklen_t _addrlen;
        int _result = 1;
        ConnectAwaitable(FdObj *fdobj, const sockaddr *addr, socklen_t addrlen) noexcept
            : Awaitable{fdobj}, _addr{addr}, _addrlen{addrlen} {} 
        bool ready() noexcept;
    };
    ConnectAwaitable &connect(const sockaddr *addr, socklen_t addrlen) noexcept {
        return _writer.emplace<ConnectAwaitable>(this, addr, addrlen);
    }

    struct RecvAwaitable : Awaitable<RecvAwaitable, AwaitableTag::reader> {
        sockaddr *_addr;
        socklen_t *_addrlen;
        void *_buf;
        size_t _len;
        ssize_t _result = -1;
        int _flags;
        explicit RecvAwaitable(FdObj *fdobj, void *buf, size_t len, int flags, sockaddr *addr, socklen_t *addrlen) noexcept 
            : Awaitable{fdobj}, _addr{addr}, _addrlen{addrlen}, _buf{buf}, _len{len}, _flags{flags} {}
        bool ready() noexcept;
    };
    RecvAwaitable &recv(void *buf, size_t len, int flags = 0, sockaddr *addr = nullptr, socklen_t *addrlen = nullptr) noexcept {
        return _reader.emplace<RecvAwaitable>(this, buf, len, flags, addr, addrlen);
    }

    struct SendAwaitable : Awaitable<SendAwaitable, AwaitableTag::writer> {
        const sockaddr *_addr;
        const void *_buf;
        size_t _len;
        ssize_t _result = -1;
        socklen_t _addrlen;
        int _flags;
        explicit SendAwaitable(FdObj *fdobj, const void *buf, size_t len, int flags, const sockaddr *addr, socklen_t addrlen) noexcept
            : Awaitable{fdobj}, _addr{addr}, _buf{buf}, _len{len}, _addrlen{addrlen}, _flags{flags} {}
        bool ready() noexcept;
    };
    SendAwaitable &send(const void *buf, size_t len, int flags = 0, const sockaddr *addr = nullptr, socklen_t addrlen = 0) noexcept {
        return _writer.emplace<SendAwaitable>(this, buf, len, flags, addr, addrlen);
    }

    struct RecvmsgAwaitable : Awaitable<RecvmsgAwaitable, AwaitableTag::reader> {
        msghdr *_msg;
        ssize_t _result = -1;
        int _flags;
        explicit RecvmsgAwaitable(FdObj *fdobj, msghdr *msg, int flags) noexcept
            : Awaitable{fdobj}, _msg{msg}, _flags{flags} {}
        bool ready() noexcept;
    };
    RecvmsgAwaitable &recvmsg(msghdr *msg, int flags = 0) noexcept {
        return _reader.emplace<RecvmsgAwaitable>(this, msg, flags);
    }

    struct SendmsgAwaitable : Awaitable<SendmsgAwaitable, AwaitableTag::writer> {
        const msghdr *_msg;
        ssize_t _result;
        int _flags;
        explicit SendmsgAwaitable(FdObj *fdobj, const msghdr *msg, int flags) noexcept
            : Awaitable{fdobj}, _msg{msg}, _flags(flags) {}
        bool ready() noexcept;
    };
    SendmsgAwaitable &sendmsg(const msghdr *msg, int flags = 0) noexcept {
        return _writer.emplace<SendmsgAwaitable>(this, msg, flags);
    }

    struct RecvmmsgAwaitable : Awaitable<RecvmmsgAwaitable, AwaitableTag::reader> {
        mmsghdr *_msgv;
        unsigned int _vlen;
        int _result = -1;
        int _flags;
        explicit RecvmmsgAwaitable(FdObj *fdobj, mmsghdr *msgv, unsigned int vlen, int flags) noexcept
            : Awaitable{fdobj}, _msgv{msgv}, _vlen{vlen}, _flags{flags} {}
        bool ready() noexcept;
    };
    RecvmmsgAwaitable &recvmmsg(mmsghdr *msgv, unsigned int vlen, int flags = 0) noexcept {
        return _reader.emplace<RecvmmsgAwaitable>(this, msgv, vlen, flags);
    }

    struct SendmmsgAwaitable : Awaitable<SendmmsgAwaitable, AwaitableTag::writer> {
        mmsghdr *_msgv;
        unsigned int _vlen;
        int _result;
        int _flags;
        explicit SendmmsgAwaitable(FdObj *fdobj, mmsghdr *msgv, unsigned int vlen, int flags) noexcept
            : Awaitable{fdobj}, _msgv{msgv}, _vlen{vlen}, _flags{flags} {}
        bool ready() noexcept;
    };
    SendmmsgAwaitable &sendmmsg(mmsghdr *msgv, unsigned int vlen, int flags = 0) noexcept {
        return _writer.emplace<SendmmsgAwaitable>(this, msgv, vlen, flags);
    }

private:
    friend struct FdRef;
    friend struct Epoll; 

    enum class Op : uint8_t {
        none,
        update_event,
        destroy,
    };

    using Callback = void (*)(FdObj *) noexcept;

    // called in create()
    explicit FdObj(int fd) noexcept : _fd{fd} {
        assert(_fd >= 0);
    }

    // called in Epoll
    ~FdObj() noexcept {
        assert(_ref_count == 0);
        assert(_defer_op == Op::destroy);
        assert(_read_callback == nullptr);
        assert(_write_callback == nullptr);

        if (_fd >= 0)
            ::close(_fd);
    }

    // called in FdRef
    void ref() noexcept {
        ++_ref_count;
    }

    // called in FdRef
    void unref() noexcept {
        if (--_ref_count == 0)
            defer_op(Op::destroy);
    }

    struct CommitResult {
        bool read, write;
        bool exist;
        Op op;
    };
    CommitResult commit() noexcept;

    uint8_t current_events() const noexcept;

    void on_readable() noexcept {
        if (_read_callback)
            _read_callback(this);
    }
    void on_writable() noexcept {
        if (_write_callback)
            _write_callback(this);
    }

    void defer_op(Op op) noexcept;

    void set_read_callback(Callback callback) noexcept;
    void set_write_callback(Callback callback) noexcept;
    void del_read_callback() noexcept;
    void del_write_callback() noexcept;
    void on_callback_change() noexcept;

    std::variant<
        std::monostate,
        AcceptAwaitable,
        RecvAwaitable,
        RecvmsgAwaitable,
        RecvmmsgAwaitable> _reader{};

    std::variant<
        std::monostate,
        ConnectAwaitable,
        SendAwaitable,
        SendmsgAwaitable,
        SendmmsgAwaitable> _writer{};

    Callback _read_callback = nullptr;
    Callback _write_callback = nullptr;

    // managed by Epoll
    FdObj *_defer_prev = nullptr;
    FdObj *_defer_next = nullptr;

    uint32_t _ref_count = 0;
    int _fd;

    Op _defer_op = Op::none;
    uint8_t _saved_events = 0;
};

// smart pointer based on reference counting
struct FdRef {
    static FdRef create(int fd) noexcept {
        return FdRef{ new FdObj{fd} };
    }

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

    FdObj *operator->() const noexcept {
        return _obj;
    }
    FdObj &operator*() const noexcept {
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
    friend struct FdObj;
    friend struct Epoll;

    explicit FdRef(FdObj *obj) noexcept : _obj{obj} {
        if (_obj) _obj->ref();
    }

    FdObj *_obj;
};
