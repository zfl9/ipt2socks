#include "fd.hpp"
#include "epoll.hpp"
#include "co.hpp"
#include "log.h"
#include <utility>
#include <cerrno>
#include <sys/epoll.h>
#include <stacktrace>
#include <iostream>

constexpr uint8_t EVENT_READ = 1 << 0;
constexpr uint8_t EVENT_WRITE = 1 << 1;

void FdObj::defer_op(Op op) noexcept {
    log_info("%d -> %d", std::to_underlying(_defer_op), std::to_underlying(op));

    assert(_defer_op != Op::destroy);

    if (_defer_op == op) return; 
    auto old_op = _defer_op;
    _defer_op = op;

    switch (op) {
        case Op::none:
            assert(old_op == Op::update_event);
            Epoll::del_fdobj(this);
            break;

        case Op::update_event:
            assert(old_op == Op::none);
            Epoll::add_fdobj(this);
            break;

        case Op::destroy:
            if (old_op == Op::none)
                Epoll::add_fdobj(this);
            break;

        default:
            std::unreachable();
    }
}

void FdObj::set_read_callback(Callback callback) noexcept {
    assert(_read_callback == nullptr);
    _read_callback = callback;
    on_callback_change();
}

void FdObj::set_write_callback(Callback callback) noexcept {
    assert(_write_callback == nullptr);
    _write_callback = callback;
    on_callback_change();
}

void FdObj::del_read_callback() noexcept {
    assert(_read_callback != nullptr);
    _read_callback = nullptr;
    on_callback_change();
}

void FdObj::del_write_callback() noexcept {
    assert(_write_callback != nullptr);
    _write_callback = nullptr;
    on_callback_change();
}

uint8_t FdObj::current_events() const noexcept {
    uint8_t events = 0;
    if (_read_callback) events |= EVENT_READ;
    if (_write_callback) events |= EVENT_WRITE;
    return events;
}

void FdObj::on_callback_change() noexcept {
    if (_saved_events != current_events())
        defer_op(Op::update_event);
    else
        defer_op(Op::none);
}

FdObj::CommitResult FdObj::commit() noexcept {
    bool exist = _saved_events != 0;
    _saved_events = current_events();

    auto op = _defer_op;
    if (op == Op::update_event)
        _defer_op = Op::none;

    return {
        .read = _read_callback != nullptr,
        .write = _write_callback != nullptr,
        .exist = exist,
        .op = op,
    };
}

bool FdObj::AcceptAwaitable::ready() noexcept {
    _result = ::accept4(_fdobj->_fd, _addr, _addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
    return _result >= 0 || errno != EAGAIN;
}

bool FdObj::ConnectAwaitable::ready() noexcept {
    if (_result == 1) {
        // first call
        _result = ::connect(_fdobj->_fd, _addr, _addrlen);
        return _result == 0 || errno != EINPROGRESS;
    } else {
        // non-first call
        int err;
        socklen_t errlen = sizeof(err);
        if (::getsockopt(_fdobj->_fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0) {
            _result = -1;
            // errno has been set by getsockopt
        } else if (err != 0) {
            _result = -1;
            errno = err;
        } else {
            _result = 0;
        }
        return true;
    }
}

bool FdObj::RecvAwaitable::ready() noexcept {
    _result = ::recvfrom(_fdobj->_fd, _buf, _len, _flags, _addr, _addrlen);
    return _result >= 0 || errno != EAGAIN;
}

bool FdObj::SendAwaitable::ready() noexcept {
    _result = ::sendto(_fdobj->_fd, _buf, _len, _flags, _addr, _addrlen);
    return _result >= 0 || errno != EAGAIN;
}

bool FdObj::RecvmsgAwaitable::ready() noexcept {
    _result = ::recvmsg(_fdobj->_fd, _msg, _flags);
    return _result >= 0 || errno != EAGAIN;
}

bool FdObj::SendmsgAwaitable::ready() noexcept {
    _result = ::sendmsg(_fdobj->_fd, _msg, _flags);
    return _result >= 0 || errno != EAGAIN;
}

bool FdObj::RecvmmsgAwaitable::ready() noexcept {
    _result = ::recvmmsg(_fdobj->_fd, _msgv, _vlen, _flags, nullptr);
    return _result >= 0 || errno != EAGAIN;
}

bool FdObj::SendmmsgAwaitable::ready() noexcept {
    _result = ::sendmmsg(_fdobj->_fd, _msgv, _vlen, _flags);
    return _result >= 0 || errno != EAGAIN;
}
