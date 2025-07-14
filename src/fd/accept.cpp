#include "../fd.hpp"

bool Fd::AcceptAwaitable::await_ready() noexcept {
    assert(this == &std::get<AcceptAwaitable>(this->_fdobj->_read_awaitable));
    _cfd = ::accept4(_fdobj->_fd, _addr, _addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
    return _cfd >= 0;
}

void Fd::AcceptAwaitable::await_suspend(std::coroutine_handle<> caller) noexcept {
    _caller = caller;
    _fdobj->_read_callback = [](Fd *fdobj) noexcept {
        std::get<AcceptAwaitable>(fdobj->_read_awaitable).callback();
    };
}

int Fd::AcceptAwaitable::await_resume() const noexcept {
    return _cfd;
}

void Fd::AcceptAwaitable::callback() noexcept {
    
}
