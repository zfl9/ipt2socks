#include "../fd.hpp"

bool Fd::RecvAwaitable::await_ready() noexcept {
    assert(this == &std::get<RecvAwaitable>(this->_fdobj->_read_awaitable));
    //todo
    return false;
}
void Fd::RecvAwaitable::await_suspend(std::coroutine_handle<> caller) noexcept {
    _caller = caller;
    //todo
}
ssize_t Fd::RecvAwaitable::await_resume() const noexcept {
    return _nbyte;
}
