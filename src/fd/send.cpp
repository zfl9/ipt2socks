#include "../fd.hpp"

bool Fd::SendAwaitable::await_ready() noexcept {
    assert(this == &std::get<SendAwaitable>(this->_fdobj->_write_awaitable));
    //todo
    return false;
}
void Fd::SendAwaitable::await_suspend(std::coroutine_handle<> caller) noexcept {
    _caller = caller;
    //todo
}
ssize_t Fd::SendAwaitable::await_resume() const noexcept {
    return _nbyte;
}
