#include "../fd.hpp"

bool Fd::SendtoAwaitable::await_ready() noexcept {
    assert(this == &std::get<SendtoAwaitable>(this->_fdobj->_write_awaitable));
    //todo
    return false;
}
void Fd::SendtoAwaitable::await_suspend(std::coroutine_handle<> caller) noexcept {
    _caller = caller;
    //todo
}
ssize_t Fd::SendtoAwaitable::await_resume() const noexcept {
    return _nbyte;
}
