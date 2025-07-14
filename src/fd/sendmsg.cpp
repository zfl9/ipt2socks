#include "../fd.hpp"

bool Fd::SendmsgAwaitable::await_ready() noexcept {
    assert(this == &std::get<SendmsgAwaitable>(this->_fdobj->_write_awaitable));
    //todo
    return false;
}
void Fd::SendmsgAwaitable::await_suspend(std::coroutine_handle<> caller) noexcept {
    _caller = caller;
    //todo
}
ssize_t Fd::SendmsgAwaitable::await_resume() const noexcept {
    return _nbyte;
}
