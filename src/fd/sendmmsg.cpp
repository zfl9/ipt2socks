#include "../fd.hpp"

bool Fd::SendmmsgAwaitable::await_ready() noexcept {
    assert(this == &std::get<SendmmsgAwaitable>(this->_fdobj->_write_awaitable));
    //todo
    return false;
}
void Fd::SendmmsgAwaitable::await_suspend(std::coroutine_handle<> caller) noexcept {
    _caller = caller;
    //todo
}
ssize_t Fd::SendmmsgAwaitable::await_resume() const noexcept {
    return _nmsg;
}
