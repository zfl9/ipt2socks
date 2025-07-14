#include "../fd.hpp"

bool Fd::RecvmmsgAwaitable::await_ready() noexcept {
    assert(this == &std::get<RecvmmsgAwaitable>(this->_fdobj->_read_awaitable));
    //todo
    return false;
}
void Fd::RecvmmsgAwaitable::await_suspend(std::coroutine_handle<> caller) noexcept {
    _caller = caller;
    //todo
}
ssize_t Fd::RecvmmsgAwaitable::await_resume() const noexcept {
    return _nmsg;
}
