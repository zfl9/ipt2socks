#include "../fd.hpp"

bool Fd::RecvmsgAwaitable::await_ready() noexcept {
    assert(this == &std::get<RecvmsgAwaitable>(this->_fdobj->_read_awaitable));
    //todo
    return false;
}
void Fd::RecvmsgAwaitable::await_suspend(std::coroutine_handle<> caller) noexcept {
    _caller = caller;
    //todo
}
ssize_t Fd::RecvmsgAwaitable::await_resume() const noexcept {
    return _nbyte;
}
