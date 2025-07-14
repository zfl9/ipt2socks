#include "../fd.hpp"

bool Fd::RecvfromAwaitable::await_ready() noexcept {
    assert(this == &std::get<RecvfromAwaitable>(this->_fdobj->_read_awaitable));
    //todo
    return false;
}
void Fd::RecvfromAwaitable::await_suspend(std::coroutine_handle<> caller) noexcept {
    _caller = caller;
    //todo
}
ssize_t Fd::RecvfromAwaitable::await_resume() const noexcept {
    return _nbyte;
}
