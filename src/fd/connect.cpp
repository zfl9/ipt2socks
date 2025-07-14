#include "../fd.hpp"

bool Fd::ConnectAwaitable::await_ready() noexcept {
    assert(this == &std::get<ConnectAwaitable>(this->_fdobj->_write_awaitable));
    //todo
    return false;
}
void Fd::ConnectAwaitable::await_suspend(std::coroutine_handle<> caller) noexcept {
    _caller = caller;
    //todo
}
bool Fd::ConnectAwaitable::await_resume() const noexcept {
    return _ok;
}
