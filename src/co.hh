#include <coroutine>
#include <utility>
#include <cassert>

/* awaitable coroutine (called with co_await) */
template<typename Result>
struct CoFuture {
    struct promise_type {
        std::coroutine_handle<> _caller;
        Result _result;

        CoFuture get_return_object() noexcept {
            return CoFuture(std::coroutine_handle<promise_type>::from_promise(*this));
        }
        std::suspend_always initial_suspend() const noexcept {
            return {};
        }
        std::suspend_never final_suspend() const noexcept {
            if (_caller) _caller.resume(); // access `_co.promise()._result`
            return {};
        }
        template<typename R>
        void return_value(R &&result) noexcept {
            _result = std::forward<R>(result);
        }
        void unhandled_exception() const noexcept {}
    };

    bool await_ready() const noexcept {
        assert(!_co.done()); // suspended by `initial_suspend()`
        return false;
    }
    void await_suspend(std::coroutine_handle<> caller) const noexcept {
        _co.promise()._caller = caller;
        _co.resume(); // continue execution from `initial_suspend()`
    }
    Result await_resume() const noexcept {
        return std::move(_co.promise()._result);
    }

private:
    explicit CoFuture(std::coroutine_handle<promise_type> co) : _co(co) {}

    CoFuture(const CoFuture &) = delete;
    CoFuture(CoFuture &&) = delete;
    CoFuture &operator=(const CoFuture &) = delete;
    CoFuture &operator=(CoFuture &&) = delete;

    const std::coroutine_handle<promise_type> _co;
};

/* awaitable coroutine (called with co_await) */
template<>
struct CoFuture<void> {
    struct promise_type {
        std::coroutine_handle<> _caller;

        CoFuture get_return_object() noexcept {
            return CoFuture(std::coroutine_handle<promise_type>::from_promise(*this));
        }
        std::suspend_always initial_suspend() const noexcept {
            return {};
        }
        std::suspend_never final_suspend() const noexcept {
            if (_caller) _caller.resume();
            return {};
        }
        void return_void() const noexcept {}
        void unhandled_exception() const noexcept {}
    };

    bool await_ready() const noexcept {
        assert(!_co.done()); // suspended by `initial_suspend()`
        return false;
    }
    void await_suspend(std::coroutine_handle<> caller) const noexcept {
        _co.promise()._caller = caller;
        _co.resume(); // continue execution from `initial_suspend()`
    }
    void await_resume() const noexcept {}

private:
    explicit CoFuture(std::coroutine_handle<promise_type> co) : _co(co) {}

    CoFuture(const CoFuture &) = delete;
    CoFuture(CoFuture &&) = delete;
    CoFuture &operator=(const CoFuture &) = delete;
    CoFuture &operator=(CoFuture &&) = delete;

    const std::coroutine_handle<promise_type> _co;
};

/* coroutine (like thread, execute async task) */
struct CoAsync {
    struct promise_type {
        CoAsync get_return_object() const noexcept { return {}; }
        std::suspend_never initial_suspend() const noexcept { return {}; }
        std::suspend_never final_suspend() const noexcept { return {}; }
        void return_void() const noexcept {}
        void unhandled_exception() const noexcept {}
    };
};
