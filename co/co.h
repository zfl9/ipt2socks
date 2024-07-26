#pragma once

#include <assert.h>

/* stackless-coroutine API (freestanding and/or hosted environment) */

#define co__concat_(a, b) a##b
#define co__concat(a, b) co__concat_(a, b)

#define co__static_assert(expr) _Static_assert(expr, #expr)
#define co__is_same_type(a, b) __builtin_types_compatible_p(__typeof__(a), __typeof__(b))
#define co__assert_same_type(a, b) co__static_assert(co__is_same_type(a, b))

// used for `co_async`, `co_async_ex`
void co_sentinel(void *restrict co, void *);

// the type of async fn (name the first arg as `c`)
typedef void co_fn_t(void *restrict co, void *arg);

// other co that will be `co_call` from itself
#define co_nested(fn) struct fn fn

#define CO_LABEL_END (-1)

// basic fields of the `co` struct
#define co_fields(nested...) \
    co_fn_t *cont_cb; \
    void *cont_co; \
    union { nested } u; \
    int label;

// init the co struct before calling it
#define co_init(co, cont_cb_, cont_co_) do { \
    (co)->cont_cb = (co_fn_t *)(cont_cb_); \
    (co)->cont_co = (cont_co_); \
    (co)->label = 0; \
} while (0)

// begin an async fn
#define co_begin(fn) \
    co__assert_same_type(c, struct fn *); \
    co_fn_t *_fn_ = (co_fn_t *)(&fn); \
    goto *(&&co_begin + c->label); \
    co_begin:

// suspend the current fn
#define co_suspend(stub...) do { \
    c->label = &&co__concat(co_, __LINE__) - &&co_begin; \
    return stub; \
    co__concat(co_, __LINE__):; \
} while (0)

// access the co of the nested fn
#define co_at(fn) (&c->u.fn)

// call `fn(args)` from the current fn
#define co_call(fn, args...) do { \
    co_init(co_at(fn), _fn_, c); \
    co_suspend(fn(co_at(fn), &(struct fn##_arg){args})); \
} while (0)

// end an async fn
#define co_end() \
    c->label = CO_LABEL_END; \
    return c->cont_cb(c->cont_co, NULL)

// start an async call (does not suspend the current fn)
#define co_async_ex(co, auto_free, fn, args...) do { \
    co__assert_same_type(co, struct fn *); \
    co_init(co, co_sentinel, (auto_free) ? (co) : NULL); \
    fn(co, &(struct fn##_arg){args}); \
} while (0)

// start an async call (does not suspend the current fn)
#define co_async(co, fn, args...) co_async_ex(co, 0, fn, args)

// wait for an async call to complete (must be used in an async fn)
#define co_await(co) do { \
    assert((co)->cont_cb == co_sentinel); \
    if ((co)->label != CO_LABEL_END) { \
        (co)->cont_cb = _fn_; \
        (co)->cont_co = c; \
        co_suspend(); \
        assert((co)->label == CO_LABEL_END); \
    } \
} while (0)
