#include "log.h"
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <coroutine>

/* socket operations return an awaitable object */
namespace co_sock {
    bool new_sock(int domain, int type) noexcept;
    bool new_listen_sock(int domain, int type) noexcept;
    bool new_tcpconn_sock(int domain, int type) noexcept;

    void setup_for_listen(int fd) noexcept;
    void setup_for_tcpconn(int fd) noexcept;

    struct connect {
        std::coroutine_handle<> _caller;
        int _fd;
        bool _ok;
        explicit connect(int fd, const sockaddr *addr) noexcept;
        bool await_ready() noexcept;
        void await_suspend(std::coroutine_handle<> caller) const noexcept;
        bool await_resume() const noexcept;
    };

    struct accept {
        int _fd;
        int _cfd;
        sockaddr *_caddr;
        explicit accept(int fd, sockaddr *caddr = nullptr) noexcept;
        bool await_ready() const noexcept;
        void await_suspend(std::coroutine_handle<>) const noexcept;
        bool await_resume() const noexcept;
    };
}

