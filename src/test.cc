#include <memory>
#include <stdio.h>
#include "co.hpp"
#include "fd.hpp"
#include "log.h"
#include "epoll.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <csignal>

#define perror_exit(str) ({ \
    perror(str); \
    exit(errno); \
})

CoAsync service(std::string data) {
    log_info("1");

    int fd = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
    if (fd < 0)
        perror_exit("socket");

    log_info("2");

    FdRef fdref = FdRef::create(fd);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(9999);

    if (co_await fdref->connect((sockaddr *)&addr, sizeof(addr)) < 0)
        perror_exit("connect");

    log_info("3");

    ssize_t nsend = co_await fdref->send(data.c_str(), data.length());
    if (nsend != (ssize_t)data.length())
        printf("not send completed. nsend:%zd #data:%zd\n", nsend, data.length());

    log_info("4");

    std::string s;
    s.resize(64);
    ssize_t nrecv = co_await fdref->recv(s.data(), s.size());
    s.resize(nrecv);
    log_info("recv data: %s", s.c_str());
}

int main() {
    auto sig_handler = [](int) noexcept {
        Epoll::stop();
    };
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    for (int i = 1; i <= 5; ++i)
        service("hello" + std::to_string(i) + "\n");

    // void *p = malloc(1);
    // (void)p;

    log_info("run before");
    Epoll::run();
    log_info("run after");

    return 0;
}
