#pragma once

namespace sock {
    int create_sock(int family, int type) noexcept;
    int create_listen_sock(int family, int type, int v6only = -1, bool reuse_port = false) noexcept;
    int create_tcpconn_sock(int family, int type, bool keepalive = true) noexcept;
}
