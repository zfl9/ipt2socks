#pragma once

struct Fd;

struct EvLoop {
    static void run() noexcept;

private:
    static void add_pending(Fd *sock);
    static void remove_pending(Fd *sock);

    friend struct Fd;

    int _epfd{-1};

    // pending list (dirty or zombie)
    Fd *_pending_head{};
    Fd *_pending_tail{};
};
