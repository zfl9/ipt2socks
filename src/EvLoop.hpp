#pragma once

struct Fd;

struct EvLoop {
    static void run() noexcept;

private:
    static void add_pending(Fd *sock);
    static void remove_pending(Fd *sock);

    int _epfd;

    // pending list (dirty or zombie)
    Fd *_pending_head, *_pending_tail;

    friend struct Fd;
};
