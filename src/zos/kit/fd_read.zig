const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const assert = std.debug.assert;
const internal = @import("internal.zig");

pub const IOV_MAX = 10;

pub const Read = FdRead(.read);
pub const Readv = FdRead(.readv);
pub const Recv = FdRead(.recv);
pub const RecvFrom = FdRead(.recvfrom);
pub const RecvMsg = FdRead(.recvmsg);

pub const Variant = enum {
    read, // read(fd: fd_t, buf: []u8) ReadError!usize
    readv, // readv(fd: fd_t, iov: []const iovec) ReadError!usize

    recv, // recv(sock: socket_t, buf: []u8, flags: u32) RecvFromError!usize
    recvfrom, // recvfrom(sockfd: socket_t, buf: []u8, flags: u32, src_addr: ?*sockaddr, addrlen: ?*socklen_t) RecvFromError!usize
    recvmsg, // recvmsg(fd: i32, msg: *msghdr, flags: u32) usize

    fn buf_t(self: Variant) type {
        return switch (self) {
            .read, .recv, .recvfrom => []u8,
            .readv, .recvmsg => void,
        };
    }

    fn iov_t(self: Variant) type {
        return switch (self) {
            .readv => []const posix.iovec,
            .read, .recv, .recvfrom, .recvmsg => void,
        };
    }

    fn flags_t(self: Variant) type {
        return switch (self) {
            .recv, .recvfrom, .recvmsg => u32,
            .read, .readv => void,
        };
    }

    fn addr_t(self: Variant) type {
        return switch (self) {
            .recvfrom => ?*posix.sockaddr,
            .read, .readv, .recv, .recvmsg => void,
        };
    }

    fn msg_t(self: Variant) type {
        return switch (self) {
            .recvmsg => *posix.msghdr,
            .read, .readv, .recv, .recvfrom => void,
        };
    }

    fn Error(self: Variant) type {
        return switch (self) {
            .read, .readv => posix.ReadError,
            .recv, .recvfrom, .recvmsg => posix.RecvFromError,
        };
    }
};

pub fn recvmsg(fd: posix.fd_t, msg: *posix.msghdr, flags: u32) posix.RecvFromError!usize {
    while (true) {
        const rc = linux.recvmsg(fd, msg, flags);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .NOTCONN => return error.SocketNotConnected,
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .NOMEM => return error.SystemResources,
            .CONNREFUSED => return error.ConnectionRefused,
            .CONNRESET => return error.ConnectionResetByPeer,
            .TIMEDOUT => return error.ConnectionTimedOut,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

pub fn FdRead(comptime variant: Variant) type {
    return struct {
        fd: posix.fd_t,
        buf: variant.buf_t() = undefined,
        iov: variant.iov_t() = undefined,
        flags: variant.flags_t() = undefined,
        addr: variant.addr_t() = undefined,
        msg: variant.msg_t() = undefined,
        policy: Policy,
        state: union(enum) {
            init: void,
            reading: usize, // nread
            done: Error!Result,
        } = .{ .init = {} },

        const Self = @This();

        pub const Error = internal.Error || variant.Error() || error{EndOfStream};
        pub const Result = usize; // nread

        pub const Policy = union(enum) {
            raw: void,
            least: usize,
            exact: void,
        };

        const Mixin = internal.Mixin(Self, .{
            .do_kill = do_kill,
        });
        pub const is_done = Mixin.is_done;
        pub const get_result = Mixin.get_result;
        pub const kill = Mixin.kill;
        const to_succ = Mixin.to_succ;
        const to_fail = Mixin.to_fail;

        fn init_read(fd: posix.fd_t, buf: variant.buf_t(), policy: Policy) Self {
            return .{
                .fd = fd,
                .buf = buf,
                .policy = policy,
            };
        }

        fn init_readv(fd: posix.fd_t, iov: variant.iov_t(), policy: Policy) Self {
            assert(iov.len <= IOV_MAX);
            return .{
                .fd = fd,
                .iov = iov,
                .policy = policy,
            };
        }

        fn init_recv(fd: posix.fd_t, buf: variant.buf_t(), flags: variant.flags_t(), policy: Policy) Self {
            return .{
                .fd = fd,
                .buf = buf,
                .flags = flags,
                .policy = policy,
            };
        }

        fn init_recvfrom(fd: posix.fd_t, buf: variant.buf_t(), addr: variant.addr_t(), flags: variant.flags_t(), policy: Policy) Self {
            return .{
                .fd = fd,
                .buf = buf,
                .addr = addr,
                .flags = flags,
                .policy = policy,
            };
        }

        fn init_recvmsg(fd: posix.fd_t, msg: variant.msg_t(), flags: variant.flags_t(), policy: Policy) Self {
            assert(msg.iovlen <= IOV_MAX);
            return .{
                .fd = fd,
                .msg = msg,
                .flags = flags,
                .policy = policy,
            };
        }

        pub const init = switch (variant) {
            .read => init_read,
            .readv => init_readv,
            .recv => init_recv,
            .recvfrom => init_recvfrom,
            .recvmsg => init_recvmsg,
        };

        pub fn deinit(self: *Self) void {
            self.kill();
            self.* = undefined;
        }

        pub fn poll(self: *Self) bool {
            assert(!self.is_done());

            while (true) switch (self.state) {
                .init => {
                    self.state = .{ .reading = 0 };
                },

                .reading => |old_nread| {
                    const n = switch (variant) {
                        .read, .readv => b: {
                            var tmp_iov: [IOV_MAX]posix.iovec = undefined;
                            const iov = self.make_iov(&tmp_iov);
                            break :b posix.readv(self.fd, iov) catch |err| return self.on_err(err);
                        },
                        .recv, .recvfrom, .recvmsg => b: {
                            var tmp_iov: [IOV_MAX]posix.iovec = undefined;
                            const iov = self.make_iov(&tmp_iov);
                            var tmp_msg: posix.msghdr = undefined;
                            const msg = self.make_msg(&tmp_msg, iov);
                            break :b recvmsg(self.fd, msg, self.flags) catch |err| return self.on_err(err);
                        },
                    };

                    const nread = old_nread + n;
                    self.state.reading = nread; // save

                    switch (self.policy) {
                        .raw => {
                            return self.to_succ(nread);
                        },
                        .least => |req_len| {
                            if (nread >= req_len) {
                                return self.to_succ(nread);
                            } else if (n == 0) {
                                return self.to_fail(Error.EndOfStream);
                            } else {
                                return self.on_yield();
                            }
                        },
                        .exact => {
                            if (nread == self.exact_len()) {
                                return self.to_succ(nread);
                            } else if (n == 0) {
                                return self.to_fail(Error.EndOfStream);
                            } else {
                                return self.on_yield();
                            }
                        },
                    }
                },

                .done => unreachable,
            };
        }

        fn do_kill(self: *Self) void {
            _ = self; // autofix
            // todo 取消事件监听
        }

        fn on_yield(self: *Self) bool {
            _ = self; // autofix
            // todo 注册readable事件监听
            return false; // poll(): false
        }

        fn on_err(self: *Self, err: Error) bool {
            switch (err) {
                error.WouldBlock => {
                    // todo 注册readable事件监听
                    return false; // poll(): false
                },
                else => {
                    return self.to_fail(err);
                },
            }
        }

        fn user_iov(self: *const Self) []const posix.iovec {
            return switch (variant) {
                .readv => self.iov,
                .recvmsg => self.msg.iov[0..self.msg.iovlen],
                else => @compileError("only used for readv, recvmsg"),
            };
        }

        fn exact_len(self: *const Self) usize {
            switch (variant) {
                .read, .recv, .recvfrom => {
                    return self.buf.len;
                },
                .readv, .recvmsg => {
                    var total_len: usize = 0;
                    for (self.user_iov()) |iov|
                        total_len += iov.len;
                    return total_len;
                },
            }
        }

        fn make_iov(self: *const Self, tmp_iov: *[IOV_MAX]posix.iovec) []posix.iovec {
            switch (variant) {
                .read, .recv, .recvfrom => {
                    tmp_iov[0] = .{
                        .base = self.buf[self.state.reading..].ptr,
                        .len = self.buf[self.state.reading..].len,
                    };
                    return tmp_iov[0..1];
                },
                .readv, .recvmsg => {
                    var touched_len = self.state.reading;
                    var tmp_iov_n: usize = 0;
                    for (self.user_iov()) |iov| {
                        if (touched_len >= iov.len) {
                            touched_len -= iov.len;
                            continue;
                        }
                        tmp_iov[tmp_iov_n] = .{
                            .base = iov.base + touched_len,
                            .len = iov.len - touched_len,
                        };
                        tmp_iov_n += 1;
                        touched_len = 0;
                    }
                    return tmp_iov[0..tmp_iov_n];
                },
            }
        }

        fn sizeof_addr(addr: *const posix.sockaddr) posix.socklen_t {
            return switch (addr.family) {
                posix.AF.INET => @sizeOf(posix.sockaddr.in),
                posix.AF.INET6 => @sizeOf(posix.sockaddr.in6),
                posix.AF.UNIX => @sizeOf(posix.sockaddr.un),
                else => unreachable,
            };
        }

        fn calc_addrlen(self: *const Self) posix.socklen_t {
            return switch (variant) {
                .recvfrom => if (self.addr) |addr| sizeof_addr(addr) else 0,
                .recvmsg => if (self.msg.name) |addr| sizeof_addr(addr) else 0,
                else => @compileError("only used for recvfrom, recvmsg"),
            };
        }

        fn make_msg(self: *const Self, tmp_msg: *posix.msghdr, iov: []posix.iovec) *posix.msghdr {
            switch (variant) {
                .recv => tmp_msg.* = .{
                    .iov = iov.ptr,
                    .iovlen = iov.len,
                    .name = null,
                    .namelen = 0,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                },
                .recvfrom => tmp_msg.* = .{
                    .iov = iov.ptr,
                    .iovlen = iov.len,
                    .name = self.addr,
                    .namelen = self.calc_addrlen(),
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                },
                .recvmsg => tmp_msg.* = .{
                    .iov = iov.ptr,
                    .iovlen = iov.len,
                    .name = self.msg.name,
                    .namelen = self.calc_addrlen(),
                    .control = self.msg.control,
                    .controllen = self.msg.controllen,
                    .flags = self.msg.flags,
                },
                else => @compileError("only used for recv, recvfrom, recvmsg"),
            }
            return tmp_msg;
        }
    };
}

test "basic" {
    var fdpair: [2]posix.fd_t = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0, &fdpair);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
    defer posix.close(fdpair[0]);
    defer posix.close(fdpair[1]);

    const fd = fdpair[0];
    var buf: [10]u8 = undefined;
    var iov: [1]posix.iovec = .{.{
        .base = &buf,
        .len = buf.len,
    }};
    var msg: posix.msghdr = .{
        .iov = &iov,
        .iovlen = iov.len,
        .name = null,
        .namelen = 0,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    {
        var obj: FdRead(.read) = .init(fd, &buf, .raw);
        defer obj.deinit();
        _ = obj.poll();
        obj.kill();
    }
    {
        var obj: FdRead(.readv) = .init(fd, &iov, .raw);
        defer obj.deinit();
        _ = obj.poll();
        obj.kill();
    }
    {
        var obj: FdRead(.recv) = .init(fd, &buf, 0, .raw);
        defer obj.deinit();
        _ = obj.poll();
        obj.kill();
    }
    {
        var obj: FdRead(.recvfrom) = .init(fd, &buf, null, 0, .raw);
        defer obj.deinit();
        _ = obj.poll();
        obj.kill();
    }
    {
        var obj: FdRead(.recvmsg) = .init(fd, &msg, 0, .raw);
        defer obj.deinit();
        _ = obj.poll();
        obj.kill();
    }
}
