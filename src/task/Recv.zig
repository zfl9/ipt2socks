const std = @import("std");
const posix = std.posix;
const assert = std.debug.assert;

const Self = @This();

pub const Mode = enum { raw_recv, exact };
pub const Error = posix.RecvFromError || error{ EndOfStream, TaskKilled };
pub const Result = usize;

sock: posix.socket_t,
buf: []u8,
flags: u32,
mode: Mode,
state: union(enum) {
    init: void,
    reading: usize, // nrecv
    done: Error!Result,
},

pub fn init(sock: posix.socket_t, buf: []u8, flags: u32, mode: Mode) Self {
    assert(buf.len > 0);
    return .{
        .sock = sock,
        .buf = buf,
        .flags = flags,
        .mode = mode,
        .state = .{ .init = {} },
    };
}

pub fn deinit(self: *Self) void {
    self.* = undefined;
}

pub fn done(self: *const Self) bool {
    return self.state == .done;
}

inline fn to_succ(self: *Self, res: Result) bool {
    assert(!self.done());
    self.state = .{ .done = res };
    return true; // poll(): true
}

inline fn to_fail(self: *Self, err: Error) bool {
    assert(!self.done());
    self.state = .{ .done = err };
    return true; // poll(): true
}

pub fn poll(self: *Self) bool {
    assert(!self.done());

    while (true) switch (self.state) {
        .init => {
            self.state = .{ .reading = 0 };
        },
        .reading => |received| {
            const n = posix.recv(self.sock, self.buf[received..], self.flags) catch |err|
                if (err == posix.RecvFromError.WouldBlock) {
                    // todo: 注册readable事件监听
                    return false;
                } else {
                    return self.to_fail(err);
                };
            const new_received = received + n;
            switch (self.mode) {
                .raw_recv => return self.to_succ(new_received),
                .exact => {
                    if (new_received == self.buf.len) {
                        return self.to_succ(new_received);
                    } else if (n == 0) {
                        return self.to_fail(Error.EndOfStream);
                    } else {
                        self.state.reading = new_received;
                        return false;
                    }
                },
            }
        },
        .done => unreachable,
    };
}

pub fn kill(self: *Self) void {
    if (self.done()) return;
    _ = self.to_fail(Error.TaskKilled);
}

pub fn result(self: *const Self) Error!Result {
    assert(self.done());
    return self.state.done;
}

test "recv" {
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(sock);

    var buf: [10]u8 = undefined;

    var obj = init(sock, &buf, 0, .exact);
    defer obj.deinit();

    try std.testing.expect(obj.poll());
    try std.testing.expect(obj.done());
    obj.kill();
    obj.kill();
    try std.testing.expect(obj.done());
    try std.testing.expectError(Error.SocketNotConnected, obj.result());
}
