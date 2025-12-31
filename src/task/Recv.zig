const std = @import("std");
const posix = std.posix;
const Task = @import("Task.zig");
const This = @This();

sock: posix.socket_t,
buf: []u8,
flags: u32,

pub fn init(sock: posix.socket_t, buf: []u8, flags: u32) This {
    return .{
        .sock = sock,
        .buf = buf,
        .flags = flags,
    };
}

pub fn finish(this: *This) posix.RecvFromError!bool {
    if (posix.recv(this.sock, this.buf, this.flags)) {
        return true;
    } else |err| switch (err) {
        error.WouldBlock => return false,
        else => return err,
    }
}

pub fn task(this: *This) Task {
    return .{
        .obj = this,
        .finish_fn = &finish,
    };
}

test "init" {
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    var buf: [10]u8 = undefined;
    const obj = init(sock, &buf, 0);
    _ = obj;
}
