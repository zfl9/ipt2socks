const This = @This();

obj: *anyopaque,
finish_fn: *const fn () anyerror!bool,

pub fn finish(this: *This) anyerror!bool {
    return this.finish_fn(this.obj);
}
