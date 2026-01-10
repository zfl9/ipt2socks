const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{TaskKilled};

pub fn Impl(comptime Task: type) type {
    return struct {
        do_kill: ?*const fn (*Task) void = null,
    };
}

pub fn Mixin(comptime Task: type, comptime impl: Impl(Task)) type {
    return struct {
        pub fn is_done(task: *const Task) bool {
            return task.state == .done;
        }

        pub fn get_result(task: *const Task) Task.Error!Task.Result {
            assert(is_done(task));
            return task.state.done;
        }

        pub fn kill(task: *Task) void {
            if (is_done(task))
                return;

            // cleanup resource
            if (impl.do_kill) |do_kill|
                do_kill(task);

            _ = to_fail(task, Task.Error.TaskKilled);
        }

        pub fn to_succ(task: *Task, result: Task.Result) bool {
            assert(!is_done(task));
            task.state = .{ .done = result };
            return true; // poll(): true
        }

        pub fn to_fail(task: *Task, err: Task.Error) bool {
            assert(!is_done(task));
            task.state = .{ .done = err };
            return true; // poll(): true
        }
    };
}
