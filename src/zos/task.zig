const zos = @import("zos.zig");

pub const Task = struct {
    vtable: *const VTable,

    pub const VTable = struct {
        tick: *const fn (self: *Task, reg: *zos.Reg) zos.Sig!void,
        kill: *const fn (self: *Task) void,
    };

    pub fn tick(self: *Task, reg: *zos.Reg) zos.Sig!void {
        return self.vtable.tick(self, reg);
    }

    pub fn kill(self: *Task) void {
        return self.vtable.kill(self);
    }
};
