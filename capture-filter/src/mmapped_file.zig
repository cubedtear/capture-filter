const std = @import("std");
const builtin = @import("builtin");
const native_os = builtin.os.tag;

pub fn map_file(file_path: []const u8) ![]u8 {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    try file.seekFromEnd(0);
    const file_size = try file.getPos();
    try file.seekTo(0);

    if (native_os == .windows) {
        const windows = std.os.windows;
        const kernel32 = std.os.windows.kernel32;
        const windows_shmem = @import("windows_shmem.zig");

        const file_mapping = windows_shmem.CreateFileMappingA(file.handle, null, windows.PAGE_READONLY, 0, 0, null) orelse return error.OutOfMemory;

        defer windows.CloseHandle(file_mapping);

        const file_view = windows_shmem.MapViewOfFileEx(file_mapping, windows_shmem.FILE_MAP_READ, 0, 0, 0, null) orelse return error.OutOfMemory;

        errdefer kernel32.UnmapViewOfFile(file_view);

        return @as([*]u8, @ptrCast(file_view))[0..file_size];
    } else {
        return error.Unsupported;
    }
}
