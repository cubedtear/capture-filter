const std = @import("std");
const Allocator = std.mem.Allocator;

const BitReader = @import("../bit_reader.zig").BitReader;

pub const ICMP = struct {
    pub fn parse(reader: *BitReader(std.io.AnyReader)) !ICMP {
        _ = reader;

        // TODO: Implement ICMP packets

        return .{};
    }
};
