const std = @import("std");
const Allocator = std.mem.Allocator;

const IPv4 = @import("../network/IPv4.zig").IPv4;
const IPv6 = @import("../network/IPv6.zig").IPv6;
const BitReader = @import("../bit_reader.zig").BitReader;

const NullLinkTypeType = enum(u32) {
    IPv4 = 2,
    IPv6_1 = 24,
    IPv6_2 = 28,
    IPv6_3 = 30,
    OSI = 7,
    IPX = 23,
    _,
};

const NullLinkTypePayload = union(enum) {
    IPv4: IPv4,
    IPv6: IPv6,
};

pub const NullLinkType = struct {
    link_type: NullLinkTypeType,
    payload: NullLinkTypePayload,

    pub fn parse(reader: *BitReader(std.io.AnyReader), alloc: Allocator) !NullLinkType {
        // First 4 bytes is link type
        var link_type_int = try reader.readBitsNoEof(u32, 32);

        if (link_type_int > 0x0000FFFF) {
            // Endianness looks wrong, swap it, as the spec says it should be in the hosts byte order (but we can't know what that is)
            link_type_int = @byteSwap(link_type_int);
        }

        const link_type: NullLinkTypeType = @enumFromInt(link_type_int);

        const payload: NullLinkTypePayload = switch (link_type) {
            .IPv4 => .{ .IPv4 = try IPv4.parse(reader, alloc) },
            .IPv6_1, .IPv6_2, .IPv6_3 => .{ .IPv6 = try IPv6.parse(reader, alloc) },
            .OSI => std.debug.panic("OSI not implemented", .{}),
            .IPX => std.debug.panic("IPX not implemented", .{}),
            _ => std.debug.panic("Unknown link type {}", .{link_type}),
        };

        return NullLinkType{ .link_type = link_type, .payload = payload };
    }

    pub fn deinit(self: *NullLinkType, alloc: Allocator) void {
        switch (self.link_type) {
            .IPv4 => IPv4.deinit(&self.payload.IPv4, alloc),
            .IPv6_1, .IPv6_2, .IPv6_3 => IPv6.deinit(&self.payload.IPv6, alloc),
            .OSI => {},
            .IPX => {},
            _ => {},
        }
    }
};
