const std = @import("std");
const Allocator = std.mem.Allocator;

const BitReader = @import("../bit_reader.zig").BitReader;

pub const UDP = struct {
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,

    payload: []u8,

    const header_size: usize = 8;

    pub fn parse(reader: *BitReader(std.io.AnyReader), alloc: Allocator) !UDP {
        const source_port = try reader.readBitsNoEof(u16, 16);
        const destination_port = try reader.readBitsNoEof(u16, 16);
        const length = try reader.readBitsNoEof(u16, 16);
        const checksum = try reader.readBitsNoEof(u16, 16);

        if (length < UDP.header_size) {
            std.debug.print("UDP Packet is too short: Expected: {} bytes - Available: {} bytes\n", .{ UDP.header_size, length });
            return error.LengthTooShort;
        }

        const payload = try alloc.alloc(u8, length - UDP.header_size);
        errdefer alloc.free(payload);

        const read_bytes = try reader.reader().readAll(payload);
        if (read_bytes != payload.len) {
            std.debug.print("UDP Packet is truncated: Expected: {} bytes - Available: {} bytes\n", .{ payload.len, read_bytes });
        }

        return .{
            .source_port = source_port,
            .destination_port = destination_port,
            .length = length,
            .checksum = checksum,
            .payload = payload,
        };
    }

    pub fn deinit(udp: *UDP, alloc: Allocator) void {
        alloc.free(udp.payload);
    }
};
