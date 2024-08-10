const std = @import("std");
const Allocator = std.mem.Allocator;

const BitReader = @import("../bit_reader.zig").BitReader;

const TCPFlags = packed struct {
    fin: u1,
    syn: u1,
    rst: u1,
    psh: u1,
    ack: u1,
    urg: u1,
    ece: u1,
    cwr: u1,
    comptime {
        if (@sizeOf(TCPFlags) != 1) {
            @compileError("TCPFlags size is not 1 byte");
        }
    }
};

pub const TCP = struct {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    data_offset: u4,
    reserved: u4,
    flags: TCPFlags,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,

    payload: []u8,

    const size: usize = 20;

    pub fn parse(reader: *BitReader(std.io.AnyReader), alloc: Allocator, total_size: usize) !TCP {
        const source_port = try reader.readBitsNoEof(u16, 16);
        const destination_port = try reader.readBitsNoEof(u16, 16);
        const sequence_number = try reader.readBitsNoEof(u32, 32);
        const acknowledgment_number = try reader.readBitsNoEof(u32, 32);
        const data_offset = try reader.readBitsNoEof(u4, 4);
        const reserved = try reader.readBitsNoEof(u4, 4);
        const flags: TCPFlags = @bitCast(try reader.readBitsNoEof(u8, 8));
        const window_size = try reader.readBitsNoEof(u16, 16);
        const checksum = try reader.readBitsNoEof(u16, 16);
        const urgent_pointer = try reader.readBitsNoEof(u16, 16);

        if (@as(usize, data_offset) * 4 != TCP.size) {
            // There are options
            // TODO: Parse the options
            try reader.skipBytes((@as(usize, data_offset) * 4) - TCP.size);
        }

        const payload = try alloc.alloc(u8, total_size - @as(usize, data_offset) * 4);
        errdefer alloc.free(payload);

        const read_bytes = try reader.reader().readAll(payload);
        std.debug.assert(read_bytes == payload.len);

        return .{
            .source_port = source_port,
            .destination_port = destination_port,
            .sequence_number = sequence_number,
            .acknowledgment_number = acknowledgment_number,
            .data_offset = data_offset,
            .reserved = reserved,
            .flags = flags,
            .window_size = window_size,
            .checksum = checksum,
            .urgent_pointer = urgent_pointer,
            .payload = payload,
        };
    }

    pub fn deinit(tcp: *TCP, alloc: Allocator) void {
        alloc.free(tcp.payload);
    }
};
