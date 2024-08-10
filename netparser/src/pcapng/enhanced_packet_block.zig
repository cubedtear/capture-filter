const std = @import("std");
const Allocator = std.mem.Allocator;

const Option = @import("block.zig").Option;
const OptionBody = @import("block.zig").OptionBody;
const round_to_multiple_of_4 = @import("../utils.zig").round_to_multiple_of_4;
const BitReader = @import("../bit_reader.zig").BitReader;

const EPBOptionType = enum(u16) {
    end_of_options = 0x0000, // type: void
    comment = 0x0001, // type: string

    epb_flags = 0x0002, // type: u32
    epb_hash = 0x0003, // type: binary
    epb_dropcount = 0x0004, // type: u64
    epb_packetid = 0x0005, // type: u64
    epb_queue = 0x0006, // type: u32
    epb_verdict = 0x0007, // type: binary
    epb_processid_threadid = 0x0008, // type: processid_threadid

    custom_utf8_copyable = 0x0BAC, // type: string
    custom_binary_copyable = 0x0BAD, // type: binary
    custom_utf8_non_copyable = 0x0BAE, // type: string
    custom_binary_non_copyable = 0x0BAF, // type: binary
};

pub const EnhancedPacketBlock = struct {
    interface_id: u32,
    timestamp_high: u32,
    timestamp_low: u32,
    captured_packet_length: u32,
    original_packet_length: u32,
    packet_data: []u8,
    options: [20]Option,

    pub fn parse(reader: *BitReader(std.io.FixedBufferStream([]u8).Reader)) !?EnhancedPacketBlock {
        const interface_id = try reader.readBitsNoEof(u32, 32);
        const timestamp_high = try reader.readBitsNoEof(u32, 32);
        const timestamp_low = try reader.readBitsNoEof(u32, 32);
        const captured_packet_length = try reader.readBitsNoEof(u32, 32);
        const original_packet_length = try reader.readBitsNoEof(u32, 32);

        const packet_data = blk: {
            const fba = reader.underlyingReader().context;
            const packet_data = fba.buffer[fba.pos .. fba.pos + captured_packet_length];
            try reader.skipBytes(captured_packet_length);
            break :blk packet_data;
        };

        if (captured_packet_length % 4 != 0) {
            const padding_length = round_to_multiple_of_4(captured_packet_length) - captured_packet_length;
            _ = try reader.readBitsNoEof(u32, padding_length * 8);
        }

        var options: [20]Option = undefined;
        var next_option_index: usize = 0;

        while (true) {
            const option_type: EPBOptionType = @enumFromInt(reader.readBitsNoEof(u16, 16) catch break);
            const option_length = try reader.readBitsNoEof(u16, 16);

            if (option_type == .end_of_options) {
                std.debug.assert(option_length == 0);
                break;
            }

            const option_value = switch (option_type) {
                .end_of_options,
                => OptionBody{ .void = {} },
                .epb_flags,
                .epb_queue,
                => OptionBody{ .u32 = try reader.readBitsNoEof(u32, 32) },
                .epb_dropcount,
                .epb_packetid,
                => OptionBody{ .u64 = try reader.readBitsNoEof(u64, 64) },
                .comment,
                .custom_utf8_copyable,
                .custom_utf8_non_copyable,
                => blk: {
                    const fba = reader.underlyingReader().context;
                    const option_data = fba.buffer[fba.pos .. fba.pos + option_length];
                    try reader.skipBytes(option_length);
                    break :blk OptionBody{ .string = option_data };
                },
                .custom_binary_copyable,
                .custom_binary_non_copyable,
                .epb_hash,
                .epb_verdict,
                => blk: {
                    const fba = reader.underlyingReader().context;
                    const option_data = fba.buffer[fba.pos .. fba.pos + option_length];
                    try reader.skipBytes(option_length);
                    break :blk OptionBody{ .binary = option_data };
                },
                .epb_processid_threadid => OptionBody{ .processid_threadid = .{
                    .process_id = try reader.readBitsNoEof(u32, 32),
                    .thread_id = try reader.readBitsNoEof(u32, 32),
                } },
            };

            if (option_length % 4 != 0) {
                const padding_length = round_to_multiple_of_4(option_length) - option_length;
                _ = try reader.readBitsNoEof(u32, padding_length * 8);
            }

            options[next_option_index] = Option{
                .option_type = @intFromEnum(option_type),
                .option_length = option_length,
                .value = option_value,
            };
            next_option_index += 1;
        }

        if (next_option_index == 0) {
            options[0] = Option{
                .option_type = @intFromEnum(EPBOptionType.end_of_options),
                .option_length = 0,
                .value = OptionBody{ .void = {} },
            };
        }

        return EnhancedPacketBlock{
            .interface_id = interface_id,
            .timestamp_high = timestamp_high,
            .timestamp_low = timestamp_low,
            .captured_packet_length = captured_packet_length,
            .original_packet_length = original_packet_length,
            .packet_data = packet_data,
            .options = options,
        };
    }
};
