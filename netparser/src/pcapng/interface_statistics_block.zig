const std = @import("std");
const Allocator = std.mem.Allocator;

const LinkType = @import("../link/link_type.zig").LinkType;
const Option = @import("block.zig").Option;
const OptionBody = @import("block.zig").OptionBody;

const round_to_multiple_of_4 = @import("../utils.zig").round_to_multiple_of_4;
const BitReader = @import("../bit_reader.zig").BitReader;

const ISBOptionType = enum(u16) {
    end_of_options = 0x0000, // type: void
    comment = 0x0001, // type: string

    isb_starttime = 0x0002,
    isb_endtime = 0x0003,
    isb_ifrecv = 0x0004,
    isb_ifdrop = 0x0005,
    isb_filteraccept = 0x0006,
    isb_osdrop = 0x0007,
    isb_usrdeliv = 0x0008,

    custom_utf8_copyable = 0x0BAC, // type: string
    custom_binary_copyable = 0x0BAD, // type: binary
    custom_utf8_non_copyable = 0x0BAE, // type: string
    custom_binary_non_copyable = 0x0BAF, // type: binary
};

pub const InterfaceStatisticsBlock = struct {
    interface_id: u32,
    timestamp_high: u32,
    timestamp_low: u32,
    options: [20]Option,

    pub fn parse(reader: *BitReader(std.io.FixedBufferStream([]u8).Reader)) !?InterfaceStatisticsBlock {
        const interface_id = try reader.readBitsNoEof(u32, 32);
        const timestamp_high = try reader.readBitsNoEof(u32, 32);
        const timestamp_low = try reader.readBitsNoEof(u32, 32);

        var options: [20]Option = undefined;
        var next_option_index: usize = 0;

        while (true) {
            const option_type: ISBOptionType = @enumFromInt(reader.readBitsNoEof(u16, 16) catch break);
            const option_length = try reader.readBitsNoEof(u16, 16);

            if (option_type == .end_of_options) {
                std.debug.assert(option_length == 0);
                break;
            }

            const option_value = switch (option_type) {
                .end_of_options => OptionBody{ .void = {} },
                .isb_starttime,
                .isb_endtime,
                .isb_ifrecv,
                .isb_ifdrop,
                .isb_filteraccept,
                .isb_osdrop,
                .isb_usrdeliv,
                => OptionBody{ .u64 = try reader.readBitsNoEof(u64, 64) },
                .comment,
                .custom_utf8_copyable,
                .custom_utf8_non_copyable,
                => blk: {
                    const fba = reader.underlyingReader().context;
                    const option_data = fba.buffer[fba.pos .. fba.pos + option_length];
                    try reader.skipBytes(option_length);
                    break :blk OptionBody{ .binary = option_data };
                },
                .custom_binary_copyable,
                .custom_binary_non_copyable,
                => blk: {
                    const fba = reader.underlyingReader().context;
                    const option_data = fba.buffer[fba.pos .. fba.pos + option_length];
                    try reader.skipBytes(option_length);
                    break :blk OptionBody{ .binary = option_data };
                },
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
                .option_type = @intFromEnum(ISBOptionType.end_of_options),
                .option_length = 0,
                .value = OptionBody{ .void = {} },
            };
        }

        return InterfaceStatisticsBlock{
            .interface_id = interface_id,
            .timestamp_high = timestamp_high,
            .timestamp_low = timestamp_low,
            .options = options,
        };
    }
};
