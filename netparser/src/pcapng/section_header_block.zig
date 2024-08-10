const std = @import("std");
const Allocator = std.mem.Allocator;
const Option = @import("block.zig").Option;
const OptionBody = @import("block.zig").OptionBody;
const BitReader = @import("../bit_reader.zig").BitReader;

const round_to_multiple_of_4 = @import("../utils.zig").round_to_multiple_of_4;

const SHBOptionType = enum(u16) {
    end_of_options = 0x0000, // type: void
    comment = 0x0001, // type: string

    shb_hardware = 0x0002, // type: string
    shb_os = 0x0003, // type: string
    shb_userappl = 0x0004, // type: string

    custom_utf8_copyable = 0x0BAC, // type: string
    custom_binary_copyable = 0x0BAD, // type: binary
    custom_utf8_non_copyable = 0x0BAE, // type: string
    custom_binary_non_copyable = 0x0BAF, // type: binary
};

pub const SectionHeaderBlock = struct {
    byte_order_magic: u32, // 0x1a2b3c4d
    major_version: u16, // 0x0001
    minor_version: u16, // 0x0000
    section_length: u64, // 0xffffffffffffffff
    options: [20]Option,

    pub fn parse(reader: *BitReader(std.io.FixedBufferStream([]u8).Reader)) !?SectionHeaderBlock {
        const byte_order_magic = try reader.readBitsNoEof(u32, 32);
        const major_version = try reader.readBitsNoEof(u16, 16);
        const minor_version = try reader.readBitsNoEof(u16, 16);
        const section_length = try reader.readBitsNoEof(u64, 64);

        std.debug.assert(byte_order_magic == 0x1a2b3c4d);

        var options: [20]Option = undefined;
        var next_option_index: usize = 0;

        while (true) {
            const option_type: SHBOptionType = @enumFromInt(reader.readBitsNoEof(u16, 16) catch break);
            const option_length = try reader.readBitsNoEof(u16, 16);

            if (option_type == .end_of_options) {
                std.debug.assert(option_length == 0);
                break;
            }

            const option_value = switch (option_type) {
                .end_of_options => OptionBody{ .void = {} },
                .comment,
                .custom_utf8_copyable,
                .custom_utf8_non_copyable,
                .shb_hardware,
                .shb_os,
                .shb_userappl,
                => blk: {
                    const fba = reader.underlyingReader().context;
                    const option_data = fba.buffer[fba.pos .. fba.pos + option_length];
                    try reader.skipBytes(option_length);
                    break :blk OptionBody{ .string = option_data };
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
                .option_type = @intFromEnum(SHBOptionType.end_of_options),
                .option_length = 0,
                .value = OptionBody{ .void = {} },
            };
        }

        return SectionHeaderBlock{
            .byte_order_magic = byte_order_magic,
            .major_version = major_version,
            .minor_version = minor_version,
            .section_length = section_length,
            .options = options,
        };
    }
};
