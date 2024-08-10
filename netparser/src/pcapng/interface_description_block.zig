const std = @import("std");
const Allocator = std.mem.Allocator;

const LinkType = @import("../link/link_type.zig").LinkType;
const Option = @import("block.zig").Option;
const OptionBody = @import("block.zig").OptionBody;

const round_to_multiple_of_4 = @import("../utils.zig").round_to_multiple_of_4;
const BitReader = @import("../bit_reader.zig").BitReader;

const IDBOptionType = enum(u16) {
    end_of_options = 0x0000, // type: void
    comment = 0x0001, // type: string

    if_name = 0x0002,
    if_description = 0x0003,
    if_IPv4addr = 0x0004,
    if_IPv6addr = 0x0005,
    if_MACaddr = 0x0006,
    if_EUIaddr = 0x0007,
    if_speed = 0x0008,
    if_tsresol = 0x0009,
    if_tzone = 0x000A,
    if_filter = 0x000B,
    if_os = 0x000C,
    if_fcslen = 0x000D,
    if_tsoffset = 0x000E,
    if_hardware = 0x000F,
    if_txspeed = 0x0010,
    if_rxspeed = 0x0011,

    custom_utf8_copyable = 0x0BAC, // type: string
    custom_binary_copyable = 0x0BAD, // type: binary
    custom_utf8_non_copyable = 0x0BAE, // type: string
    custom_binary_non_copyable = 0x0BAF, // type: binary
};

pub const InterfaceDescriptionBlock = struct {
    link_type: LinkType,
    reserved: u16,
    snap_len: u32,
    options: [20]Option,

    pub fn parse(reader: *BitReader(std.io.FixedBufferStream([]u8).Reader)) !?InterfaceDescriptionBlock {
        const link_type: LinkType = @enumFromInt(try reader.readBitsNoEof(u16, 16));
        const reserved = try reader.readBitsNoEof(u16, 16);
        const snap_len = try reader.readBitsNoEof(u32, 32);

        var options: [20]Option = undefined;
        var next_option_index: usize = 0;

        while (true) {
            if (reader.underlyingReader().context.pos >= reader.underlyingReader().context.buffer.len - 4) {
                break;
            }
            const option_type: IDBOptionType = @enumFromInt(reader.readBitsNoEof(u16, 16) catch break);
            const option_length = try reader.readBitsNoEof(u16, 16);

            if (option_type == .end_of_options) {
                std.debug.assert(option_length == 0);
                break;
            }

            const option_value = switch (option_type) {
                .end_of_options => OptionBody{ .void = {} },
                .if_speed,
                .if_tsoffset,
                .if_txspeed,
                .if_rxspeed,
                => OptionBody{ .u64 = try reader.readBitsNoEof(u64, 64) },
                .if_tsresol, .if_fcslen => OptionBody{ .u8 = try reader.readBitsNoEof(u8, 8) },
                .comment,
                .custom_utf8_copyable,
                .custom_utf8_non_copyable,
                .if_name,
                .if_description,
                .if_os,
                .if_hardware,
                => blk: {
                    const fba = reader.underlyingReader().context;
                    const option_data = fba.buffer[fba.pos .. fba.pos + option_length];
                    try reader.skipBytes(option_length);
                    break :blk OptionBody{ .string = option_data };
                },
                .custom_binary_copyable,
                .custom_binary_non_copyable,
                .if_MACaddr,
                .if_EUIaddr,
                .if_tzone,
                .if_filter,
                => blk: {
                    const fba = reader.underlyingReader().context;
                    const option_data = fba.buffer[fba.pos .. fba.pos + option_length];
                    try reader.skipBytes(option_length);
                    break :blk OptionBody{ .binary = option_data };
                },
                .if_IPv4addr => blk: {
                    var ip_addr: [4]u8 = undefined;
                    var netmask: [4]u8 = undefined;
                    const ip_addr_read_count = try reader.reader().readAll(&ip_addr);
                    std.debug.assert(ip_addr_read_count == 4);
                    const net_mask_read_count = try reader.reader().readAll(&netmask);
                    std.debug.assert(net_mask_read_count == 4);
                    break :blk OptionBody{ .ipv4 = .{
                        .ip_address = ip_addr,
                        .net_mask = netmask,
                    } };
                },
                .if_IPv6addr => blk: {
                    var ip_addr: [16]u8 = undefined;
                    const ipv6_read_count = try reader.reader().readAll(&ip_addr);
                    std.debug.assert(ipv6_read_count == 16);

                    const prefix_length = try reader.readBitsNoEof(u8, 8);
                    break :blk OptionBody{ .ipv6 = .{
                        .ip_address = ip_addr,
                        .prefix_length = prefix_length,
                    } };
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
                .option_type = @intFromEnum(IDBOptionType.end_of_options),
                .option_length = 0,
                .value = OptionBody{ .void = {} },
            };
        }

        return InterfaceDescriptionBlock{
            .link_type = link_type,
            .reserved = reserved,
            .snap_len = snap_len,
            .options = options,
        };
    }
};
