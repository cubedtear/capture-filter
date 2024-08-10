const std = @import("std");
const Allocator = std.mem.Allocator;

const ICMP = @import("../transport/icmp.zig").ICMP;
const IGMP = @import("../transport/igmp.zig").IGMP;
const TCP = @import("../transport/tcp.zig").TCP;
const UDP = @import("../transport/udp.zig").UDP;
const BitReader = @import("../bit_reader.zig").BitReader;

pub const IPv4Protocol = enum(u8) {
    IPv6_HopByHopOpt = 0,
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    IPv6_Route = 43,
    IPv6_ICMP = 58,
    _,
};

pub const IPv4Payload = union(enum) {
    IPv6_HopByHopOpt: void,
    IPv6_Route: void,
    ICMP: ICMP,
    IGMP: IGMP,
    TCP: TCP,
    UDP: UDP,
    IPv6_ICMP: void,
    FragmentedPacket: void,
};

pub const IPv4Address = [4]u8;

pub const IPv4 = struct {
    version: u4,
    ihl: u4,
    dscp: u6,
    ecn: u2,
    total_length: u16,
    identification: u16,
    flags_reserved: bool,
    flags_dont_fragment: bool,
    flags_more_fragments: bool,
    fragment_offset: u13,
    ttl: u8,
    protocol: IPv4Protocol,
    header_checksum: u16,
    source_address: IPv4Address,
    destination_address: IPv4Address,

    payload: IPv4Payload,

    const size_without_options: usize = 20;

    pub fn parse(reader: *BitReader(std.io.AnyReader), alloc: Allocator) !IPv4 {
        const version = try reader.readBitsNoEof(u4, 4);
        const ihl = try reader.readBitsNoEof(u4, 4);
        const dscp = try reader.readBitsNoEof(u6, 6);
        const ecn = try reader.readBitsNoEof(u2, 2);
        const total_length = try reader.readBitsNoEof(u16, 16);
        const identification = try reader.readBitsNoEof(u16, 16);
        const flags_reserved = try reader.readBitsNoEof(u1, 1) != 0;
        const flags_dont_fragment = try reader.readBitsNoEof(u1, 1) != 0;
        const flags_more_fragments = try reader.readBitsNoEof(u1, 1) != 0;
        const fragment_offset = try reader.readBitsNoEof(u13, 13);
        const ttl = try reader.readBitsNoEof(u8, 8);
        const protocol: IPv4Protocol = @enumFromInt(try reader.readBitsNoEof(u8, 8));
        const header_checksum = try reader.readBitsNoEof(u16, 16);
        const source_address = try reader.reader().readBytesNoEof(4);
        const destination_address = try reader.reader().readBytesNoEof(4);

        const ihl_bytes = @as(u32, @intCast(ihl)) * 4;
        if (ihl_bytes > IPv4.size_without_options) {
            // TODO: Parse options
            try reader.skipBytes(ihl_bytes - IPv4.size_without_options);
        }

        const payload: IPv4Payload = if (flags_more_fragments) blk: {
            std.debug.print("Fragmented IPv4 packets are not supported\n", .{});
            break :blk .{ .FragmentedPacket = {} };
        } else blk: {
            break :blk switch (protocol) {
                .IPv6_HopByHopOpt => std.debug.panic("IPv6 HopByHopOpt is not a valid IPv4 protocol\n", .{}),
                .IPv6_Route => std.debug.panic("IPv6 Route is not a valid IPv4 protocol\n", .{}),
                .IPv6_ICMP => std.debug.panic("IPv6 ICMP is not a valid IPv4 protocol\n", .{}),

                .ICMP => .{ .ICMP = try ICMP.parse(reader) },
                .IGMP => .{ .IGMP = try IGMP.parse(reader, alloc, total_length - ihl_bytes) },
                .TCP => .{ .TCP = try TCP.parse(reader, alloc, total_length - ihl_bytes) },
                .UDP => .{ .UDP = try UDP.parse(reader, alloc) },
                _ => std.debug.panic("Unimplemented IPv4 protocol {}\n", .{protocol}),
            };
        };

        return .{
            .version = version,
            .ihl = ihl,
            .dscp = dscp,
            .ecn = ecn,
            .total_length = total_length,
            .identification = identification,
            .flags_reserved = flags_reserved,
            .flags_dont_fragment = flags_dont_fragment,
            .flags_more_fragments = flags_more_fragments,
            .fragment_offset = fragment_offset,
            .ttl = ttl,
            .protocol = protocol,
            .header_checksum = header_checksum,
            .source_address = source_address,
            .destination_address = destination_address,
            .payload = payload,
        };
    }

    pub fn deinit(ipv4: *IPv4, alloc: Allocator) void {
        switch (ipv4.payload) {
            .IPv6_HopByHopOpt => {},
            .IPv6_Route => {},
            .ICMP => {},
            .IGMP => IGMP.deinit(&ipv4.payload.IGMP, alloc),
            .TCP => TCP.deinit(&ipv4.payload.TCP, alloc),
            .UDP => UDP.deinit(&ipv4.payload.UDP, alloc),
            .IPv6_ICMP => {},
            .FragmentedPacket => {},
        }
    }
};
