const std = @import("std");
const Allocator = std.mem.Allocator;

const IPv4Payload = @import("IPv4.zig").IPv4Payload;
const IPv4Protocol = @import("IPv4.zig").IPv4Protocol;
const ICMP = @import("../transport/icmp.zig").ICMP;
const IGMP = @import("../transport/igmp.zig").IGMP;
const TCP = @import("../transport/tcp.zig").TCP;
const UDP = @import("../transport/udp.zig").UDP;
const BitReader = @import("../bit_reader.zig").BitReader;

pub const IPv6Protocol = IPv4Protocol;
pub const IPv6Payload = IPv4Payload;
pub const IPv6Address = [16]u8;

pub const IPv6 = struct {
    version: u4,
    differenciated_services: u6,
    explicit_congestion_notification: u2,
    flow_label: u20,
    payload_length: u16,
    next_header: IPv6Protocol,
    hop_limit: u8,
    source_address: IPv6Address,
    destination_address: IPv6Address,

    payload: IPv6Payload,

    pub fn parse(reader: *BitReader(std.io.AnyReader), alloc: Allocator) !IPv6 {
        const version = try reader.readBitsNoEof(u4, 4);
        const differenciated_services = try reader.readBitsNoEof(u6, 6);
        const explicit_congestion_notification = try reader.readBitsNoEof(u2, 2);
        const flow_label = try reader.readBitsNoEof(u20, 20);
        const payload_length = try reader.readBitsNoEof(u16, 16);
        const next_header: IPv6Protocol = @enumFromInt(try reader.readBitsNoEof(u8, 8));
        const hop_limit = try reader.readBitsNoEof(u8, 8);
        const source_address = try reader.reader().readBytesNoEof(16);
        const destination_address = try reader.reader().readBytesNoEof(16);

        const payload: IPv6Payload = switch (next_header) {
            .IPv6_HopByHopOpt => .{ .IPv6_HopByHopOpt = {} }, // TODO: Implement IPv6 HopByHopOpt
            .IPv6_Route => .{ .IPv6_Route = {} }, // TODO: Implement IPv6 HopByHopOpt
            .ICMP => .{ .ICMP = try ICMP.parse(reader) },
            .IGMP => .{ .IGMP = try IGMP.parse(reader, alloc, payload_length) },
            .TCP => .{ .TCP = try TCP.parse(reader, alloc, payload_length) },
            .UDP => .{ .UDP = try UDP.parse(reader, alloc) },
            .IPv6_ICMP => .{ .IPv6_ICMP = {} }, // TODO: Implement IPv6 ICMP
            _ => std.debug.panic("Unimplemented IPv6 next_header 0x{X}\n", .{@intFromEnum(next_header)}),
        };

        return .{
            .version = version,
            .differenciated_services = differenciated_services,
            .explicit_congestion_notification = explicit_congestion_notification,
            .flow_label = flow_label,
            .payload_length = payload_length,
            .next_header = next_header,
            .hop_limit = hop_limit,
            .source_address = source_address,
            .destination_address = destination_address,
            .payload = payload,
        };
    }

    pub fn deinit(ipv6: *IPv6, alloc: Allocator) void {
        switch (ipv6.payload) {
            .IPv6_HopByHopOpt => {},
            .IPv6_Route => {},
            .ICMP => {},
            .IGMP => IGMP.deinit(&ipv6.payload.IGMP, alloc),
            .TCP => TCP.deinit(&ipv6.payload.TCP, alloc),
            .IPv6_ICMP => {},
            .UDP => UDP.deinit(&ipv6.payload.UDP, alloc),
            .FragmentedPacket => {},
        }
    }
};
