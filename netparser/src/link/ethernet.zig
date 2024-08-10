const std = @import("std");
const Allocator = std.mem.Allocator;

const IPv4 = @import("../network/IPv4.zig").IPv4;
const IPv6 = @import("../network/IPv6.zig").IPv6;
const ARP = @import("../network/arp.zig").ARP;
const BitReader = @import("../bit_reader.zig").BitReader;

pub const EtherType = enum(u16) {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
    VlanTagged = 0x8100,
    _,

    const maxLengthEthertype: u16 = 1500;
};

pub const TagControlInformation = packed struct {
    priority_code_point: u3,
    drop_elegible_indicator: bool,
    vlan_id: u12,
};

pub const MacAddress = [6]u8;

pub const EthernetPayload = union(enum) {
    IPv4: IPv4,
    IPv6: IPv6,
    ARP: ARP,
    unknown: []u8,

    pub fn deinit(self: *EthernetPayload, alloc: Allocator) void {
        switch (self.*) {
            .IPv4 => self.IPv4.deinit(alloc),
            .ARP => {},
            .IPv6 => self.IPv6.deinit(alloc),
            .unknown => |unk| alloc.free(unk),
        }
    }
};

pub const EthernetLinkType = struct {
    destination: MacAddress,
    source: MacAddress,
    ether_type: EtherType,
    tag_control_information: ?TagControlInformation,
    payload: EthernetPayload,

    pub fn parse(reader: *BitReader(std.io.AnyReader), alloc: Allocator) !EthernetLinkType {
        const destination: MacAddress = try reader.reader().readBytesNoEof(6);
        const source: MacAddress = try reader.reader().readBytesNoEof(6);

        var ether_type: EtherType = @enumFromInt(try reader.readBitsNoEof(u16, 16));

        const tag_control_information: ?TagControlInformation = if (ether_type == EtherType.VlanTagged) blk: {
            const priority_code_point = try reader.readBitsNoEof(u3, 3);
            const drop_elegible_indicator = try reader.readBitsNoEof(u1, 1) != 0;
            const vlan_id = try reader.readBitsNoEof(u12, 12);

            // Read the next ether type
            ether_type = @enumFromInt(try reader.readBitsNoEof(u16, 16));
            break :blk .{ .priority_code_point = priority_code_point, .drop_elegible_indicator = drop_elegible_indicator, .vlan_id = vlan_id };
        } else blk: {
            break :blk null;
        };

        const payload: EthernetPayload = if (@intFromEnum(ether_type) > EtherType.maxLengthEthertype) blk: {
            switch (ether_type) {
                .IPv4 => break :blk .{ .IPv4 = try IPv4.parse(reader, alloc) },
                .IPv6 => break :blk .{ .IPv6 = try IPv6.parse(reader, alloc) },
                .VlanTagged => std.debug.panic("VLAN tagged frame should have been handled above", .{}),
                .ARP => break :blk .{ .ARP = try ARP.parse(reader) },
                _ => break :blk .{ .unknown = try reader.reader().readAllAlloc(alloc, 10000) },
            }
        } else blk: {
            const payload_bufer = try alloc.alloc(u8, @intCast(@intFromEnum(ether_type)));
            errdefer alloc.free(payload_bufer);

            const payload_read_bytes = try reader.reader().readAll(payload_bufer);
            std.debug.assert(payload_read_bytes == @intFromEnum(ether_type));

            break :blk .{ .unknown = payload_bufer };
        };

        return EthernetLinkType{ .destination = destination, .source = source, .ether_type = ether_type, .tag_control_information = tag_control_information, .payload = payload };
    }

    pub fn deinit(self: *EthernetLinkType, alloc: Allocator) void {
        self.payload.deinit(alloc);
    }
};
