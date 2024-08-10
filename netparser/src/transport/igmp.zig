const std = @import("std");
const Allocator = std.mem.Allocator;

const IPv4Address = @import("../network/IPv4.zig").IPv4Address;
const BitReader = @import("../bit_reader.zig").BitReader;

pub const IGMPType = enum(u8) {
    Membership_Query = 0x11,
    IGMPv1_Membership_Report = 0x12,
    IGMPv2_Membership_Report = 0x16,
    IGMPv3_Membership_Report = 0x22,
    Leave_Group = 0x17,
};

pub const IGMPPayload = union(enum) {
    v1_v2_Membership_Query: void,
    v3_Membership_Query: IGMPv3_Membership_Query,
    IGMPv1_Membership_Report: void,
    IGMPv2_Membership_Report: void,
    IGMPv3_Membership_Report: void,
    Leave_Group: void,
};

pub const IGMPv3_Membership_Query = struct {
    s: bool,
    qrv: u3,
    qqic: u8,
    number_of_sources: u16,
    source_addresses: []IPv4Address,

    pub fn parse(reader: *BitReader(std.io.AnyReader), alloc: Allocator) !IGMPv3_Membership_Query {
        const s = try reader.readBitsNoEof(u1, 1) != 0;
        const qrv = try reader.readBitsNoEof(u3, 3);
        const qqic = try reader.readBitsNoEof(u8, 8);
        const number_of_sources = try reader.readBitsNoEof(u16, 16);

        const source_addresses = try alloc.alloc(IPv4Address, number_of_sources);
        for (source_addresses) |*source_address| {
            const read_count = try reader.reader().readAll(source_address);
            std.debug.assert(read_count == 4);
        }
        return .{
            .s = s,
            .qrv = qrv,
            .qqic = qqic,
            .number_of_sources = number_of_sources,
            .source_addresses = source_addresses,
        };
    }

    pub fn deinit(self: *IGMPv3_Membership_Query, alloc: Allocator) void {
        alloc.free(self.source_addresses);
    }
};

pub const IGMP = struct {
    message_type: IGMPType,
    max_response_time: u8,
    checksum: u16,
    group_address: IPv4Address,
    payload: IGMPPayload,

    pub fn parse(reader: *BitReader(std.io.AnyReader), alloc: Allocator, total_size: usize) !IGMP {
        const message_type: IGMPType = @enumFromInt(try reader.readBitsNoEof(u8, 8));
        const max_response_time = try reader.readBitsNoEof(u8, 8);
        const checksum = try reader.readBitsNoEof(u16, 16);
        const group_address = try reader.reader().readBytesNoEof(4);

        const payload: IGMPPayload = switch (message_type) {
            .Membership_Query => blk: {
                if (total_size == 8) {
                    break :blk .{ .v1_v2_Membership_Query = {} };
                } else if (total_size >= 12) {
                    break :blk .{ .v3_Membership_Query = try IGMPv3_Membership_Query.parse(reader, alloc) };
                } else {
                    std.debug.panic("Invalid IGMP Membership Query size {}\n", .{total_size});
                }
            },
            .IGMPv1_Membership_Report => .{ .IGMPv1_Membership_Report = {} },
            .IGMPv2_Membership_Report => .{ .IGMPv2_Membership_Report = {} },
            .IGMPv3_Membership_Report => .{ .IGMPv3_Membership_Report = {} },
            .Leave_Group => .{ .Leave_Group = {} },
        };

        // FIXME: Implement the rest of the IGMP message types

        return .{
            .message_type = message_type,
            .max_response_time = max_response_time,
            .checksum = checksum,
            .group_address = group_address,
            .payload = payload,
        };
    }

    pub fn deinit(igmp: *IGMP, alloc: Allocator) void {
        switch (igmp.message_type) {
            .Membership_Query => {
                switch (igmp.payload) {
                    .v3_Membership_Query => {
                        igmp.payload.v3_Membership_Query.deinit(alloc);
                    },
                    else => {},
                }
            },
            else => {},
        }
    }
};
