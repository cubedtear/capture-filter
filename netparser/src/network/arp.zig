const std = @import("std");
const Allocator = std.mem.Allocator;

const MacAddress = @import("../link/ethernet.zig").MacAddress;
const EtherType = @import("../link/ethernet.zig").EtherType;
const BitReader = @import("../bit_reader.zig").BitReader;

const HType = enum(u16) {
    Reserved1 = 0,
    Ethernet = 1,
    Experimental_Ethernet = 2,
    Amateur_Radio_AX_25 = 3,
    Proteon_ProNET_Token_Ring = 4,
    Chaos = 5,
    IEEE_802_Networks = 6,
    ARCNET = 7,
    Hyperchannel = 8,
    Lanstar = 9,
    Autonet_Short_Address = 10,
    LocalTalk = 11,
    LocalNet = 12,
    Ultra_link = 13,
    SMDS = 14,
    Frame_Relay = 15,
    Asynchronous_Transmission_Mode1 = 16,
    HDLC = 17,
    Fibre_Channel = 18,
    Asynchronous_Transmission_Mode2 = 19,
    Serial_Line = 20,
    Asynchronous_Transmission_Mode3 = 21,
    MIL_STD_188_220 = 22,
    Metricom = 23,
    IEEE_1394_1995 = 24,
    MAPOS = 25,
    Twinaxial = 26,
    EUI_64 = 27,
    HIPARP = 28,
    IP_and_ARP_over_ISO_7816_3 = 29,
    ARPSec = 30,
    IPsec_tunnel = 31,
    InfiniBand = 32,
    TIA_102_Project_25_Common_Air_Interface = 33,
    Wiegand_Interface = 34,
    Pure_IP = 35,
    HW_EXP1 = 36,
    HFI = 37,
    Unified_Bus = 38,
    HW_EXP2 = 256,
    AEthernet = 257,
    Reserved2 = 65535,
};

const ARPOperation = enum(u16) {
    Reserved1 = 0,
    REQUEST = 1,
    REPLY = 2,
    Reverse_request = 3,
    Reverse_reply = 4,
    DRARP_Request = 5,
    DRARP_Reply = 6,
    DRARP_Error = 7,
    InARP_Request = 8,
    InARP_Reply = 9,
    ARP_NAK = 10,
    MARS_Request = 11,
    MARS_Multi = 12,
    MARS_MServ = 13,
    MARS_Join = 14,
    MARS_Leave = 15,
    MARS_NAK = 16,
    MARS_Unserv = 17,
    MARS_SJoin = 18,
    MARS_SLeave = 19,
    MARS_Grouplist_Request = 20,
    MARS_Grouplist_Reply = 21,
    MARS_Redirect_Map = 22,
    MAPOS_UNARP = 23,
    OP_EXP1 = 24,
    OP_EXP2 = 25,
    Reserved2 = 65535,
    _,
};

const ARPHwAddress = union(enum) {
    Ethernet: MacAddress,
};

const ARPProtocolAddress = union(enum) {
    IPv4: u32,
    IPv6: u128,
};

pub const ARP = struct {
    htype: HType,
    ptype: EtherType,
    hlen: u8,
    plen: u8,
    operation: ARPOperation,
    sender_hw_address: ARPHwAddress,
    sender_protocol_address: ARPProtocolAddress,

    const size_without_options: usize = 20;

    pub fn parse(reader: *BitReader(std.io.AnyReader)) !ARP {
        const htype: HType = @enumFromInt(try reader.readBitsNoEof(u16, 16));
        const ptype: EtherType = @enumFromInt(try reader.readBitsNoEof(u16, 16));
        const hlen = try reader.readBitsNoEof(u8, 8);
        const plen = try reader.readBitsNoEof(u8, 8);
        const operation: ARPOperation = @enumFromInt(try reader.readBitsNoEof(u16, 16));

        const sender_hw_address: ARPHwAddress = switch (htype) {
            HType.Ethernet => .{ .Ethernet = try reader.reader().readBytesNoEof(6) },
            else => return std.debug.panic("Unimplemented ARP hardware {}\n", .{htype}),
        };

        const sender_protocol_address: ARPProtocolAddress = switch (ptype) {
            EtherType.IPv4 => .{ .IPv4 = try reader.readBitsNoEof(u32, 32) },
            EtherType.IPv6 => .{ .IPv6 = try reader.readBitsNoEof(u128, 128) },
            else => return std.debug.panic("Unimplemented ARP protocol {}\n", .{ptype}),
        };

        return .{
            .htype = htype,
            .ptype = ptype,
            .hlen = hlen,
            .plen = plen,
            .operation = operation,
            .sender_hw_address = sender_hw_address,
            .sender_protocol_address = sender_protocol_address,
        };
    }
};
