const std = @import("std");
const Allocator = std.mem.Allocator;

const SectionHeaderBlock = @import("section_header_block.zig").SectionHeaderBlock;
const InterfaceDescriptionBlock = @import("interface_description_block.zig").InterfaceDescriptionBlock;
const EnhancedPacketBlock = @import("enhanced_packet_block.zig").EnhancedPacketBlock;
const InterfaceStatisticsBlock = @import("interface_statistics_block.zig").InterfaceStatisticsBlock;

pub const IPv4Option = struct {
    ip_address: [4]u8,
    net_mask: [4]u8,
};

pub const IPv6Option = struct {
    ip_address: [16]u8,
    prefix_length: u8,
};

pub const ProcessIDThreadIDOption = struct {
    process_id: u32,
    thread_id: u32,
};

const OptionType = enum {
    void,
    string,
    binary,
    u8,
    u32,
    u64,
    ipv4,
    ipv6,
    processid_threadid,
};

pub const OptionBody = union(OptionType) {
    void: void,
    string: []u8,
    binary: []u8,
    u8: u8,
    u32: u32,
    u64: u64,
    ipv4: IPv4Option,
    ipv6: IPv6Option,
    processid_threadid: ProcessIDThreadIDOption,

    pub fn deinit(self: *OptionBody, alloc: Allocator) void {
        switch (self.*) {
            .void => {},
            .string => alloc.free(self.string),
            .binary => alloc.free(self.binary),
            .u8 => {},
            .u32 => {},
            .u64 => {},
            .ipv4 => {},
            .ipv6 => {},
            .processid_threadid => {},
        }
    }
};

pub const CommonOptionType = struct {
    pub const end_of_options: u16 = 0x0000;
    pub const comment: u16 = 0x0001;
    pub const custom_utf8_copyable: u16 = 0x0BAC;
    pub const custom_binary_copyable: u16 = 0x0BAD;
    pub const custom_utf8_non_copyable: u16 = 0x0BAE;
    pub const custom_binary_non_copyable: u16 = 0x0BAF;
};

pub const Option = struct {
    option_type: u16,
    option_length: u16,
    value: OptionBody,
};

pub const Block = struct {
    block_type: BlockType,
    block_total_length: u32,
    body: BlockBody,

    pub fn deinit(self: *Block, alloc: Allocator) void {
        self.body.deinit(alloc);
    }
};

pub const BlockType = enum(u32) {
    Reserved_Unknown = 0x00000000, // This value is reserved in the spec, and used here to represent an unknown block type.
    InterfaceDescriptionBlock = 0x00000001,
    PacketBlock = 0x00000002,
    SimplePacketBlock = 0x00000003,
    NameResolutionBlock = 0x00000004,
    InterfaceStatisticsBlock = 0x00000005,
    EnhancedPacketBlock = 0x00000006,
    IRIGTimestampBlock = 0x00000007,
    Arinc429InformationBlock = 0x00000008,
    SystemdJournalExportBlock = 0x00000009,
    DecryptionSecretsBlock = 0x0000000A,
    HoneProjectMachineInfoBlock = 0x00000101,
    HoneProjectConnectionEventBlock = 0x00000102,
    SysdigMachineInfoBlock = 0x00000201,
    SysdigProcessInfoBlockV1 = 0x00000202,
    SysdigFDListBlock = 0x00000203,
    SysdigEventBlock = 0x00000204,
    SysdigInterfaceListBlock = 0x00000205,
    SysdigUserListBlock = 0x00000206,
    SysdigProcessInfoBlockV2 = 0x00000207,
    SysdigEventBlockWithFlags = 0x00000208,
    SysdigProcessInfoBlockV3 = 0x00000209,
    SysdigProcessInfoBlockV4 = 0x00000210,
    SysdigProcessInfoBlockV5 = 0x00000211,
    SysdigProcessInfoBlockV6 = 0x00000212,
    SysdigProcessInfoBlockV7 = 0x00000213,
    CustomBlockCopyable = 0x00000BAD,
    CustomBlockNotCopyable = 0x40000BAD,
    SectionHeaderBlock = 0x0A0D0D0A,
    // 0x0A0D0A00-0x0A0D0AFF => Reserved. Used to detect trace files corrupted because of file transfers using the HTTP protocol in text mode.
    // 0x000A0D0A-0xFF0A0D0A => Reserved. Used to detect trace files corrupted because of file transfers using the HTTP protocol in text mode.
    // 0x000A0D0D-0xFF0A0D0D => Reserved. Used to detect trace files corrupted because of file transfers using the HTTP protocol in text mode.
    // 0x0D0D0A00-0x0D0D0AFF => Reserved. Used to detect trace files corrupted because of file transfers using the FTP protocol in text mode.
    // 0x80000000-0xFFFFFFFF => Reserved for local use
};

pub const BlockBody = union(BlockType) {
    Reserved_Unknown: void,
    InterfaceDescriptionBlock: InterfaceDescriptionBlock,
    PacketBlock: void,
    SimplePacketBlock: void,
    NameResolutionBlock: void,
    InterfaceStatisticsBlock: InterfaceStatisticsBlock,
    EnhancedPacketBlock: EnhancedPacketBlock,
    IRIGTimestampBlock: void,
    Arinc429InformationBlock: void,
    SystemdJournalExportBlock: void,
    DecryptionSecretsBlock: void,
    HoneProjectMachineInfoBlock: void,
    HoneProjectConnectionEventBlock: void,
    SysdigMachineInfoBlock: void,
    SysdigProcessInfoBlockV1: void,
    SysdigFDListBlock: void,
    SysdigEventBlock: void,
    SysdigInterfaceListBlock: void,
    SysdigUserListBlock: void,
    SysdigProcessInfoBlockV2: void,
    SysdigEventBlockWithFlags: void,
    SysdigProcessInfoBlockV3: void,
    SysdigProcessInfoBlockV4: void,
    SysdigProcessInfoBlockV5: void,
    SysdigProcessInfoBlockV6: void,
    SysdigProcessInfoBlockV7: void,
    CustomBlockCopyable: void,
    CustomBlockNotCopyable: void,
    SectionHeaderBlock: SectionHeaderBlock,
};
