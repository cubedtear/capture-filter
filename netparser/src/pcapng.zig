pub const Block = @import("pcapng/block.zig").Block;
pub const BlockType = @import("pcapng/block.zig").BlockType;
pub const BlockBody = @import("pcapng/block.zig").BlockBody;

pub const EnhancedPacketBlock = @import("pcapng/enhanced_packet_block.zig").EnhancedPacketBlock;

pub const InterfaceDescriptionBlock = @import("pcapng/interface_description_block.zig").InterfaceDescriptionBlock;

pub const CommonOptionType = @import("pcapng/block.zig").CommonOptionType;
pub const OptionBody = @import("pcapng/block.zig").OptionBody;
pub const Option = @import("pcapng/block.zig").Option;
pub const PcapngParser = @import("pcapng/pcapng.zig").PcapngParser;

pub const SHBOptionType = @import("pcapng/section_header_block.zig").SHBOptionType;
pub const SectionHeaderBlock = @import("pcapng/section_header_block.zig").SectionHeaderBlock;
