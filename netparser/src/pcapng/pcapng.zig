const std = @import("std");
const Allocator = std.mem.Allocator;

const Block = @import("block.zig").Block;
const BlockBody = @import("block.zig").BlockBody;
const BlockType = @import("block.zig").BlockType;
const SectionHeaderBlock = @import("section_header_block.zig").SectionHeaderBlock;
const InterfaceDescriptionBlock = @import("interface_description_block.zig").InterfaceDescriptionBlock;
const EnhancedPacketBlock = @import("enhanced_packet_block.zig").EnhancedPacketBlock;
const InterfaceStatisticsBlock = @import("interface_statistics_block.zig").InterfaceStatisticsBlock;

const BitReader = @import("../bit_reader.zig").BitReader;
const bitReader = @import("../bit_reader.zig").bitReader;

pub const PcapngParser = struct {
    file_data: []u8,
    current_offset: usize,
    section_endian: ?std.builtin.Endian,

    pub const min_file_size: usize = 16;

    pub fn init(file_data: []u8) PcapngParser {
        return PcapngParser{
            .file_data = file_data,
            .current_offset = 0,
            .section_endian = null,
        };
    }

    pub fn get_next_block_slice(self: *PcapngParser) ?[]u8 {
        if (self.current_offset >= self.file_data.len) {
            return null;
        }

        // const block_type = @as(*BlockType, @alignCast(@ptrCast(self.file_data.ptr + self.current_offset))).*;
        const block_total_length = @as(*u32, @alignCast(@ptrCast(self.file_data.ptr + self.current_offset + @sizeOf(u32)))).*;

        return self.file_data[self.current_offset .. self.current_offset + block_total_length];
    }

    pub fn parse_block_slice(self: *PcapngParser, allocator: Allocator, block_slice: []u8) !?Block {
        std.debug.assert(block_slice.ptr >= self.file_data.ptr and block_slice.ptr + block_slice.len <= self.file_data.ptr + self.file_data.len);

        const block_type = @as(*BlockType, @alignCast(@ptrCast(block_slice.ptr))).*;

        if (block_type == BlockType.SectionHeaderBlock) {
            const byte_order_magic: *u32 = @alignCast(@ptrCast(block_slice[0..4].ptr));

            self.section_endian = try blk: {
                if (byte_order_magic.* == 0x1a2b3c4d) {
                    break :blk std.builtin.Endian.little;
                } else if (byte_order_magic.* == 0x4d3c2b1a) {
                    break :blk std.builtin.Endian.big;
                } else {
                    break :blk error.invalid_pcapng_byte_order_magic;
                }
            };
        }

        std.debug.assert(self.section_endian != null);

        var fbs = std.io.fixedBufferStream(block_slice);
        var bit_reader: BitReader(std.io.FixedBufferStream([]u8).Reader) = bitReader(self.section_endian orelse unreachable, fbs.reader());

        // std.debug.print("Block Type: {} - Block Total Length: {}\n", .{ block_type, block_total_length });

        const block_body: BlockBody = switch (block_type) {
            .SectionHeaderBlock => BlockBody{ .SectionHeaderBlock = (try SectionHeaderBlock.parse(allocator, &bit_reader)).? },
            .InterfaceDescriptionBlock => BlockBody{ .InterfaceDescriptionBlock = (try InterfaceDescriptionBlock.parse(allocator, &bit_reader)).? },
            .EnhancedPacketBlock => BlockBody{ .EnhancedPacketBlock = (try EnhancedPacketBlock.parse(allocator, &bit_reader)).? },
            .InterfaceStatisticsBlock => BlockBody{ .InterfaceStatisticsBlock = (try InterfaceStatisticsBlock.parse(allocator, &bit_reader)).? },
            else => std.debug.panic("Unknown block type {} found", .{block_type}),
        };

        return Block{
            .block_type = block_type,
            .block_total_length = block_slice.len,
            .body = block_body,
        };
    }

    pub fn parse_block(self: *PcapngParser) !?Block {
        if (self.current_offset >= self.file_data.len) {
            return null;
        }

        const block_type = @as(*BlockType, @alignCast(@ptrCast(self.file_data.ptr + self.current_offset))).*;
        const block_total_length = @as(*u32, @alignCast(@ptrCast(self.file_data.ptr + self.current_offset + @sizeOf(u32)))).*;

        const block_start_addr = self.current_offset + @sizeOf(u32) + @sizeOf(u32);

        const block_slice = self.file_data[block_start_addr .. self.current_offset + block_total_length - 4];

        if (block_type == BlockType.SectionHeaderBlock) {
            const byte_order_magic: *u32 = @alignCast(@ptrCast(block_slice[0..4].ptr));

            self.section_endian = try blk: {
                if (byte_order_magic.* == 0x1a2b3c4d) {
                    break :blk std.builtin.Endian.little;
                } else if (byte_order_magic.* == 0x4d3c2b1a) {
                    break :blk std.builtin.Endian.big;
                } else {
                    break :blk error.invalid_pcapng_byte_order_magic;
                }
            };
        }

        std.debug.assert(self.section_endian != null);

        var fbs = std.io.fixedBufferStream(block_slice);
        var bit_reader = bitReader(self.section_endian orelse unreachable, fbs.reader());

        // std.debug.print("Block Type: {} - Block Total Length: {}\n", .{ block_type, block_total_length });

        const block_body: BlockBody = switch (block_type) {
            .SectionHeaderBlock => BlockBody{ .SectionHeaderBlock = (try SectionHeaderBlock.parse(&bit_reader)).? },
            .InterfaceDescriptionBlock => BlockBody{ .InterfaceDescriptionBlock = (try InterfaceDescriptionBlock.parse(&bit_reader)).? },
            .EnhancedPacketBlock => BlockBody{ .EnhancedPacketBlock = (try EnhancedPacketBlock.parse(&bit_reader)).? },
            .InterfaceStatisticsBlock => BlockBody{ .InterfaceStatisticsBlock = (try InterfaceStatisticsBlock.parse(&bit_reader)).? },
            else => std.debug.panic("Unknown block type {} found", .{block_type}),
        };

        self.current_offset += block_total_length;

        return Block{
            .block_type = block_type,
            .block_total_length = block_total_length,
            .body = block_body,
        };
    }
};
