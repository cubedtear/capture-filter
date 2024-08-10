const std = @import("std");

pub const bit_reader = @import("bit_reader.zig");

pub fn round_to_multiple_of_4(value: usize) usize {
    return (((value + 3) / 4) * 4);
}
