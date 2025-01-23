const std = @import("std");
const fmt = std.fmt;
const types = @import("../types/types.zig");
const Allocator = std.mem.Allocator;
const Address = types.Address;

// This function turns an optionally '0x'-prefixed hex string
// to a types.Hash32
pub fn prefixedhex2hash(dst: []u8, src: []const u8) !void {
    if (src.len < 2 or src.len % 2 != 0) {
        return error.InvalidInput;
    }
    const skip0x: usize = if (src[1] == 'X' or src[1] == 'x') 2 else 0;
    if (src[skip0x..].len != 2 * dst.len) {
        return error.InvalidOutputLength;
    }
    _ = try fmt.hexToBytes(dst, src[skip0x..]);
}

// This function turns an optionally '0x'-prefixed hex string
// to a byte slice
pub fn prefixedhex2byteslice(allocator: Allocator, src: []const u8) ![]u8 {
    if (src.len == 0 or (src.len == 3 and std.mem.eql(u8, src, "0x0"))) {
        return allocator.alloc(u8, 0); // Return an empty slice for "0x0"
    }

    if (src.len < 2 or src.len % 2 != 0) {
        return error.InvalidInput;
    }
    const skip0x: usize = if (src[1] == 'X' or src[1] == 'x') 2 else 0;
    // TODO when refactoring, ensure the alloc is also made in the equivalent for prefixedhex2hash
    var dst: []u8 = try allocator.alloc(u8, src[skip0x..].len / 2);

    _ = try fmt.hexToBytes(dst[0..], src[skip0x..]);

    return dst;
}

test "ensure '0x0' is replaced with an empty slice" {
    const out = try prefixedhex2byteslice(std.testing.allocator, "0x0");
    try std.testing.expect(out.len == 0);
}

test "ensure a odd-length string that is not '0x0' will cause an error" {
    const out = prefixedhex2byteslice(std.testing.allocator, "0x012");
    try std.testing.expect(out == error.InvalidInput);
}

test "ensure a hex string matching the correct pattern can be decoded" {
    const out = try prefixedhex2byteslice(std.testing.allocator, "0x0123");
    defer std.testing.allocator.free(out);
    try std.testing.expect(std.mem.eql(u8, out, &[_]u8{ 0x01, 0x23 }));
}

// prefixedHexToint turns an optionally '0x'-prefixed hex string to a integer type T.
pub fn prefixedHexToInt(comptime T: type, hex: []const u8) !T {
    if (hex.len < 3) {
        return error.InvalidInput;
    }
    const skip0x: usize = if (hex[1] == 'X' or hex[1] == 'x') 2 else 0;
    return std.fmt.parseInt(T, hex[skip0x..], 16);
}

// hexToAddress parses an optionally '0x'-prefixed hext string to an Address.
pub fn hexToAddress(account_hex: []const u8) Address {
    const account_hex_strip = if (std.mem.startsWith(u8, account_hex, "0x")) account_hex[2..] else account_hex[0..];
    var address = std.mem.zeroes(Address);
    _ = std.fmt.hexToBytes(&address, account_hex_strip) catch unreachable;
    return address;
}

pub fn comptimeHexToBytes(comptime bytes: []const u8) [bytes.len / 2]u8 {
    var result: [bytes.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(result[0..], bytes);
    return result;
}
