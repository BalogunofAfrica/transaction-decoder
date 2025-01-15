const std = @import("std");

fn hexDecode(allocator: *std.mem.Allocator, data: []const u8) ![]u8 {
    const buffer = try allocator.alloc(u8, data.len / 2);
    _ = try std.fmt.hexToBytes(buffer, data);

    return buffer;
}

fn hexEncode(data: anytype) [data.len * 2]u8 {
    return std.fmt.bytesToHex(data, .lower);
}

fn hexEncode_n(allocator: *std.mem.Allocator, bytes: []const u8) ![]u8 {
    var output = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        const hex = "0123456789abcdef";
        output[i * 2] = hex[b >> 4];
        output[i * 2 + 1] = hex[b & 15];
    }

    return output;
}

fn reverse(slice: []u8) []u8 {
    var start: u32 = 0;
    var end = slice.len - 1;
    while (start < end) {
        const temp = slice[start];
        slice[start] = slice[end];
        slice[end] = temp;

        start += 1;
        end -= 1;
    }
    return slice;
}

fn read_bytes(comptime T: type, reader: anytype) !T {
    const value = try reader.readInt(T, .little);

    return value;
}

fn read_bytes_v(allocator: *std.mem.Allocator, comptime T: type, n: usize, reader: anytype) ![]T {
    const values: []T = try allocator.alloc(T, n);

    for (values) |*value| {
        value.* = try reader.readInt(T, .little);
    }

    return values;
}

fn read_bytes_n(comptime T: type, comptime n: usize, reader: anytype) ![n]T {
    var values: [n]T = undefined;

    for (&values) |*value| {
        value.* = try reader.readInt(T, .little);
    }

    return values;
}

fn read_txid(reader: anytype) ![]const u8 {
    var buffer = try read_bytes_n(u8, 32, reader);
    _ = reverse(&buffer);
    return &hexEncode(buffer);
}

fn read_compact_size(reader: anytype) !u64 {
    const compact_size = try read_bytes(u8, reader);

    return @as(u64, switch (compact_size) {
        0...252 => compact_size,
        253 => try read_bytes(u16, reader),
        254 => try read_bytes(u32, reader),
        255 => try read_bytes(u64, reader),
    });
}

fn read_script(allocator: *std.mem.Allocator, reader: anytype) ![]const u8 {
    const script_size = try read_compact_size(reader);
    const buffer = try read_bytes_v(allocator, u8, script_size, reader);
    defer allocator.free(buffer);

    return hexEncode_n(allocator, buffer);
}

const Input = struct { txid: []const u8, output_index: u32, script_sig: []const u8, sequence: u32 };

pub fn main() !void {
    const transaction_hex = "01000000021b04470fa0e6a5c5a1b406b7136cb00a550214310b3d659eed5720ec1d5ebafa16000000da004730440220137dbf6aa0cc89c64d2c224af794cd24d9e28df2d9c84af6f521f31623d5ea730220395e417fee49db252f3eaff8c5cccbed7ac60ee0f32b5017a76bb20f9b37798e01483045022100d80bf3887af3fcf006c9f300d0ec82e0a03d81d36f735794c037bcdefcec086e02201ce4d47478cb438aed860fc5eab28cc763d464af5aa0a249f2737a081afd35d50147522102907a54bed8ad74b3f35638c60114ca240a308cb986f3f2f306178869a8880b61210377f8715b7895e57dd49de1ef084f94e6edb7df0f9e4807b94800ce751430004c52aeffffffff2a04e7374dd90a033120d3182db77d502210ecfb21a4499f8458e3f464b8e1e4020000006b483045022100992206f9b180553f07742ace393a6eb9542a5e704a3de55b57a2a112cd722c8c02206b040aeb7b3172dbae2e02344710a8174887d69614dddd034e08a07e5b296e8d012102ec4ce6f13fef0cd94532693d0d45a2f28dec2d3c8e693a5134da9d4c6dc0d16cffffffff02cdfb07000000000017a9142743d98a6175c25c9353c42b2feb8c09c769c4d387f4344b00000000001976a914714c6982c9f1c3560deceee9264eb193a737a69988ac00000000";
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();
    const transaction_bytes = try hexDecode(&allocator, transaction_hex);
    defer allocator.free(transaction_bytes);

    var stream = std.io.fixedBufferStream(transaction_bytes);
    const reader = stream.reader();
    const version = try read_bytes(u32, reader);
    const input_count = try read_compact_size(reader);
    var inputs = std.ArrayList(Input).init(allocator);

    for (0..input_count) |_| {
        const txid = try read_txid(reader);
        const output_index = try read_bytes(u32, reader);
        const script_sig = try read_script(&allocator, reader);
        const sequence = try read_bytes(u32, reader);

        const input = Input{ .sequence = sequence, .script_sig = script_sig, .output_index = output_index, .txid = txid };
        try inputs.append(input);
    }

    const output_count = try read_compact_size(reader);

    for (0..output_count) |_| {
        const amount = try read_bytes(u64, reader);
        const script_pub_key = try read_script(&allocator, reader);
        std.debug.print("Here it is amount:{any} \nscript_pub_key:{s}\n", .{ amount, script_pub_key });

        defer allocator.free(script_pub_key);
    }

    defer {
        for (inputs.items) |i| {
            defer allocator.free(i.script_sig);
        }
    }
    // std.debug.print("bytes are {any}\n", .{transaction_bytes});
    std.debug.print("version is {any}\n", .{version});
    // std.debug.print("inputs are {any}\n", .{inputs.items});
    // std.debug.print("compact size is {any}\n", .{input_count});
}

test "test encode" {
    const bytes = [_]u8{ 1, 0, 0, 0, 2, 27, 4, 71, 15, 160, 230, 165, 197, 161, 180, 6, 183, 19, 108, 176, 10, 85, 2, 20, 49, 11, 61, 101, 158, 237, 87, 32, 236, 29, 94, 186, 250, 22, 0, 0, 0, 218, 0, 71, 48, 68, 2, 32, 19, 125, 191, 106, 160, 204, 137, 198, 77, 44, 34, 74, 247, 148, 205, 36, 217, 226, 141, 242, 217, 200, 74, 246, 245, 33, 243, 22, 35, 213, 234, 115, 2, 32, 57, 94, 65, 127, 238, 73, 219, 37, 47, 62, 175, 248, 197, 204, 203, 237, 122, 198, 14, 224, 243, 43, 80, 23, 167, 107, 178, 15, 155, 55, 121, 142, 1, 72, 48, 69, 2, 33, 0, 216, 11, 243, 136, 122, 243, 252, 240, 6, 201, 243, 0, 208, 236, 130, 224, 160, 61, 129, 211, 111, 115, 87, 148, 192, 55, 188, 222, 252, 236, 8, 110, 2, 32, 28, 228, 212, 116, 120, 203, 67, 138, 237, 134, 15, 197, 234, 178, 140, 199, 99, 212, 100, 175, 90, 160, 162, 73, 242, 115, 122, 8, 26, 253, 53, 213, 1, 71, 82, 33, 2, 144, 122, 84, 190, 216, 173, 116, 179, 243, 86, 56, 198, 1, 20, 202, 36, 10, 48, 140, 185, 134, 243, 242, 243, 6, 23, 136, 105, 168, 136, 11, 97, 33, 3, 119, 248, 113, 91, 120, 149, 229, 125, 212, 157, 225, 239, 8, 79, 148, 230, 237, 183, 223, 15, 158, 72, 7, 185, 72, 0, 206, 117, 20, 48, 0, 76, 82, 174, 255, 255, 255, 255, 42, 4, 231, 55, 77, 217, 10, 3, 49, 32, 211, 24, 45, 183, 125, 80, 34, 16, 236, 251, 33, 164, 73, 159, 132, 88, 227, 244, 100, 184, 225, 228, 2, 0, 0, 0, 107, 72, 48, 69, 2, 33, 0, 153, 34, 6, 249, 177, 128, 85, 63, 7, 116, 42, 206, 57, 58, 110, 185, 84, 42, 94, 112, 74, 61, 229, 91, 87, 162, 161, 18, 205, 114, 44, 140, 2, 32, 107, 4, 10, 235, 123, 49, 114, 219, 174, 46, 2, 52, 71, 16, 168, 23, 72, 135, 214, 150, 20, 221, 221, 3, 78, 8, 160, 126, 91, 41, 110, 141, 1, 33, 2, 236, 76, 230, 241, 63, 239, 12, 217, 69, 50, 105, 61, 13, 69, 162, 242, 141, 236, 45, 60, 142, 105, 58, 81, 52, 218, 157, 76, 109, 192, 209, 108, 255, 255, 255, 255, 2, 205, 251, 7, 0, 0, 0, 0, 0, 23, 169, 20, 39, 67, 217, 138, 97, 117, 194, 92, 147, 83, 196, 43, 47, 235, 140, 9, 199, 105, 196, 211, 135, 244, 52, 75, 0, 0, 0, 0, 0, 25, 118, 169, 20, 113, 76, 105, 130, 201, 241, 195, 86, 13, 236, 238, 233, 38, 78, 177, 147, 167, 55, 166, 153, 136, 172, 0, 0, 0, 0 };
    const encoded = hexEncode(bytes);
    const expected: []const u8 = "01000000021b04470fa0e6a5c5a1b406b7136cb00a550214310b3d659eed5720ec1d5ebafa16000000da004730440220137dbf6aa0cc89c64d2c224af794cd24d9e28df2d9c84af6f521f31623d5ea730220395e417fee49db252f3eaff8c5cccbed7ac60ee0f32b5017a76bb20f9b37798e01483045022100d80bf3887af3fcf006c9f300d0ec82e0a03d81d36f735794c037bcdefcec086e02201ce4d47478cb438aed860fc5eab28cc763d464af5aa0a249f2737a081afd35d50147522102907a54bed8ad74b3f35638c60114ca240a308cb986f3f2f306178869a8880b61210377f8715b7895e57dd49de1ef084f94e6edb7df0f9e4807b94800ce751430004c52aeffffffff2a04e7374dd90a033120d3182db77d502210ecfb21a4499f8458e3f464b8e1e4020000006b483045022100992206f9b180553f07742ace393a6eb9542a5e704a3de55b57a2a112cd722c8c02206b040aeb7b3172dbae2e02344710a8174887d69614dddd034e08a07e5b296e8d012102ec4ce6f13fef0cd94532693d0d45a2f28dec2d3c8e693a5134da9d4c6dc0d16cffffffff02cdfb07000000000017a9142743d98a6175c25c9353c42b2feb8c09c769c4d387f4344b00000000001976a914714c6982c9f1c3560deceee9264eb193a737a69988ac00000000";

    try std.testing.expectEqualStrings(expected, encoded[0..expected.len]);
}

test "test decode" {
    const bytes = [_]u8{ 1, 0, 0, 0, 2, 27, 4, 71, 15, 160, 230, 165, 197, 161, 180, 6, 183, 19, 108, 176, 10, 85, 2, 20, 49, 11, 61, 101, 158, 237, 87, 32, 236, 29, 94, 186, 250, 22, 0, 0, 0, 218, 0, 71, 48, 68, 2, 32, 19, 125, 191, 106, 160, 204, 137, 198, 77, 44, 34, 74, 247, 148, 205, 36, 217, 226, 141, 242, 217, 200, 74, 246, 245, 33, 243, 22, 35, 213, 234, 115, 2, 32, 57, 94, 65, 127, 238, 73, 219, 37, 47, 62, 175, 248, 197, 204, 203, 237, 122, 198, 14, 224, 243, 43, 80, 23, 167, 107, 178, 15, 155, 55, 121, 142, 1, 72, 48, 69, 2, 33, 0, 216, 11, 243, 136, 122, 243, 252, 240, 6, 201, 243, 0, 208, 236, 130, 224, 160, 61, 129, 211, 111, 115, 87, 148, 192, 55, 188, 222, 252, 236, 8, 110, 2, 32, 28, 228, 212, 116, 120, 203, 67, 138, 237, 134, 15, 197, 234, 178, 140, 199, 99, 212, 100, 175, 90, 160, 162, 73, 242, 115, 122, 8, 26, 253, 53, 213, 1, 71, 82, 33, 2, 144, 122, 84, 190, 216, 173, 116, 179, 243, 86, 56, 198, 1, 20, 202, 36, 10, 48, 140, 185, 134, 243, 242, 243, 6, 23, 136, 105, 168, 136, 11, 97, 33, 3, 119, 248, 113, 91, 120, 149, 229, 125, 212, 157, 225, 239, 8, 79, 148, 230, 237, 183, 223, 15, 158, 72, 7, 185, 72, 0, 206, 117, 20, 48, 0, 76, 82, 174, 255, 255, 255, 255, 42, 4, 231, 55, 77, 217, 10, 3, 49, 32, 211, 24, 45, 183, 125, 80, 34, 16, 236, 251, 33, 164, 73, 159, 132, 88, 227, 244, 100, 184, 225, 228, 2, 0, 0, 0, 107, 72, 48, 69, 2, 33, 0, 153, 34, 6, 249, 177, 128, 85, 63, 7, 116, 42, 206, 57, 58, 110, 185, 84, 42, 94, 112, 74, 61, 229, 91, 87, 162, 161, 18, 205, 114, 44, 140, 2, 32, 107, 4, 10, 235, 123, 49, 114, 219, 174, 46, 2, 52, 71, 16, 168, 23, 72, 135, 214, 150, 20, 221, 221, 3, 78, 8, 160, 126, 91, 41, 110, 141, 1, 33, 2, 236, 76, 230, 241, 63, 239, 12, 217, 69, 50, 105, 61, 13, 69, 162, 242, 141, 236, 45, 60, 142, 105, 58, 81, 52, 218, 157, 76, 109, 192, 209, 108, 255, 255, 255, 255, 2, 205, 251, 7, 0, 0, 0, 0, 0, 23, 169, 20, 39, 67, 217, 138, 97, 117, 194, 92, 147, 83, 196, 43, 47, 235, 140, 9, 199, 105, 196, 211, 135, 244, 52, 75, 0, 0, 0, 0, 0, 25, 118, 169, 20, 113, 76, 105, 130, 201, 241, 195, 86, 13, 236, 238, 233, 38, 78, 177, 147, 167, 55, 166, 153, 136, 172, 0, 0, 0, 0 };
    const transaction_hex = "01000000021b04470fa0e6a5c5a1b406b7136cb00a550214310b3d659eed5720ec1d5ebafa16000000da004730440220137dbf6aa0cc89c64d2c224af794cd24d9e28df2d9c84af6f521f31623d5ea730220395e417fee49db252f3eaff8c5cccbed7ac60ee0f32b5017a76bb20f9b37798e01483045022100d80bf3887af3fcf006c9f300d0ec82e0a03d81d36f735794c037bcdefcec086e02201ce4d47478cb438aed860fc5eab28cc763d464af5aa0a249f2737a081afd35d50147522102907a54bed8ad74b3f35638c60114ca240a308cb986f3f2f306178869a8880b61210377f8715b7895e57dd49de1ef084f94e6edb7df0f9e4807b94800ce751430004c52aeffffffff2a04e7374dd90a033120d3182db77d502210ecfb21a4499f8458e3f464b8e1e4020000006b483045022100992206f9b180553f07742ace393a6eb9542a5e704a3de55b57a2a112cd722c8c02206b040aeb7b3172dbae2e02344710a8174887d69614dddd034e08a07e5b296e8d012102ec4ce6f13fef0cd94532693d0d45a2f28dec2d3c8e693a5134da9d4c6dc0d16cffffffff02cdfb07000000000017a9142743d98a6175c25c9353c42b2feb8c09c769c4d387f4344b00000000001976a914714c6982c9f1c3560deceee9264eb193a737a69988ac00000000";
    var allocator = std.testing.allocator;
    const decoded = try hexDecode(&allocator, transaction_hex);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, decoded[0..], bytes[0..]);
}
