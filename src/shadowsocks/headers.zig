const std = @import("std");

pub const FixedLengthRequestHeader = struct {
    type: u8,
    timestamp: u64,
    length: u16,

    pub fn decode(reader: anytype) !@This() {
        return .{
            .type = try reader.readIntBig(u8),
            .timestamp = try reader.readIntBig(u64),
            .length = try reader.readIntBig(u16),
        };
    }

    pub fn encode(self: @This(), writer: anytype) !void {
        try writer.writeIntBig(u8, self.type);
        try writer.writeIntBig(u64, self.timestamp);
        try writer.writeIntBig(u16, self.length);
    }
};

pub const VariableLengthRequestHeader = struct {
    address_type: u8,
    address: []u8,
    port: u16,
    padding_length: u16,
    padding: []u8,
    initial_payload: []u8,

    allocator: ?std.mem.Allocator = null,

    pub fn deinit(self: @This()) void {
        if (self.allocator != null) {
            std.heap.page_allocator.free(self.address);
            std.heap.page_allocator.free(self.padding);
            std.heap.page_allocator.free(self.initial_payload);
        }
    }

    pub fn decode(reader: anytype, length: u16, allocator: std.mem.Allocator) !@This() {
        const start_pos = reader.context.pos;

        const address_type = try reader.readIntBig(u8);
        var address: []u8 = try allocator.alloc(u8, 6);
        try reader.readNoEof(address[0..6]);

        const port = try reader.readIntBig(u16);

        const padding_length = try reader.readIntBig(u16);
        var padding: []u8 = try allocator.alloc(u8, padding_length);
        try reader.readNoEof(padding[0..padding_length]);

        const remaining_length = length - (reader.context.pos - start_pos);
        var initial_payload = try allocator.alloc(u8, remaining_length);
        try reader.readNoEof(initial_payload[0..remaining_length]);

        return .{
            .address_type = address_type,
            .address = address,
            .port = port,
            .padding_length = padding_length,
            .padding = padding,
            .initial_payload = initial_payload,
            .allocator = allocator,
        };
    }

    pub fn encode(self: @This(), writer: anytype) !void {
        try writer.writeIntBig(u8, self.address_type);
        _ = try writer.write(self.address);
        try writer.writeIntBig(u16, self.port);
        try writer.writeIntBig(u16, self.padding_length);
        _ = try writer.write(self.padding);
        _ = try writer.write(self.initial_payload);
    }
};

pub const FixedLengthResponseHeader = struct {
    type: u8,
    timestamp: u64,
    salt: u32,
    length: u16,

    pub fn decode(reader: anytype) !@This() {
        return .{
            .type = try reader.readIntBig(u8),
            .timestamp = try reader.readIntBig(u64),
            .salt = try reader.readIntBig(u32),
            .length = try reader.readIntBig(u16),
        };
    }

    pub fn encode(self: @This(), writer: anytype) !void {
        try writer.writeIntBig(u8, self.type);
        try writer.writeIntBig(u64, self.timestamp);
        try writer.writeIntBig(u32, self.salt);
        try writer.writeIntBig(u16, self.length);
    }
};

test "encode FixedLengthRequestHeader" {
    const header = FixedLengthRequestHeader{
        .type = 0,
        .timestamp = 123,
        .length = 33,
    };

    var buffer: [100]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    var writer = stream.writer();

    try header.encode(writer);

    try std.testing.expectEqual(@as(usize, 11), stream.pos);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 123, 0, 33 }, buffer[0..11]);
}

test "decode FixedLengthRequestHeader" {
    var buffer = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 123, 0, 33, 7, 8, 9, 10 };
    var stream = std.io.fixedBufferStream(&buffer);
    var reader = stream.reader();

    const header = try FixedLengthRequestHeader.decode(reader);

    try std.testing.expectEqual(@as(usize, 11), reader.context.pos);
    try std.testing.expectEqual(@as(u8, 0), header.type);
    try std.testing.expectEqual(@as(u64, 123), header.timestamp);
    try std.testing.expectEqual(@as(u16, 33), header.length);
}

test "encode VariableLengthRequestHeader" {
    var address = [_]u8{ 1, 2, 3, 4, 5, 6 };
    var padding = [_]u8{ 0, 0, 0, 0 };
    var initial_payload = [_]u8{ 5, 6, 7 };

    const header = VariableLengthRequestHeader{
        .address_type = 1,
        .address = &address,
        .port = 55,
        .padding_length = 4,
        .padding = &padding,
        .initial_payload = &initial_payload,
    };
    defer header.deinit();

    var buffer: [100]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    var writer = stream.writer();

    try header.encode(writer);

    try std.testing.expectEqual(@as(usize, 18), stream.pos);
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 2, 3, 4, 5, 6, 0, 55, 0, 4, 0, 0, 0, 0, 5, 6, 7 }, buffer[0..18]);
}

test "decode VariableLengthRequestHeader" {
    var buffer = [_]u8{ 1, 1, 2, 3, 4, 5, 6, 0, 55, 0, 4, 0, 0, 0, 0, 5, 6, 7, 9, 9, 9 };
    var stream = std.io.fixedBufferStream(&buffer);
    var reader = stream.reader();

    const header = try VariableLengthRequestHeader.decode(reader, buffer.len - 3, std.heap.page_allocator);
    defer header.deinit();

    try std.testing.expectEqual(@as(usize, 18), reader.context.pos);
    try std.testing.expectEqual(@as(u8, 1), header.address_type);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6 }, header.address);
    try std.testing.expectEqual(@as(u16, 55), header.port);
    try std.testing.expectEqual(@as(u16, 4), header.padding_length);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, header.padding);
    try std.testing.expectEqualSlices(u8, &.{ 5, 6, 7 }, header.initial_payload);
}

test "encode FixedLengthResponseHeader" {
    const header = FixedLengthResponseHeader{
        .type = 0,
        .timestamp = 123,
        .salt = 77,
        .length = 33,
    };

    var buffer: [100]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    var writer = stream.writer();

    try header.encode(writer);

    try std.testing.expectEqual(@as(usize, 15), stream.pos);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 77, 0, 33 }, buffer[0..15]);
}

test "decode FixedLengthResponseHeader" {
    var buffer = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 77, 0, 33, 7, 8, 9, 10 };
    var stream = std.io.fixedBufferStream(&buffer);
    var reader = stream.reader();

    const header = try FixedLengthResponseHeader.decode(reader);

    try std.testing.expectEqual(@as(usize, 15), reader.context.pos);
    try std.testing.expectEqual(@as(u8, 0), header.type);
    try std.testing.expectEqual(@as(u64, 123), header.timestamp);
    try std.testing.expectEqual(@as(u32, 77), header.salt);
    try std.testing.expectEqual(@as(u16, 33), header.length);
}