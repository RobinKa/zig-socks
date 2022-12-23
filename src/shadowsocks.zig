const std = @import("std");
const network = @import("network");
pub const Crypto = @import("shadowsocks/crypto.zig");
pub const Headers = @import("shadowsocks/headers.zig");

fn handleClient(socket: network.Socket, key: []const u8) !void {
    defer socket.close();

    // Buffer and count reused for send / receive calls
    var buffer: [1024]u8 = undefined;
    var count: usize = undefined;

    // Handle initial request
    count = try socket.receive(&buffer);

    // Initial request needs to have at least the fixed length header
    if (count < 32 + 11 + 16) {
        return;
    }

    var variable_header_length: usize = undefined;
    var session_subkey: [32]u8 = undefined;
    const salt = buffer[0..4];
    _ = salt; // TODO
    Crypto.deriveSessionSubkey(key, &session_subkey);

    var decode_encryptor: Crypto.Encryptor = .{
        .key = session_subkey,
    };

    // Read fixed length header
    {
        const encrypted = buffer[4 .. 4 + 11];
        const tag = buffer[4 + 11 .. 4 + 11 + 2];

        var decrypted: [11]u8 = undefined;
        try decode_encryptor.decrypt(&decrypted, encrypted, tag);

        var stream = std.io.fixedBufferStream(&decrypted);
        var reader = stream.reader();
        const decoded_header = try Headers.FixedLengthRequestHeader.decode(reader);

        variable_header_length = decoded_header.length;
    }

    // Read variable length header
    var remote_address: []u8 = undefined;
    var initial_payload: []u8 = undefined;

    {
        const encrypted = buffer[4 + 11 + 2 .. 4 + 11 + 2 + variable_header_length];
        const tag = buffer[4 + 11 + 2 + variable_header_length .. 4 + 11 + 2 + variable_header_length + 2];

        var decrypted: [11]u8 = undefined;
        try decode_encryptor.decrypt(&decrypted, encrypted, tag);

        var stream = std.io.fixedBufferStream(&decrypted);
        var reader = stream.reader();
        const decoded_header = try Headers.VariableLengthRequestHeader.decode(reader);
        defer decoded_header.deinit();

        remote_address = decoded_header.address;
        initial_payload = decoded_header.initial_payload;
    }

    // Connect to requested remote and send initial payload
    var remote_socket = try network.Socket.create(.ipv4, .tcp);
    defer remote_socket.close();
    try remote_socket.connect(.{
        .address = .{ .ipv4 = .{ .value = remote_address.* } },
        .port = 123,
    });
    try remote_socket.send(initial_payload);

    // Setup sockets for concurrent send and receive
    var socket_set = try network.SocketSet.init(std.heap.page_allocator);
    try socket_set.add(socket, .{
        .read = true,
        .write = false,
    });
    try socket_set.add(remote_socket, .{
        .read = true,
        .write = false,
    });

    // Proxy loop
    while (true) {
        _ = try network.waitForSocketEvent(&socket_set, null);

        // Receive from client and send to remote
        if (socket_set.isReadyRead(socket)) {
            count = try socket.receive(&buffer);
            // TODO: Decrypt and parse chunks

            var sent: usize = 0;
            while (sent < count) {
                sent += try remote_socket.send(buffer[sent..count]);
            }
        }

        // Receive from remote and send to client
        if (socket_set.isReadyRead(remote_socket)) {
            count = try remote_socket.receive(&buffer);

            // TODO: Make chunks and encrypt
            var sent: usize = 0;
            while (sent < count) {
                sent += try socket.send(buffer[sent..count]);
            }
        }
    }
}

pub fn startServer(port: u16, key: []const u8) !void {
    var socket = try network.Socket.create(.ipv4, .tcp);
    defer socket.close();
    try socket.bindToPort(port);
    try socket.listen();

    while (true) {
        var client = try socket.accept();
        (try std.Thread.spawn(.{}, handleClient, .{ client, key })).detach();
        std.time.sleep(std.time.ns_per_us * 100);
    }
}

test "FixedLengthRequestHeader - derive, encode, encrypt, decrypt, decode" {
    var session_subkey: [32]u8 = undefined;
    Crypto.deriveSessionSubkey("test key", &session_subkey);

    var encode_encryptor: Crypto.Encryptor = .{
        .key = session_subkey,
    };

    var decode_encryptor: Crypto.Encryptor = .{
        .key = session_subkey,
    };

    const header = Headers.FixedLengthRequestHeader{
        .type = 0,
        .timestamp = 123,
        .length = 33,
    };

    var encoded: [11]u8 = undefined;
    var stream = std.io.fixedBufferStream(&encoded);
    var writer = stream.writer();

    try header.encode(writer);

    var encrypted: [encoded.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    encode_encryptor.encrypt(&encoded, &encrypted, &tag);

    var decrypted: [encrypted.len]u8 = undefined;
    try decode_encryptor.decrypt(&decrypted, &encrypted, tag);

    stream = std.io.fixedBufferStream(&decrypted);
    var reader = stream.reader();

    const decoded_header = try Headers.FixedLengthRequestHeader.decode(reader);

    try std.testing.expectEqual(header.length, decoded_header.length);
    try std.testing.expectEqual(header.timestamp, decoded_header.timestamp);
    try std.testing.expectEqual(header.type, decoded_header.type);
}
