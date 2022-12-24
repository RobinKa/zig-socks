const std = @import("std");
const network = @import("network");
pub const Crypto = @import("shadowsocks/crypto.zig");
pub const Headers = @import("shadowsocks/headers.zig");

fn readContent(buffer: []const u8, content: []u8, encryptor: *Crypto.Encryptor) !void {
    const encrypted = buffer[0 .. buffer.len - 16];
    var tag: [16]u8 = undefined;
    std.mem.copy(u8, &tag, buffer[buffer.len - 16 .. buffer.len]);
    try encryptor.decrypt(content, encrypted, tag);
}

const ClientStateTag = enum {
    wait_for_fixed,
    wait_for_variable,
    wait_for_length,
    wait_for_payload,
};

const SharedClientState = struct {
    state: ClientStateTag = .wait_for_fixed,

    socket: network.Socket,
    remote_socket: network.Socket,
    socket_set: *network.SocketSet,
    recv_buffer: std.ArrayList(u8),

    request_salt: [32]u8 = undefined,
    response_salt: [32]u8 = undefined,
    key: []const u8,

    sent_initial_response: bool = false,
    response_encryptor: Crypto.Encryptor,

    length: u16 = undefined,
    request_decryptor: Crypto.Encryptor = undefined,
    session_subkey: [32]u8 = undefined,

    fn deinit(self: @This()) void {
        self.socket.close();
        self.remote_socket.close();
        self.socket_set.deinit();
    }
};

const ShadowsocksError = error{
    ProtocolViolation,
    Unsupported,
};

fn handleWaitForFixed(state: *SharedClientState) !bool {
    // Initial request needs to have at least the fixed length header
    if (state.recv_buffer.items.len < 32 + 11 + 16) {
        return ShadowsocksError.ProtocolViolation;
    }

    var session_subkey: [32]u8 = undefined;

    var key_and_request_salt: [64]u8 = undefined;
    std.mem.copy(u8, key_and_request_salt[0..32], state.key);
    std.mem.copy(u8, key_and_request_salt[32..64], &state.request_salt);

    Crypto.deriveSessionSubkey(&key_and_request_salt, &session_subkey);

    state.request_decryptor = .{
        .key = session_subkey,
    };

    var decrypted: [11]u8 = undefined;
    try readContent(state.recv_buffer.items[32 .. 32 + 11 + 16], &decrypted, &state.request_decryptor);

    var stream = std.io.fixedBufferStream(&decrypted);
    var reader = stream.reader();
    const decoded_header = try Headers.FixedLengthRequestHeader.decode(reader);

    state.length = decoded_header.length;
    state.state = .wait_for_variable;

    try state.recv_buffer.replaceRange(0, 32 + 11 + 16, &.{});

    return true;
}

fn handleWaitForVariable(state: *SharedClientState) !bool {
    if (state.recv_buffer.items.len < state.length + 16) {
        return false;
    }

    var decrypted: []u8 = try std.heap.page_allocator.alloc(u8, state.length);
    defer std.heap.page_allocator.free(decrypted);

    try readContent(state.recv_buffer.items[0 .. state.length + 16], decrypted, &state.request_decryptor);

    var stream = std.io.fixedBufferStream(decrypted);
    var reader = stream.reader();
    const decoded_header = try Headers.VariableLengthRequestHeader.decode(reader, state.length, std.heap.page_allocator);

    if (decoded_header.address_type != 1) {
        return ShadowsocksError.Unsupported;
    }

    const address = decoded_header.address[0..4];
    const port = std.mem.readIntBig(u16, decoded_header.address[4..6]);

    try state.remote_socket.connect(.{
        .address = .{ .ipv4 = .{ .value = address.* } },
        .port = port,
    });

    var sent: usize = 0;
    while (sent < decoded_header.initial_payload.len) {
        sent += try state.remote_socket.send(decoded_header.initial_payload[sent..]);
    }

    state.state = .wait_for_length;

    try state.recv_buffer.replaceRange(0, state.length + 16, &.{});

    return true;
}

fn handleWaitForLength(state: *SharedClientState) !bool {
    if (state.recv_buffer.items.len < 18) {
        return false;
    }

    var decrypted: [18]u8 = undefined;
    try readContent(state.recv_buffer.items[0..18], &decrypted, &state.request_decryptor);

    state.length = std.mem.readIntBig(u16, decrypted[0..2]);
    state.state = .wait_for_payload;

    try state.recv_buffer.replaceRange(0, 18, &.{});

    return true;
}

fn handleWaitForPayload(state: *SharedClientState) !bool {
    if (state.recv_buffer.items.len < state.length + 16) {
        return false;
    }

    var decrypted: []u8 = try std.heap.page_allocator.alloc(u8, state.length);
    defer std.heap.page_allocator.free(decrypted);

    try readContent(state.recv_buffer.items[0 .. state.length + 16], decrypted, &state.request_decryptor);

    var sent: usize = 0;
    while (sent < decrypted.len) {
        sent += try state.remote_socket.send(decrypted[sent..]);
    }

    state.state = .wait_for_length;

    try state.recv_buffer.replaceRange(0, state.length + 16, &.{});

    return true;
}

fn handleResponse(state: *SharedClientState, received: []const u8) !void {
    var send_buffer = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, 1024);

    if (!state.sent_initial_response) {
        const header: Headers.FixedLengthResponseHeader = .{
            .type = 1,
            .timestamp = @intCast(u64, std.time.milliTimestamp()),
            .salt = state.request_salt,
            .length = @intCast(u16, received.len),
        };

        var encoded: [43]u8 = undefined;
        var stream = std.io.fixedBufferStream(&encoded);
        var writer = stream.writer();
        try header.encode(writer);

        var encrypted: [encoded.len]u8 = undefined;
        var tag: [16]u8 = undefined;
        state.response_encryptor.encrypt(&encoded, &encrypted, &tag);

        var initial_response: [32 + 43 + 16]u8 = undefined;
        std.mem.copy(u8, initial_response[0..32], &state.response_salt);
        std.mem.copy(u8, initial_response[32 .. 32 + 43], &encrypted);
        std.mem.copy(u8, initial_response[32 + 43 .. 32 + 43 + 16], &tag);

        try send_buffer.appendSlice(&initial_response);

        state.sent_initial_response = true;
    } else {
        var encoded: [2]u8 = undefined;
        std.mem.writeIntBig(u16, &encoded, @intCast(u16, received.len));

        var encrypted_and_tag: [18]u8 = undefined;
        state.response_encryptor.encrypt(&encoded, encrypted_and_tag[0..2], encrypted_and_tag[2..18]);

        try send_buffer.appendSlice(&encrypted_and_tag);
    }

    var encrypted: []u8 = try std.heap.page_allocator.alloc(u8, received.len);
    defer std.heap.page_allocator.free(encrypted);

    var tag: [16]u8 = undefined;
    state.response_encryptor.encrypt(received, encrypted, &tag);
    try send_buffer.appendSlice(encrypted);
    try send_buffer.appendSlice(&tag);

    var sent: usize = 0;
    while (sent < send_buffer.items.len) {
        sent += try state.remote_socket.send(send_buffer.items[sent..]);
    }
}

fn handleClient(socket: network.Socket, key: []const u8) !void {
    var response_salt: [32]u8 = undefined;
    Crypto.generateRandomSalt(&response_salt, .{1} ** 32);

    var key_and_response_salt: [64]u8 = undefined;
    std.mem.copy(u8, key_and_response_salt[0..32], key);
    std.mem.copy(u8, key_and_response_salt[32..64], &response_salt);

    var response_session_subkey: [32]u8 = undefined;
    Crypto.deriveSessionSubkey(&key_and_response_salt, &response_session_subkey);

    var socket_set = try network.SocketSet.init(std.heap.page_allocator);

    // TODO: if any of the trys fail, things aren't cleaned up properly.
    var state = SharedClientState{
        .socket = socket,
        .remote_socket = try network.Socket.create(.ipv4, .tcp),
        .socket_set = &socket_set,
        .key = key[0..32],
        .response_salt = response_salt,
        .response_encryptor = .{
            .key = response_session_subkey,
        },
        .recv_buffer = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, 1024),
    };
    defer state.deinit();

    try state.socket_set.add(state.socket, .{
        .read = true,
        .write = false,
    });

    try state.socket_set.add(state.remote_socket, .{
        .read = true,
        .write = false,
    });

    var buffer: [1024]u8 = undefined;
    while (true) {
        _ = try network.waitForSocketEvent(state.socket_set, null);

        if (state.socket_set.isReadyRead(state.socket)) {
            const count = try state.socket.receive(&buffer);
            try state.recv_buffer.appendSlice(buffer[0..count]);
        }

        if (state.socket_set.isReadyRead(state.remote_socket)) {
            const count = try state.remote_socket.receive(&buffer);
            try handleResponse(&state, buffer[0..count]);
        }

        while (true) {
            switch (state.state) {
                .wait_for_fixed => {
                    if (!try handleWaitForFixed(&state)) break;
                },
                .wait_for_variable => {
                    if (!try handleWaitForVariable(&state)) break;
                },
                .wait_for_length => {
                    if (!try handleWaitForLength(&state)) break;
                },
                .wait_for_payload => {
                    if (!try handleWaitForPayload(&state)) break;
                },
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
