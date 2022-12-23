const std = @import("std");
const network = @import("network");

fn handleClient(socket: network.Socket) !void {
    defer socket.close();

    // Buffer and count reused for send / receive calls
    var buffer: [1024]u8 = undefined;
    var count: usize = undefined;

    // Handle initial request
    count = try socket.receive(&buffer);

    // Initial request needs to have at least 8 bytes
    if (buffer.len < 8) {
        return;
    }

    // We can only handle SOCKS4
    if (buffer[0] != 4) {
        return;
    }

    // We only support connection requests
    if (buffer[1] != 1) {
        return;
    }

    // Send initial success response
    const destination_port = std.mem.readIntBig(u16, buffer[2..4]);
    const destination_ip = buffer[4..8];
    const response = [_]u8{ 0x00, 0x5A } ++ buffer[2..8];
    count = try socket.send(response);

    // Connect to requested remote
    var remote_socket = try network.Socket.create(.ipv4, .tcp);
    defer remote_socket.close();
    try remote_socket.connect(.{
        .address = .{ .ipv4 = .{ .value = destination_ip.* } },
        .port = destination_port,
    });

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
            var sent: usize = 0;
            while (sent < count) {
                sent += try remote_socket.send(buffer[sent..count]);
            }
        }

        // Receive from remote and send to client
        if (socket_set.isReadyRead(remote_socket)) {
            count = try remote_socket.receive(&buffer);
            var sent: usize = 0;
            while (sent < count) {
                sent += try socket.send(buffer[sent..count]);
            }
        }
    }
}

pub fn startServer(port: u16) !void {
    var socket = try network.Socket.create(.ipv4, .tcp);
    defer socket.close();
    try socket.bindToPort(port);
    try socket.listen();

    while (true) {
        var client = try socket.accept();
        (try std.Thread.spawn(.{}, handleClient, .{client})).detach();
        std.time.sleep(std.time.ns_per_us * 100);
    }
}
