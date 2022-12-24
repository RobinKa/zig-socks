const std = @import("std");
const socks = @import("socks.zig");
const shadowsocks = @import("shadowsocks.zig");

pub fn main() !void {
    const encoded_key = "changeme";
    var key: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&key, encoded_key);

    try shadowsocks.startServer(5667, &key);
}
