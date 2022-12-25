const std = @import("std");
const network = @import("network");
const socks = @import("socks.zig");
const shadowsocks = @import("shadowsocks.zig");

pub fn main() !void {
    try network.init();
    defer network.deinit();

    const encoded_key = "base64 encoded 32 bytes";
    var key: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&key, encoded_key);

    try shadowsocks.Server.start(5667, &key);
}
