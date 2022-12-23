const socks = @import("socks.zig");

pub fn main() !void {
    try socks.startServer(5667);
}
