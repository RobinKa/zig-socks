const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

pub fn deriveSessionSubkey(key: []const u8, session_subkey: []u8) void {
    var blake = Blake3.initKdf("shadowsocks 2022 session subkey", .{});
    blake.update(key);
    blake.final(session_subkey);
}

pub const Encryptor = struct {
    nonce: u96 = 0,
    key: [Aes256Gcm.key_length]u8,

    pub fn encrypt(self: *@This(), message: []const u8, encrypted: []u8, tag: *[Aes256Gcm.tag_length]u8) void {
        var nonce: [96 / 8]u8 = undefined;
        std.mem.writeIntBig(u96, &nonce, self.nonce);

        Aes256Gcm.encrypt(encrypted, tag, message, "", nonce, self.key);

        self.nonce += 1;
    }

    pub fn decrypt(self: *@This(), message: []u8, encrypted: []const u8, tag: [Aes256Gcm.tag_length]u8) !void {
        var nonce: [96 / 8]u8 = undefined;
        std.mem.writeIntBig(u96, &nonce, self.nonce);

        try Aes256Gcm.decrypt(message, encrypted, tag, "", nonce, self.key);

        self.nonce += 1;
    }
};

test "deriveSessionSubkey" {
    var session_subkey: [4]u8 = undefined;
    deriveSessionSubkey("abcdefg", &session_subkey);
    try std.testing.expectEqualSlices(u8, &.{ 197, 57, 176, 92 }, &session_subkey);
}

test "Encryptor encrypt" {
    var encryptor: Encryptor = .{
        .key = [32]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 },
    };

    try std.testing.expectEqual(@as(u96, 0), encryptor.nonce);

    const message = "asdfqwer";
    var encrypted: [message.len]u8 = undefined;
    var tag: [Aes256Gcm.tag_length]u8 = undefined;

    encryptor.encrypt(message, &encrypted, &tag);

    try std.testing.expectEqualSlices(u8, &.{ 111, 207, 209, 184, 196, 91, 230, 207 }, &encrypted);
    try std.testing.expectEqualSlices(u8, &.{ 108, 175, 174, 87, 224, 85, 75, 9, 36, 55, 163, 93, 250, 24, 52, 249 }, &tag);
    try std.testing.expectEqual(@as(u96, 1), encryptor.nonce);
}

test "Encryptor decrypt" {
    var encryptor: Encryptor = .{
        .key = [32]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 },
    };

    try std.testing.expectEqual(@as(u96, 0), encryptor.nonce);

    const encrypted = [_]u8{ 111, 207, 209, 184, 196, 91, 230, 207 };
    const tag = [_]u8{ 108, 175, 174, 87, 224, 85, 75, 9, 36, 55, 163, 93, 250, 24, 52, 249 };
    var message: [encrypted.len]u8 = undefined;

    try encryptor.decrypt(&message, &encrypted, tag);

    try std.testing.expectEqualStrings("asdfqwer", &message);
    try std.testing.expectEqual(@as(u96, 1), encryptor.nonce);
}
