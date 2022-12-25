# SOCKS4 server written in Zig

Implementations of proxy servers and clients written in [Zig](https://ziglang.org).

Uses [zig-network](https://github.com/MasterQ32/zig-network) for sockets.

## Implementations

### SOCKS4

A basic [SOCKS4](https://www.openssh.com/txt/socks4.protocol) proxy server

### Shadowsocks 2022

Implementation of Shadowsocks 2022 according to [this document](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md).

Shadowsocks 2022 is an encrypted protocol utilizing a pre-shared key and was designed to be hard to detect to avoid government censorship.
