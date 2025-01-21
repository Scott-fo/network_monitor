const std = @import("std");
const headers = @import("headers.zig");
const IPv4Address = headers.IPv4Address;
const port = @import("port.zig");
const Protocol = port.Protocol;

pub const ConnectionId = struct {
    const Self = @This();

    src_ip: IPv4Address,
    dest_ip: IPv4Address,
    src_port: u16,
    dest_port: u16,
    protocol: Protocol,

    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);

        hasher.update(&self.src_ip.address);
        hasher.update(&self.dest_ip.address);
        hasher.update(std.mem.asBytes(&self.src_port));
        hasher.update(std.mem.asBytes(&self.dest_port));
        hasher.update(@tagName(self.protocol));

        return hasher.final();
    }

    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, &self.src_ip.address, &other.src_ip.address) and
            std.mem.eql(u8, &self.dst_ip.address, &other.dst_ip.address) and
            self.src_port == other.src_port and
            self.dst_port == other.dst_port and
            self.protocol == other.protocol;
    }
};

pub const Connection = struct {
    const Self = @This();

    id: ConnectionId,
    packets_sent: usize,
    bytes_sent: usize,
    first_seen: i64,
    last_seen: i64,
};
