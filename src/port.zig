const std = @import("std");

pub const Protocol = enum {
    tcp,
    udp,
};

const TcpPortMap = std.StaticStringMap([]const u8).initComptime(.{
    .{ "21", "FTP" },
    .{ "22", "SSH" },
    .{ "53", "DNS" },
    .{ "80", "HTTP" },
    .{ "443", "HTTPS" },
});

const UdpPortMap = std.StaticStringMap([]const u8).initComptime(.{
    .{ "53", "DNS" },
    .{ "67", "DHCP-SERVER" },
    .{ "68", "DHCP-CLIENT" },
});

pub fn lookupPort(port: u16, protocol: Protocol) ?[]const u8 {
    var port_buf: [5]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch return null;

    return switch (protocol) {
        .tcp => TcpPortMap.get(port_str),
        .udp => UdpPortMap.get(port_str),
    };
}
