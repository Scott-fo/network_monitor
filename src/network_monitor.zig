const std = @import("std");
const print = std.debug.print;
const os = std.os;

const headers = @import("headers.zig");
const EthernetHeader = headers.EthernetHeader;
const MacAddress = headers.MacAddress;
const IPv4Header = headers.IPv4Header;
const IPv4Address = headers.IPv4Address;
const TcpHeader = headers.TcpHeader;
const UdpHeader = headers.UdpHeader;

const port = @import("port.zig");
const Protocol = port.Protocol;

const ETH_P_ALL = 0x0003;
const ETH_P_IP = 0x0800;

const ParsedEthernet = struct {
    const Self = @This();

    header: EthernetHeader,
    payload: []const u8,

    pub fn init(buffer: []const u8) ?Self {
        if (buffer.len < @sizeOf(EthernetHeader)) {
            return null;
        }

        const dest_mac = MacAddress{ .address = buffer[0..6].* };
        const src_mac = MacAddress{ .address = buffer[6..12].* };
        const ether_type = std.mem.readInt(u16, buffer[12..14], .big);

        return Self{
            .header = .{
                .dest_mac = dest_mac,
                .src_mac = src_mac,
                .ether_type = ether_type,
            },
            .payload = buffer[@sizeOf(EthernetHeader)..],
        };
    }
};

const ParsedIpv4 = struct {
    const Self = @This();

    header: IPv4Header,
    payload: []const u8,

    pub fn init(buffer: []const u8) ?Self {
        if (buffer.len < @sizeOf(IPv4Header)) {
            return null;
        }

        const src_addr = IPv4Address{ .address = buffer[12..16].* };
        const dest_addr = IPv4Address{ .address = buffer[16..20].* };

        return Self{
            .header = .{
                .version_ihl = buffer[0],
                .tos = buffer[1],
                .total_length = std.mem.readInt(u16, buffer[2..4], .big),
                .id = std.mem.readInt(u16, buffer[4..6], .big),
                .flags_fragment = std.mem.readInt(u16, buffer[6..8], .big),
                .ttl = buffer[8],
                .protocol = buffer[9],
                .checksum = std.mem.readInt(u16, buffer[10..12], .big),
                .src_addr = src_addr,
                .dest_addr = dest_addr,
            },
            .payload = buffer[@sizeOf(IPv4Header)..],
        };
    }
};

const ParsedTcp = struct {
    const Self = @This();

    header: TcpHeader,
    payload: []const u8,

    pub fn init(buffer: []const u8) ?Self {
        if (buffer.len < @sizeOf(TcpHeader)) {
            return null;
        }

        return Self{
            .header = .{
                .src_port = std.mem.readInt(u16, buffer[0..2], .big),
                .dest_port = std.mem.readInt(u16, buffer[2..4], .big),
                .sequence = std.mem.readInt(u32, buffer[4..8], .big),
                .ack = std.mem.readInt(u32, buffer[8..12], .big),
                .offset_reserved = buffer[12],
                .flags = buffer[13],
                .window = std.mem.readInt(u16, buffer[14..16], .big),
                .checksum = std.mem.readInt(u16, buffer[16..18], .big),
                .urgent = std.mem.readInt(u16, buffer[18..20], .big),
            },
            .payload = buffer[@sizeOf(TcpHeader)..],
        };
    }
};

const ParsedUdp = struct {
    const Self = @This();

    header: UdpHeader,
    payload: []const u8,

    pub fn init(buffer: []const u8) ?Self {
        if (buffer.len < @sizeOf(UdpHeader)) {
            return null;
        }

        return Self{
            .header = .{
                .src_port = std.mem.readInt(u16, buffer[0..2], .big),
                .dest_port = std.mem.readInt(u16, buffer[2..4], .big),
                .length = std.mem.readInt(u16, buffer[4..6], .big),
                .checksum = std.mem.readInt(u16, buffer[6..8], .big),
            },
            .payload = buffer[@sizeOf(UdpHeader)..],
        };
    }
};

const PacketStats = struct {
    const Self = @This();

    total_packets: usize,
    total_bytes: usize,
    ipv4_packets: usize,
    ipv6_packets: usize,
    tcp_packets: usize,
    udp_packets: usize,
    other_packets: usize,

    pub fn show(self: *const Self) void {
        print("\nPacket Stats:\n", .{});
        print("Total Packets: {d}\n", .{self.total_packets});
        print("Total Bytes: {d}\n", .{self.total_bytes});
        print("IPv4 Packets: {d}\n", .{self.ipv4_packets});
        print("IPv6 Packets: {d}\n", .{self.ipv6_packets});
        print("TCP Packets: {d}\n", .{self.tcp_packets});
        print("UDP Packets: {d}\n", .{self.udp_packets});
        print("Other Packets: {d}\n", .{self.other_packets});
    }

    pub fn init() Self {
        return .{
            .total_packets = 0,
            .total_bytes = 0,
            .ipv4_packets = 0,
            .ipv6_packets = 0,
            .tcp_packets = 0,
            .udp_packets = 0,
            .other_packets = 0,
        };
    }
};

pub const NetworkMonitor = struct {
    const Self = @This();

    socket: std.posix.fd_t,
    allocator: std.mem.Allocator,
    stats: PacketStats,
    running: bool,

    pub fn init(gpa: std.mem.Allocator) !Self {
        if (@import("builtin").os.tag != .linux) {
            @compileError("Only supporting linux for now");
        }

        const socket = try std.posix.socket(
            std.os.linux.AF.PACKET,
            std.os.linux.SOCK.RAW,
            std.mem.nativeToBig(u16, ETH_P_ALL),
        );

        return Self{
            .socket = socket,
            .allocator = gpa,
            .stats = PacketStats.init(),
            .running = false,
        };
    }

    pub fn deinit(self: *Self) void {
        std.posix.close(self.socket);
    }

    pub fn start(self: *Self) !void {
        var buffer: [65535]u8 = undefined;
        self.running = true;

        while (self.running) {
            const bytes_read = try std.posix.read(self.socket, &buffer);
            if (bytes_read > 0) {
                self.parse_packet(buffer[0..bytes_read]);
                if (self.stats.total_packets % 10 == 0) {
                    self.stats.show();
                }
            }
        }
    }

    pub fn parse_packet(self: *Self, buffer: []const u8) void {
        const ethernet = ParsedEthernet.init(buffer);
        if (ethernet == null) {
            return;
        }

        const ether_type = ethernet.?.header.ether_type;

        self.stats.total_packets += 1;
        self.stats.total_bytes += buffer.len;

        switch (ether_type) {
            ETH_P_IP => {
                self.stats.ipv4_packets += 1;
                if (ParsedIpv4.init(ethernet.?.payload)) |ipv4| {
                    print("From IP: {}\n", .{ipv4.header.src_addr});
                    print("To IP: {}\n", .{ipv4.header.dest_addr});

                    switch (ipv4.header.protocol) {
                        6 => {
                            self.stats.tcp_packets += 1;
                            if (ParsedTcp.init(ipv4.payload)) |tcp| {
                                const src_service = port.lookupPort(tcp.header.src_port, .tcp);
                                const dest_service = port.lookupPort(tcp.header.dest_port, .tcp);
                                print("TCP {}:{s} -> {}:{s}\n", .{
                                    tcp.header.src_port,
                                    src_service orelse "",
                                    tcp.header.dest_port,
                                    dest_service orelse "",
                                });
                            }
                        },
                        17 => {
                            self.stats.udp_packets += 1;
                            if (ParsedUdp.init(ipv4.payload)) |udp| {
                                const src_service = port.lookupPort(udp.header.src_port, .udp);
                                const dest_service = port.lookupPort(udp.header.dest_port, .udp);
                                print("udp {}:{s} -> {}:{s}\n", .{
                                    udp.header.src_port,
                                    src_service orelse "EPHEMERAL",
                                    udp.header.dest_port,
                                    dest_service orelse "EPHEMERAL",
                                });
                            }
                        },
                        else => {},
                    }
                }
            },
            else => {
                self.stats.other_packets += 1;
            },
        }
    }
};
