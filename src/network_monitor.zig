const std = @import("std");
const print = std.debug.print;
const os = std.os;

const headers = @import("headers.zig");
const EthernetHeader = headers.EthernetHeader;
const MacAddress = headers.MacAddress;
const IPv4Header = headers.IPv4Header;
const IPv4Address = headers.IPv4Address;

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

        // print("EtherType: 0x{X:0>4}\n", .{ether_type});

        switch (ether_type) {
            ETH_P_IP => {
                self.stats.ipv4_packets += 1;
                if (ParsedIpv4.init(ethernet.?.payload)) |ipv4| {
                    print("From IP: {}\n", .{ipv4.header.src_addr});
                    print("To IP: {}\n", .{ipv4.header.dest_addr});
                }
            },
            else => {
                self.stats.other_packets += 1;
            },
        }

        // print("From: {}\n", .{ethernet.?.header.src_mac});
        // print("To: {}\n", .{ethernet.?.header.dest_mac});
    }
};
