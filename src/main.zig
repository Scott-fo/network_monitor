const std = @import("std");
const NetworkMonitor = @import("network_monitor.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();
    var monitor = try NetworkMonitor.NetworkMonitor.init(allocator);
    defer monitor.deinit();

    std.debug.print("Starting network monitor", .{});
    try monitor.start();
}
