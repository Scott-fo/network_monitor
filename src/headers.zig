pub const MacAddress = extern struct {
    address: [6]u8,
};

const Ipv4Address = extern struct {
    address: [4]u8,
};

pub const EthernetHeader = extern struct {
    dest_mac: MacAddress,
    src_mac: MacAddress,
    ether_type: u16,
};

pub const IPv4Header = extern struct {
    version_ihl: u8,
    tos: u8,
    total_length: u16,
    id: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: Ipv4Address,
    dest_addr: Ipv4Address,

    pub fn get_header_length(self: *const IPv4Header) u8 {
        return (self.version_ihl & 0x0F) * 4;
    }
};

pub const TcpHeader = extern struct {
    src_port: u16,
    dest_port: u16,
    sequence: u32,
    ack: u32,
    offset_reserved: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urgent: u16,
};

pub const UdpHeader = extern struct {
    src_port: u16,
    dest_port: u16,
    length: u16,
    checksum: u16,
};
