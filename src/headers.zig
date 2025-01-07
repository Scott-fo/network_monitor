const EthernetHeader = packed struct {
    dest_mac: [6]u8,
    src_mac: [6]u8,
    ether_type: u16,
};

const IPv4Header = packed struct {
    version_ihl: u8,
    tos: u8,
    total_length: u16,
    id: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: u32,
    dest_addr: u32,

    pub fn get_header_length(self: *const IPv4Header) u8 {
        return (self.version_ihl & 0x0F) * 4;
    }
};

const TcpHeader = packed struct {
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

const UdpHeader = packed struct {
    src_port: u16,
    dest_port: u16,
    length: u16,
    checksum: u16,
};
