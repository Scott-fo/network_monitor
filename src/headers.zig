pub const MacAddress = extern struct {
    address: [6]u8,
};

pub const IPv4Address = extern struct {
    address: [4]u8,
};

/// Ethernet Frame Header
/// +-------------------+------------------+----------------+
/// | Destination MAC   | Source MAC       | EtherType      |
/// | 6 bytes           | 6 bytes          | 2 bytes        |
/// +-------------------+------------------+----------------+
/// EtherType values:
/// - 0x0800: IPv4
/// - 0x86DD: IPv6
/// - 0x0806: ARP
pub const EthernetHeader = extern struct {
    dest_mac: MacAddress,
    src_mac: MacAddress,
    ether_type: u16,
};

// IPv4 Header Format
// +--------+--------+----------------+--------------------------------+
// |Version | IHL    | Type of Service|         Total Length           |
// |4 bits  | 4 bits | 8 bits         |         16 bits                |
// +--------+--------+----------------+-----+--------------------------+
// |          Identification          |Flags|    Fragment Offset       |
// |          16 bits                 |3bits|    13 bits               |
// +-----------------+----------------+-----+--------------------------+
// |  Time to Live   |   Protocol     |     Header Checksum            |
// |    8 bits       |   8 bits       |     16 bits                    |
// +-----------------+----------------+--------------------------------+
// |                       Source IP Address                           |
// |                         32 bits                                   |
// +-------------------------------------------------------------------+
// |                    Destination IP Address                         |
// |                         32 bits                                   |
// +-------------------------------------------------------------------+
/// Protocol values:
/// - 6: TCP
/// - 17: UDP
/// - 1: ICMP
/// - 2: IGMP
pub const IPv4Header = extern struct {
    version_ihl: u8,
    tos: u8,
    total_length: u16,
    id: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: IPv4Address,
    dest_addr: IPv4Address,

    pub fn get_header_length(self: *const IPv4Header) u8 {
        return (self.version_ihl & 0x0F) * 4;
    }
};

// TCP Header Format
// +----------------------+---------------------+
// |     Source Port      |   Destination Port  |
// |      16 bits         |      16 bits        |
// +----------------------+---------------------+
// |              Sequence Number               |
// |                 32 bits                    |
// +--------------------------------------------+
// |           Acknowledgment Number            |
// |                 32 bits                    |
// +--------+--------+--------+-----------------+
// |  Data  |Reserved|  Flags |     Window      |
// | Offset |  6 bits| 6 bits |    16 bits      |
// | 4 bits |        |        |                 |
// +--------+--------+--------+-----------------+
// |      Checksum        |   Urgent Pointer   |
// |      16 bits         |     16 bits        |
// +----------------------+---------------------+
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

/// UDP Header
/// +-------------------+-------------------+
/// | Source Port       | Destination Port  |
/// | 16 bits           | 16 bits           |
/// +-------------------+-------------------+
/// | Length            | Checksum          |
/// | 16 bits           | 16 bits           |
/// +-------------------+-------------------+
pub const UdpHeader = extern struct {
    src_port: u16,
    dest_port: u16,
    length: u16,
    checksum: u16,
};
