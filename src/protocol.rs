#[derive(Clone, Copy)]
pub enum Protocol {
    Ipv4,
    Icmp4,
    Igmp,
    Tcp,
    Udp,
    Ipv6,
    Icmp6,
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Protocol::Ipv4 => 0,
            Protocol::Icmp4 => 1,
            Protocol::Igmp => 2,
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Ipv6 => 41,
            Protocol::Icmp6 => 58,
        }
    }
}
