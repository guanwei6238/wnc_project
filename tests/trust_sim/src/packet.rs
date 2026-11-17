use std::net::SocketAddr;

pub const SECOND: u64 = 1_000_000_000;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    pub protocol: Protocol,
    pub low: SocketAddr,
    pub high: SocketAddr,
}

impl Key {
    pub fn new(protocol: Protocol, a: SocketAddr, b: SocketAddr) -> Self {
        let (low, high) = if a <= b { (a, b) } else { (b, a) };
        Self { protocol, low, high }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Other,
    Flow {
        protocol: Protocol,
        src: SocketAddr,
        dst: SocketAddr,
        flags: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub ts: u64,
    pub len: u32,
    pub kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    pub key: Option<Key>,
    pub sid: u64,
}
