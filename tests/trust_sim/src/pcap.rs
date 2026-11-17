use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::packet::{Kind, Packet, Protocol};

const ETHERNET: u32 = 1;
const RAW: u32 = 101;
const VLAN_TAGS: [u16; 3] = [0x8100, 0x88a8, 0x9100];

pub struct Reader<R> {
    input: R,
    swapped: bool,
    nanos: bool,
    linktype: u32,
    buf: Vec<u8>,
    pub truncated: bool,
}

impl<R: Read> Reader<R> {
    pub fn new(mut input: R) -> io::Result<Self> {
        let mut header = [0u8; 24];
        input.read_exact(&mut header)?;
        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let (swapped, nanos) = match magic {
            0xa1b2c3d4 => (false, false),
            0xa1b23c4d => (false, true),
            0xd4c3b2a1 => (true, false),
            0x4d3cb2a1 => (true, true),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "not a pcap file (pcapng is not supported)")),
        };
        let mut reader = Self {
            input,
            swapped,
            nanos,
            linktype: 0,
            buf: Vec::new(),
            truncated: false,
        };
        reader.linktype = reader.u32(&header[20..24]) & 0x0fff_ffff;
        if reader.linktype != ETHERNET && reader.linktype != RAW {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported link type {}", reader.linktype),
            ));
        }
        Ok(reader)
    }

    fn u32(&self, b: &[u8]) -> u32 {
        let b: [u8; 4] = b.try_into().unwrap();
        if self.swapped { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
    }

    pub fn read_packet(&mut self) -> io::Result<Option<(Packet, bool)>> {
        let mut header = [0u8; 16];
        match self.input.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let sec = u64::from(self.u32(&header[0..4]));
        let frac = u64::from(self.u32(&header[4..8]));
        let caplen = self.u32(&header[8..12]) as usize;
        let len = self.u32(&header[12..16]);
        self.buf.resize(caplen, 0);
        match self.input.read_exact(&mut self.buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                self.truncated = true;
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
        let ts = sec * 1_000_000_000 + if self.nanos { frac } else { frac * 1_000 };
        let (kind, vlan) = match self.linktype {
            ETHERNET => ethernet(&self.buf),
            _ => (ip(&self.buf), false),
        };
        Ok(Some((Packet { ts, len, kind }, vlan)))
    }
}

pub fn ethernet(frame: &[u8]) -> (Kind, bool) {
    let mut vlan = false;
    if frame.len() < 14 || frame[0] & 1 != 0 {
        return (Kind::Other, vlan);
    }
    let mut at = 12;
    while frame.len() >= at + 2 && VLAN_TAGS.contains(&be16(frame, at)) {
        vlan = true;
        at += 4;
    }
    if frame.len() < at + 2 {
        return (Kind::Other, vlan);
    }
    let kind = match be16(frame, at) {
        0x0800 | 0x86dd => ip(&frame[at + 2..]),
        _ => Kind::Other,
    };
    (kind, vlan)
}

pub fn ip(packet: &[u8]) -> Kind {
    parse_ip(packet).unwrap_or(Kind::Other)
}

fn parse_ip(p: &[u8]) -> Option<Kind> {
    let (proto, src, dst, l4): (u8, IpAddr, IpAddr, usize) = match p.first()? >> 4 {
        4 => {
            let ihl = usize::from(p.first()? & 0x0f) * 4;
            if ihl < 20 || be16(p.get(..8)?, 6) & 0x3fff != 0 {
                return None;
            }
            let src = Ipv4Addr::from(<[u8; 4]>::try_from(p.get(12..16)?).ok()?);
            let dst = Ipv4Addr::from(<[u8; 4]>::try_from(p.get(16..20)?).ok()?);
            if dst.is_multicast() || dst.is_broadcast() {
                return None;
            }
            (p[9], src.into(), dst.into(), ihl)
        }
        6 => {
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(p.get(8..24)?).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(p.get(24..40)?).ok()?);
            if dst.is_multicast() {
                return None;
            }
            (p[6], src.into(), dst.into(), 40)
        }
        _ => return None,
    };
    let protocol = match proto {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return None,
    };
    let l4 = p.get(l4..)?;
    let sport = be16(l4.get(..4)?, 0);
    let dport = be16(l4, 2);
    let flags = match protocol {
        Protocol::Tcp => *l4.get(13)?,
        Protocol::Udp => 0,
    };
    Some(Kind::Flow {
        protocol,
        src: SocketAddr::new(src, sport),
        dst: SocketAddr::new(dst, dport),
        flags,
    })
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

#[cfg(test)]
mod tests;
