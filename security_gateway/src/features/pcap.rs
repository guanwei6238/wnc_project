use std::io::{self, Read};

pub const MAX_PACKETS: usize = 1_000_000;
const MAX_FRAME: u32 = 262_144;
const LINKTYPE_ETHERNET: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum PcapError {
    #[error("cannot read the pcap file: {0}")]
    Io(#[from] io::Error),
    #[error("not a pcap file (pcapng is not supported; convert it with: editcap -F pcap in.pcapng out.pcap)")]
    Magic,
    #[error("the pcap's link type is {0}; only Ethernet (1) is supported")]
    LinkType(u32),
    #[error("packet {index} claims {len} bytes, more than {MAX_FRAME}")]
    Frame { index: usize, len: u32 },
    #[error("the pcap has more than {MAX_PACKETS} packets")]
    TooMany,
}

/// Reads every packet of a classic pcap file (either byte order, µs or ns timestamps).
pub fn packets(mut input: impl Read) -> Result<Vec<Vec<u8>>, PcapError> {
    let mut header = [0u8; 24];
    input.read_exact(&mut header)?;
    let little = match header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => return Err(PcapError::Magic),
    };
    let word = |b: &[u8]| {
        let b: [u8; 4] = b.try_into().unwrap();
        if little { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
    };
    let link = word(&header[20..24]);
    if link != LINKTYPE_ETHERNET {
        return Err(PcapError::LinkType(link));
    }
    let mut packets = Vec::new();
    loop {
        let mut record = [0u8; 16];
        match input.read_exact(&mut record) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let len = word(&record[8..12]);
        if len > MAX_FRAME {
            return Err(PcapError::Frame { index: packets.len(), len });
        }
        if packets.len() == MAX_PACKETS {
            return Err(PcapError::TooMany);
        }
        let mut data = vec![0u8; len as usize];
        input.read_exact(&mut data)?;
        packets.push(data);
    }
    Ok(packets)
}

#[cfg(test)]
mod tests;
