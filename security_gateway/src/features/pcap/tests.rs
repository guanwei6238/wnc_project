use super::*;

fn pcap(little: bool, link: u32, frames: &[&[u8]]) -> Vec<u8> {
    let w = |v: u32| if little { v.to_le_bytes() } else { v.to_be_bytes() };
    let mut out = Vec::new();
    out.extend(w(0xa1b2c3d4));
    out.extend([0u8, 2, 0, 4]);
    out.extend(w(0));
    out.extend(w(0));
    out.extend(w(65535));
    out.extend(w(link));
    for frame in frames {
        out.extend(w(1));
        out.extend(w(2));
        out.extend(w(frame.len() as u32));
        out.extend(w(frame.len() as u32));
        out.extend(*frame);
    }
    out
}

#[test]
fn reads_both_byte_orders() {
    for little in [true, false] {
        let data = pcap(little, 1, &[b"abc", b"defgh"]);
        assert_eq!(packets(&data[..]).unwrap(), [b"abc".to_vec(), b"defgh".to_vec()]);
    }
}

#[test]
fn rejects_what_it_cannot_read() {
    assert!(matches!(packets(&[0x0a, 0x0d, 0x0d, 0x0a].repeat(6)[..]), Err(PcapError::Magic)));
    assert!(matches!(packets(&pcap(true, 101, &[])[..]), Err(PcapError::LinkType(101))));
    let mut huge = pcap(true, 1, &[]);
    huge.extend([0u8; 8]);
    huge.extend((MAX_FRAME + 1).to_le_bytes());
    huge.extend(0u32.to_le_bytes());
    assert!(matches!(packets(&huge[..]), Err(PcapError::Frame { index: 0, .. })));
    let mut cut = pcap(true, 1, &[b"abcdef"]);
    cut.truncate(cut.len() - 2);
    assert!(matches!(packets(&cut[..]), Err(PcapError::Io(_))));
}
