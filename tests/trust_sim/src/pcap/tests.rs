use super::*;

fn ipv4(proto: u8, ihl_words: u8, frag: u16, dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
    let ihl = usize::from(ihl_words) * 4;
    let mut p = vec![0u8; ihl];
    p[0] = 0x40 | ihl_words;
    p[6..8].copy_from_slice(&frag.to_be_bytes());
    p[9] = proto;
    p[12..16].copy_from_slice(&[192, 168, 1, 10]);
    p[16..20].copy_from_slice(&dst);
    p.extend_from_slice(l4);
    p
}

fn tcp(flags: u8) -> Vec<u8> {
    let mut l4 = vec![0u8; 20];
    l4[0..2].copy_from_slice(&40000u16.to_be_bytes());
    l4[2..4].copy_from_slice(&443u16.to_be_bytes());
    l4[13] = flags;
    l4
}

fn udp() -> Vec<u8> {
    let mut l4 = vec![0u8; 8];
    l4[0..2].copy_from_slice(&5353u16.to_be_bytes());
    l4[2..4].copy_from_slice(&53u16.to_be_bytes());
    l4
}

fn frame(dst_mac0: u8, tags: &[u16], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 12];
    f[0] = dst_mac0;
    for tag in tags {
        f.extend_from_slice(&tag.to_be_bytes());
        f.extend_from_slice(&[0, 1]);
    }
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

const WAN: [u8; 4] = [203, 0, 113, 5];

#[test]
fn ipv4_tcp() {
    let (kind, vlan) = ethernet(&frame(0, &[], 0x0800, &ipv4(6, 5, 0, WAN, &tcp(0x18))));
    assert!(!vlan);
    assert_eq!(
        kind,
        Kind::Flow {
            protocol: Protocol::Tcp,
            src: "192.168.1.10:40000".parse().unwrap(),
            dst: "203.0.113.5:443".parse().unwrap(),
            flags: 0x18,
        }
    );
}

#[test]
fn ipv4_options_move_the_ports() {
    let kind = ip(&ipv4(17, 6, 0, WAN, &udp()));
    assert!(matches!(kind, Kind::Flow { protocol: Protocol::Udp, dst, .. } if dst.port() == 53));
}

#[test]
fn vlan_tags_are_skipped_and_reported() {
    let (kind, vlan) = ethernet(&frame(0, &[0x8100, 0x8100], 0x0800, &ipv4(17, 5, 0, WAN, &udp())));
    assert!(vlan);
    assert!(matches!(kind, Kind::Flow { .. }));
}

#[test]
fn not_fast_path_material() {
    let cases = [
        frame(1, &[], 0x0800, &ipv4(6, 5, 0, WAN, &tcp(0x10))),
        frame(0, &[], 0x0806, &[0; 28]),
        frame(0, &[], 0x0800, &ipv4(6, 5, 0x2000, WAN, &tcp(0x10))),
        frame(0, &[], 0x0800, &ipv4(6, 5, 0x0001, WAN, &tcp(0x10))),
        frame(0, &[], 0x0800, &ipv4(1, 5, 0, WAN, &[8, 0, 0, 0])),
        frame(0, &[], 0x0800, &ipv4(17, 5, 0, [224, 0, 0, 251], &udp())),
        frame(0, &[], 0x0800, &ipv4(17, 5, 0, [255, 255, 255, 255], &udp())),
        frame(0, &[], 0x0800, &ipv4(6, 5, 0, WAN, &tcp(0x10)[..10])),
    ];
    for (i, f) in cases.iter().enumerate() {
        assert_eq!(ethernet(f).0, Kind::Other, "case {i}");
    }
}

#[test]
fn ipv6_udp_and_multicast() {
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[6] = 17;
    p[8] = 0xfe;
    p[24] = 0x20;
    p.extend_from_slice(&udp());
    assert!(matches!(ip(&p), Kind::Flow { protocol: Protocol::Udp, .. }));
    p[24] = 0xff;
    assert_eq!(ip(&p), Kind::Other);
    p[24] = 0x20;
    p[6] = 0;
    assert_eq!(ip(&p), Kind::Other);
}

fn pcap_file(magic: u32, big_endian: bool, frac: u32) -> Vec<u8> {
    let w = |v: u32| if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
    let frame = frame(0, &[], 0x0800, &ipv4(17, 5, 0, WAN, &udp()));
    let mut f = Vec::new();
    f.extend_from_slice(&w(magic));
    f.extend_from_slice(&[0; 12]);
    f.extend_from_slice(&w(65535));
    f.extend_from_slice(&w(1));
    for record in [w(7), w(frac), w(frame.len() as u32), w(1500)] {
        f.extend_from_slice(&record);
    }
    f.extend_from_slice(&frame);
    f
}

#[test]
fn reads_records_in_all_byte_orders_and_resolutions() {
    for (magic, big_endian, frac, ts) in [
        (0xa1b2c3d4, false, 5, 7_000_005_000),
        (0xa1b2c3d4, true, 5, 7_000_005_000),
        (0xa1b23c4d, false, 5, 7_000_000_005),
    ] {
        let file = pcap_file(magic, big_endian, frac);
        let mut reader = Reader::new(&file[..]).unwrap();
        let (packet, vlan) = reader.read_packet().unwrap().unwrap();
        assert_eq!((packet.ts, packet.len, vlan), (ts, 1500, false));
        assert!(matches!(packet.kind, Kind::Flow { .. }));
        assert!(reader.read_packet().unwrap().is_none());
    }
}

#[test]
fn a_cut_short_last_record_ends_the_file() {
    let file = pcap_file(0xa1b2c3d4, false, 0);
    let mut reader = Reader::new(&file[..file.len() - 3]).unwrap();
    assert!(reader.read_packet().unwrap().is_none());
    assert!(reader.truncated);
}

#[test]
fn rejects_pcapng() {
    let mut f = vec![0x0a, 0x0d, 0x0d, 0x0a];
    f.extend_from_slice(&[0; 20]);
    assert!(Reader::new(&f[..]).is_err());
}
