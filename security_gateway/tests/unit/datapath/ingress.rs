use super::*;

const EM_BPF: u16 = 247;

#[test]
fn embedded_object_is_a_bpf_elf() {
    let elf = &ELF.0;
    assert_eq!(&elf[..4], b"\x7fELF", "embedded object is not an ELF file");
    assert_eq!(u16::from_le_bytes([elf[18], elf[19]]), EM_BPF, "embedded object is not for the BPF machine");
}

#[test]
fn embedded_object_has_the_program_map_and_license() {
    let elf = &ELF.0;
    for name in [CORE_PROGRAM_NAME, COUNTERS, TRUST, PEER, CONFIG, "Dual MIT/GPL"] {
        assert!(
            elf.windows(name.len()).any(|w| w == name.as_bytes()),
            "embedded object has no {name:?}"
        );
    }
}

fn tuple(protocol: Protocol, src: &str, dst: &str) -> FiveTuple {
    FiveTuple::new(protocol, src.parse().unwrap(), dst.parse().unwrap()).unwrap()
}

#[test]
fn keys_hold_the_packet_bytes_and_convert_back() {
    let t = tuple(Protocol::Tcp, "10.0.1.2:40000", "10.0.2.2:5001");
    let key = key_of(&t).unwrap();
    assert_eq!(key.saddr[0].to_ne_bytes(), [10, 0, 1, 2]);
    assert_eq!(key.sport.to_ne_bytes(), 40000u16.to_be_bytes());
    assert_eq!(key.proto, 6);
    assert_eq!(tuple_of(&key), Some(t));
    let v6 = tuple(Protocol::Udp, "[2001:db8::1]:53", "[2001:db8::2]:4000");
    assert_eq!(tuple_of(&key_of(&v6).unwrap()), Some(v6));
}

#[test]
fn only_tcp_and_udp_can_be_trusted() {
    let icmp = tuple(Protocol::Other(1), "10.0.1.2:0", "10.0.2.2:0");
    assert_eq!(
        key_of(&icmp).unwrap_err().to_string(),
        "only TCP and UDP connections can be trusted, not 1"
    );
}

#[test]
fn both_directions_are_listed_as_one_connection() {
    let t = tuple(Protocol::Udp, "10.0.1.2:5000", "10.0.2.2:6000");
    let key = key_of(&t).unwrap();
    let stats = |packets, direction| FlowStats {
        packets,
        direction,
        ..FlowStats::default()
    };
    let other = key_of(&tuple(Protocol::Tcp, "10.0.1.3:1", "10.0.2.2:2")).unwrap();
    let flows = pair_flows(vec![
        (key, stats(7, DIRECTION_ORIGINAL)),
        (other, stats(1, DIRECTION_ORIGINAL)),
        (key.reverse(), stats(3, DIRECTION_REPLY)),
    ]);
    assert_eq!(flows.len(), 2);
    let udp = flows.iter().find(|f| f.tuple.protocol() == Protocol::Udp).unwrap();
    assert_eq!((udp.tuple, udp.original.packets, udp.reply.packets), (t, 7, 3), "shown in the trusted direction");
}

fn numbered(i: u32) -> FiveTuple {
    let [_, _, a, b] = i.to_be_bytes();
    tuple(Protocol::Udp, &format!("10.1.{a}.{b}:4000"), "10.2.0.1:53")
}

#[test]
#[ignore = "needs CAP_BPF and CAP_NET_ADMIN"]
fn the_trust_map_holds_16384_connections_and_then_reports_full() {
    let mut core = CoreProgram::attach(&[], Mode::Bridge).unwrap();
    for i in 0..16384 {
        core.trust(&numbered(i)).unwrap();
    }
    let full = core.trust(&numbered(16384)).unwrap_err();
    assert!(matches!(full, TrustError::Bpf(BpfError::MapFull { .. })), "{full}");
    assert_eq!(full.to_string(), "map \"TRUST\" is full");
    assert_eq!(core.trusted().unwrap().len(), 16384, "a failed trust leaves no half entry behind");
    assert!(core.untrust(&numbered(0)).unwrap());
    core.trust(&numbered(16384)).unwrap();
}
