use super::*;

use netlink_packet_core::{DefaultNla, NLM_F_MULTIPART, NetlinkHeader, NetlinkMessage, NetlinkPayload};
use netlink_packet_netfilter::conntrack::{
    ConntrackAttribute as A, ConntrackMessage, IPTuple, ProtoInfo, ProtoInfoTCP, ProtoTuple, Protocol as P, Tuple,
};
use netlink_packet_netfilter::{NetfilterHeader, NetfilterMessage, NetfilterProtoFamily};

fn v4() -> FiveTuple {
    FiveTuple::new(Protocol::Tcp, "10.0.1.2:40000".parse().unwrap(), "10.0.2.2:5001".parse().unwrap()).unwrap()
}

fn v6() -> FiveTuple {
    FiveTuple::new(Protocol::Udp, "[2001:db8::1]:5353".parse().unwrap(), "[2001:db8::2]:53".parse().unwrap()).unwrap()
}

fn reversed(t: &FiveTuple) -> FiveTuple {
    FiveTuple::new(t.protocol(), t.dst(), t.src()).unwrap()
}

fn reference_family(t: &FiveTuple) -> NetfilterProtoFamily {
    if t.src().is_ipv4() { NetfilterProtoFamily::IPv4 } else { NetfilterProtoFamily::IPv6 }
}

fn reference_tuple(t: &FiveTuple) -> Vec<Tuple> {
    vec![
        Tuple::Ip(vec![IPTuple::SourceAddress(t.src().ip()), IPTuple::DestinationAddress(t.dst().ip())]),
        Tuple::Proto(vec![
            ProtoTuple::Protocol(P::from(t.protocol().number())),
            ProtoTuple::SourcePort(t.src().port()),
            ProtoTuple::DestinationPort(t.dst().port()),
        ]),
    ]
}

fn reference(family: NetfilterProtoFamily, flags: u16, seq: u32, msg: ConntrackMessage) -> Vec<u8> {
    let mut header = NetlinkHeader::default();
    header.flags = flags;
    header.sequence_number = seq;
    let nf = NetfilterMessage::new(NetfilterHeader::new(family, 0, 0), msg);
    let mut m = NetlinkMessage::new(header, NetlinkPayload::from(nf));
    m.finalize();
    let mut buf = vec![0; m.buffer_len()];
    m.serialize(&mut buf);
    buf
}

fn mark_mask(mask: u32) -> A {
    A::Other(DefaultNla::new(CTA_MARK_MASK, mask.to_be_bytes().to_vec()))
}

fn kernel_reply(seq: u32, c: &Connection) -> Vec<u8> {
    reference(
        reference_family(&c.original),
        NLM_F_MULTIPART,
        seq,
        ConntrackMessage::New(vec![
            A::CtaTupleOrig(reference_tuple(&c.original)),
            A::CtaTupleReply(reference_tuple(&c.reply)),
            A::Other(DefaultNla::new(3, 0x18e_u32.to_be_bytes().to_vec())),
            A::CtaProtoInfo(vec![ProtoInfo::TCP(vec![ProtoInfoTCP::State(3), ProtoInfoTCP::OriginalWindowScale(7)])]),
            A::CtaTimeout(c.timeout_s.unwrap()),
            A::CtaMark(c.mark),
            A::Other(DefaultNla::new(CTA_ID, c.id.to_be_bytes().to_vec())),
            A::Other(DefaultNla::new(18, 1_u32.to_be_bytes().to_vec())),
        ]),
    )
}

fn raw(kind: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(16 + payload.len() as u32).to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(&0u16.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(payload);
    buf
}

fn error(seq: u32, code: i32) -> Vec<u8> {
    let mut payload = code.to_ne_bytes().to_vec();
    payload.extend_from_slice(&[0; 16]);
    raw(NLMSG_ERROR, seq, &payload)
}

fn done(seq: u32) -> Vec<u8> {
    raw(NLMSG_DONE, seq, &0i32.to_ne_bytes())
}

fn connection(original: FiveTuple) -> Connection {
    Connection {
        id: 0xdead_beef,
        original,
        reply: reversed(&original),
        tcp_state: Some(TcpState::Established),
        timeout_s: Some(431_999),
        mark: 0x8000_1234,
    }
}

#[test]
fn set_mark_request_matches_reference_encoding() {
    for t in [v4(), v6()] {
        assert_eq!(
            set_mark_request(7, &t, 0x8000_0000, 0x8000_0000),
            reference(
                reference_family(&t),
                NLM_F_REQUEST | NLM_F_ACK,
                7,
                ConntrackMessage::New(vec![
                    A::CtaTupleOrig(reference_tuple(&t)),
                    A::CtaMark(0x8000_0000),
                    mark_mask(0x8000_0000),
                ]),
            )
        );
    }
}

#[test]
fn set_mark_never_sends_bits_outside_the_mask() {
    // kernel 算 (old & ~mask) ^ mark：mask 外的位元若送出去會被翻轉
    let t = v4();
    assert_eq!(set_mark_request(1, &t, 0xffff_ffff, 0x8000_0000), set_mark_request(1, &t, 0x8000_0000, 0x8000_0000));
    assert_eq!(set_mark_request(1, &t, 0x7fff_ffff, 0x8000_0000), set_mark_request(1, &t, 0, 0x8000_0000));
}

#[test]
fn get_request_matches_reference_encoding() {
    for t in [v4(), v6()] {
        assert_eq!(
            get_request(9, &t),
            reference(
                reference_family(&t),
                NLM_F_REQUEST,
                9,
                ConntrackMessage::Get(vec![A::CtaTupleOrig(reference_tuple(&t))])
            )
        );
    }
}

#[test]
fn list_request_covers_both_families_and_filters_by_mark() {
    assert_eq!(
        list_request(3, 0xffff_ffff, 0x8000_0000),
        reference(
            NetfilterProtoFamily::Unspec,
            NLM_F_REQUEST | NLM_F_DUMP,
            3,
            ConntrackMessage::Get(vec![A::CtaMark(0x8000_0000), mark_mask(0x8000_0000)]),
        )
    );
}

#[test]
fn parses_connections() {
    for t in [v4(), v6()] {
        let c = connection(t);
        assert_eq!(parse_replies(&kernel_reply(5, &c), 5).unwrap(), [Reply::Connection(c)]);
    }
}

#[test]
fn parses_several_messages_in_one_datagram() {
    let (a, b) = (connection(v4()), connection(v6()));
    let datagram = [kernel_reply(2, &a), kernel_reply(2, &b), done(2)].concat();
    assert_eq!(
        parse_replies(&datagram, 2).unwrap(),
        [Reply::Connection(a), Reply::Connection(b), Reply::Done]
    );
}

#[test]
fn skips_replies_to_other_requests() {
    let datagram = [kernel_reply(1, &connection(v4())), error(1, -libc::ENOENT), error(2, 0)].concat();
    assert_eq!(parse_replies(&datagram, 2).unwrap(), [Reply::Ack]);
}

#[test]
fn maps_kernel_errors() {
    assert!(matches!(parse_replies(&error(1, -libc::ENOENT), 1), Err(ConntrackError::NotFound)));
    assert!(matches!(parse_replies(&error(1, -libc::EPERM), 1), Err(ConntrackError::PermissionDenied)));
    assert!(matches!(
        parse_replies(&error(1, -libc::EINVAL), 1),
        Err(ConntrackError::Kernel(e)) if e.raw_os_error() == Some(libc::EINVAL)
    ));
}

#[test]
fn rejects_truncated_replies() {
    let reply = kernel_reply(1, &connection(v4()));
    assert!(matches!(parse_replies(&reply[..reply.len() - 8], 1), Err(ConntrackError::Malformed(_))));
    assert!(matches!(parse_replies(&reply[..10], 1), Err(ConntrackError::Malformed(_))));
}

#[test]
fn connection_without_id_is_malformed() {
    let t = v4();
    let reply = reference(
        NetfilterProtoFamily::IPv4,
        0,
        1,
        ConntrackMessage::New(vec![
            A::CtaTupleOrig(reference_tuple(&t)),
            A::CtaTupleReply(reference_tuple(&reversed(&t))),
        ]),
    );
    match parse_replies(&reply, 1) {
        Err(ConntrackError::Malformed(m)) => assert_eq!(m, "connection has no id"),
        other => panic!("expected malformed, got {other:?}"),
    }
}

#[test]
fn missing_mark_means_zero() {
    let t = v4();
    let reply = reference(
        NetfilterProtoFamily::IPv4,
        0,
        1,
        ConntrackMessage::New(vec![
            A::CtaTupleOrig(reference_tuple(&t)),
            A::CtaTupleReply(reference_tuple(&reversed(&t))),
            A::Other(DefaultNla::new(CTA_ID, 7_u32.to_be_bytes().to_vec())),
        ]),
    );
    let Ok([Reply::Connection(c)]) = <[Reply; 1]>::try_from(parse_replies(&reply, 1).unwrap()) else {
        panic!("expected one connection");
    };
    assert_eq!((c.mark, c.tcp_state, c.timeout_s), (0, None, None));
}

#[test]
fn protocol_round_trips() {
    for p in [Protocol::Tcp, Protocol::Udp, Protocol::Other(132)] {
        assert_eq!(p.to_string().parse::<Protocol>(), Ok(p));
    }
    assert_eq!("6".parse::<Protocol>(), Ok(Protocol::Tcp));
}

#[test]
fn rejects_unknown_protocols() {
    for s in ["", "TCP", "icmp", "256", "-1", "+6"] {
        assert_eq!(
            s.parse::<Protocol>().unwrap_err().to_string(),
            format!("invalid protocol {s:?} (expected \"tcp\", \"udp\" or a protocol number)")
        );
    }
}

#[test]
fn five_tuple_rejects_mixed_families() {
    let e = FiveTuple::new(Protocol::Tcp, "10.0.1.2:1".parse().unwrap(), "[2001:db8::2]:2".parse().unwrap()).unwrap_err();
    assert_eq!(e.to_string(), "source 10.0.1.2 and destination 2001:db8::2 are not the same IP version");
}

#[test]
fn five_tuple_display() {
    assert_eq!(v4().to_string(), "tcp 10.0.1.2:40000 -> 10.0.2.2:5001");
    assert_eq!(v6().to_string(), "udp [2001:db8::1]:5353 -> [2001:db8::2]:53");
}

#[test]
fn tcp_state_names() {
    assert_eq!(TcpState::from(3).to_string(), "ESTABLISHED");
    assert_eq!(TcpState::from(7).to_string(), "TIME_WAIT");
    assert_eq!(TcpState::from(42).to_string(), "UNKNOWN(42)");
}

#[test]
fn batch_asks_for_an_ack_only_on_the_last_request() {
    let tuples = [v4(), v6(), reversed(&v4())];
    let expected: Vec<u8> = tuples
        .iter()
        .enumerate()
        .flat_map(|(i, t)| {
            let ack = if i == 2 { NLM_F_ACK } else { 0 };
            reference(
                reference_family(t),
                NLM_F_REQUEST | ack,
                10 + i as u32,
                ConntrackMessage::New(vec![
                    A::CtaTupleOrig(reference_tuple(t)),
                    A::CtaMark(0),
                    mark_mask(0x8000_0000),
                ]),
            )
        })
        .collect();
    assert_eq!(set_marks_request(10, &tuples, 0, 0x8000_0000), expected);
}

#[test]
fn batch_replies_report_each_failure_and_when_the_batch_is_done() {
    let datagram = [error(11, -libc::ENOENT), error(99, -libc::EINVAL), error(12, -libc::EINVAL)].concat();
    let (failed, done) = parse_batch_replies(&datagram, 10, 14).unwrap();
    assert!(matches!(failed.as_slice(), [(11, ConntrackError::NotFound), (12, ConntrackError::Kernel(_))]));
    assert!(!done);

    let (failed, done) = parse_batch_replies(&error(14, 0), 10, 14).unwrap();
    assert!(failed.is_empty() && done);

    let (failed, done) = parse_batch_replies(&error(14, -libc::ENOENT), 10, 14).unwrap();
    assert!(matches!(failed.as_slice(), [(14, ConntrackError::NotFound)]) && done);
}

#[test]
fn batch_seq_range_survives_wrapping() {
    let (failed, done) = parse_batch_replies(&[error(u32::MAX, -libc::ENOENT), error(1, 0)].concat(), u32::MAX - 1, 1).unwrap();
    assert!(matches!(failed.as_slice(), [(u32::MAX, ConntrackError::NotFound)]) && done);
}

fn stats_reply(kind: u16, seq: u32, cpu: u16, attrs: &[(u16, u32)]) -> Vec<u8> {
    let mut payload = vec![AF_UNSPEC, 0];
    payload.extend_from_slice(&cpu.to_be_bytes());
    for (kind, value) in attrs {
        payload.extend_from_slice(&8u16.to_ne_bytes());
        payload.extend_from_slice(&kind.to_ne_bytes());
        payload.extend_from_slice(&value.to_be_bytes());
    }
    raw(kind, seq, &payload)
}

#[test]
fn stats_requests_are_bare_headers() {
    let header = |kind: u16, flags: u16| {
        let mut buf = raw(kind, 9, &[AF_UNSPEC, 0, 0, 0]);
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        buf
    };
    assert_eq!(stats_request(9), header(0x105, NLM_F_REQUEST));
    assert_eq!(cpu_stats_request(9), header(0x104, NLM_F_REQUEST | NLM_F_DUMP));
}

#[test]
fn parses_global_stats() {
    let reply = stats_reply(MSG_GET_STATS, 4, 0, &[(CTA_STATS_GLOBAL_ENTRIES, 812), (CTA_STATS_GLOBAL_MAX_ENTRIES, 65_536)]);
    assert_eq!(parse_replies(&reply, 4).unwrap(), [Reply::Global { entries: 812, max: 65_536 }]);
}

#[test]
fn global_stats_without_maximum_are_malformed() {
    let reply = stats_reply(MSG_GET_STATS, 4, 0, &[(CTA_STATS_GLOBAL_ENTRIES, 812)]);
    assert!(matches!(parse_replies(&reply, 4), Err(ConntrackError::Malformed(_))));
}

#[test]
fn parses_per_cpu_stats_and_ignores_other_counters() {
    let datagram = [
        stats_reply(MSG_GET_STATS_CPU, 6, 0, &[(4, 99), (CTA_STATS_INSERT_FAILED, 3), (CTA_STATS_DROP, 2), (CTA_STATS_EARLY_DROP, 1)]),
        stats_reply(MSG_GET_STATS_CPU, 6, 3, &[(CTA_STATS_DROP, 0xffff_fffe), (14, 7)]),
        done(6),
    ]
    .concat();
    assert_eq!(
        parse_replies(&datagram, 6).unwrap(),
        [
            Reply::Cpu(CpuStats { cpu: 0, drop: 2, early_drop: 1, insert_failed: 3 }),
            Reply::Cpu(CpuStats { cpu: 3, drop: 0xffff_fffe, ..CpuStats::default() }),
            Reply::Done,
        ]
    );
}

#[test]
fn rejects_truncated_cpu_stats() {
    assert!(matches!(parse_replies(&raw(MSG_GET_STATS_CPU, 1, &[0, 0]), 1), Err(ConntrackError::Malformed(_))));
}
