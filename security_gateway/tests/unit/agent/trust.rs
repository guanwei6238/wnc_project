use std::net::SocketAddr;

use super::*;
use crate::kernel::conntrack::Counters;

const POLICY: TrustPolicy = TrustPolicy {
    min_packets: 10,
    min_age: Duration::from_secs(5),
    ttl: Duration::from_secs(60),
};

fn tuple(protocol: Protocol, src: &str, dst: &str) -> FiveTuple {
    FiveTuple::new(protocol, src.parse::<SocketAddr>().unwrap(), dst.parse::<SocketAddr>().unwrap()).unwrap()
}

fn tcp() -> FiveTuple {
    tuple(Protocol::Tcp, "10.0.1.2:40000", "10.0.2.2:5001")
}

fn conn(id: u32, original: FiveTuple, packets: (u64, u64), mark: u32) -> Connection {
    let reply = FiveTuple::new(original.protocol(), original.dst(), original.src()).unwrap();
    Connection {
        id,
        original,
        reply,
        tcp_state: (original.protocol() == Protocol::Tcp).then_some(TcpState::Established),
        timeout_s: Some(300),
        mark,
        original_counters: Some(Counters { packets: packets.0, bytes: packets.0 * 100 }),
        reply_counters: Some(Counters { packets: packets.1, bytes: packets.1 * 100 }),
    }
}

fn alert_on(t: &FiveTuple, sid: u64) -> Alert {
    Alert {
        flow_id: Some(42),
        protocol: "TCP".into(),
        src: Some(t.src().ip()),
        src_port: Some(t.src().port()),
        dst: Some(t.dst().ip()),
        dst_port: Some(t.dst().port()),
        signature_id: sid,
        signature: "test".into(),
        action: "allowed".into(),
    }
}

fn agent() -> TrustAgent {
    let mut agent = TrustAgent::new(POLICY);
    agent.set_inspecting(true);
    agent
}

fn after(start: Instant, secs: u64) -> Instant {
    start + Duration::from_secs(secs)
}

const TRUSTED: u32 = TRUSTED_MARK;

#[test]
fn trusts_after_enough_time_and_packets_each_way() {
    let mut a = agent();
    let t0 = Instant::now();
    assert_eq!(a.observe(&[conn(1, tcp(), (3, 2), 0)], t0), []);
    assert_eq!(a.observe(&[conn(1, tcp(), (30, 30), 0)], after(t0, 4)), [], "too early");
    assert_eq!(
        a.observe(&[conn(1, tcp(), (30, 30), 0)], after(t0, 5)),
        [Decision::Trust { tuple: tcp(), packets: (27, 28) }]
    );
}

#[test]
fn needs_packets_in_both_directions() {
    let mut a = agent();
    let t0 = Instant::now();
    a.observe(&[conn(1, tcp(), (0, 0), 0)], t0);
    assert_eq!(a.observe(&[conn(1, tcp(), (500, 9), 0)], after(t0, 10)), []);
    assert_eq!(a.observe(&[conn(1, tcp(), (500, 10), 0)], after(t0, 11)).len(), 1);
}

#[test]
fn tcp_must_be_established_but_udp_needs_no_state() {
    let mut a = agent();
    let t0 = Instant::now();
    let mut half_open = conn(1, tcp(), (0, 0), 0);
    half_open.tcp_state = Some(TcpState::SynSent);
    let udp = tuple(Protocol::Udp, "10.0.1.2:5353", "10.0.2.2:53");
    a.observe(&[half_open.clone(), conn(2, udp, (0, 0), 0)], t0);
    half_open.original_counters = Some(Counters { packets: 50, bytes: 0 });
    half_open.reply_counters = Some(Counters { packets: 50, bytes: 0 });
    let decisions = a.observe(&[half_open, conn(2, udp, (50, 50), 0)], after(t0, 10));
    assert_eq!(decisions, [Decision::Trust { tuple: udp, packets: (50, 50) }]);
}

#[test]
fn ignores_protocols_without_ports() {
    let mut a = agent();
    let t0 = Instant::now();
    let icmp = tuple(Protocol::Other(1), "10.0.1.2:0", "10.0.2.2:0");
    a.observe(&[conn(1, icmp, (0, 0), 0)], t0);
    assert_eq!(a.observe(&[conn(1, icmp, (99, 99), 0)], after(t0, 10)), []);
}

#[test]
fn connections_without_counters_are_never_trusted() {
    let mut a = agent();
    let t0 = Instant::now();
    let mut c = conn(1, tcp(), (0, 0), 0);
    c.original_counters = None;
    c.reply_counters = None;
    a.observe(std::slice::from_ref(&c), t0);
    assert_eq!(a.observe(&[c], after(t0, 60)), []);
}

#[test]
fn watching_starts_over_when_inspection_resumes() {
    let mut a = TrustAgent::new(POLICY);
    let t0 = Instant::now();
    assert_eq!(a.observe(&[conn(1, tcp(), (100, 100), 0)], t0), [], "suricata is not inspecting yet");
    assert_eq!(a.observe(&[conn(1, tcp(), (200, 200), 0)], after(t0, 10)), []);
    a.set_inspecting(true);
    a.observe(&[conn(1, tcp(), (205, 205), 0)], after(t0, 11));
    assert_eq!(a.observe(&[conn(1, tcp(), (209, 209), 0)], after(t0, 20)), [], "packets seen before inspection do not count");
    assert_eq!(
        a.observe(&[conn(1, tcp(), (215, 216), 0)], after(t0, 21)),
        [Decision::Trust { tuple: tcp(), packets: (15, 16) }]
    );
}

#[test]
fn a_stop_of_suricata_forgets_what_was_watched() {
    let mut a = agent();
    let t0 = Instant::now();
    a.observe(&[conn(1, tcp(), (0, 0), 0)], t0);
    a.set_inspecting(false);
    a.set_inspecting(true);
    a.observe(&[conn(1, tcp(), (50, 50), 0)], after(t0, 10));
    assert_eq!(a.observe(&[conn(1, tcp(), (60, 60), 0)], after(t0, 11)), [], "watching restarted at 10 s");
}

#[test]
fn an_alert_while_watching_means_never_trusted() {
    let mut a = agent();
    let t0 = Instant::now();
    a.observe(&[conn(1, tcp(), (0, 0), 0)], t0);
    assert_eq!(a.alert(&alert_on(&tcp(), 7), after(t0, 1)), None);
    assert_eq!(a.observe(&[conn(1, tcp(), (99, 99), 0)], after(t0, 30)), []);
}

#[test]
fn an_alert_from_the_other_direction_counts_too() {
    let mut a = agent();
    let t0 = Instant::now();
    a.observe(&[conn(1, tcp(), (0, 0), 0)], t0);
    let reverse = FiveTuple::new(Protocol::Tcp, tcp().dst(), tcp().src()).unwrap();
    a.alert(&alert_on(&reverse, 7), after(t0, 1));
    assert_eq!(a.observe(&[conn(1, tcp(), (99, 99), 0)], after(t0, 30)), []);
}

#[test]
fn an_alert_before_the_connection_is_seen_still_counts() {
    let mut a = agent();
    let t0 = Instant::now();
    a.alert(&alert_on(&tcp(), 7), t0);
    a.observe(&[conn(1, tcp(), (0, 0), 0)], after(t0, 1));
    assert_eq!(a.observe(&[conn(1, tcp(), (99, 99), 0)], after(t0, 30)), []);
}

#[test]
fn an_alert_on_a_trusted_connection_revokes_it() {
    let mut a = agent();
    let t0 = Instant::now();
    a.observe(&[conn(1, tcp(), (0, 0), 0)], t0);
    a.observe(&[conn(1, tcp(), (20, 20), 0)], after(t0, 5));
    assert_eq!(
        a.alert(&alert_on(&tcp(), 2001), after(t0, 6)),
        Some(Decision::Revoke {
            tuple: tcp(),
            sid: 2001,
            signature: "test".into(),
            flow_id: Some(42),
        })
    );
    assert_eq!(a.observe(&[conn(1, tcp(), (99, 99), 0)], after(t0, 100)), [], "never trusted again");
}

#[test]
fn trust_expires_after_the_ttl_and_the_connection_is_watched_again() {
    let mut a = agent();
    let t0 = Instant::now();
    a.observe(&[conn(1, tcp(), (0, 0), 0)], t0);
    a.observe(&[conn(1, tcp(), (20, 20), 0)], after(t0, 5));
    assert_eq!(a.observe(&[conn(1, tcp(), (20, 20), TRUSTED)], after(t0, 64)), []);
    assert_eq!(
        a.observe(&[conn(1, tcp(), (20, 20), TRUSTED)], after(t0, 65)),
        [Decision::Expire { tuple: tcp() }]
    );
    assert_eq!(a.observe(&[conn(1, tcp(), (25, 25), 0)], after(t0, 70)), [], "needs new packets");
    assert_eq!(a.observe(&[conn(1, tcp(), (30, 30), 0)], after(t0, 71)).len(), 1);
}

#[test]
fn a_cleared_trust_bit_means_watching_again() {
    let mut a = agent();
    let t0 = Instant::now();
    a.observe(&[conn(1, tcp(), (0, 0), 0)], t0);
    a.observe(&[conn(1, tcp(), (20, 20), 0)], after(t0, 5));
    a.observe(&[conn(1, tcp(), (20, 20), TRUSTED)], after(t0, 6));
    assert_eq!(a.observe(&[conn(1, tcp(), (21, 21), 0)], after(t0, 7)), [], "a bare syn cleared the bit");
    assert_eq!(a.observe(&[conn(1, tcp(), (31, 31), 0)], after(t0, 12)).len(), 1);
}

#[test]
fn a_new_connection_with_the_same_tuple_starts_over() {
    let mut a = agent();
    let t0 = Instant::now();
    a.observe(&[conn(1, tcp(), (0, 0), 0)], t0);
    a.alert(&alert_on(&tcp(), 7), after(t0, 1));
    a.observe(&[conn(2, tcp(), (0, 0), 0)], after(t0, 700));
    assert_eq!(
        a.observe(&[conn(2, tcp(), (10, 10), 0)], after(t0, 705)).len(),
        1,
        "the old alert is forgotten after 10 minutes and the new entry is watched from the start"
    );
}

#[test]
fn ended_connections_are_forgotten() {
    let mut a = agent();
    let t0 = Instant::now();
    a.observe(&[conn(1, tcp(), (0, 0), 0)], t0);
    a.observe(&[], after(t0, 1));
    assert!(a.tracked.is_empty());
}

#[test]
fn a_manually_trusted_connection_is_left_alone() {
    let mut a = agent();
    let t0 = Instant::now();
    a.observe(&[conn(1, tcp(), (0, 0), TRUSTED)], t0);
    assert_eq!(a.observe(&[conn(1, tcp(), (99, 99), TRUSTED)], after(t0, 3_600)), []);
}

#[derive(Default)]
struct FakePrivd {
    connections: Vec<Connection>,
    trusted: Vec<FiveTuple>,
    untrusted: Vec<FiveTuple>,
    fail_reads: bool,
}

impl Privd for FakePrivd {
    fn forwarded_connections(&mut self) -> Result<Vec<Connection>, ConntrackError> {
        if self.fail_reads {
            return Err(ConntrackError::NoReply);
        }
        Ok(self.connections.clone())
    }

    fn trust(&mut self, tuple: &FiveTuple) -> Result<(), ConntrackError> {
        self.trusted.push(*tuple);
        let c = self.connections.iter_mut().find(|c| c.original == *tuple).ok_or(ConntrackError::NotFound)?;
        c.mark |= TRUSTED_MARK;
        Ok(())
    }

    fn untrust(&mut self, tuple: &FiveTuple) -> Result<(), ConntrackError> {
        self.untrusted.push(*tuple);
        let c = self.connections.iter_mut().find(|c| c.original == *tuple).ok_or(ConntrackError::NotFound)?;
        c.mark &= !TRUSTED_MARK;
        Ok(())
    }
}

#[test]
fn check_writes_trust_and_revokes_on_alerts() {
    let mut a = agent();
    let mut privd = FakePrivd {
        connections: vec![conn(1, tcp(), (0, 0), 0)],
        ..FakePrivd::default()
    };
    let t0 = Instant::now();
    a.check(&mut privd, t0);
    privd.connections[0] = conn(1, tcp(), (20, 20), 0);
    a.check(&mut privd, after(t0, 5));
    assert_eq!(privd.trusted, [tcp()]);
    assert_ne!(privd.connections[0].mark & TRUSTED_MARK, 0);
    a.on_alert(&alert_on(&tcp(), 9), &mut privd, after(t0, 6));
    assert_eq!(privd.untrusted, [tcp()]);
    assert_eq!(privd.connections[0].mark & TRUSTED_MARK, 0);
}

#[test]
fn check_survives_a_failed_read() {
    let mut a = agent();
    let mut privd = FakePrivd {
        fail_reads: true,
        ..FakePrivd::default()
    };
    a.check(&mut privd, Instant::now());
    privd.fail_reads = false;
    a.check(&mut privd, Instant::now());
    assert!(!a.failing);
}
