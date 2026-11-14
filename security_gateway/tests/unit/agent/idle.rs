use gw_common::FlowStats;

use super::*;

fn flow(protocol: Protocol, packets: u64) -> TrustedFlow {
    let tuple = FiveTuple::new(protocol, "10.0.1.2:40000".parse().unwrap(), "10.0.2.2:5001".parse().unwrap()).unwrap();
    let stats = |packets| FlowStats {
        packets,
        ..FlowStats::default()
    };
    TrustedFlow {
        tuple,
        original: stats(packets),
        reply: stats(0),
    }
}

fn after(start: Instant, secs: u64) -> Instant {
    start + Duration::from_secs(secs)
}

#[test]
fn a_connection_that_keeps_sending_stays_trusted() {
    let mut sweep = IdleSweep::default();
    let t0 = Instant::now();
    for (i, secs) in [0, 100, 200, 700].into_iter().enumerate() {
        assert_eq!(sweep.observe(&[flow(Protocol::Tcp, i as u64)], after(t0, secs)), []);
    }
}

#[test]
fn udp_ends_after_two_minutes_without_packets_and_tcp_after_ten() {
    let mut sweep = IdleSweep::default();
    let t0 = Instant::now();
    let udp = flow(Protocol::Udp, 5);
    assert_eq!(sweep.observe(&[udp], t0), []);
    assert_eq!(sweep.observe(&[udp], after(t0, 119)), []);
    assert_eq!(sweep.observe(&[udp], after(t0, 120)), [udp.tuple]);
    let tcp = flow(Protocol::Tcp, 5);
    assert_eq!(sweep.observe(&[tcp], t0), []);
    assert_eq!(sweep.observe(&[tcp], after(t0, 599)), []);
    assert_eq!(sweep.observe(&[tcp], after(t0, 600)), [tcp.tuple]);
}

#[test]
fn new_packets_restart_the_clock() {
    let mut sweep = IdleSweep::default();
    let t0 = Instant::now();
    sweep.observe(&[flow(Protocol::Udp, 1)], t0);
    sweep.observe(&[flow(Protocol::Udp, 2)], after(t0, 100));
    assert_eq!(sweep.observe(&[flow(Protocol::Udp, 2)], after(t0, 219)), [], "idle since 100 s");
    assert_eq!(sweep.observe(&[flow(Protocol::Udp, 2)], after(t0, 220)).len(), 1);
}

#[test]
fn connections_no_longer_in_the_map_are_forgotten() {
    let mut sweep = IdleSweep::default();
    let t0 = Instant::now();
    sweep.observe(&[flow(Protocol::Udp, 1)], t0);
    sweep.observe(&[], after(t0, 10));
    assert!(sweep.last.is_empty());
    assert_eq!(sweep.observe(&[flow(Protocol::Udp, 1)], after(t0, 200)), [], "trusted again: the clock starts over");
}
