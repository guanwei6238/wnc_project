use std::net::SocketAddr;

use super::*;
use crate::packet::{Protocol, SECOND};

const MS: u64 = 1_000_000;
const BOTH: [Variant; 2] = [Variant::CtMark, Variant::Tc];

fn lan() -> SocketAddr {
    "192.168.1.10:40000".parse().unwrap()
}

fn wan() -> SocketAddr {
    "203.0.113.5:443".parse().unwrap()
}

fn packet(ms: u64, protocol: Protocol, from_lan: bool, flags: u8) -> Packet {
    let (src, dst) = if from_lan { (lan(), wan()) } else { (wan(), lan()) };
    Packet {
        ts: ms * MS,
        len: 100,
        kind: Kind::Flow {
            protocol,
            src,
            dst,
            flags,
        },
    }
}

fn exchange(sim: &mut Sim, protocol: Protocol, from_ms: u64, to_ms: u64) -> u64 {
    let flags = if protocol == Protocol::Tcp { ACK } else { 0 };
    (from_ms..to_ms)
        .step_by(100)
        .map(|ms| sim.packet(&packet(ms, protocol, ms / 100 % 2 == 0, flags), &[]))
        .filter(|&fast| fast)
        .count() as u64
}

fn alert(sid: u64) -> Alert {
    Alert {
        key: Some(Key::new(Protocol::Tcp, lan(), wan())),
        sid,
    }
}

#[test]
fn udp_is_trusted_at_the_second_check_after_it_is_seen() {
    for variant in BOTH {
        let mut sim = Sim::new(variant, Policy::default());
        assert_eq!(exchange(&mut sim, Protocol::Udp, 0, 30_000), 200, "{variant:?}");
        let stats = sim.finish();
        assert_eq!((stats.packets, stats.fast_packets, stats.trusted), (300, 200, 1), "{variant:?}");
    }
}

#[test]
fn tcp_control_packets_are_inspected_and_pure_syn_ends_trust() {
    for variant in BOTH {
        let mut sim = Sim::new(variant, Policy::default());
        sim.packet(&packet(0, Protocol::Tcp, true, SYN), &[]);
        sim.packet(&packet(1, Protocol::Tcp, false, SYN | ACK), &[]);
        assert_eq!(exchange(&mut sim, Protocol::Tcp, 2, 30_002), 200, "{variant:?}");
        assert!(!sim.packet(&packet(30_100, Protocol::Tcp, true, FIN | ACK), &[]));
        assert!(!sim.packet(&packet(30_200, Protocol::Tcp, true, SYN), &[]));
        sim.packet(&packet(30_201, Protocol::Tcp, false, SYN | ACK), &[]);
        assert_eq!(exchange(&mut sim, Protocol::Tcp, 30_300, 60_000), 0, "{variant:?}");
    }
}

#[test]
fn alert_before_trust_refuses() {
    for variant in BOTH {
        let mut sim = Sim::new(variant, Policy::default());
        sim.packet(&packet(0, Protocol::Tcp, true, ACK), &[alert(1)]);
        assert_eq!(exchange(&mut sim, Protocol::Tcp, 100, 30_000), 0, "{variant:?}");
        let stats = sim.finish();
        assert_eq!((stats.trusted, stats.alerts_seen, stats.refused), (0, 1, 1), "{variant:?}");
    }
}

#[test]
fn alert_on_a_fast_packet_is_missed() {
    for variant in BOTH {
        let mut sim = Sim::new(variant, Policy::default());
        exchange(&mut sim, Protocol::Tcp, 0, 20_000);
        assert!(sim.packet(&packet(20_000, Protocol::Tcp, true, ACK), &[alert(7)]));
        assert_eq!(exchange(&mut sim, Protocol::Tcp, 20_100, 30_000), 99, "{variant:?}");
        let stats = sim.finish();
        assert_eq!((stats.alerts_missed, stats.revoked), (1, 0), "{variant:?}");
        assert_eq!(stats.missed_sids.get(&7), Some(&1));
    }
}

#[test]
fn alert_on_an_inspected_packet_revokes() {
    for variant in BOTH {
        let mut sim = Sim::new(variant, Policy::default());
        exchange(&mut sim, Protocol::Tcp, 0, 20_000);
        assert!(!sim.packet(&packet(20_000, Protocol::Tcp, true, FIN | ACK), &[alert(7)]));
        assert_eq!(exchange(&mut sim, Protocol::Tcp, 20_100, 30_000), 0, "{variant:?}");
        assert_eq!(sim.finish().revoked, 1, "{variant:?}");
    }
}

#[test]
fn ttl_expiry_inspects_until_trusted_again() {
    let policy = Policy {
        ttl: 20 * SECOND,
        ..Policy::default()
    };
    for variant in BOTH {
        let mut sim = Sim::new(variant, policy);
        assert_eq!(exchange(&mut sim, Protocol::Udp, 0, 60_000), 400, "{variant:?}");
        let stats = sim.finish();
        assert_eq!((stats.trusted, stats.expired), (2, 2), "{variant:?}");
    }
}

#[test]
fn quiet_udp_is_not_trusted_again_until_ttl() {
    for variant in BOTH {
        let mut sim = Sim::new(variant, Policy::default());
        exchange(&mut sim, Protocol::Udp, 0, 20_000);
        assert_eq!(exchange(&mut sim, Protocol::Udp, 200_000, 230_000), 0, "{variant:?}");
        let stats = sim.finish();
        assert_eq!(stats.idle_ended, u64::from(variant == Variant::Tc), "{variant:?}");
    }
}

#[test]
fn idle_tcp_ends_trust_only_in_tc() {
    for (variant, fast) in [(Variant::CtMark, true), (Variant::Tc, false)] {
        let mut sim = Sim::new(variant, Policy::default());
        exchange(&mut sim, Protocol::Tcp, 0, 20_000);
        assert_eq!(sim.packet(&packet(720_000, Protocol::Tcp, true, ACK), &[]), fast, "{variant:?}");
    }
}

#[test]
fn tcp_that_sends_again_after_an_idle_clear_is_counted_by_service_port() {
    let mut sim = Sim::new(Variant::Tc, Policy::default());
    exchange(&mut sim, Protocol::Tcp, 0, 20_000);
    exchange(&mut sim, Protocol::Tcp, 700_000, 701_000);
    sim.packet(&packet(701_000, Protocol::Tcp, true, FIN | ACK), &[]);
    let stats = sim.finish();
    assert_eq!((stats.idle_ended, stats.idle_resumed, stats.idle_resumed_packets), (1, 1, 10));
    assert_eq!(stats.idle_resumed_ports.into_iter().collect::<Vec<_>>(), vec![(443, (1, 10))]);
}

#[test]
fn trusted_again_or_reused_ports_are_no_longer_counted() {
    let mut sim = Sim::new(Variant::Tc, Policy::default());
    exchange(&mut sim, Protocol::Tcp, 0, 20_000);
    sim.packet(&packet(700_000, Protocol::Tcp, true, SYN), &[]);
    exchange(&mut sim, Protocol::Tcp, 700_100, 701_000);
    assert_eq!(sim.finish().idle_resumed, 0, "a pure syn starts another connection");
    let mut sim = Sim::new(Variant::Tc, Policy::default());
    exchange(&mut sim, Protocol::Tcp, 0, 20_000);
    exchange(&mut sim, Protocol::Tcp, 700_000, 1_700_000);
    let stats = sim.finish();
    assert_eq!(stats.trusted, 2);
    assert!(stats.idle_resumed_packets < 10_000 - 5, "counting stops once it is trusted again");
}

#[test]
fn other_packets_are_always_inspected() {
    for variant in BOTH {
        let mut sim = Sim::new(variant, Policy::default());
        exchange(&mut sim, Protocol::Udp, 0, 20_000);
        let other = Packet {
            ts: 20_000 * MS,
            len: 60,
            kind: Kind::Other,
        };
        assert!(!sim.packet(&other, &[]));
    }
}

#[test]
fn skipping_quiet_checks_changes_nothing() {
    let mut seed = 7u64;
    let mut next = move |n: u64| {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (seed >> 33) % n
    };
    let gaps = [0, 3 * 86_400_000, 2_000_000, 600_000, 5 * 86_400_000, 40_000];
    let mut packets = Vec::new();
    let mut ms = 1_000_000;
    for gap in gaps {
        ms += gap;
        for _ in 0..3_000 {
            ms += next(400);
            let port = 40_000 + next(6) as u16;
            let protocol = if port.is_multiple_of(2) { Protocol::Tcp } else { Protocol::Udp };
            let flags = match (protocol, next(50)) {
                (Protocol::Udp, _) => 0,
                (_, 0) => SYN,
                (_, 1) => FIN | ACK,
                _ => ACK,
            };
            let lan: SocketAddr = format!("192.168.1.10:{port}").parse().unwrap();
            let (src, dst) = if next(2) == 0 { (lan, wan()) } else { (wan(), lan) };
            let back = if next(500) == 0 { 30_000 } else { 0 };
            let alert = (next(400) == 0).then(|| Alert {
                key: Some(Key::new(protocol, src, dst)),
                sid: 1,
            });
            packets.push((Packet { ts: (ms - back) * MS, len: 100, kind: Kind::Flow { protocol, src, dst, flags } }, alert));
        }
    }
    for variant in BOTH {
        let run = |quiet: Option<u64>| {
            let mut sim = Sim::new(variant, Policy::default());
            if let Some(quiet) = quiet {
                sim.quiet = quiet;
            }
            for (p, alert) in &packets {
                sim.packet(p, alert.as_slice());
            }
            sim.finish()
        };
        let skipped = run(None);
        assert!(skipped.trusted > 0 && skipped.expired > 0, "{variant:?}: {skipped:?}");
        assert_eq!(skipped, run(Some(u64::MAX)), "{variant:?}");
    }
}
