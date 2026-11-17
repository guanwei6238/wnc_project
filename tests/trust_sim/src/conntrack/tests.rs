use std::net::SocketAddr;

use super::*;
use crate::packet::SECOND;

fn lan() -> SocketAddr {
    "192.168.1.10:40000".parse().unwrap()
}

fn wan() -> SocketAddr {
    "203.0.113.5:443".parse().unwrap()
}

fn key(protocol: Protocol) -> Key {
    Key::new(protocol, lan(), wan())
}

#[test]
fn udp_without_reply_lasts_30_seconds() {
    let mut ct = Conntrack::default();
    let e = ct.update(key(Protocol::Udp), lan(), 0, 0);
    assert_eq!(e.timeout, 30 * SECOND);
    assert!(ct.get_mut(&key(Protocol::Udp), 29 * SECOND).is_some());
    assert!(ct.get_mut(&key(Protocol::Udp), 30 * SECOND).is_none());
}

#[test]
fn udp_reply_within_two_seconds_keeps_30_and_later_gets_120() {
    let mut ct = Conntrack::default();
    ct.update(key(Protocol::Udp), lan(), 0, 0);
    assert_eq!(ct.update(key(Protocol::Udp), wan(), 0, SECOND).timeout, 30 * SECOND);
    let e = ct.update(key(Protocol::Udp), lan(), 0, 3 * SECOND);
    assert_eq!(e.timeout, 120 * SECOND);
    assert_eq!(e.packets, [2, 1]);
}

#[test]
fn tcp_handshake_becomes_established() {
    let mut ct = Conntrack::default();
    let k = key(Protocol::Tcp);
    assert_eq!(ct.update(k, lan(), SYN, 0).phase, Phase::Opening);
    assert_eq!(ct.update(k, wan(), SYN | ACK, 1).phase, Phase::Opening);
    let e = ct.update(k, lan(), ACK, 2);
    assert_eq!(e.phase, Phase::Established);
    assert_eq!(e.timeout, 432_000 * SECOND);
}

#[test]
fn tcp_midstream_is_established() {
    let mut ct = Conntrack::default();
    assert_eq!(ct.update(key(Protocol::Tcp), wan(), ACK, 0).phase, Phase::Established);
}

#[test]
fn tcp_fin_and_rst_close() {
    let mut ct = Conntrack::default();
    let k = key(Protocol::Tcp);
    ct.update(k, lan(), ACK, 0);
    let e = ct.update(k, lan(), FIN | ACK, 1);
    assert_eq!((e.phase, e.timeout), (Phase::Closing, 120 * SECOND));
    let e = ct.update(k, wan(), RST, 2);
    assert_eq!((e.phase, e.timeout), (Phase::Closed, 10 * SECOND));
    assert_eq!(ct.update(k, wan(), FIN | ACK, 3).phase, Phase::Closed);
}

#[test]
fn pure_syn_replaces_a_closing_entry_but_not_an_established_one() {
    let mut ct = Conntrack::default();
    let k = key(Protocol::Tcp);
    let first = ct.update(k, lan(), ACK, 0).id;
    assert_eq!(ct.update(k, lan(), SYN, 1).id, first);
    ct.update(k, lan(), FIN | ACK, 2);
    let e = ct.update(k, lan(), SYN, 3);
    assert_ne!(e.id, first);
    assert_eq!(e.phase, Phase::Opening);
}

#[test]
fn expired_entry_is_replaced_and_purged() {
    let mut ct = Conntrack::default();
    let k = key(Protocol::Udp);
    let first = ct.update(k, lan(), 0, 0).id;
    assert!(ct.live(30 * SECOND).is_empty());
    assert!(ct.is_empty());
    assert_ne!(ct.update(k, lan(), 0, 40 * SECOND).id, first);
}
