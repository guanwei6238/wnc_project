use super::*;

fn key() -> Key {
    Key::new(
        Protocol::Udp,
        "192.168.1.10:40000".parse().unwrap(),
        "203.0.113.5:53".parse().unwrap(),
    )
}

fn live(id: u64, packets: [u64; 2], established: bool) -> Live {
    Live {
        key: key(),
        id,
        packets,
        established,
    }
}

#[test]
fn counts_from_the_first_sighting() {
    let mut agent = Agent::new(Policy::default());
    assert!(agent.observe(&[live(1, [50, 50], true)], 0).is_empty());
    assert!(agent.observe(&[live(1, [59, 70], true)], 5 * SECOND).is_empty());
    assert_eq!(agent.observe(&[live(1, [60, 60], true)], 10 * SECOND), [Decision::Trust(key())]);
}

#[test]
fn needs_min_age() {
    let mut agent = Agent::new(Policy::default());
    agent.observe(&[live(1, [0, 0], true)], 0);
    assert!(agent.observe(&[live(1, [100, 100], true)], 4 * SECOND).is_empty());
    assert_eq!(agent.observe(&[live(1, [100, 100], true)], 5 * SECOND), [Decision::Trust(key())]);
}

#[test]
fn unestablished_is_not_trusted() {
    let mut agent = Agent::new(Policy::default());
    agent.observe(&[live(1, [0, 0], false)], 0);
    assert!(agent.observe(&[live(1, [100, 100], false)], 10 * SECOND).is_empty());
}

#[test]
fn alert_before_watching_refuses() {
    let mut agent = Agent::new(Policy::default());
    assert_eq!(agent.alert(Some(key()), 0), None);
    agent.observe(&[live(1, [0, 0], true)], SECOND);
    assert!(agent.observe(&[live(1, [100, 100], true)], 10 * SECOND).is_empty());
    assert_eq!(agent.refused, 1);
}

#[test]
fn alert_while_trusted_revokes_for_good() {
    let mut agent = Agent::new(Policy::default());
    agent.observe(&[live(1, [0, 0], true)], 0);
    agent.observe(&[live(1, [10, 10], true)], 5 * SECOND);
    assert_eq!(agent.alert(Some(key()), 6 * SECOND), Some(Decision::Revoke(key())));
    assert!(agent.observe(&[live(1, [100, 100], true)], 700 * SECOND).is_empty());
    assert!(agent.observe(&[live(1, [200, 200], true)], 705 * SECOND).is_empty());
}

#[test]
fn ttl_expires_and_watching_restarts() {
    let mut agent = Agent::new(Policy::default());
    agent.observe(&[live(1, [0, 0], true)], 0);
    agent.observe(&[live(1, [10, 10], true)], 5 * SECOND);
    assert_eq!(agent.observe(&[live(1, [90, 90], true)], 905 * SECOND), [Decision::Expire(key())]);
    assert!(agent.observe(&[live(1, [95, 95], true)], 910 * SECOND).is_empty());
    assert_eq!(agent.observe(&[live(1, [100, 100], true)], 915 * SECOND), [Decision::Trust(key())]);
}

#[test]
fn new_conntrack_entry_keeps_trust() {
    let mut agent = Agent::new(Policy::default());
    agent.observe(&[live(1, [0, 0], true)], 0);
    agent.observe(&[live(1, [10, 10], true)], 5 * SECOND);
    assert!(agent.observe(&[], 200 * SECOND).is_empty());
    assert!(agent.observe(&[live(2, [1, 0], true)], 300 * SECOND).is_empty());
    assert_eq!(agent.observe(&[], 905 * SECOND), [Decision::Expire(key())]);
    assert!(agent.is_idle());
}

#[test]
fn idle_sweep_ends_unchanged_flows() {
    let mut sweep = IdleSweep::default();
    let mut flows = HashMap::from_iter([(key(), 5)]);
    assert!(sweep.observe(&flows, 0).is_empty());
    assert!(sweep.observe(&flows, 110 * SECOND).is_empty());
    flows.insert(key(), 6);
    assert!(sweep.observe(&flows, 115 * SECOND).is_empty());
    assert!(sweep.observe(&flows, 230 * SECOND).is_empty());
    assert_eq!(sweep.observe(&flows, 235 * SECOND), [key()]);
}
