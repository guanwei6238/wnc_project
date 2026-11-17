use super::*;

fn sockets(drops: &[(u64, u32)]) -> io::Result<Vec<NetfilterSocket>> {
    Ok(drops.iter().map(|&(inode, drops)| NetfilterSocket { inode, drops }).collect())
}

#[test]
fn counts_every_drop_of_a_new_suricata() {
    let mut m = CopyMonitor::default();
    assert_eq!(m.observe(7, sockets(&[(1, 0), (2, 0)])), []);
    assert_eq!(m.observe(7, sockets(&[(1, 0), (2, 0)])), []);
    let mut m = CopyMonitor::default();
    assert_eq!(m.observe(7, sockets(&[(1, 30), (2, 4)])), [Finding::Missed { missed: 34 }]);
}

#[test]
fn reports_increases_summed_over_sockets() {
    let mut m = CopyMonitor::default();
    m.observe(7, sockets(&[(1, 30), (2, 4)]));
    assert_eq!(m.observe(7, sockets(&[(1, 30), (2, 4)])), []);
    assert_eq!(m.observe(7, sockets(&[(1, 35), (2, 10)])), [Finding::Missed { missed: 11 }]);
}

#[test]
fn drops_that_wrap_still_count() {
    let mut m = CopyMonitor::default();
    m.observe(7, sockets(&[(1, u32::MAX - 1)]));
    assert_eq!(m.observe(7, sockets(&[(1, 3)])), [Finding::Missed { missed: 5 }]);
}

#[test]
fn a_restarted_suricata_starts_from_zero() {
    let mut m = CopyMonitor::default();
    m.observe(7, sockets(&[(1, 500)]));
    assert_eq!(m.observe(8, sockets(&[(9, 2)])), [Finding::Missed { missed: 2 }]);
    assert_eq!(m.observe(8, sockets(&[(9, 2)])), []);
}

#[test]
fn missing_sockets_are_reported_once_per_suricata() {
    let mut m = CopyMonitor::default();
    assert_eq!(m.observe(7, sockets(&[])), [Finding::NoSockets { pid: 7 }]);
    assert_eq!(m.observe(7, sockets(&[])), []);
    assert_eq!(m.observe(8, sockets(&[])), [Finding::NoSockets { pid: 8 }]);
}

#[test]
fn read_failure_is_reported_once_until_it_recovers() {
    let mut m = CopyMonitor::default();
    let denied = || Err(io::Error::from(io::ErrorKind::PermissionDenied));
    assert_eq!(m.observe(7, denied()), [Finding::ReadFailed { error: "permission denied".to_owned() }]);
    assert_eq!(m.observe(7, denied()), []);
    assert_eq!(m.observe(7, sockets(&[(1, 0)])), [Finding::ReadRecovered]);
}
