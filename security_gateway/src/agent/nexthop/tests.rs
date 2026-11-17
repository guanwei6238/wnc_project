use super::*;

fn after(start: Instant, millis: u64) -> Instant {
    start + Duration::from_millis(millis)
}

#[test]
fn next_hops_wait_until_routes_are_quiet() {
    let mut hops = NextHops::new([2, 3]);
    let t0 = Instant::now();
    hops.changed(t0);
    assert!(hops.refresh_all);
    assert_eq!(hops.settle(after(t0, 9_999)), None);
    assert!(hops.last_change.is_some_and(|at| after(t0, 9_999).duration_since(at) < QUIET));
    assert_eq!(hops.settle(after(t0, 10_000)), None, "quiet again, nothing to report when it never became unstable");
}

#[test]
fn routes_that_keep_changing_are_reported_once_and_then_their_end() {
    let mut hops = NextHops::new([2, 3]);
    let t0 = Instant::now();
    let mut reports = Vec::new();
    for ms in (0..=70_000).step_by(500) {
        hops.changed(after(t0, ms));
        reports.extend(hops.settle(after(t0, ms)));
    }
    assert_eq!(reports, [Change::Unstable], "after 60 s of changes, reported once");
    assert_eq!(hops.settle(after(t0, 75_000)), None);
    assert_eq!(hops.settle(after(t0, 80_000)), Some(Change::Stable));
    assert_eq!(hops.settle(after(t0, 90_000)), None);
}

#[test]
fn changes_apart_from_each_other_are_not_unstable() {
    let mut hops = NextHops::new([2, 3]);
    let t0 = Instant::now();
    for ms in (0..=300_000).step_by(20_000) {
        hops.changed(after(t0, ms));
        assert_eq!(hops.settle(after(t0, ms + 1)), None);
    }
}

#[test]
fn only_the_two_ports_count() {
    assert_eq!(other_port([2, 3], 2), Some(3));
    assert_eq!(other_port([2, 3], 3), Some(2));
    assert_eq!(other_port([2, 3], 9), None);
}
