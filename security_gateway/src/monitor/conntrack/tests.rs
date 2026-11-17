use super::*;

fn stats(entries: u32, max: u32, cpus: &[(u16, u32, u32, u32)]) -> Result<Stats, ConntrackError> {
    Ok(Stats {
        entries,
        max,
        cpus: cpus
            .iter()
            .map(|&(cpu, drop, early_drop, insert_failed)| CpuStats { cpu, drop, early_drop, insert_failed })
            .collect(),
    })
}

fn quiet(entries: u32) -> Result<Stats, ConntrackError> {
    stats(entries, 1000, &[(0, 0, 0, 0)])
}

#[test]
fn first_reading_reports_the_table_size() {
    let mut m = ConntrackMonitor::default();
    assert_eq!(m.observe(quiet(12)), [Finding::Table { entries: 12, max: 1000 }]);
    assert_eq!(m.observe(quiet(15)), []);
}

#[test]
fn nearly_full_is_reported_once_and_cleared_below_80_percent() {
    let mut m = ConntrackMonitor::default();
    m.observe(quiet(500));
    assert_eq!(m.observe(quiet(899)), []);
    assert_eq!(m.observe(quiet(900)), [Finding::NearlyFull { entries: 900, max: 1000 }]);
    assert_eq!(m.observe(quiet(1000)), []);
    assert_eq!(m.observe(quiet(850)), []);
    assert_eq!(m.observe(quiet(800)), []);
    assert_eq!(m.observe(quiet(799)), [Finding::NoLongerNearlyFull { entries: 799, max: 1000 }]);
    assert_eq!(m.observe(quiet(950)), [Finding::NearlyFull { entries: 950, max: 1000 }]);
}

#[test]
fn table_already_nearly_full_at_start() {
    let mut m = ConntrackMonitor::default();
    assert_eq!(
        m.observe(quiet(990)),
        [Finding::Table { entries: 990, max: 1000 }, Finding::NearlyFull { entries: 990, max: 1000 }]
    );
}

#[test]
fn unlimited_table_is_never_nearly_full() {
    let mut m = ConntrackMonitor::default();
    m.observe(stats(10, 0, &[]));
    assert_eq!(m.observe(stats(4_000_000, 0, &[])), []);
}

#[test]
fn reports_increases_summed_over_cpus() {
    let mut m = ConntrackMonitor::default();
    m.observe(stats(10, 1000, &[(0, 1, 5, 2), (1, 0, 0, 0)]));
    assert_eq!(m.observe(stats(10, 1000, &[(0, 1, 5, 2), (1, 0, 0, 0)])), []);
    assert_eq!(
        m.observe(stats(10, 1000, &[(0, 4, 5, 3), (1, 2, 0, 0)])),
        [Finding::Dropped { drop: 5, insert_failed: 1 }]
    );
    assert_eq!(m.observe(stats(10, 1000, &[(0, 4, 9, 3), (1, 2, 1, 0)])), [Finding::Evicted { early_drop: 5 }]);
}

#[test]
fn counters_that_wrap_still_count() {
    let mut m = ConntrackMonitor::default();
    m.observe(stats(10, 1000, &[(0, u32::MAX - 1, 0, 0)]));
    assert_eq!(m.observe(stats(10, 1000, &[(0, 3, 0, 0)])), [Finding::Dropped { drop: 5, insert_failed: 0 }]);
}

#[test]
fn cpus_missing_from_the_last_reading_are_skipped() {
    let mut m = ConntrackMonitor::default();
    m.observe(stats(10, 1000, &[(0, 0, 0, 0)]));
    assert_eq!(m.observe(stats(10, 1000, &[(0, 0, 0, 0), (2, 70, 0, 0)])), []);
}

#[test]
fn read_failure_is_reported_once_until_it_recovers() {
    let mut m = ConntrackMonitor::default();
    m.observe(quiet(10));
    assert_eq!(
        m.observe(Err(ConntrackError::NoReply)),
        [Finding::ReadFailed { error: "no reply from ctnetlink".to_owned() }]
    );
    assert_eq!(m.observe(Err(ConntrackError::NoReply)), []);
    assert_eq!(m.observe(quiet(10)), [Finding::ReadRecovered]);
    assert_eq!(
        m.observe(Err(ConntrackError::NoReply)),
        [Finding::ReadFailed { error: "no reply from ctnetlink".to_owned() }]
    );
}

#[test]
fn failure_before_the_first_reading_still_reports_the_table_later() {
    let mut m = ConntrackMonitor::default();
    m.observe(Err(ConntrackError::NoReply));
    assert_eq!(m.observe(quiet(10)), [Finding::ReadRecovered, Finding::Table { entries: 10, max: 1000 }]);
}
