use super::*;

fn alert(sid: u64, signature: &str, src_port: u16) -> Alert {
    Alert {
        flow_id: Some(u64::from(src_port)),
        protocol: "TCP".into(),
        src: Some("10.0.0.1".parse().unwrap()),
        src_port: Some(src_port),
        dst: Some("10.0.0.2".parse().unwrap()),
        dst_port: Some(80),
        signature_id: sid,
        signature: signature.into(),
        action: "allowed".into(),
    }
}

fn monitor() -> AlertMonitor {
    AlertMonitor::new(Path::new("/var/log/wnc-gw/suricata/eve.json"))
}

#[test]
fn nothing_to_say_without_alerts() {
    let mut m = monitor();
    assert_eq!(m.take_summary(), []);
}

#[test]
fn summarizes_alerts_by_signature_and_connection() {
    let mut m = monitor();
    m.alert(&alert(2, "b", 1000));
    m.alert(&alert(1, "a", 1000));
    m.alert(&alert(1, "a", 1001));
    assert_eq!(
        m.take_summary(),
        [Finding::Summary {
            alerts: 3,
            connections: 2,
            connections_capped: false,
            top: vec![(1, "a".into(), 2), (2, "b".into(), 1)],
        }]
    );
    assert_eq!(m.take_summary(), []);
}

#[test]
fn both_directions_of_a_flow_are_one_connection() {
    let mut m = monitor();
    let request = alert(1, "icmp", 7);
    let reply = Alert {
        src: request.dst,
        dst: request.src,
        ..request.clone()
    };
    m.alert(&request);
    m.alert(&reply);
    assert!(matches!(m.take_summary()[0], Finding::Summary { alerts: 2, connections: 1, .. }));
}

#[test]
fn keeps_the_five_most_frequent_signatures() {
    let mut m = monitor();
    for sid in 1..=7 {
        for _ in 0..sid {
            m.alert(&alert(sid, "s", 1000));
        }
    }
    let summary = m.take_summary();
    let Finding::Summary { alerts, top, .. } = &summary[0] else { panic!("{summary:?}") };
    assert_eq!(*alerts, 28);
    let sids: Vec<u64> = top.iter().map(|(sid, _, _)| *sid).collect();
    assert_eq!(sids, [7, 6, 5, 4, 3]);
}

#[test]
fn stops_counting_connections_at_the_limit() {
    let mut m = monitor();
    let mut a = alert(1, "a", 0);
    for i in 0..=MAX_CONNECTIONS {
        a.flow_id = Some(i as u64);
        m.alert(&a);
    }
    let summary = m.take_summary();
    assert!(matches!(
        summary[0],
        Finding::Summary { connections: MAX_CONNECTIONS, connections_capped: true, .. }
    ));
}

#[test]
fn reports_skipped_lines() {
    let mut m = monitor();
    m.malformed(&eve::parse_alert(br#"{"event_type":"alert""#).unwrap_err());
    m.read(Ok(ReadReport {
        too_long: 2,
        ..ReadReport::default()
    }));
    assert_eq!(m.take_summary(), [Finding::Skipped { malformed: 1, too_long: 2 }]);
}

#[test]
fn reports_a_read_failure_once_and_its_recovery() {
    let mut m = monitor();
    let gone = || Err(io::Error::new(io::ErrorKind::NotFound, "no such file"));
    assert_eq!(m.observe_read(gone()), [Finding::ReadFailed { error: "no such file".into() }]);
    assert_eq!(m.observe_read(gone()), []);
    assert_eq!(m.observe_read(Ok(ReadReport::default())), [Finding::ReadRecovered]);
    assert_eq!(m.observe_read(Ok(ReadReport::default())), []);
}

#[test]
fn reports_restarts_and_falling_behind() {
    let mut m = monitor();
    let report = |restart, behind| ReadReport {
        restart,
        behind,
        ..ReadReport::default()
    };
    assert_eq!(
        m.observe_read(Ok(report(Some(Restart::Truncated), true))),
        [Finding::Restarted(Restart::Truncated), Finding::Behind]
    );
    assert_eq!(m.observe_read(Ok(report(None, true))), []);
    assert_eq!(m.observe_read(Ok(report(None, false))), [Finding::CaughtUp]);
}
