use super::*;
use crate::features::record::tests::Entries;

fn plan(text: &str) -> Plan {
    Plan::new(&Definition::parse(text).unwrap(), "flows", false, false)
}

fn json(plan: &Plan) -> String {
    let mut out = Vec::new();
    plan.json(&mut out, 1_763_500_000_000);
    String::from_utf8(out).unwrap()
}

#[test]
fn writes_one_object_per_row_in_the_definition_order() {
    let mut plan = plan(
        r#"{"map": "M", "key": [{"name": "saddr", "type": "ipv4"}, {"name": "level", "type": "i8"}],
            "value": [{"name": "packets", "type": "u32"}, {"name": "hist", "type": "u16", "len": 3}],
            "derived": [{"name": "pps", "op": "rate", "of": "packets"},
                        {"name": "half", "op": "scale", "of": "packets", "by": 0.5},
                        {"name": "proto", "op": "enum", "of": "level", "values": {"-1": "low-1.a_b"}}]}"#,
    );
    let value = |packets: u32, hist: [u16; 3]| {
        let mut v = packets.to_le_bytes().to_vec();
        hist.iter().for_each(|h| v.extend(h.to_le_bytes()));
        v.extend([0, 0]);
        v
    };
    let entries = Entries(vec![
        (vec![10, 0, 1, 2, 0xff, 0, 0, 0], vec![value(3, [1, 2, 3])]),
        (vec![192, 168, 0, 255, 5, 0, 0, 0], vec![value(4, [0, 0, 9])]),
    ]);
    assert_eq!(plan.round(&entries, Instant::now()), 0);
    assert_eq!(
        json(&plan),
        concat!(
            r#"{"ts_ms":1763500000000,"feature":"flows","saddr":"10.0.1.2","level":-1,"packets":3,"hist":[1,2,3],"pps":null,"half":1.5,"proto":"low-1.a_b"}"#,
            "\n",
            r#"{"ts_ms":1763500000000,"feature":"flows","saddr":"192.168.0.255","level":5,"packets":4,"hist":[0,0,9],"pps":null,"half":2.0,"proto":null}"#,
            "\n"
        )
    );
}

#[test]
fn ipv6_is_written_in_its_short_form() {
    let mut plan = plan(r#"{"map": "M", "value": [{"name": "a", "type": "ipv6"}]}"#);
    let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    plan.round(&[addr.octets().to_vec()][..], Instant::now());
    assert_eq!(json(&plan), "{\"ts_ms\":1763500000000,\"feature\":\"flows\",\"a\":\"2001:db8::1\"}\n");
}

#[test]
fn records_of_the_wrong_size_are_counted_and_left_out() {
    let mut plan = plan(r#"{"map": "M", "value": [{"name": "a", "type": "u32"}]}"#);
    let records = [vec![1, 0, 0, 0], vec![2, 0, 0], vec![3, 0, 0, 0]];
    assert_eq!(plan.round(&records[..], Instant::now()), 1);
    assert_eq!(plan.len(), 2);
    assert_eq!(plan.row(1), [Value::Unsigned(3)]);
    assert_eq!(plan.round(&records[..0], Instant::now()), 0);
    assert!(plan.is_empty());
    assert_eq!(json(&plan), "");
}

#[test]
fn matches_serde_json_for_floats() {
    let mut plan = plan(
        r#"{"map": "M", "value": [{"name": "a", "type": "u64"}],
            "derived": [{"name": "s", "op": "scale", "of": "a", "by": 1e-9}, {"name": "t", "op": "scale", "of": "a", "by": 3.3}]}"#,
    );
    for a in [0u64, 1, 7, 123_456_789, 1_763_500_000_123_456_789, u64::MAX] {
        plan.round(&[a.to_le_bytes().to_vec()][..], Instant::now());
        let line = json(&plan);
        for (name, by) in [("s", 1e-9), ("t", 3.3)] {
            let want = format!(",\"{name}\":{}", serde_json::to_string(&(a as f64 * by)).unwrap());
            assert!(line.contains(&want), "{a} × {by}: {line}");
        }
    }
}
