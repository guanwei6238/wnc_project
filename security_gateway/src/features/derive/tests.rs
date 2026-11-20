use std::time::Duration;

use super::*;
use crate::features::definition::Definition;
use crate::features::plan::Plan;
use crate::features::record::tests::Entries;

fn definition(derived: &str) -> Definition {
    Definition::parse(&format!(
        r#"{{"map": "M", "key": [{{"name": "k", "type": "u32"}}],
            "value": [{{"name": "packets", "type": "u64"}}, {{"name": "bytes", "type": "u64"}},
                      {{"name": "sumsq", "type": "u64"}}, {{"name": "proto", "type": "u8"}},
                      {{"name": "level", "type": "i32"}}, {{"name": "hist", "type": "u32", "len": 4}}],
            "derived": {derived}}}"#
    ))
    .unwrap()
}

fn entry(key: u8, packets: u64, bytes: u64, sumsq: u64, proto: u8, level: i32, hist: [u32; 4]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut v = Vec::new();
    v.extend(packets.to_le_bytes());
    v.extend(bytes.to_le_bytes());
    v.extend(sumsq.to_le_bytes());
    v.extend([proto, 0, 0, 0]);
    v.extend(level.to_le_bytes());
    hist.iter().for_each(|h| v.extend(h.to_le_bytes()));
    (vec![key, 0, 0, 0], vec![v])
}

/// The derived columns of each row; the key, value and hist take the first 10.
fn derived(plan: &mut Plan, entries: Vec<(Vec<u8>, Vec<Vec<u8>>)>, now: Instant) -> Vec<Vec<Value>> {
    assert_eq!(plan.round(&Entries(entries), now), 0);
    (0..plan.len()).map(|i| plan.row(i)[10..].to_vec()).collect()
}

fn plan(def: &Definition) -> Plan {
    Plan::new(def, "f", false, false)
}

#[test]
fn arithmetic_and_statistics() {
    let def = definition(
        r#"[{"name": "sum", "op": "add", "args": ["packets", "bytes"]},
            {"name": "diff", "op": "sub", "args": ["packets", "bytes"]},
            {"name": "below", "op": "sub", "args": ["level", "packets"]},
            {"name": "prod", "op": "mul", "args": ["packets", "level"]},
            {"name": "mean", "op": "mean", "sum": "bytes", "count": "packets"},
            {"name": "var", "op": "var", "sum": "bytes", "sumsq": "sumsq", "count": "packets"},
            {"name": "std", "op": "std", "sum": "bytes", "sumsq": "sumsq", "count": "packets"},
            {"name": "half", "op": "scale", "of": "bytes", "by": 0.5}]"#,
    );
    let out = derived(&mut plan(&def), vec![entry(1, 4, 400, 50_000, 6, -3, [0; 4])], Instant::now());
    assert_eq!(
        out[0],
        [
            Value::Unsigned(404),
            Value::Signed(-396),
            Value::Signed(-7),
            Value::Signed(-12),
            Value::Float(100.0),
            Value::Float(2_500.0),
            Value::Float(50.0),
            Value::Float(200.0)
        ]
    );
}

#[test]
fn zero_count_and_overflow_give_null() {
    let def = definition(
        r#"[{"name": "mean", "op": "div", "args": ["bytes", "packets"]},
            {"name": "std", "op": "std", "sum": "bytes", "sumsq": "sumsq", "count": "packets"},
            {"name": "big", "op": "mul", "args": ["bytes", "bytes"]},
            {"name": "bigger", "op": "mul", "args": ["big", "big"]}]"#,
    );
    let out = derived(&mut plan(&def), vec![entry(1, 0, u64::MAX, 0, 6, 0, [0; 4])], Instant::now());
    assert_eq!(out[0][0], Value::Null);
    assert_eq!(out[0][1], Value::Null);
    assert_eq!(out[0][2], Value::Null, "u64::MAX squared does not fit");
    assert_eq!(out[0][3], Value::Null);
}

#[test]
fn delta_and_rate_compare_with_the_previous_reading_of_the_same_key() {
    let def = definition(
        r#"[{"name": "d", "op": "delta", "of": "packets"}, {"name": "pps", "op": "rate", "of": "packets"}]"#,
    );
    let mut plan = plan(&def);
    let t0 = Instant::now();
    let first = derived(&mut plan, vec![entry(1, 10, 0, 0, 6, 0, [0; 4]), entry(2, 5, 0, 0, 6, 0, [0; 4])], t0);
    assert_eq!(first, [[Value::Null, Value::Null], [Value::Null, Value::Null]]);
    let second = derived(&mut plan, vec![entry(1, 30, 0, 0, 6, 0, [0; 4])], t0 + Duration::from_secs(10));
    assert_eq!(second, [[Value::Unsigned(20), Value::Float(2.0)]]);
    let again = derived(&mut plan, vec![entry(2, 9, 0, 0, 6, 0, [0; 4])], t0 + Duration::from_secs(20));
    assert_eq!(again, [[Value::Null, Value::Null]], "key 2 was missing from the last read, so it starts over");
    let reset = derived(&mut plan, vec![entry(2, 1, 0, 0, 6, 0, [0; 4])], t0 + Duration::from_secs(30));
    assert_eq!(reset, [[Value::Null, Value::Null]], "a counter that went down was recreated");
}

#[test]
fn delta_of_a_derived_field_uses_its_previous_derived_value() {
    let def = definition(
        r#"[{"name": "total", "op": "add", "args": ["packets", "bytes"]}, {"name": "d", "op": "delta", "of": "total"}]"#,
    );
    let mut plan = plan(&def);
    let t0 = Instant::now();
    derived(&mut plan, vec![entry(1, 1, 100, 0, 6, 0, [0; 4])], t0);
    let next = derived(&mut plan, vec![entry(1, 3, 250, 0, 6, 0, [0; 4])], t0 + Duration::from_secs(1));
    assert_eq!(next, [[Value::Unsigned(253), Value::Unsigned(152)]]);
}

#[test]
fn many_keys_keep_their_own_previous_reading() {
    let def = definition(r#"[{"name": "d", "op": "delta", "of": "packets"}]"#);
    let mut plan = plan(&def);
    let t0 = Instant::now();
    derived(&mut plan, (0..200).map(|k| entry(k, u64::from(k), 0, 0, 6, 0, [0; 4])).collect(), t0);
    let out = derived(&mut plan, (0..200).rev().map(|k| entry(k, 3 * u64::from(k), 0, 0, 6, 0, [0; 4])).collect(), t0);
    for (i, k) in (0..200u64).rev().enumerate() {
        assert_eq!(out[i], [Value::Unsigned(2 * k)], "key {k}");
    }
}

#[test]
fn bucket_enum_and_percentile() {
    let def = definition(
        r#"[{"name": "size", "op": "bucket", "of": "bytes", "edges": [100, 1000]},
            {"name": "name", "op": "enum", "of": "proto", "values": {"6": "tcp", "17": "udp"}, "other": "other"},
            {"name": "strict", "op": "enum", "of": "proto", "values": {"6": "tcp"}},
            {"name": "p50", "op": "percentile", "of": "hist", "p": 50, "bounds": [64, 256, 1024, 1514]},
            {"name": "p99", "op": "percentile", "of": "hist", "p": 99, "bounds": [64, 256, 1024, 1514]}]"#,
    );
    let mut plan = plan(&def);
    let out = derived(&mut plan, vec![entry(1, 1, 99, 0, 6, 0, [5, 4, 0, 1]), entry(2, 1, 1000, 0, 1, 0, [0; 4])], Instant::now());
    let label = |v: Value| match v {
        Value::Label(i) => plan.label(i).to_string(),
        other => panic!("{other:?} is not a label"),
    };
    assert_eq!(out[0][0], Value::Unsigned(0));
    assert_eq!(label(out[0][1]), "tcp");
    assert_eq!(label(out[0][2]), "tcp");
    assert_eq!(out[0][3..], [Value::Float(64.0), Value::Float(1514.0)]);
    assert_eq!(out[1][0], Value::Unsigned(2));
    assert_eq!(label(out[1][1]), "other");
    assert_eq!(out[1][2..], [Value::Null, Value::Null, Value::Null]);
}
