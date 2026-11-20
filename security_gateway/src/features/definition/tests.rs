use super::*;

const FLOWS: &str = r#"{
  "map": "FLOWS",
  "key": [
    {"name": "saddr", "type": "ipv4"},
    {"name": "daddr", "type": "ipv4"},
    {"name": "sport", "type": "u16", "endian": "big"},
    {"name": "dport", "type": "u16", "endian": "big"},
    {"name": "proto", "type": "u8"}
  ],
  "value": [
    {"name": "flags", "type": "u8", "merge": "or"},
    {"name": "packets", "type": "u64", "merge": "sum"},
    {"name": "bytes", "type": "u64", "merge": "sum"},
    {"name": "len_sumsq", "type": "u64", "merge": "sum"},
    {"name": "hist", "type": "u32", "len": 4, "merge": "sum"}
  ],
  "derived": [
    {"name": "len_std", "op": "std", "sum": "bytes", "sumsq": "len_sumsq", "count": "packets"},
    {"name": "pps", "op": "rate", "of": "packets"},
    {"name": "len_mean", "op": "div", "args": ["bytes", "packets"]},
    {"name": "proto_name", "op": "enum", "of": "proto", "values": {"6": "tcp", "17": "udp"}, "other": "other"},
    {"name": "len_p50", "op": "percentile", "of": "hist", "p": 50, "bounds": [64, 256, 1024, 1514]}
  ]
}"#;

fn offsets(layout: &Layout) -> Vec<(&str, usize)> {
    layout.fields.iter().map(|f| (f.name.as_str(), f.offset)).collect()
}

fn with_value(value: &str) -> String {
    format!(r#"{{"map": "M", "key": [{{"name": "k", "type": "u32"}}], "value": {value}}}"#)
}

fn with_derived(derived: &str) -> String {
    format!(
        r#"{{"map": "M", "key": [{{"name": "k", "type": "u32"}}],
            "value": [{{"name": "a", "type": "u64"}}, {{"name": "b", "type": "u32"}}, {{"name": "addr", "type": "ipv4"}},
                      {{"name": "hist", "type": "u32", "len": 2}}],
            "derived": {derived}}}"#
    )
}

#[test]
fn padding_follows_c_alignment() {
    let def = Definition::parse(FLOWS).unwrap();
    let key = def.key.as_ref().unwrap();
    assert_eq!(offsets(key), [("saddr", 0), ("daddr", 4), ("sport", 8), ("dport", 10), ("proto", 12)]);
    assert_eq!(key.size, 16);
    assert_eq!(offsets(&def.value), [("flags", 0), ("packets", 8), ("bytes", 16), ("len_sumsq", 24), ("hist", 32)]);
    assert_eq!(def.value.size, 48);
}

#[test]
fn packed_has_no_padding() {
    let def = Definition::parse(&FLOWS.replace(r#""map": "FLOWS","#, r#""map": "FLOWS", "packed": true,"#)).unwrap();
    assert_eq!(def.key.as_ref().unwrap().size, 13);
    assert_eq!(offsets(&def.value), [("flags", 0), ("packets", 1), ("bytes", 9), ("len_sumsq", 17), ("hist", 25)]);
    assert_eq!(def.value.size, 41);
}

#[test]
fn derived_fields_are_ordered_by_what_they_use() {
    let def = Definition::parse(&with_derived(
        r#"[{"name": "z", "op": "scale", "of": "y", "by": 2},
            {"name": "y", "op": "add", "args": ["a", "b"]}]"#,
    ))
    .unwrap();
    let names: Vec<&str> = def.derived.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, ["y", "z"]);
    assert_eq!(def.derived[0].op, Op::Add(1, 2));
    assert_eq!(def.derived[1].op, Op::Scale { of: 5, by: 2.0 });
    assert_eq!(def.derived[0].kind, Kind::Int);
}

#[test]
fn a_cycle_is_an_error() {
    let err = Definition::parse(&with_derived(
        r#"[{"name": "x", "op": "add", "args": ["a", "y"]}, {"name": "y", "op": "add", "args": ["a", "x"]}]"#,
    ))
    .unwrap_err();
    assert!(matches!(err, DefinitionError::Cycle(names) if names == ["x", "y"]));
}

#[test]
fn unknown_and_wrong_kind_references_are_errors() {
    let unknown = Definition::parse(&with_derived(r#"[{"name": "x", "op": "rate", "of": "nope"}]"#)).unwrap_err();
    assert!(matches!(unknown, DefinitionError::Unknown { target, .. } if target == "nope"));
    let address = Definition::parse(&with_derived(r#"[{"name": "x", "op": "rate", "of": "addr"}]"#)).unwrap_err();
    assert!(matches!(address, DefinitionError::Kind { found: Kind::Address, .. }));
    let array = Definition::parse(&with_derived(r#"[{"name": "x", "op": "div", "args": ["a", "hist"]}]"#)).unwrap_err();
    assert!(matches!(array, DefinitionError::Kind { found: Kind::List(2), .. }));
}

#[test]
fn rate_needs_a_key() {
    let text = r#"{"map": "EVENTS", "value": [{"name": "a", "type": "u64"}],
                   "derived": [{"name": "r", "op": "rate", "of": "a"}]}"#;
    assert!(matches!(Definition::parse(text).unwrap_err(), DefinitionError::NeedsKey(n) if n == "r"));
}

#[test]
fn names_must_be_unique_and_well_formed() {
    let dup = with_value(r#"[{"name": "k", "type": "u8"}]"#);
    assert!(matches!(Definition::parse(&dup).unwrap_err(), DefinitionError::Duplicate(n) if n == "k"));
    for bad in ["Bytes", "1x", "a-b", ""] {
        let text = with_value(&format!(r#"[{{"name": "{bad}", "type": "u8"}}]"#));
        assert!(matches!(Definition::parse(&text).unwrap_err(), DefinitionError::BadName(_)), "{bad}");
    }
}

#[test]
fn field_rules() {
    let cases = [
        r#"[{"name": "a", "type": "ipv4", "endian": "big"}]"#,
        r#"[{"name": "a", "type": "ipv6", "len": 2}]"#,
        r#"[{"name": "a", "type": "u8", "len": 0}]"#,
        r#"[{"name": "a", "type": "u8", "len": 1025}]"#,
        r#"[{"name": "a", "type": "ipv4", "merge": "sum"}]"#,
    ];
    for case in cases {
        assert!(matches!(Definition::parse(&with_value(case)).unwrap_err(), DefinitionError::Field(..)), "{case}");
    }
    let key_merge = r#"{"map": "M", "key": [{"name": "k", "type": "u32", "merge": "sum"}], "value": [{"name": "a", "type": "u8"}]}"#;
    assert!(matches!(Definition::parse(key_merge).unwrap_err(), DefinitionError::Field(..)));
    assert!(matches!(Definition::parse(&with_value("[]")).unwrap_err(), DefinitionError::Empty("value")));
}

#[test]
fn unknown_keys_and_ops_are_rejected() {
    assert!(Definition::parse(&with_value(r#"[{"name": "a", "type": "u8", "unit": "s"}]"#)).is_err());
    assert!(Definition::parse(&with_derived(r#"[{"name": "x", "op": "median", "of": "a"}]"#)).is_err());
    assert!(Definition::parse(&with_derived(r#"[{"name": "x", "op": "rate", "of": "a", "extra": 1}]"#)).is_err());
    assert!(Definition::parse(&with_value(r#"[{"name": "a", "type": "f32"}]"#)).is_err());
}

#[test]
fn parameter_rules() {
    let cases = [
        r#"[{"name": "x", "op": "bucket", "of": "a", "edges": [10, 5]}]"#,
        r#"[{"name": "x", "op": "bucket", "of": "a", "edges": []}]"#,
        r#"[{"name": "x", "op": "percentile", "of": "hist", "p": 0, "bounds": [1, 2]}]"#,
        r#"[{"name": "x", "op": "percentile", "of": "hist", "p": 50, "bounds": [1, 2, 3]}]"#,
        r#"[{"name": "x", "op": "enum", "of": "a", "values": {"six": "tcp"}}]"#,
        r#"[{"name": "x", "op": "enum", "of": "a", "values": {"6": "t c p"}}]"#,
        r#"[{"name": "x", "op": "enum", "of": "a", "values": {}}]"#,
    ];
    for case in cases {
        assert!(matches!(Definition::parse(&with_derived(case)).unwrap_err(), DefinitionError::Param(..)), "{case}");
    }
}

#[test]
fn the_example_parses() {
    let def = Definition::parse(FLOWS).unwrap();
    assert_eq!(def.map, "FLOWS");
    assert_eq!(def.names().count(), 15);
    assert_eq!(def.derived.iter().find(|d| d.name == "proto_name").unwrap().kind, Kind::Text);
}

#[test]
fn a_large_file_is_rejected_before_reading() {
    let dir = std::env::temp_dir().join(format!("wnc-gw-def-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("big.json");
    std::fs::write(&path, " ".repeat(MAX_DEFINITION_BYTES as usize + 1)).unwrap();
    assert!(matches!(Definition::load(&path).unwrap_err(), DefinitionError::TooLarge { .. }));
    std::fs::write(&path, FLOWS).unwrap();
    assert!(Definition::load(&path).is_ok());
    std::fs::remove_dir_all(&dir).unwrap();
}
