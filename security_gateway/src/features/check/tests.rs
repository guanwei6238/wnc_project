use std::collections::BTreeMap;

use super::*;
use crate::features::btf::{Btf, tests::Builder};
use crate::features::elf::MapKind;
use crate::features::hook::XdpMode;

const DEFINITION: &str = r#"{"map": "FLOWS",
  "key": [{"name": "saddr", "type": "ipv4"}, {"name": "sport", "type": "u16", "endian": "big"}],
  "value": [{"name": "flags", "type": "u8"}, {"name": "packets", "type": "u64"}, {"name": "hist", "type": "u32", "len": 2}]}"#;

const VALUE: [(&str, &str); 3] = [("flags", "u8"), ("packets", "u64"), ("hist", "hist")];

fn btf(value_members: &[(&str, &str)]) -> Btf {
    let mut b = Builder::new();
    let u8_ = b.int("unsigned char", 1, false);
    let u16_ = b.int("unsigned short", 2, false);
    let u32_ = b.int("unsigned int", 4, false);
    let u64_ = b.int("unsigned long long", 8, false);
    let hist = b.array(u32_, u32_, 2);
    let key = b.structure("flow_key", 8, &[("saddr", u32_, 0), ("sport", u16_, 32)]);
    let mut members = Vec::new();
    let mut offset = 0u32;
    for (name, kind) in value_members {
        let (ty, size, align) = match *kind {
            "u8" => (u8_, 1, 1),
            "u64" => (u64_, 8, 8),
            _ => (hist, 8, 4),
        };
        offset = offset.next_multiple_of(align);
        members.push((*name, ty, offset * 8));
        offset += size;
    }
    let value = b.structure("flow_val", 24, &members);
    b.map("FLOWS", key, value);
    Btf::parse(&b.bytes()).unwrap()
}

fn elf(kind: MapKind, value_size: u32, btf: Option<Btf>) -> Elf {
    Elf {
        programs: BTreeMap::from([("flows".to_string(), ProgramKind::Classifier), ("x".to_string(), ProgramKind::Xdp)]),
        maps: BTreeMap::from([("FLOWS".to_string(), MapInfo { kind, key_size: 8, value_size, max_entries: 1024 })]),
        btf: btf.map(Ok),
    }
}

fn run(elf: &Elf, entry: &str, hook: Hook) -> Vec<Problem> {
    check(&Definition::parse(DEFINITION).unwrap(), elf, entry, hook)
}

#[test]
fn a_matching_program_has_no_problems() {
    assert_eq!(run(&elf(MapKind::Hash, 24, Some(btf(&VALUE))), "flows", Hook::TcEgress), []);
}

#[test]
fn entry_must_exist_and_fit_the_hook() {
    let e = elf(MapKind::Hash, 24, Some(btf(&VALUE)));
    assert!(matches!(&run(&e, "nope", Hook::TcEgress)[..], [Problem::EntryMissing { available, .. }] if available.len() == 2));
    assert!(matches!(&run(&e, "flows", Hook::Xdp(XdpMode::Native))[..], [Problem::EntryWrongKind { .. }]));
    assert!(matches!(&run(&e, "x", Hook::TcIngress)[..], [Problem::EntryWrongKind { found: ProgramKind::Xdp, .. }]));
    assert_eq!(run(&e, "x", Hook::Xdp(XdpMode::Generic)), []);
}

#[test]
fn sizes_and_map_kinds() {
    let size = run(&elf(MapKind::Hash, 32, None), "flows", Hook::TcEgress);
    assert!(matches!(&size[..], [Problem::Shape(m)] if m.contains("24 bytes") && m.contains("32-byte")), "{size:?}");
    let ring = run(&elf(MapKind::RingBuf, 0, None), "flows", Hook::TcEgress);
    assert!(matches!(&ring[..], [Problem::Shape(m)] if m.contains("ringbuf")), "{ring:?}");
    let events = Definition::parse(r#"{"map": "FLOWS", "value": [{"name": "a", "type": "u64"}]}"#).unwrap();
    let undeclared = elf(MapKind::RingBuf, 0, None);
    assert_eq!(check(&events, &undeclared, "flows", Hook::TcEgress), [], "a ringbuf without a record type is checked when read");
    let declared = elf(MapKind::RingBuf, 16, None);
    assert!(matches!(&check(&events, &declared, "flows", Hook::TcEgress)[..], [Problem::Shape(m)] if m.contains("16-byte")));
    let per_cpu = run(&elf(MapKind::PerCpuHash, 24, None), "flows", Hook::TcEgress);
    assert!(matches!(&per_cpu[..], [Problem::Shape(m)] if m.contains("missing on: flags, packets, hist")), "{per_cpu:?}");
    let other = run(&elf(MapKind::Other(12), 24, None), "flows", Hook::TcEgress);
    assert!(matches!(&other[..], [Problem::MapUnsupported { .. }]));
    let mut no_map = elf(MapKind::Hash, 24, None);
    no_map.maps.clear();
    assert!(matches!(&run(&no_map, "flows", Hook::TcEgress)[..], [Problem::MapMissing { .. }]));
}

#[test]
fn without_btf_only_sizes_are_checked() {
    assert!(matches!(&run(&elf(MapKind::Hash, 24, None), "flows", Hook::TcEgress)[..], [Problem::NoBtf(_)]));
}

#[test]
fn btf_catches_what_sizes_do_not() {
    let swapped = btf(&[("packets", "u64"), ("flags", "u8"), ("hist", "hist")]);
    let found = run(&elf(MapKind::Hash, 24, Some(swapped)), "flows", Hook::TcEgress);
    let [Problem::BtfMismatch { part: "value", details }] = &found[..] else { panic!("{found:?}") };
    assert!(details.iter().any(|d| d.contains("packets is at offset 0 in the struct, 8 in the definition")), "{details:?}");
    let renamed = btf(&[("flags", "u8"), ("pkts", "u64"), ("hist", "hist")]);
    let found = run(&elf(MapKind::Hash, 24, Some(renamed)), "flows", Hook::TcEgress);
    assert!(
        matches!(&found[..], [Problem::BtfMismatch { .. }, Problem::Undescribed { members, .. }] if members == &["pkts"]),
        "{found:?}"
    );
}

#[test]
fn compare_scalar_and_signedness() {
    let def = Definition::parse(
        r#"{"map": "M", "key": [{"name": "k", "type": "u32"}], "value": [{"name": "v", "type": "u32"}]}"#,
    )
    .unwrap();
    let (ok, _) = compare(def.key.as_ref().unwrap(), &Shape::Int { size: 4, signed: false });
    assert_eq!(ok, Vec::<String>::new());
    let (signed, _) = compare(&def.value, &Shape::Int { size: 4, signed: true });
    assert_eq!(signed, ["v is signed in the struct, unsigned in the definition"]);
    let (wrong, _) = compare(&def.value, &Shape::Int { size: 8, signed: false });
    assert_eq!(wrong, ["v is 8 bytes in the struct, 4 in the definition"]);
}
