use super::*;
use crate::features::definition::Definition;

fn definition() -> Definition {
    Definition::parse(
        r#"{"map": "M",
            "key": [{"name": "saddr", "type": "ipv4"}, {"name": "sport", "type": "u16", "endian": "big"},
                    {"name": "delta", "type": "i16"}],
            "value": [{"name": "flags", "type": "u8", "merge": "or"}, {"name": "packets", "type": "u64", "merge": "sum"},
                      {"name": "first", "type": "u64", "merge": "min"}, {"name": "peak", "type": "i32", "merge": "max"},
                      {"name": "hist", "type": "u16", "len": 2, "merge": "sum"}]}"#,
    )
    .unwrap()
}

fn value(flags: u8, packets: u64, first: u64, peak: i32, hist: [u16; 2]) -> Vec<u8> {
    let mut b = vec![flags, 0, 0, 0, 0, 0, 0, 0];
    b.extend(packets.to_le_bytes());
    b.extend(first.to_le_bytes());
    b.extend(peak.to_le_bytes());
    b.extend(hist[0].to_le_bytes());
    b.extend(hist[1].to_le_bytes());
    b
}

pub(crate) struct Entries(pub(crate) Vec<(Vec<u8>, Vec<Vec<u8>>)>);

impl Records for Entries {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn key(&self, i: usize) -> &[u8] {
        &self.0[i].0
    }
    fn copies(&self, i: usize) -> usize {
        self.0[i].1.len()
    }
    fn copy(&self, i: usize, c: usize) -> &[u8] {
        &self.0[i].1[c]
    }
}

fn decode_one(def: &Definition, per_cpu: bool, skip_zero: bool, key: Vec<u8>, copies: Vec<Vec<u8>>) -> Result<Option<Vec<Value>>, LengthMismatch> {
    let columns = Columns::new(def);
    let decoder = Decoder::new(def, &columns, per_cpu, skip_zero);
    let mut row = vec![Value::Null; columns.width];
    let written = decoder.decode(&Entries(vec![(key, copies)]), 0, &mut row)?;
    Ok(written.then_some(row))
}

const KEY: [u8; 8] = [10, 0, 1, 2, 0x01, 0xbb, 0xfe, 0xff];

#[test]
fn decodes_each_type_and_byte_order() {
    let row = decode_one(&definition(), false, false, KEY.to_vec(), vec![value(0x12, 7, 100, -5, [3, 4])]).unwrap().unwrap();
    assert_eq!(
        row,
        [
            Value::Ipv4([10, 0, 1, 2]),
            Value::Unsigned(443),
            Value::Signed(-2),
            Value::Unsigned(0x12),
            Value::Unsigned(7),
            Value::Unsigned(100),
            Value::Signed(-5),
            Value::Unsigned(3),
            Value::Unsigned(4)
        ]
    );
}

#[test]
fn columns_give_an_array_one_column_per_element() {
    let columns = Columns::new(&definition());
    assert_eq!(columns.start, [0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(columns.list[7], Some(2));
    assert_eq!(columns.width, 9);
    assert_eq!(columns.number(6), Some(6));
    assert_eq!(columns.number(7), None, "an array is not a number");
}

#[test]
fn ipv6_is_decoded_in_network_order() {
    let def = Definition::parse(r#"{"map": "M", "value": [{"name": "a", "type": "ipv6"}]}"#).unwrap();
    let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    let row = decode_one(&def, false, false, Vec::new(), vec![addr.octets().to_vec()]).unwrap().unwrap();
    assert_eq!(row, [Value::Ipv6(addr.octets())]);
}

#[test]
fn a_wrong_length_is_an_error() {
    let def = definition();
    assert_eq!(decode_one(&def, false, false, KEY.to_vec(), vec![vec![0; 31]]).unwrap_err(), LengthMismatch { expected: 32, got: 31 });
    assert_eq!(
        decode_one(&def, false, false, KEY[..7].to_vec(), vec![vec![0; 32]]).unwrap_err(),
        LengthMismatch { expected: 8, got: 7 }
    );
}

#[test]
fn per_cpu_copies_merge_by_rule_and_unwritten_copies_are_skipped() {
    let def = definition();
    let a = value(0x02, 3, 500, 9, [1, 0]);
    let b = value(0x10, 4, 200, -1, [2, 5]);
    let unwritten = vec![0u8; 32];
    let row = decode_one(&def, true, false, KEY.to_vec(), vec![a, unwritten.clone(), b]).unwrap().unwrap();
    assert_eq!(
        row[3..],
        [Value::Unsigned(0x12), Value::Unsigned(7), Value::Unsigned(200), Value::Signed(9), Value::Unsigned(3), Value::Unsigned(5)]
    );
    let all_zero = decode_one(&def, true, false, KEY.to_vec(), vec![unwritten.clone(), unwritten]).unwrap().unwrap();
    assert_eq!(all_zero[4], Value::Unsigned(0));
}

#[test]
fn an_array_entry_never_written_is_skipped() {
    let def = definition();
    assert_eq!(decode_one(&def, true, true, KEY.to_vec(), vec![vec![0; 32], vec![0; 32]]).unwrap(), None);
    assert!(decode_one(&def, true, true, KEY.to_vec(), vec![vec![0; 32], value(1, 0, 0, 0, [0, 0])]).unwrap().is_some());
}
