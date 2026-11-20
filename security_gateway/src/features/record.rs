use super::definition::{Definition, Endian, Field, Merge, Scalar};
use crate::kernel::bpf::user::Table;

/// One column of a row. An array field takes as many columns as it has elements.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    /// An index into the labels of the definition's enum fields.
    Label(u32),
    Null,
}

/// The records of one read: entries of a map read into a Table, or ring buffer records.
pub trait Records {
    fn len(&self) -> usize;
    fn key(&self, i: usize) -> &[u8];
    /// One copy per possible CPU for a per-CPU map, otherwise one.
    fn copies(&self, i: usize) -> usize;
    fn copy(&self, i: usize, c: usize) -> &[u8];
}

impl Records for Table {
    fn len(&self) -> usize {
        Table::len(self)
    }
    fn key(&self, i: usize) -> &[u8] {
        Table::key(self, i)
    }
    fn copies(&self, _: usize) -> usize {
        Table::copies(self)
    }
    fn copy(&self, i: usize, c: usize) -> &[u8] {
        Table::value(self, i, c)
    }
}

impl Records for [Vec<u8>] {
    fn len(&self) -> usize {
        <[Vec<u8>]>::len(self)
    }
    fn key(&self, _: usize) -> &[u8] {
        &[]
    }
    fn copies(&self, _: usize) -> usize {
        1
    }
    fn copy(&self, i: usize, _: usize) -> &[u8] {
        &self[i]
    }
}

/// Where each field's columns start in a row: key fields, value fields, then derived fields.
pub struct Columns {
    pub start: Vec<usize>,
    /// The length of an array field, None for the others.
    pub list: Vec<Option<usize>>,
    pub width: usize,
}

impl Columns {
    pub fn new(definition: &Definition) -> Self {
        let (mut start, mut list, mut width) = (Vec::new(), Vec::new(), 0);
        let base = definition.key.iter().flat_map(|k| &k.fields).chain(&definition.value.fields);
        for len in base.map(|f| f.len.map(|n| n as usize)).chain(definition.derived.iter().map(|_| None)) {
            start.push(width);
            list.push(len);
            width += len.unwrap_or(1);
        }
        Self { start, list, width }
    }

    /// The column of a field that holds a single number, None for an array, which never does.
    pub fn number(&self, field: usize) -> Option<usize> {
        self.list[field].is_none().then(|| self.start[field])
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("record is {got} bytes, but the definition describes {expected}")]
pub struct LengthMismatch {
    pub expected: usize,
    pub got: usize,
}

struct Src {
    offset: usize,
    scalar: Scalar,
    endian: Endian,
    merge: Merge,
    count: usize,
    column: usize,
}

impl Src {
    fn new(field: &Field, column: usize) -> Self {
        Self {
            offset: field.offset,
            scalar: field.scalar,
            endian: field.endian,
            merge: field.merge.unwrap_or(Merge::First),
            count: field.len.unwrap_or(1) as usize,
            column,
        }
    }
}

/// The key and value layouts compiled into where each field's bytes go in a row.
pub struct Decoder {
    key: Vec<Src>,
    value: Vec<Src>,
    key_size: Option<usize>,
    value_size: usize,
    per_cpu: bool,
    skip_zero: bool,
}

impl Decoder {
    /// `skip_zero`: an array entry whose copies are all zero was never written and is skipped.
    pub fn new(definition: &Definition, columns: &Columns, per_cpu: bool, skip_zero: bool) -> Self {
        let keys = definition.key.iter().flat_map(|k| &k.fields);
        let nkey = keys.clone().count();
        let key = keys.zip(&columns.start).map(|(f, &c)| Src::new(f, c)).collect();
        let value = definition.value.fields.iter().zip(&columns.start[nkey..]).map(|(f, &c)| Src::new(f, c)).collect();
        Self {
            key,
            value,
            key_size: definition.key.as_ref().map(|k| k.size),
            value_size: definition.value.size,
            per_cpu,
            skip_zero,
        }
    }

    /// Fills the key and value columns of `row` from record `n`. Ok(false) is an array entry
    /// that was never written. A per-CPU map's copies merge by each field's rule; a CPU that
    /// never wrote the entry leaves its copy all zero, so those are skipped (otherwise min would
    /// always be 0).
    pub fn decode<R: Records + ?Sized>(&self, records: &R, n: usize, row: &mut [Value]) -> Result<bool, LengthMismatch> {
        let copies = records.copies(n);
        if self.skip_zero && (0..copies).all(|c| records.copy(n, c).iter().all(|&b| b == 0)) {
            return Ok(false);
        }
        let key = records.key(n);
        if let Some(size) = self.key_size.filter(|&size| key.len() != size) {
            return Err(LengthMismatch { expected: size, got: key.len() });
        }
        if let Some(got) = (0..copies).map(|c| records.copy(n, c).len()).find(|&len| len != self.value_size) {
            return Err(LengthMismatch { expected: self.value_size, got });
        }
        if copies == 0 {
            return Err(LengthMismatch { expected: self.value_size, got: 0 });
        }
        for s in &self.key {
            put(s, key, row);
        }
        let mut first = true;
        if self.per_cpu {
            for bytes in (0..copies).map(|c| records.copy(n, c)).filter(|b| b.iter().any(|&x| x != 0)) {
                for s in &self.value {
                    if first { put(s, bytes, row) } else { fold(s, bytes, row) }
                }
                first = false;
            }
        }
        if first {
            for s in &self.value {
                put(s, records.copy(n, 0), row);
            }
        }
        Ok(true)
    }
}

fn scalar(s: &Src, bytes: &[u8]) -> Value {
    match s.scalar {
        Scalar::Ipv4 => return Value::Ipv4(bytes.try_into().unwrap()),
        Scalar::Ipv6 => return Value::Ipv6(bytes.try_into().unwrap()),
        _ => {}
    }
    let mut buf = [0u8; 8];
    let raw = match s.endian {
        Endian::Little => {
            buf[..bytes.len()].copy_from_slice(bytes);
            u64::from_le_bytes(buf)
        }
        Endian::Big => {
            buf[8 - bytes.len()..].copy_from_slice(bytes);
            u64::from_be_bytes(buf)
        }
    };
    if s.scalar.is_signed() {
        let shift = 64 - 8 * bytes.len() as u32;
        Value::Signed(((raw << shift) as i64) >> shift)
    } else {
        Value::Unsigned(raw)
    }
}

fn put(s: &Src, bytes: &[u8], row: &mut [Value]) {
    let size = s.scalar.size();
    for k in 0..s.count {
        let at = s.offset + k * size;
        row[s.column + k] = scalar(s, &bytes[at..at + size]);
    }
}

fn fold(s: &Src, bytes: &[u8], row: &mut [Value]) {
    let size = s.scalar.size();
    for k in 0..s.count {
        let at = s.offset + k * size;
        let new = scalar(s, &bytes[at..at + size]);
        let acc = &mut row[s.column + k];
        *acc = match (*acc, new) {
            (Value::Unsigned(x), Value::Unsigned(y)) => Value::Unsigned(match s.merge {
                Merge::Sum => x.wrapping_add(y),
                Merge::Min => x.min(y),
                Merge::Max => x.max(y),
                Merge::Or => x | y,
                Merge::First => x,
            }),
            (Value::Signed(x), Value::Signed(y)) => Value::Signed(match s.merge {
                Merge::Sum => x.wrapping_add(y),
                Merge::Min => x.min(y),
                Merge::Max => x.max(y),
                Merge::Or => x | y,
                Merge::First => x,
            }),
            (kept, _) => kept,
        };
    }
}

#[cfg(test)]
pub(crate) mod tests;
