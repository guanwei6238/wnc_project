//! The read path of wnc-gw before the plan (2026-11-19), kept as the reference the plan is
//! checked against and the baseline it is timed against.
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use security_gateway::features::definition::{Definition, Endian, Field, Layout, Merge, Op, Scalar};

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    Address(IpAddr),
    List(Vec<Value>),
    Text(String),
    Null,
}

impl Value {
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::Value as J;
        match self {
            Self::Unsigned(v) => J::from(*v),
            Self::Signed(v) => J::from(*v),
            Self::Float(v) => serde_json::Number::from_f64(*v).map_or(J::Null, J::Number),
            Self::Address(a) => J::String(a.to_string()),
            Self::List(items) => J::Array(items.iter().map(Self::to_json).collect()),
            Self::Text(t) => J::String(t.clone()),
            Self::Null => J::Null,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct LengthMismatch {
    pub expected: usize,
    pub got: usize,
}

pub fn decode(layout: &Layout, bytes: &[u8]) -> Result<Vec<Value>, LengthMismatch> {
    if bytes.len() != layout.size {
        return Err(LengthMismatch { expected: layout.size, got: bytes.len() });
    }
    Ok(layout.fields.iter().map(|field| decode_field(field, &bytes[field.offset..field.offset + field.size()])).collect())
}

fn decode_field(field: &Field, bytes: &[u8]) -> Value {
    match field.len {
        Some(_) => Value::List(
            bytes.chunks_exact(field.scalar.size()).map(|chunk| scalar(field.scalar, field.endian, chunk)).collect(),
        ),
        None => scalar(field.scalar, field.endian, bytes),
    }
}

fn scalar(kind: Scalar, endian: Endian, bytes: &[u8]) -> Value {
    if kind == Scalar::Ipv4 {
        return Value::Address(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap())));
    }
    if kind == Scalar::Ipv6 {
        return Value::Address(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap())));
    }
    let mut buf = [0u8; 8];
    match endian {
        Endian::Little => buf[..bytes.len()].copy_from_slice(bytes),
        Endian::Big => buf[8 - bytes.len()..].copy_from_slice(bytes),
    }
    let raw = match endian {
        Endian::Little => u64::from_le_bytes(buf),
        Endian::Big => u64::from_be_bytes(buf),
    };
    if kind.is_signed() {
        let shift = 64 - 8 * bytes.len() as u32;
        Value::Signed(((raw << shift) as i64) >> shift)
    } else {
        Value::Unsigned(raw)
    }
}

/// Merges the copies a per-CPU map keeps, one per CPU. A CPU that never wrote the entry
/// leaves it all zero, so those copies are skipped (otherwise min would always be 0).
pub fn merge(layout: &Layout, per_cpu: &[&[u8]]) -> Result<Vec<Value>, LengthMismatch> {
    let written: Vec<&[u8]> = per_cpu.iter().copied().filter(|b| b.iter().any(|&x| x != 0)).collect();
    let copies = if written.is_empty() { &per_cpu[..per_cpu.len().min(1)] } else { &written[..] };
    let decoded = copies.iter().map(|bytes| decode(layout, bytes)).collect::<Result<Vec<_>, _>>()?;
    let Some((first, rest)) = decoded.split_first() else {
        return Err(LengthMismatch { expected: layout.size, got: 0 });
    };
    let mut out = first.clone();
    for copy in rest {
        for ((field, acc), value) in layout.fields.iter().zip(out.iter_mut()).zip(copy) {
            *acc = combine(field.merge.unwrap_or(Merge::First), acc, value);
        }
    }
    Ok(out)
}

fn combine(merge: Merge, a: &Value, b: &Value) -> Value {
    match (a, b) {
        (Value::List(x), Value::List(y)) => Value::List(x.iter().zip(y).map(|(p, q)| combine(merge, p, q)).collect()),
        (Value::Unsigned(x), Value::Unsigned(y)) => Value::Unsigned(match merge {
            Merge::Sum => x.wrapping_add(*y),
            Merge::Min => *x.min(y),
            Merge::Max => *x.max(y),
            Merge::Or => x | y,
            Merge::First => *x,
        }),
        (Value::Signed(x), Value::Signed(y)) => Value::Signed(match merge {
            Merge::Sum => x.wrapping_add(*y),
            Merge::Min => *x.min(y),
            Merge::Max => *x.max(y),
            Merge::Or => x | y,
            Merge::First => *x,
        }),
        _ => a.clone(),
    }
}

pub struct Reading {
    pub key_bytes: Vec<u8>,
    pub fields: Vec<Value>,
}

#[derive(Debug, Default)]
pub struct Deriver {
    previous: HashMap<Vec<u8>, (Instant, Vec<Value>)>,
}

impl Deriver {
    /// Appends the derived fields to each reading. `readings` is one full read of the map:
    /// keys that are missing from it are forgotten, so delta and rate start over if they come back.
    pub fn round(&mut self, definition: &Definition, readings: &mut [Reading], now: Instant) {
        let mut next = HashMap::with_capacity(readings.len());
        for reading in readings.iter_mut() {
            let before = self.previous.get(&reading.key_bytes);
            for derived in &definition.derived {
                let value = eval(&derived.op, &reading.fields, before, now);
                reading.fields.push(value);
            }
            if definition.derived.iter().any(|d| matches!(d.op, Op::Delta(_) | Op::Rate(_))) {
                next.insert(reading.key_bytes.clone(), (now, reading.fields.clone()));
            }
        }
        self.previous = next;
    }
}

#[derive(Clone, Copy)]
enum Num {
    Int(i128),
    Float(f64),
}

impl Num {
    fn of(value: &Value) -> Option<Self> {
        match value {
            Value::Unsigned(v) => Some(Self::Int(*v as i128)),
            Value::Signed(v) => Some(Self::Int(*v as i128)),
            Value::Float(v) if v.is_finite() => Some(Self::Float(*v)),
            _ => None,
        }
    }

    fn float(self) -> f64 {
        match self {
            Self::Int(v) => v as f64,
            Self::Float(v) => v,
        }
    }

    fn value(self) -> Value {
        match self {
            Self::Int(v) => u64::try_from(v)
                .map(Value::Unsigned)
                .or_else(|_| i64::try_from(v).map(Value::Signed))
                .unwrap_or(Value::Float(v as f64)),
            Self::Float(v) if v.is_finite() => Value::Float(v),
            Self::Float(_) => Value::Null,
        }
    }
}

fn int_op(a: Num, b: Num, int: fn(i128, i128) -> Option<i128>, float: fn(f64, f64) -> f64) -> Value {
    match (a, b) {
        (Num::Int(x), Num::Int(y)) => int(x, y).map_or(Value::Null, |v| Num::Int(v).value()),
        _ => Num::Float(float(a.float(), b.float())).value(),
    }
}

fn eval(op: &Op, fields: &[Value], before: Option<&(Instant, Vec<Value>)>, now: Instant) -> Value {
    let n = |i: usize| Num::of(&fields[i]);
    let f = |v: f64| Num::Float(v).value();
    let moments = |sum, sumsq, count| -> Option<(f64, f64)> {
        let count = n(count)?.float();
        if count <= 0.0 {
            return None;
        }
        let mean = n(sum)?.float() / count;
        Some((mean, (n(sumsq)?.float() / count - mean * mean).max(0.0)))
    };
    let change = |i: usize| -> Option<(Num, f64)> {
        let (at, old) = before?;
        let (new, old) = (n(i)?, Num::of(old.get(i)?)?);
        let delta = match (new, old) {
            (Num::Int(a), Num::Int(b)) if a >= b => Num::Int(a - b),
            (Num::Int(_), Num::Int(_)) => return None,
            (a, b) => Num::Float(a.float() - b.float()),
        };
        Some((delta, now.duration_since(*at).as_secs_f64()))
    };
    let result = match op {
        Op::Add(a, b) => n(*a).zip(n(*b)).map(|(x, y)| int_op(x, y, i128::checked_add, |p, q| p + q)),
        Op::Sub(a, b) => n(*a).zip(n(*b)).map(|(x, y)| int_op(x, y, i128::checked_sub, |p, q| p - q)),
        Op::Mul(a, b) => n(*a).zip(n(*b)).map(|(x, y)| int_op(x, y, i128::checked_mul, |p, q| p * q)),
        Op::Div(a, b) | Op::Mean { sum: a, count: b } => n(*a)
            .zip(n(*b))
            .filter(|(_, y)| y.float() != 0.0)
            .map(|(x, y)| f(x.float() / y.float())),
        Op::Var { sum, sumsq, count } => moments(*sum, *sumsq, *count).map(|(_, var)| f(var)),
        Op::Std { sum, sumsq, count } => moments(*sum, *sumsq, *count).map(|(_, var)| f(var.sqrt())),
        Op::Delta(i) => change(*i).map(|(delta, _)| delta.value()),
        Op::Rate(i) => change(*i).filter(|(_, secs)| *secs > 0.0).map(|(delta, secs)| f(delta.float() / secs)),
        Op::Scale { of, by } => n(*of).map(|x| f(x.float() * by)),
        Op::Bucket { of, edges } => n(*of).map(|x| Value::Unsigned(edges.iter().filter(|e| x.float() >= **e).count() as u64)),
        Op::Percentile { of, p, bounds } => percentile(&fields[*of], *p, bounds).map(f),
        Op::Enum { of, values, other } => match n(*of) {
            Some(Num::Int(v)) => values.get(&v).or(other.as_ref()).map(|label| Value::Text(label.clone())),
            _ => None,
        },
    };
    result.unwrap_or(Value::Null)
}

fn percentile(list: &Value, p: f64, bounds: &[f64]) -> Option<f64> {
    let Value::List(counts) = list else { return None };
    let counts: Vec<f64> = counts.iter().map(|c| Num::of(c).map_or(0.0, Num::float)).collect();
    let total: f64 = counts.iter().sum();
    if total <= 0.0 {
        return None;
    }
    let target = total * p / 100.0;
    let mut seen = 0.0;
    counts.iter().zip(bounds).find_map(|(count, bound)| {
        seen += count;
        (seen >= target).then_some(*bound)
    })
}

pub fn table_readings(definition: &Definition, entries: Vec<Entry>, per_cpu: bool, skip_zero: bool) -> (Vec<Reading>, u64) {
    let mut readings = Vec::with_capacity(entries.len());
    let mut bad = 0;
    for entry in entries {
        if skip_zero && entry.values.iter().all(|v| v.iter().all(|&b| b == 0)) {
            continue;
        }
        let copies: Vec<&[u8]> = entry.values.iter().map(Vec::as_slice).collect();
        let value = if per_cpu { merge(&definition.value, &copies) } else { decode(&definition.value, copies[0]) };
        let key = definition.key.as_ref().map(|k| decode(k, &entry.key)).transpose();
        match (key, value) {
            (Ok(key), Ok(value)) => {
                let mut fields = key.unwrap_or_default();
                fields.extend(value);
                readings.push(Reading { key_bytes: entry.key, fields });
            }
            _ => bad += 1,
        }
    }
    (readings, bad)
}


/// Field names come from the definition, which only allows lowercase letters, digits and _, so
/// they need no escaping.
pub fn json_line(feature: &str, names: &[&str], reading: &Reading, ts_ms: u128) -> String {
    let mut line = format!("{{\"ts_ms\":{ts_ms},\"feature\":{}", serde_json::Value::from(feature));
    for (name, value) in names.iter().zip(&reading.fields) {
        line.push_str(&format!(",\"{name}\":{}", value.to_json()));
    }
    line.push_str("}\n");
    line
}

pub struct Entry {
    pub key: Vec<u8>,
    pub values: Vec<Vec<u8>>,
}

#[repr(C)]
#[derive(Default)]
struct ElemAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value_or_next_key: u64,
    flags: u64,
}

fn elem(cmd: libc::c_long, fd: i32, key: u64, out: u64) -> bool {
    let mut attr = ElemAttr { map_fd: fd as u32, key, value_or_next_key: out, ..Default::default() };
    let r = unsafe { libc::syscall(libc::SYS_bpf, cmd, &mut attr as *mut ElemAttr, size_of::<ElemAttr>() as libc::c_uint) };
    if r < 0 {
        let e = std::io::Error::last_os_error();
        assert_eq!(e.raw_os_error(), Some(libc::ENOENT), "bpf failed: {e}");
    }
    r >= 0
}

/// Table::read as it was: GET_NEXT_KEY + LOOKUP_ELEM, new buffers for every entry.
pub fn read(fd: i32, key_size: usize, value_size: usize, cpus: usize, per_cpu: bool, limit: usize) -> Vec<Entry> {
    let slot = if per_cpu { value_size.next_multiple_of(8) } else { value_size };
    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    let mut key: Option<Vec<u8>> = None;
    while entries.len() < limit {
        let mut next = vec![0u8; key_size];
        let found = elem(4, fd, key.as_ref().map_or(0, |k| k.as_ptr() as u64), next.as_mut_ptr() as u64);
        if !found || !seen.insert(next.clone()) {
            break;
        }
        let mut buf = vec![0u8; slot * cpus];
        if elem(1, fd, next.as_ptr() as u64, buf.as_mut_ptr() as u64) {
            let values = buf.chunks_exact(slot).map(|c| c[..value_size].to_vec()).collect();
            entries.push(Entry { key: next.clone(), values });
        }
        key = Some(next);
    }
    entries
}
