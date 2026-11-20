use std::collections::HashMap;
use std::time::Instant;

use super::definition::{Definition, Op};
use super::record::{Columns, Records, Value};

/// An operand: the column of a field that holds a number, or None for an array, which never does.
type Arg = Option<usize>;

enum Step {
    Add(Arg, Arg),
    Sub(Arg, Arg),
    Mul(Arg, Arg),
    Div(Arg, Arg),
    Moments { sum: Arg, sumsq: Arg, count: Arg, std: bool },
    /// The column now and where its previous value is kept.
    Delta(Arg, Option<usize>),
    Rate(Arg, Option<usize>),
    Scale(Arg, f64),
    Bucket(Arg, Vec<f64>),
    /// The array's first column and length.
    Percentile(Option<(usize, usize)>, f64, Vec<f64>),
    Enum(Arg, HashMap<i128, u32>, Option<u32>),
}

/// The derived fields compiled into steps that each fill one column of a row.
pub struct Deriver {
    steps: Vec<(Step, usize)>,
    /// Columns that delta and rate compare with the previous read of the same key.
    keep: Vec<usize>,
    labels: Vec<String>,
    previous: History,
    next: History,
    previous_at: Option<Instant>,
}

impl Deriver {
    pub fn new(definition: &Definition, columns: &Columns) -> Self {
        let base = columns.start.len() - definition.derived.len();
        let arg = |i: usize| columns.number(i);
        let mut keep: Vec<usize> = Vec::new();
        let mut kept = |i: usize| {
            let column = arg(i)?;
            Some(keep.iter().position(|&k| k == column).unwrap_or_else(|| {
                keep.push(column);
                keep.len() - 1
            }))
        };
        let mut labels: Vec<String> = Vec::new();
        let mut label = |text: &String| {
            labels.push(text.clone());
            labels.len() as u32 - 1
        };
        let steps = definition
            .derived
            .iter()
            .enumerate()
            .map(|(j, d)| {
                let step = match &d.op {
                    Op::Add(a, b) => Step::Add(arg(*a), arg(*b)),
                    Op::Sub(a, b) => Step::Sub(arg(*a), arg(*b)),
                    Op::Mul(a, b) => Step::Mul(arg(*a), arg(*b)),
                    Op::Div(a, b) | Op::Mean { sum: a, count: b } => Step::Div(arg(*a), arg(*b)),
                    Op::Var { sum, sumsq, count } => Step::Moments { sum: arg(*sum), sumsq: arg(*sumsq), count: arg(*count), std: false },
                    Op::Std { sum, sumsq, count } => Step::Moments { sum: arg(*sum), sumsq: arg(*sumsq), count: arg(*count), std: true },
                    Op::Delta(i) => Step::Delta(arg(*i), kept(*i)),
                    Op::Rate(i) => Step::Rate(arg(*i), kept(*i)),
                    Op::Scale { of, by } => Step::Scale(arg(*of), *by),
                    Op::Bucket { of, edges } => Step::Bucket(arg(*of), edges.clone()),
                    Op::Percentile { of, p, bounds } => {
                        Step::Percentile(columns.list[*of].map(|n| (columns.start[*of], n)), *p, bounds.clone())
                    }
                    Op::Enum { of, values, other } => {
                        let values = values.iter().map(|(k, v)| (*k, label(v))).collect();
                        Step::Enum(arg(*of), values, other.as_ref().map(&mut label))
                    }
                };
                (step, columns.start[base + j])
            })
            .collect();
        Self { steps, keep, labels, previous: History::default(), next: History::default(), previous_at: None }
    }

    /// The text of a Value::Label.
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// Fills the derived columns of each row. `rows` holds `width` columns per row, and row r
    /// came from record `from[r]`. One call is one full read of the map: keys missing from it
    /// are forgotten, so delta and rate start over if they come back.
    pub fn round<R: Records + ?Sized>(&mut self, records: &R, from: &[u32], rows: &mut [Value], width: usize, now: Instant) {
        let track = !self.keep.is_empty();
        if track {
            let key_size = from.first().map_or(0, |&n| records.key(n as usize).len());
            self.next.reset(from.len(), key_size, self.keep.len());
        }
        let seconds = self.previous_at.map_or(0.0, |at| now.duration_since(at).as_secs_f64());
        for (row, &n) in rows.chunks_exact_mut(width.max(1)).zip(from) {
            let key = records.key(n as usize);
            let before = if track { self.previous.find(key) } else { None };
            for (step, column) in &self.steps {
                row[*column] = eval(step, row, before, seconds);
            }
            if track {
                self.next.insert(key, self.keep.iter().map(|&c| row[c]));
            }
        }
        std::mem::swap(&mut self.previous, &mut self.next);
        self.previous_at = Some(now);
    }
}

#[derive(Clone, Copy)]
enum Num {
    Int(i128),
    Float(f64),
}

impl Num {
    fn of(value: Value) -> Option<Self> {
        match value {
            Value::Unsigned(v) => Some(Self::Int(v as i128)),
            Value::Signed(v) => Some(Self::Int(v as i128)),
            Value::Float(v) if v.is_finite() => Some(Self::Float(v)),
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

fn eval(step: &Step, row: &[Value], before: Option<&[Value]>, seconds: f64) -> Value {
    let n = |a: Arg| Num::of(row[a?]);
    let f = |v: f64| Num::Float(v).value();
    let change = |a: Arg, slot: Option<usize>| -> Option<Num> {
        let (new, old) = (n(a)?, Num::of(before?[slot?])?);
        match (new, old) {
            (Num::Int(x), Num::Int(y)) if x >= y => Some(Num::Int(x - y)),
            (Num::Int(_), Num::Int(_)) => None,
            (x, y) => Some(Num::Float(x.float() - y.float())),
        }
    };
    let result = match step {
        Step::Add(a, b) => n(*a).zip(n(*b)).map(|(x, y)| int_op(x, y, i128::checked_add, |p, q| p + q)),
        Step::Sub(a, b) => n(*a).zip(n(*b)).map(|(x, y)| int_op(x, y, i128::checked_sub, |p, q| p - q)),
        Step::Mul(a, b) => n(*a).zip(n(*b)).map(|(x, y)| int_op(x, y, i128::checked_mul, |p, q| p * q)),
        Step::Div(a, b) => n(*a).zip(n(*b)).filter(|(_, y)| y.float() != 0.0).map(|(x, y)| f(x.float() / y.float())),
        Step::Moments { sum, sumsq, count, std } => (|| {
            let count = n(*count)?.float();
            if count <= 0.0 {
                return None;
            }
            let mean = n(*sum)?.float() / count;
            let var = (n(*sumsq)?.float() / count - mean * mean).max(0.0);
            Some(f(if *std { var.sqrt() } else { var }))
        })(),
        Step::Delta(a, slot) => change(*a, *slot).map(Num::value),
        Step::Rate(a, slot) => change(*a, *slot).filter(|_| seconds > 0.0).map(|d| f(d.float() / seconds)),
        Step::Scale(a, by) => n(*a).map(|x| f(x.float() * by)),
        Step::Bucket(a, edges) => n(*a).map(|x| Value::Unsigned(edges.iter().filter(|e| x.float() >= **e).count() as u64)),
        Step::Percentile(list, p, bounds) => list.and_then(|(start, len)| {
            let counts = &row[start..start + len];
            let count = |v: &Value| Num::of(*v).map_or(0.0, Num::float);
            let total: f64 = counts.iter().map(count).sum();
            if total <= 0.0 {
                return None;
            }
            let target = total * p / 100.0;
            let mut seen = 0.0;
            counts.iter().zip(bounds).find_map(|(c, bound)| {
                seen += count(c);
                (seen >= target).then(|| f(*bound))
            })
        }),
        Step::Enum(a, values, other) => match n(*a) {
            Some(Num::Int(v)) => values.get(&v).or(other.as_ref()).map(|i| Value::Label(*i)),
            _ => None,
        },
    };
    result.unwrap_or(Value::Null)
}

/// The kept columns of the previous read by key: open addressing over buffers that keep their
/// capacity, rebuilt every read.
#[derive(Default)]
struct History {
    keys: Vec<u8>,
    values: Vec<Value>,
    slots: Vec<u32>,
    key_size: usize,
    stride: usize,
    len: u32,
}

const EMPTY: u32 = u32::MAX;

impl History {
    fn reset(&mut self, rows: usize, key_size: usize, stride: usize) {
        self.slots.clear();
        self.slots.resize((rows * 2).next_power_of_two().max(16), EMPTY);
        self.keys.clear();
        self.values.clear();
        self.key_size = key_size;
        self.stride = stride;
        self.len = 0;
    }

    fn find(&self, key: &[u8]) -> Option<&[Value]> {
        if self.slots.is_empty() || key.len() != self.key_size {
            return None;
        }
        let mask = self.slots.len() - 1;
        let mut i = hash(key) & mask;
        loop {
            let s = self.slots[i];
            if s == EMPTY {
                return None;
            }
            let s = s as usize;
            if &self.keys[s * self.key_size..(s + 1) * self.key_size] == key {
                return Some(&self.values[s * self.stride..(s + 1) * self.stride]);
            }
            i = (i + 1) & mask;
        }
    }

    fn insert(&mut self, key: &[u8], values: impl Iterator<Item = Value>) {
        let mask = self.slots.len() - 1;
        let mut i = hash(key) & mask;
        while self.slots[i] != EMPTY {
            i = (i + 1) & mask;
        }
        self.slots[i] = self.len;
        self.keys.extend_from_slice(key);
        self.values.extend(values);
        self.len += 1;
    }
}

fn hash(key: &[u8]) -> usize {
    let mut h: u64 = 0;
    for chunk in key.chunks(8) {
        let mut b = [0u8; 8];
        b[..chunk.len()].copy_from_slice(chunk);
        h = (h.rotate_left(5) ^ u64::from_le_bytes(b)).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
    (h ^ (h >> 29)) as usize
}

#[cfg(test)]
mod tests;
