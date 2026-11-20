//! The definition compiled once into a plan: decode, merge, derive and format straight from the
//! map's bytes into buffers that are reused every round.
use std::collections::HashMap;
use std::io::Write;
use std::net::Ipv6Addr;
use std::time::Instant;

use security_gateway::features::definition::{Definition, Endian, Field, Merge, Op, Scalar};
use crate::read::Source;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Cell {
    U(u64),
    I(i64),
    F(f64),
    V4([u8; 4]),
    V6([u8; 16]),
    T(u32),
    Null,
}

struct Src {
    offset: usize,
    scalar: Scalar,
    endian: Endian,
    merge: Merge,
    count: usize,
    cell: usize,
}

struct Col {
    prefix: Vec<u8>,
    start: usize,
    list: Option<usize>,
}

/// An operand is the cell of a field that holds a number, or None for an array, which never does.
type Arg = Option<usize>;

enum Step {
    Add(Arg, Arg),
    Sub(Arg, Arg),
    Mul(Arg, Arg),
    Div(Arg, Arg),
    Moments { sum: Arg, sumsq: Arg, count: Arg, std: bool },
    Delta(Arg, Option<usize>),
    Rate(Arg, Option<usize>),
    Scale(Arg, f64),
    Bucket(Arg, Vec<f64>),
    Percentile(Option<(usize, usize)>, f64, Vec<f64>),
    Enum(Arg, HashMap<i128, u32>, Option<u32>),
}

pub struct Plan {
    key: Vec<Src>,
    value: Vec<Src>,
    key_size: Option<usize>,
    value_size: usize,
    per_cpu: bool,
    skip_zero: bool,
    width: usize,
    steps: Vec<(Step, usize)>,
    keep: Vec<usize>,
    cols: Vec<Col>,
    payload: Vec<u8>,
    record: usize,
    feature: Vec<u8>,
    labels: Vec<Vec<u8>>,
    cells: Vec<Cell>,
    rows: Vec<u32>,
    prev: Prev,
    next: Prev,
    prev_at: Option<Instant>,
    pub bad: u64,
}

impl Plan {
    pub fn new(def: &Definition, feature: &str, per_cpu: bool, skip_zero: bool) -> Self {
        let base: Vec<&Field> = def.key.iter().flat_map(|k| &k.fields).chain(&def.value.fields).collect();
        let mut width = 0;
        let mut starts = Vec::new();
        let mut lists = Vec::new();
        let mut payload = Vec::new();
        for f in &base {
            starts.push(width);
            lists.push(f.len.map(|n| n as usize));
            let w = match f.scalar {
                Scalar::Ipv4 => 4,
                Scalar::Ipv6 => 16,
                _ => 8,
            };
            payload.extend(std::iter::repeat_n(w, f.len.unwrap_or(1) as usize));
            width += f.len.unwrap_or(1) as usize;
        }
        let nkey = def.key.as_ref().map_or(0, |k| k.fields.len());
        let src = |f: &Field, cell: usize| Src {
            offset: f.offset,
            scalar: f.scalar,
            endian: f.endian,
            merge: f.merge.unwrap_or(Merge::First),
            count: f.len.unwrap_or(1) as usize,
            cell,
        };
        let key = base[..nkey].iter().zip(&starts).map(|(f, &c)| src(f, c)).collect();
        let value = base[nkey..].iter().zip(&starts[nkey..]).map(|(f, &c)| src(f, c)).collect();
        for _ in &def.derived {
            starts.push(width);
            lists.push(None);
            payload.push(8);
            width += 1;
        }
        let arg = |i: usize| if lists[i].is_some() { None } else { Some(starts[i]) };
        let mut keep: Vec<usize> = Vec::new();
        let mut kept = |i: usize| {
            let c = arg(i)?;
            Some(keep.iter().position(|&k| k == c).unwrap_or_else(|| {
                keep.push(c);
                keep.len() - 1
            }))
        };
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut label = |s: &String| {
            labels.push(serde_json::to_string(s).unwrap().into_bytes());
            labels.len() as u32 - 1
        };
        let steps = def
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
                    Op::Percentile { of, p, bounds } => Step::Percentile(lists[*of].map(|n| (starts[*of], n)), *p, bounds.clone()),
                    Op::Enum { of, values, other } => {
                        Step::Enum(arg(*of), values.iter().map(|(k, v)| (*k, label(v))).collect(), other.as_ref().map(&mut label))
                    }
                };
                (step, starts[base.len() + j])
            })
            .collect();
        let cols = def
            .names()
            .enumerate()
            .map(|(i, name)| Col { prefix: format!(",\"{name}\":").into_bytes(), start: starts[i], list: lists[i] })
            .collect();
        let record = width + payload.iter().map(|&w| w as usize).sum::<usize>();
        Self {
            key,
            value,
            key_size: def.key.as_ref().map(|k| k.size),
            value_size: def.value.size,
            per_cpu,
            skip_zero,
            width,
            steps,
            keep,
            cols,
            payload,
            record,
            feature: serde_json::to_string(feature).unwrap().into_bytes(),
            labels,
            cells: Vec::new(),
            rows: Vec::new(),
            prev: Prev::default(),
            next: Prev::default(),
            prev_at: None,
            bad: 0,
        }
    }

    pub fn rows(&self) -> usize {
        self.rows.len()
    }

    pub fn decode<S: Source + ?Sized>(&mut self, src: &S) {
        self.cells.clear();
        self.rows.clear();
        self.bad = 0;
        for n in 0..src.len() {
            let copies = src.copies(n);
            if self.skip_zero && (0..copies).all(|c| src.copy(n, c).iter().all(|&b| b == 0)) {
                continue;
            }
            let key = src.key(n);
            if self.key_size.is_some_and(|k| key.len() != k) || copies == 0 || (0..copies).any(|c| src.copy(n, c).len() != self.value_size) {
                self.bad += 1;
                continue;
            }
            let base = self.cells.len();
            self.cells.resize(base + self.width, Cell::Null);
            let row = &mut self.cells[base..];
            for s in &self.key {
                put(s, key, row);
            }
            let mut first = true;
            if self.per_cpu {
                for v in (0..copies).map(|c| src.copy(n, c)).filter(|v| v.iter().any(|&b| b != 0)) {
                    for s in &self.value {
                        if first {
                            put(s, v, row);
                        } else {
                            fold(s, v, row);
                        }
                    }
                    first = false;
                }
            }
            if first {
                for s in &self.value {
                    put(s, src.copy(n, 0), row);
                }
            }
            self.rows.push(n as u32);
        }
    }

    pub fn derive<S: Source + ?Sized>(&mut self, src: &S, now: Instant) {
        let track = !self.keep.is_empty();
        let key_size = if src.len() > 0 { src.key(0).len() } else { 0 };
        if track {
            self.next.reset(self.rows.len(), key_size, self.keep.len());
        }
        let secs = self.prev_at.map_or(0.0, |at| now.duration_since(at).as_secs_f64());
        let w = self.width;
        for (r, &n) in self.rows.iter().enumerate() {
            let key = src.key(n as usize);
            let before = if track { self.prev.find(key) } else { None };
            let row = &mut self.cells[r * w..(r + 1) * w];
            for (step, out) in &self.steps {
                row[*out] = eval(step, row, before, secs);
            }
            if track {
                self.next.insert(key, self.keep.iter().map(|&c| row[c]));
            }
        }
        if track {
            std::mem::swap(&mut self.prev, &mut self.next);
            self.prev_at = Some(now);
        }
    }

    pub fn json(&self, out: &mut Vec<u8>, ts_ms: u64) {
        let mut int = itoa::Buffer::new();
        let ts = int.format(ts_ms).as_bytes().to_vec();
        for row in self.cells.chunks_exact(self.width.max(1)).take(self.rows.len()) {
            out.extend_from_slice(b"{\"ts_ms\":");
            out.extend_from_slice(&ts);
            out.extend_from_slice(b",\"feature\":");
            out.extend_from_slice(&self.feature);
            for c in &self.cols {
                out.extend_from_slice(&c.prefix);
                match c.list {
                    None => self.cell_json(row[c.start], out),
                    Some(n) => {
                        out.push(b'[');
                        for (k, cell) in row[c.start..c.start + n].iter().enumerate() {
                            if k > 0 {
                                out.push(b',');
                            }
                            self.cell_json(*cell, out);
                        }
                        out.push(b']');
                    }
                }
            }
            out.extend_from_slice(b"}\n");
        }
    }

    fn cell_json(&self, cell: Cell, out: &mut Vec<u8>) {
        match cell {
            Cell::U(v) => out.extend_from_slice(itoa::Buffer::new().format(v).as_bytes()),
            Cell::I(v) => out.extend_from_slice(itoa::Buffer::new().format(v).as_bytes()),
            Cell::F(v) => out.extend_from_slice(zmij::Buffer::new().format_finite(v).as_bytes()),
            Cell::V4(a) => {
                out.push(b'"');
                for (k, octet) in a.iter().enumerate() {
                    if k > 0 {
                        out.push(b'.');
                    }
                    out.extend_from_slice(itoa::Buffer::new().format(*octet).as_bytes());
                }
                out.push(b'"');
            }
            Cell::V6(a) => {
                let _ = write!(out, "\"{}\"", Ipv6Addr::from(a));
            }
            Cell::T(i) => out.extend_from_slice(&self.labels[i as usize]),
            Cell::Null => out.extend_from_slice(b"null"),
        }
    }

    /// Header: "WFB1", ts_ms u64, rows u32, cells per row u32; then per row one tag byte per
    /// cell followed by the payloads, 4 or 16 bytes for an address column and 8 otherwise.
    pub fn binary(&self, out: &mut Vec<u8>, ts_ms: u64) {
        out.extend_from_slice(b"WFB1");
        out.extend_from_slice(&ts_ms.to_le_bytes());
        out.extend_from_slice(&(self.rows.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.width as u32).to_le_bytes());
        let mut at = out.len();
        out.resize(at + self.record * self.rows.len(), 0);
        for row in self.cells.chunks_exact(self.width.max(1)).take(self.rows.len()) {
            let (tags, mut body) = out[at..at + self.record].split_at_mut(self.width);
            for ((cell, tag), &w) in row.iter().zip(tags.iter_mut()).zip(&self.payload) {
                let (dst, rest) = body.split_at_mut(w as usize);
                body = rest;
                *tag = match *cell {
                    Cell::U(v) => {
                        dst.copy_from_slice(&v.to_le_bytes());
                        1
                    }
                    Cell::I(v) => {
                        dst.copy_from_slice(&v.to_le_bytes());
                        2
                    }
                    Cell::F(v) => {
                        dst.copy_from_slice(&v.to_le_bytes());
                        3
                    }
                    Cell::V4(a) => {
                        dst.copy_from_slice(&a);
                        4
                    }
                    Cell::V6(a) => {
                        dst.copy_from_slice(&a);
                        5
                    }
                    Cell::T(i) => {
                        dst.copy_from_slice(&(i as u64).to_le_bytes());
                        6
                    }
                    Cell::Null => 0,
                };
            }
            at += self.record;
        }
    }

    /// Reads back what binary wrote and prints it as JSON lines, to check the two agree.
    pub fn binary_to_json(&self, bytes: &[u8]) -> Vec<u8> {
        assert_eq!(&bytes[..4], b"WFB1", "bad magic");
        let ts = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
        let rows = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
        assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize, self.width, "width differs");
        let mut cells = Vec::with_capacity(rows * self.width);
        for rec in bytes[20..].chunks_exact(self.record) {
            let (tags, mut body) = rec.split_at(self.width);
            for (tag, &w) in tags.iter().zip(&self.payload) {
                let (src, rest) = body.split_at(w as usize);
                body = rest;
                let u = || u64::from_le_bytes(src.try_into().unwrap());
                cells.push(match tag {
                    1 => Cell::U(u()),
                    2 => Cell::I(u() as i64),
                    3 => Cell::F(f64::from_bits(u())),
                    4 => Cell::V4(src.try_into().unwrap()),
                    5 => Cell::V6(src.try_into().unwrap()),
                    6 => Cell::T(u() as u32),
                    _ => Cell::Null,
                });
            }
        }
        let view = Self { cells, rows: (0..rows as u32).collect(), ..self.shell() };
        let mut out = Vec::new();
        view.json(&mut out, ts);
        out
    }

    fn shell(&self) -> Self {
        Self {
            key: Vec::new(),
            value: Vec::new(),
            key_size: None,
            value_size: 0,
            per_cpu: false,
            skip_zero: false,
            width: self.width,
            steps: Vec::new(),
            keep: Vec::new(),
            cols: self.cols.iter().map(|c| Col { prefix: c.prefix.clone(), start: c.start, list: c.list }).collect(),
            payload: self.payload.clone(),
            record: self.record,
            feature: self.feature.clone(),
            labels: self.labels.clone(),
            cells: Vec::new(),
            rows: Vec::new(),
            prev: Prev::default(),
            next: Prev::default(),
            prev_at: None,
            bad: 0,
        }
    }
}

fn scalar(s: &Src, bytes: &[u8]) -> Cell {
    match s.scalar {
        Scalar::Ipv4 => return Cell::V4(bytes.try_into().unwrap()),
        Scalar::Ipv6 => return Cell::V6(bytes.try_into().unwrap()),
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
        Cell::I(((raw << shift) as i64) >> shift)
    } else {
        Cell::U(raw)
    }
}

fn put(s: &Src, bytes: &[u8], row: &mut [Cell]) {
    let size = s.scalar.size();
    for k in 0..s.count {
        let at = s.offset + k * size;
        row[s.cell + k] = scalar(s, &bytes[at..at + size]);
    }
}

fn fold(s: &Src, bytes: &[u8], row: &mut [Cell]) {
    let size = s.scalar.size();
    for k in 0..s.count {
        let at = s.offset + k * size;
        let b = scalar(s, &bytes[at..at + size]);
        let a = &mut row[s.cell + k];
        *a = match (*a, b) {
            (Cell::U(x), Cell::U(y)) => Cell::U(match s.merge {
                Merge::Sum => x.wrapping_add(y),
                Merge::Min => x.min(y),
                Merge::Max => x.max(y),
                Merge::Or => x | y,
                Merge::First => x,
            }),
            (Cell::I(x), Cell::I(y)) => Cell::I(match s.merge {
                Merge::Sum => x.wrapping_add(y),
                Merge::Min => x.min(y),
                Merge::Max => x.max(y),
                Merge::Or => x | y,
                Merge::First => x,
            }),
            (keep, _) => keep,
        };
    }
}

#[derive(Clone, Copy)]
enum Num {
    Int(i128),
    Float(f64),
}

impl Num {
    fn of(cell: Cell) -> Option<Self> {
        match cell {
            Cell::U(v) => Some(Self::Int(v as i128)),
            Cell::I(v) => Some(Self::Int(v as i128)),
            Cell::F(v) if v.is_finite() => Some(Self::Float(v)),
            _ => None,
        }
    }

    fn float(self) -> f64 {
        match self {
            Self::Int(v) => v as f64,
            Self::Float(v) => v,
        }
    }

    fn cell(self) -> Cell {
        match self {
            Self::Int(v) => u64::try_from(v).map(Cell::U).or_else(|_| i64::try_from(v).map(Cell::I)).unwrap_or(Cell::F(v as f64)),
            Self::Float(v) if v.is_finite() => Cell::F(v),
            Self::Float(_) => Cell::Null,
        }
    }
}

fn int_op(a: Num, b: Num, int: fn(i128, i128) -> Option<i128>, float: fn(f64, f64) -> f64) -> Cell {
    match (a, b) {
        (Num::Int(x), Num::Int(y)) => int(x, y).map_or(Cell::Null, |v| Num::Int(v).cell()),
        _ => Num::Float(float(a.float(), b.float())).cell(),
    }
}

fn eval(step: &Step, row: &[Cell], before: Option<&[Cell]>, secs: f64) -> Cell {
    let n = |a: Arg| Num::of(row[a?]);
    let f = |v: f64| Num::Float(v).cell();
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
        Step::Delta(a, slot) => change(*a, *slot).map(Num::cell),
        Step::Rate(a, slot) => change(*a, *slot).filter(|_| secs > 0.0).map(|d| f(d.float() / secs)),
        Step::Scale(a, by) => n(*a).map(|x| f(x.float() * by)),
        Step::Bucket(a, edges) => n(*a).map(|x| Cell::U(edges.iter().filter(|e| x.float() >= **e).count() as u64)),
        Step::Percentile(list, p, bounds) => list.and_then(|(start, len)| {
            let counts = &row[start..start + len];
            let total: f64 = counts.iter().map(|c| Num::of(*c).map_or(0.0, Num::float)).sum();
            if total <= 0.0 {
                return None;
            }
            let target = total * p / 100.0;
            let mut seen = 0.0;
            counts.iter().zip(bounds).find_map(|(c, bound)| {
                seen += Num::of(*c).map_or(0.0, Num::float);
                (seen >= target).then_some(f(*bound))
            })
        }),
        Step::Enum(a, values, other) => match n(*a) {
            Some(Num::Int(v)) => values.get(&v).or(other.as_ref()).map(|i| Cell::T(*i)),
            _ => None,
        },
    };
    result.unwrap_or(Cell::Null)
}

/// Open-addressing table from key bytes to the cells kept for delta and rate, rebuilt every
/// round into buffers that keep their capacity.
#[derive(Default)]
struct Prev {
    keys: Vec<u8>,
    cells: Vec<Cell>,
    slots: Vec<u32>,
    key_size: usize,
    stride: usize,
    len: u32,
}

impl Prev {
    fn reset(&mut self, rows: usize, key_size: usize, stride: usize) {
        let cap = (rows * 2).next_power_of_two().max(16);
        self.slots.clear();
        self.slots.resize(cap, u32::MAX);
        self.keys.clear();
        self.cells.clear();
        self.key_size = key_size;
        self.stride = stride;
        self.len = 0;
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

    fn find(&self, key: &[u8]) -> Option<&[Cell]> {
        if self.slots.is_empty() || key.len() != self.key_size {
            return None;
        }
        let mask = self.slots.len() - 1;
        let mut i = Self::hash(key) & mask;
        loop {
            let s = self.slots[i];
            if s == u32::MAX {
                return None;
            }
            let s = s as usize;
            if &self.keys[s * self.key_size..(s + 1) * self.key_size] == key {
                return Some(&self.cells[s * self.stride..(s + 1) * self.stride]);
            }
            i = (i + 1) & mask;
        }
    }

    fn insert(&mut self, key: &[u8], cells: impl Iterator<Item = Cell>) {
        let mask = self.slots.len() - 1;
        let mut i = Self::hash(key) & mask;
        while self.slots[i] != u32::MAX {
            i = (i + 1) & mask;
        }
        self.slots[i] = self.len;
        self.keys.extend_from_slice(key);
        self.cells.extend(cells);
        self.len += 1;
    }
}
