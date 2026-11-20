use std::io::Write;
use std::net::Ipv6Addr;
use std::time::Instant;

use super::definition::Definition;
use super::derive::Deriver;
use super::record::{Columns, Decoder, Records, Value};

struct Output {
    prefix: Vec<u8>,
    start: usize,
    list: Option<usize>,
}

/// A definition compiled once into where every field goes, so that each read is decoded,
/// merged, derived and written into buffers that keep their capacity, with no allocation per
/// record.
pub struct Plan {
    columns: Columns,
    decoder: Decoder,
    deriver: Deriver,
    outputs: Vec<Output>,
    feature: Vec<u8>,
    labels: Vec<Vec<u8>>,
    rows: Vec<Value>,
    from: Vec<u32>,
}

impl Plan {
    pub fn new(definition: &Definition, feature: &str, per_cpu: bool, skip_zero: bool) -> Self {
        let columns = Columns::new(definition);
        let decoder = Decoder::new(definition, &columns, per_cpu, skip_zero);
        let deriver = Deriver::new(definition, &columns);
        let outputs = definition
            .names()
            .enumerate()
            .map(|(i, name)| Output { prefix: format!(",\"{name}\":").into_bytes(), start: columns.start[i], list: columns.list[i] })
            .collect();
        let json = |text: &str| serde_json::to_string(text).unwrap_or_default().into_bytes();
        let labels = deriver.labels().iter().map(|l| json(l)).collect();
        Self { columns, decoder, deriver, outputs, feature: json(feature), labels, rows: Vec::new(), from: Vec::new() }
    }

    /// Decodes and derives one read. Returns how many records did not match the definition's
    /// size and were dropped.
    pub fn round<R: Records + ?Sized>(&mut self, records: &R, now: Instant) -> u64 {
        let width = self.columns.width;
        self.rows.clear();
        self.from.clear();
        let mut bad = 0;
        for n in 0..records.len() {
            let at = self.rows.len();
            self.rows.resize(at + width, Value::Null);
            match self.decoder.decode(records, n, &mut self.rows[at..]) {
                Ok(true) => self.from.push(n as u32),
                Ok(false) => self.rows.truncate(at),
                Err(_) => {
                    self.rows.truncate(at);
                    bad += 1;
                }
            }
        }
        self.deriver.round(records, &self.from, &mut self.rows, width, now);
        bad
    }

    pub fn len(&self) -> usize {
        self.from.len()
    }

    pub fn is_empty(&self) -> bool {
        self.from.is_empty()
    }

    /// Row `i` of the last read: key, value and derived columns in the definition's order, an
    /// array taking one column per element.
    pub fn row(&self, i: usize) -> &[Value] {
        let w = self.columns.width;
        &self.rows[i * w..(i + 1) * w]
    }

    pub fn label(&self, index: u32) -> &str {
        &self.deriver.labels()[index as usize]
    }

    /// Appends one JSON object per row: ts_ms, feature, then each field by name in the
    /// definition's order. Field names come from the definition, which only allows lowercase
    /// letters, digits and _, so they need no escaping.
    pub fn json(&self, out: &mut Vec<u8>, ts_ms: u64) {
        let mut int = itoa::Buffer::new();
        for i in 0..self.len() {
            let row = self.row(i);
            out.extend_from_slice(b"{\"ts_ms\":");
            out.extend_from_slice(int.format(ts_ms).as_bytes());
            out.extend_from_slice(b",\"feature\":");
            out.extend_from_slice(&self.feature);
            for o in &self.outputs {
                out.extend_from_slice(&o.prefix);
                match o.list {
                    None => self.json_value(row[o.start], out),
                    Some(len) => {
                        out.push(b'[');
                        for (k, v) in row[o.start..o.start + len].iter().enumerate() {
                            if k > 0 {
                                out.push(b',');
                            }
                            self.json_value(*v, out);
                        }
                        out.push(b']');
                    }
                }
            }
            out.extend_from_slice(b"}\n");
        }
    }

    fn json_value(&self, value: Value, out: &mut Vec<u8>) {
        match value {
            Value::Unsigned(v) => out.extend_from_slice(itoa::Buffer::new().format(v).as_bytes()),
            Value::Signed(v) => out.extend_from_slice(itoa::Buffer::new().format(v).as_bytes()),
            Value::Float(v) => out.extend_from_slice(zmij::Buffer::new().format_finite(v).as_bytes()),
            Value::Ipv4(a) => {
                out.push(b'"');
                for (k, octet) in a.iter().enumerate() {
                    if k > 0 {
                        out.push(b'.');
                    }
                    out.extend_from_slice(itoa::Buffer::new().format(*octet).as_bytes());
                }
                out.push(b'"');
            }
            Value::Ipv6(a) => {
                let _ = write!(out, "\"{}\"", Ipv6Addr::from(a));
            }
            Value::Label(i) => out.extend_from_slice(&self.labels[i as usize]),
            Value::Null => out.extend_from_slice(b"null"),
        }
    }
}

#[cfg(test)]
mod tests;
