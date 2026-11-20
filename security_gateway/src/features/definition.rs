use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const MAX_DEFINITION_BYTES: u64 = 64 * 1024;
pub const MAX_FIELDS: usize = 128;
pub const MAX_DERIVED: usize = 128;
pub const MAX_ARRAY_LEN: u32 = 1024;
pub const MAX_TABLE: usize = 256;
const MAX_NAME: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum DefinitionError {
    #[error("failed to read feature definition {}: {source}", .path.display())]
    Read { path: PathBuf, source: io::Error },
    #[error("feature definition {} is larger than {MAX_DEFINITION_BYTES} bytes", .path.display())]
    TooLarge { path: PathBuf },
    #[error("invalid feature definition: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid name {0:?}: use 1 to {MAX_NAME} lowercase letters, digits or _, starting with a letter")]
    BadName(String),
    #[error("name {0:?} is used more than once")]
    Duplicate(String),
    #[error("{0} has no fields")]
    Empty(&'static str),
    #[error("{what} has more than {limit} entries")]
    TooMany { what: &'static str, limit: usize },
    #[error("field {0:?}: {1}")]
    Field(String, &'static str),
    #[error("derived field {name:?} refers to {target:?}, which is not a field or an earlier derived field")]
    Unknown { name: String, target: String },
    #[error("derived field {name:?}: {target:?} is {found}, but {op} needs {expected}")]
    Kind { name: String, target: String, op: &'static str, found: Kind, expected: &'static str },
    #[error("derived fields {0:?} refer to each other in a cycle")]
    Cycle(Vec<String>),
    #[error("derived field {0:?}: delta and rate compare readings of the same key, so the definition needs a key")]
    NeedsKey(String),
    #[error("derived field {0:?}: {1}")]
    Param(String, &'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scalar {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    Ipv4,
    Ipv6,
}

impl Scalar {
    pub const fn size(self) -> usize {
        match self {
            Self::U8 | Self::I8 => 1,
            Self::U16 | Self::I16 => 2,
            Self::U32 | Self::I32 | Self::Ipv4 => 4,
            Self::U64 | Self::I64 => 8,
            Self::Ipv6 => 16,
        }
    }

    const fn align(self) -> usize {
        match self {
            Self::Ipv4 | Self::Ipv6 => 4,
            other => other.size(),
        }
    }

    pub const fn is_address(self) -> bool {
        matches!(self, Self::Ipv4 | Self::Ipv6)
    }

    pub const fn is_signed(self) -> bool {
        matches!(self, Self::I8 | Self::I16 | Self::I32 | Self::I64)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    #[default]
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Merge {
    Sum,
    Min,
    Max,
    Or,
    First,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub scalar: Scalar,
    pub len: Option<u32>,
    pub endian: Endian,
    pub merge: Option<Merge>,
    pub offset: usize,
}

impl Field {
    pub fn size(&self) -> usize {
        self.scalar.size() * self.len.unwrap_or(1) as usize
    }

    pub fn kind(&self) -> Kind {
        match (self.len, self.scalar.is_address()) {
            (Some(len), _) => Kind::List(len),
            (None, true) => Kind::Address,
            (None, false) => Kind::Int,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub fields: Vec<Field>,
    pub size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Int,
    Float,
    Address,
    List(u32),
    Text,
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int => f.write_str("an integer"),
            Self::Float => f.write_str("a number with a fraction"),
            Self::Address => f.write_str("an address"),
            Self::List(len) => write!(f, "an array of {len}"),
            Self::Text => f.write_str("text"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Add(usize, usize),
    Sub(usize, usize),
    Mul(usize, usize),
    Div(usize, usize),
    Mean { sum: usize, count: usize },
    Var { sum: usize, sumsq: usize, count: usize },
    Std { sum: usize, sumsq: usize, count: usize },
    Delta(usize),
    Rate(usize),
    Scale { of: usize, by: f64 },
    Bucket { of: usize, edges: Vec<f64> },
    Percentile { of: usize, p: f64, bounds: Vec<f64> },
    Enum { of: usize, values: HashMap<i128, String>, other: Option<String> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Derived {
    pub name: String,
    pub op: Op,
    pub kind: Kind,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Definition {
    pub map: String,
    pub packed: bool,
    pub key: Option<Layout>,
    pub value: Layout,
    pub derived: Vec<Derived>,
}

impl Definition {
    pub fn load(path: &Path) -> Result<Self, DefinitionError> {
        let read = |source| DefinitionError::Read { path: path.to_path_buf(), source };
        if std::fs::metadata(path).map_err(read)?.len() > MAX_DEFINITION_BYTES {
            return Err(DefinitionError::TooLarge { path: path.to_path_buf() });
        }
        Self::parse(&std::fs::read_to_string(path).map_err(read)?)
    }

    pub fn parse(text: &str) -> Result<Self, DefinitionError> {
        let file: FileDefinition = serde_json::from_str(text)?;
        let packed = file.packed;
        let key = file.key.map(|fields| layout(fields, packed, true, "key")).transpose()?;
        let value = layout(file.value, packed, false, "value")?;
        let base: Vec<&Field> = key.iter().flat_map(|k| &k.fields).chain(&value.fields).collect();
        let derived = resolve(file.derived, &base, key.is_some())?;
        Ok(Self { map: file.map, packed, key, value, derived })
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        let key = self.key.iter().flat_map(|k| &k.fields).map(|f| f.name.as_str());
        let value = self.value.fields.iter().map(|f| f.name.as_str());
        key.chain(value).chain(self.derived.iter().map(|d| d.name.as_str()))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDefinition {
    map: String,
    #[serde(default)]
    packed: bool,
    key: Option<Vec<FileField>>,
    value: Vec<FileField>,
    #[serde(default)]
    derived: Vec<FileDerived>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileField {
    name: String,
    #[serde(rename = "type")]
    scalar: Scalar,
    len: Option<u32>,
    endian: Option<Endian>,
    merge: Option<Merge>,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum FileDerived {
    Add { name: String, args: [String; 2] },
    Sub { name: String, args: [String; 2] },
    Mul { name: String, args: [String; 2] },
    Div { name: String, args: [String; 2] },
    Mean { name: String, sum: String, count: String },
    Var { name: String, sum: String, sumsq: String, count: String },
    Std { name: String, sum: String, sumsq: String, count: String },
    Delta { name: String, of: String },
    Rate { name: String, of: String },
    Scale { name: String, of: String, by: f64 },
    Bucket { name: String, of: String, edges: Vec<f64> },
    Percentile { name: String, of: String, p: f64, bounds: Vec<f64> },
    Enum { name: String, of: String, values: BTreeMap<String, String>, other: Option<String> },
}

impl FileDerived {
    fn name(&self) -> &str {
        match self {
            Self::Add { name, .. }
            | Self::Sub { name, .. }
            | Self::Mul { name, .. }
            | Self::Div { name, .. }
            | Self::Mean { name, .. }
            | Self::Var { name, .. }
            | Self::Std { name, .. }
            | Self::Delta { name, .. }
            | Self::Rate { name, .. }
            | Self::Scale { name, .. }
            | Self::Bucket { name, .. }
            | Self::Percentile { name, .. }
            | Self::Enum { name, .. } => name,
        }
    }

    fn inputs(&self) -> Vec<&str> {
        match self {
            Self::Add { args, .. } | Self::Sub { args, .. } | Self::Mul { args, .. } | Self::Div { args, .. } => {
                vec![&args[0], &args[1]]
            }
            Self::Mean { sum, count, .. } => vec![sum, count],
            Self::Var { sum, sumsq, count, .. } | Self::Std { sum, sumsq, count, .. } => vec![sum, sumsq, count],
            Self::Delta { of, .. }
            | Self::Rate { of, .. }
            | Self::Scale { of, .. }
            | Self::Bucket { of, .. }
            | Self::Percentile { of, .. }
            | Self::Enum { of, .. } => vec![of],
        }
    }
}

pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= MAX_NAME
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn check_name(name: &str) -> Result<(), DefinitionError> {
    if valid_name(name) { Ok(()) } else { Err(DefinitionError::BadName(name.to_string())) }
}

fn layout(fields: Vec<FileField>, packed: bool, is_key: bool, what: &'static str) -> Result<Layout, DefinitionError> {
    if fields.is_empty() {
        return Err(DefinitionError::Empty(what));
    }
    if fields.len() > MAX_FIELDS {
        return Err(DefinitionError::TooMany { what, limit: MAX_FIELDS });
    }
    let mut offset: usize = 0;
    let mut max_align: usize = 1;
    let mut out = Vec::with_capacity(fields.len());
    for f in fields {
        check_name(&f.name)?;
        let bad = |reason| Err(DefinitionError::Field(f.name.clone(), reason));
        if f.scalar.is_address() && f.endian.is_some() {
            return bad("addresses are always in network order, so endian does not apply");
        }
        if f.scalar.is_address() && f.len.is_some() {
            return bad("arrays of addresses are not supported");
        }
        if f.len.is_some_and(|len| len == 0 || len > MAX_ARRAY_LEN) {
            return bad("len must be 1 to 1024");
        }
        if is_key && f.merge.is_some() {
            return bad("merge applies to value fields only");
        }
        if f.scalar.is_address() && f.merge.is_some_and(|m| m != Merge::First) {
            return bad("addresses can only be merged with first");
        }
        let align = if packed { 1 } else { f.scalar.align() };
        offset = offset.next_multiple_of(align);
        max_align = max_align.max(align);
        let field = Field {
            name: f.name,
            scalar: f.scalar,
            len: f.len,
            endian: f.endian.unwrap_or_default(),
            merge: f.merge,
            offset,
        };
        offset += field.size();
        out.push(field);
    }
    Ok(Layout { fields: out, size: offset.next_multiple_of(max_align) })
}

fn resolve(specs: Vec<FileDerived>, base: &[&Field], has_key: bool) -> Result<Vec<Derived>, DefinitionError> {
    if specs.len() > MAX_DERIVED {
        return Err(DefinitionError::TooMany { what: "derived", limit: MAX_DERIVED });
    }
    let mut slots: HashMap<String, (usize, Kind)> = HashMap::new();
    for (i, field) in base.iter().enumerate() {
        if slots.insert(field.name.clone(), (i, field.kind())).is_some() {
            return Err(DefinitionError::Duplicate(field.name.clone()));
        }
    }
    let mut pending: Vec<FileDerived> = Vec::with_capacity(specs.len());
    let mut seen = std::collections::HashSet::new();
    for spec in specs {
        check_name(spec.name())?;
        if slots.contains_key(spec.name()) || !seen.insert(spec.name().to_string()) {
            return Err(DefinitionError::Duplicate(spec.name().to_string()));
        }
        pending.push(spec);
    }
    let names: std::collections::HashSet<String> = seen;
    for spec in &pending {
        for target in spec.inputs() {
            if !slots.contains_key(target) && !names.contains(target) {
                return Err(DefinitionError::Unknown { name: spec.name().to_string(), target: target.to_string() });
            }
        }
    }
    let mut out = Vec::with_capacity(pending.len());
    while !pending.is_empty() {
        let ready = pending.iter().position(|spec| spec.inputs().iter().all(|t| slots.contains_key(*t)));
        let Some(i) = ready else {
            return Err(DefinitionError::Cycle(pending.iter().map(|s| s.name().to_string()).collect()));
        };
        let spec = pending.remove(i);
        let derived = build(spec, &slots, has_key)?;
        slots.insert(derived.name.clone(), (base.len() + out.len(), derived.kind));
        out.push(derived);
    }
    Ok(out)
}

fn build(spec: FileDerived, slots: &HashMap<String, (usize, Kind)>, has_key: bool) -> Result<Derived, DefinitionError> {
    let name = spec.name().to_string();
    let get = |target: &str, op: &'static str, accepts: fn(Kind) -> bool, expected: &'static str| {
        let (index, kind) = slots[target];
        if accepts(kind) {
            Ok((index, kind))
        } else {
            Err(DefinitionError::Kind { name: name.clone(), target: target.to_string(), op, found: kind, expected })
        }
    };
    let number = |target: &str, op| get(target, op, |k| matches!(k, Kind::Int | Kind::Float), "a number");
    let num = |target: &str, op| number(target, op).map(|(i, _)| i);
    let bad = |reason| DefinitionError::Param(name.clone(), reason);
    let pair = |args: &[String; 2], op| -> Result<(usize, usize, Kind), DefinitionError> {
        let (a, ka) = number(&args[0], op)?;
        let (b, kb) = number(&args[1], op)?;
        Ok((a, b, if ka == Kind::Int && kb == Kind::Int { Kind::Int } else { Kind::Float }))
    };
    if !has_key && matches!(spec, FileDerived::Delta { .. } | FileDerived::Rate { .. }) {
        return Err(DefinitionError::NeedsKey(name));
    }
    let (op, kind) = match &spec {
        FileDerived::Add { args, .. } => pair(args, "add").map(|(a, b, k)| (Op::Add(a, b), k))?,
        FileDerived::Sub { args, .. } => pair(args, "sub").map(|(a, b, k)| (Op::Sub(a, b), k))?,
        FileDerived::Mul { args, .. } => pair(args, "mul").map(|(a, b, k)| (Op::Mul(a, b), k))?,
        FileDerived::Div { args, .. } => (Op::Div(num(&args[0], "div")?, num(&args[1], "div")?), Kind::Float),
        FileDerived::Mean { sum, count, .. } => (Op::Mean { sum: num(sum, "mean")?, count: num(count, "mean")? }, Kind::Float),
        FileDerived::Var { sum, sumsq, count, .. } => {
            (Op::Var { sum: num(sum, "var")?, sumsq: num(sumsq, "var")?, count: num(count, "var")? }, Kind::Float)
        }
        FileDerived::Std { sum, sumsq, count, .. } => {
            (Op::Std { sum: num(sum, "std")?, sumsq: num(sumsq, "std")?, count: num(count, "std")? }, Kind::Float)
        }
        FileDerived::Delta { of, .. } => number(of, "delta").map(|(i, k)| (Op::Delta(i), k))?,
        FileDerived::Rate { of, .. } => (Op::Rate(num(of, "rate")?), Kind::Float),
        FileDerived::Scale { of, by, .. } => {
            if !by.is_finite() {
                return Err(bad("by must be a finite number"));
            }
            (Op::Scale { of: num(of, "scale")?, by: *by }, Kind::Float)
        }
        FileDerived::Bucket { of, edges, .. } => {
            check_increasing(edges).map_err(bad)?;
            (Op::Bucket { of: num(of, "bucket")?, edges: edges.clone() }, Kind::Int)
        }
        FileDerived::Percentile { of, p, bounds, .. } => {
            let (i, kind) = get(of, "percentile", |k| matches!(k, Kind::List(_)), "an array")?;
            if !(*p > 0.0 && *p <= 100.0) {
                return Err(bad("p must be greater than 0 and at most 100"));
            }
            check_increasing(bounds).map_err(bad)?;
            if kind != Kind::List(bounds.len() as u32) {
                return Err(bad("bounds must have one upper bound for each element of the array"));
            }
            (Op::Percentile { of: i, p: *p, bounds: bounds.clone() }, Kind::Float)
        }
        FileDerived::Enum { of, values, other, .. } => {
            let (i, _) = get(of, "enum", |k| k == Kind::Int, "an integer")?;
            if values.is_empty() || values.len() > MAX_TABLE {
                return Err(bad("values must have 1 to 256 entries"));
            }
            let mut table = HashMap::with_capacity(values.len());
            for (number, label) in values {
                let number = number.parse::<i128>().map_err(|_| bad("values must be keyed by integers"))?;
                check_label(label).map_err(bad)?;
                table.insert(number, label.clone());
            }
            if let Some(label) = other {
                check_label(label).map_err(bad)?;
            }
            (Op::Enum { of: i, values: table, other: other.clone() }, Kind::Text)
        }
    };
    Ok(Derived { name, op, kind })
}

fn check_increasing(edges: &[f64]) -> Result<(), &'static str> {
    if edges.is_empty() || edges.len() > MAX_TABLE {
        return Err("edges and bounds must have 1 to 256 entries");
    }
    if edges.iter().any(|e| !e.is_finite()) || edges.windows(2).any(|w| w[0] >= w[1]) {
        return Err("edges and bounds must be finite and strictly increasing");
    }
    Ok(())
}

fn check_label(label: &str) -> Result<(), &'static str> {
    let ok = !label.is_empty()
        && label.len() <= MAX_NAME
        && label.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if ok { Ok(()) } else { Err("enum labels must be 1 to 64 letters, digits, _, - or .") }
}

#[cfg(test)]
mod tests;
