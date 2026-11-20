use std::fmt;

use super::btf::Shape;
use super::definition::{Definition, Field, Layout};
use super::elf::{Elf, MapInfo, ProgramKind};
use super::hook::Hook;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    EntryMissing { entry: String, available: Vec<String> },
    EntryWrongKind { entry: String, hook: Hook, found: ProgramKind },
    MapMissing { map: String, available: Vec<String> },
    MapUnsupported { map: String, info: MapInfo },
    Shape(String),
    BtfMismatch { part: &'static str, details: Vec<String> },
    NoBtf(String),
    Undescribed { part: &'static str, members: Vec<String> },
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntryMissing { entry, available } => {
                write!(f, "the program has no function {entry:?} (it has: {})", list(available))
            }
            Self::EntryWrongKind { entry, hook, found } => {
                let needs = match hook {
                    Hook::Xdp(_) => "an XDP program (section xdp)",
                    Hook::TcIngress | Hook::TcEgress => "a TC program (section classifier)",
                };
                write!(f, "{entry:?} is {found}, but hook {} needs {needs}", hook.name())
            }
            Self::MapMissing { map, available } => {
                write!(f, "the program has no map {map:?} (it has: {})", list(available))
            }
            Self::MapUnsupported { map, info } => write!(
                f,
                "map {map:?} is a {}, which cannot be read (supported: hash, lru_hash, array and their percpu kinds, ringbuf)",
                info.kind
            ),
            Self::Shape(message) => f.write_str(message),
            Self::BtfMismatch { part, details } => {
                write!(f, "the {part} described by the definition does not match the program's BTF: {}", details.join("; "))
            }
            Self::NoBtf(reason) => write!(f, "{reason}, so only the sizes were compared, not each field"),
            Self::Undescribed { part, members } => {
                write!(f, "the {part} struct has members the definition skips (not read): {}", members.join(", "))
            }
        }
    }
}

impl Problem {
    /// Whether decoding with this definition would read the wrong bytes (or nothing).
    pub fn blocks_loading(&self) -> bool {
        !matches!(self, Self::NoBtf(_) | Self::Undescribed { .. })
    }
}

fn list(names: &[String]) -> String {
    if names.is_empty() { "nothing".to_string() } else { names.join(", ") }
}

pub fn check(definition: &Definition, elf: &Elf, entry: &str, hook: Hook) -> Vec<Problem> {
    let mut problems = Vec::new();
    match elf.programs.get(entry) {
        None => problems.push(Problem::EntryMissing {
            entry: entry.to_string(),
            available: elf.programs.keys().cloned().collect(),
        }),
        Some(&found) => {
            let fits = match hook {
                Hook::Xdp(_) => found == ProgramKind::Xdp,
                Hook::TcIngress | Hook::TcEgress => found == ProgramKind::Classifier,
            };
            if !fits {
                problems.push(Problem::EntryWrongKind { entry: entry.to_string(), hook, found });
            }
        }
    }
    let Some(&info) = elf.maps.get(&definition.map) else {
        problems.push(Problem::MapMissing {
            map: definition.map.clone(),
            available: elf.maps.keys().cloned().collect(),
        });
        return problems;
    };
    if matches!(info.kind, super::elf::MapKind::Other(_)) {
        problems.push(Problem::MapUnsupported { map: definition.map.clone(), info });
        return problems;
    }
    let shape_problems = shape(definition, &info);
    let sizes_match = shape_problems.is_empty();
    problems.extend(shape_problems.into_iter().map(Problem::Shape));
    if sizes_match && (!info.kind.is_events() || info.value_size != 0) {
        problems.extend(compare_btf(definition, elf));
    }
    problems
}

fn shape(definition: &Definition, info: &MapInfo) -> Vec<String> {
    let mut out = Vec::new();
    let map = &definition.map;
    match (&definition.key, info.kind.is_events()) {
        (Some(_), true) => out.push(format!("map {map:?} is a ringbuf, which has no key, but the definition has one")),
        (None, false) => out.push(format!("map {map:?} is a {}, so the definition needs a key", info.kind)),
        (Some(key), false) if key.size != info.key_size as usize => out.push(format!(
            "the key described is {} bytes, but map {map:?} has {}-byte keys",
            key.size, info.key_size
        )),
        _ => {}
    }
    let declared = !info.kind.is_events() || info.value_size != 0;
    if declared && definition.value.size != info.value_size as usize {
        out.push(format!(
            "the value described is {} bytes, but map {map:?} has {}-byte values",
            definition.value.size, info.value_size
        ));
    }
    let merged: Vec<&str> = definition.value.fields.iter().filter(|f| f.merge.is_some()).map(|f| f.name.as_str()).collect();
    let unmerged: Vec<&str> = definition.value.fields.iter().filter(|f| f.merge.is_none()).map(|f| f.name.as_str()).collect();
    if info.kind.per_cpu() && !unmerged.is_empty() {
        out.push(format!(
            "map {map:?} is a {} (one copy per CPU), so every value field needs merge; missing on: {}",
            info.kind,
            unmerged.join(", ")
        ));
    }
    if !info.kind.per_cpu() && !merged.is_empty() {
        out.push(format!(
            "merge applies to percpu maps only, but map {map:?} is a {}; remove merge from: {}",
            info.kind,
            merged.join(", ")
        ));
    }
    out
}

fn compare_btf(definition: &Definition, elf: &Elf) -> Vec<Problem> {
    let btf = match &elf.btf {
        None => return vec![Problem::NoBtf("the program has no BTF".into())],
        Some(Err(e)) => return vec![Problem::NoBtf(format!("the program's BTF cannot be read ({e})"))],
        Some(Ok(btf)) => btf,
    };
    let Some(types) = btf.map_types(&definition.map) else {
        return vec![Problem::NoBtf(format!(
            "map {:?} is not declared with BTF (libbpf's .maps section with __type(key, ...) and __type(value, ...))",
            definition.map
        ))];
    };
    let mut problems = Vec::new();
    let parts = [("key", definition.key.as_ref(), types.key), ("value", Some(&definition.value), types.value)];
    for (part, layout, id) in parts {
        let (Some(layout), Some(id)) = (layout, id) else { continue };
        let (details, skipped) = compare(layout, &btf.shape(id));
        if !details.is_empty() {
            problems.push(Problem::BtfMismatch { part, details });
        }
        if !skipped.is_empty() {
            problems.push(Problem::Undescribed { part, members: skipped });
        }
    }
    problems
}

/// Compares a layout with a BTF type: returns the mismatches, and the struct members the
/// layout leaves out (fine when they sit in what the layout treats as padding).
pub fn compare(layout: &Layout, shape: &Shape) -> (Vec<String>, Vec<String>) {
    let mut details = Vec::new();
    let Shape::Struct { size, members } = shape else {
        match layout.fields.as_slice() {
            [field] => details.extend(compare_field(field, shape)),
            _ => details.push(format!("the type is not a struct, but the definition has {} fields", layout.fields.len())),
        }
        return (details, Vec::new());
    };
    if *size as usize != layout.size {
        details.push(format!("struct is {size} bytes, definition {}", layout.size));
    }
    for field in &layout.fields {
        let Some((member, member_shape)) = members.iter().find(|(m, _)| m.name == field.name) else {
            details.push(format!("{} is not a member of the struct", field.name));
            continue;
        };
        if member.bitfield || member.bit_offset % 8 != 0 {
            details.push(format!("{} is a bit field, which cannot be described", field.name));
            continue;
        }
        let offset = member.bit_offset as usize / 8;
        if offset != field.offset {
            details.push(format!("{} is at offset {offset} in the struct, {} in the definition", field.name, field.offset));
        }
        details.extend(compare_field(field, member_shape));
    }
    let skipped = members
        .iter()
        .filter(|(m, _)| !layout.fields.iter().any(|f| f.name == m.name))
        .map(|(m, _)| m.name.clone())
        .collect();
    (details, skipped)
}

fn compare_field(field: &Field, shape: &Shape) -> Option<String> {
    let name = &field.name;
    let size = shape.size();
    if size != Some(field.size() as u32) {
        let found = size.map_or("of unknown size".to_string(), |s| format!("{s} bytes"));
        return Some(format!("{name} is {found} in the struct, {} in the definition", field.size()));
    }
    if field.scalar.is_address() {
        return None;
    }
    let element = match (field.len, shape) {
        (Some(len), Shape::Array { elem, len: n }) if *n == len => elem.as_ref(),
        (Some(len), _) => return Some(format!("{name} is not an array of {len} in the struct")),
        (None, Shape::Array { .. }) => return Some(format!("{name} is an array in the struct but not in the definition")),
        (None, other) => other,
    };
    match element {
        Shape::Int { signed, .. } if *signed != field.scalar.is_signed() => Some(format!(
            "{name} is {} in the struct, {} in the definition",
            if *signed { "signed" } else { "unsigned" },
            if field.scalar.is_signed() { "signed" } else { "unsigned" }
        )),
        Shape::Int { .. } => None,
        Shape::Other { what, .. } => Some(format!("{name} is {what} in the struct")),
        _ => Some(format!("{name} is not an integer in the struct")),
    }
}

#[cfg(test)]
mod tests;
