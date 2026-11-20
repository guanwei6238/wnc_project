use std::collections::BTreeMap;
use std::fmt;

use aya_obj::{Object, ProgramSection};

use super::btf::{Btf, BtfError};

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
const BPF_MAP_TYPE_LRU_PERCPU_HASH: u32 = 10;
const BPF_MAP_TYPE_RINGBUF: u32 = 27;

#[derive(Debug, thiserror::Error)]
#[error("not a usable eBPF object file: {0}")]
pub struct ElfError(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramKind {
    Xdp,
    Classifier,
    Other,
}

impl fmt::Display for ProgramKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Xdp => "an XDP program (section xdp)",
            Self::Classifier => "a TC program (section classifier)",
            Self::Other => "neither an XDP nor a TC program",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    Hash,
    Array,
    PerCpuHash,
    PerCpuArray,
    LruHash,
    LruPerCpuHash,
    RingBuf,
    Other(u32),
}

impl MapKind {
    fn from_type(map_type: u32) -> Self {
        match map_type {
            BPF_MAP_TYPE_HASH => Self::Hash,
            BPF_MAP_TYPE_ARRAY => Self::Array,
            BPF_MAP_TYPE_PERCPU_HASH => Self::PerCpuHash,
            BPF_MAP_TYPE_PERCPU_ARRAY => Self::PerCpuArray,
            BPF_MAP_TYPE_LRU_HASH => Self::LruHash,
            BPF_MAP_TYPE_LRU_PERCPU_HASH => Self::LruPerCpuHash,
            BPF_MAP_TYPE_RINGBUF => Self::RingBuf,
            other => Self::Other(other),
        }
    }

    pub fn per_cpu(self) -> bool {
        matches!(self, Self::PerCpuHash | Self::PerCpuArray | Self::LruPerCpuHash)
    }

    pub fn is_array(self) -> bool {
        matches!(self, Self::Array | Self::PerCpuArray)
    }

    pub fn is_events(self) -> bool {
        self == Self::RingBuf
    }
}

impl fmt::Display for MapKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hash => f.write_str("hash"),
            Self::Array => f.write_str("array"),
            Self::PerCpuHash => f.write_str("percpu_hash"),
            Self::PerCpuArray => f.write_str("percpu_array"),
            Self::LruHash => f.write_str("lru_hash"),
            Self::LruPerCpuHash => f.write_str("lru_percpu_hash"),
            Self::RingBuf => f.write_str("ringbuf"),
            Self::Other(n) => write!(f, "map type {n}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapInfo {
    pub kind: MapKind,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

#[derive(Debug)]
pub struct Elf {
    pub programs: BTreeMap<String, ProgramKind>,
    pub maps: BTreeMap<String, MapInfo>,
    pub btf: Option<Result<Btf, BtfError>>,
}

pub fn inspect(bytes: &[u8]) -> Result<Elf, ElfError> {
    let object = Object::parse(bytes).map_err(|e| ElfError(e.to_string()))?;
    let programs = object
        .programs
        .iter()
        .map(|(name, program)| {
            let kind = match program.section {
                ProgramSection::Xdp { .. } => ProgramKind::Xdp,
                ProgramSection::SchedClassifier => ProgramKind::Classifier,
                _ => ProgramKind::Other,
            };
            (name.clone(), kind)
        })
        .collect();
    let maps = object
        .maps
        .iter()
        .map(|(name, map)| {
            let info = MapInfo {
                kind: MapKind::from_type(map.map_type()),
                key_size: map.key_size(),
                value_size: map.value_size(),
                max_entries: map.max_entries(),
            };
            (name.clone(), info)
        })
        .collect();
    let btf = object.btf.as_ref().map(|btf| Btf::parse(&btf.to_bytes()));
    Ok(Elf { programs, maps, btf })
}

#[cfg(test)]
mod tests;
