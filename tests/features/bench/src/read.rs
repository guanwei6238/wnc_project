//! Reading the map into flat buffers that keep their capacity between rounds: the
//! GET_NEXT_KEY + LOOKUP walk, or BPF_MAP_LOOKUP_BATCH.
use std::fs;

use crate::legacy::Entry;

pub trait Source {
    fn len(&self) -> usize;
    fn key(&self, i: usize) -> &[u8];
    fn copies(&self, i: usize) -> usize;
    fn copy(&self, i: usize, c: usize) -> &[u8];
}

impl Source for [Entry] {
    fn len(&self) -> usize {
        <[Entry]>::len(self)
    }
    fn key(&self, i: usize) -> &[u8] {
        &self[i].key
    }
    fn copies(&self, i: usize) -> usize {
        self[i].values.len()
    }
    fn copy(&self, i: usize, c: usize) -> &[u8] {
        &self[i].values[c]
    }
}

pub struct Flat {
    pub fd: i32,
    pub key_size: usize,
    pub value_size: usize,
    slot: usize,
    ncopies: usize,
    keys: Vec<u8>,
    values: Vec<u8>,
    len: usize,
}

impl Source for Flat {
    fn len(&self) -> usize {
        self.len
    }
    fn key(&self, i: usize) -> &[u8] {
        &self.keys[i * self.key_size..(i + 1) * self.key_size]
    }
    fn copies(&self, _: usize) -> usize {
        self.ncopies
    }
    fn copy(&self, i: usize, c: usize) -> &[u8] {
        let at = (i * self.ncopies + c) * self.slot;
        &self.values[at..at + self.value_size]
    }
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

#[repr(C)]
#[derive(Default)]
struct BatchAttr {
    in_batch: u64,
    out_batch: u64,
    keys: u64,
    values: u64,
    count: u32,
    map_fd: u32,
    elem_flags: u64,
    flags: u64,
}

const LOOKUP_ELEM: libc::c_long = 1;
const GET_NEXT_KEY: libc::c_long = 4;
const LOOKUP_BATCH: libc::c_long = 24;

fn bpf<T>(cmd: libc::c_long, attr: &mut T) -> Result<(), i32> {
    let r = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr as *mut T, size_of::<T>() as libc::c_uint) };
    if r < 0 { Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)) } else { Ok(()) }
}

pub fn possible_cpus() -> usize {
    let s = fs::read_to_string("/sys/devices/system/cpu/possible").expect("possible cpus");
    s.trim().rsplit([',', '-']).next().unwrap().parse::<usize>().unwrap() + 1
}

impl Flat {
    pub fn new(fd: i32, key_size: usize, value_size: usize, per_cpu: bool) -> Self {
        let (slot, ncopies) = if per_cpu { (value_size.next_multiple_of(8), possible_cpus()) } else { (value_size, 1) };
        Self { fd, key_size, value_size, slot, ncopies, keys: Vec::new(), values: Vec::new(), len: 0 }
    }

    fn grow(&mut self, rows: usize) {
        if self.keys.len() < rows * self.key_size {
            self.keys.resize(rows * self.key_size, 0);
        }
        let bytes = rows * self.ncopies * self.slot;
        if self.values.len() < bytes {
            self.values.resize(bytes, 0);
        }
    }

    /// Walks with GET_NEXT_KEY, each key written right after the previous one, and looks
    /// each up into its own slot. Stops at `limit`, which also ends a walk that restarted.
    pub fn walk(&mut self, limit: usize) {
        self.len = 0;
        let (ks, row) = (self.key_size, self.ncopies * self.slot);
        while self.len < limit {
            self.grow(self.len + 1);
            let i = self.len;
            let prev = if i == 0 { 0 } else { self.keys[(i - 1) * ks..].as_ptr() as u64 };
            let mut attr = ElemAttr {
                map_fd: self.fd as u32,
                key: prev,
                value_or_next_key: self.keys[i * ks..].as_mut_ptr() as u64,
                ..Default::default()
            };
            match bpf(GET_NEXT_KEY, &mut attr) {
                Ok(()) => {}
                Err(libc::ENOENT) => break,
                Err(e) => panic!("get_next_key failed: errno {e}"),
            }
            let mut attr = ElemAttr {
                map_fd: self.fd as u32,
                key: self.keys[i * ks..].as_ptr() as u64,
                value_or_next_key: self.values[i * row..].as_mut_ptr() as u64,
                ..Default::default()
            };
            match bpf(LOOKUP_ELEM, &mut attr) {
                Ok(()) => self.len += 1,
                Err(libc::ENOENT) => {}
                Err(e) => panic!("lookup failed: errno {e}"),
            }
        }
    }

    /// BPF_MAP_LOOKUP_BATCH `batch` entries per call until the kernel says there are no more.
    /// A hash bucket holding more than `batch` entries returns ENOSPC, so the call is retried
    /// with room for twice as many.
    pub fn batch(&mut self, mut batch: usize, limit: usize) {
        self.len = 0;
        let (ks, row) = (self.key_size, self.ncopies * self.slot);
        let mut token = [[0u8; 8]; 2];
        let mut first = true;
        while self.len < limit {
            let want = batch.min(limit - self.len).max(1);
            self.grow(self.len + want);
            let (input, output) = token.split_at_mut(1);
            let mut attr = BatchAttr {
                in_batch: if first { 0 } else { input[0].as_ptr() as u64 },
                out_batch: output[0].as_mut_ptr() as u64,
                keys: self.keys[self.len * ks..].as_mut_ptr() as u64,
                values: self.values[self.len * row..].as_mut_ptr() as u64,
                count: want as u32,
                map_fd: self.fd as u32,
                ..Default::default()
            };
            let r = bpf(LOOKUP_BATCH, &mut attr);
            match r {
                Ok(()) | Err(libc::ENOENT) => self.len += attr.count as usize,
                Err(libc::ENOSPC) if attr.count == 0 => {
                    batch *= 2;
                    continue;
                }
                Err(e) => panic!("lookup_batch failed: errno {e}"),
            }
            if r.is_err() {
                break;
            }
            token[0] = token[1];
            first = false;
        }
    }
}

/// The map's fd, found through /proc/self/fdinfo by type, key, value and size.
pub fn map_fd(max_entries: u32, key_size: usize, value_size: usize, per_cpu: bool) -> i32 {
    let types: &[&str] = if per_cpu { &["5", "6", "10"] } else { &["1", "2", "9"] };
    fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok()?.parse::<i32>().ok())
        .find(|fd| {
            let Ok(s) = fs::read_to_string(format!("/proc/self/fdinfo/{fd}")) else { return false };
            let field = |k: &str| s.lines().find_map(|l| l.strip_prefix(k)).map(|v| v.trim().to_string());
            field("map_type:").is_some_and(|t| types.contains(&t.as_str()))
                && field("key_size:") == Some(key_size.to_string())
                && field("value_size:") == Some(value_size.to_string())
                && field("max_entries:") == Some(max_entries.to_string())
        })
        .expect("map fd")
}
