use std::io;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, RawFd};

use aya::maps::{Map, MapData, RingBuf};
use aya::programs::{LinkOrder, SchedClassifier, TcAttach, TcAttachType, Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader};
use tokio::io::unix::AsyncFd;

use super::error_chain;

const BPF_MAP_LOOKUP_ELEM: libc::c_long = 1;
const BPF_MAP_GET_NEXT_KEY: libc::c_long = 4;
const BPF_PROG_TEST_RUN: libc::c_long = 10;
const BPF_MAP_LOOKUP_BATCH: libc::c_long = 24;
const BATCH: usize = 256;
/// The kernel's ENOTSUPP, which libc does not export: the map type has no batch operations.
const ENOTSUPP: i32 = 524;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attach {
    Xdp { generic: bool },
    TcxIngressLast,
    TcxEgressLast,
}

impl Attach {
    fn hook(self) -> &'static str {
        match self {
            Self::Xdp { generic: false } => "native xdp",
            Self::Xdp { generic: true } => "generic xdp",
            Self::TcxIngressLast => "tcx ingress",
            Self::TcxEgressLast => "tcx egress",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UserProgramError {
    #[error("cannot load the eBPF object: {0}")]
    Object(String),
    #[error("the eBPF object has no program {0:?}")]
    NoProgram(String),
    #[error("cannot load program {name:?} into the kernel: {error}")]
    Load { name: String, error: String },
    #[error("cannot attach program {name:?} to {hook} of interface {ifindex}: {error}")]
    Attach { name: String, hook: &'static str, ifindex: u32, error: String },
    #[error("the eBPF object has no map {0:?}")]
    NoMap(String),
    #[error("map {0:?} cannot be read as a table or a ring buffer")]
    MapKind(String),
    #[error("cannot count the possible CPUs: {0}")]
    Cpus(String),
    #[error("cannot run program {name:?} on a test packet: {error}")]
    TestRun { name: String, error: String },
}

/// A program the administrator supplies; it stays attached until this is dropped.
pub struct UserProgram {
    ebpf: Ebpf,
    entry: String,
    attach: Attach,
    id: Option<u32>,
}

impl UserProgram {
    pub fn load(elf: &[u8], entry: &str, attach: Attach) -> Result<Self, UserProgramError> {
        let mut ebpf = EbpfLoader::new().load(elf).map_err(|e| UserProgramError::Object(error_chain(&e)))?;
        let load_error = |e: &dyn std::error::Error| UserProgramError::Load { name: entry.to_string(), error: error_chain(e) };
        let program = ebpf.program_mut(entry).ok_or_else(|| UserProgramError::NoProgram(entry.to_string()))?;
        let id = match attach {
            Attach::Xdp { .. } => {
                let xdp: &mut Xdp = program.try_into().map_err(|e| load_error(&e))?;
                xdp.load().map_err(|e| load_error(&e))?;
                xdp.info().ok().map(|info| info.id())
            }
            Attach::TcxIngressLast | Attach::TcxEgressLast => {
                let tc: &mut SchedClassifier = program.try_into().map_err(|e| load_error(&e))?;
                tc.load().map_err(|e| load_error(&e))?;
                tc.info().ok().map(|info| info.id())
            }
        };
        Ok(Self { ebpf, entry: entry.to_string(), attach, id })
    }

    pub fn id(&self) -> Option<u32> {
        self.id
    }

    pub fn attach(&mut self, ifindex: u32) -> Result<(), UserProgramError> {
        let (name, attach) = (self.entry.clone(), self.attach);
        let attach_error =
            |e: &dyn std::error::Error| UserProgramError::Attach { name: name.clone(), hook: attach.hook(), ifindex, error: error_chain(e) };
        let program = self.ebpf.program_mut(&self.entry).ok_or_else(|| UserProgramError::NoProgram(name.clone()))?;
        match attach {
            Attach::Xdp { generic } => {
                let xdp: &mut Xdp = program.try_into().map_err(|e| attach_error(&e))?;
                let mode = if generic { XdpMode::Skb } else { XdpMode::Driver };
                xdp.attach(ifindex, mode).map_err(|e| attach_error(&e))?;
            }
            Attach::TcxIngressLast | Attach::TcxEgressLast => {
                let tc: &mut SchedClassifier = program.try_into().map_err(|e| attach_error(&e))?;
                let attach_type = if attach == Attach::TcxIngressLast { TcAttachType::Ingress } else { TcAttachType::Egress };
                tc.attach(ifindex, TcAttach::Tcx { attach_type, order: LinkOrder::last() }).map_err(|e| attach_error(&e))?;
            }
        }
        Ok(())
    }

    /// Runs the loaded (not necessarily attached) program once on `packet` with
    /// bpf(BPF_PROG_TEST_RUN) and returns its return value. The program's maps are updated as if
    /// the packet had arrived.
    pub fn test_run(&self, packet: &[u8]) -> Result<u32, UserProgramError> {
        let failed = |error: String| UserProgramError::TestRun { name: self.entry.clone(), error };
        let program = self.ebpf.program(&self.entry).ok_or_else(|| UserProgramError::NoProgram(self.entry.clone()))?;
        let fd = program.fd().map_err(|e| failed(error_chain(&e)))?;
        let mut attr = TestRunAttr {
            prog_fd: fd.as_fd().as_raw_fd() as u32,
            data_size_in: packet.len() as u32,
            data_in: packet.as_ptr() as u64,
            repeat: 1,
            ..Default::default()
        };
        bpf_syscall(BPF_PROG_TEST_RUN, &mut attr).map_err(|e| failed(e.to_string()))?;
        Ok(attr.retval)
    }

    pub fn take_table(&mut self, name: &str, key_size: usize, value_size: usize, per_cpu: bool) -> Result<Table, UserProgramError> {
        let data = match self.ebpf.take_map(name).ok_or_else(|| UserProgramError::NoMap(name.to_string()))? {
            Map::HashMap(d) | Map::LruHashMap(d) | Map::PerCpuHashMap(d) | Map::PerCpuLruHashMap(d) => d,
            Map::Array(d) | Map::PerCpuArray(d) => d,
            _ => return Err(UserProgramError::MapKind(name.to_string())),
        };
        let cpus = if per_cpu {
            aya::util::nr_cpus().map_err(|(path, e)| UserProgramError::Cpus(format!("{path}: {e}")))?.get() as usize
        } else {
            1
        };
        let slot = if per_cpu { value_size.next_multiple_of(8) } else { value_size };
        Ok(Table {
            data,
            key_size,
            value_size,
            slot,
            cpus,
            batch: Some(BATCH),
            keys: Vec::new(),
            values: Vec::new(),
            len: 0,
            seen: Vec::new(),
        })
    }

    pub fn take_ring(&mut self, name: &str) -> Result<Ring, UserProgramError> {
        let map = self.ebpf.take_map(name).ok_or_else(|| UserProgramError::NoMap(name.to_string()))?;
        let ring = RingBuf::try_from(map).map_err(|_| UserProgramError::MapKind(name.to_string()))?;
        Ok(Ring { ring })
    }
}

pub struct Ring {
    ring: RingBuf<MapData>,
}

impl Ring {
    pub fn into_async(self) -> io::Result<AsyncFd<Self>> {
        // SAFETY: the fd belongs to the RingBuf inside self, so it stays open and the same for as
        // long as the AsyncFd owns self, and as_raw_fd always returns it.
        unsafe { AsyncFd::register(self) }.map_err(io::Error::from)
    }

    pub fn drain(&mut self, limit: usize) -> Vec<Vec<u8>> {
        let mut records = Vec::new();
        while records.len() < limit {
            match self.ring.next() {
                Some(item) => records.push(item.to_vec()),
                None => break,
            }
        }
        records
    }
}

impl AsRawFd for Ring {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.ring.as_raw_fd()
    }
}

/// A hash or array map, read into buffers that keep their capacity between reads.
pub struct Table {
    data: MapData,
    key_size: usize,
    value_size: usize,
    slot: usize,
    cpus: usize,
    /// Entries per BPF_MAP_LOOKUP_BATCH, or None once the kernel has said it cannot.
    batch: Option<usize>,
    keys: Vec<u8>,
    values: Vec<u8>,
    len: usize,
    seen: Vec<u32>,
}

impl Table {
    /// Reads up to `limit` entries, replacing the last read. BPF_MAP_LOOKUP_BATCH reads many
    /// entries per call; a kernel or map type without it (EINVAL before 5.6, ENOTSUPP) is read
    /// one key at a time from then on.
    pub fn read(&mut self, limit: usize) -> io::Result<()> {
        self.len = 0;
        if self.batch.is_some() {
            match self.read_batch(limit) {
                Err(e) if self.len == 0 && matches!(e.raw_os_error(), Some(libc::EINVAL | libc::EOPNOTSUPP | ENOTSUPP)) => {
                    self.batch = None;
                }
                other => return other,
            }
        }
        self.walk(limit)
    }

    pub fn reads_in_batches(&self) -> bool {
        self.batch.is_some()
    }

    /// Reads one key at a time from now on, as on a kernel without batches.
    pub fn read_one_at_a_time(&mut self) {
        self.batch = None;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn key(&self, i: usize) -> &[u8] {
        &self.keys[i * self.key_size..(i + 1) * self.key_size]
    }

    /// One copy per possible CPU for a per-CPU map, otherwise one.
    pub fn copies(&self) -> usize {
        self.cpus
    }

    pub fn value(&self, i: usize, cpu: usize) -> &[u8] {
        let at = (i * self.cpus + cpu) * self.slot;
        &self.values[at..at + self.value_size]
    }

    fn grow(&mut self, entries: usize) {
        if self.keys.len() < entries * self.key_size {
            self.keys.resize(entries * self.key_size, 0);
        }
        if self.values.len() < entries * self.cpus * self.slot {
            self.values.resize(entries * self.cpus * self.slot, 0);
        }
    }

    fn read_batch(&mut self, limit: usize) -> io::Result<()> {
        let fd = self.data.fd().as_fd().as_raw_fd() as u32;
        let token_size = self.key_size.max(8);
        let mut tokens = [vec![0u8; token_size], vec![0u8; token_size]];
        let mut first = true;
        while self.len < limit {
            let batch = self.batch.unwrap_or(BATCH);
            let want = batch.min(limit - self.len);
            self.grow(self.len + want);
            let [input, output] = &mut tokens;
            let mut attr = BatchAttr {
                in_batch: if first { 0 } else { input.as_ptr() as u64 },
                out_batch: output.as_mut_ptr() as u64,
                keys: self.keys[self.len * self.key_size..].as_mut_ptr() as u64,
                values: self.values[self.len * self.cpus * self.slot..].as_mut_ptr() as u64,
                count: want as u32,
                map_fd: fd,
                ..Default::default()
            };
            let done = match bpf_syscall(BPF_MAP_LOOKUP_BATCH, &mut attr) {
                Ok(()) => false,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => true,
                // A hash bucket holds more entries than fit: ask for more at once, unless that
                // would pass the limit.
                Err(e) if e.raw_os_error() == Some(libc::ENOSPC) && attr.count == 0 => {
                    if want == limit - self.len {
                        break;
                    }
                    self.batch = Some(batch * 2);
                    continue;
                }
                Err(e) => return Err(e),
            };
            self.len += attr.count as usize;
            if done {
                break;
            }
            tokens.swap(0, 1);
            first = false;
        }
        Ok(())
    }

    /// GET_NEXT_KEY + LOOKUP_ELEM. Entries deleted during the walk can make the kernel start
    /// again from the first key; a key seen twice ends it.
    fn walk(&mut self, limit: usize) -> io::Result<()> {
        let fd = self.data.fd().as_fd().as_raw_fd();
        self.seen.clear();
        self.seen.resize((limit * 2).next_power_of_two().max(16), u32::MAX);
        let (mut prev, mut next) = (vec![0u8; self.key_size], vec![0u8; self.key_size]);
        let mut started = false;
        let row = self.cpus * self.slot;
        while self.len < limit {
            if !next_key(fd, started.then_some(&prev[..]), &mut next)? {
                break;
            }
            started = true;
            let i = self.len;
            self.grow(i + 1);
            if lookup(fd, &next, &mut self.values[i * row..(i + 1) * row])? {
                self.keys[i * self.key_size..(i + 1) * self.key_size].copy_from_slice(&next);
                if !self.remember(i) {
                    break;
                }
                self.len += 1;
            }
            std::mem::swap(&mut prev, &mut next);
        }
        Ok(())
    }

    fn slot_of(&self, key: &[u8]) -> (usize, Option<usize>) {
        let mask = self.seen.len() - 1;
        let mut h: u64 = 0;
        for chunk in key.chunks(8) {
            let mut b = [0u8; 8];
            b[..chunk.len()].copy_from_slice(chunk);
            h = (h.rotate_left(5) ^ u64::from_le_bytes(b)).wrapping_mul(0x517c_c1b7_2722_0a95);
        }
        let mut s = (h ^ (h >> 29)) as usize & mask;
        loop {
            match self.seen[s] {
                u32::MAX => return (s, None),
                i if self.key(i as usize) == key => return (s, Some(i as usize)),
                _ => s = (s + 1) & mask,
            }
        }
    }

    /// Records key `i` as seen; false if it was seen before.
    fn remember(&mut self, i: usize) -> bool {
        let (s, found) = self.slot_of(self.key(i));
        if found.is_some() {
            return false;
        }
        self.seen[s] = i as u32;
        true
    }
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

#[repr(C)]
#[derive(Default)]
struct ElemAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value_or_next_key: u64,
    flags: u64,
}

fn next_key(fd: RawFd, key: Option<&[u8]>, next: &mut [u8]) -> io::Result<bool> {
    let mut attr = ElemAttr {
        map_fd: fd as u32,
        key: key.map_or(0, |k| k.as_ptr() as u64),
        value_or_next_key: next.as_mut_ptr() as u64,
        ..Default::default()
    };
    match bpf_syscall(BPF_MAP_GET_NEXT_KEY, &mut attr) {
        Ok(()) => Ok(true),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(e) => Err(e),
    }
}

fn lookup(fd: RawFd, key: &[u8], value: &mut [u8]) -> io::Result<bool> {
    let mut attr = ElemAttr {
        map_fd: fd as u32,
        key: key.as_ptr() as u64,
        value_or_next_key: value.as_mut_ptr() as u64,
        ..Default::default()
    };
    match bpf_syscall(BPF_MAP_LOOKUP_ELEM, &mut attr) {
        Ok(()) => Ok(true),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(e) => Err(e),
    }
}

#[repr(C)]
#[derive(Default)]
struct TestRunAttr {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
    _pad: u32,
}

/// `attr` is one of the bpf_attr layouts above. Every pointer in it points at a buffer the
/// caller owns and sized for what the kernel reads or writes there: keys and values from the
/// map's key_size and value_size (per-CPU values: one 8-byte aligned slot per possible CPU),
/// `count` of each for a batch and batch tokens of at least the key size and 8 bytes, test
/// packets with data_size_in, and no output buffers for test runs.
fn bpf_syscall<T>(cmd: libc::c_long, attr: &mut T) -> io::Result<()> {
    let ret = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr as *mut T, size_of::<T>() as libc::c_uint) };
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}
