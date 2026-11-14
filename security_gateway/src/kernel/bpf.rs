use std::collections::HashMap;
use std::io;
use std::mem::size_of;

use aya::Ebpf;
use aya::maps::PerCpuArray;
use aya::programs::{LinkOrder, SchedClassifier, TcAttach, TcAttachType, loaded_programs};

const BPF_PROG_QUERY: libc::c_long = 16;
const BPF_TCX_INGRESS: u32 = 46;
const BPF_MPROG_MAX: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum BpfError {
    #[error("cannot load the eBPF object: {0}")]
    Object(String),
    #[error("the eBPF object has no program {0:?}")]
    NoProgram(&'static str),
    #[error("the eBPF object has no map {0:?}")]
    NoMap(&'static str),
    #[error("cannot load program {name:?} into the kernel: {error}")]
    Load { name: &'static str, error: String },
    #[error("cannot attach program {name:?} to tcx ingress of interface {ifindex}: {error}")]
    Attach {
        name: &'static str,
        ifindex: u32,
        error: String,
    },
    #[error("cannot read map {name:?}: {error}")]
    Map { name: &'static str, error: String },
    #[error("cannot list the loaded eBPF programs: {0}")]
    List(String),
}

pub struct TcxProgram {
    ebpf: Ebpf,
    name: &'static str,
    id: u32,
}

impl TcxProgram {
    pub fn load(elf: &[u8], name: &'static str) -> Result<Self, BpfError> {
        let mut ebpf = Ebpf::load(elf).map_err(|e| BpfError::Object(error_chain(&e)))?;
        let load_error = |e: &dyn std::error::Error| BpfError::Load {
            name,
            error: error_chain(e),
        };
        let program: &mut SchedClassifier = ebpf
            .program_mut(name)
            .ok_or(BpfError::NoProgram(name))?
            .try_into()
            .map_err(|e| load_error(&e))?;
        program.load().map_err(|e| load_error(&e))?;
        let id = program.info().map_err(|e| load_error(&e))?.id();
        Ok(Self { ebpf, name, id })
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn attach_ingress_first(&mut self, ifindex: u32) -> Result<(), BpfError> {
        let name = self.name;
        let attach_error = |e: &dyn std::error::Error| BpfError::Attach {
            name,
            ifindex,
            error: error_chain(e),
        };
        let program: &mut SchedClassifier = self
            .ebpf
            .program_mut(name)
            .ok_or(BpfError::NoProgram(name))?
            .try_into()
            .map_err(|e| attach_error(&e))?;
        let order = TcAttach::Tcx {
            attach_type: TcAttachType::Ingress,
            order: LinkOrder::first(),
        };
        program.attach(ifindex, order).map_err(|e| attach_error(&e))?;
        Ok(())
    }

    pub fn per_cpu_sum(&self, map: &'static str) -> Result<u64, BpfError> {
        let map_error = |e: &dyn std::error::Error| BpfError::Map {
            name: map,
            error: error_chain(e),
        };
        let array: PerCpuArray<_, u64> = self
            .ebpf
            .map(map)
            .ok_or(BpfError::NoMap(map))?
            .try_into()
            .map_err(|e| map_error(&e))?;
        let values = array.get(&0, 0).map_err(|e| map_error(&e))?;
        Ok(values.iter().fold(0u64, |sum, v| sum.wrapping_add(*v)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcxChain {
    pub revision: u64,
    pub prog_ids: Vec<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum TcxQueryError {
    #[error("listing tcx programs needs CAP_NET_ADMIN")]
    NotPermitted,
    #[error("the kernel rejected the tcx query (tcx needs Linux 6.6 or later)")]
    Unsupported,
    #[error("interface {0} no longer exists")]
    NoDevice(u32),
    #[error("bpf(BPF_PROG_QUERY) failed: {0}")]
    Io(io::Error),
}

#[repr(C)]
#[derive(Default)]
struct QueryAttr {
    target_ifindex: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    prog_cnt: u32,
    _pad: u32,
    prog_attach_flags: u64,
    link_ids: u64,
    link_attach_flags: u64,
    revision: u64,
}

pub fn tcx_ingress(ifindex: u32) -> Result<TcxChain, TcxQueryError> {
    let mut ids = [0u32; BPF_MPROG_MAX];
    let mut attr = QueryAttr {
        target_ifindex: ifindex,
        attach_type: BPF_TCX_INGRESS,
        prog_ids: ids.as_mut_ptr() as u64,
        prog_cnt: BPF_MPROG_MAX as u32,
        ..Default::default()
    };
    // QueryAttr 照 kernel bpf_attr 的 query 段排列（測試檢查 offset）；prog_ids 指向的陣列在呼叫期間有效、長度是 prog_cnt
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_QUERY,
            &mut attr as *mut QueryAttr,
            size_of::<QueryAttr>() as libc::c_uint,
        )
    };
    if ret < 0 {
        return Err(query_error(io::Error::last_os_error(), ifindex));
    }
    let count = (attr.prog_cnt as usize).min(BPF_MPROG_MAX);
    Ok(TcxChain {
        revision: attr.revision,
        prog_ids: ids[..count].to_vec(),
    })
}

fn query_error(e: io::Error, ifindex: u32) -> TcxQueryError {
    match e.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => TcxQueryError::NotPermitted,
        Some(libc::EINVAL) => TcxQueryError::Unsupported,
        Some(libc::ENODEV) => TcxQueryError::NoDevice(ifindex),
        _ => TcxQueryError::Io(e),
    }
}

pub fn program_names() -> Result<HashMap<u32, String>, BpfError> {
    let mut names = HashMap::new();
    for info in loaded_programs() {
        match info {
            Ok(info) => {
                names.insert(info.id(), info.name_as_str().unwrap_or_default().to_owned());
            }
            // 列舉途中結束的程式會在這裡失敗，只有一筆都拿不到時才算錯
            Err(e) if names.is_empty() => return Err(BpfError::List(error_chain(&e))),
            Err(_) => {}
        }
    }
    Ok(names)
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

#[cfg(test)]
#[path = "../../tests/unit/kernel/bpf.rs"]
mod tests;
