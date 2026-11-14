use crate::kernel::bpf::{BpfError, TcxProgram};
use crate::ports::Port;

#[repr(C, align(8))]
struct Aligned<T: ?Sized>(T);

static ELF: &Aligned<[u8]> = &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/gw-ebpf")));

pub const CORE_PROGRAM_NAME: &str = "wnc_gw_ingress";
const PACKETS: &str = "PACKETS";

pub struct CoreProgram {
    program: TcxProgram,
}

impl CoreProgram {
    pub fn attach(ports: &[Port]) -> Result<Self, BpfError> {
        let mut program = TcxProgram::load(&ELF.0, CORE_PROGRAM_NAME)?;
        for port in ports {
            program.attach_ingress_first(port.interface.index)?;
        }
        Ok(Self { program })
    }

    pub fn id(&self) -> u32 {
        self.program.id()
    }

    pub fn packets(&self) -> Result<u64, BpfError> {
        self.program.per_cpu_sum(PACKETS)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/datapath/ingress.rs"]
mod tests;
