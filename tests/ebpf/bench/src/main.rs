use std::env;
use std::error::Error;
use std::ffi::CString;
use std::io::Write;
use std::net::IpAddr;
use std::process::ExitCode;

use aya::maps::{HashMap, PerCpuArray};
use aya::programs::{LinkOrder, SchedClassifier, TcAttach, TcAttachType};
use aya::{Ebpf, Pod};

#[repr(C, align(8))]
struct Aligned<T: ?Sized>(T);

static ELF: &Aligned<[u8]> = &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/bench-ebpf")));

const USAGE: &str =
    "usage: ebpf-bench <v1|v2|v3> [--flow <tcp|udp> <src ip> <src port> <dst ip> <dst port>] <interface>...";

// 和 ebpf/src/main.rs 的 FlowKey 一樣：位址和 port 照封包裡的 bytes 存
#[repr(C)]
#[derive(Clone, Copy)]
struct FlowKey {
    saddr: [u32; 4],
    daddr: [u32; 4],
    sport: u16,
    dport: u16,
    proto: u32,
}

unsafe impl Pod for FlowKey {}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        return Err(USAGE.into());
    }
    let program = match args.remove(0).as_str() {
        "v1" => "v1_empty",
        "v2" => "v2_count",
        "v3" => "v3_lookup",
        _ => return Err(USAGE.into()),
    };
    let flow = if args.first().map(String::as_str) == Some("--flow") {
        if args.len() < 7 {
            return Err(USAGE.into());
        }
        let spec: Vec<String> = args.drain(..6).collect();
        Some(flow_key(&spec[1..])?)
    } else {
        None
    };
    if args.is_empty() {
        return Err(USAGE.into());
    }
    let signals = block_stop_signals();

    let mut ebpf = Ebpf::load(&ELF.0)?;
    if let Some(key) = flow {
        let mut flows: HashMap<_, FlowKey, u64> = HashMap::try_from(ebpf.map_mut("FLOWS").ok_or("no map FLOWS")?)?;
        flows.insert(&key, &0, 0)?;
    }
    let prog: &mut SchedClassifier = ebpf.program_mut(program).ok_or("no such program")?.try_into()?;
    prog.load()?;
    for interface in &args {
        let name = CString::new(interface.as_str())?;
        let order = TcAttach::Tcx {
            attach_type: TcAttachType::Ingress,
            order: LinkOrder::first(),
        };
        prog.attach(&name, order)?;
    }
    println!("prog_id={}", prog.info()?.id());
    std::io::stdout().flush()?;

    wait_for(&signals);
    let counts: PerCpuArray<_, u64> = PerCpuArray::try_from(ebpf.map("COUNT").ok_or("no map COUNT")?)?;
    let packets: u64 = counts.get(&0, 0)?.iter().sum();
    let hits: u64 = counts.get(&1, 0)?.iter().sum();
    println!("packets={packets} hits={hits}");
    Ok(())
}

fn flow_key(spec: &[String]) -> Result<FlowKey, Box<dyn Error>> {
    let proto = match spec[0].as_str() {
        "tcp" => 6u32,
        "udp" => 17,
        _ => return Err(USAGE.into()),
    };
    let address = |s: &str| -> Result<[u32; 4], Box<dyn Error>> {
        Ok(match s.parse::<IpAddr>()? {
            IpAddr::V4(a) => [u32::from_ne_bytes(a.octets()), 0, 0, 0],
            IpAddr::V6(a) => {
                let o = a.octets();
                std::array::from_fn(|i| u32::from_ne_bytes([o[i * 4], o[i * 4 + 1], o[i * 4 + 2], o[i * 4 + 3]]))
            }
        })
    };
    Ok(FlowKey {
        saddr: address(&spec[1])?,
        sport: spec[2].parse::<u16>()?.to_be(),
        daddr: address(&spec[3])?,
        dport: spec[4].parse::<u16>()?.to_be(),
        proto,
    })
}

fn block_stop_signals() -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        set
    }
}

fn wait_for(set: &libc::sigset_t) {
    let mut signal = 0;
    unsafe { libc::sigwait(set, &mut signal) };
}
