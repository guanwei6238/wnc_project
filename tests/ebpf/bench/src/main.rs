use std::env;
use std::error::Error;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Instant;

use aya::maps::{HashMap, MapData, PerCpuArray};
use aya::programs::{LinkOrder, SchedClassifier, TcAttach, TcAttachType};
use aya::{Ebpf, Pod};

#[repr(C, align(8))]
struct Aligned<T: ?Sized>(T);

static ELF: &Aligned<[u8]> = &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/bench-ebpf")));

const USAGE: &str = "usage: ebpf-bench <v1|v2|v3|v4|v5> [--flow <tcp|udp> <src ip> <src port> <dst ip> <dst port>] \
                     [--flows <file>] [--via <neigh|nexthop|fib>] [--nexthop <interface> <ipv4>]... <interface>...\n       \
                     ebpf-bench mapbench <entries>";

#[repr(C)]
#[derive(Clone, Copy)]
struct FlowKey {
    saddr: [u32; 4],
    daddr: [u32; 4],
    sport: u16,
    dport: u16,
    proto: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FlowStats {
    packets: u64,
    bytes: u64,
    last_ns: u64,
}

unsafe impl Pod for FlowKey {}
unsafe impl Pod for FlowStats {}

impl FlowKey {
    fn reverse(&self) -> Self {
        Self {
            saddr: self.daddr,
            daddr: self.saddr,
            sport: self.dport,
            dport: self.sport,
            proto: self.proto,
        }
    }
}

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
    let variant = args.remove(0);
    if variant == "mapbench" {
        let entries = args.first().ok_or(USAGE)?.parse()?;
        return mapbench(entries);
    }
    let program = match variant.as_str() {
        "v1" => "v1_empty",
        "v2" => "v2_count",
        "v3" => "v3_lookup",
        "v4" => "v4_redirect",
        "v5" => "v5_routed",
        _ => return Err(USAGE.into()),
    };
    let mut flows = Vec::new();
    let mut via = 0u32;
    let mut nexthops: Vec<(String, std::net::Ipv4Addr)> = Vec::new();
    loop {
        match args.first().map(String::as_str) {
            Some("--via") => {
                via = match args.get(1).map(String::as_str) {
                    Some("neigh") => 0,
                    Some("nexthop") => 1,
                    Some("fib") => 2,
                    _ => return Err(USAGE.into()),
                };
                args.drain(..2);
            }
            Some("--nexthop") => {
                if args.len() < 3 {
                    return Err(USAGE.into());
                }
                let spec: Vec<String> = args.drain(..3).collect();
                nexthops.push((spec[1].clone(), spec[2].parse()?));
            }
            Some("--flow") => {
                if args.len() < 7 {
                    return Err(USAGE.into());
                }
                let spec: Vec<String> = args.drain(..6).collect();
                flows.push(flow_key(&spec[1..])?);
            }
            Some("--flows") => {
                if args.len() < 2 {
                    return Err(USAGE.into());
                }
                let path = args.drain(..2).nth(1).unwrap_or_default();
                for line in fs::read_to_string(&path)?.lines().filter(|l| !l.trim().is_empty()) {
                    let spec: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
                    if spec.len() != 5 {
                        return Err(format!("bad line in {path}: {line:?}").into());
                    }
                    flows.push(flow_key(&spec)?);
                }
            }
            _ => break,
        }
    }
    let redirects = program == "v4_redirect" || program == "v5_routed";
    if args.is_empty() || (redirects && args.len() != 2) {
        return Err(USAGE.into());
    }
    let signals = block_stop_signals();

    let mut ebpf = Ebpf::load(&ELF.0)?;
    if redirects {
        let mut trust: HashMap<_, FlowKey, FlowStats> = HashMap::try_from(ebpf.map_mut("TRUST").ok_or("no map TRUST")?)?;
        for key in &flows {
            trust.insert(key, &FlowStats::default(), 0)?;
            trust.insert(&key.reverse(), &FlowStats::default(), 0)?;
        }
        let (a, b) = (ifindex(&args[0])?, ifindex(&args[1])?);
        let mut peer: HashMap<_, u32, u32> = HashMap::try_from(ebpf.map_mut("PEER").ok_or("no map PEER")?)?;
        peer.insert(&a, &b, 0)?;
        peer.insert(&b, &a, 0)?;
        if program == "v5_routed" {
            let mut config: aya::maps::Array<_, u32> = aya::maps::Array::try_from(ebpf.map_mut("ROUTE_VIA").ok_or("no map ROUTE_VIA")?)?;
            config.set(0, &via, 0)?;
            let mut hops: HashMap<_, u32, u32> = HashMap::try_from(ebpf.map_mut("NEXTHOP").ok_or("no map NEXTHOP")?)?;
            for (interface, hop) in &nexthops {
                hops.insert(&ifindex(interface)?, &u32::from_ne_bytes(hop.octets()), 0)?;
            }
        }
    } else {
        let mut lookup: HashMap<_, FlowKey, u64> = HashMap::try_from(ebpf.map_mut("FLOWS").ok_or("no map FLOWS")?)?;
        for key in &flows {
            lookup.insert(key, &0, 0)?;
        }
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
    println!("prog_id={} flows={}", prog.info()?.id(), flows.len());
    std::io::stdout().flush()?;

    wait_for(&signals);
    let counts: PerCpuArray<_, u64> = PerCpuArray::try_from(ebpf.map("COUNT").ok_or("no map COUNT")?)?;
    let packets: u64 = counts.get(&0, 0)?.iter().sum();
    let hits: u64 = counts.get(&1, 0)?.iter().sum();
    let trust: HashMap<_, FlowKey, FlowStats> = HashMap::try_from(ebpf.map("TRUST").ok_or("no map TRUST")?)?;
    let trusted = trust.keys().filter(Result::is_ok).count();
    println!("packets={packets} hits={hits} trust_entries={trusted}");
    Ok(())
}

fn mapbench(entries: u32) -> Result<(), Box<dyn Error>> {
    let mut ebpf = Ebpf::load(&ELF.0)?;
    let mut trust: HashMap<&mut MapData, FlowKey, FlowStats> =
        HashMap::try_from(ebpf.map_mut("TRUST").ok_or("no map TRUST")?)?;
    let keys: Vec<FlowKey> = (0..entries)
        .map(|i| FlowKey {
            saddr: [u32::from_ne_bytes([10, 1, (i >> 8) as u8, i as u8]), 0, 0, 0],
            daddr: [u32::from_ne_bytes([10, 2, 0, 1]), 0, 0, 0],
            sport: ((i % 50000) as u16 + 1024).to_be(),
            dport: 443u16.to_be(),
            proto: 6,
        })
        .collect();
    let start = Instant::now();
    for key in &keys {
        trust.insert(key, &FlowStats::default(), 0)?;
    }
    let insert = start.elapsed();
    let start = Instant::now();
    for key in &keys {
        trust.get(key, 0)?;
    }
    let lookup = start.elapsed();
    let start = Instant::now();
    for key in &keys {
        trust.remove(key)?;
    }
    let remove = start.elapsed();
    let per = |d: std::time::Duration| d.as_secs_f64() * 1e6 / f64::from(entries);
    println!(
        "entries={entries} insert_us={:.2} lookup_us={:.2} remove_us={:.2}",
        per(insert),
        per(lookup),
        per(remove)
    );
    Ok(())
}

fn ifindex(name: &str) -> Result<u32, Box<dyn Error>> {
    let c = CString::new(name)?;
    match unsafe { libc::if_nametoindex(c.as_ptr()) } {
        0 => Err(format!("unknown interface {name:?}").into()),
        index => Ok(index),
    }
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
