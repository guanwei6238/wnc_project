#![no_std]
#![no_main]

use core::mem::size_of;

use aya_ebpf::bindings::tcx_action_base::TCX_NEXT;
use aya_ebpf::bindings::xdp_action::XDP_PASS;
use aya_ebpf::btf_maps::{HashMap, PerCpuHashMap, RingBuf};
use aya_ebpf::helpers::{bpf_ktime_get_ns, bpf_xdp_get_buff_len};
use aya_ebpf::macros::{btf_map, classifier, map, xdp};
use aya_ebpf::maps::HashMap as LegacyHashMap;
use aya_ebpf::programs::{TcContext, XdpContext};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Key {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
    proto: u8,
    pad8: u8,
    pad16: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Value {
    packets: u64,
    bytes: u64,
    len_sumsq: u64,
    first_ns: u64,
    last_ns: u64,
    hist: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    saddr: u32,
    len: u32,
}

#[btf_map]
static FLOWS: HashMap<Key, Value, 16384> = HashMap::new();

#[btf_map]
static PFLOWS: PerCpuHashMap<Key, Value, 16384> = PerCpuHashMap::new();

#[btf_map]
static EVENTS: RingBuf<Event, 65536> = RingBuf::new();

#[map]
static LEGACY: LegacyHashMap<Key, Value> = LegacyHashMap::with_max_entries(1024, 0);

const ETH_HLEN: usize = 14;

fn bucket(len: u64) -> usize {
    match len {
        0..=64 => 0,
        65..=256 => 1,
        257..=1024 => 2,
        _ => 3,
    }
}

fn update<M: Fn(&Key) -> Option<*mut Value>, I: Fn(&Key, &Value)>(key: &Key, len: u64, get: M, insert: I) {
    let now = unsafe { bpf_ktime_get_ns() };
    match get(key) {
        Some(v) => unsafe {
            (*v).packets += 1;
            (*v).bytes += len;
            (*v).len_sumsq += len * len;
            (*v).last_ns = now;
            match bucket(len) {
                0 => (*v).hist[0] += 1,
                1 => (*v).hist[1] += 1,
                2 => (*v).hist[2] += 1,
                _ => (*v).hist[3] += 1,
            }
        },
        None => {
            let b = bucket(len);
            let hist = [u32::from(b == 0), u32::from(b == 1), u32::from(b == 2), u32::from(b == 3)];
            let value = Value { packets: 1, bytes: len, len_sumsq: len * len, first_ns: now, last_ns: now, hist };
            insert(key, &value);
        }
    }
}

fn record(key: &Key, len: u64) {
    update(key, len, |k| FLOWS.get_ptr_mut(k), |k, v| {
        let _ = FLOWS.insert(k, v, 0);
    });
    update(key, len, |k| PFLOWS.get_ptr_mut(k), |k, v| {
        let _ = PFLOWS.insert(k, v, 0);
    });
    update(key, len, |k| LEGACY.get_ptr_mut(k), |k, v| {
        let _ = LEGACY.insert(k, v, 0);
    });
    let _ = EVENTS.output(&Event { saddr: key.saddr, len: len as u32 }, 0);
}

fn key_from(eth_type: [u8; 2], ip: [u8; 20], ports: [u8; 4]) -> Option<Key> {
    if eth_type != [0x08, 0x00] || ip[0] != 0x45 || (ip[9] != 6 && ip[9] != 17) {
        return None;
    }
    Some(Key {
        saddr: u32::from_ne_bytes([ip[12], ip[13], ip[14], ip[15]]),
        daddr: u32::from_ne_bytes([ip[16], ip[17], ip[18], ip[19]]),
        sport: u16::from_ne_bytes([ports[0], ports[1]]),
        dport: u16::from_ne_bytes([ports[2], ports[3]]),
        proto: ip[9],
        pad8: 0,
        pad16: 0,
    })
}

#[classifier]
pub fn flows_tc(ctx: TcContext) -> i32 {
    let (Ok(eth), Ok(ip), Ok(ports)) = (ctx.load::<[u8; 2]>(12), ctx.load::<[u8; 20]>(ETH_HLEN), ctx.load::<[u8; 4]>(ETH_HLEN + 20)) else {
        return TCX_NEXT;
    };
    if let Some(key) = key_from(eth, ip, ports) {
        record(&key, u64::from(ctx.skb.len()));
    }
    TCX_NEXT
}

#[xdp]
pub fn flows_xdp(ctx: XdpContext) -> u32 {
    let (start, end) = (ctx.data(), ctx.data_end());
    if start + ETH_HLEN + 24 > end {
        return XDP_PASS;
    }
    let read = |offset: usize| unsafe { core::ptr::read_unaligned((start + offset) as *const [u8; 4]) };
    let eth = read(12);
    let mut ip = [0u8; 20];
    for (i, chunk) in ip.chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&read(ETH_HLEN + 4 * i));
    }
    if let Some(key) = key_from([eth[0], eth[1]], ip, read(ETH_HLEN + 20)) {
        record(&key, unsafe { bpf_xdp_get_buff_len(ctx.ctx) });
    }
    XDP_PASS
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

const _: () = assert!(size_of::<Key>() == 16 && size_of::<Value>() == 56);
