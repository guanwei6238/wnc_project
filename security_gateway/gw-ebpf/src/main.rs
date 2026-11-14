#![no_std]
#![no_main]

use core::mem::size_of;
use core::ptr;

use aya_ebpf::EbpfContext;
use aya_ebpf::bindings::{__sk_buff, bpf_redir_neigh, tcx_action_base::TCX_NEXT};
use aya_ebpf::helpers::{bpf_ktime_get_ns, bpf_redirect, bpf_redirect_neigh};
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray};
use aya_ebpf::programs::TcContext;
use gw_common::{
    CONFIG_MODE, CONFIG_ROUTE_GENERATION, COUNTER_PACKETS, COUNTER_REDIRECTED, FlowKey, FlowStats, MODE_ROUTED, NH_INET,
    NH_INET6, TRUST_ENTRIES,
};

#[map]
static COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

#[map]
static TRUST: HashMap<FlowKey, FlowStats> = HashMap::with_max_entries(TRUST_ENTRIES, 0);

#[map]
static PEER: HashMap<u32, u32> = HashMap::with_max_entries(8, 0);

#[map]
static CONFIG: Array<u32> = Array::with_max_entries(2, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct RedirNeigh {
    family: u32,
    addr: [u32; 4],
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

enum L4 {
    At34,
    At54,
    At(usize),
}

#[inline(always)]
fn count(index: u32) {
    if let Some(n) = COUNTERS.get_ptr_mut(index) {
        unsafe { *n += 1 };
    }
}

#[inline(always)]
fn read<T: Copy>(ctx: &TcContext, offset: usize) -> Option<T> {
    let start = ctx.data();
    if start + offset + size_of::<T>() > ctx.data_end() {
        return None;
    }
    Some(unsafe { ((start + offset) as *const T).read_unaligned() })
}

#[inline(always)]
fn fast_path(ctx: &TcContext) -> Option<i32> {
    let ethertype = u16::from_be(read::<u16>(ctx, 12)?);
    if read::<u8>(ctx, 0)? & 1 != 0 {
        return None;
    }
    let (proto, saddr, daddr, l4, ipv4): (u8, [u32; 4], [u32; 4], L4, bool) = match ethertype {
        0x0800 => {
            let vhl = read::<u8>(ctx, 14)?;
            if u16::from_be(read::<u16>(ctx, 20)?) & 0x3fff != 0 {
                return None;
            }
            let l4 = if vhl == 0x45 { L4::At34 } else { L4::At(14 + (vhl & 0x0f) as usize * 4) };
            (read(ctx, 23)?, [read(ctx, 26)?, 0, 0, 0], [read(ctx, 30)?, 0, 0, 0], l4, true)
        }
        0x86dd => (
            read(ctx, 20)?,
            [read(ctx, 22)?, read(ctx, 26)?, read(ctx, 30)?, read(ctx, 34)?],
            [read(ctx, 38)?, read(ctx, 42)?, read(ctx, 46)?, read(ctx, 50)?],
            L4::At54,
            false,
        ),
        _ => return None,
    };
    if proto != 6 && proto != 17 {
        return None;
    }
    let (sport, dport, flags): (u16, u16, u8) = match l4 {
        L4::At34 => (read(ctx, 34)?, read(ctx, 36)?, if proto == 6 { read(ctx, 47)? } else { 0 }),
        L4::At54 => (read(ctx, 54)?, read(ctx, 56)?, if proto == 6 { read(ctx, 67)? } else { 0 }),
        L4::At(offset) => {
            let ports: [u16; 2] = ctx.load(offset).ok()?;
            let flags = if proto == 6 { ctx.load(offset + 13).ok()? } else { 0 };
            (ports[0], ports[1], flags)
        }
    };
    let key = FlowKey {
        saddr,
        daddr,
        sport,
        dport,
        proto: u32::from(proto),
    };
    if flags & (TCP_SYN | TCP_FIN | TCP_RST) != 0 {
        if flags & (TCP_SYN | TCP_ACK) == TCP_SYN {
            let _ = TRUST.remove(&key);
            let _ = TRUST.remove(&key.reverse());
        }
        return None;
    }
    let stats = TRUST.get_ptr_mut(&key)?;
    let skb = ctx.as_ptr() as *const __sk_buff;
    let (ifindex, len) = unsafe { ((*skb).ifindex, (*skb).len) };
    let peer = *unsafe { PEER.get(&ifindex) }?;
    let routed = CONFIG.get(CONFIG_MODE).copied() == Some(MODE_ROUTED);
    if routed {
        if ipv4 {
            let ttl: u8 = read(ctx, 22)?;
            if ttl <= 1 {
                return None;
            }
            let old: u16 = read(ctx, 22)?;
            let new = u16::from_ne_bytes([ttl - 1, proto]);
            ctx.store(22, &(ttl - 1), 0).ok()?;
            ctx.l3_csum_replace(24, u64::from(old), u64::from(new), 2).ok()?;
        } else {
            let hop: u8 = read(ctx, 21)?;
            if hop <= 1 {
                return None;
            }
            ctx.store(21, &(hop - 1), 0).ok()?;
        }
    }
    unsafe {
        (*stats).packets += 1;
        (*stats).bytes += u64::from(len);
        (*stats).last_ns = bpf_ktime_get_ns();
    }
    let action = if routed {
        let generation = CONFIG.get(CONFIG_ROUTE_GENERATION).copied().unwrap_or(0);
        let (family, nh_generation, addr) = unsafe { ((*stats).nh_family, (*stats).nh_generation, (*stats).nh) };
        if nh_generation == generation && family == if ipv4 { NH_INET } else { NH_INET6 } {
            let mut nh = RedirNeigh { family, addr };
            unsafe {
                bpf_redirect_neigh(peer, &mut nh as *mut RedirNeigh as *mut bpf_redir_neigh, size_of::<RedirNeigh>() as i32, 0)
            }
        } else {
            unsafe { bpf_redirect_neigh(peer, ptr::null_mut(), 0, 0) }
        }
    } else {
        unsafe { bpf_redirect(peer, 0) }
    };
    Some(action as i32)
}

#[classifier]
pub fn wnc_gw_ingress(ctx: TcContext) -> i32 {
    count(COUNTER_PACKETS);
    match fast_path(&ctx) {
        Some(action) => {
            count(COUNTER_REDIRECTED);
            action
        }
        None => TCX_NEXT,
    }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
