#![no_std]
#![no_main]

use core::mem::{MaybeUninit, size_of};
use core::ptr::{self, addr_of, addr_of_mut, read_volatile, write_volatile};

use aya_ebpf::EbpfContext;
use aya_ebpf::bindings::__sk_buff;
use aya_ebpf::bindings::tcx_action_base::TCX_NEXT;
use aya_ebpf::bindings::{bpf_fib_lookup, bpf_redir_neigh};
use aya_ebpf::helpers::{bpf_fib_lookup as fib_lookup, bpf_ktime_get_ns, bpf_redirect, bpf_redirect_neigh};
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray};
use aya_ebpf::programs::TcContext;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowKey {
    saddr: [u32; 4],
    daddr: [u32; 4],
    sport: u16,
    dport: u16,
    proto: u32,
}

// 0：封包數，1：V3 查到的次數、V4 redirect 的次數
#[map]
static COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

#[map]
static FLOWS: HashMap<FlowKey, u64> = HashMap::with_max_entries(65536, 0);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowStats {
    packets: u64,
    bytes: u64,
    last_ns: u64,
}

// V4：信任的五元組（每個方向一筆）和收到的 port → 送出的 port
#[map]
static TRUST: HashMap<FlowKey, FlowStats> = HashMap::with_max_entries(65536, 0);

#[map]
static PEER: HashMap<u32, u32> = HashMap::with_max_entries(8, 0);

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

#[inline(always)]
fn count(index: u32) {
    if let Some(n) = COUNT.get_ptr_mut(index) {
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

enum L4 {
    At34,
    At54,
    At(usize),
}

// 沒有 CAP_PERFMON 時 verifier 不接受「變數 offset ＋ 封包指標」（編譯器會產生 scalar += pkt），
// 所以常見的兩種位置用固定 offset 直接讀，IPv4 帶 option 時改用 bpf_skb_load_bytes
#[inline(always)]
fn lookup(ctx: &TcContext) -> Option<()> {
    // key 一次組好：先清成 0 再填欄位會被編成逐 byte 的 memset，沒有 CAP_PERFMON 時 verifier 也不接受
    let (proto, saddr, daddr, l4): (u8, [u32; 4], [u32; 4], L4) = match u16::from_be(read::<u16>(ctx, 12)?) {
        0x0800 => {
            let vhl = read::<u8>(ctx, 14)?;
            let l4 = if vhl == 0x45 { L4::At34 } else { L4::At(14 + (vhl & 0x0f) as usize * 4) };
            (read(ctx, 23)?, [read(ctx, 26)?, 0, 0, 0], [read(ctx, 30)?, 0, 0, 0], l4)
        }
        0x86dd => (
            read(ctx, 20)?,
            [read(ctx, 22)?, read(ctx, 26)?, read(ctx, 30)?, read(ctx, 34)?],
            [read(ctx, 38)?, read(ctx, 42)?, read(ctx, 46)?, read(ctx, 50)?],
            L4::At54,
        ),
        _ => return None,
    };
    let (sport, dport) = if proto == 6 || proto == 17 {
        match l4 {
            L4::At34 => (read(ctx, 34)?, read(ctx, 36)?),
            L4::At54 => (read(ctx, 54)?, read(ctx, 56)?),
            L4::At(offset) => {
                let ports: [u16; 2] = ctx.load(offset).ok()?;
                (ports[0], ports[1])
            }
        }
    } else {
        (0, 0)
    };
    let key = FlowKey {
        saddr,
        daddr,
        sport,
        dport,
        proto: u32::from(proto),
    };
    if unsafe { FLOWS.get(&key) }.is_some() {
        count(1);
    }
    Some(())
}

#[inline(always)]
fn fast_path(ctx: &TcContext) -> Option<i32> {
    let ethertype = u16::from_be(read::<u16>(ctx, 12)?);
    // 廣播、多播交回 bridge：它們也要送給 gateway 自己。
    // 先讀 offset 12 才讀 0：offset 0 自己的邊界檢查會被 LLVM 改成 data >= data_end，verifier 不認得
    if read::<u8>(ctx, 0)? & 1 != 0 {
        return None;
    }
    let (proto, saddr, daddr, l4): (u8, [u32; 4], [u32; 4], L4) = match ethertype {
        0x0800 => {
            let vhl = read::<u8>(ctx, 14)?;
            // 分片沒有 L4 header，交回 netfilter（conntrack 會先組回）
            if u16::from_be(read::<u16>(ctx, 20)?) & 0x3fff != 0 {
                return None;
            }
            let l4 = if vhl == 0x45 { L4::At34 } else { L4::At(14 + (vhl & 0x0f) as usize * 4) };
            (read(ctx, 23)?, [read(ctx, 26)?, 0, 0, 0], [read(ctx, 30)?, 0, 0, 0], l4)
        }
        0x86dd => (
            read(ctx, 20)?,
            [read(ctx, 22)?, read(ctx, 26)?, read(ctx, 30)?, read(ctx, 34)?],
            [read(ctx, 38)?, read(ctx, 42)?, read(ctx, 46)?, read(ctx, 50)?],
            L4::At54,
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
        // 純 SYN：同一組五元組的新連線，不沿用舊的信任
        if flags & (TCP_SYN | TCP_ACK) == TCP_SYN {
            let reverse = FlowKey {
                saddr: daddr,
                daddr: saddr,
                sport: dport,
                dport: sport,
                proto: u32::from(proto),
            };
            let _ = TRUST.remove(&key);
            let _ = TRUST.remove(&reverse);
        }
        return None;
    }
    let stats = TRUST.get_ptr_mut(&key)?;
    let skb = ctx.as_ptr() as *const __sk_buff;
    let (ifindex, len) = unsafe { ((*skb).ifindex, (*skb).len) };
    let peer = unsafe { PEER.get(&ifindex) }?;
    unsafe {
        (*stats).packets += 1;
        (*stats).bytes += u64::from(len);
        (*stats).last_ns = bpf_ktime_get_ns();
    }
    Some(unsafe { bpf_redirect(*peer, 0) } as i32)
}

#[classifier]
pub fn v4_redirect(ctx: TcContext) -> i32 {
    count(0);
    match fast_path(&ctx) {
        Some(action) => {
            count(1);
            action
        }
        None => TCX_NEXT,
    }
}

// V5：routed 的三種送法。0 = bpf_redirect_neigh 不帶參數（kernel 查路由和 neighbor，wnc-gw 現在的做法）；
// 1 = bpf_redirect_neigh 帶下一跳（kernel 只查 neighbor，下一跳從 NEXTHOP 查，key 是出口的 ifindex）；
// 2 = bpf_fib_lookup（kernel 查路由和 neighbor 給 MAC）＋自己改 MAC＋bpf_redirect（GPL-only）
#[map]
static ROUTE_VIA: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static NEXTHOP: HashMap<u32, u32> = HashMap::with_max_entries(8, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct FibParams {
    family: u8,
    l4_protocol: u8,
    sport: u16,
    dport: u16,
    tot_len: u16,
    ifindex: u32,
    tos: u32,
    src: [u32; 4],
    dst: [u32; 4],
    vlan: u32,
    // MAC 拆成純量欄位：全部是 0 的陣列會被編成 memset，沒有 CAP_PERFMON 時 verifier 不接受
    smac0: u16,
    smac1: u16,
    smac2: u16,
    dmac0: u16,
    dmac1: u16,
    dmac2: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RedirNeigh {
    family: u32,
    addr: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EthAddrs {
    dmac0: u16,
    dmac1: u16,
    dmac2: u16,
    smac0: u16,
    smac1: u16,
    smac2: u16,
}

const AF_INET: u32 = 2;

#[inline(always)]
fn routed_path(ctx: &TcContext) -> Option<i32> {
    let ethertype = u16::from_be(read::<u16>(ctx, 12)?);
    if read::<u8>(ctx, 0)? & 1 != 0 || ethertype != 0x0800 {
        return None;
    }
    let vhl = read::<u8>(ctx, 14)?;
    if vhl != 0x45 || u16::from_be(read::<u16>(ctx, 20)?) & 0x3fff != 0 {
        return None;
    }
    let proto: u8 = read(ctx, 23)?;
    if proto != 6 && proto != 17 {
        return None;
    }
    let (saddr, daddr): (u32, u32) = (read(ctx, 26)?, read(ctx, 30)?);
    let (sport, dport): (u16, u16) = (read(ctx, 34)?, read(ctx, 36)?);
    if proto == 6 && read::<u8>(ctx, 47)? & (TCP_SYN | TCP_FIN | TCP_RST) != 0 {
        return None;
    }
    let key = FlowKey {
        saddr: [saddr, 0, 0, 0],
        daddr: [daddr, 0, 0, 0],
        sport,
        dport,
        proto: u32::from(proto),
    };
    let stats = TRUST.get_ptr_mut(&key)?;
    let skb = ctx.as_ptr() as *const __sk_buff;
    let (ifindex, len) = unsafe { ((*skb).ifindex, (*skb).len) };
    let peer = *unsafe { PEER.get(&ifindex) }?;
    let ttl: u8 = read(ctx, 22)?;
    if ttl <= 1 {
        return None;
    }
    let via = ROUTE_VIA.get(0).copied().unwrap_or(0);
    // 一個欄位一個欄位用 write_volatile 寫：連續的 0 會被 LLVM 合成 memset，沒有 CAP_PERFMON 時 verifier 不接受。
    // FibParams 沒有 padding，所以每個 byte 都寫到了
    let mut slot = MaybeUninit::<FibParams>::uninit();
    let f = slot.as_mut_ptr();
    let tot_len = u16::from_be(read::<u16>(ctx, 16)?);
    let tos = u32::from(read::<u8>(ctx, 15)?);
    unsafe {
        write_volatile(addr_of_mut!((*f).family), AF_INET as u8);
        write_volatile(addr_of_mut!((*f).l4_protocol), proto);
        write_volatile(addr_of_mut!((*f).sport), sport);
        write_volatile(addr_of_mut!((*f).dport), dport);
        write_volatile(addr_of_mut!((*f).tot_len), tot_len);
        write_volatile(addr_of_mut!((*f).ifindex), ifindex);
        write_volatile(addr_of_mut!((*f).tos), tos);
        write_volatile(addr_of_mut!((*f).src), [saddr, 0, 0, 0]);
        write_volatile(addr_of_mut!((*f).dst[0]), daddr);
        write_volatile(addr_of_mut!((*f).dst[1]), 0);
        write_volatile(addr_of_mut!((*f).dst[2]), 0);
        write_volatile(addr_of_mut!((*f).dst[3]), 0);
        write_volatile(addr_of_mut!((*f).vlan), 0);
        write_volatile(addr_of_mut!((*f).smac0), 0);
        write_volatile(addr_of_mut!((*f).smac1), 0);
        write_volatile(addr_of_mut!((*f).smac2), 0);
        write_volatile(addr_of_mut!((*f).dmac0), 0);
        write_volatile(addr_of_mut!((*f).dmac1), 0);
        write_volatile(addr_of_mut!((*f).dmac2), 0);
    }
    if via == 2 {
        let ret = unsafe {
            fib_lookup(ctx.as_ptr(), f as *mut bpf_fib_lookup, size_of::<FibParams>() as i32, 0)
        };
        // 查不到、neighbor 還沒解析、出口不是另一個 port：交回 kernel
        if ret != 0 || unsafe { read_volatile(addr_of!((*f).ifindex)) } != peer {
            return None;
        }
    }
    let old: u16 = read(ctx, 22)?;
    let new = u16::from_ne_bytes([ttl - 1, proto]);
    ctx.store(22, &(ttl - 1), 0).ok()?;
    ctx.l3_csum_replace(24, u64::from(old), u64::from(new), 2).ok()?;
    unsafe {
        (*stats).packets += 1;
        (*stats).bytes += u64::from(len);
        (*stats).last_ns = bpf_ktime_get_ns();
    }
    let action = match via {
        2 => {
            let eth = unsafe {
                EthAddrs {
                    dmac0: read_volatile(addr_of!((*f).dmac0)),
                    dmac1: read_volatile(addr_of!((*f).dmac1)),
                    dmac2: read_volatile(addr_of!((*f).dmac2)),
                    smac0: read_volatile(addr_of!((*f).smac0)),
                    smac1: read_volatile(addr_of!((*f).smac1)),
                    smac2: read_volatile(addr_of!((*f).smac2)),
                }
            };
            ctx.store(0, &eth, 0).ok()?;
            unsafe { bpf_redirect(peer, 0) }
        }
        1 => {
            let hop = *unsafe { NEXTHOP.get(&peer) }?;
            let mut nh = RedirNeigh {
                family: AF_INET,
                addr: [hop, 0, 0, 0],
            };
            unsafe {
                bpf_redirect_neigh(peer, &mut nh as *mut RedirNeigh as *mut bpf_redir_neigh, size_of::<RedirNeigh>() as i32, 0)
            }
        }
        _ => unsafe { bpf_redirect_neigh(peer, ptr::null_mut(), 0, 0) },
    };
    Some(action as i32)
}

#[classifier]
pub fn v5_routed(ctx: TcContext) -> i32 {
    count(0);
    match routed_path(&ctx) {
        Some(action) => {
            count(1);
            action
        }
        None => TCX_NEXT,
    }
}

#[classifier]
pub fn v1_empty(_ctx: TcContext) -> i32 {
    TCX_NEXT
}

#[classifier]
pub fn v2_count(_ctx: TcContext) -> i32 {
    count(0);
    TCX_NEXT
}

#[classifier]
pub fn v3_lookup(ctx: TcContext) -> i32 {
    count(0);
    let _ = lookup(&ctx);
    TCX_NEXT
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
