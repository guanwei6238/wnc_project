#![no_std]
#![no_main]

use core::mem::size_of;

use aya_ebpf::bindings::tcx_action_base::TCX_NEXT;
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::{HashMap, PerCpuArray};
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

// 0：封包數，1：V3 查到的次數
#[map]
static COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

#[map]
static FLOWS: HashMap<FlowKey, u64> = HashMap::with_max_entries(65536, 0);

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
