#![no_std]
#![no_main]

use aya_ebpf::bindings::tcx_action_base::TCX_NEXT;
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::PerCpuArray;
use aya_ebpf::programs::TcContext;

#[map]
static PACKETS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[classifier]
pub fn wnc_gw_ingress(_ctx: TcContext) -> i32 {
    if let Some(count) = PACKETS.get_ptr_mut(0) {
        unsafe { *count += 1 };
    }
    TCX_NEXT
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
