#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug, PartialEq, Eq, Hash))]
pub struct FlowKey {
    pub saddr: [u32; 4],
    pub daddr: [u32; 4],
    pub sport: u16,
    pub dport: u16,
    pub proto: u32,
}

impl FlowKey {
    pub const fn reverse(&self) -> Self {
        Self {
            saddr: self.daddr,
            daddr: self.saddr,
            sport: self.dport,
            dport: self.sport,
            proto: self.proto,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[cfg_attr(feature = "user", derive(Debug, PartialEq, Eq))]
pub struct FlowStats {
    pub packets: u64,
    pub bytes: u64,
    pub last_ns: u64,
    pub direction: u32,
    pub nh_family: u32,
    pub nh: [u32; 4],
    pub nh_generation: u32,
    pub pad: u32,
    pub reserved: [u64; 2],
}

pub const TRUST_ENTRIES: u32 = 32768;
pub const MODE_BRIDGE: u32 = 0;
pub const MODE_ROUTED: u32 = 1;
pub const COUNTER_PACKETS: u32 = 0;
pub const COUNTER_REDIRECTED: u32 = 1;
pub const CONFIG_MODE: u32 = 0;
pub const CONFIG_ROUTE_GENERATION: u32 = 1;
pub const NH_NONE: u32 = 0;
pub const NH_INET: u32 = 2;
pub const NH_INET6: u32 = 10;
pub const DIRECTION_ORIGINAL: u32 = 1;
pub const DIRECTION_REPLY: u32 = 2;

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowStats {}
