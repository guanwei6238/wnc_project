use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use gw_common::{
    CONFIG_MODE, CONFIG_ROUTE_GENERATION, COUNTER_PACKETS, COUNTER_REDIRECTED, DIRECTION_ORIGINAL, DIRECTION_REPLY,
    FlowKey, FlowStats, MODE_BRIDGE, MODE_ROUTED, NH_INET, NH_INET6, NH_NONE,
};

use crate::config::ports::Port;
use crate::forwarding::Mode;
use crate::kernel::{bpf::{BpfError, TcxProgram}, conntrack::{FiveTuple, Protocol}};

#[repr(C, align(8))]
struct Aligned<T: ?Sized>(T);

static ELF: &Aligned<[u8]> = &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/gw-ebpf")));

pub const CORE_PROGRAM_NAME: &str = "wnc_gw_ingress";
const COUNTERS: &str = "COUNTERS";
const TRUST: &str = "TRUST";
const PEER: &str = "PEER";
const CONFIG: &str = "CONFIG";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedFlow {
    pub tuple: FiveTuple,
    pub original: FlowStats,
    pub reply: FlowStats,
}

impl TrustedFlow {
    pub fn next_hop_original(&self, generation: Option<u32>) -> Option<IpAddr> {
        next_hop(&self.original, generation?)
    }

    pub fn next_hop_reply(&self, generation: Option<u32>) -> Option<IpAddr> {
        next_hop(&self.reply, generation?)
    }
}

fn next_hop(stats: &FlowStats, generation: u32) -> Option<IpAddr> {
    if stats.nh_generation != generation {
        return None;
    }
    let words = stats.nh;
    match stats.nh_family {
        NH_INET => Some(IpAddr::V4(Ipv4Addr::from(words[0].to_ne_bytes()))),
        NH_INET6 => {
            let mut bytes = [0u8; 16];
            for (chunk, word) in bytes.chunks_exact_mut(4).zip(words) {
                chunk.copy_from_slice(&word.to_ne_bytes());
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("only TCP and UDP connections can be trusted, not {0}")]
pub struct UntrustableProtocol(Protocol);

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error(transparent)]
    Protocol(#[from] UntrustableProtocol),
    #[error(transparent)]
    Bpf(#[from] BpfError),
}

pub struct CoreProgram {
    program: TcxProgram,
    ports: Vec<u32>,
    route_generation: u32,
}

impl CoreProgram {
    pub fn attach(ports: &[Port], mode: Mode) -> Result<Self, BpfError> {
        let mut program = TcxProgram::load(&ELF.0, CORE_PROGRAM_NAME)?;
        let mode = match mode {
            Mode::Bridge => MODE_BRIDGE,
            Mode::Routed => MODE_ROUTED,
        };
        program.set_u32(CONFIG, CONFIG_MODE, mode)?;
        program.set_u32(CONFIG, CONFIG_ROUTE_GENERATION, 1)?;
        if let [a, b] = ports {
            program.insert_u32(PEER, a.interface.index, b.interface.index)?;
            program.insert_u32(PEER, b.interface.index, a.interface.index)?;
        }
        for port in ports {
            program.attach_ingress_first(port.interface.index)?;
        }
        Ok(Self {
            program,
            ports: ports.iter().map(|port| port.interface.index).collect(),
            route_generation: 1,
        })
    }

    pub fn ports(&self) -> &[u32] {
        &self.ports
    }

    pub fn route_generation(&self) -> u32 {
        self.route_generation
    }

    pub fn invalidate_next_hops(&mut self) -> Result<(), BpfError> {
        let next = self.route_generation.wrapping_add(1).max(1);
        self.program.set_u32(CONFIG, CONFIG_ROUTE_GENERATION, next)?;
        self.route_generation = next;
        Ok(())
    }

    pub fn set_next_hops(
        &mut self,
        tuple: &FiveTuple,
        original: Option<IpAddr>,
        reply: Option<IpAddr>,
        generation: u32,
    ) -> Result<bool, TrustError> {
        let key = key_of(tuple)?;
        for (key, hop) in [(key, original), (key.reverse(), reply)] {
            let Some(mut stats) = self.program.get_flow(TRUST, &key)? else {
                return Ok(false);
            };
            (stats.nh_family, stats.nh) = match hop {
                Some(ip @ IpAddr::V4(_)) => (NH_INET, address(ip)),
                Some(ip @ IpAddr::V6(_)) => (NH_INET6, address(ip)),
                None => (NH_NONE, [0; 4]),
            };
            stats.nh_generation = generation;
            if !self.program.update_flow(TRUST, &key, &stats)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn id(&self) -> u32 {
        self.program.id()
    }

    pub fn packets(&self) -> Result<u64, BpfError> {
        self.program.per_cpu_sum(COUNTERS, COUNTER_PACKETS)
    }

    pub fn redirected(&self) -> Result<u64, BpfError> {
        self.program.per_cpu_sum(COUNTERS, COUNTER_REDIRECTED)
    }

    pub fn trust(&mut self, tuple: &FiveTuple) -> Result<(), TrustError> {
        let key = key_of(tuple)?;
        let stats = |direction| FlowStats {
            direction,
            ..FlowStats::default()
        };
        self.program.insert_flow(TRUST, &key, &stats(DIRECTION_ORIGINAL))?;
        if let Err(e) = self.program.insert_flow(TRUST, &key.reverse(), &stats(DIRECTION_REPLY)) {
            let _ = self.program.remove_flow(TRUST, &key);
            return Err(e.into());
        }
        Ok(())
    }

    pub fn untrust(&mut self, tuple: &FiveTuple) -> Result<bool, TrustError> {
        let key = key_of(tuple)?;
        let original = self.program.remove_flow(TRUST, &key)?;
        let reply = self.program.remove_flow(TRUST, &key.reverse())?;
        Ok(original || reply)
    }

    pub fn trusted(&self) -> Result<Vec<TrustedFlow>, BpfError> {
        Ok(pair_flows(self.program.flows(TRUST)?))
    }
}

fn pair_flows(mut flows: Vec<(FlowKey, FlowStats)>) -> Vec<TrustedFlow> {
    let mut pairs = Vec::new();
    while let Some((key, stats)) = flows.pop() {
        let reverse = key.reverse();
        let other = flows.iter().position(|(k, _)| *k == reverse).map(|i| flows.swap_remove(i).1);
        let (key, original, reply) = match other {
            Some(other) if stats.direction == DIRECTION_REPLY => (reverse, other, stats),
            other => (key, stats, other.unwrap_or_default()),
        };
        let Some(tuple) = tuple_of(&key) else { continue };
        pairs.push(TrustedFlow { tuple, original, reply });
    }
    pairs.sort_by_key(|flow| flow.tuple.to_string());
    pairs
}

fn key_of(tuple: &FiveTuple) -> Result<FlowKey, UntrustableProtocol> {
    let proto = match tuple.protocol() {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
        other => return Err(UntrustableProtocol(other)),
    };
    Ok(FlowKey {
        saddr: address(tuple.src().ip()),
        daddr: address(tuple.dst().ip()),
        sport: tuple.src().port().to_be(),
        dport: tuple.dst().port().to_be(),
        proto,
    })
}

fn tuple_of(key: &FlowKey) -> Option<FiveTuple> {
    let protocol = match key.proto {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return None,
    };
    let ipv4 = key.saddr[1..] == [0; 3] && key.daddr[1..] == [0; 3];
    let ip = |words: [u32; 4]| -> IpAddr {
        if ipv4 {
            IpAddr::V4(Ipv4Addr::from(words[0].to_ne_bytes()))
        } else {
            let mut bytes = [0u8; 16];
            for (chunk, word) in bytes.chunks_exact_mut(4).zip(words) {
                chunk.copy_from_slice(&word.to_ne_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
    };
    let src = SocketAddr::new(ip(key.saddr), u16::from_be(key.sport));
    let dst = SocketAddr::new(ip(key.daddr), u16::from_be(key.dport));
    FiveTuple::new(protocol, src, dst).ok()
}

fn address(ip: IpAddr) -> [u32; 4] {
    match ip {
        IpAddr::V4(a) => [u32::from_ne_bytes(a.octets()), 0, 0, 0],
        IpAddr::V6(a) => {
            let o = a.octets();
            std::array::from_fn(|i| u32::from_ne_bytes([o[i * 4], o[i * 4 + 1], o[i * 4 + 2], o[i * 4 + 3]]))
        }
    }
}

#[cfg(test)]
mod tests;
