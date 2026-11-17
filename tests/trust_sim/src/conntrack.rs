use std::net::SocketAddr;

use rustc_hash::FxHashMap as HashMap;

use crate::packet::{ACK, FIN, Key, Protocol, RST, SECOND, SYN};

const TCP_OPENING: u64 = 120 * SECOND;
const TCP_ESTABLISHED: u64 = 432_000 * SECOND;
const TCP_CLOSING: u64 = 120 * SECOND;
const TCP_CLOSED: u64 = 10 * SECOND;
const UDP_UNREPLIED: u64 = 30 * SECOND;
const UDP_REPLIED: u64 = 120 * SECOND;
const UDP_STREAM_AFTER: u64 = 2 * SECOND;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Udp,
    Opening,
    Established,
    Closing,
    Closed,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub id: u64,
    pub original: SocketAddr,
    pub created: u64,
    pub last: u64,
    pub timeout: u64,
    pub packets: [u64; 2],
    pub replied: bool,
    pub phase: Phase,
    pub marked: bool,
}

impl Entry {
    pub fn alive(&self, now: u64) -> bool {
        self.last + self.timeout > now
    }

    pub fn established(&self) -> bool {
        matches!(self.phase, Phase::Udp | Phase::Established)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Live {
    pub key: Key,
    pub id: u64,
    pub packets: [u64; 2],
    pub established: bool,
}

#[derive(Debug, Default)]
pub struct Conntrack {
    entries: HashMap<Key, Entry>,
    next_id: u64,
}

impl Conntrack {
    pub fn update(&mut self, key: Key, src: SocketAddr, flags: u8, now: u64) -> &mut Entry {
        let pure_syn = flags & (SYN | ACK) == SYN;
        let stale = self.entries.get(&key).is_some_and(|e| {
            !e.alive(now) || (pure_syn && matches!(e.phase, Phase::Closing | Phase::Closed))
        });
        if stale {
            self.entries.remove(&key);
        }
        let next_id = &mut self.next_id;
        let entry = self.entries.entry(key).or_insert_with(|| {
            *next_id += 1;
            let phase = match key.protocol {
                Protocol::Udp => Phase::Udp,
                Protocol::Tcp if flags & RST != 0 => Phase::Closed,
                Protocol::Tcp if flags & FIN != 0 => Phase::Closing,
                Protocol::Tcp if pure_syn => Phase::Opening,
                Protocol::Tcp => Phase::Established,
            };
            Entry {
                id: *next_id,
                original: src,
                created: now,
                last: now,
                timeout: 0,
                packets: [0, 0],
                replied: false,
                phase,
                marked: false,
            }
        });
        let reply = src != entry.original;
        entry.packets[usize::from(reply)] += 1;
        entry.replied |= reply;
        entry.phase = match entry.phase {
            Phase::Udp => Phase::Udp,
            _ if flags & RST != 0 => Phase::Closed,
            Phase::Closed => Phase::Closed,
            _ if flags & FIN != 0 => Phase::Closing,
            Phase::Opening if entry.replied && flags & SYN == 0 => Phase::Established,
            phase => phase,
        };
        entry.timeout = match entry.phase {
            Phase::Udp if entry.replied && now > entry.created + UDP_STREAM_AFTER => UDP_REPLIED,
            Phase::Udp => UDP_UNREPLIED,
            Phase::Opening => TCP_OPENING,
            Phase::Established => TCP_ESTABLISHED,
            Phase::Closing => TCP_CLOSING,
            Phase::Closed => TCP_CLOSED,
        };
        entry.last = now;
        entry
    }

    pub fn get_mut(&mut self, key: &Key, now: u64) -> Option<&mut Entry> {
        self.entries.get_mut(key).filter(|e| e.alive(now))
    }

    pub fn live(&mut self, now: u64) -> Vec<Live> {
        self.entries.retain(|_, e| e.alive(now));
        self.entries
            .iter()
            .map(|(key, e)| Live {
                key: *key,
                id: e.id,
                packets: e.packets,
                established: e.established(),
            })
            .collect()
    }

    pub fn next_expiry(&self) -> Option<u64> {
        self.entries.values().map(|e| e.last + e.timeout).min()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests;
