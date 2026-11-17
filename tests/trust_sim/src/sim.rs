use std::collections::BTreeMap;

use rustc_hash::FxHashMap as HashMap;

use crate::agent::{ALERT_MEMORY, Agent, CHECK_INTERVAL, Decision, IDLE_INTERVAL, IdleSweep, Policy, TCP_IDLE};
use crate::conntrack::Conntrack;
use crate::packet::{ACK, Alert, FIN, Key, Kind, Packet, RST, SYN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    CtMark,
    Tc,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub packets: u64,
    pub bytes: u64,
    pub fast_packets: u64,
    pub fast_bytes: u64,
    pub trusted: u64,
    pub expired: u64,
    pub revoked: u64,
    pub refused: u64,
    pub idle_ended: u64,
    pub idle_resumed: u64,
    pub idle_resumed_packets: u64,
    pub idle_resumed_ports: BTreeMap<u16, (u64, u64)>,
    pub alerts_seen: u64,
    pub alerts_missed: u64,
    pub missed_sids: BTreeMap<u64, u64>,
    pub peak_conntrack: usize,
    pub peak_trusted: usize,
}

#[derive(Debug)]
pub struct Sim {
    variant: Variant,
    conntrack: Conntrack,
    agent: Agent,
    map: HashMap<Key, u64>,
    idle_cleared: HashMap<Key, bool>,
    idle: IdleSweep,
    next_check: Option<u64>,
    next_idle: u64,
    last_packet: u64,
    quiet: u64,
    stats: Stats,
}

impl Sim {
    pub fn new(variant: Variant, policy: Policy) -> Self {
        Self {
            variant,
            conntrack: Conntrack::default(),
            agent: Agent::new(policy),
            map: HashMap::default(),
            idle_cleared: HashMap::default(),
            idle: IdleSweep::default(),
            next_check: None,
            next_idle: 0,
            last_packet: 0,
            quiet: 2 * policy.ttl.max(TCP_IDLE).max(ALERT_MEMORY),
            stats: Stats::default(),
        }
    }

    pub fn packet(&mut self, p: &Packet, alerts: &[Alert]) -> bool {
        self.advance(p.ts);
        self.stats.packets += 1;
        self.stats.bytes += u64::from(p.len);
        let fast = match p.kind {
            Kind::Other => false,
            Kind::Flow {
                protocol,
                src,
                dst,
                flags,
            } => {
                let key = Key::new(protocol, src, dst);
                let control = flags & (SYN | FIN | RST) != 0;
                let pure_syn = flags & (SYN | ACK) == SYN;
                match self.variant {
                    Variant::Tc => {
                        if pure_syn {
                            self.map.remove(&key);
                            self.idle_cleared.remove(&key);
                        }
                        match self.map.get_mut(&key) {
                            Some(packets) if !control => {
                                *packets += 1;
                                true
                            }
                            _ => {
                                self.conntrack.update(key, src, flags, p.ts);
                                if !control && let Some(resumed) = self.idle_cleared.get_mut(&key) {
                                    let at = self.stats.idle_resumed_ports.entry(src.port().min(dst.port())).or_default();
                                    if !std::mem::replace(resumed, true) {
                                        self.stats.idle_resumed += 1;
                                        at.0 += 1;
                                    }
                                    at.1 += 1;
                                    self.stats.idle_resumed_packets += 1;
                                }
                                false
                            }
                        }
                    }
                    Variant::CtMark => {
                        let entry = self.conntrack.update(key, src, flags, p.ts);
                        if pure_syn {
                            entry.marked = false;
                        }
                        !control && entry.marked
                    }
                }
            }
        };
        if fast {
            self.stats.fast_packets += 1;
            self.stats.fast_bytes += u64::from(p.len);
        }
        for alert in alerts {
            if fast {
                self.stats.alerts_missed += 1;
                *self.stats.missed_sids.entry(alert.sid).or_default() += 1;
            } else {
                self.stats.alerts_seen += 1;
                if let Some(decision) = self.agent.alert(alert.key, p.ts) {
                    self.apply(decision, p.ts);
                }
            }
        }
        fast
    }

    pub fn finish(mut self) -> Stats {
        self.stats.refused = self.agent.refused;
        self.stats
    }

    fn advance(&mut self, now: u64) {
        let mut next_check = *self.next_check.get_or_insert_with(|| {
            self.next_idle = now;
            self.last_packet = now;
            now
        });
        loop {
            if self.conntrack.is_empty() && self.agent.is_idle() && self.map.is_empty() {
                if next_check <= now {
                    next_check += (now - next_check) / CHECK_INTERVAL * CHECK_INTERVAL;
                }
                if self.next_idle <= now {
                    self.next_idle += (now - self.next_idle) / IDLE_INTERVAL * IDLE_INTERVAL;
                }
            }
            let at = next_check.min(self.next_idle);
            if at > now {
                break;
            }
            if self.next_idle == at && self.variant == Variant::Tc {
                for key in self.idle.observe(&self.map, at) {
                    if self.map.remove(&key).is_some() {
                        self.stats.idle_ended += 1;
                        self.idle_cleared.insert(key, false);
                    }
                }
            }
            if next_check == at {
                let live = self.conntrack.live(at);
                self.stats.peak_conntrack = self.stats.peak_conntrack.max(live.len());
                for decision in self.agent.observe(&live, at) {
                    self.apply(decision, at);
                }
                next_check += CHECK_INTERVAL;
            }
            if self.next_idle == at {
                self.next_idle += IDLE_INTERVAL;
            }
            if at >= self.last_packet.saturating_add(self.quiet) {
                let until = self.conntrack.next_expiry().map_or(now, |e| e.min(now));
                next_check = skip_to(next_check, until, CHECK_INTERVAL);
                self.next_idle = skip_to(self.next_idle, until, IDLE_INTERVAL);
            }
        }
        self.next_check = Some(next_check);
        self.last_packet = self.last_packet.max(now);
    }

    fn apply(&mut self, decision: Decision, now: u64) {
        match decision {
            Decision::Trust(key) => {
                let trusted = match self.variant {
                    Variant::Tc => {
                        self.map.insert(key, 0);
                        self.idle_cleared.remove(&key);
                        self.stats.peak_trusted = self.stats.peak_trusted.max(self.map.len());
                        true
                    }
                    Variant::CtMark => match self.conntrack.get_mut(&key, now) {
                        Some(entry) => {
                            entry.marked = true;
                            true
                        }
                        None => false,
                    },
                };
                self.stats.trusted += u64::from(trusted);
            }
            Decision::Expire(key) => {
                if self.untrust(&key, now) {
                    self.stats.expired += 1;
                }
            }
            Decision::Revoke(key) => {
                self.untrust(&key, now);
                self.stats.revoked += 1;
            }
        }
    }

    fn untrust(&mut self, key: &Key, now: u64) -> bool {
        match self.variant {
            Variant::Tc => self.map.remove(key).is_some(),
            Variant::CtMark => self
                .conntrack
                .get_mut(key, now)
                .is_some_and(|entry| std::mem::replace(&mut entry.marked, false)),
        }
    }
}

fn skip_to(next: u64, until: u64, step: u64) -> u64 {
    if next < until { next + (until - next).div_ceil(step) * step } else { next }
}

#[cfg(test)]
mod tests;
