use rustc_hash::FxHashMap as HashMap;

use crate::conntrack::Live;
use crate::packet::{Key, Protocol, SECOND};

pub const CHECK_INTERVAL: u64 = 5 * SECOND;
pub const IDLE_INTERVAL: u64 = 10 * SECOND;
pub const TCP_IDLE: u64 = 600 * SECOND;
const UDP_IDLE: u64 = 120 * SECOND;
pub const ALERT_MEMORY: u64 = 600 * SECOND;
const MAX_ALERTED: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub min_packets: u64,
    pub min_age: u64,
    pub ttl: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_packets: 10,
            min_age: 5 * SECOND,
            ttl: 900 * SECOND,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Watching { since: u64, base: [u64; 2] },
    Trusted { until: u64 },
    Refused,
}

#[derive(Debug, Clone, Copy)]
struct Tracked {
    id: u64,
    seen: u64,
    state: State,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Trust(Key),
    Expire(Key),
    Revoke(Key),
}

#[derive(Debug, Default)]
pub struct Agent {
    policy: Policy,
    tracked: HashMap<Key, Tracked>,
    alerted: HashMap<Key, u64>,
    pub refused: u64,
}

impl Agent {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    pub fn is_idle(&self) -> bool {
        self.tracked.is_empty()
    }

    pub fn alert(&mut self, key: Option<Key>, now: u64) -> Option<Decision> {
        let key = key?;
        if self.alerted.len() >= MAX_ALERTED {
            self.alerted.retain(|_, at| now - *at < ALERT_MEMORY);
        }
        if self.alerted.len() < MAX_ALERTED || self.alerted.contains_key(&key) {
            self.alerted.insert(key, now);
        }
        let tracked = self.tracked.get_mut(&key)?;
        match tracked.state {
            State::Trusted { .. } => {
                tracked.state = State::Refused;
                Some(Decision::Revoke(key))
            }
            State::Watching { .. } => {
                tracked.state = State::Refused;
                self.refused += 1;
                None
            }
            State::Refused => None,
        }
    }

    pub fn observe(&mut self, live: &[Live], now: u64) -> Vec<Decision> {
        self.alerted.retain(|_, at| now - *at < ALERT_MEMORY);
        let mut decisions = Vec::new();
        for c in live {
            let watching = State::Watching {
                since: now,
                base: c.packets,
            };
            let tracked = self.tracked.entry(c.key).or_insert(Tracked {
                id: c.id,
                seen: now,
                state: watching,
            });
            tracked.seen = now;
            if tracked.id != c.id {
                tracked.state = match tracked.state {
                    State::Trusted { until } => State::Trusted { until },
                    _ => watching,
                };
                tracked.id = c.id;
            }
            if self.alerted.contains_key(&c.key) && matches!(tracked.state, State::Watching { .. }) {
                tracked.state = State::Refused;
                self.refused += 1;
            }
            match tracked.state {
                State::Trusted { until } => {
                    if now >= until {
                        tracked.state = watching;
                        decisions.push(Decision::Expire(c.key));
                    }
                }
                State::Watching { since, base } => {
                    if !c.established {
                        continue;
                    }
                    let original = c.packets[0].saturating_sub(base[0]);
                    let reply = c.packets[1].saturating_sub(base[1]);
                    if now - since >= self.policy.min_age
                        && original >= self.policy.min_packets
                        && reply >= self.policy.min_packets
                    {
                        tracked.state = State::Trusted {
                            until: now + self.policy.ttl,
                        };
                        decisions.push(Decision::Trust(c.key));
                    }
                }
                State::Refused => {}
            }
        }
        self.tracked.retain(|key, tracked| match tracked.state {
            _ if tracked.seen == now => true,
            State::Trusted { until } if now < until => true,
            State::Trusted { .. } => {
                decisions.push(Decision::Expire(*key));
                false
            }
            _ => false,
        });
        decisions
    }
}

#[derive(Debug, Default)]
pub struct IdleSweep {
    last: HashMap<Key, (u64, u64)>,
}

impl IdleSweep {
    pub fn observe(&mut self, flows: &HashMap<Key, u64>, now: u64) -> Vec<Key> {
        let mut active = HashMap::default();
        let mut idle = Vec::new();
        for (key, &packets) in flows {
            let since = match self.last.get(key) {
                Some(&(seen, since)) if seen == packets => since,
                _ => now,
            };
            let after = match key.protocol {
                Protocol::Udp => UDP_IDLE,
                Protocol::Tcp => TCP_IDLE,
            };
            if now - since >= after {
                idle.push(*key);
            } else {
                active.insert(*key, (packets, since));
            }
        }
        self.last = active;
        idle
    }
}

#[cfg(test)]
mod tests;
