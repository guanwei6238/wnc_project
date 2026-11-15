use std::collections::{HashMap, HashSet};
use std::mem;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tracing::{debug, error, info, warn};

use crate::ids::eve::Alert;
use crate::issue::Issue;
use crate::kernel::conntrack::{Connection, FiveTuple, Protocol, TcpState};
use super::{Privd, PrivdError};

pub const DEFAULT_MIN_PACKETS: u64 = 10;
pub const DEFAULT_MIN_AGE: Duration = Duration::from_secs(5);
pub const DEFAULT_TTL: Duration = Duration::from_secs(900);
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const ALERT_MEMORY: Duration = Duration::from_secs(600);
const MAX_ALERTED: usize = 10_000;
const SUMMARY_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustPolicy {
    pub min_packets: u64,
    pub min_age: Duration,
    pub ttl: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    protocol: Protocol,
    low: SocketAddr,
    high: SocketAddr,
}

impl Key {
    fn new(protocol: Protocol, a: SocketAddr, b: SocketAddr) -> Self {
        let (low, high) = if a <= b { (a, b) } else { (b, a) };
        Self { protocol, low, high }
    }

    fn of(tuple: &FiveTuple) -> Self {
        Self::new(tuple.protocol(), tuple.src(), tuple.dst())
    }

    fn of_alert(alert: &Alert) -> Option<Self> {
        let protocol = match alert.protocol.to_ascii_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => return None,
        };
        let src = SocketAddr::new(alert.src?, alert.src_port?);
        let dst = SocketAddr::new(alert.dst?, alert.dst_port?);
        Some(Self::new(protocol, src, dst))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Watching { since: Instant, base: (u64, u64) },
    Trusted { until: Instant },
    Refused,
}

#[derive(Debug, Clone)]
struct Tracked {
    id: u32,
    tuple: FiveTuple,
    state: State,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Trust { tuple: FiveTuple, packets: (u64, u64) },
    Expire { tuple: FiveTuple },
    Revoke { tuple: FiveTuple, sid: u64, signature: String, flow_id: Option<u64> },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Counts {
    trusted: u64,
    expired: u64,
    revoked: u64,
    refused: u64,
}

#[derive(Debug)]
pub struct TrustAgent {
    policy: TrustPolicy,
    tracked: HashMap<Key, Tracked>,
    alerted: HashMap<Key, Instant>,
    inspecting: bool,
    alerts_current: bool,
    counts: Counts,
    last_summary: Option<Instant>,
    failing: bool,
    no_counters: bool,
}

impl TrustAgent {
    pub fn new(policy: TrustPolicy) -> Self {
        Self {
            policy,
            tracked: HashMap::new(),
            alerted: HashMap::new(),
            inspecting: false,
            alerts_current: true,
            counts: Counts::default(),
            last_summary: None,
            failing: false,
            no_counters: false,
        }
    }

    pub fn set_inspecting(&mut self, inspecting: bool) {
        self.inspecting = inspecting;
        if !inspecting {
            self.tracked.retain(|_, t| !matches!(t.state, State::Watching { .. }));
        }
    }

    pub fn set_alerts_current(&mut self, current: bool) {
        if mem::replace(&mut self.alerts_current, current) == current {
            return;
        }
        if current {
            info!("suricata's alerts are current again; automatic trust resumed");
        } else {
            warn!(
                code = %Issue::AutoTrustPaused,
                "automatic trust is paused because suricata's alerts are not current; no new connection is trusted"
            );
        }
    }

    pub fn check(&mut self, privd: &mut impl Privd, now: Instant) {
        match privd.forwarded_connections() {
            Ok(connections) => {
                if mem::take(&mut self.failing) {
                    info!("reading the conntrack table again; automatic trust resumed");
                }
                for decision in self.observe(&connections, now) {
                    self.apply(privd, decision);
                }
            }
            Err(e) => {
                if !mem::replace(&mut self.failing, true) {
                    warn!(code = %Issue::ConntrackUnreadable, error = %e, "cannot read the conntrack table; automatic trust is paused");
                }
            }
        }
        self.summarize(now);
    }

    pub fn on_alert(&mut self, alert: &Alert, privd: &mut impl Privd, now: Instant) {
        if let Some(decision) = self.alert(alert, now) {
            self.apply(privd, decision);
        }
    }

    fn alert(&mut self, alert: &Alert, now: Instant) -> Option<Decision> {
        let key = Key::of_alert(alert)?;
        if self.alerted.len() >= MAX_ALERTED {
            self.alerted.retain(|_, at| now.duration_since(*at) < ALERT_MEMORY);
        }
        if self.alerted.len() < MAX_ALERTED || self.alerted.contains_key(&key) {
            self.alerted.insert(key, now);
        }
        let tracked = self.tracked.get_mut(&key)?;
        match tracked.state {
            State::Trusted { .. } => {
                tracked.state = State::Refused;
                Some(Decision::Revoke {
                    tuple: tracked.tuple,
                    sid: alert.signature_id,
                    signature: alert.signature.clone(),
                    flow_id: alert.flow_id,
                })
            }
            State::Watching { .. } => {
                tracked.state = State::Refused;
                self.counts.refused += 1;
                let connection = tracked.tuple.to_string();
                debug!(
                    connection = connection.as_str(),
                    sid = alert.signature_id,
                    flow_id = alert.flow_id,
                    "suricata alerted on a watched connection; it will not be trusted"
                );
                None
            }
            State::Refused => None,
        }
    }

    fn observe(&mut self, connections: &[Connection], now: Instant) -> Vec<Decision> {
        self.alerted.retain(|_, at| now.duration_since(*at) < ALERT_MEMORY);
        let mut seen = HashSet::new();
        let mut decisions = Vec::new();
        for c in connections {
            let protocol = c.original.protocol();
            if !matches!(protocol, Protocol::Tcp | Protocol::Udp) {
                continue;
            }
            let key = Key::of(&c.original);
            seen.insert(key);
            let packets = c.original_counters.zip(c.reply_counters).map(|(o, r)| (o.packets, r.packets));
            if packets.is_none() && !mem::replace(&mut self.no_counters, true) {
                warn!(
                    code = %Issue::NoPacketCounters,
                    "conntrack keeps no packet counters for forwarded connections, so none of them can be trusted; \
                     set net.netfilter.nf_conntrack_acct = 1 (it applies to connections that start after that)"
                );
            }
            let watching = State::Watching {
                since: now,
                base: packets.unwrap_or_default(),
            };
            let tracked = self.tracked.entry(key).or_insert_with(|| Tracked {
                id: c.id,
                tuple: c.original,
                state: watching,
            });
            if tracked.id != c.id {
                let (tuple, state) = match tracked.state {
                    State::Trusted { until } => (tracked.tuple, State::Trusted { until }),
                    _ => (c.original, watching),
                };
                *tracked = Tracked { id: c.id, tuple, state };
            }
            if self.alerted.contains_key(&key) && matches!(tracked.state, State::Watching { .. }) {
                tracked.state = State::Refused;
                self.counts.refused += 1;
                let connection = tracked.tuple.to_string();
                debug!(
                    connection = connection.as_str(),
                    "suricata alerted on this connection before it was watched; it will not be trusted"
                );
            }
            match tracked.state {
                State::Trusted { until } => {
                    if now >= until {
                        tracked.state = watching;
                        decisions.push(Decision::Expire { tuple: tracked.tuple });
                    }
                }
                State::Watching { since, base } => {
                    if !self.inspecting || !self.alerts_current {
                        tracked.state = watching;
                        continue;
                    }
                    let Some((original, reply)) = packets else {
                        continue;
                    };
                    if protocol == Protocol::Tcp && c.tcp_state != Some(TcpState::Established) {
                        continue;
                    }
                    let seen_packets = (original.saturating_sub(base.0), reply.saturating_sub(base.1));
                    if now.duration_since(since) >= self.policy.min_age
                        && seen_packets.0 >= self.policy.min_packets
                        && seen_packets.1 >= self.policy.min_packets
                    {
                        tracked.state = State::Trusted {
                            until: now + self.policy.ttl,
                        };
                        decisions.push(Decision::Trust {
                            tuple: tracked.tuple,
                            packets: seen_packets,
                        });
                    }
                }
                State::Refused => {}
            }
        }
        self.tracked.retain(|key, tracked| match tracked.state {
            _ if seen.contains(key) => true,
            State::Trusted { until } if now < until => true,
            State::Trusted { .. } => {
                decisions.push(Decision::Expire { tuple: tracked.tuple });
                false
            }
            _ => false,
        });
        decisions
    }

    fn apply(&mut self, privd: &mut impl Privd, decision: Decision) {
        match decision {
            Decision::Trust { tuple, packets } => {
                let connection = tuple.to_string();
                match privd.trust(&tuple) {
                    Ok(()) => {
                        self.counts.trusted += 1;
                        info!(
                            connection = connection.as_str(),
                            packets_original = packets.0,
                            packets_reply = packets.1,
                            ttl_s = self.policy.ttl.as_secs(),
                            "connection trusted; its packets other than syn/fin/rst skip inspection"
                        );
                    }
                    Err(e) => warn!(code = %Issue::TrustFailed, connection = connection.as_str(), error = %e, "cannot trust connection"),
                }
            }
            Decision::Expire { tuple } => {
                let connection = tuple.to_string();
                match privd.untrust(&tuple) {
                    Ok(()) => {
                        self.counts.expired += 1;
                        debug!(connection = connection.as_str(), "trust expired; connection is inspected again");
                    }
                    Err(PrivdError::NotTrusted) => {}
                    Err(e) => error!(
                        code = %Issue::ExpireFailed,
                        connection = connection.as_str(),
                        error = %e,
                        "cannot end trust; this connection skips inspection until it ends"
                    ),
                }
            }
            Decision::Revoke {
                tuple,
                sid,
                signature,
                flow_id,
            } => {
                let connection = tuple.to_string();
                match privd.untrust(&tuple) {
                    Ok(()) | Err(PrivdError::NotTrusted) => {
                        self.counts.revoked += 1;
                        warn!(
                            code = %Issue::TrustRevoked,
                            connection = connection.as_str(),
                            sid,
                            signature = ?signature,
                            flow_id,
                            "suricata alerted on a trusted connection; trust revoked"
                        );
                    }
                    Err(e) => error!(
                        code = %Issue::RevokeFailed,
                        connection = connection.as_str(),
                        sid,
                        error = %e,
                        "suricata alerted on a trusted connection but its trust cannot be revoked; it skips inspection until it ends"
                    ),
                }
            }
        }
    }

    fn summarize(&mut self, now: Instant) {
        let last = *self.last_summary.get_or_insert(now);
        if now.duration_since(last) < SUMMARY_INTERVAL {
            return;
        }
        self.last_summary = Some(now);
        let counts = mem::take(&mut self.counts);
        if counts == Counts::default() {
            return;
        }
        let trusted_now = self.tracked.values().filter(|t| matches!(t.state, State::Trusted { .. })).count();
        info!(
            trusted = counts.trusted,
            expired = counts.expired,
            revoked = counts.revoked,
            refused = counts.refused,
            trusted_now,
            interval_s = SUMMARY_INTERVAL.as_secs(),
            "automatic trust"
        );
    }
}

#[cfg(test)]
#[path = "../../tests/unit/agent/trust.rs"]
mod tests;
