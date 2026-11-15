use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use super::{Privd, PrivdError};
use crate::datapath::TrustedFlow;
use crate::issue::Issue;
use crate::kernel::conntrack::{FiveTuple, Protocol};

pub const TCP_IDLE: Duration = Duration::from_secs(600);
pub const UDP_IDLE: Duration = Duration::from_secs(120);

#[derive(Debug, Default)]
pub struct IdleSweep {
    last: HashMap<FiveTuple, (u64, Instant)>,
}

impl IdleSweep {
    pub const INTERVAL: Duration = Duration::from_secs(10);

    pub fn check(&mut self, privd: &mut impl Privd, now: Instant) {
        let flows = match privd.trusted() {
            Ok(flows) => flows,
            Err(e) => {
                debug!(error = %e, "cannot list trusted connections to find idle ones");
                return;
            }
        };
        let mut ended = 0;
        for tuple in self.observe(&flows, now) {
            let connection = tuple.to_string();
            match privd.untrust(&tuple) {
                Ok(()) => {
                    ended += 1;
                    debug!(connection = connection.as_str(), "trust of an idle connection ended");
                }
                Err(PrivdError::NotTrusted) => {}
                Err(e) => warn!(
                    code = %Issue::ExpireFailed,
                    connection = connection.as_str(),
                    error = %e,
                    "cannot end the trust of an idle connection"
                ),
            }
        }
        if ended > 0 {
            info!(
                ended,
                tcp_idle_s = TCP_IDLE.as_secs(),
                udp_idle_s = UDP_IDLE.as_secs(),
                "ended the trust of idle connections; they are inspected if they send again"
            );
        }
    }

    fn observe(&mut self, flows: &[TrustedFlow], now: Instant) -> Vec<FiveTuple> {
        let mut active = HashMap::new();
        let mut idle = Vec::new();
        for flow in flows {
            let packets = flow.original.packets.wrapping_add(flow.reply.packets);
            let since = match self.last.get(&flow.tuple) {
                Some(&(seen, since)) if seen == packets => since,
                _ => now,
            };
            if now.duration_since(since) >= idle_after(flow.tuple.protocol()) {
                idle.push(flow.tuple);
            } else {
                active.insert(flow.tuple, (packets, since));
            }
        }
        self.last = active;
        idle
    }
}

fn idle_after(protocol: Protocol) -> Duration {
    match protocol {
        Protocol::Udp => UDP_IDLE,
        _ => TCP_IDLE,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/agent/idle.rs"]
mod tests;
