use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use super::{LocalPrivd, Privd};
use crate::issue::Issue;
use crate::kernel::{conntrack::FiveTuple, netif::Netlink};

pub const QUIET: Duration = Duration::from_secs(10);
const UNSTABLE_AFTER: Duration = Duration::from_secs(60);
const PER_TICK: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    Unstable,
    Stable,
}

#[derive(Debug)]
pub struct NextHops {
    ports: [u32; 2],
    pending: VecDeque<FiveTuple>,
    refresh_all: bool,
    last_change: Option<Instant>,
    changing_since: Option<Instant>,
    unstable: bool,
}

impl NextHops {
    pub const INTERVAL: Duration = Duration::from_secs(1);

    pub fn new(ports: [u32; 2]) -> Self {
        Self {
            ports,
            pending: VecDeque::new(),
            refresh_all: false,
            last_change: None,
            changing_since: None,
            unstable: false,
        }
    }

    pub fn route_changed(&mut self, privd: &mut LocalPrivd, now: Instant) {
        if let Err(e) = privd.invalidate_next_hops() {
            warn!(code = %Issue::NextHopsOff, error = %e, "cannot invalidate the next hops after a route change");
        }
        self.changed(now);
        debug!("routes changed; trusted connections use the kernel's route lookup until routes are quiet again");
    }

    pub async fn check(&mut self, privd: &mut LocalPrivd, netlink: &Netlink, now: Instant) {
        match self.settle(now) {
            Some(Change::Unstable) => warn!(
                code = %Issue::RoutesUnstable,
                unstable_s = UNSTABLE_AFTER.as_secs(),
                "routes keep changing; trusted connections in routed mode use the kernel's route lookup"
            ),
            Some(Change::Stable) => info!("routes are stable again; trusted connections use their next hops"),
            None => {}
        }
        if self.last_change.is_some_and(|at| now.duration_since(at) < QUIET) {
            return;
        }
        self.pending.extend(privd.take_newly_trusted());
        if std::mem::take(&mut self.refresh_all) {
            self.pending.clear();
            match privd.trusted() {
                Ok(flows) => self.pending.extend(flows.into_iter().map(|flow| flow.tuple)),
                Err(e) => debug!(error = %e, "cannot list trusted connections to fill their next hops"),
            }
        }
        let Some(generation) = privd.route_generation() else { return };
        for _ in 0..PER_TICK {
            let Some(tuple) = self.pending.pop_front() else { break };
            let (original, reply) = resolve(netlink, &tuple, self.ports).await;
            if let Err(e) = privd.set_next_hops(&tuple, original, reply, generation) {
                let connection = tuple.to_string();
                debug!(connection = connection.as_str(), error = %e, "cannot set the next hops");
            }
        }
    }

    fn changed(&mut self, now: Instant) {
        if self.last_change.is_none_or(|at| now.duration_since(at) >= QUIET) {
            self.changing_since = Some(now);
        }
        self.last_change = Some(now);
        self.refresh_all = true;
    }

    fn settle(&mut self, now: Instant) -> Option<Change> {
        let quiet = self.last_change.is_none_or(|at| now.duration_since(at) >= QUIET);
        if quiet {
            self.changing_since = None;
            return std::mem::take(&mut self.unstable).then_some(Change::Stable);
        }
        let long = self.changing_since.is_some_and(|since| now.duration_since(since) >= UNSTABLE_AFTER);
        (long && !std::mem::replace(&mut self.unstable, true)).then_some(Change::Unstable)
    }
}

async fn resolve(netlink: &Netlink, tuple: &FiveTuple, ports: [u32; 2]) -> (Option<IpAddr>, Option<IpAddr>) {
    let (src, dst) = (tuple.src().ip(), tuple.dst().ip());
    let Ok(Some(toward_src)) = netlink.output_route(src).await else { return (None, None) };
    let Some(other) = other_port(ports, toward_src.oif) else { return (None, None) };
    let hop = |route: Option<crate::kernel::netif::RouteTo>, expected: u32, to: IpAddr| {
        route.filter(|r| r.oif == expected).map(|r| r.gateway.unwrap_or(to))
    };
    let original = hop(netlink.forwarding_route(src, dst, toward_src.oif).await.ok().flatten(), other, dst);
    let reply = hop(netlink.forwarding_route(dst, src, other).await.ok().flatten(), toward_src.oif, src);
    (original, reply)
}

fn other_port(ports: [u32; 2], ifindex: u32) -> Option<u32> {
    match ports {
        [a, b] if a == ifindex => Some(b),
        [a, b] if b == ifindex => Some(a),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/agent/nexthop.rs"]
mod tests;
