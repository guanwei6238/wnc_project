use std::mem;
use std::time::Duration;

use tracing::{info, warn};

use crate::issue::Issue;
use crate::kernel::conntrack::{ConntrackError, CpuStats, Stats};

const NEARLY_FULL_PERCENT: u64 = 90;
const NO_LONGER_FULL_PERCENT: u64 = 80;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Finding {
    Table { entries: u32, max: u32 },
    NearlyFull { entries: u32, max: u32 },
    NoLongerNearlyFull { entries: u32, max: u32 },
    Dropped { drop: u64, insert_failed: u64 },
    Evicted { early_drop: u64 },
    ReadFailed { error: String },
    ReadRecovered,
}

#[derive(Debug, Default)]
pub struct ConntrackMonitor {
    last: Option<Stats>,
    nearly_full: bool,
    failing: bool,
}

impl ConntrackMonitor {
    pub const INTERVAL: Duration = Duration::from_secs(10);

    pub fn check(&mut self, read: Result<Stats, ConntrackError>) {
        for finding in self.observe(read) {
            log(finding);
        }
    }

    fn observe(&mut self, read: Result<Stats, ConntrackError>) -> Vec<Finding> {
        let stats = match read {
            Ok(stats) => stats,
            Err(_) if mem::replace(&mut self.failing, true) => return Vec::new(),
            Err(e) => return vec![Finding::ReadFailed { error: e.to_string() }],
        };
        let mut findings = Vec::new();
        if mem::take(&mut self.failing) {
            findings.push(Finding::ReadRecovered);
        }
        let (entries, max) = (stats.entries, stats.max);
        if self.last.is_none() {
            findings.push(Finding::Table { entries, max });
        }
        let used = u64::from(entries) * 100;
        if max > 0 && !self.nearly_full && used >= u64::from(max) * NEARLY_FULL_PERCENT {
            self.nearly_full = true;
            findings.push(Finding::NearlyFull { entries, max });
        } else if self.nearly_full && used < u64::from(max) * NO_LONGER_FULL_PERCENT {
            self.nearly_full = false;
            findings.push(Finding::NoLongerNearlyFull { entries, max });
        }
        if let Some(last) = &self.last {
            let drop = increase(last, &stats, |c| c.drop);
            let insert_failed = increase(last, &stats, |c| c.insert_failed);
            let early_drop = increase(last, &stats, |c| c.early_drop);
            if drop + insert_failed > 0 {
                findings.push(Finding::Dropped { drop, insert_failed });
            }
            if early_drop > 0 {
                findings.push(Finding::Evicted { early_drop });
            }
        }
        self.last = Some(stats);
        findings
    }
}

fn increase(last: &Stats, now: &Stats, counter: impl Fn(&CpuStats) -> u32) -> u64 {
    now.cpus
        .iter()
        .filter_map(|c| last.cpus.iter().find(|l| l.cpu == c.cpu).map(|l| counter(c).wrapping_sub(counter(l))))
        .map(u64::from)
        .sum()
}

fn log(finding: Finding) {
    let interval_s = ConntrackMonitor::INTERVAL.as_secs();
    match finding {
        Finding::Table { entries, max } => info!(entries, max, "conntrack table"),
        Finding::NearlyFull { entries, max } => {
            warn!(code = %Issue::ConntrackNearlyFull, entries, max, "conntrack table is nearly full; new connections may be dropped")
        }
        Finding::NoLongerNearlyFull { entries, max } => info!(entries, max, "conntrack table is no longer nearly full"),
        Finding::Dropped { drop, insert_failed } => warn!(code = %Issue::ConntrackDropped, drop, insert_failed, interval_s, "conntrack dropped packets"),
        Finding::Evicted { early_drop } => {
            warn!(code = %Issue::ConntrackEvicted, early_drop, interval_s, "conntrack evicted unassured connections to make room")
        }
        Finding::ReadFailed { error } => warn!(code = %Issue::ConntrackStatsUnreadable, error = error.as_str(), "cannot read conntrack statistics"),
        Finding::ReadRecovered => info!("conntrack statistics can be read again"),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/monitor/conntrack.rs"]
mod tests;
