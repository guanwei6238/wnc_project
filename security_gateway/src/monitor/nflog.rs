use std::collections::HashMap;
use std::io;
use std::mem;
use std::time::Duration;

use tracing::{info, warn};

use crate::kernel::nflog::NetfilterSocket;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Finding {
    Missed { missed: u64 },
    NoSockets { pid: u32 },
    ReadFailed { error: String },
    ReadRecovered,
}

#[derive(Debug, Default)]
pub struct CopyMonitor {
    pid: Option<u32>,
    last: HashMap<u64, u32>,
    no_sockets_reported: bool,
    failing: bool,
}

impl CopyMonitor {
    pub const INTERVAL: Duration = Duration::from_secs(10);

    pub fn check(&mut self, pid: u32, read: io::Result<Vec<NetfilterSocket>>) {
        for finding in self.observe(pid, read) {
            log(finding);
        }
    }

    fn observe(&mut self, pid: u32, read: io::Result<Vec<NetfilterSocket>>) -> Vec<Finding> {
        if self.pid != Some(pid) {
            self.pid = Some(pid);
            self.last.clear();
            self.no_sockets_reported = false;
        }
        let sockets = match read {
            Ok(sockets) => sockets,
            Err(_) if mem::replace(&mut self.failing, true) => return Vec::new(),
            Err(e) => return vec![Finding::ReadFailed { error: e.to_string() }],
        };
        let mut findings = Vec::new();
        if mem::take(&mut self.failing) {
            findings.push(Finding::ReadRecovered);
        }
        if sockets.is_empty() {
            if !mem::replace(&mut self.no_sockets_reported, true) {
                findings.push(Finding::NoSockets { pid });
            }
            return findings;
        }
        let missed: u64 = sockets
            .iter()
            .map(|s| u64::from(s.drops.wrapping_sub(self.last.get(&s.inode).copied().unwrap_or(0))))
            .sum();
        self.last = sockets.iter().map(|s| (s.inode, s.drops)).collect();
        if missed > 0 {
            findings.push(Finding::Missed { missed });
        }
        findings
    }
}

fn log(finding: Finding) {
    let interval_s = CopyMonitor::INTERVAL.as_secs();
    match finding {
        Finding::Missed { missed } => {
            warn!(missed, interval_s, "suricata missed packet copies; that traffic was forwarded without inspection")
        }
        Finding::NoSockets { pid } => {
            warn!(pid, "cannot find suricata's nflog sockets; missed packet copies are not counted")
        }
        Finding::ReadFailed { error } => {
            warn!(error = error.as_str(), "cannot read suricata's nflog sockets; missed packet copies are not counted")
        }
        Finding::ReadRecovered => info!("suricata's nflog sockets can be read again"),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/monitor/nflog.rs"]
mod tests;
