use std::collections::{HashMap, HashSet};
use std::io;
use std::mem;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::time::{self, Instant, Interval, MissedTickBehavior};
use tracing::{debug, info, warn};

use crate::ids::eve::{self, Alert, EveFile, EveInterval, ParseAlertError, ReadReport, Restart};
use crate::issue::Issue;

const MAX_CONNECTIONS: usize = 10_000;
const MAX_SIGNATURES: usize = 1_000;
const TOP: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Finding {
    Summary {
        alerts: u64,
        connections: usize,
        connections_capped: bool,
        top: Vec<(u64, String, u64)>,
    },
    Skipped {
        malformed: u64,
        too_long: u64,
    },
    ReadFailed {
        error: String,
    },
    ReadRecovered,
    Restarted(Restart),
    Behind,
    CaughtUp,
}

#[derive(Debug, Default)]
struct Window {
    alerts: u64,
    connections: HashSet<String>,
    connections_capped: bool,
    signatures: HashMap<u64, (String, u64)>,
    malformed: u64,
    too_long: u64,
}

impl Window {
    fn add(&mut self, alert: &Alert, connection: String) {
        self.alerts += 1;
        let key = alert.flow_id.map_or(connection, |id| format!("flow {id}"));
        if !self.connections.contains(&key) {
            if self.connections.len() < MAX_CONNECTIONS {
                self.connections.insert(key);
            } else {
                self.connections_capped = true;
            }
        }
        if let Some((_, count)) = self.signatures.get_mut(&alert.signature_id) {
            *count += 1;
        } else if self.signatures.len() < MAX_SIGNATURES {
            self.signatures.insert(alert.signature_id, (alert.signature.clone(), 1));
        }
    }
}

#[derive(Debug)]
pub struct AlertMonitor {
    path: String,
    window: Window,
    failing: bool,
    behind: bool,
}

impl AlertMonitor {
    pub const SUMMARY_INTERVAL: Duration = Duration::from_secs(60);

    pub fn new(path: &Path) -> Self {
        Self {
            path: path.display().to_string(),
            window: Window::default(),
            failing: false,
            behind: false,
        }
    }

    pub fn is_current(&self) -> bool {
        !self.failing && !self.behind
    }

    pub fn alert(&mut self, alert: &Alert) {
        let connection = alert.connection();
        debug!(
            connection = connection.as_str(),
            flow_id = alert.flow_id,
            sid = alert.signature_id,
            signature = ?alert.signature,
            action = ?alert.action,
            "suricata alert"
        );
        self.window.add(alert, connection);
    }

    pub fn malformed(&mut self, error: &ParseAlertError) {
        debug!(error = %error, "skipped a malformed EVE alert");
        self.window.malformed += 1;
    }

    pub fn read(&mut self, result: io::Result<ReadReport>) {
        for finding in self.observe_read(result) {
            self.log(finding);
        }
    }

    pub fn summarize(&mut self) {
        for finding in self.take_summary() {
            self.log(finding);
        }
    }

    fn observe_read(&mut self, result: io::Result<ReadReport>) -> Vec<Finding> {
        let report = match result {
            Ok(report) => report,
            Err(_) if mem::replace(&mut self.failing, true) => return Vec::new(),
            Err(e) => return vec![Finding::ReadFailed { error: e.to_string() }],
        };
        let mut findings = Vec::new();
        if mem::take(&mut self.failing) {
            findings.push(Finding::ReadRecovered);
        }
        if let Some(restart) = report.restart {
            findings.push(Finding::Restarted(restart));
        }
        self.window.too_long += report.too_long;
        if report.behind != self.behind {
            self.behind = report.behind;
            findings.push(if report.behind { Finding::Behind } else { Finding::CaughtUp });
        }
        findings
    }

    fn take_summary(&mut self) -> Vec<Finding> {
        let window = mem::take(&mut self.window);
        let mut findings = Vec::new();
        if window.alerts > 0 {
            let mut top: Vec<(u64, String, u64)> = window
                .signatures
                .into_iter()
                .map(|(sid, (signature, count))| (sid, signature, count))
                .collect();
            top.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
            top.truncate(TOP);
            findings.push(Finding::Summary {
                alerts: window.alerts,
                connections: window.connections.len(),
                connections_capped: window.connections_capped,
                top,
            });
        }
        if window.malformed + window.too_long > 0 {
            findings.push(Finding::Skipped {
                malformed: window.malformed,
                too_long: window.too_long,
            });
        }
        findings
    }

    fn log(&self, finding: Finding) {
        let path = self.path.as_str();
        match finding {
            Finding::Summary {
                alerts,
                connections,
                connections_capped,
                top,
            } => {
                let top: Vec<String> = top
                    .iter()
                    .map(|(sid, signature, count)| format!("{sid} {signature:?} x{count}"))
                    .collect();
                info!(
                    alerts,
                    connections,
                    connections_capped,
                    top = top.join("; ").as_str(),
                    interval_s = Self::SUMMARY_INTERVAL.as_secs(),
                    "suricata raised alerts"
                );
            }
            Finding::Skipped { malformed, too_long } => {
                warn!(code = %Issue::EveSkipped, path, malformed, too_long, "skipped EVE lines that wnc-gw could not read")
            }
            Finding::ReadFailed { error } => warn!(
                code = %Issue::EveUnreadable,
                path,
                error = error.as_str(),
                "cannot read suricata's EVE file; wnc-gw does not see alerts until it can"
            ),
            Finding::ReadRecovered => info!(path, "reading suricata's EVE file again"),
            Finding::Restarted(Restart::Appeared) => debug!(path, "suricata's EVE file appeared; reading it from the start"),
            Finding::Restarted(Restart::Replaced) => {
                info!(path, "suricata's EVE file was replaced; reading the new file from the start")
            }
            Finding::Restarted(Restart::Truncated) => {
                info!(path, "suricata's EVE file was truncated; reading it from the start")
            }
            Finding::Behind => warn!(
                code = %Issue::EveBehind,
                path,
                "suricata writes its EVE file faster than wnc-gw reads it; alerts reach wnc-gw late"
            ),
            Finding::CaughtUp => info!(path, "wnc-gw caught up with suricata's EVE file"),
        }
    }
}

pub struct AlertWatch {
    file: EveFile,
    poll: Interval,
    summary: Interval,
    monitor: AlertMonitor,
}

impl AlertWatch {
    pub fn new(path: PathBuf, interval: EveInterval) -> Self {
        let shown = path.display().to_string();
        let mut poll = time::interval(interval.duration());
        poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        info!(
            path = shown.as_str(),
            eve_interval_s = interval.duration().as_secs_f64(),
            "reading suricata's alerts from its EVE file"
        );
        let mut summary = time::interval_at(
            Instant::now() + AlertMonitor::SUMMARY_INTERVAL,
            AlertMonitor::SUMMARY_INTERVAL,
        );
        summary.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Self {
            monitor: AlertMonitor::new(&path),
            file: EveFile::open_at_end(path),
            poll,
            summary,
        }
    }

    pub async fn next(&mut self) -> Vec<Alert> {
        let read = {
            let (poll, summary) = (&mut self.poll, &mut self.summary);
            tokio::select! {
                _ = poll.tick() => true,
                _ = summary.tick() => false,
            }
        };
        if read {
            self.read()
        } else {
            self.monitor.summarize();
            Vec::new()
        }
    }

    pub fn is_current(&self) -> bool {
        self.monitor.is_current()
    }

    pub fn finish(&mut self) {
        self.read();
        self.monitor.summarize();
    }

    fn read(&mut self) -> Vec<Alert> {
        let monitor = &mut self.monitor;
        let mut alerts = Vec::new();
        let result = self.file.read(|line| match eve::parse_alert(line) {
            Ok(Some(alert)) => {
                monitor.alert(&alert);
                alerts.push(alert);
            }
            Ok(None) => {}
            Err(e) => monitor.malformed(&e),
        });
        self.monitor.read(result);
        alerts
    }
}

#[cfg(test)]
#[path = "../../tests/unit/monitor/alerts.rs"]
mod tests;
