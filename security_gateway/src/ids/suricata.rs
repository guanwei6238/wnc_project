use std::io;
use std::process::{ExitStatus, Stdio};
use std::str::Lines;
use std::time::Duration;

use tokio::process::Command;

pub const SURICATA: &str = "/usr/bin/suricata";
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuricataInfo {
    pub version: Option<String>,
    pub nfqueue: Option<bool>,
    pub ready_notify: Option<bool>,
}

#[derive(Debug, thiserror::Error)]
pub enum SuricataError {
    #[error("{} not found", SURICATA)]
    NotFound,
    #[error("failed to run {}: {}", SURICATA, .0)]
    Spawn(io::Error),
    #[error("{} did not finish within {} seconds", SURICATA, TIMEOUT.as_secs())]
    Timeout,
    #[error("{} failed ({status}): {stderr}", SURICATA)]
    Failed { status: ExitStatus, stderr: String },
}

pub async fn info() -> Result<SuricataInfo, SuricataError> {
    let stdout = run(&["--build-info"]).await?;
    Ok(SuricataInfo::parse(&String::from_utf8_lossy(&stdout)))
}

impl SuricataInfo {
    fn parse(output: &str) -> Self {
        let mut lines = output.lines();
        let version = lines
            .next()
            .and_then(|line| line.strip_prefix("This is Suricata version "))
            .and_then(|rest| rest.split_whitespace().next())
            .map(str::to_owned);
        Self {
            version,
            nfqueue: flag(lines.clone(), "NFQueue support"),
            ready_notify: flag(lines, "Systemd support"),
        }
    }
}

fn flag(lines: Lines<'_>, name: &str) -> Option<bool> {
    lines
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.trim() == name)
        .and_then(|(_, value)| match value.trim() {
            "yes" => Some(true),
            "no" => Some(false),
            _ => None,
        })
}

async fn run(args: &[&str]) -> Result<Vec<u8>, SuricataError> {
    let child = match Command::new(SURICATA)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(SuricataError::NotFound),
        Err(e) => return Err(SuricataError::Spawn(e)),
    };
    let output = match tokio::time::timeout(TIMEOUT, child.wait_with_output()).await {
        Err(_) => return Err(SuricataError::Timeout),
        Ok(Err(e)) => return Err(SuricataError::Spawn(e)),
        Ok(Ok(output)) => output,
    };
    if !output.status.success() {
        return Err(SuricataError::Failed {
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(output.stdout)
}

#[cfg(test)]
#[path = "../../tests/unit/ids/suricata.rs"]
mod tests;
