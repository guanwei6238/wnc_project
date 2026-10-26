use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::str::Lines;
use std::time::Duration;

use tokio::process::Command;

pub const DEFAULT_PATH: &str = "/usr/bin/suricata";
pub const DEFAULT_CONFIG: &str = "/etc/suricata/suricata.yaml";
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suricata {
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuricataInfo {
    pub version: Option<String>,
    pub nfqueue: Option<bool>,
    pub ready_notify: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuricataConfig {
    pub default_rule_path: Option<PathBuf>,
    pub rule_files: Vec<String>,
}

#[derive(Debug)]
pub struct RuleFile {
    pub entry: String,
    pub path: Option<PathBuf>,
    pub state: RuleFileState,
}

#[derive(Debug)]
pub enum RuleFileState {
    HasRules,
    NoRules,
    Missing,
    Unreadable(io::Error),
    Wildcard,
    NoRulePath,
}

#[derive(Debug, thiserror::Error)]
pub enum SuricataError {
    #[error("{} not found", .path.display())]
    NotFound { path: PathBuf },
    #[error("failed to run {}: {source}", .path.display())]
    Spawn { path: PathBuf, source: io::Error },
    #[error("{} did not finish within {} seconds", .path.display(), TIMEOUT.as_secs())]
    Timeout { path: PathBuf },
    #[error("{} failed ({status}): {stderr}", .path.display())]
    Failed {
        path: PathBuf,
        status: ExitStatus,
        stderr: String,
    },
}

impl Suricata {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn info(&self) -> Result<SuricataInfo, SuricataError> {
        let stdout = self.run(&[OsStr::new("--build-info")]).await?;
        Ok(SuricataInfo::parse(&String::from_utf8_lossy(&stdout)))
    }

    pub async fn dump_config(&self, config: &Path) -> Result<SuricataConfig, SuricataError> {
        let stdout = self
            .run(&[OsStr::new("--dump-config"), OsStr::new("-c"), config.as_os_str()])
            .await?;
        Ok(SuricataConfig::parse(&String::from_utf8_lossy(&stdout)))
    }

    async fn run(&self, args: &[&OsStr]) -> Result<Vec<u8>, SuricataError> {
        let path = || self.path.clone();
        let child = match Command::new(&self.path)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => child,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(SuricataError::NotFound { path: path() }),
            Err(source) => return Err(SuricataError::Spawn { path: path(), source }),
        };
        let output = match tokio::time::timeout(TIMEOUT, child.wait_with_output()).await {
            Err(_) => return Err(SuricataError::Timeout { path: path() }),
            Ok(Err(source)) => return Err(SuricataError::Spawn { path: path(), source }),
            Ok(Ok(output)) => output,
        };
        if !output.status.success() {
            return Err(SuricataError::Failed {
                path: path(),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(output.stdout)
    }
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

impl SuricataConfig {
    fn parse(output: &str) -> Self {
        let mut config = Self {
            default_rule_path: None,
            rule_files: Vec::new(),
        };
        for (key, value) in output.lines().filter_map(|line| line.split_once(" = ")) {
            if key == "default-rule-path" {
                config.default_rule_path = Some(PathBuf::from(value));
            } else if key
                .strip_prefix("rule-files.")
                .is_some_and(|index| !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()))
            {
                config.rule_files.push(value.to_owned());
            }
        }
        config
    }

    pub fn check_rule_files(&self) -> Vec<RuleFile> {
        self.rule_files
            .iter()
            .map(|entry| match self.resolve(entry) {
                Ok(path) => RuleFile {
                    entry: entry.clone(),
                    state: check_rule_file(&path),
                    path: Some(path),
                },
                Err(state) => RuleFile {
                    entry: entry.clone(),
                    path: None,
                    state,
                },
            })
            .collect()
    }

    fn resolve(&self, entry: &str) -> Result<PathBuf, RuleFileState> {
        if entry.contains(['*', '?', '[']) {
            return Err(RuleFileState::Wildcard);
        }
        let entry = Path::new(entry);
        if entry.is_absolute() {
            return Ok(entry.to_path_buf());
        }
        self.default_rule_path
            .as_ref()
            .map(|dir| dir.join(entry))
            .ok_or(RuleFileState::NoRulePath)
    }
}

fn check_rule_file(path: &Path) -> RuleFileState {
    match File::open(path).and_then(|file| has_rule(BufReader::new(file))) {
        Ok(true) => RuleFileState::HasRules,
        Ok(false) => RuleFileState::NoRules,
        Err(e) if e.kind() == io::ErrorKind::NotFound => RuleFileState::Missing,
        Err(e) => RuleFileState::Unreadable(e),
    }
}

fn has_rule(reader: impl BufRead) -> io::Result<bool> {
    for line in reader.split(b'\n') {
        match line?.iter().find(|b| !b.is_ascii_whitespace()) {
            None | Some(b'#') => {}
            Some(_) => return Ok(true),
        }
    }
    Ok(false)
}

#[cfg(test)]
#[path = "../../tests/unit/ids/suricata.rs"]
mod tests;
