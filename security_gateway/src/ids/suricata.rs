use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::str::Lines;

use crate::command::{self, CommandError};
use crate::kernel::nfqueue::QueueRange;
use crate::kernel::procs::{self, Process};

pub const DEFAULT_PATH: &str = "/usr/bin/suricata";
pub const DEFAULT_CONFIG: &str = "/etc/suricata/suricata.yaml";

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

pub type SuricataError = CommandError;

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

    pub async fn dump_config(&self, config: &Path, settings: &[&str]) -> Result<SuricataConfig, SuricataError> {
        let mut args = vec![OsStr::new("--dump-config"), OsStr::new("-c"), config.as_os_str()];
        for setting in settings {
            args.extend([OsStr::new("--set"), OsStr::new(setting)]);
        }
        let stdout = self.run(&args).await?;
        Ok(SuricataConfig::parse(&String::from_utf8_lossy(&stdout)))
    }

    async fn run(&self, args: &[&OsStr]) -> Result<Vec<u8>, SuricataError> {
        command::run(&self.path, args, b"").await
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capture {
    Nfq(Vec<QueueRange>),
    Live(&'static str),
    File,
    Test,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    WncGw,
    LeftByWncGw,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningSuricata {
    pub pid: u32,
    pub capture: Capture,
    pub rss_kb: Option<u64>,
    pub cgroup: Option<String>,
    pub owner: Owner,
    pub same_net_ns: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuricataScan {
    pub running: Vec<RunningSuricata>,
    pub others_hidden: bool,
}

const COMM: [&str; 2] = ["Suricata-Main", "suricata"];
const WNC_GW_COMM: &str = "wnc-gw";
const SHORT_WITH_VALUE: &str = "cdFiklqrSsU";
const LONG_WITH_VALUE: [&str; 8] = [
    "set",
    "pidfile",
    "user",
    "group",
    "runmode",
    "include",
    "capture-plugin",
    "capture-plugin-args",
];

pub fn scan(control_socket: &Path) -> io::Result<SuricataScan> {
    let marker = format!("unix-command.filename={}", control_socket.display());
    let own_net_ns = procs::own_net_ns();
    let running = procs::find(|comm| COMM.contains(&comm))?
        .iter()
        .filter(|p| p.state != Some('Z'))
        .map(|p| RunningSuricata::from_process(p, &marker, p.ppid.and_then(procs::comm).as_deref(), own_net_ns))
        .collect();
    Ok(SuricataScan {
        running,
        others_hidden: procs::others_hidden()?,
    })
}

impl RunningSuricata {
    fn from_process(process: &Process, marker: &str, parent_comm: Option<&str>, own_net_ns: Option<u64>) -> Self {
        let owner = if !process.cmdline.iter().any(|arg| arg == marker) {
            Owner::Other
        } else if parent_comm == Some(WNC_GW_COMM) {
            Owner::WncGw
        } else {
            Owner::LeftByWncGw
        };
        Self {
            pid: process.pid,
            capture: capture(&process.cmdline),
            rss_kb: process.rss_kb,
            cgroup: process.cgroup.clone(),
            owner,
            same_net_ns: process.net_ns.zip(own_net_ns).map(|(theirs, ours)| theirs == ours),
        }
    }
}

fn capture(cmdline: &[String]) -> Capture {
    let mut queues = Vec::new();
    let mut live = None;
    let mut file = false;
    let mut test = false;
    let mut args = cmdline.iter().skip(1).map(String::as_str);
    while let Some(arg) = args.next() {
        if let Some(long) = arg.strip_prefix("--") {
            let (name, has_value) = long.split_once('=').map_or((long, false), |(name, _)| (name, true));
            match name {
                "af-packet" => live = Some("af-packet"),
                "af-xdp" => live = Some("af-xdp"),
                "pcap" => live = Some("pcap"),
                "netmap" => live = Some("netmap"),
                "dpdk" => live = Some("dpdk"),
                "nflog" => live = Some("nflog"),
                _ if name.starts_with("pfring") => live = Some("pf_ring"),
                "unix-socket" => file = true,
                "engine-analysis" | "dump-config" | "build-info" => test = true,
                _ if LONG_WITH_VALUE.contains(&name) && !has_value => {
                    args.next();
                }
                _ => {}
            }
            continue;
        }
        let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) else {
            continue;
        };
        for (i, c) in cluster.char_indices() {
            if SHORT_WITH_VALUE.contains(c) {
                let rest = &cluster[i + c.len_utf8()..];
                let value = if rest.is_empty() { args.next() } else { Some(rest) };
                match c {
                    'q' => queues.extend(value.and_then(queue)),
                    'i' => live = Some("-i"),
                    'r' => file = true,
                    _ => {}
                }
                break;
            }
            if matches!(c, 'T' | 'V' | 'h') {
                test = true;
            }
        }
    }
    if test {
        Capture::Test
    } else if !queues.is_empty() {
        Capture::Nfq(queues)
    } else if let Some(method) = live {
        Capture::Live(method)
    } else if file {
        Capture::File
    } else {
        Capture::Unknown
    }
}

fn queue(value: &str) -> Option<QueueRange> {
    value.replace(':', "-").parse().ok()
}

#[cfg(test)]
#[path = "../../tests/unit/ids/suricata.rs"]
mod tests;
