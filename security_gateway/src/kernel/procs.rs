use std::fs;
use std::io;
use std::path::Path;

const PROC: &str = "/proc";
const MOUNTS: &str = "/proc/self/mounts";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
    pub state: Option<char>,
    pub ppid: Option<u32>,
    pub comm: String,
    pub cmdline: Vec<String>,
    pub rss_kb: Option<u64>,
    pub cgroup: Option<String>,
    pub net_ns: Option<u64>,
}

pub fn find(matches: impl Fn(&str) -> bool) -> io::Result<Vec<Process>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(PROC)? {
        let entry = entry?;
        let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };
        let Some(comm) = comm(pid) else {
            continue;
        };
        if !matches(&comm) {
            continue;
        }
        let dir = entry.path();
        let Ok(status) = fs::read_to_string(dir.join("status")) else {
            continue;
        };
        let (state, ppid, rss_kb) = parse_status(&status);
        found.push(Process {
            pid,
            state,
            ppid,
            comm,
            cmdline: fs::read(dir.join("cmdline")).map(|bytes| parse_cmdline(&bytes)).unwrap_or_default(),
            rss_kb,
            cgroup: fs::read_to_string(dir.join("cgroup")).ok().and_then(|text| parse_cgroup(&text)),
            net_ns: net_ns(&dir),
        });
    }
    found.sort_by_key(|p| p.pid);
    Ok(found)
}

pub fn own_net_ns() -> Option<u64> {
    net_ns(&Path::new(PROC).join("self"))
}

pub fn others_hidden() -> io::Result<bool> {
    let mounts = fs::read_to_string(MOUNTS)?;
    let status = fs::read_to_string(Path::new(PROC).join("self/status"))?;
    Ok(hidepid(&mounts) && !is_root(&status))
}

pub fn comm(pid: u32) -> Option<String> {
    let text = fs::read_to_string(Path::new(PROC).join(pid.to_string()).join("comm")).ok()?;
    Some(text.trim_end_matches('\n').to_owned())
}

fn parse_status(text: &str) -> (Option<char>, Option<u32>, Option<u64>) {
    let field = |name: &str| text.lines().find_map(|line| line.strip_prefix(name)).map(str::trim);
    let state = field("State:").and_then(|value| value.chars().next());
    let ppid = field("PPid:").and_then(|value| value.parse().ok());
    let rss_kb = field("VmRSS:")
        .and_then(|value| value.strip_suffix("kB"))
        .and_then(|value| value.trim().parse().ok());
    (state, ppid, rss_kb)
}

fn net_ns(dir: &Path) -> Option<u64> {
    let link = fs::read_link(dir.join("ns/net")).ok()?;
    parse_net_ns(link.to_str()?)
}

fn parse_net_ns(link: &str) -> Option<u64> {
    link.strip_prefix("net:[")?.strip_suffix(']')?.parse().ok()
}

fn hidepid(mounts: &str) -> bool {
    mounts
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.len() >= 4 && fields[1] == PROC && fields[2] == "proc").then(|| fields[3])
        })
        .last()
        .is_some_and(|options| {
            options
                .split(',')
                .filter_map(|option| option.strip_prefix("hidepid="))
                .any(|value| value != "0" && value != "off")
        })
}

fn is_root(status: &str) -> bool {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().nth(1))
        == Some("0")
}

fn parse_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

fn parse_cgroup(text: &str) -> Option<String> {
    text.lines().find_map(|line| line.strip_prefix("0::")).map(str::to_owned)
}

#[cfg(test)]
#[path = "../../tests/unit/kernel/procs.rs"]
mod tests;
