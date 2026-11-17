use std::collections::HashSet;
use std::fmt;
use std::io;
use std::str::FromStr;

use super::nfqueue::QueueRange;

const DEFAULT_GROUP: u16 = 10;
const PROC_NET_NETLINK: &str = "/proc/net/netlink";
const NETLINK_NETFILTER: u32 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupRange(QueueRange);

impl GroupRange {
    pub fn first(&self) -> u16 {
        self.0.first()
    }

    pub fn last(&self) -> u16 {
        self.0.last()
    }

    pub fn groups(&self) -> impl Iterator<Item = u16> + use<> {
        self.first()..=self.last()
    }
}

impl Default for GroupRange {
    fn default() -> Self {
        Self(DEFAULT_GROUP.to_string().parse().expect("the default group is a valid range"))
    }
}

impl fmt::Display for GroupRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid group {0:?} (expected a number from 1 to 65535 such as 10, or a range such as \"10-11\")")]
pub struct ParseGroupRangeError(String);

impl FromStr for GroupRange {
    type Err = ParseGroupRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<QueueRange>() {
            Ok(range) if range.first() > 0 => Ok(Self(range)),
            _ => Err(ParseGroupRangeError(s.to_owned())),
        }
    }
}

impl<'de> serde::Deserialize<'de> for GroupRange {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = GroupRange;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a group number such as 10, or a range such as \"10-11\"")
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<GroupRange, E> {
                v.to_string().parse().map_err(E::custom)
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<GroupRange, E> {
                v.to_string().parse().map_err(E::custom)
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<GroupRange, E> {
                v.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetfilterSocket {
    pub inode: u64,
    pub drops: u32,
}

pub fn netfilter_sockets(pid: u32) -> io::Result<Vec<NetfilterSocket>> {
    let mut inodes = HashSet::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
        if let Ok(link) = std::fs::read_link(entry?.path())
            && let Some(inode) = socket_inode(&link.to_string_lossy())
        {
            inodes.insert(inode);
        }
    }
    let table = std::fs::read_to_string(PROC_NET_NETLINK)?;
    Ok(parse_netlink(&table).into_iter().filter(|s| inodes.contains(&s.inode)).collect())
}

fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

fn parse_netlink(text: &str) -> Vec<NetfilterSocket> {
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return Vec::new();
    };
    let column = |name| header.split_whitespace().position(|h| h == name);
    let (Some(protocol), Some(drops), Some(inode)) = (column("Eth"), column("Drops"), column("Inode")) else {
        return Vec::new();
    };
    lines
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.get(protocol)?.parse::<u32>().ok()? != NETLINK_NETFILTER {
                return None;
            }
            Some(NetfilterSocket {
                inode: fields.get(inode)?.parse().ok()?,
                drops: fields.get(drops)?.parse::<i64>().ok()? as u32,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
