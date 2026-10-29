use std::fmt;
use std::str::FromStr;

use crate::ids::delivery::Delivery;
use crate::kernel::conntrack::{Connection, Conntrack, ConntrackError, FiveTuple};
use crate::kernel::nflog::GroupRange;
use crate::kernel::nft::{BaseChain, Family, Hook, Nft, NftError, Policy, RegularChain, Statement, Table, TcpFlag};

pub const FAMILY: Family = Family::Inet;
pub const TABLE: &str = "wnc_gw";
const PRIORITY_FILTER: i32 = 0;
const IDS_CHAIN: &str = "ids";
pub const TRUSTED_MARK: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WhenUnavailable {
    #[default]
    Accept,
    Drop,
}

impl fmt::Display for WhenUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Accept => "accept",
            Self::Drop => "drop",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid when_unavailable {0:?} (expected \"accept\" or \"drop\")")]
pub struct ParseWhenUnavailableError(String);

impl FromStr for WhenUnavailable {
    type Err = ParseWhenUnavailableError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "accept" => Ok(Self::Accept),
            "drop" => Ok(Self::Drop),
            _ => Err(ParseWhenUnavailableError(s.to_owned())),
        }
    }
}

impl<'de> serde::Deserialize<'de> for WhenUnavailable {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inspection {
    pub delivery: Delivery,
    pub when_unavailable: WhenUnavailable,
}

pub async fn install(nft: &Nft, inspection: Inspection) -> Result<(), NftError> {
    nft.replace_table(&table(inspection)).await
}

pub async fn start_inspection(nft: &Nft, inspection: Inspection) -> Result<(), NftError> {
    nft.replace_rules(FAMILY, TABLE, IDS_CHAIN, &inspecting_rules(inspection)).await
}

pub async fn stop_inspection(nft: &Nft, inspection: Inspection) -> Result<(), NftError> {
    nft.replace_rules(FAMILY, TABLE, IDS_CHAIN, &unavailable_rules(inspection.when_unavailable)).await
}

pub async fn remove(nft: &Nft) -> Result<(), NftError> {
    nft.delete_table(FAMILY, TABLE).await
}

pub fn trust(conntrack: &mut Conntrack, tuple: &FiveTuple) -> Result<(), ConntrackError> {
    conntrack.set_mark(tuple, TRUSTED_MARK, TRUSTED_MARK)
}

pub fn untrust(conntrack: &mut Conntrack, tuple: &FiveTuple) -> Result<(), ConntrackError> {
    conntrack.set_mark(tuple, 0, TRUSTED_MARK)
}

pub fn trusted(conntrack: &mut Conntrack) -> Result<Vec<Connection>, ConntrackError> {
    conntrack.list(TRUSTED_MARK, TRUSTED_MARK)
}

#[derive(Debug, Default)]
pub struct Untrusted {
    pub cleared: usize,
    pub gone: usize,
    pub failed: Vec<(FiveTuple, ConntrackError)>,
}

pub fn untrust_all(conntrack: &mut Conntrack) -> Result<Untrusted, ConntrackError> {
    let tuples: Vec<FiveTuple> = trusted(conntrack)?.into_iter().map(|c| c.original).collect();
    let failures = conntrack.set_marks(&tuples, 0, TRUSTED_MARK)?;
    Ok(untrusted(tuples.len(), failures))
}

fn untrusted(total: usize, failures: Vec<(FiveTuple, ConntrackError)>) -> Untrusted {
    let (gone, failed): (Vec<_>, Vec<_>) =
        failures.into_iter().partition(|(_, e)| matches!(e, ConntrackError::NotFound));
    Untrusted {
        cleared: total - gone.len() - failed.len(),
        gone: gone.len(),
        failed,
    }
}

fn table(inspection: Inspection) -> Table {
    Table {
        family: FAMILY,
        name: TABLE.to_owned(),
        chains: vec![BaseChain {
            name: "forward".to_owned(),
            hook: Hook::Forward,
            priority: PRIORITY_FILTER,
            policy: Policy::Accept,
            rules: vec![
                vec![Statement::Counter],
                vec![
                    Statement::TcpFlagsEq {
                        mask: vec![TcpFlag::Syn, TcpFlag::Ack],
                        value: vec![TcpFlag::Syn],
                    },
                    Statement::CtMarkHas(TRUSTED_MARK),
                    Statement::Counter,
                    Statement::CtMarkClear(TRUSTED_MARK),
                ],
                vec![
                    Statement::TcpFlagsAny(vec![TcpFlag::Fin, TcpFlag::Syn, TcpFlag::Rst]),
                    Statement::Jump(IDS_CHAIN.to_owned()),
                ],
                vec![Statement::CtMarkHas(TRUSTED_MARK), Statement::Counter, Statement::Accept],
                vec![Statement::Jump(IDS_CHAIN.to_owned())],
            ],
        }],
        regular_chains: [RegularChain {
            name: IDS_CHAIN.to_owned(),
            rules: unavailable_rules(inspection.when_unavailable),
        }]
        .into_iter()
        .chain(group_chains(inspection.delivery))
        .collect(),
    }
}

fn group_chains(delivery: Delivery) -> Vec<RegularChain> {
    match delivery {
        Delivery::Copy(groups) if groups.first() != groups.last() => groups
            .groups()
            .map(|group| RegularChain {
                name: group_chain(group),
                rules: vec![copy_rule(group)],
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn group_chain(group: u16) -> String {
    format!("{IDS_CHAIN}_g{group}")
}

fn copy_rule(group: u16) -> Vec<Statement> {
    vec![Statement::Counter, Statement::Log { group }, Statement::Accept]
}

fn inspecting_rules(inspection: Inspection) -> Vec<Vec<Statement>> {
    match inspection.delivery {
        Delivery::Queue(queue) => vec![vec![
            Statement::Counter,
            Statement::Queue {
                queue,
                bypass: inspection.when_unavailable == WhenUnavailable::Accept,
            },
        ]],
        Delivery::Copy(groups) => vec![copy_rules(groups)],
    }
}

fn copy_rules(groups: GroupRange) -> Vec<Statement> {
    if groups.first() == groups.last() {
        return copy_rule(groups.first());
    }
    vec![Statement::Counter, Statement::JumpBySymhash(groups.groups().map(group_chain).collect())]
}

fn unavailable_rules(when_unavailable: WhenUnavailable) -> Vec<Vec<Statement>> {
    match when_unavailable {
        WhenUnavailable::Accept => vec![vec![Statement::Counter, Statement::Accept]],
        WhenUnavailable::Drop => vec![vec![Statement::Counter, Statement::Drop]],
    }
}

#[cfg(test)]
#[path = "../tests/unit/firewall.rs"]
mod tests;
