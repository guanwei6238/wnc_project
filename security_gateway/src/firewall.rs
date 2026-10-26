use std::fmt;
use std::str::FromStr;

use crate::kernel::nfqueue::QueueRange;
use crate::kernel::nft::{BaseChain, Family, Hook, Nft, NftError, Policy, RegularChain, Statement, Table};

pub const FAMILY: Family = Family::Inet;
pub const TABLE: &str = "wnc_gw";
const PRIORITY_FILTER: i32 = 0;
const IDS_CHAIN: &str = "ids";

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
    pub queue: QueueRange,
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

fn table(inspection: Inspection) -> Table {
    Table {
        family: FAMILY,
        name: TABLE.to_owned(),
        chains: vec![BaseChain {
            name: "forward".to_owned(),
            hook: Hook::Forward,
            priority: PRIORITY_FILTER,
            policy: Policy::Accept,
            rules: vec![vec![Statement::Counter], vec![Statement::Jump(IDS_CHAIN.to_owned())]],
        }],
        regular_chains: vec![RegularChain {
            name: IDS_CHAIN.to_owned(),
            rules: unavailable_rules(inspection.when_unavailable),
        }],
    }
}

// bypass：queue 沒有程式綁定時（Suricata 剛結束）直接放行，不加就丟掉
fn inspecting_rules(inspection: Inspection) -> Vec<Vec<Statement>> {
    vec![vec![
        Statement::Counter,
        Statement::Queue {
            queue: inspection.queue,
            bypass: inspection.when_unavailable == WhenUnavailable::Accept,
        },
    ]]
}

fn unavailable_rules(when_unavailable: WhenUnavailable) -> Vec<Vec<Statement>> {
    match when_unavailable {
        WhenUnavailable::Accept => vec![vec![Statement::Counter]],
        WhenUnavailable::Drop => vec![vec![Statement::Counter, Statement::Drop]],
    }
}

#[cfg(test)]
#[path = "../tests/unit/firewall.rs"]
mod tests;
