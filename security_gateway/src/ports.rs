use std::fmt;
use std::str::FromStr;

use crate::kernel::netif::{Interface, MacAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Lan,
    Wan,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Lan => "LAN",
            Self::Wan => "WAN",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSelector {
    Name(String),
    Mac(MacAddr),
}

impl fmt::Display for PortSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => f.write_str(name),
            Self::Mac(mac) => mac.fmt(f),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid interface name or MAC address: {0:?}")]
pub struct ParseSelectorError(String);

impl FromStr for PortSelector {
    type Err = ParseSelectorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(mac) = s.parse::<MacAddr>() {
            Ok(Self::Mac(mac))
        } else if is_valid_ifname(s) {
            Ok(Self::Name(s.to_owned()))
        } else {
            Err(ParseSelectorError(s.to_owned()))
        }
    }
}

fn is_valid_ifname(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 16
        && s != "."
        && s != ".."
        && !s
            .bytes()
            .any(|b| b == b'/' || b == b':' || b == 0 || b == 0x0b || b.is_ascii_whitespace())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    pub role: Role,
    pub selector: PortSelector,
}

impl<'de> serde::Deserialize<'de> for PortSelector {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedBy {
    Name,
    PermanentMac,
    CurrentMac,
}

impl fmt::Display for MatchedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Name => "name",
            Self::PermanentMac => "permanent MAC",
            Self::CurrentMac => "current MAC",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    pub role: Role,
    pub interface: Interface,
    pub matched_by: MatchedBy,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("{role} ({selector}): no matching interface")]
    NotFound { role: Role, selector: PortSelector },
    #[error("{role} ({selector}): matches more than one interface ({}); specify the interface by name instead", .candidates.join(", "))]
    Ambiguous {
        role: Role,
        selector: PortSelector,
        candidates: Vec<String>,
    },
    #[error("{role} and {other} both resolve to interface {name}")]
    SharedInterface { role: Role, other: Role, name: String },
}

pub fn resolve(specs: &[PortSpec], interfaces: &[Interface]) -> Vec<Result<Port, ResolveError>> {
    let mut results: Vec<_> = specs.iter().map(|spec| resolve_one(spec, interfaces)).collect();

    let resolved: Vec<(Role, u32)> = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .map(|port| (port.role, port.interface.index))
        .collect();
    for result in &mut results {
        let shared = match result {
            Ok(port) => resolved
                .iter()
                .find(|(role, index)| *role != port.role && *index == port.interface.index)
                .map(|(other, _)| ResolveError::SharedInterface {
                    role: port.role,
                    other: *other,
                    name: port.interface.name.clone(),
                }),
            Err(_) => None,
        };
        if let Some(err) = shared {
            *result = Err(err);
        }
    }
    results
}

fn resolve_one(spec: &PortSpec, interfaces: &[Interface]) -> Result<Port, ResolveError> {
    match &spec.selector {
        PortSelector::Name(name) => {
            let by_name = interfaces.iter().filter(|i| &i.name == name).collect();
            single(spec, by_name, MatchedBy::Name)
        }
        PortSelector::Mac(mac) => {
            let by_perm: Vec<_> = interfaces.iter().filter(|i| i.perm_mac == Some(*mac)).collect();
            if !by_perm.is_empty() {
                return single(spec, by_perm, MatchedBy::PermanentMac);
            }
            let by_current = interfaces.iter().filter(|i| i.mac == Some(*mac)).collect();
            single(spec, by_current, MatchedBy::CurrentMac)
        }
    }
}

fn single(
    spec: &PortSpec,
    candidates: Vec<&Interface>,
    matched_by: MatchedBy,
) -> Result<Port, ResolveError> {
    match candidates.as_slice() {
        [] => Err(ResolveError::NotFound {
            role: spec.role,
            selector: spec.selector.clone(),
        }),
        [interface] => Ok(Port {
            role: spec.role,
            interface: (*interface).clone(),
            matched_by,
        }),
        _ => Err(ResolveError::Ambiguous {
            role: spec.role,
            selector: spec.selector.clone(),
            candidates: candidates.iter().map(|i| i.name.clone()).collect(),
        }),
    }
}

#[cfg(test)]
#[path = "../tests/unit/ports.rs"]
mod tests;
