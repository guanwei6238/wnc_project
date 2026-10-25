pub mod bridge;
pub mod routed;

use std::fmt;
use std::str::FromStr;

use crate::kernel::modules::RequiredModule;
use crate::kernel::netif::Interface;
use crate::kernel::sysctl;
use crate::platform::{BootConfig, Current};
use crate::ports::{Port, Role};

pub use bridge::Bridged;
pub use routed::Routed;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Bridge,
    Routed,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bridge => "bridge",
            Self::Routed => "routed",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid mode {0:?} (expected \"bridge\" or \"routed\")")]
pub struct ParseModeError(String);

impl FromStr for Mode {
    type Err = ParseModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bridge" => Ok(Self::Bridge),
            "routed" => Ok(Self::Routed),
            _ => Err(ParseModeError(s.to_owned())),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Mode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

pub trait Forwarding {
    fn required_modules(&self) -> &'static [RequiredModule];
    fn check_environment(&self, ports: &[Port], interfaces: &[Interface]) -> Vec<EnvCheck>;
}

pub fn for_mode(mode: Mode) -> Box<dyn Forwarding> {
    match mode {
        Mode::Bridge => Box::new(Bridged),
        Mode::Routed => Box::new(Routed),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Required,
    Recommended,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvCheck {
    pub item: String,
    pub level: Level,
    pub state: EnvState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvState {
    Met { actual: String },
    Unmet { actual: String, problem: String, fix: String },
    Unknown { reason: String },
}

struct RequiredSysctl {
    key: &'static str,
    level: Level,
    consequence: &'static str,
    absent: &'static str,
}

fn sysctl_checks(
    required: &[RequiredSysctl],
    read: impl Fn(&str) -> Result<Option<String>, String>,
) -> Vec<EnvCheck> {
    required
        .iter()
        .map(|r| {
            let state = match read(r.key) {
                Ok(Some(value)) if value == "1" => EnvState::Met { actual: value },
                Ok(Some(value)) => EnvState::Unmet {
                    problem: format!("{} is {value}, so {}", r.key, r.consequence),
                    fix: format!(
                        "set it with: sysctl -w {}=1, and {}",
                        r.key,
                        Current.persist_sysctl_hint(r.key, "1")
                    ),
                    actual: value,
                },
                Ok(None) => EnvState::Unknown {
                    reason: r.absent.to_owned(),
                },
                Err(reason) => EnvState::Unknown { reason },
            };
            EnvCheck {
                item: r.key.to_owned(),
                level: r.level,
                state,
            }
        })
        .collect()
}

fn read_sysctl(key: &str) -> Result<Option<String>, String> {
    sysctl::read(key).map_err(|e| e.to_string())
}

fn port_pair(ports: &[Port]) -> Option<(&Port, &Port)> {
    let find = |role| ports.iter().find(|p| p.role == role);
    Some((find(Role::Lan)?, find(Role::Wan)?))
}

fn unresolved(item: &str) -> EnvCheck {
    EnvCheck {
        item: item.to_owned(),
        level: Level::Required,
        state: EnvState::Unknown {
            reason: "LAN or WAN port could not be resolved".to_owned(),
        },
    }
}

fn master_of<'a>(interface: &Interface, interfaces: &'a [Interface]) -> Option<&'a Interface> {
    let index = interface.master?;
    interfaces.iter().find(|i| i.index == index)
}

fn is_bridge(interface: &Interface) -> bool {
    interface.kind.as_deref() == Some("bridge")
}

fn describe(port: &Port) -> String {
    format!("{} ({})", port.role, port.interface.name)
}

#[cfg(test)]
#[path = "../../tests/unit/forwarding/mod.rs"]
mod tests;
