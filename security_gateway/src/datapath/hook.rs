use std::fmt;
use std::str::FromStr;

use crate::kernel::netdev::XdpFeatures;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XdpPolicy {
    #[default]
    Auto,
    Off,
    Generic,
}

impl fmt::Display for XdpPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Auto => "auto",
            Self::Off => "off",
            Self::Generic => "generic",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid xdp setting {0:?} (expected \"auto\", \"off\" or \"generic\")")]
pub struct ParseXdpPolicyError(String);

impl FromStr for XdpPolicy {
    type Err = ParseXdpPolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "off" => Ok(Self::Off),
            "generic" => Ok(Self::Generic),
            _ => Err(ParseXdpPolicyError(s.to_owned())),
        }
    }
}

impl<'de> serde::Deserialize<'de> for XdpPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreHook {
    NativeXdp,
    GenericXdp,
    Tc,
}

impl fmt::Display for CoreHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NativeXdp => "xdp (native)",
            Self::GenericXdp => "xdp (generic)",
            Self::Tc => "tc",
        })
    }
}

pub fn core_hook(policy: XdpPolicy, native: Option<XdpFeatures>) -> CoreHook {
    match policy {
        XdpPolicy::Off => CoreHook::Tc,
        XdpPolicy::Generic => CoreHook::GenericXdp,
        XdpPolicy::Auto => match native {
            Some(features) if features.basic() => CoreHook::NativeXdp,
            _ => CoreHook::Tc,
        },
    }
}

#[cfg(test)]
#[path = "../../tests/unit/datapath/hook.rs"]
mod tests;
