use std::fmt;
use std::str::FromStr;

use crate::kernel::conntrack::FiveTuple;
use super::ingress::{TrustError, TrustedFlow};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TrustBackend {
    #[default]
    Tc,
    CtMark,
}

impl fmt::Display for TrustBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tc => "tc",
            Self::CtMark => "ctmark",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid trust backend {0:?} (expected \"tc\" or \"ctmark\")")]
pub struct ParseTrustBackendError(String);

impl FromStr for TrustBackend {
    type Err = ParseTrustBackendError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tc" => Ok(Self::Tc),
            "ctmark" => Ok(Self::CtMark),
            _ => Err(ParseTrustBackendError(s.to_owned())),
        }
    }
}

impl<'de> serde::Deserialize<'de> for TrustBackend {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

pub trait TrustStore {
    fn trust(&mut self, tuple: &FiveTuple) -> Result<(), TrustError>;
    fn untrust(&mut self, tuple: &FiveTuple) -> Result<bool, TrustError>;
    fn trusted(&mut self) -> Result<Vec<TrustedFlow>, TrustError>;
}

#[cfg(test)]
mod tests;
