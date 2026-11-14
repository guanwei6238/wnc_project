use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Protection {
    #[default]
    Ids,
    Ips,
}

impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ids => "ids",
            Self::Ips => "ips",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid protection {0:?} (expected \"ids\" or \"ips\")")]
pub struct ParseProtectionError(String);

impl FromStr for Protection {
    type Err = ParseProtectionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ids" => Ok(Self::Ids),
            "ips" => Ok(Self::Ips),
            _ => Err(ParseProtectionError(s.to_owned())),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Protection {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/config/protection.rs"]
mod tests;
