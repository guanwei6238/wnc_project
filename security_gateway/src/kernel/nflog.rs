use std::fmt;
use std::str::FromStr;

use super::nfqueue::QueueRange;

const DEFAULT_GROUP: u16 = 10;

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

#[cfg(test)]
#[path = "../../tests/unit/kernel/nflog.rs"]
mod tests;
