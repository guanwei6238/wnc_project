use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueRange {
    first: u16,
    last: u16,
}

impl QueueRange {
    pub fn first(&self) -> u16 {
        self.first
    }

    pub fn last(&self) -> u16 {
        self.last
    }

    pub fn overlaps(&self, other: &QueueRange) -> bool {
        self.first <= other.last && other.first <= self.last
    }
}

impl fmt::Display for QueueRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.first == self.last {
            write!(f, "{}", self.first)
        } else {
            write!(f, "{}-{}", self.first, self.last)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid queue {0:?} (expected a number from 0 to 65535 such as 0, or a range such as \"0-3\")")]
pub struct ParseQueueRangeError(String);

impl FromStr for QueueRange {
    type Err = ParseQueueRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseQueueRangeError(s.to_owned());
        let number = |n: &str| {
            if !n.bytes().all(|b| b.is_ascii_digit()) {
                return Err(err());
            }
            n.parse::<u16>().map_err(|_| err())
        };
        let (first, last) = match s.split_once('-') {
            Some((first, last)) => (number(first)?, number(last)?),
            None => (number(s)?, number(s)?),
        };
        if first > last {
            return Err(err());
        }
        Ok(Self { first, last })
    }
}

impl<'de> serde::Deserialize<'de> for QueueRange {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = QueueRange;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a queue number such as 0, or a range such as \"0-3\"")
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<QueueRange, E> {
                v.to_string().parse().map_err(E::custom)
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<QueueRange, E> {
                v.to_string().parse().map_err(E::custom)
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<QueueRange, E> {
                v.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/kernel/nfqueue.rs"]
mod tests;
