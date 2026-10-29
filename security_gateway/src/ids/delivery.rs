use std::fmt;

use crate::kernel::nflog::GroupRange;
use crate::kernel::nfqueue::QueueRange;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Queue(QueueRange),
    Copy(GroupRange),
}

impl fmt::Display for Delivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queue(queue) => write!(f, "nfqueue {queue}"),
            Self::Copy(group) => write!(f, "nflog {group}"),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/ids/delivery.rs"]
mod tests;
