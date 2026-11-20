use std::fmt;

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    Xdp(XdpMode),
    TcIngress,
    TcEgress,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    #[default]
    Native,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum HookName {
    #[serde(rename = "xdp")]
    Xdp,
    #[serde(rename = "tc-ingress")]
    TcIngress,
    #[serde(rename = "tc-egress")]
    TcEgress,
}

impl Hook {
    pub fn name(self) -> HookName {
        match self {
            Self::Xdp(_) => HookName::Xdp,
            Self::TcIngress => HookName::TcIngress,
            Self::TcEgress => HookName::TcEgress,
        }
    }
}

impl fmt::Display for HookName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Xdp => "xdp",
            Self::TcIngress => "tc-ingress",
            Self::TcEgress => "tc-egress",
        })
    }
}

impl fmt::Display for XdpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Native => "native",
            Self::Generic => "generic",
        })
    }
}

impl fmt::Display for Hook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xdp(mode) => write!(f, "xdp ({mode})"),
            other => other.name().fmt(f),
        }
    }
}
