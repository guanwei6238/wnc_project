use std::fmt;
use std::io;

use futures::StreamExt;
use genetlink::{GenetlinkError, GenetlinkHandle};
use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, NLA_TYPE_MASK, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
    NlasIterator, ParseableParametrized, parse_u32, parse_u64,
};
use netlink_packet_generic::{GenlFamily, GenlHeader, GenlMessage};

const FAMILY_NAME: &str = "netdev";
const FAMILY_VERSION: u8 = 1;
const CMD_DEV_GET: u8 = 1;
const A_DEV_IFINDEX: u16 = 1;
const A_DEV_XDP_FEATURES: u16 = 3;

const XDP_FEATURE_NAMES: &[(u64, &str)] = &[
    (1, "basic"),
    (2, "redirect"),
    (4, "ndo-xmit"),
    (8, "xsk-zerocopy"),
    (16, "hw-offload"),
    (32, "rx-sg"),
    (64, "ndo-xmit-sg"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XdpFeatures(pub u64);

impl XdpFeatures {
    pub fn basic(self) -> bool {
        self.0 & 1 != 0
    }

    pub fn names(self) -> Vec<&'static str> {
        XDP_FEATURE_NAMES
            .iter()
            .filter(|(bit, _)| self.0 & bit != 0)
            .map(|(_, name)| *name)
            .collect()
    }
}

impl fmt::Display for XdpFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.names().as_slice() {
            [] => f.write_str("none"),
            names => f.write_str(&names.join(",")),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NetdevError {
    #[error("failed to open a generic netlink socket: {0}")]
    Connect(io::Error),
    #[error("the kernel has no netdev generic netlink family (needs Linux 6.3 or later)")]
    Unsupported,
    #[error("netdev query failed: {0}")]
    Query(String),
}

pub struct Netdev {
    handle: GenetlinkHandle,
}

impl Netdev {
    pub fn connect() -> Result<Self, NetdevError> {
        let (connection, handle, _) = genetlink::new_connection().map_err(NetdevError::Connect)?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    pub async fn xdp_features(&self, ifindex: u32) -> Result<XdpFeatures, NetdevError> {
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST;
        let request = NetlinkMessage::new(header, GenlMessage::from_payload(DevMessage::request(ifindex)).into());
        let mut responses = self.handle.clone().request(request).await.map_err(request_error)?;

        while let Some(response) = responses.next().await {
            let response = response.map_err(|e| NetdevError::Query(e.to_string()))?;
            match response.payload {
                NetlinkPayload::InnerMessage(msg) if msg.payload.ifindex == Some(ifindex) => {
                    return msg
                        .payload
                        .xdp_features
                        .map(XdpFeatures)
                        .ok_or_else(|| NetdevError::Query("response has no xdp-features".to_owned()));
                }
                NetlinkPayload::Error(e) => return Err(NetdevError::Query(e.to_io().to_string())),
                _ => {}
            }
        }
        Err(NetdevError::Query(format!("no response for interface index {ifindex}")))
    }
}

fn request_error(e: GenetlinkError) -> NetdevError {
    match e {
        GenetlinkError::NetlinkError(io) if io.kind() == io::ErrorKind::NotFound => NetdevError::Unsupported,
        e => NetdevError::Query(e.to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DevMessage {
    cmd: u8,
    ifindex: Option<u32>,
    xdp_features: Option<u64>,
}

impl DevMessage {
    fn request(ifindex: u32) -> Self {
        Self {
            cmd: CMD_DEV_GET,
            ifindex: Some(ifindex),
            xdp_features: None,
        }
    }

    fn attributes(&self) -> Vec<DefaultNla> {
        self.ifindex
            .map(|index| DefaultNla::new(A_DEV_IFINDEX, index.to_ne_bytes().to_vec()))
            .into_iter()
            .collect()
    }
}

impl GenlFamily for DevMessage {
    fn family_name() -> &'static str {
        FAMILY_NAME
    }

    fn command(&self) -> u8 {
        self.cmd
    }

    fn version(&self) -> u8 {
        FAMILY_VERSION
    }
}

impl Emitable for DevMessage {
    fn buffer_len(&self) -> usize {
        self.attributes().as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.attributes().as_slice().emit(buffer)
    }
}

impl ParseableParametrized<[u8], GenlHeader> for DevMessage {
    fn parse_with_param(buf: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        let mut msg = Self {
            cmd: header.cmd,
            ifindex: None,
            xdp_features: None,
        };
        for nla in NlasIterator::new(buf) {
            let nla = nla?;
            match nla.kind() & NLA_TYPE_MASK {
                A_DEV_IFINDEX => msg.ifindex = Some(parse_u32(nla.value())?),
                A_DEV_XDP_FEATURES => msg.xdp_features = Some(parse_u64(nla.value())?),
                _ => {}
            }
        }
        Ok(msg)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/kernel/netdev.rs"]
mod tests;
