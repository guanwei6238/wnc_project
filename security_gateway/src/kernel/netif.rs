use std::fmt;
use std::io;
use std::path::Path;
use std::str::FromStr;

use futures::TryStreamExt;
use rtnetlink::packet_route::link::{
    LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, LinkMessage, LinkXdp, State, XdpAttached,
};

const SYS_CLASS_NET: &str = "/sys/class/net";
const DEVICE_DRIVER: &str = "device/driver";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid MAC address {0:?} (expected aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff)")]
pub struct ParseMacError(String);

impl FromStr for MacAddr {
    type Err = ParseMacError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseMacError(s.to_owned());
        let separator = if s.contains(':') { ':' } else { '-' };
        let mut parts = s.split(separator);
        let mut bytes = [0u8; 6];
        for byte in &mut bytes {
            let part = parts.next().ok_or_else(err)?;
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(err());
            }
            *byte = u8::from_str_radix(part, 16).map_err(|_| err())?;
        }
        if parts.next().is_some() {
            return Err(err());
        }
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperState {
    Unknown,
    NotPresent,
    Down,
    LowerLayerDown,
    Testing,
    Dormant,
    Up,
}

impl fmt::Display for OperState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unknown => "UNKNOWN",
            Self::NotPresent => "NOTPRESENT",
            Self::Down => "DOWN",
            Self::LowerLayerDown => "LOWERLAYERDOWN",
            Self::Testing => "TESTING",
            Self::Dormant => "DORMANT",
            Self::Up => "UP",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    pub mac: Option<MacAddr>,
    pub perm_mac: Option<MacAddr>,
    pub admin_up: bool,
    pub oper_state: OperState,
    pub kind: Option<String>,
    pub master: Option<u32>,
    pub driver: Option<String>,
    pub xdp: Option<XdpAttachment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpMode {
    Native,
    Generic,
    Offload,
    Multiple,
}

impl fmt::Display for XdpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Native => "native",
            Self::Generic => "generic",
            Self::Offload => "offload",
            Self::Multiple => "multiple",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpAttachment {
    pub mode: XdpMode,
    pub prog_id: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    Up,
    AdminDown,
    NoCarrier,
    Unknown,
    Other(OperState),
}

impl Interface {
    pub fn link_status(&self) -> LinkStatus {
        if !self.admin_up {
            return LinkStatus::AdminDown;
        }
        match self.oper_state {
            OperState::Up => LinkStatus::Up,
            OperState::Down | OperState::LowerLayerDown => LinkStatus::NoCarrier,
            OperState::Unknown => LinkStatus::Unknown,
            other => LinkStatus::Other(other),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NetifError {
    #[error("failed to open netlink connection: {0}")]
    Connect(io::Error),
    #[error("failed to dump interfaces: {0}")]
    Dump(String),
}

pub struct Netlink {
    handle: rtnetlink::Handle,
}

impl Netlink {
    pub fn connect() -> Result<Self, NetifError> {
        let (connection, handle, _) = rtnetlink::new_connection().map_err(NetifError::Connect)?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    pub async fn interfaces(&self) -> Result<Vec<Interface>, NetifError> {
        let messages: Vec<LinkMessage> = self
            .handle
            .link()
            .get()
            .execute()
            .try_collect()
            .await
            .map_err(|e| NetifError::Dump(e.to_string()))?;

        Ok(messages
            .into_iter()
            .map(|msg| {
                let mut iface = from_link_message(msg);
                iface.driver = read_driver(&iface.name);
                iface
            })
            .collect())
    }
}

fn from_link_message(msg: LinkMessage) -> Interface {
    let mut iface = Interface {
        index: msg.header.index,
        name: String::new(),
        mac: None,
        perm_mac: None,
        admin_up: msg.header.flags.contains(LinkFlags::Up),
        oper_state: OperState::Unknown,
        kind: None,
        master: None,
        driver: None,
        xdp: None,
    };
    let is_ether = msg.header.link_layer_type == LinkLayerType::Ether;

    for attr in msg.attributes {
        match attr {
            LinkAttribute::IfName(name) => iface.name = name,
            LinkAttribute::Address(bytes) if is_ether => iface.mac = mac_from_bytes(&bytes),
            LinkAttribute::PermAddress(bytes) if is_ether => iface.perm_mac = mac_from_bytes(&bytes),
            LinkAttribute::OperState(state) => iface.oper_state = oper_state(state),
            LinkAttribute::Controller(index) => iface.master = Some(index),
            LinkAttribute::Xdp(attrs) => iface.xdp = xdp_attachment(&attrs),
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    if let LinkInfo::Kind(kind) = info {
                        iface.kind = Some(kind.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    iface
}

fn xdp_attachment(attrs: &[LinkXdp]) -> Option<XdpAttachment> {
    let mut mode = None;
    let mut prog_id = None;
    for attr in attrs {
        match attr {
            LinkXdp::Attached(XdpAttached::Driver) => mode = Some(XdpMode::Native),
            LinkXdp::Attached(XdpAttached::SocketBuffer) => mode = Some(XdpMode::Generic),
            LinkXdp::Attached(XdpAttached::Hardware) => mode = Some(XdpMode::Offload),
            LinkXdp::Attached(XdpAttached::Multiple) => mode = Some(XdpMode::Multiple),
            LinkXdp::ProgId(id) => prog_id = Some(*id),
            _ => {}
        }
    }
    mode.map(|mode| XdpAttachment { mode, prog_id })
}

fn mac_from_bytes(bytes: &[u8]) -> Option<MacAddr> {
    <[u8; 6]>::try_from(bytes).ok().map(MacAddr)
}

fn oper_state(state: State) -> OperState {
    match state {
        State::NotPresent => OperState::NotPresent,
        State::Down => OperState::Down,
        State::LowerLayerDown => OperState::LowerLayerDown,
        State::Testing => OperState::Testing,
        State::Dormant => OperState::Dormant,
        State::Up => OperState::Up,
        _ => OperState::Unknown,
    }
}

fn read_driver(name: &str) -> Option<String> {
    let target = std::fs::read_link(Path::new(SYS_CLASS_NET).join(name).join(DEVICE_DRIVER)).ok()?;
    Some(target.file_name()?.to_str()?.to_owned())
}

#[cfg(test)]
#[path = "../../tests/unit/kernel/netif.rs"]
mod tests;
