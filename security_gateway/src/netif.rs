use std::fmt;
use std::io;
use std::path::Path;

use futures::TryStreamExt;
use rtnetlink::packet_route::link::{
    LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, LinkMessage, State,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
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
    pub admin_up: bool,
    pub oper_state: OperState,
    pub kind: Option<String>,
    pub master: Option<u32>,
    pub driver: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum NetifError {
    #[error("無法建立 netlink 連線: {0}")]
    Connect(io::Error),
    #[error("讀取介面列表失敗: {0}")]
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
        admin_up: msg.header.flags.contains(LinkFlags::Up),
        oper_state: OperState::Unknown,
        kind: None,
        master: None,
        driver: None,
    };
    let is_ether = msg.header.link_layer_type == LinkLayerType::Ether;

    for attr in msg.attributes {
        match attr {
            LinkAttribute::IfName(name) => iface.name = name,
            LinkAttribute::Address(bytes) if is_ether => {
                iface.mac = <[u8; 6]>::try_from(bytes.as_slice()).ok().map(MacAddr);
            }
            LinkAttribute::OperState(state) => iface.oper_state = oper_state(state),
            LinkAttribute::Controller(index) => iface.master = Some(index),
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
    let target = std::fs::read_link(Path::new("/sys/class/net").join(name).join("device/driver")).ok()?;
    Some(target.file_name()?.to_str()?.to_owned())
}

#[cfg(test)]
#[path = "../tests/unit/netif.rs"]
mod tests;
