use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::str::FromStr;

use futures::channel::mpsc::UnboundedReceiver;
use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::{IpVersion, MulticastGroup, RouteMessageBuilder};
use rtnetlink::packet_route::{
    AddressFamily, address::{AddressAttribute, AddressMessage},
    link::{LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, LinkMessage, LinkXdp, State, XdpAttached},
    RouteNetlinkMessage,
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteType},
    rule::{RuleAction, RuleAttribute, RuleFlags, RuleMessage},
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
    #[error("failed to dump {what}: {reason}")]
    Dump { what: &'static str, reason: String },
    #[error("route lookup failed: {0}")]
    Route(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteTo {
    pub oif: u32,
    pub gateway: Option<IpAddr>,
}

pub struct RouteChanges {
    messages: UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, netlink_sys::SocketAddr)>,
}

impl RouteChanges {
    pub fn subscribe() -> Result<Self, NetifError> {
        let (connection, _, messages) =
            rtnetlink::new_multicast_connection(&[MulticastGroup::Ipv4Route, MulticastGroup::Ipv6Route])
                .map_err(NetifError::Connect)?;
        tokio::spawn(connection);
        Ok(Self { messages })
    }

    pub async fn next(&mut self) -> Option<()> {
        while let Some((message, _)) = self.messages.next().await {
            if matches!(
                message.payload,
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(_) | RouteNetlinkMessage::DelRoute(_))
            ) {
                return Some(());
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Net {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
}

impl Ipv4Net {
    pub fn network(self) -> Self {
        Self {
            addr: masked(self.addr, self.prefix_len),
            prefix_len: self.prefix_len,
        }
    }

    pub fn overlaps(self, other: Self) -> bool {
        let len = self.prefix_len.min(other.prefix_len);
        masked(self.addr, len) == masked(other.addr, len)
    }

    pub fn is_link_local(self) -> bool {
        self.addr.is_link_local()
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

fn masked(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix_len.min(32))).unwrap_or(0);
    Ipv4Addr::from(u32::from(addr) & mask)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceAddress {
    pub index: u32,
    pub net: Ipv4Net,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Unicast,
    Blackhole,
    Unreachable,
    Prohibit,
    Throw,
    Other,
}

impl fmt::Display for RouteKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unicast => "unicast",
            Self::Blackhole => "blackhole",
            Self::Unreachable => "unreachable",
            Self::Prohibit => "prohibit",
            Self::Throw => "throw",
            Self::Other => "other",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NextHop {
    pub oif: u32,
    pub gateway: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub destination: Ipv4Net,
    pub kind: RouteKind,
    pub metric: u32,
    pub next_hops: Vec<NextHop>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub priority: u32,
    pub table: Option<u32>,
    pub unconditional: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ipv4Routing {
    pub addresses: Vec<InterfaceAddress>,
    pub main_routes: Vec<Route>,
    pub rules: Vec<Rule>,
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
            .map_err(dump_error("interfaces"))?;

        Ok(messages
            .into_iter()
            .map(|msg| {
                let mut iface = from_link_message(msg);
                iface.driver = read_driver(&iface.name);
                iface
            })
            .collect())
    }

    pub async fn ipv4_routing(&self) -> Result<Ipv4Routing, NetifError> {
        let mut addresses = self.handle.address().get();
        addresses.message_mut().header.family = AddressFamily::Inet;
        let addresses: Vec<AddressMessage> =
            addresses.execute().try_collect().await.map_err(dump_error("addresses"))?;
        let routes: Vec<RouteMessage> = self
            .handle
            .route()
            .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
            .execute()
            .try_collect()
            .await
            .map_err(dump_error("routes"))?;
        let rules: Vec<RuleMessage> = self
            .handle
            .rule()
            .get(IpVersion::V4)
            .execute()
            .try_collect()
            .await
            .map_err(dump_error("routing rules"))?;

        Ok(Ipv4Routing {
            addresses: addresses.into_iter().filter_map(from_address_message).collect(),
            main_routes: routes.into_iter().filter_map(from_route_message).collect(),
            rules: rules.into_iter().map(from_rule_message).collect(),
        })
    }
}

impl Netlink {
    pub async fn output_route(&self, dst: IpAddr) -> Result<Option<RouteTo>, NetifError> {
        let message = RouteMessageBuilder::<IpAddr>::new()
            .destination_prefix(dst, host_prefix(dst))
            .map_err(|e| NetifError::Route(e.to_string()))?
            .build();
        self.route_get(message).await
    }

    pub async fn forwarding_route(&self, src: IpAddr, dst: IpAddr, iif: u32) -> Result<Option<RouteTo>, NetifError> {
        let message = RouteMessageBuilder::<IpAddr>::new()
            .destination_prefix(dst, host_prefix(dst))
            .and_then(|b| b.source_prefix(src, host_prefix(src)))
            .map_err(|e| NetifError::Route(e.to_string()))?
            .input_interface(iif)
            .build();
        self.route_get(message).await
    }

    async fn route_get(&self, message: RouteMessage) -> Result<Option<RouteTo>, NetifError> {
        let mut replies = self.handle.route().get(message).execute();
        match replies.try_next().await {
            Ok(Some(reply)) => Ok(route_of(&reply)),
            Ok(None) | Err(rtnetlink::Error::NetlinkError(_)) => Ok(None),
            Err(e) => Err(NetifError::Route(e.to_string())),
        }
    }
}

fn host_prefix(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
}

fn route_of(reply: &RouteMessage) -> Option<RouteTo> {
    if reply.header.kind != RouteType::Unicast {
        return None;
    }
    let (mut oif, mut gateway) = (None, None);
    for attr in &reply.attributes {
        match attr {
            RouteAttribute::Oif(index) => oif = Some(*index),
            RouteAttribute::Gateway(RouteAddress::Inet(a)) => gateway = Some(IpAddr::V4(*a)),
            RouteAttribute::Gateway(RouteAddress::Inet6(a)) => gateway = Some(IpAddr::V6(*a)),
            RouteAttribute::MultiPath(_) | RouteAttribute::Via(_) => return None,
            _ => {}
        }
    }
    Some(RouteTo { oif: oif?, gateway })
}

fn dump_error(what: &'static str) -> impl Fn(rtnetlink::Error) -> NetifError {
    move |e| NetifError::Dump {
        what,
        reason: e.to_string(),
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

const RT_TABLE_MAIN: u32 = 254;

fn from_address_message(msg: AddressMessage) -> Option<InterfaceAddress> {
    if msg.header.family != AddressFamily::Inet {
        return None;
    }
    let mut address = None;
    let mut local = None;
    for attr in msg.attributes {
        match attr {
            AddressAttribute::Address(IpAddr::V4(addr)) => address = Some(addr),
            AddressAttribute::Local(IpAddr::V4(addr)) => local = Some(addr),
            _ => {}
        }
    }
    Some(InterfaceAddress {
        index: msg.header.index,
        net: Ipv4Net {
            addr: local.or(address)?,
            prefix_len: msg.header.prefix_len,
        },
    })
}

fn from_route_message(msg: RouteMessage) -> Option<Route> {
    if msg.header.address_family != AddressFamily::Inet {
        return None;
    }
    let mut table = u32::from(msg.header.table);
    let mut destination = Ipv4Addr::UNSPECIFIED;
    let mut metric = 0;
    let mut oif = None;
    let mut gateway = None;
    let mut next_hops = Vec::new();
    for attr in msg.attributes {
        match attr {
            RouteAttribute::Table(id) => table = id,
            RouteAttribute::Destination(RouteAddress::Inet(addr)) => destination = addr,
            RouteAttribute::Priority(value) => metric = value,
            RouteAttribute::Oif(index) => oif = Some(index),
            RouteAttribute::Gateway(RouteAddress::Inet(addr)) => gateway = Some(addr),
            RouteAttribute::MultiPath(hops) => next_hops.extend(hops.into_iter().map(|hop| NextHop {
                oif: hop.interface_index,
                gateway: hop.attributes.into_iter().find_map(|attr| match attr {
                    RouteAttribute::Gateway(RouteAddress::Inet(addr)) => Some(addr),
                    _ => None,
                }),
            })),
            _ => {}
        }
    }
    if table != RT_TABLE_MAIN {
        return None;
    }
    if let Some(oif) = oif {
        next_hops.insert(0, NextHop { oif, gateway });
    }
    Some(Route {
        destination: Ipv4Net {
            addr: destination,
            prefix_len: msg.header.destination_prefix_length,
        },
        kind: match msg.header.kind {
            RouteType::Unicast => RouteKind::Unicast,
            RouteType::BlackHole => RouteKind::Blackhole,
            RouteType::Unreachable => RouteKind::Unreachable,
            RouteType::Prohibit => RouteKind::Prohibit,
            RouteType::Throw => RouteKind::Throw,
            _ => RouteKind::Other,
        },
        metric,
        next_hops,
    })
}

fn from_rule_message(msg: RuleMessage) -> Rule {
    let mut priority = 0;
    let mut table = u32::from(msg.header.table);
    let mut unconditional = msg.header.src_len == 0
        && msg.header.dst_len == 0
        && msg.header.tos == 0
        && !msg.header.flags.contains(RuleFlags::Invert);
    for attr in msg.attributes {
        match attr {
            RuleAttribute::Priority(value) => priority = value,
            RuleAttribute::Table(id) => table = id,
            RuleAttribute::Protocol(_) => {}
            RuleAttribute::SuppressPrefixLen(u32::MAX) | RuleAttribute::SuppressIfGroup(u32::MAX) => {}
            _ => unconditional = false,
        }
    }
    Rule {
        priority,
        table: (msg.header.action == RuleAction::ToTable).then_some(table),
        unconditional,
    }
}

fn read_driver(name: &str) -> Option<String> {
    let target = std::fs::read_link(Path::new(SYS_CLASS_NET).join(name).join(DEVICE_DRIVER)).ok()?;
    Some(target.file_name()?.to_str()?.to_owned())
}

#[cfg(test)]
#[path = "../../tests/unit/kernel/netif.rs"]
mod tests;
