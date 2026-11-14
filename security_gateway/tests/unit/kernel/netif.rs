use rtnetlink::packet_route::{link::InfoKind, route::RouteNextHop};
use super::*;

fn message(link_layer_type: LinkLayerType, attributes: Vec<LinkAttribute>) -> LinkMessage {
    let mut msg = LinkMessage::default();
    msg.header.index = 7;
    msg.header.link_layer_type = link_layer_type;
    msg.attributes = attributes;
    msg
}

#[test]
fn mac_display() {
    let mac = MacAddr([0x02, 0x00, 0x00, 0x00, 0x01, 0xab]);
    assert_eq!(mac.to_string(), "02:00:00:00:01:ab");
}

#[test]
fn ethernet_link() {
    let mut msg = message(
        LinkLayerType::Ether,
        vec![
            LinkAttribute::IfName("eth0".into()),
            LinkAttribute::Address(vec![0x02, 0, 0, 0, 0x01, 0x01]),
            LinkAttribute::PermAddress(vec![0x9c, 0x69, 0xd3, 0x2a, 0x11, 0x54]),
            LinkAttribute::OperState(State::Up),
            LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Veth)]),
            LinkAttribute::Controller(5),
        ],
    );
    msg.header.flags = LinkFlags::Up;

    let iface = from_link_message(msg);
    assert_eq!(iface.index, 7);
    assert_eq!(iface.name, "eth0");
    assert_eq!(iface.mac, Some(MacAddr([0x02, 0, 0, 0, 0x01, 0x01])));
    assert_eq!(iface.perm_mac, Some(MacAddr([0x9c, 0x69, 0xd3, 0x2a, 0x11, 0x54])));
    assert!(iface.admin_up);
    assert_eq!(iface.oper_state, OperState::Up);
    assert_eq!(iface.kind.as_deref(), Some("veth"));
    assert_eq!(iface.master, Some(5));
    assert_eq!(iface.driver, None);
    assert_eq!(iface.xdp, None);
}

#[test]
fn generic_xdp_attachment() {
    let msg = message(
        LinkLayerType::Ether,
        vec![LinkAttribute::Xdp(vec![LinkXdp::Attached(XdpAttached::SocketBuffer), LinkXdp::ProgId(42)])],
    );
    assert_eq!(
        from_link_message(msg).xdp,
        Some(XdpAttachment { mode: XdpMode::Generic, prog_id: Some(42) })
    );
}

#[test]
fn no_xdp_attached_is_none() {
    let msg = message(LinkLayerType::Ether, vec![LinkAttribute::Xdp(vec![LinkXdp::Attached(XdpAttached::None)])]);
    assert_eq!(from_link_message(msg).xdp, None);
}

#[test]
fn multiple_xdp_programs() {
    let msg = message(
        LinkLayerType::Ether,
        vec![LinkAttribute::Xdp(vec![
            LinkXdp::Attached(XdpAttached::Multiple),
            LinkXdp::DrvProgId(3),
            LinkXdp::SkbProgId(4),
        ])],
    );
    assert_eq!(
        from_link_message(msg).xdp,
        Some(XdpAttachment { mode: XdpMode::Multiple, prog_id: None })
    );
}

#[test]
fn tunnel_address_is_not_mac() {
    let msg = message(
        LinkLayerType::Tunnel,
        vec![LinkAttribute::Address(vec![10, 0, 0, 1])],
    );
    assert_eq!(from_link_message(msg).mac, None);
}

#[test]
fn loopback_address_is_not_mac() {
    let msg = message(
        LinkLayerType::Loopback,
        vec![LinkAttribute::Address(vec![0; 6])],
    );
    assert_eq!(from_link_message(msg).mac, None);
}

#[test]
fn ethernet_with_wrong_length_is_not_mac() {
    let msg = message(
        LinkLayerType::Ether,
        vec![LinkAttribute::Address(vec![1, 2, 3, 4])],
    );
    assert_eq!(from_link_message(msg).mac, None);
}

#[test]
fn missing_attributes_use_defaults() {
    let iface = from_link_message(message(LinkLayerType::Ether, vec![]));
    assert!(!iface.admin_up);
    assert_eq!(iface.oper_state, OperState::Unknown);
    assert_eq!(iface.kind, None);
    assert_eq!(iface.master, None);
}

#[test]
fn tunnel_perm_address_is_not_mac() {
    let msg = message(
        LinkLayerType::Tunnel,
        vec![LinkAttribute::PermAddress(vec![10, 0, 0, 1])],
    );
    assert_eq!(from_link_message(msg).perm_mac, None);
}

#[test]
fn virtual_link_has_no_perm_mac() {
    let msg = message(
        LinkLayerType::Ether,
        vec![LinkAttribute::Address(vec![0x02, 0, 0, 0, 0x01, 0x01])],
    );
    assert_eq!(from_link_message(msg).perm_mac, None);
}

#[test]
fn parse_mac() {
    let expected = MacAddr([0x9c, 0x69, 0xd3, 0x2a, 0x11, 0x54]);
    assert_eq!("9c:69:d3:2a:11:54".parse(), Ok(expected));
    assert_eq!("9C:69:D3:2A:11:54".parse(), Ok(expected));
    assert_eq!("9c-69-d3-2a-11-54".parse(), Ok(expected));
}

#[test]
fn parse_mac_round_trip() {
    let mac = MacAddr([0x02, 0x00, 0x00, 0x00, 0x01, 0xab]);
    assert_eq!(mac.to_string().parse(), Ok(mac));
}

#[test]
fn parse_mac_rejects_invalid() {
    for s in [
        "",
        "9c69d32a1154",
        "9c:69:d3:2a:11",
        "9c:69:d3:2a:11:54:00",
        "9c:69-d3:2a:11:54",
        "9c:69:d3:2a:11:5",
        "9c:69:d3:2a:11:054",
        "+c:69:d3:2a:11:54",
        "9g:69:d3:2a:11:54",
        "eth0",
    ] {
        assert!(s.parse::<MacAddr>().is_err(), "{s:?} should be rejected");
    }
}

fn with_state(admin_up: bool, oper_state: OperState) -> Interface {
    let mut iface = from_link_message(message(LinkLayerType::Ether, vec![]));
    iface.admin_up = admin_up;
    iface.oper_state = oper_state;
    iface
}

#[test]
fn link_status() {
    assert_eq!(with_state(true, OperState::Up).link_status(), LinkStatus::Up);
    assert_eq!(with_state(false, OperState::Down).link_status(), LinkStatus::AdminDown);
    assert_eq!(with_state(true, OperState::Down).link_status(), LinkStatus::NoCarrier);
    assert_eq!(with_state(true, OperState::LowerLayerDown).link_status(), LinkStatus::NoCarrier);
    assert_eq!(with_state(true, OperState::Unknown).link_status(), LinkStatus::Unknown);
    assert_eq!(
        with_state(true, OperState::Dormant).link_status(),
        LinkStatus::Other(OperState::Dormant)
    );
}

#[test]
fn admin_down_takes_precedence() {
    assert_eq!(with_state(false, OperState::Unknown).link_status(), LinkStatus::AdminDown);
}

fn net(s: &str) -> Ipv4Net {
    let (addr, len) = s.split_once('/').unwrap();
    Ipv4Net {
        addr: addr.parse().unwrap(),
        prefix_len: len.parse().unwrap(),
    }
}

#[test]
fn ipv4_net_display_and_network() {
    assert_eq!(net("10.99.1.1/24").to_string(), "10.99.1.1/24");
    assert_eq!(net("10.99.1.1/24").network(), net("10.99.1.0/24"));
    assert_eq!(net("10.99.1.1/0").network(), net("0.0.0.0/0"));
    assert_eq!(net("10.99.1.1/32").network(), net("10.99.1.1/32"));
}

#[test]
fn ipv4_net_overlap() {
    assert!(net("10.0.1.1/24").overlaps(net("10.0.1.2/24")));
    assert!(net("10.0.1.1/24").overlaps(net("10.0.2.1/16")));
    assert!(net("10.0.2.1/16").overlaps(net("10.0.1.1/24")));
    assert!(net("10.0.1.1/24").overlaps(net("10.0.1.200/32")));
    assert!(!net("10.0.1.1/24").overlaps(net("10.0.2.1/24")));
    assert!(!net("10.0.1.1/32").overlaps(net("10.0.1.2/32")));
}

#[test]
fn ipv4_link_local() {
    assert!(net("169.254.3.4/16").is_link_local());
    assert!(!net("10.0.1.1/24").is_link_local());
}

fn address_message(family: AddressFamily, attributes: Vec<AddressAttribute>) -> AddressMessage {
    let mut msg = AddressMessage::default();
    msg.header.family = family;
    msg.header.index = 3;
    msg.header.prefix_len = 24;
    msg.attributes = attributes;
    msg
}

#[test]
fn ipv4_address() {
    let msg = address_message(
        AddressFamily::Inet,
        vec![AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(10, 99, 1, 1)))],
    );
    assert_eq!(
        from_address_message(msg),
        Some(InterfaceAddress { index: 3, net: net("10.99.1.1/24") })
    );
}

#[test]
fn point_to_point_address_uses_local() {
    let msg = address_message(
        AddressFamily::Inet,
        vec![
            AddressAttribute::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            AddressAttribute::Local(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        ],
    );
    assert_eq!(from_address_message(msg).map(|a| a.net), Some(net("10.0.0.1/24")));
}

#[test]
fn ipv6_address_is_skipped() {
    let msg = address_message(AddressFamily::Inet6, vec![AddressAttribute::Address("2001:db8::1".parse().unwrap())]);
    assert_eq!(from_address_message(msg), None);
}

fn route_message(table: u8, kind: RouteType, prefix_len: u8, attributes: Vec<RouteAttribute>) -> RouteMessage {
    let mut msg = RouteMessage::default();
    msg.header.address_family = AddressFamily::Inet;
    msg.header.table = table;
    msg.header.kind = kind;
    msg.header.destination_prefix_length = prefix_len;
    msg.attributes = attributes;
    msg
}

fn inet(a: u8, b: u8, c: u8, d: u8) -> RouteAddress {
    RouteAddress::Inet(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn default_route() {
    let msg = route_message(
        254,
        RouteType::Unicast,
        0,
        vec![
            RouteAttribute::Table(254),
            RouteAttribute::Priority(100),
            RouteAttribute::Gateway(inet(10, 99, 2, 2)),
            RouteAttribute::Oif(4),
        ],
    );
    assert_eq!(
        from_route_message(msg),
        Some(Route {
            destination: net("0.0.0.0/0"),
            kind: RouteKind::Unicast,
            metric: 100,
            next_hops: vec![NextHop { oif: 4, gateway: Some(Ipv4Addr::new(10, 99, 2, 2)) }],
        })
    );
}

#[test]
fn connected_route() {
    let msg = route_message(
        254,
        RouteType::Unicast,
        24,
        vec![RouteAttribute::Destination(inet(10, 99, 1, 0)), RouteAttribute::Oif(3)],
    );
    let route = from_route_message(msg).unwrap();
    assert_eq!(route.destination, net("10.99.1.0/24"));
    assert_eq!(route.next_hops, vec![NextHop { oif: 3, gateway: None }]);
}

#[test]
fn multipath_route() {
    let hop = |oif, gateway| {
        let mut hop = RouteNextHop::default();
        hop.interface_index = oif;
        hop.attributes = vec![RouteAttribute::Gateway(gateway)];
        hop
    };
    let msg = route_message(
        254,
        RouteType::Unicast,
        0,
        vec![RouteAttribute::MultiPath(vec![hop(4, inet(10, 99, 2, 2)), hop(5, inet(10, 99, 3, 2))])],
    );
    assert_eq!(
        from_route_message(msg).unwrap().next_hops,
        vec![
            NextHop { oif: 4, gateway: Some(Ipv4Addr::new(10, 99, 2, 2)) },
            NextHop { oif: 5, gateway: Some(Ipv4Addr::new(10, 99, 3, 2)) },
        ]
    );
}

#[test]
fn blackhole_route_has_no_next_hop() {
    let route = from_route_message(route_message(254, RouteType::BlackHole, 0, vec![])).unwrap();
    assert_eq!(route.kind, RouteKind::Blackhole);
    assert_eq!(route.next_hops, vec![]);
}

#[test]
fn only_main_table_routes_are_kept() {
    assert_eq!(from_route_message(route_message(255, RouteType::Local, 32, vec![RouteAttribute::Oif(1)])), None);
    assert_eq!(
        from_route_message(route_message(252, RouteType::Unicast, 0, vec![RouteAttribute::Table(1000)])),
        None
    );
    assert!(from_route_message(route_message(252, RouteType::Unicast, 0, vec![RouteAttribute::Table(254)])).is_some());
}

fn rule_message(table: u8, action: RuleAction, attributes: Vec<RuleAttribute>) -> RuleMessage {
    let mut msg = RuleMessage::default();
    msg.header.family = AddressFamily::Inet;
    msg.header.table = table;
    msg.header.action = action;
    msg.attributes = attributes;
    msg
}

fn kernel_attributes(priority: u32, table: u32) -> Vec<RuleAttribute> {
    vec![
        RuleAttribute::Table(table),
        RuleAttribute::SuppressPrefixLen(u32::MAX),
        RuleAttribute::Protocol(Default::default()),
        RuleAttribute::Priority(priority),
    ]
}

#[test]
fn kernel_main_rule() {
    let msg = rule_message(254, RuleAction::ToTable, kernel_attributes(32766, 254));
    assert_eq!(
        from_rule_message(msg),
        Rule { priority: 32766, table: Some(254), unconditional: true }
    );
}

#[test]
fn rule_with_selector_is_conditional() {
    let mut attributes = kernel_attributes(100, 100);
    attributes.push(RuleAttribute::Iifname("eth0".into()));
    assert!(!from_rule_message(rule_message(100, RuleAction::ToTable, attributes)).unconditional);

    let mut msg = rule_message(100, RuleAction::ToTable, kernel_attributes(100, 100));
    msg.header.src_len = 24;
    assert!(!from_rule_message(msg).unconditional);

    let mut msg = rule_message(254, RuleAction::ToTable, kernel_attributes(32766, 254));
    msg.header.flags = RuleFlags::Invert;
    assert!(!from_rule_message(msg).unconditional);
}

#[test]
fn suppress_prefix_length_makes_rule_conditional() {
    let attributes = vec![RuleAttribute::Table(254), RuleAttribute::SuppressPrefixLen(0), RuleAttribute::Priority(32764)];
    assert!(!from_rule_message(rule_message(254, RuleAction::ToTable, attributes)).unconditional);
}

#[test]
fn non_lookup_rule_has_no_table() {
    let rule = from_rule_message(rule_message(0, RuleAction::Blackhole, vec![RuleAttribute::Priority(10)]));
    assert_eq!(rule.table, None);
}

#[test]
fn large_table_id_comes_from_attribute() {
    let rule = from_rule_message(rule_message(252, RuleAction::ToTable, kernel_attributes(100, 1000)));
    assert_eq!(rule.table, Some(1000));
}
