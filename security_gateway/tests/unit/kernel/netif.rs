use super::*;
use rtnetlink::packet_route::link::InfoKind;

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
