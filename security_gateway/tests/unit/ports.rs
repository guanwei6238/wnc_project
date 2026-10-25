use super::*;
use crate::kernel::netif::OperState;

const PHY: MacAddr = MacAddr([0x9c, 0x69, 0xd3, 0x2a, 0x11, 0x54]);
const VETH: MacAddr = MacAddr([0x02, 0, 0, 0, 0x01, 0x01]);
const OTHER: MacAddr = MacAddr([0x02, 0, 0, 0, 0x02, 0x01]);

fn iface(index: u32, name: &str, mac: Option<MacAddr>, perm_mac: Option<MacAddr>, kind: Option<&str>) -> Interface {
    Interface {
        index,
        name: name.to_owned(),
        mac,
        perm_mac,
        admin_up: true,
        oper_state: OperState::Up,
        kind: kind.map(str::to_owned),
        master: None,
        driver: None,
        xdp: None,
    }
}

fn spec(role: Role, selector: &str) -> PortSpec {
    PortSpec {
        role,
        selector: selector.parse().unwrap(),
    }
}

fn resolve_single(spec: PortSpec, interfaces: &[Interface]) -> Result<Port, ResolveError> {
    resolve(&[spec], interfaces).remove(0)
}

#[test]
fn parse_selector() {
    assert_eq!("eth0".parse(), Ok(PortSelector::Name("eth0".into())));
    assert_eq!("br-test".parse(), Ok(PortSelector::Name("br-test".into())));
    assert_eq!("9C:69:D3:2A:11:54".parse(), Ok(PortSelector::Mac(PHY)));
    assert_eq!("9c-69-d3-2a-11-54".parse(), Ok(PortSelector::Mac(PHY)));
}

#[test]
fn parse_selector_rejects_invalid() {
    for s in [
        "",
        ".",
        "..",
        "eth0/x",
        "eth 0",
        "eth\t0",
        "eth:0",
        "9c:69:d3:2a:11",
        "0123456789abcdef",
    ] {
        assert!(s.parse::<PortSelector>().is_err(), "{s:?} should be rejected");
    }
}

// 少一組的 MAC 若用 '-' 分隔，仍是合法的介面名稱，會被當成名稱，在 resolve 時找不到
#[test]
fn partial_dashed_mac_is_a_name() {
    assert_eq!(
        "9c-69-d3-2a-11".parse(),
        Ok(PortSelector::Name("9c-69-d3-2a-11".into()))
    );
}

#[test]
fn selector_round_trip() {
    for s in ["eth0", "9c:69:d3:2a:11:54"] {
        assert_eq!(s.parse::<PortSelector>().unwrap().to_string(), s);
    }
}

#[test]
fn by_name() {
    let interfaces = [iface(2, "eth0", Some(VETH), None, Some("veth"))];
    let port = resolve_single(spec(Role::Lan, "eth0"), &interfaces).unwrap();
    assert_eq!(port.interface.name, "eth0");
    assert_eq!(port.matched_by, MatchedBy::Name);
}

#[test]
fn by_permanent_mac() {
    let interfaces = [iface(2, "eth0", Some(PHY), Some(PHY), None)];
    let port = resolve_single(spec(Role::Wan, "9c:69:d3:2a:11:54"), &interfaces).unwrap();
    assert_eq!(port.interface.name, "eth0");
    assert_eq!(port.matched_by, MatchedBy::PermanentMac);
}

#[test]
fn permanent_mac_still_matches_after_address_change() {
    let interfaces = [iface(2, "eth0", Some(OTHER), Some(PHY), None)];
    let port = resolve_single(spec(Role::Wan, "9c:69:d3:2a:11:54"), &interfaces).unwrap();
    assert_eq!(port.interface.name, "eth0");
    assert_eq!(port.matched_by, MatchedBy::PermanentMac);
}

#[test]
fn permanent_mac_wins_over_cloned_current_mac() {
    let interfaces = [
        iface(2, "eth0", Some(PHY), Some(PHY), None),
        iface(3, "eth1", Some(PHY), Some(OTHER), None),
    ];
    let port = resolve_single(spec(Role::Wan, "9c:69:d3:2a:11:54"), &interfaces).unwrap();
    assert_eq!(port.interface.name, "eth0");
    assert_eq!(port.matched_by, MatchedBy::PermanentMac);
}

#[test]
fn permanent_mac_wins_over_bridge_sharing_address() {
    let interfaces = [
        iface(2, "eth0", Some(PHY), Some(PHY), None),
        iface(5, "br0", Some(PHY), None, Some("bridge")),
    ];
    let port = resolve_single(spec(Role::Lan, "9c:69:d3:2a:11:54"), &interfaces).unwrap();
    assert_eq!(port.interface.name, "eth0");
}

#[test]
fn falls_back_to_current_mac_without_permanent() {
    let interfaces = [iface(2, "eth0", Some(VETH), None, Some("veth"))];
    let port = resolve_single(spec(Role::Lan, "02:00:00:00:01:01"), &interfaces).unwrap();
    assert_eq!(port.interface.name, "eth0");
    assert_eq!(port.matched_by, MatchedBy::CurrentMac);
}

#[test]
fn ambiguous_current_mac_is_an_error() {
    let interfaces = [
        iface(2, "eth0", Some(VETH), None, Some("veth")),
        iface(5, "br0", Some(VETH), None, Some("bridge")),
    ];
    assert_eq!(
        resolve_single(spec(Role::Lan, "02:00:00:00:01:01"), &interfaces),
        Err(ResolveError::Ambiguous {
            role: Role::Lan,
            selector: PortSelector::Mac(VETH),
            candidates: vec!["eth0".into(), "br0".into()],
        })
    );
}

#[test]
fn name_resolves_what_mac_cannot() {
    let interfaces = [
        iface(2, "eth0", Some(VETH), None, Some("veth")),
        iface(5, "br0", Some(VETH), None, Some("bridge")),
    ];
    let port = resolve_single(spec(Role::Lan, "eth0"), &interfaces).unwrap();
    assert_eq!(port.interface.index, 2);
}

#[test]
fn not_found() {
    let interfaces = [iface(2, "eth0", Some(VETH), None, None)];
    assert_eq!(
        resolve_single(spec(Role::Wan, "eth9"), &interfaces),
        Err(ResolveError::NotFound {
            role: Role::Wan,
            selector: PortSelector::Name("eth9".into()),
        })
    );
    assert!(matches!(
        resolve_single(spec(Role::Wan, "9c:69:d3:2a:11:54"), &interfaces),
        Err(ResolveError::NotFound { .. })
    ));
}

#[test]
fn two_roles_on_one_interface() {
    let interfaces = [iface(2, "eth0", Some(VETH), None, Some("veth"))];
    let results = resolve(
        &[spec(Role::Lan, "eth0"), spec(Role::Wan, "02:00:00:00:01:01")],
        &interfaces,
    );
    assert_eq!(
        results,
        vec![
            Err(ResolveError::SharedInterface {
                role: Role::Lan,
                other: Role::Wan,
                name: "eth0".into(),
            }),
            Err(ResolveError::SharedInterface {
                role: Role::Wan,
                other: Role::Lan,
                name: "eth0".into(),
            }),
        ]
    );
}

#[test]
fn lan_and_wan_resolved() {
    let interfaces = [
        iface(2, "eth0", Some(VETH), None, Some("veth")),
        iface(3, "eth1", Some(PHY), Some(PHY), None),
    ];
    let results = resolve(
        &[spec(Role::Lan, "eth0"), spec(Role::Wan, "9c:69:d3:2a:11:54")],
        &interfaces,
    );
    assert_eq!(results[0].as_ref().unwrap().interface.name, "eth0");
    assert_eq!(results[1].as_ref().unwrap().interface.name, "eth1");
}

#[test]
fn error_messages() {
    let err = ResolveError::Ambiguous {
        role: Role::Lan,
        selector: PortSelector::Mac(VETH),
        candidates: vec!["eth0".into(), "br0".into()],
    };
    assert_eq!(
        err.to_string(),
        "LAN (02:00:00:00:01:01): matches more than one interface (eth0, br0); specify the interface by name instead"
    );
}
