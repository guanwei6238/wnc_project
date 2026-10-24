use super::*;
use crate::forwarding::tests::{iface, port};
use crate::ports::Role;

fn interfaces(wan_master: Option<u32>) -> Vec<Interface> {
    vec![
        iface(2, "eth0", None, None),
        iface(3, "eth1", None, wan_master),
        iface(10, "br0", Some("bridge"), None),
        iface(12, "bond0", Some("bond"), None),
    ]
}

fn ports(interfaces: &[Interface]) -> Vec<Port> {
    vec![port(Role::Lan, &interfaces[0]), port(Role::Wan, &interfaces[1])]
}

#[test]
fn ports_outside_bridges_are_met() {
    let interfaces = interfaces(None);
    let check = not_bridged_check(&ports(&interfaces), &interfaces);
    assert_eq!(check.item, "LAN and WAN not in a bridge");
    assert_eq!(check.state, EnvState::Met { actual: String::new() });
}

#[test]
fn non_bridge_master_is_ignored() {
    let interfaces = interfaces(Some(12));
    let check = not_bridged_check(&ports(&interfaces), &interfaces);
    assert_eq!(check.state, EnvState::Met { actual: String::new() });
}

#[test]
fn bridged_port_is_unmet() {
    let interfaces = interfaces(Some(10));
    let check = not_bridged_check(&ports(&interfaces), &interfaces);
    assert_eq!(check.level, Level::Required);
    assert_eq!(
        check.state,
        EnvState::Unmet {
            actual: "eth1: br0".into(),
            problem: "WAN (eth1) is in bridge br0, so traffic is bridged instead of routed".into(),
            fix: "remove the ports from the bridge, or set mode = \"bridge\"".into(),
        }
    );
}

#[test]
fn unresolved_port_is_unknown() {
    let interfaces = interfaces(None);
    let check = not_bridged_check(&[port(Role::Wan, &interfaces[1])], &interfaces);
    assert!(matches!(check.state, EnvState::Unknown { .. }), "{check:?}");
}
