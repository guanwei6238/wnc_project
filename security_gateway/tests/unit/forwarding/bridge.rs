use super::*;
use crate::forwarding::tests::{iface, port};
use crate::ports::Role;

const BR0: u32 = 10;
const BR1: u32 = 11;

fn interfaces(lan_master: Option<u32>, wan_master: Option<u32>) -> Vec<Interface> {
    vec![
        iface(2, "eth0", None, lan_master),
        iface(3, "eth1", None, wan_master),
        iface(BR0, "br0", Some("bridge"), None),
        iface(BR1, "br1", Some("bridge"), None),
        iface(12, "bond0", Some("bond"), None),
    ]
}

fn ports(interfaces: &[Interface]) -> Vec<Port> {
    vec![port(Role::Lan, &interfaces[0]), port(Role::Wan, &interfaces[1])]
}

fn unmet(checks: &[EnvCheck]) -> (&str, &str) {
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].item, "LAN and WAN in one bridge");
    assert_eq!(checks[0].level, Level::Required);
    match &checks[0].state {
        EnvState::Unmet { actual, problem, .. } => (actual, problem),
        other => panic!("expected unmet, got {other:?}"),
    }
}

#[test]
fn same_bridge_is_met() {
    let interfaces = interfaces(Some(BR0), Some(BR0));
    let checks = membership_checks(&ports(&interfaces), &interfaces);
    assert_eq!(
        checks,
        vec![
            EnvCheck {
                item: "LAN and WAN in one bridge".into(),
                level: Level::Required,
                state: EnvState::Met { actual: "br0".into() },
            },
            EnvCheck {
                item: "bridge br0 is up".into(),
                level: Level::Recommended,
                state: EnvState::Met { actual: String::new() },
            },
        ]
    );
}

#[test]
fn bridge_down_is_recommended() {
    let mut interfaces = interfaces(Some(BR0), Some(BR0));
    interfaces[2].admin_up = false;
    let checks = membership_checks(&ports(&interfaces), &interfaces);
    assert_eq!(
        checks[1],
        EnvCheck {
            item: "bridge br0 is up".into(),
            level: Level::Recommended,
            state: EnvState::Unmet {
                actual: "down".into(),
                problem: "bridge br0 is administratively down".into(),
                fix: "bring it up with: ip link set br0 up".into(),
            },
        }
    );
}

#[test]
fn port_outside_bridge_is_unmet() {
    let interfaces = interfaces(None, Some(BR0));
    let checks = membership_checks(&ports(&interfaces), &interfaces);
    assert_eq!(unmet(&checks), ("eth0: none, eth1: br0", "LAN (eth0) is not in a bridge"));
    match &checks[0].state {
        EnvState::Unmet { fix, .. } => assert!(fix.contains("ip link set eth0 master br0; ip link set eth1 master br0"), "{fix}"),
        _ => unreachable!(),
    }
}

#[test]
fn both_ports_outside_bridge_are_listed() {
    let interfaces = interfaces(None, None);
    let checks = membership_checks(&ports(&interfaces), &interfaces);
    assert_eq!(
        unmet(&checks).1,
        "LAN (eth0) is not in a bridge and WAN (eth1) is not in a bridge"
    );
}

#[test]
fn different_bridges_are_unmet() {
    let interfaces = interfaces(Some(BR0), Some(BR1));
    let checks = membership_checks(&ports(&interfaces), &interfaces);
    assert_eq!(unmet(&checks), ("eth0: br0, eth1: br1", "LAN (eth0) is in br0 but WAN (eth1) is in br1"));
}

#[test]
fn non_bridge_master_is_unmet() {
    let interfaces = interfaces(Some(12), Some(BR0));
    let checks = membership_checks(&ports(&interfaces), &interfaces);
    assert_eq!(unmet(&checks).1, "LAN (eth0) belongs to bond0 (bond), not to a bridge");
}

#[test]
fn unresolved_port_is_unknown() {
    let interfaces = interfaces(Some(BR0), Some(BR0));
    let checks = membership_checks(&[port(Role::Lan, &interfaces[0])], &interfaces);
    assert_eq!(
        checks,
        vec![EnvCheck {
            item: "LAN and WAN in one bridge".into(),
            level: Level::Required,
            state: EnvState::Unknown {
                reason: "LAN or WAN port could not be resolved".into()
            },
        }]
    );
}
