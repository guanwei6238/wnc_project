use super::*;
use crate::forwarding::tests::{iface, port};
use crate::kernel::netif::InterfaceAddress;
use crate::ports::Role;
use std::net::Ipv4Addr;

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

const LAN: u32 = 2;
const WAN: u32 = 3;
const MGMT: u32 = 5;

fn net(s: &str) -> Ipv4Net {
    let (addr, len) = s.split_once('/').unwrap();
    Ipv4Net {
        addr: addr.parse().unwrap(),
        prefix_len: len.parse().unwrap(),
    }
}

fn addr(index: u32, s: &str) -> InterfaceAddress {
    InterfaceAddress { index, net: net(s) }
}

fn route(destination: &str, metric: u32, hops: &[(u32, Option<&str>)]) -> Route {
    Route {
        destination: net(destination),
        kind: RouteKind::Unicast,
        metric,
        next_hops: hops
            .iter()
            .map(|&(oif, gateway)| NextHop {
                oif,
                gateway: gateway.map(|g| g.parse::<Ipv4Addr>().unwrap()),
            })
            .collect(),
    }
}

fn kernel_rules() -> Vec<Rule> {
    KERNEL_RULES
        .iter()
        .map(|&(priority, table)| Rule { priority, table: Some(table), unconditional: true })
        .collect()
}

fn routed_interfaces() -> Vec<Interface> {
    vec![
        iface(LAN, "eth0", None, None),
        iface(WAN, "eth1.20", None, None),
        iface(MGMT, "eth1", None, None),
    ]
}

fn lan_wan(interfaces: &[Interface]) -> (Port, Port) {
    (port(Role::Lan, &interfaces[0]), port(Role::Wan, &interfaces[1]))
}

fn healthy() -> Ipv4Routing {
    Ipv4Routing {
        addresses: vec![addr(1, "127.0.0.1/8"), addr(LAN, "10.99.1.1/24"), addr(WAN, "10.99.2.1/24"), addr(MGMT, "10.254.254.2/24")],
        main_routes: vec![
            route("0.0.0.0/0", 0, &[(WAN, Some("10.99.2.2"))]),
            route("10.99.1.0/24", 0, &[(LAN, None)]),
            route("10.99.2.0/24", 0, &[(WAN, None)]),
            route("10.254.254.0/24", 0, &[(MGMT, None)]),
            route("192.168.100.0/24", 0, &[(LAN, Some("10.99.1.2"))]),
        ],
        rules: kernel_rules(),
    }
}

#[test]
fn healthy_routing_is_met() {
    let interfaces = routed_interfaces();
    let (lan, wan) = lan_wan(&interfaces);
    let checks = routing_checks(&[lan, wan], &interfaces, Ok(&healthy()));
    let items: Vec<&str> = checks.iter().map(|c| c.item.as_str()).collect();
    assert_eq!(items, ["LAN and WAN have IPv4 addresses", "subnets do not overlap", "default route via WAN"]);
    assert_eq!(
        checks.iter().map(|c| c.level).collect::<Vec<_>>(),
        [Level::Awaited, Level::Required, Level::Recommended]
    );
    assert_eq!(checks[0].state, EnvState::Met { actual: "eth0: 10.99.1.1/24, eth1.20: 10.99.2.1/24".into() });
    assert_eq!(checks[1].state, EnvState::Met { actual: String::new() });
    assert_eq!(checks[2].state, EnvState::Met { actual: "via 10.99.2.2 dev eth1.20".into() });
}

#[test]
fn missing_address_is_unmet() {
    let interfaces = routed_interfaces();
    let (lan, wan) = lan_wan(&interfaces);
    let mut routing = healthy();
    routing.addresses.retain(|a| a.index != LAN);
    routing.addresses.push(addr(LAN, "169.254.7.7/16"));
    assert_eq!(
        address_check(&lan, &wan, &routing).state,
        EnvState::Unmet {
            actual: "eth0: none, eth1.20: 10.99.2.1/24".into(),
            problem: "LAN (eth0) has no IPv4 address, so IPv4 traffic cannot be routed through it".into(),
            fix: "assign one with your network manager; if the port uses DHCP, it may not have a lease yet".into(),
        }
    );
}

#[test]
fn both_addresses_missing() {
    let interfaces = routed_interfaces();
    let (lan, wan) = lan_wan(&interfaces);
    let routing = Ipv4Routing::default();
    let EnvState::Unmet { problem, .. } = address_check(&lan, &wan, &routing).state else {
        panic!("expected unmet");
    };
    assert_eq!(
        problem,
        "LAN (eth0) and WAN (eth1.20) have no IPv4 address, so IPv4 traffic cannot be routed through them"
    );
}

#[test]
fn several_addresses_are_listed() {
    let interfaces = routed_interfaces();
    let (lan, wan) = lan_wan(&interfaces);
    let mut routing = healthy();
    routing.addresses.push(addr(LAN, "192.168.50.1/24"));
    assert_eq!(
        address_check(&lan, &wan, &routing).state,
        EnvState::Met { actual: "eth0: 10.99.1.1/24 192.168.50.1/24, eth1.20: 10.99.2.1/24".into() }
    );
}

#[test]
fn lan_overlapping_wan_is_unmet() {
    let interfaces = routed_interfaces();
    let (lan, wan) = lan_wan(&interfaces);
    let mut routing = healthy();
    routing.addresses.push(addr(WAN, "10.99.0.1/16"));
    assert_eq!(
        overlap_check(&lan, &wan, &interfaces, &routing).state,
        EnvState::Unmet {
            actual: "eth0 and eth1.20".into(),
            problem: "LAN (eth0) 10.99.1.1/24 overlaps WAN (eth1.20) 10.99.0.1/16, so the kernel cannot tell which \
                      interface the overlapping addresses are on"
                .into(),
            fix: "give LAN and WAN their own subnets that no other interface uses".into(),
        }
    );
}

#[test]
fn overlap_with_another_interface_is_unmet() {
    let interfaces = routed_interfaces();
    let (lan, wan) = lan_wan(&interfaces);
    let mut routing = healthy();
    routing.addresses.push(addr(WAN, "10.254.254.9/24"));
    let EnvState::Unmet { actual, problem, .. } = overlap_check(&lan, &wan, &interfaces, &routing).state else {
        panic!("expected unmet");
    };
    assert_eq!(actual, "eth1.20 and eth1");
    assert!(problem.starts_with("WAN (eth1.20) 10.254.254.9/24 overlaps eth1 10.254.254.2/24, so"), "{problem}");
}

#[test]
fn link_local_addresses_do_not_overlap() {
    let interfaces = routed_interfaces();
    let (lan, wan) = lan_wan(&interfaces);
    let mut routing = healthy();
    routing.addresses.push(addr(LAN, "169.254.1.1/16"));
    routing.addresses.push(addr(WAN, "169.254.2.2/16"));
    assert_eq!(overlap_check(&lan, &wan, &interfaces, &routing).state, EnvState::Met { actual: String::new() });
}

#[test]
fn missing_default_route_is_unmet() {
    let interfaces = routed_interfaces();
    let (_, wan) = lan_wan(&interfaces);
    let mut routing = healthy();
    routing.main_routes.retain(|r| r.destination.prefix_len != 0);
    assert_eq!(
        default_route_check(&wan, &interfaces, &routing).state,
        EnvState::Unmet {
            actual: "none".into(),
            problem: "there is no IPv4 default route, so traffic to networks missing from the routing table is not \
                      forwarded"
                .into(),
            fix: "add one through WAN with your network manager; if WAN uses DHCP, it may not have a lease yet".into(),
        }
    );
}

#[test]
fn default_route_through_another_interface_is_unmet() {
    let interfaces = routed_interfaces();
    let (_, wan) = lan_wan(&interfaces);
    let mut routing = healthy();
    routing.main_routes[0] = route("0.0.0.0/0", 0, &[(MGMT, Some("10.254.254.1"))]);
    assert_eq!(
        default_route_check(&wan, &interfaces, &routing).state,
        EnvState::Unmet {
            actual: "via 10.254.254.1 dev eth1".into(),
            problem: "the default route leaves through eth1, not WAN (eth1.20), so traffic from the LAN to other \
                      networks does not leave through WAN; with rp_filter, traffic arriving on WAN may also be dropped"
                .into(),
            fix: "move the default route to WAN, or give a default route through WAN a lower metric".into(),
        }
    );
}

#[test]
fn lowest_metric_default_route_wins() {
    let interfaces = routed_interfaces();
    let (_, wan) = lan_wan(&interfaces);
    let mut routing = healthy();
    routing.main_routes.push(route("0.0.0.0/0", 50, &[(MGMT, Some("10.254.254.1"))]));
    routing.main_routes[0].metric = 100;
    assert!(matches!(default_route_check(&wan, &interfaces, &routing).state, EnvState::Unmet { .. }));
    routing.main_routes[0].metric = 10;
    assert!(matches!(default_route_check(&wan, &interfaces, &routing).state, EnvState::Met { .. }));
}

#[test]
fn multipath_default_route_must_stay_on_wan() {
    let interfaces = routed_interfaces();
    let (_, wan) = lan_wan(&interfaces);
    let mut routing = healthy();
    routing.main_routes[0] = route("0.0.0.0/0", 0, &[(WAN, Some("10.99.2.2")), (MGMT, None)]);
    let EnvState::Unmet { actual, problem, .. } = default_route_check(&wan, &interfaces, &routing).state else {
        panic!("expected unmet");
    };
    assert_eq!(actual, "via 10.99.2.2 dev eth1.20, dev eth1");
    assert!(problem.starts_with("the default route leaves through eth1, not WAN (eth1.20)"), "{problem}");
}

#[test]
fn blackhole_default_route_is_unmet() {
    let interfaces = routed_interfaces();
    let (_, wan) = lan_wan(&interfaces);
    let mut routing = healthy();
    routing.main_routes[0] = Route { kind: RouteKind::Blackhole, next_hops: vec![], ..route("0.0.0.0/0", 0, &[]) };
    let EnvState::Unmet { actual, problem, .. } = default_route_check(&wan, &interfaces, &routing).state else {
        panic!("expected unmet");
    };
    assert_eq!(actual, "blackhole");
    assert!(problem.starts_with("the IPv4 default route is blackhole, so"), "{problem}");
}

#[test]
fn default_route_without_interface_is_unknown() {
    let interfaces = routed_interfaces();
    let (_, wan) = lan_wan(&interfaces);
    let mut routing = healthy();
    routing.main_routes[0] = route("0.0.0.0/0", 0, &[]);
    assert!(matches!(default_route_check(&wan, &interfaces, &routing).state, EnvState::Unknown { .. }));
}

#[test]
fn policy_routing_is_unknown() {
    let interfaces = routed_interfaces();
    let (_, wan) = lan_wan(&interfaces);
    let mut routing = healthy();
    routing.rules.push(Rule { priority: 100, table: Some(100), unconditional: false });
    assert_eq!(
        default_route_check(&wan, &interfaces, &routing).state,
        EnvState::Unknown {
            reason: "routing rules other than the kernel's defaults are in use (see ip rule), so the main table alone \
                     does not decide where traffic goes"
                .into()
        }
    );
}

#[test]
fn kernel_rules_are_recognised() {
    assert!(kernel_rules_only(&kernel_rules()));
    let without_default_table: Vec<Rule> = kernel_rules().into_iter().filter(|r| r.priority != 32767).collect();
    assert!(kernel_rules_only(&without_default_table));
    let without_main: Vec<Rule> = kernel_rules().into_iter().filter(|r| r.priority != 32766).collect();
    assert!(!kernel_rules_only(&without_main));
    let mut conditional = kernel_rules();
    conditional[1].unconditional = false;
    assert!(!kernel_rules_only(&conditional));
    let mut moved = kernel_rules();
    moved[1].priority = 100;
    assert!(!kernel_rules_only(&moved));
}

#[test]
fn routing_failure_is_unknown() {
    let interfaces = routed_interfaces();
    let (lan, wan) = lan_wan(&interfaces);
    let checks = routing_checks(&[lan, wan], &interfaces, Err("failed to dump routes: x"));
    assert_eq!(checks.len(), 3);
    for check in checks {
        assert_eq!(check.state, EnvState::Unknown { reason: "failed to dump routes: x".into() });
    }
}

#[test]
fn unresolved_ports_make_routing_unknown() {
    let interfaces = routed_interfaces();
    let (_, wan) = lan_wan(&interfaces);
    let checks = routing_checks(&[wan], &interfaces, Ok(&healthy()));
    assert_eq!(checks.len(), 3);
    assert!(checks.iter().all(|c| matches!(c.state, EnvState::Unknown { .. })), "{checks:?}");
}

#[test]
fn upstream_note_lists_networks_behind_lan() {
    let interfaces = routed_interfaces();
    let (lan, wan) = lan_wan(&interfaces);
    assert_eq!(
        Routed.notes(&[lan, wan], Ok(&healthy())),
        vec![
            "LAN hosts must use 10.99.1.1 as their gateway, and the upstream router needs a route to 10.99.1.0/24, \
             192.168.100.0/24 via 10.99.2.1; wnc-gw does not translate addresses, so that route is needed unless you \
             set up NAT yourself"
                .to_owned()
        ]
    );
}

#[test]
fn no_upstream_note_without_addresses() {
    let interfaces = routed_interfaces();
    let (lan, wan) = lan_wan(&interfaces);
    let mut routing = healthy();
    routing.addresses.retain(|a| a.index != WAN);
    assert_eq!(Routed.notes(&[lan.clone(), wan.clone()], Ok(&routing)), Vec::<String>::new());
    assert_eq!(Routed.notes(&[lan, wan], Err("x")), Vec::<String>::new());
}
