use crate::config::ports::Port;
use crate::issue::Issue;
use crate::kernel::{modules::RequiredModule, netif::{Interface, Ipv4Net, Ipv4Routing, NextHop, Route, RouteKind, Rule}};
use super::{
    EnvCheck, EnvState, Forwarding, Level, Note, RequiredSysctl, describe, is_bridge, master_of, port_pair, read_sysctl,
    sysctl_checks, unresolved,
};

pub struct Routed;

const SYSCTLS: &[RequiredSysctl] = &[
    RequiredSysctl {
        issue: Issue::RoutedIpForward,
        key: "net.ipv4.ip_forward",
        level: Level::Required,
        consequence: "IPv4 traffic is not forwarded",
        absent: "IPv4 forwarding is not available in this kernel",
    },
    RequiredSysctl {
        issue: Issue::RoutedIpv6Forward,
        key: "net.ipv6.conf.all.forwarding",
        level: Level::Recommended,
        consequence: "IPv6 traffic is not forwarded",
        absent: "IPv6 is disabled",
    },
];

const NOT_BRIDGED: &str = "LAN and WAN not in a bridge";
const ADDRESSED: &str = "LAN and WAN have IPv4 addresses";
const SEPARATE: &str = "subnets do not overlap";
const DEFAULT_ROUTE: &str = "default route via WAN";

const KERNEL_RULES: &[(u32, u32)] = &[(0, 255), (32766, 254), (32767, 253)];
const MAIN_RULE: (u32, u32) = (32766, 254);

impl Forwarding for Routed {
    fn required_modules(&self) -> &'static [RequiredModule] {
        &[]
    }

    fn check_environment(
        &self,
        ports: &[Port],
        interfaces: &[Interface],
        routing: Result<&Ipv4Routing, &str>,
    ) -> Vec<EnvCheck> {
        let mut checks = vec![not_bridged_check(ports, interfaces)];
        checks.extend(sysctl_checks(SYSCTLS, read_sysctl));
        checks.extend(routing_checks(ports, interfaces, routing));
        checks
    }

    fn notes(&self, ports: &[Port], routing: Result<&Ipv4Routing, &str>) -> Vec<Note> {
        let (Some((lan, wan)), Ok(routing)) = (port_pair(ports), routing) else {
            return Vec::new();
        };
        upstream_note(lan, wan, routing)
            .map(|text| Note {
                issue: Issue::RoutedUpstream,
                text,
            })
            .into_iter()
            .collect()
    }
}

fn routing_checks(ports: &[Port], interfaces: &[Interface], routing: Result<&Ipv4Routing, &str>) -> Vec<EnvCheck> {
    let items = [
        (ADDRESSED, Issue::RoutedAddresses),
        (SEPARATE, Issue::RoutedOverlap),
        (DEFAULT_ROUTE, Issue::RoutedDefaultRoute),
    ];
    let Some((lan, wan)) = port_pair(ports) else {
        return items.map(|(item, issue)| unresolved(item, issue)).into();
    };
    let routing = match routing {
        Ok(routing) => routing,
        Err(reason) => {
            return items
                .map(|(item, issue)| EnvCheck {
                    issue,
                    item: item.to_owned(),
                    level: Level::Required,
                    state: EnvState::Unknown {
                        reason: reason.to_owned(),
                    },
                })
                .into();
        }
    };
    vec![
        address_check(lan, wan, routing),
        overlap_check(lan, wan, interfaces, routing),
        default_route_check(wan, interfaces, routing),
    ]
}

fn nets_of(port: &Port, routing: &Ipv4Routing) -> Vec<Ipv4Net> {
    routing
        .addresses
        .iter()
        .filter(|a| a.index == port.interface.index && !a.net.is_link_local())
        .map(|a| a.net)
        .collect()
}

fn join<T: ToString>(items: &[T], separator: &str) -> String {
    items.iter().map(ToString::to_string).collect::<Vec<_>>().join(separator)
}

fn address_check(lan: &Port, wan: &Port, routing: &Ipv4Routing) -> EnvCheck {
    let nets = [(lan, nets_of(lan, routing)), (wan, nets_of(wan, routing))];
    let actual = nets
        .iter()
        .map(|(port, nets)| {
            let list = if nets.is_empty() { "none".to_owned() } else { join(nets, " ") };
            format!("{}: {list}", port.interface.name)
        })
        .collect::<Vec<_>>()
        .join(", ");
    let missing: Vec<String> = nets
        .iter()
        .filter(|(_, nets)| nets.is_empty())
        .map(|(port, _)| describe(port))
        .collect();
    let state = match missing.len() {
        0 => EnvState::Met { actual },
        n => EnvState::Unmet {
            actual,
            problem: format!(
                "{} {} no IPv4 address, so IPv4 traffic cannot be routed through {}",
                missing.join(" and "),
                if n == 1 { "has" } else { "have" },
                if n == 1 { "it" } else { "them" },
            ),
            fix: "assign one with your network manager; if the port uses DHCP, it may not have a lease yet"
                .to_owned(),
        },
    };
    EnvCheck {
        issue: Issue::RoutedAddresses,
        item: ADDRESSED.to_owned(),
        level: Level::Awaited,
        state,
    }
}

fn overlap_check(lan: &Port, wan: &Port, interfaces: &[Interface], routing: &Ipv4Routing) -> EnvCheck {
    let name_of = |index: u32| {
        if index == lan.interface.index {
            describe(lan)
        } else if index == wan.interface.index {
            describe(wan)
        } else {
            interface_name(index, interfaces)
        }
    };

    let mut problems = Vec::new();
    let mut pairs = Vec::new();
    for port in [lan, wan] {
        for own in nets_of(port, routing) {
            for other in &routing.addresses {
                let already_compared = port.interface.index == wan.interface.index && other.index == lan.interface.index;
                if other.index == port.interface.index
                    || already_compared
                    || other.net.is_link_local()
                    || !own.overlaps(other.net)
                {
                    continue;
                }
                problems.push(format!(
                    "{} {own} overlaps {} {}",
                    describe(port),
                    name_of(other.index),
                    other.net
                ));
                pairs.push(format!("{} and {}", port.interface.name, interface_name(other.index, interfaces)));
            }
        }
    }
    let state = if problems.is_empty() {
        EnvState::Met { actual: String::new() }
    } else {
        pairs.dedup();
        EnvState::Unmet {
            actual: pairs.join(", "),
            problem: format!(
                "{}, so the kernel cannot tell which interface the overlapping addresses are on",
                problems.join(" and ")
            ),
            fix: "give LAN and WAN their own subnets that no other interface uses".to_owned(),
        }
    };
    EnvCheck {
        issue: Issue::RoutedOverlap,
        item: SEPARATE.to_owned(),
        level: Level::Required,
        state,
    }
}

fn kernel_rules_only(rules: &[Rule]) -> bool {
    let kernel_rule = |rule: &Rule| {
        rule.unconditional
            && rule
                .table
                .is_some_and(|table| KERNEL_RULES.contains(&(rule.priority, table)))
    };
    rules.iter().all(kernel_rule)
        && rules
            .iter()
            .any(|rule| (rule.priority, rule.table) == (MAIN_RULE.0, Some(MAIN_RULE.1)))
}

fn interface_name(index: u32, interfaces: &[Interface]) -> String {
    interfaces
        .iter()
        .find(|i| i.index == index)
        .map_or_else(|| format!("interface {index}"), |i| i.name.clone())
}

fn describe_hops(hops: &[NextHop], interfaces: &[Interface]) -> String {
    hops.iter()
        .map(|hop| {
            let dev = interface_name(hop.oif, interfaces);
            match hop.gateway {
                Some(gateway) => format!("via {gateway} dev {dev}"),
                None => format!("dev {dev}"),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn default_route_check(wan: &Port, interfaces: &[Interface], routing: &Ipv4Routing) -> EnvCheck {
    let unmet = |actual: String, problem: String, fix: &str| EnvState::Unmet {
        actual,
        problem,
        fix: fix.to_owned(),
    };
    let default = routing
        .main_routes
        .iter()
        .filter(|r| r.destination.prefix_len == 0)
        .min_by_key(|r| r.metric);
    let state = match default {
        _ if !kernel_rules_only(&routing.rules) => EnvState::Unknown {
            reason: "routing rules other than the kernel's defaults are in use (see ip rule), so the main table \
                     alone does not decide where traffic goes"
                .to_owned(),
        },
        None => unmet(
            "none".to_owned(),
            "there is no IPv4 default route, so traffic to networks missing from the routing table is not forwarded"
                .to_owned(),
            "add one through WAN with your network manager; if WAN uses DHCP, it may not have a lease yet",
        ),
        Some(Route { kind, .. }) if *kind != RouteKind::Unicast => unmet(
            kind.to_string(),
            format!("the IPv4 default route is {kind}, so traffic to networks missing from the routing table is dropped"),
            "replace it with a default route through WAN",
        ),
        Some(Route { next_hops, .. }) if next_hops.is_empty() => EnvState::Unknown {
            reason: "the default route does not name its interface (it may use a nexthop object)".to_owned(),
        },
        Some(Route { next_hops, .. }) => {
            let actual = describe_hops(next_hops, interfaces);
            let mut elsewhere: Vec<String> = next_hops
                .iter()
                .filter(|hop| hop.oif != wan.interface.index)
                .map(|hop| interface_name(hop.oif, interfaces))
                .collect();
            elsewhere.dedup();
            if elsewhere.is_empty() {
                EnvState::Met { actual }
            } else {
                unmet(
                    actual,
                    format!(
                        "the default route leaves through {}, not {}, so traffic from the LAN to other networks does \
                         not leave through WAN; with rp_filter, traffic arriving on WAN may also be dropped",
                        elsewhere.join(" and "),
                        describe(wan)
                    ),
                    "move the default route to WAN, or give a default route through WAN a lower metric",
                )
            }
        }
    };
    EnvCheck {
        issue: Issue::RoutedDefaultRoute,
        item: DEFAULT_ROUTE.to_owned(),
        level: Level::Recommended,
        state,
    }
}

fn upstream_note(lan: &Port, wan: &Port, routing: &Ipv4Routing) -> Option<String> {
    let lan_nets = nets_of(lan, routing);
    let wan_nets = nets_of(wan, routing);
    if lan_nets.is_empty() || wan_nets.is_empty() {
        return None;
    }
    let mut behind_lan: Vec<Ipv4Net> = lan_nets.iter().map(|net| net.network()).collect();
    for route in &routing.main_routes {
        let via_lan = !route.next_hops.is_empty() && route.next_hops.iter().all(|hop| hop.oif == lan.interface.index);
        let destination = route.destination.network();
        if route.kind == RouteKind::Unicast
            && route.destination.prefix_len > 0
            && !route.destination.is_link_local()
            && via_lan
            && !behind_lan.contains(&destination)
        {
            behind_lan.push(destination);
        }
    }
    let addrs = |nets: &[Ipv4Net]| nets.iter().map(|net| net.addr.to_string()).collect::<Vec<_>>().join(" or ");
    Some(format!(
        "LAN hosts must use {} as their gateway, and the upstream router needs a route to {} via {}; wnc-gw does \
         not translate addresses, so that route is needed unless you set up NAT yourself",
        addrs(&lan_nets),
        join(&behind_lan, ", "),
        addrs(&wan_nets),
    ))
}

fn not_bridged_check(ports: &[Port], interfaces: &[Interface]) -> EnvCheck {
    let Some((lan, wan)) = port_pair(ports) else {
        return unresolved(NOT_BRIDGED, Issue::RoutedNotBridged);
    };
    let bridged: Vec<(&Port, &Interface)> = [lan, wan]
        .into_iter()
        .filter_map(|port| {
            master_of(&port.interface, interfaces)
                .filter(|m| is_bridge(m))
                .map(|m| (port, m))
        })
        .collect();
    let state = if bridged.is_empty() {
        EnvState::Met { actual: String::new() }
    } else {
        let actual: Vec<String> = bridged
            .iter()
            .map(|(p, m)| format!("{}: {}", p.interface.name, m.name))
            .collect();
        let problem: Vec<String> = bridged
            .iter()
            .map(|(p, m)| format!("{} is in bridge {}", describe(p), m.name))
            .collect();
        EnvState::Unmet {
            actual: actual.join(", "),
            problem: format!("{}, so traffic is bridged instead of routed", problem.join(" and ")),
            fix: "remove the ports from the bridge, or set mode = \"bridge\"".to_owned(),
        }
    };
    EnvCheck {
        issue: Issue::RoutedNotBridged,
        item: NOT_BRIDGED.to_owned(),
        level: Level::Required,
        state,
    }
}

#[cfg(test)]
mod tests;
