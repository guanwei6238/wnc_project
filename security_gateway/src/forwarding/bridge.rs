use super::{
    EnvCheck, EnvState, Forwarding, Level, RequiredSysctl, describe, is_bridge, master_of, port_pair, read_sysctl,
    sysctl_checks, unresolved,
};
use crate::kernel::modules::RequiredModule;
use crate::kernel::netif::Interface;
use crate::ports::Port;

pub struct Bridged;

const MODULES: &[RequiredModule] = &[
    RequiredModule {
        name: "bridge",
        purpose: "bridging LAN and WAN",
        must_be_loaded: false,
    },
    RequiredModule {
        name: "br_netfilter",
        purpose: "passing bridged traffic through nftables",
        must_be_loaded: true,
    },
];

const SYSCTLS: &[RequiredSysctl] = &[
    RequiredSysctl {
        key: "net.bridge.bridge-nf-call-iptables",
        level: Level::Required,
        consequence: "bridged IPv4 traffic bypasses nftables",
        absent: "br_netfilter is not loaded",
    },
    RequiredSysctl {
        key: "net.bridge.bridge-nf-call-ip6tables",
        level: Level::Required,
        consequence: "bridged IPv6 traffic bypasses nftables",
        absent: "br_netfilter is not loaded",
    },
];

const MEMBERSHIP: &str = "LAN and WAN in one bridge";

impl Forwarding for Bridged {
    fn required_modules(&self) -> &'static [RequiredModule] {
        MODULES
    }

    fn check_environment(&self, ports: &[Port], interfaces: &[Interface]) -> Vec<EnvCheck> {
        let mut checks = membership_checks(ports, interfaces);
        checks.extend(sysctl_checks(SYSCTLS, read_sysctl));
        checks
    }
}

fn membership_checks(ports: &[Port], interfaces: &[Interface]) -> Vec<EnvCheck> {
    let Some((lan, wan)) = port_pair(ports) else {
        return vec![unresolved(MEMBERSHIP)];
    };
    let lan_master = master_of(&lan.interface, interfaces);
    let wan_master = master_of(&wan.interface, interfaces);
    let name = |master: Option<&Interface>| master.map_or("none", |m| m.name.as_str()).to_owned();
    let actual = format!(
        "{}: {}, {}: {}",
        lan.interface.name,
        name(lan_master),
        wan.interface.name,
        name(wan_master)
    );
    let unmet = |problem: String, fix: String| EnvCheck {
        item: MEMBERSHIP.to_owned(),
        level: Level::Required,
        state: EnvState::Unmet {
            actual: actual.clone(),
            problem,
            fix,
        },
    };

    match (lan_master, wan_master) {
        (Some(a), Some(b)) if is_bridge(a) && is_bridge(b) => {
            if a.index != b.index {
                return vec![unmet(
                    format!("{} is in {} but {} is in {}", describe(lan), a.name, describe(wan), b.name),
                    "put both ports in the same bridge".to_owned(),
                )];
            }
            vec![
                EnvCheck {
                    item: MEMBERSHIP.to_owned(),
                    level: Level::Required,
                    state: EnvState::Met { actual: a.name.clone() },
                },
                up_check(a),
            ]
        }
        _ => {
            let problems: Vec<String> = [(lan, lan_master), (wan, wan_master)]
                .into_iter()
                .filter_map(|(port, master)| match master {
                    None => Some(format!("{} is not in a bridge", describe(port))),
                    Some(m) if !is_bridge(m) => Some(format!(
                        "{} belongs to {} ({}), not to a bridge",
                        describe(port),
                        m.name,
                        m.kind.as_deref().unwrap_or("unknown type")
                    )),
                    Some(_) => None,
                })
                .collect();
            vec![unmet(
                problems.join(" and "),
                format!(
                    "create a bridge containing both ports with your network manager \
                     (to try it out: ip link add br0 type bridge; ip link set {} master br0; ip link set {} master br0)",
                    lan.interface.name, wan.interface.name
                ),
            )]
        }
    }
}

fn up_check(bridge: &Interface) -> EnvCheck {
    let state = if bridge.admin_up {
        EnvState::Met { actual: String::new() }
    } else {
        EnvState::Unmet {
            actual: "down".to_owned(),
            problem: format!("bridge {} is administratively down", bridge.name),
            fix: format!("bring it up with: ip link set {} up", bridge.name),
        }
    };
    EnvCheck {
        item: format!("bridge {} is up", bridge.name),
        level: Level::Recommended,
        state,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/forwarding/bridge.rs"]
mod tests;
