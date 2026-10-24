use super::{
    EnvCheck, EnvState, Forwarding, Level, RequiredSysctl, describe, is_bridge, master_of, port_pair, read_sysctl,
    sysctl_checks, unresolved,
};
use crate::kernel::modules::RequiredModule;
use crate::kernel::netif::Interface;
use crate::ports::Port;

pub struct Routed;

const SYSCTLS: &[RequiredSysctl] = &[
    RequiredSysctl {
        key: "net.ipv4.ip_forward",
        level: Level::Required,
        consequence: "IPv4 traffic is not forwarded",
        absent: "IPv4 forwarding is not available in this kernel",
    },
    RequiredSysctl {
        key: "net.ipv6.conf.all.forwarding",
        level: Level::Recommended,
        consequence: "IPv6 traffic is not forwarded",
        absent: "IPv6 is disabled",
    },
];

const NOT_BRIDGED: &str = "LAN and WAN not in a bridge";

impl Forwarding for Routed {
    fn required_modules(&self) -> &'static [RequiredModule] {
        &[]
    }

    fn check_environment(&self, ports: &[Port], interfaces: &[Interface]) -> Vec<EnvCheck> {
        let mut checks = vec![not_bridged_check(ports, interfaces)];
        checks.extend(sysctl_checks(SYSCTLS, read_sysctl));
        checks
    }
}

fn not_bridged_check(ports: &[Port], interfaces: &[Interface]) -> EnvCheck {
    let Some((lan, wan)) = port_pair(ports) else {
        return unresolved(NOT_BRIDGED);
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
        item: NOT_BRIDGED.to_owned(),
        level: Level::Required,
        state,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/forwarding/routed.rs"]
mod tests;
