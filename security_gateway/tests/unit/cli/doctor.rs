use super::*;
use security_gateway::forwarding::{EnvCheck, EnvState, Level};
use security_gateway::kernel::netif::OperState;
use security_gateway::ports::{MatchedBy, PortSelector, Role};

fn port(role: Role, name: &str, admin_up: bool, oper_state: OperState) -> Port {
    Port {
        role,
        interface: Interface {
            index: 2,
            name: name.to_owned(),
            mac: None,
            perm_mac: None,
            admin_up,
            oper_state,
            kind: None,
            master: None,
            driver: None,
        },
        matched_by: MatchedBy::Name,
    }
}

#[test]
fn link_up_has_no_finding() {
    assert_eq!(link_finding(&port(Role::Lan, "eth0", true, OperState::Up)), None);
}

#[test]
fn admin_down_is_a_warning() {
    let finding = link_finding(&port(Role::Wan, "eth1", false, OperState::Down)).unwrap();
    assert_eq!(finding.severity, Severity::Warning);
    assert_eq!(
        finding.message,
        "WAN (eth1): interface is administratively down; bring it up with: ip link set eth1 up"
    );
}

#[test]
fn no_carrier_is_a_warning() {
    let finding = link_finding(&port(Role::Lan, "eth0", true, OperState::LowerLayerDown)).unwrap();
    assert_eq!(finding.severity, Severity::Warning);
    assert!(finding.message.starts_with("LAN (eth0): no carrier"));
}

#[test]
fn unknown_is_a_note() {
    let finding = link_finding(&port(Role::Lan, "d0", true, OperState::Unknown)).unwrap();
    assert_eq!(finding.severity, Severity::Note);
}

#[test]
fn other_state_is_a_warning() {
    let finding = link_finding(&port(Role::Lan, "eth0", true, OperState::Dormant)).unwrap();
    assert_eq!(finding.severity, Severity::Warning);
    assert_eq!(finding.message, "LAN (eth0): link state is DORMANT");
}

#[test]
fn resolve_error_is_an_error() {
    let results = vec![
        Err(ResolveError::NotFound {
            role: Role::Lan,
            selector: PortSelector::Name("eth9".into()),
        }),
        Ok(port(Role::Wan, "eth1", false, OperState::Down)),
    ];
    let severities: Vec<_> = port_findings(&results).iter().map(|f| f.severity).collect();
    assert_eq!(severities, vec![Severity::Error, Severity::Warning]);
}

const MODULE: RequiredModule = RequiredModule {
    name: "nft_queue",
    purpose: "queueing packets to the IDS",
    must_be_loaded: false,
};

const PRELOADED: RequiredModule = RequiredModule {
    name: "br_netfilter",
    purpose: "passing bridged traffic through nftables",
    must_be_loaded: true,
};

#[test]
fn available_modules_have_no_finding() {
    for state in [ModuleState::Loaded, ModuleState::Builtin, ModuleState::Loadable] {
        assert_eq!(module_findings("6.12.47", &[(&MODULE, state)]), vec![]);
    }
}

#[test]
fn missing_module_is_an_error() {
    let findings = module_findings("6.12.47", &[(&MODULE, ModuleState::Missing)]);
    assert_eq!(
        findings,
        vec![Finding {
            severity: Severity::Error,
            message: "kernel module nft_queue is missing (needed for queueing packets to the IDS)".into(),
        }]
    );
}

#[test]
fn unknown_module_is_a_warning() {
    let findings = module_findings("6.12.47", &[(&MODULE, ModuleState::Unknown)]);
    assert_eq!(findings[0].severity, Severity::Warning);
    assert_eq!(
        findings[0].message,
        "cannot verify kernel module nft_queue: it is not loaded and /lib/modules/6.12.47 is not readable"
    );
}

#[test]
fn module_that_must_be_loaded_is_fine_when_loaded() {
    for state in [ModuleState::Loaded, ModuleState::Builtin] {
        assert_eq!(module_findings("6.18.50", &[(&PRELOADED, state)]), vec![]);
    }
}

#[test]
fn module_that_must_be_loaded_but_is_only_loadable_is_an_error() {
    let findings = module_findings("6.18.50", &[(&PRELOADED, ModuleState::Loadable)]);
    assert_eq!(
        findings,
        vec![Finding {
            severity: Severity::Error,
            message: "kernel module br_netfilter is not loaded (needed for passing bridged traffic through nftables) \
                      and the kernel does not load it on demand; load it with: modprobe br_netfilter, \
                      and list it in /etc/modules-load.d/ to load it at boot"
                .into(),
        }]
    );
}

fn env(level: Level, state: EnvState) -> EnvCheck {
    EnvCheck {
        item: "net.bridge.bridge-nf-call-iptables".into(),
        level,
        state,
    }
}

fn unmet() -> EnvState {
    EnvState::Unmet {
        actual: "0".into(),
        problem: "P".into(),
        fix: "F".into(),
    }
}

#[test]
fn met_check_has_no_finding() {
    let checks = [env(Level::Required, EnvState::Met { actual: "1".into() })];
    assert_eq!(env_findings(Mode::Bridge, &checks), vec![]);
}

#[test]
fn unmet_required_check_is_an_error() {
    let findings = env_findings(Mode::Bridge, &[env(Level::Required, unmet())]);
    assert_eq!(
        findings,
        vec![Finding {
            severity: Severity::Error,
            message: "bridge mode: P; F".into(),
        }]
    );
}

#[test]
fn unmet_recommended_check_is_a_warning() {
    let findings = env_findings(Mode::Routed, &[env(Level::Recommended, unmet())]);
    assert_eq!(findings[0].severity, Severity::Warning);
    assert_eq!(findings[0].message, "routed mode: P; F");
}

#[test]
fn unknown_check_is_a_warning() {
    let checks = [env(
        Level::Required,
        EnvState::Unknown {
            reason: "br_netfilter is not loaded".into(),
        },
    )];
    assert_eq!(
        env_findings(Mode::Bridge, &checks),
        vec![Finding {
            severity: Severity::Warning,
            message: "bridge mode: cannot verify net.bridge.bridge-nf-call-iptables: br_netfilter is not loaded".into(),
        }]
    );
}
