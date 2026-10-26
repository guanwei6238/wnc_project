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
            xdp: None,
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
            message: format!(
                "kernel module br_netfilter is not loaded (needed for passing bridged traffic through nftables) \
                 and the kernel does not load it on demand; load it with: modprobe br_netfilter, and {}",
                Current.persist_module_hint("br_netfilter")
            ),
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

fn xdp_row(attached: Option<XdpAttachment>, native: Option<XdpFeatures>, hook: CoreHook) -> XdpRow {
    let mut port = port(Role::Lan, "eth0", true, OperState::Up);
    port.interface.xdp = attached;
    XdpRow { port, native, hook }
}

#[test]
fn native_xdp_has_no_finding() {
    let rows = [xdp_row(None, Some(XdpFeatures(1)), CoreHook::NativeXdp)];
    assert_eq!(xdp_findings(XdpPolicy::Auto, None, &rows), vec![]);
}

#[test]
fn tc_fallback_has_no_finding() {
    let rows = [xdp_row(None, Some(XdpFeatures(0)), CoreHook::Tc)];
    assert_eq!(xdp_findings(XdpPolicy::Auto, None, &rows), vec![]);
}

#[test]
fn detection_failure_is_a_warning_in_auto() {
    let rows = [xdp_row(None, None, CoreHook::Tc)];
    assert_eq!(
        xdp_findings(XdpPolicy::Auto, Some("netdev query failed: x"), &rows),
        vec![Finding {
            severity: Severity::Warning,
            message: "cannot detect native XDP support (netdev query failed: x); the core program will use TC".into(),
        }]
    );
    assert_eq!(xdp_findings(XdpPolicy::Off, Some("netdev query failed: x"), &rows), vec![]);
}

#[test]
fn attached_generic_xdp_is_a_warning() {
    let attached = XdpAttachment {
        mode: XdpMode::Generic,
        prog_id: Some(42),
    };
    let findings = xdp_findings(XdpPolicy::Off, None, &[xdp_row(Some(attached), Some(XdpFeatures(0)), CoreHook::Tc)]);
    assert_eq!(
        findings,
        vec![Finding {
            severity: Severity::Warning,
            message: "LAN (eth0): generic XDP program 42 is attached; generic XDP disables GRO on this interface \
                      and is slower than TC (detach it with: ip link set dev eth0 xdpgeneric off)"
                .into(),
        }]
    );
}

#[test]
fn attached_native_xdp_has_no_finding() {
    let attached = XdpAttachment {
        mode: XdpMode::Native,
        prog_id: Some(7),
    };
    let rows = [xdp_row(Some(attached), Some(XdpFeatures(1)), CoreHook::NativeXdp)];
    assert_eq!(xdp_findings(XdpPolicy::Auto, None, &rows), vec![]);
}

#[test]
fn generic_policy_is_a_warning() {
    let findings = xdp_findings(XdpPolicy::Generic, None, &[xdp_row(None, None, CoreHook::GenericXdp)]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Warning);
    assert!(findings[0].message.starts_with("LAN (eth0): xdp = \"generic\" makes the core program use generic XDP"));
}

fn nft_info(json: Option<bool>) -> Result<NftInfo, NftError> {
    Ok(NftInfo {
        version: Some("1.1.3".into()),
        json,
    })
}

#[test]
fn nft_with_json_has_no_finding() {
    assert_eq!(nft_finding(&nft_info(Some(true))), None);
}

#[test]
fn nft_without_json_is_an_error() {
    assert_eq!(
        nft_finding(&nft_info(Some(false))),
        Some(Finding {
            severity: Severity::Error,
            message: "/usr/sbin/nft is built without JSON support (needed for installing the gateway's nftables \
                      rules); install an nftables build with JSON support"
                .into(),
        })
    );
}

#[test]
fn unreported_json_support_is_a_warning() {
    assert_eq!(
        nft_finding(&nft_info(None)),
        Some(Finding {
            severity: Severity::Warning,
            message: "cannot verify JSON support of /usr/sbin/nft: nft -V does not report it".into(),
        })
    );
}

#[test]
fn missing_nft_is_an_error() {
    assert_eq!(
        nft_finding(&Err(NftError::NotFound)),
        Some(Finding {
            severity: Severity::Error,
            message: "/usr/sbin/nft not found (needed for installing the gateway's nftables rules); install nftables"
                .into(),
        })
    );
}

#[test]
fn nft_probe_failure_is_a_warning() {
    assert_eq!(
        nft_finding(&Err(NftError::Timeout)),
        Some(Finding {
            severity: Severity::Warning,
            message: "could not check nft: /usr/sbin/nft did not finish within 5 seconds".into(),
        })
    );
}

fn suricata_info(nfqueue: Option<bool>, ready_notify: Option<bool>) -> Result<SuricataInfo, SuricataError> {
    Ok(SuricataInfo {
        version: Some("8.0.7".into()),
        nfqueue,
        ready_notify,
    })
}

#[test]
fn suricata_with_nfqueue_and_notify_has_no_finding() {
    assert_eq!(suricata_findings(&suricata_info(Some(true), Some(true))), vec![]);
}

#[test]
fn suricata_without_nfqueue_is_an_error() {
    assert_eq!(
        suricata_findings(&suricata_info(Some(false), Some(true))),
        vec![Finding {
            severity: Severity::Error,
            message: "/usr/bin/suricata is built without NFQueue support (needed for receiving the packets the \
                      gateway queues); install a suricata build with NFQueue support"
                .into(),
        }]
    );
}

#[test]
fn suricata_without_systemd_support_is_an_error() {
    assert_eq!(
        suricata_findings(&suricata_info(Some(true), Some(false))),
        vec![Finding {
            severity: Severity::Error,
            message: "/usr/bin/suricata is built without systemd support (needed for the readiness notification the \
                      gateway waits for before queueing packets); install a suricata build with systemd support"
                .into(),
        }]
    );
}

#[test]
fn unreported_suricata_capabilities_are_warnings() {
    assert_eq!(
        suricata_findings(&suricata_info(None, None)),
        vec![
            Finding {
                severity: Severity::Warning,
                message: "cannot verify NFQueue support of /usr/bin/suricata: --build-info does not report it".into(),
            },
            Finding {
                severity: Severity::Warning,
                message: "cannot verify systemd support of /usr/bin/suricata (needed for the readiness notification): \
                          --build-info does not report it (Suricata 8.0 and later do)"
                    .into(),
            },
        ]
    );
}

#[test]
fn missing_suricata_is_an_error() {
    assert_eq!(
        suricata_findings(&Err(SuricataError::NotFound)),
        vec![Finding {
            severity: Severity::Error,
            message: "/usr/bin/suricata not found (needed for inspecting traffic); install suricata".into(),
        }]
    );
}

#[test]
fn suricata_probe_failure_is_a_warning() {
    assert_eq!(
        suricata_findings(&Err(SuricataError::Timeout)),
        vec![Finding {
            severity: Severity::Warning,
            message: "could not check suricata: /usr/bin/suricata did not finish within 5 seconds".into(),
        }]
    );
}
