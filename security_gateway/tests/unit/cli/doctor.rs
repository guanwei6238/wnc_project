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
    assert_eq!(nft_finding(Path::new("/usr/sbin/nft"), &nft_info(Some(true))), None);
}

#[test]
fn nft_without_json_is_an_error() {
    assert_eq!(
        nft_finding(Path::new("/usr/sbin/nft"), &nft_info(Some(false))),
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
        nft_finding(Path::new("/usr/sbin/nft"), &nft_info(None)),
        Some(Finding {
            severity: Severity::Warning,
            message: "cannot verify JSON support of /usr/sbin/nft: nft -V does not report it".into(),
        })
    );
}

#[test]
fn missing_nft_is_an_error() {
    assert_eq!(
        nft_finding(Path::new("/usr/sbin/nft"), &Err(NftError::NotFound { path: "/usr/sbin/nft".into() })),
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
        nft_finding(Path::new("/usr/sbin/nft"), &Err(NftError::Timeout { path: "/usr/sbin/nft".into() })),
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
    assert_eq!(
        suricata_findings(Path::new("/usr/bin/suricata"), &suricata_info(Some(true), Some(true))),
        vec![]
    );
}

#[test]
fn suricata_without_nfqueue_is_an_error() {
    assert_eq!(
        suricata_findings(Path::new("/usr/bin/suricata"), &suricata_info(Some(false), Some(true))),
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
        suricata_findings(Path::new("/usr/bin/suricata"), &suricata_info(Some(true), Some(false))),
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
        suricata_findings(Path::new("/usr/bin/suricata"), &suricata_info(None, None)),
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
        suricata_findings(
            Path::new("/usr/bin/suricata"),
            &Err(SuricataError::NotFound { path: "/usr/bin/suricata".into() })
        ),
        vec![Finding {
            severity: Severity::Error,
            message: "/usr/bin/suricata not found (needed for inspecting traffic); install suricata".into(),
        }]
    );
}

#[test]
fn suricata_probe_failure_is_a_warning() {
    assert_eq!(
        suricata_findings(
            Path::new("/usr/bin/suricata"),
            &Err(SuricataError::Timeout { path: "/usr/bin/suricata".into() })
        ),
        vec![Finding {
            severity: Severity::Warning,
            message: "could not check suricata: /usr/bin/suricata did not finish within 5 seconds".into(),
        }]
    );
}

const YAML: &str = "/etc/suricata/suricata.yaml";
const FIX: &str = "download rules (for example with suricata-update) or set rule-files in /etc/suricata/suricata.yaml";

fn dump() -> Result<SuricataConfig, SuricataError> {
    Ok(SuricataConfig {
        default_rule_path: Some("/var/lib/suricata/rules".into()),
        rule_files: vec![],
    })
}

fn rule_file(entry: &str, state: RuleFileState) -> RuleFile {
    let path = match state {
        RuleFileState::Wildcard | RuleFileState::NoRulePath => None,
        _ => Some(Path::new("/var/lib/suricata/rules").join(entry)),
    };
    RuleFile {
        entry: entry.into(),
        path,
        state,
    }
}

fn config_findings(dump: Result<SuricataConfig, SuricataError>, files: &[RuleFile]) -> Vec<Finding> {
    suricata_config_findings(Path::new(YAML), &dump, files)
}

#[test]
fn rule_file_with_rules_has_no_finding() {
    assert_eq!(config_findings(dump(), &[rule_file("suricata.rules", RuleFileState::HasRules)]), vec![]);
}

#[test]
fn unloadable_config_is_an_error() {
    let failed = Err(SuricataError::Failed {
        path: "/usr/bin/suricata".into(),
        status: std::os::unix::process::ExitStatusExt::from_raw(256),
        stderr: "Error: conf-yaml-loader: failed to open file: /etc/suricata/suricata.yaml: Permission denied\n\
                 Error: suricata: oops"
            .into(),
    });
    assert_eq!(
        config_findings(failed, &[]),
        vec![Finding {
            severity: Severity::Error,
            message: "suricata cannot load /etc/suricata/suricata.yaml: conf-yaml-loader: failed to open file: \
                      /etc/suricata/suricata.yaml: Permission denied; suricata: oops"
                .into(),
        }]
    );
}

#[test]
fn config_probe_failure_is_a_warning() {
    let timeout = Err(SuricataError::Timeout {
        path: "/usr/bin/suricata".into(),
    });
    assert_eq!(
        config_findings(timeout, &[]),
        vec![Finding {
            severity: Severity::Warning,
            message: "could not check /etc/suricata/suricata.yaml: /usr/bin/suricata did not finish within 5 seconds"
                .into(),
        }]
    );
}

#[test]
fn no_rule_files_is_an_error() {
    assert_eq!(
        config_findings(dump(), &[]),
        vec![Finding {
            severity: Severity::Error,
            message: format!("suricata has no rules to load: rule-files is empty; {FIX}"),
        }]
    );
}

#[test]
fn no_usable_rule_file_is_one_error() {
    let files = [
        rule_file("suricata.rules", RuleFileState::Missing),
        rule_file("local.rules", RuleFileState::NoRules),
    ];
    assert_eq!(
        config_findings(dump(), &files),
        vec![Finding {
            severity: Severity::Error,
            message: format!(
                "suricata has no rules to load: /var/lib/suricata/rules/suricata.rules does not exist, \
                 /var/lib/suricata/rules/local.rules contains no rules; {FIX}"
            ),
        }]
    );
}

#[test]
fn problems_beside_a_usable_rule_file_are_warnings() {
    let files = [
        rule_file("suricata.rules", RuleFileState::HasRules),
        rule_file("local.rules", RuleFileState::Missing),
        rule_file("empty.rules", RuleFileState::NoRules),
    ];
    let findings = config_findings(dump(), &files);
    assert_eq!(
        findings,
        vec![
            Finding {
                severity: Severity::Warning,
                message: "rule file /var/lib/suricata/rules/local.rules does not exist".into(),
            },
            Finding {
                severity: Severity::Warning,
                message: "rule file /var/lib/suricata/rules/empty.rules contains no rules".into(),
            },
        ]
    );
}

#[test]
fn unverifiable_rule_files_are_warnings_not_an_error() {
    let files = [
        rule_file("suricata.rules", RuleFileState::Missing),
        rule_file("*.rules", RuleFileState::Wildcard),
        rule_file(
            "x.rules",
            RuleFileState::Unreadable(io::Error::from(io::ErrorKind::PermissionDenied)),
        ),
    ];
    let findings = config_findings(dump(), &files);
    assert!(findings.iter().all(|f| f.severity == Severity::Warning), "{findings:?}");
    assert_eq!(
        findings.iter().map(|f| f.message.as_str()).collect::<Vec<_>>(),
        vec![
            "rule file /var/lib/suricata/rules/suricata.rules does not exist",
            "cannot verify rule files *.rules: wildcard patterns are not checked",
            "cannot read rule file /var/lib/suricata/rules/x.rules: permission denied",
        ]
    );
}

#[test]
fn rule_file_without_rule_path_is_a_warning() {
    let findings = config_findings(dump(), &[rule_file("suricata.rules", RuleFileState::NoRulePath)]);
    assert_eq!(
        findings,
        vec![Finding {
            severity: Severity::Warning,
            message: "cannot verify rule file suricata.rules: default-rule-path is not set in \
                      /etc/suricata/suricata.yaml"
                .into(),
        }]
    );
}

fn access_row(writers: io::Result<Vec<(Writable, Option<String>)>>) -> AccessRow {
    AccessRow {
        path: "/opt/suricata/bin/suricata".into(),
        used_as: "suricata command",
        writers,
    }
}

fn writable(path: &str, writer: Writer) -> Writable {
    Writable {
        path: path.into(),
        writer,
    }
}

#[test]
fn root_only_files_have_no_finding() {
    assert_eq!(access_findings(&[access_row(Ok(vec![]))]), vec![]);
}

#[test]
fn non_root_writers_are_a_warning() {
    let row = access_row(Ok(vec![
        (writable("/opt/suricata/bin/suricata", Writer::User(1000)), Some("wnc".into())),
        (writable("/opt/suricata/bin", Writer::User(1000)), Some("wnc".into())),
        (writable("/opt/suricata", Writer::Group(50)), None),
        (writable("/opt", Writer::Everyone), None),
    ]));
    assert_eq!(
        access_findings(&[row]),
        vec![Finding {
            severity: Severity::Warning,
            message: "suricata command /opt/suricata/bin/suricata can be modified without root (user wnc owns \
                      /opt/suricata/bin/suricata, /opt/suricata/bin; group 50 can write to /opt/suricata; everyone \
                      can write to /opt), so those accounts could make the gateway run code with its privileges"
                .into(),
        }]
    );
}

#[test]
fn missing_file_is_left_to_its_own_check() {
    let row = access_row(Err(io::Error::from(io::ErrorKind::NotFound)));
    assert_eq!(access_findings(&[row]), vec![]);
}

#[test]
fn access_probe_failure_is_a_warning() {
    let row = access_row(Err(io::Error::from(io::ErrorKind::PermissionDenied)));
    assert_eq!(
        access_findings(&[row]),
        vec![Finding {
            severity: Severity::Warning,
            message: "could not check who can modify /opt/suricata/bin/suricata: permission denied".into(),
        }]
    );
}

#[test]
fn accepting_uninspected_traffic_is_a_warning() {
    assert_eq!(
        when_unavailable_finding(WhenUnavailable::Accept),
        Some(Finding {
            severity: Severity::Warning,
            message: "forwarded traffic passes without inspection while suricata starts, restarts or falls behind \
                      (when_unavailable = \"accept\"); set when_unavailable = \"drop\" to drop it instead"
                .into(),
        })
    );
    assert_eq!(when_unavailable_finding(WhenUnavailable::Drop), None);
}

#[test]
fn spawned_suricata_is_a_warning() {
    assert_eq!(
        spawned_finding(),
        Finding {
            severity: Severity::Warning,
            message: "suricata is started by wnc-gw and shares its account and privileges, so a compromised \
                      suricata can do whatever the gateway can"
                .into(),
        }
    );
}

const SERVICE: &str = "suricata.service";

fn other(pid: u32, capture: Capture, cgroup: &str) -> RunningSuricata {
    RunningSuricata {
        pid,
        capture,
        rss_kb: Some(72328),
        cgroup: Some(cgroup.into()),
        owner: Owner::Other,
        same_net_ns: Some(true),
    }
}

fn scan(running: Vec<RunningSuricata>) -> io::Result<SuricataScan> {
    Ok(SuricataScan {
        running,
        others_hidden: false,
    })
}

fn q(s: &str) -> QueueRange {
    s.parse().unwrap()
}

fn warning(message: impl Into<String>) -> Finding {
    Finding {
        severity: Severity::Warning,
        message: message.into(),
    }
}

#[test]
fn system_service_capturing_is_a_warning() {
    let running = scan(vec![other(842, Capture::Live("af-packet"), "/system.slice/suricata.service")]);
    let stop = Current.stop_service_hint(SERVICE);
    assert_eq!(
        other_suricata_findings(q("0"), &running, SERVICE, Some(&BootState::Enabled)),
        [warning(format!(
            "another suricata (pid 842, suricata.service) is capturing traffic (af-packet) and inspects it \
             separately from wnc-gw; it competes for CPU and uses 71 MB of memory; stop it with: {stop}"
        ))]
    );
}

#[test]
fn another_suricata_on_our_queue_is_a_warning_not_an_error() {
    let running = scan(vec![other(9, Capture::Nfq(vec![q("0-3")]), "/")]);
    assert_eq!(
        other_suricata_findings(q("2"), &running, SERVICE, Some(&BootState::Disabled)),
        [warning(
            "another suricata (pid 9) is running inline on NFQUEUE 0-3, which wnc-gw is configured to use; wnc-gw's \
             suricata cannot bind it until that one stops (wnc-gw keeps retrying); stop it with: kill 9"
        )]
    );
}

#[test]
fn queue_in_an_unknown_network_namespace_says_so() {
    let mut s = other(9, Capture::Nfq(vec![q("0")]), "/");
    s.same_net_ns = None;
    assert_eq!(
        other_suricata_findings(q("0"), &scan(vec![s]), SERVICE, Some(&BootState::Disabled)),
        [warning(
            "another suricata (pid 9) is running inline on NFQUEUE 0, which wnc-gw is configured to use; if it is in \
             wnc-gw's network namespace (could not tell), wnc-gw's suricata cannot bind it until that one stops; \
             stop it with: kill 9"
        )]
    );
}

#[test]
fn queue_in_another_network_namespace_does_not_conflict() {
    let mut s = other(9, Capture::Nfq(vec![q("0")]), "/");
    s.same_net_ns = Some(false);
    assert_eq!(
        other_suricata_findings(q("0"), &scan(vec![s]), SERVICE, Some(&BootState::Disabled)),
        [warning(
            "another suricata (pid 9) is running inline on NFQUEUE 0 in another network namespace; it competes with \
             wnc-gw's suricata for CPU and uses 71 MB of memory; stop it with: kill 9"
        )]
    );
}

#[test]
fn another_suricata_on_other_queues_is_a_warning() {
    let running = scan(vec![other(9, Capture::Nfq(vec![q("4"), q("6-7")]), "/")]);
    assert_eq!(
        other_suricata_findings(q("0"), &running, SERVICE, Some(&BootState::Disabled)),
        [warning(
            "another suricata (pid 9) is running inline on NFQUEUE 4, 6-7; it competes with wnc-gw's suricata for CPU \
             and uses 71 MB of memory; stop it with: kill 9"
        )]
    );
}

#[test]
fn only_the_suricata_service_gets_a_systemctl_hint() {
    let running = scan(vec![other(9, Capture::Live("af-packet"), "/system.slice/cron.service")]);
    assert_eq!(
        other_suricata_findings(q("0"), &running, SERVICE, Some(&BootState::Disabled)),
        [warning(
            "another suricata (pid 9, under cron.service) is capturing traffic (af-packet) and inspects it separately \
             from wnc-gw; it competes for CPU and uses 71 MB of memory; stop it with: kill 9"
        )]
    );
}

#[test]
fn suricata_left_by_a_previous_wnc_gw() {
    let mut holding = other(5, Capture::Nfq(vec![q("0")]), "/system.slice/wnc-gw.service");
    holding.owner = Owner::LeftByWncGw;
    let mut elsewhere = holding.clone();
    elsewhere.pid = 6;
    elsewhere.same_net_ns = Some(false);
    assert_eq!(
        other_suricata_findings(q("0"), &scan(vec![holding, elsewhere]), SERVICE, Some(&BootState::Disabled)),
        [
            warning(
                "a suricata left by a previous wnc-gw (pid 5) is still running and holds NFQUEUE 0, so wnc-gw's \
                 suricata cannot bind it until it exits; it should exit by itself shortly, otherwise stop it with: \
                 kill 5"
            ),
            warning(
                "a suricata left by a previous wnc-gw (pid 6) is still running; it should exit by itself shortly, \
                 otherwise stop it with: kill 6"
            ),
        ]
    );
}

#[test]
fn suricata_started_by_wnc_gw_is_not_a_finding() {
    let mut ours = other(5, Capture::Nfq(vec![q("0")]), "/");
    ours.owner = Owner::WncGw;
    assert_eq!(
        other_suricata_findings(q("0"), &scan(vec![ours]), SERVICE, Some(&BootState::Disabled)),
        []
    );
}

#[test]
fn transient_runs_are_notes_and_do_not_hide_the_boot_warning() {
    let running = scan(vec![
        other(9, Capture::File, "/system.slice/suricata.service"),
        other(10, Capture::Test, "/user.slice/user-1000.slice/session-3.scope"),
    ]);
    let disable = Current.disable_service_hint(SERVICE);
    assert_eq!(
        other_suricata_findings(q("0"), &running, SERVICE, Some(&BootState::Enabled)),
        [
            Finding {
                severity: Severity::Note,
                message: "another suricata (pid 9, suricata.service) is reading pcap files; it competes for CPU while \
                          it runs"
                    .into(),
            },
            Finding {
                severity: Severity::Note,
                message: "another suricata (pid 10) is testing its configuration (suricata-update runs suricata -T); \
                          it exits by itself"
                    .into(),
            },
            warning(format!(
                "suricata.service is enabled, so another suricata starts at boot; disable it with: {disable}"
            )),
        ]
    );
}

#[test]
fn unknown_capture_is_a_warning() {
    let mut s = other(10, Capture::Unknown, "/");
    s.rss_kb = None;
    assert_eq!(
        other_suricata_findings(q("0"), &scan(vec![s]), SERVICE, Some(&BootState::NotInstalled)),
        [warning(
            "another suricata (pid 10) is running, but its command line does not show how it gets packets; it may \
             compete with wnc-gw's suricata; stop it with: kill 10"
        )]
    );
}

#[test]
fn enabled_service_that_is_not_running_is_a_warning() {
    let disable = Current.disable_service_hint(SERVICE);
    assert_eq!(
        other_suricata_findings(q("0"), &scan(vec![]), SERVICE, Some(&BootState::Enabled)),
        [warning(format!(
            "suricata.service is enabled, so another suricata starts at boot; disable it with: {disable}"
        ))]
    );
}

#[test]
fn boot_is_not_checked_when_starting() {
    assert_eq!(other_suricata_findings(q("0"), &scan(vec![]), SERVICE, None), []);
}

#[test]
fn hidden_processes_unknown_boot_state_and_probe_failure_are_warnings() {
    let hidden = Ok(SuricataScan {
        running: vec![],
        others_hidden: true,
    });
    assert_eq!(
        other_suricata_findings(q("0"), &hidden, SERVICE, Some(&BootState::Disabled)),
        [warning(
            "could not see other users' processes (/proc is mounted with hidepid), so other suricata processes may \
             be missing"
        )]
    );
    let failed = Err(io::Error::from(io::ErrorKind::PermissionDenied));
    assert_eq!(
        other_suricata_findings(
            q("0"),
            &failed,
            SERVICE,
            Some(&BootState::Unknown("/usr/bin/systemctl not found".into()))
        ),
        [
            warning("could not check for other suricata processes: permission denied"),
            warning("could not check whether suricata.service starts at boot: /usr/bin/systemctl not found"),
        ]
    );
}
