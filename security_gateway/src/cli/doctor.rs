use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use security_gateway::config::{
    self, AbsolutePath, AutoTrust, Config, ConfigError, Overrides, Setting, SuricataSettings, TrustSettings,
    ports::{self, Port, ResolveError}, protection::Protection,
};
use security_gateway::datapath::{CORE_PROGRAM_NAME, CoreHook, XdpPolicy, core_hook, firewall::WhenUnavailable};
use security_gateway::forwarding::{self, EnvCheck, EnvState, Forwarding, Level, Mode, Note};
use security_gateway::ids::{
    delivery::Delivery, spawned,
    suricata::{
        self, Capture, Owner, RuleFile, RuleFileState, RunningSuricata, Suricata, SuricataConfig, SuricataError,
        SuricataInfo, SuricataScan,
    },
};
use security_gateway::issue::Issue;
use security_gateway::kernel::{
    bpf::{self, TcxChain, TcxQueryError}, modules::{ModuleIndex, ModuleState, RequiredModule},
    netdev::{Netdev, XdpFeatures}, netif::{Interface, Ipv4Routing, LinkStatus, Netlink, XdpAttachment, XdpMode},
    nfqueue::QueueRange, nft::{Nft, NftError, NftInfo}, sysctl,
};
use security_gateway::platform::{BootConfig, BootState, Current, Dirs, Services};
use security_gateway::system::access::{self, Writable, Writer};

#[derive(Debug, Args)]
pub struct DoctorArgs {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    Error,
    Warning,
    Note,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    severity: Severity,
    issue: Issue,
    message: String,
}

impl Finding {
    fn print(&self) {
        let label = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Note => "note",
        };
        out!("{label}[{}]: {}", self.issue, self.message);
    }
}

pub async fn run(config_path: Option<&Path>, overrides: Overrides, _args: DoctorArgs) -> ExitCode {
    let config = match config::load(config_path, overrides) {
        Ok(config) => config,
        Err(e) => {
            Finding {
                severity: Severity::Error,
                issue: config_issue(&e),
                message: e.to_string(),
            }
            .print();
            return ExitCode::FAILURE;
        }
    };
    if passes(&config, false).await {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

pub async fn passes(config: &Config, starting: bool) -> bool {
    match &config.file {
        Some(path) => out!("config: {}", path.display()),
        None => out!("config: none ({} not found)", config::DEFAULT_PATH),
    }
    out!("mode:   {} ({})", config.mode.value, config.mode.source);
    out!("xdp:    {} ({})", config.xdp.value, config.xdp.source);
    out!("protection: {} ({}), suricata receives {}", config.protection.value, config.protection.source, config.delivery());
    out!("trust:  {}", trust_summary(&config.trust));
    out!();

    let netlink = match Netlink::connect() {
        Ok(netlink) => netlink,
        Err(e) => {
            Finding {
                severity: Severity::Error,
                issue: Issue::InterfacesUnlisted,
                message: e.to_string(),
            }
            .print();
            return false;
        }
    };
    let interfaces = match netlink.interfaces().await {
        Ok(interfaces) => interfaces,
        Err(e) => {
            Finding {
                severity: Severity::Error,
                issue: Issue::InterfacesUnlisted,
                message: e.to_string(),
            }
            .print();
            return false;
        }
    };
    let results = ports::resolve(&config.port_specs(), &interfaces);
    print_ports(config, &results);
    let mut findings = port_findings(&results);
    out!();

    let mode = config.mode.value;
    let forwarding = forwarding::for_mode(mode);
    let ports: Vec<Port> = results.iter().filter_map(|r| r.as_ref().ok().cloned()).collect();
    let routing = netlink.ipv4_routing().await.map_err(|e| e.to_string());
    let routing = routing.as_ref().map_err(String::as_str);
    findings.extend(check_environment(mode, forwarding.as_ref(), &ports, &interfaces, routing));
    out!();

    findings.extend(check_xdp(config.xdp.value, &ports).await);
    out!();

    findings.extend(check_tcx(&ports));
    out!();

    findings.extend(check_modules(forwarding.required_modules(), config.delivery()));
    out!();

    findings.extend(check_nft(&config.nftables.path).await);
    out!();

    findings.extend(check_suricata(config).await);
    out!();

    findings.extend(check_other_suricata(config.delivery(), !starting).await);
    out!();

    findings.extend(check_access(config));

    if !findings.is_empty() {
        out!();
    }
    for finding in &findings {
        finding.print();
    }
    if let Some(first) = findings.first() {
        out!("\nfor more about a finding, run: wnc-gw explain <code> (for example wnc-gw explain {})", first.issue);
    }
    !findings.iter().any(|f| f.severity == Severity::Error)
}

pub(crate) fn config_issue(e: &ConfigError) -> Issue {
    match e {
        ConfigError::Read { .. } => Issue::ConfigUnreadable,
        ConfigError::Parse { .. } => Issue::ConfigInvalid,
        ConfigError::Missing { .. } => Issue::PortUnspecified,
        ConfigError::Inapplicable { .. } => Issue::ConfigInapplicable,
    }
}

fn resolve_issue(e: &ResolveError) -> Issue {
    match e {
        ResolveError::NotFound { .. } => Issue::PortNotFound,
        ResolveError::Ambiguous { .. } => Issue::PortAmbiguous,
        ResolveError::SharedInterface { .. } => Issue::PortShared,
    }
}

fn port_findings(results: &[Result<Port, ResolveError>]) -> Vec<Finding> {
    results
        .iter()
        .filter_map(|result| match result {
            Ok(port) => link_finding(port),
            Err(e) => Some(Finding {
                severity: Severity::Error,
                issue: resolve_issue(e),
                message: e.to_string(),
            }),
        })
        .collect()
}

fn link_finding(port: &Port) -> Option<Finding> {
    let name = &port.interface.name;
    let (severity, issue, problem) = match port.interface.link_status() {
        LinkStatus::Up => return None,
        LinkStatus::AdminDown => (
            Severity::Warning,
            Issue::PortAdminDown,
            format!("interface is administratively down; bring it up with: ip link set {name} up"),
        ),
        LinkStatus::NoCarrier => (
            Severity::Warning,
            Issue::PortNoCarrier,
            "no carrier (link is down); check the cable and the device on the other end".to_owned(),
        ),
        LinkStatus::Unknown => (
            Severity::Note,
            Issue::PortStateUnreported,
            "link state is not reported by the driver".to_owned(),
        ),
        LinkStatus::Other(state) => (Severity::Warning, Issue::PortStateOther, format!("link state is {state}")),
    };
    Some(Finding {
        severity,
        issue,
        message: format!("{} ({name}): {problem}", port.role),
    })
}

fn check_environment(
    mode: Mode,
    forwarding: &dyn Forwarding,
    ports: &[Port],
    interfaces: &[Interface],
    routing: Result<&Ipv4Routing, &str>,
) -> Vec<Finding> {
    let checks = forwarding.check_environment(ports, interfaces, routing);
    print_environment(mode, &checks);
    let mut findings = env_findings(mode, &checks);
    findings.extend(note_findings(mode, &forwarding.notes(ports, routing)));
    findings
}

fn env_findings(mode: Mode, checks: &[EnvCheck]) -> Vec<Finding> {
    checks
        .iter()
        .filter_map(|check| match &check.state {
            EnvState::Met { .. } => None,
            EnvState::Unmet { problem, fix, .. } => Some(Finding {
                severity: match check.level {
                    Level::Required => Severity::Error,
                    Level::Awaited | Level::Recommended => Severity::Warning,
                },
                issue: check.issue,
                message: format!("{mode} mode: {problem}; {fix}"),
            }),
            EnvState::Unknown { reason } => Some(Finding {
                severity: Severity::Warning,
                issue: check.issue,
                message: format!("{mode} mode: cannot verify {}: {reason}", check.item),
            }),
        })
        .collect()
}

fn note_findings(mode: Mode, notes: &[Note]) -> Vec<Finding> {
    notes
        .iter()
        .map(|note| Finding {
            severity: Severity::Note,
            issue: note.issue,
            message: format!("{mode} mode: {}", note.text),
        })
        .collect()
}

fn print_environment(mode: Mode, checks: &[EnvCheck]) {
    out!("{:<36} {}", format!("{} MODE CHECK", mode.to_string().to_uppercase()), "RESULT");
    for check in checks {
        let result = match &check.state {
            EnvState::Met { actual } if actual.is_empty() => "ok".to_owned(),
            EnvState::Met { actual } => format!("ok ({actual})"),
            EnvState::Unmet { actual, .. } => format!("not met ({actual})"),
            EnvState::Unknown { .. } => "unknown".to_owned(),
        };
        out!("{:<36} {}", check.item, result);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct XdpRow {
    port: Port,
    native: Option<XdpFeatures>,
    hook: CoreHook,
}

async fn check_xdp(policy: XdpPolicy, ports: &[Port]) -> Vec<Finding> {
    let netdev = Netdev::connect();
    let mut error = None;
    let mut rows = Vec::new();
    for port in ports {
        let detected = match &netdev {
            Ok(netdev) => netdev.xdp_features(port.interface.index).await.map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        let native = match detected {
            Ok(features) => Some(features),
            Err(e) => {
                error.get_or_insert(e);
                None
            }
        };
        rows.push(XdpRow {
            port: port.clone(),
            native,
            hook: core_hook(policy, native),
        });
    }
    print_xdp(&rows);
    xdp_findings(policy, error.as_deref(), &rows)
}

fn xdp_findings(policy: XdpPolicy, detection_error: Option<&str>, rows: &[XdpRow]) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let (Some(e), XdpPolicy::Auto) = (detection_error, policy) {
        findings.push(Finding {
            severity: Severity::Warning,
            issue: Issue::XdpUndetected,
            message: format!("cannot detect native XDP support ({e}); the core program will use TC"),
        });
    }
    for row in rows {
        let (role, name) = (row.port.role, &row.port.interface.name);
        if let Some(XdpAttachment {
            mode: XdpMode::Generic,
            prog_id,
        }) = row.port.interface.xdp
        {
            let program = prog_id.map_or("a generic XDP program".to_owned(), |id| format!("generic XDP program {id}"));
            findings.push(Finding {
                severity: Severity::Warning,
                issue: Issue::XdpGenericAttached,
                message: format!(
                    "{role} ({name}): {program} is attached; generic XDP disables GRO on this interface and is slower \
                     than TC (detach it with: ip link set dev {name} xdpgeneric off)"
                ),
            });
        }
        if row.hook == CoreHook::GenericXdp {
            findings.push(Finding {
                severity: Severity::Warning,
                issue: Issue::XdpGenericConfigured,
                message: format!(
                    "{role} ({name}): xdp = \"generic\" makes the core program use generic XDP, which disables GRO \
                     on this interface; use \"auto\" to get native XDP or TC"
                ),
            });
        }
    }
    findings
}

fn print_xdp(rows: &[XdpRow]) {
    out!(
        "{:<4} {:<15} {:<10} {:<28} {:<18} {}",
        "ROLE", "INTERFACE", "DRIVER", "NATIVE XDP", "ATTACHED XDP", "CORE HOOK"
    );
    for row in rows {
        let iface = &row.port.interface;
        let native = match row.native {
            None => "unknown".to_owned(),
            Some(features) if features.0 == 0 => "no".to_owned(),
            Some(features) => features.to_string(),
        };
        let attached = match iface.xdp {
            None => "none".to_owned(),
            Some(XdpAttachment { mode, prog_id: None }) => mode.to_string(),
            Some(XdpAttachment { mode, prog_id: Some(id) }) => format!("{mode} (id {id})"),
        };
        out!(
            "{:<4} {:<15} {:<10} {:<28} {:<18} {}",
            row.port.role.to_string(),
            iface.name,
            iface.driver.as_deref().unwrap_or("-"),
            native,
            attached,
            row.hook
        );
    }
}

#[derive(Debug)]
struct TcxRow {
    port: Port,
    chain: Result<TcxChain, TcxQueryError>,
}

fn check_tcx(ports: &[Port]) -> Vec<Finding> {
    let rows: Vec<TcxRow> = ports
        .iter()
        .map(|port| TcxRow {
            port: port.clone(),
            chain: bpf::tcx_ingress(port.interface.index),
        })
        .collect();
    let any_program = rows.iter().any(|row| matches!(&row.chain, Ok(chain) if !chain.prog_ids.is_empty()));
    let names = if any_program { bpf::program_names().ok() } else { None };
    print_tcx(&rows, names.as_ref());
    tcx_findings(&rows, names.as_ref())
}

fn tcx_findings(rows: &[TcxRow], names: Option<&HashMap<u32, String>>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let errors: Vec<&TcxQueryError> = rows.iter().filter_map(|row| row.chain.as_ref().err()).collect();
    if errors.iter().any(|e| matches!(e, TcxQueryError::Unsupported)) {
        findings.push(Finding {
            severity: Severity::Warning,
            issue: Issue::TcxUnsupported,
            message: "the kernel has no TCX (it needs Linux 6.6 or later), so run cannot attach its core eBPF \
                      program (D001), which holds trust; every connection is inspected"
                .to_owned(),
        });
    } else if let Some(e) = errors.first() {
        findings.push(Finding {
            severity: Severity::Warning,
            issue: Issue::TcxUnchecked,
            message: format!("cannot list the TCX programs on the ports ({e}); run doctor as root to see them"),
        });
    }
    for row in rows {
        let Ok(chain) = &row.chain else { continue };
        if chain.prog_ids.is_empty() {
            continue;
        }
        let (role, name) = (row.port.role, &row.port.interface.name);
        let Some(names) = names else {
            findings.push(Finding {
                severity: Severity::Warning,
                issue: Issue::ForeignTcxPrograms,
                message: format!(
                    "{role} ({name}): TCX ingress has programs {}; without CAP_SYS_ADMIN doctor cannot tell which, if \
                     any, is wnc-gw's",
                    program_list(&chain.prog_ids, None)
                ),
            });
            continue;
        };
        let is_core = |id: &u32| names.get(id).map(String::as_str) == Some(CORE_PROGRAM_NAME);
        let before = chain.prog_ids.iter().position(is_core).map_or(&[][..], |at| &chain.prog_ids[..at]);
        if !before.is_empty() {
            findings.push(Finding {
                severity: Severity::Warning,
                issue: Issue::CoreProgramNotFirst,
                message: format!(
                    "{role} ({name}): {} run before wnc-gw's core eBPF program on TCX ingress and see every packet \
                     first",
                    program_list(before, Some(names))
                ),
            });
        }
        let after: Vec<u32> = chain.prog_ids[before.len()..].iter().copied().filter(|id| !is_core(id)).collect();
        if !after.is_empty() {
            findings.push(Finding {
                severity: Severity::Warning,
                issue: Issue::ForeignTcxPrograms,
                message: format!(
                    "{role} ({name}): TCX ingress has programs that wnc-gw did not load: {}; wnc-gw's core program \
                     runs before them",
                    program_list(&after, Some(names))
                ),
            });
        }
    }
    findings
}

fn program_list(ids: &[u32], names: Option<&HashMap<u32, String>>) -> String {
    let labels: Vec<String> = ids
        .iter()
        .map(|id| match names.and_then(|names| names.get(id)).filter(|name| !name.is_empty()) {
            Some(name) => format!("{id} ({name})"),
            None => id.to_string(),
        })
        .collect();
    labels.join(", ")
}

fn print_tcx(rows: &[TcxRow], names: Option<&HashMap<u32, String>>) {
    out!("{:<4} {:<15} {}", "ROLE", "INTERFACE", "TCX INGRESS (IN ORDER)");
    for row in rows {
        let programs = match &row.chain {
            Ok(chain) if chain.prog_ids.is_empty() => "none".to_owned(),
            Ok(chain) => program_list(&chain.prog_ids, names),
            Err(TcxQueryError::NotPermitted) => "not checked (needs CAP_NET_ADMIN)".to_owned(),
            Err(TcxQueryError::Unsupported) => "no tcx".to_owned(),
            Err(_) => "unknown".to_owned(),
        };
        out!("{:<4} {:<15} {}", row.port.role.to_string(), row.port.interface.name, programs);
    }
}

const REQUIRED_MODULES: &[RequiredModule] = &[
    RequiredModule {
        name: "nf_tables",
        purpose: "nftables rules",
        must_be_loaded: false,
    },
    RequiredModule {
        name: "nf_conntrack",
        purpose: "connection tracking",
        must_be_loaded: false,
    },
    RequiredModule {
        name: "nft_ct",
        purpose: "marking forwarded connections (ct mark)",
        must_be_loaded: false,
    },
    RequiredModule {
        name: "nf_conntrack_netlink",
        purpose: "reading forwarded connections from user space",
        must_be_loaded: false,
    },
];

const QUEUE_MODULES: &[RequiredModule] = &[
    RequiredModule {
        name: "nft_queue",
        purpose: "queueing packets to the IDS",
        must_be_loaded: false,
    },
    RequiredModule {
        name: "nfnetlink_queue",
        purpose: "passing queued packets to user space",
        must_be_loaded: false,
    },
];

const COPY_MODULES: &[RequiredModule] = &[
    RequiredModule {
        name: "nft_log",
        purpose: "copying packets to the IDS",
        must_be_loaded: false,
    },
    RequiredModule {
        name: "nfnetlink_log",
        purpose: "passing packet copies to user space",
        must_be_loaded: false,
    },
];

fn delivery_modules(delivery: Delivery) -> &'static [RequiredModule] {
    match delivery {
        Delivery::Queue(_) => QUEUE_MODULES,
        Delivery::Copy(_) => COPY_MODULES,
    }
}

fn check_modules(mode_modules: &[RequiredModule], delivery: Delivery) -> Vec<Finding> {
    let index = match ModuleIndex::load() {
        Ok(index) => index,
        Err(e) => {
            return vec![Finding {
                severity: Severity::Warning,
                issue: Issue::ModulesUnchecked,
                message: format!("could not check kernel modules: {e}"),
            }];
        }
    };
    let states: Vec<_> = REQUIRED_MODULES
        .iter()
        .chain(delivery_modules(delivery))
        .chain(mode_modules)
        .map(|module| (module, index.state(module.name)))
        .collect();
    print_modules(index.release(), &states);
    module_findings(index.release(), &states)
}

fn module_findings(release: &str, states: &[(&RequiredModule, ModuleState)]) -> Vec<Finding> {
    states
        .iter()
        .filter_map(|(module, state)| {
            let (severity, issue, message) = match state {
                ModuleState::Loaded | ModuleState::Builtin => return None,
                ModuleState::Loadable if !module.must_be_loaded => return None,
                ModuleState::Loadable => (
                    Severity::Error,
                    Issue::ModuleNotLoaded,
                    format!(
                        "kernel module {name} is not loaded (needed for {}) and the kernel does not load it on demand; \
                         load it with: modprobe {name}, and {}",
                        module.purpose,
                        Current.persist_module_hint(module.name),
                        name = module.name
                    ),
                ),
                ModuleState::Missing => (
                    Severity::Error,
                    Issue::ModuleMissing,
                    format!("kernel module {} is missing (needed for {})", module.name, module.purpose),
                ),
                ModuleState::Unknown => (
                    Severity::Warning,
                    Issue::ModuleUnverified,
                    format!(
                        "cannot verify kernel module {}: it is not loaded and /lib/modules/{release} is not readable",
                        module.name
                    ),
                ),
            };
            Some(Finding {
                severity,
                issue,
                message,
            })
        })
        .collect()
}

fn print_modules(release: &str, states: &[(&RequiredModule, ModuleState)]) {
    out!("kernel: {release}");
    out!("{:<20} {:<9} {}", "KERNEL MODULE", "STATE", "NEEDED FOR");
    for (module, state) in states {
        out!("{:<20} {:<9} {}", module.name, state.to_string(), module.purpose);
    }
}

async fn check_nft(path: &Setting<AbsolutePath>) -> Vec<Finding> {
    let nft = Nft::new(path.value.as_path());
    let info = nft.info().await;
    print_nft(path, &info);
    nft_finding(nft.path(), &info).into_iter().collect()
}

fn nft_finding(path: &Path, info: &Result<NftInfo, NftError>) -> Option<Finding> {
    const PURPOSE: &str = "needed for installing the gateway's nftables rules";
    let nft = path.display();
    let (severity, issue, message) = match info {
        Ok(NftInfo { json: Some(true), .. }) => return None,
        Ok(NftInfo { json: Some(false), .. }) => (
            Severity::Error,
            Issue::NftNoJson,
            format!("{nft} is built without JSON support ({PURPOSE}); install an nftables build with JSON support"),
        ),
        Ok(NftInfo { json: None, .. }) => (
            Severity::Warning,
            Issue::NftUnverified,
            format!("cannot verify JSON support of {nft}: nft -V does not report it"),
        ),
        Err(NftError::NotFound { .. }) => (
            Severity::Error,
            Issue::NftNotFound,
            format!("{nft} not found ({PURPOSE}); install nftables"),
        ),
        Err(e) => (Severity::Warning, Issue::NftUnverified, format!("could not check nft: {e}")),
    };
    Some(Finding {
        severity,
        issue,
        message,
    })
}

fn print_nft(path: &Setting<AbsolutePath>, info: &Result<NftInfo, NftError>) {
    let (version, json) = match info {
        Ok(info) => (
            info.version.as_deref().unwrap_or("unknown"),
            match info.json {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unknown",
            },
        ),
        Err(NftError::NotFound { .. }) => ("not found", "-"),
        Err(_) => ("unknown", "unknown"),
    };
    out!("{:<18} {:<12} {:<10} {}", "COMMAND", "SOURCE", "VERSION", "JSON");
    out!(
        "{:<18} {:<12} {version:<10} {json}",
        path.value.to_string(),
        path.source.to_string()
    );
}

async fn check_suricata(config: &Config) -> Vec<Finding> {
    let settings = &config.suricata;
    let suricata = Suricata::new(settings.path.value.as_path());
    let info = suricata.info().await;
    print_suricata(&settings.path, &info);
    let mut findings = suricata_findings(suricata.path(), &info, config.delivery());
    findings.extend(when_unavailable_finding(settings.when_unavailable.value, config.protection.value));
    findings.extend(protection_findings(config.protection.value));
    findings.push(spawned_finding());
    let mut alerts = None;
    let mut tcp_established_timeout = None;
    if info.is_ok() {
        out!();
        let yaml = settings.config.value.as_path();
        let dump = suricata.dump_config(yaml, &spawned::FORCED_SETTINGS).await;
        let rule_files = dump.as_ref().map(SuricataConfig::check_rule_files).unwrap_or_default();
        let log_dir = spawned::log_dir(Current.log_dir());
        let alert_file = dump.as_ref().ok().and_then(|dump| dump.alert_file(&log_dir));
        tcp_established_timeout = dump.as_ref().ok().and_then(|dump| dump.tcp_established_timeout);
        alerts = dump.as_ref().ok().map(|_| alert_file.is_some());
        print_suricata_config(settings, &dump, &rule_files, alert_file.as_deref());
        findings.extend(suricata_config_findings(yaml, &dump, &rule_files, alert_file.as_deref()));
    }
    let acct = sysctl::read(CONNTRACK_ACCT).map_err(|e| e.to_string());
    findings.extend(trust_findings(
        &config.trust,
        config.protection.value,
        alerts,
        acct,
        tcp_established_timeout,
    ));
    findings
}

async fn check_other_suricata(delivery: Delivery, check_boot: bool) -> Vec<Finding> {
    let scan = suricata::scan(&spawned::control_socket(Current.runtime_dir()));
    let service = Current.suricata_service();
    let boot = if check_boot {
        Some(Current.starts_at_boot(service).await)
    } else {
        None
    };
    print_other_suricata(&scan, service, boot.as_ref());
    other_suricata_findings(delivery, &scan, service, boot.as_ref())
}

fn other_suricata_findings(
    delivery: Delivery,
    scan: &io::Result<SuricataScan>,
    service: &str,
    boot: Option<&BootState>,
) -> Vec<Finding> {
    let warning = |issue: Issue, message: String| Finding {
        severity: Severity::Warning,
        issue,
        message,
    };
    let mut findings = Vec::new();
    let running = match scan {
        Ok(scan) => {
            if scan.others_hidden {
                findings.push(warning(
                    Issue::ProcessesHidden,
                    "could not see other users' processes (/proc is mounted with hidepid), so other suricata \
                     processes may be missing"
                        .to_owned(),
                ));
            }
            scan.running.as_slice()
        }
        Err(e) => {
            findings.push(warning(
                Issue::OtherSuricataUnchecked,
                format!("could not check for other suricata processes: {e}"),
            ));
            &[]
        }
    };
    let mut service_running = false;
    for other in running {
        let held = match (&other.capture, delivery) {
            (Capture::Nfq(queues), Delivery::Queue(queue)) if queues.iter().any(|q| q.overlaps(&queue)) => {
                Some(queue_list(queues))
            }
            _ => None,
        };
        let nflog_groups = match (&other.capture, delivery) {
            (Capture::Live("nflog"), Delivery::Copy(groups)) if other.same_net_ns != Some(false) => Some(groups),
            _ => None,
        };
        match other.owner {
            Owner::WncGw => continue,
            Owner::LeftByWncGw => {
                let held = match &held {
                    Some(queues) if other.same_net_ns != Some(false) => {
                        format!(" and holds NFQUEUE {queues}, so wnc-gw's suricata cannot bind it until it exits")
                    }
                    _ => String::new(),
                };
                findings.push(warning(
                    Issue::LeftoverSuricata,
                    format!(
                        "a suricata left by a previous wnc-gw (pid {pid}) is still running{held}; it should exit by \
                         itself shortly, otherwise stop it with: kill {pid}",
                        pid = other.pid
                    ),
                ));
                continue;
            }
            Owner::Other => {}
        }
        let unit = service_unit(other);
        let is_service = unit.as_deref() == Some(service);
        let who = match &unit {
            Some(unit) if is_service => format!("another suricata (pid {}, {unit})", other.pid),
            Some(unit) => format!("another suricata (pid {}, under {unit})", other.pid),
            None => format!("another suricata (pid {})", other.pid),
        };
        let stop = if is_service {
            Current.stop_service_hint(service)
        } else {
            format!("kill {}", other.pid)
        };
        let memory = other
            .rss_kb
            .map_or_else(|| "memory".to_owned(), |kb| format!("{} MB of memory", megabytes(kb)));
        let (severity, issue, message) = match (&other.capture, &held, other.same_net_ns) {
            _ if let Some(groups) = nflog_groups => (
                Severity::Warning,
                Issue::OtherSuricataOnNflog,
                format!(
                    "{who} is receiving packet copies over NFLOG; if it binds NFLOG group {groups}, which wnc-gw is \
                     configured to use (wnc-gw cannot tell which group it binds), wnc-gw's suricata cannot start until \
                     that one stops; stop it with: {stop}"
                ),
            ),
            (Capture::Nfq(_), Some(queues), Some(true)) => (
                Severity::Warning,
                Issue::OtherSuricataOnQueue,
                format!(
                    "{who} is running inline on NFQUEUE {queues}, which wnc-gw is configured to use; wnc-gw's \
                     suricata cannot bind it until that one stops (wnc-gw keeps retrying); stop it with: {stop}"
                ),
            ),
            (Capture::Nfq(_), Some(queues), None) => (
                Severity::Warning,
                Issue::OtherSuricataOnQueue,
                format!(
                    "{who} is running inline on NFQUEUE {queues}, which wnc-gw is configured to use; if it is in \
                     wnc-gw's network namespace (could not tell), wnc-gw's suricata cannot bind it until that one \
                     stops; stop it with: {stop}"
                ),
            ),
            (Capture::Nfq(queues), _, same_net_ns) => (
                Severity::Warning,
                Issue::OtherSuricataInline,
                format!(
                    "{who} is running inline on NFQUEUE {}{}; it competes with wnc-gw's suricata for CPU and uses \
                     {memory}; stop it with: {stop}",
                    queue_list(queues),
                    if same_net_ns == Some(false) { " in another network namespace" } else { "" }
                ),
            ),
            (Capture::Live(method), _, _) => (
                Severity::Warning,
                Issue::OtherSuricataLive,
                format!(
                    "{who} is capturing traffic ({method}) and inspects it separately from wnc-gw; it competes \
                     for CPU and uses {memory}; stop it with: {stop}"
                ),
            ),
            (Capture::File, _, _) => (
                Severity::Note,
                Issue::OtherSuricataPcap,
                format!("{who} is reading pcap files; it competes for CPU while it runs"),
            ),
            (Capture::Test, _, _) => (
                Severity::Note,
                Issue::OtherSuricataTest,
                format!("{who} is testing its configuration (suricata-update runs suricata -T); it exits by itself"),
            ),
            (Capture::Unknown, _, _) => (
                Severity::Warning,
                Issue::OtherSuricataUnknown,
                format!(
                    "{who} is running, but its command line does not show how it gets packets; it may compete \
                     with wnc-gw's suricata; stop it with: {stop}"
                ),
            ),
        };
        service_running |= is_service && !matches!(other.capture, Capture::File | Capture::Test);
        findings.push(Finding {
            severity,
            issue,
            message,
        });
    }
    match boot {
        Some(BootState::Enabled) if !service_running => findings.push(warning(
            Issue::SuricataServiceEnabled,
            format!(
                "{service} is enabled, so another suricata starts at boot; disable it with: {}",
                Current.disable_service_hint(service)
            ),
        )),
        Some(BootState::Unknown(reason)) => findings.push(warning(
            Issue::SuricataServiceUnchecked,
            format!("could not check whether {service} starts at boot: {reason}"),
        )),
        _ => {}
    }
    findings
}

fn service_unit(other: &RunningSuricata) -> Option<String> {
    other.cgroup.as_deref().and_then(|cgroup| Current.service_of(cgroup))
}

fn megabytes(kb: u64) -> u64 {
    (kb + 512) / 1024
}

fn queue_list(queues: &[QueueRange]) -> String {
    queues.iter().map(QueueRange::to_string).collect::<Vec<_>>().join(", ")
}

fn print_other_suricata(scan: &io::Result<SuricataScan>, service: &str, boot: Option<&BootState>) {
    out!(
        "{:<18} {:<14} {:<9} {:<8} {}",
        "RUNNING SURICATA", "CAPTURE", "RSS", "NETNS", "STARTED BY"
    );
    match scan {
        Ok(scan) if scan.running.is_empty() => out!("none"),
        Ok(scan) => {
            for s in &scan.running {
                let capture = match &s.capture {
                    Capture::Nfq(queues) => format!("nfq {}", queue_list(queues)),
                    Capture::Live(method) => (*method).to_owned(),
                    Capture::File => "pcap file".to_owned(),
                    Capture::Test => "test".to_owned(),
                    Capture::Unknown => "unknown".to_owned(),
                };
                let rss = s.rss_kb.map_or_else(|| "-".to_owned(), |kb| format!("{} MB", megabytes(kb)));
                let net_ns = match s.same_net_ns {
                    Some(true) => "same",
                    Some(false) => "other",
                    None => "unknown",
                };
                let started_by = match s.owner {
                    Owner::WncGw => "wnc-gw".to_owned(),
                    Owner::LeftByWncGw => "previous wnc-gw".to_owned(),
                    Owner::Other => service_unit(s).unwrap_or_else(|| "-".to_owned()),
                };
                out!("{:<18} {capture:<14} {rss:<9} {net_ns:<8} {started_by}", s.pid);
            }
        }
        Err(_) => out!("unknown"),
    }
    let at_boot = match boot {
        None => "not checked",
        Some(BootState::Enabled) => "enabled",
        Some(BootState::Disabled) => "disabled",
        Some(BootState::NotInstalled) => "not installed",
        Some(BootState::Unknown(_)) => "unknown",
    };
    out!("{:<18} {}", "SURICATA SERVICE", "AT BOOT");
    out!("{service:<18} {at_boot}");
}

fn suricata_findings(path: &Path, info: &Result<SuricataInfo, SuricataError>, delivery: Delivery) -> Vec<Finding> {
    let suricata = path.display();
    let info = match info {
        Ok(info) => info,
        Err(SuricataError::NotFound { .. }) => {
            return vec![Finding {
                severity: Severity::Error,
                issue: Issue::SuricataNotFound,
                message: format!("{suricata} not found (needed for inspecting traffic); install suricata"),
            }];
        }
        Err(e) => {
            return vec![Finding {
                severity: Severity::Warning,
                issue: Issue::SuricataUnchecked,
                message: format!("could not check suricata: {e}"),
            }];
        }
    };
    let mut findings = Vec::new();
    let (support, name, needed_for) = match delivery {
        Delivery::Queue(_) => (info.nfqueue, "NFQueue", "receiving the packets the gateway queues"),
        Delivery::Copy(_) => (info.nflog, "NFLOG", "receiving the packet copies the gateway sends"),
    };
    match support {
        Some(true) => {}
        Some(false) => findings.push(Finding {
            severity: Severity::Error,
            issue: Issue::SuricataNoCapture,
            message: format!(
                "{suricata} is built without {name} support (needed for {needed_for}); \
                 install a suricata build with {name} support"
            ),
        }),
        None => findings.push(Finding {
            severity: Severity::Warning,
            issue: Issue::SuricataNoCapture,
            message: format!("cannot verify {name} support of {suricata}: --build-info does not report it"),
        }),
    }
    match info.ready_notify {
        Some(true) => {}
        Some(false) => findings.push(Finding {
            severity: Severity::Error,
            issue: Issue::SuricataNoSystemd,
            message: format!(
                "{suricata} is built without systemd support (needed for the readiness notification the gateway \
                 waits for before sending it packets); install a suricata build with systemd support"
            ),
        }),
        None => findings.push(Finding {
            severity: Severity::Warning,
            issue: Issue::SuricataNoSystemd,
            message: format!(
                "cannot verify systemd support of {suricata} (needed for the readiness notification): \
                 --build-info does not report it (Suricata 8.0 and later do)"
            ),
        }),
    }
    findings
}

fn spawned_finding() -> Finding {
    Finding {
        severity: Severity::Warning,
        issue: Issue::SuricataSpawned,
        message: "suricata is started by wnc-gw and shares its account and privileges, so a compromised suricata \
                  can do whatever the gateway can"
            .to_owned(),
    }
}

fn when_unavailable_finding(when_unavailable: WhenUnavailable, protection: Protection) -> Option<Finding> {
    // ids 時跟不上不受 when_unavailable 影響，另外由 protection_findings 說明
    let when = match protection {
        Protection::Ips => "starts, restarts or falls behind",
        Protection::Ids => "starts or restarts",
    };
    match when_unavailable {
        WhenUnavailable::Accept => Some(Finding {
            severity: Severity::Warning,
            issue: Issue::AcceptWhenUnavailable,
            message: format!(
                "forwarded traffic passes without inspection while suricata {when} (when_unavailable = \"accept\"); \
                 set when_unavailable = \"drop\" to drop it instead"
            ),
        }),
        WhenUnavailable::Drop => None,
    }
}

fn protection_findings(protection: Protection) -> Vec<Finding> {
    if protection == Protection::Ips {
        return Vec::new();
    }
    [
        (
            Issue::IdsNoBlocking,
            "protection = \"ids\": suricata only gets copies of forwarded packets, so no detection blocks traffic; \
         set protection = \"ips\" to make packets wait for suricata's verdict",
        ),
        (
            Issue::IdsNoChecksum,
            "protection = \"ids\": suricata does not validate checksums, because packets merged by GRO reach it with \
         incomplete ones; it also inspects packets that the receiving host drops for a bad checksum, which an \
         attacker can use to hide data from inspection; protection = \"ips\" does not have this limitation",
        ),
        (
            Issue::IdsCopiesDropped,
            "protection = \"ids\": traffic that arrives faster than suricata takes the copies is forwarded without \
         inspection, whichever when_unavailable is set",
        ),
    ]
    .into_iter()
    .map(|(issue, message)| Finding {
        severity: Severity::Warning,
        issue,
        message: message.to_owned(),
    })
    .collect()
}

fn print_suricata(path: &Setting<AbsolutePath>, info: &Result<SuricataInfo, SuricataError>) {
    let yes_no = |value: Option<bool>| match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    };
    let (version, nfqueue, nflog, ready_notify) = match info {
        Ok(info) => (
            info.version.as_deref().unwrap_or("unknown"),
            yes_no(info.nfqueue),
            yes_no(info.nflog),
            yes_no(info.ready_notify),
        ),
        Err(SuricataError::NotFound { .. }) => ("not found", "-", "-", "-"),
        Err(_) => ("unknown", "unknown", "unknown", "unknown"),
    };
    out!(
        "{:<18} {:<12} {:<10} {:<8} {:<8} {}",
        "COMMAND", "SOURCE", "VERSION", "NFQUEUE", "NFLOG", "READY NOTIFY"
    );
    out!(
        "{:<18} {:<12} {version:<10} {nfqueue:<8} {nflog:<8} {ready_notify}",
        path.value.to_string(),
        path.source.to_string()
    );
}

const CONNTRACK_ACCT: &str = "net.netfilter.nf_conntrack_acct";

fn trust_summary(trust: &TrustSettings) -> String {
    let trust = match trust {
        TrustSettings::Manual { source } => return format!("manual (wnc-gw trust) ({source})"),
        TrustSettings::Auto(auto) => auto,
    };
    format!(
        "automatic after {} packets each way and {} s, for {} s; checked every {} s ({})",
        trust.min_packets.value,
        trust.min_age.value.as_secs(),
        trust.ttl.value.as_secs(),
        trust.check_interval.value.as_secs(),
        trust.source
    )
}

fn trust_findings(
    trust: &TrustSettings,
    protection: Protection,
    alerts: Option<bool>,
    acct: Result<Option<String>, String>,
    tcp_established_timeout: Option<u64>,
) -> Vec<Finding> {
    let trust: &AutoTrust = match trust {
        TrustSettings::Manual { .. } => return Vec::new(),
        TrustSettings::Auto(auto) => auto,
    };
    let ttl = trust.ttl.value.as_secs();
    let mut findings = vec![Finding {
        severity: Severity::Warning,
        issue: Issue::AutoTrust,
        message: format!(
            "automatic trust is on: a connection that carries {} packets each way, for at least {} s and without \
             a suricata alert, skips inspection for {ttl} s except for syn/fin/rst; an attack sent after that is \
             not seen until the trust expires",
            trust.min_packets.value,
            trust.min_age.value.as_secs()
        ),
    }];
    if alerts.is_none() {
        findings.push(Finding {
            severity: Severity::Warning,
            issue: Issue::AutoTrustOff,
            message: "cannot verify that suricata writes alerts, because its config could not be checked; if run \
                      cannot find them either, it starts with automatic trust off and inspects every connection"
                .to_owned(),
        });
    }
    if alerts == Some(false) {
        findings.push(Finding {
            severity: Severity::Error,
            issue: Issue::AutoTrustNoAlerts,
            message: "automatic trust needs suricata's alerts in an EVE file; without them, connections that raise \
                      alerts would be trusted too"
                .to_owned(),
        });
    }
    match acct {
        Ok(Some(value)) if value == "1" => {}
        Ok(Some(value)) => findings.push(Finding {
            severity: Severity::Error,
            issue: Issue::ConntrackAcct,
            message: format!(
                "automatic trust needs {CONNTRACK_ACCT} = 1 to count each connection's packets, but it is {value}; \
                 set it with: sysctl -w {CONNTRACK_ACCT}=1, and {}",
                Current.persist_sysctl_hint(CONNTRACK_ACCT, "1")
            ),
        }),
        Ok(None) => findings.push(Finding {
            severity: Severity::Warning,
            issue: Issue::ConntrackAcct,
            message: format!(
                "cannot verify {CONNTRACK_ACCT} because nf_conntrack is not loaded yet; automatic trust needs it set \
                 to 1 (sysctl -w {CONNTRACK_ACCT}=1 once the module is loaded)"
            ),
        }),
        Err(e) => findings.push(Finding {
            severity: Severity::Warning,
            issue: Issue::ConntrackAcct,
            message: format!("cannot verify {CONNTRACK_ACCT}: {e}; automatic trust needs it set to 1"),
        }),
    }
    if protection == Protection::Ips
        && let Some(established) = tcp_established_timeout
        && ttl <= established
    {
        findings.push(Finding {
            severity: Severity::Warning,
            issue: Issue::TrustTtlTooShort,
            message: format!(
                "trust ttl ({ttl} s) is not longer than suricata's flow-timeouts.tcp.established ({established} s): \
                 when trust ends suricata may still hold the connection's old state and drop its packets as out of \
                 sync; set [trust] ttl above {established}"
            ),
        });
    }
    findings
}

fn suricata_config_findings(
    config: &Path,
    dump: &Result<SuricataConfig, SuricataError>,
    rule_files: &[RuleFile],
    alert_file: Option<&Path>,
) -> Vec<Finding> {
    let mut findings = rule_file_findings(config, dump, rule_files);
    if dump.is_ok() && alert_file.is_none() {
        findings.push(Finding {
            severity: Severity::Warning,
            issue: Issue::NoAlertOutput,
            message: format!(
                "suricata does not write alerts to a regular EVE file, so wnc-gw cannot see alerts; enable an \
                 eve-log output with filetype: regular and alert in its types in {}",
                config.display()
            ),
        });
    }
    findings
}

fn rule_file_findings(
    config: &Path,
    dump: &Result<SuricataConfig, SuricataError>,
    rule_files: &[RuleFile],
) -> Vec<Finding> {
    let config = config.display();
    match dump {
        Ok(_) => {}
        Err(SuricataError::Failed { stderr, .. }) => {
            return vec![Finding {
                severity: Severity::Error,
                issue: Issue::SuricataConfigUnloadable,
                message: format!("suricata cannot load {config}: {}", suricata_errors(stderr)),
            }];
        }
        Err(e) => {
            return vec![Finding {
                severity: Severity::Warning,
                issue: Issue::SuricataConfigUnloadable,
                message: format!("could not check {config}: {e}"),
            }];
        }
    }
    let fix = format!("download rules (for example with suricata-update) or set rule-files in {config}");
    if rule_files.is_empty() {
        return vec![Finding {
            severity: Severity::Error,
            issue: Issue::NoRules,
            message: format!("suricata has no rules to load: rule-files is empty; {fix}"),
        }];
    }
    let usable = rule_files.iter().any(|f| matches!(f.state, RuleFileState::HasRules));
    let unknown = rule_files.iter().any(|f| {
        matches!(
            f.state,
            RuleFileState::Unreadable(_) | RuleFileState::Wildcard | RuleFileState::NoRulePath
        )
    });
    if !usable && !unknown {
        let problems: Vec<String> = rule_files.iter().filter_map(rule_file_problem).collect();
        return vec![Finding {
            severity: Severity::Error,
            issue: Issue::NoRules,
            message: format!("suricata has no rules to load: {}; {fix}", problems.join(", ")),
        }];
    }
    rule_files
        .iter()
        .filter_map(|file| {
            let message = match &file.state {
                RuleFileState::HasRules => return None,
                RuleFileState::Missing | RuleFileState::NoRules => format!("rule file {}", rule_file_problem(file)?),
                RuleFileState::Unreadable(e) => format!("cannot read rule file {}: {e}", rule_file_name(file)),
                RuleFileState::Wildcard => {
                    format!("cannot verify rule files {}: wildcard patterns are not checked", file.entry)
                }
                RuleFileState::NoRulePath => {
                    format!("cannot verify rule file {}: default-rule-path is not set in {config}", file.entry)
                }
            };
            Some(Finding {
                severity: Severity::Warning,
                issue: Issue::RuleFileProblem,
                message,
            })
        })
        .collect()
}

fn rule_file_problem(file: &RuleFile) -> Option<String> {
    let name = rule_file_name(file);
    match file.state {
        RuleFileState::Missing => Some(format!("{name} does not exist")),
        RuleFileState::NoRules => Some(format!("{name} contains no rules")),
        _ => None,
    }
}

fn rule_file_name(file: &RuleFile) -> String {
    file.path
        .as_ref()
        .map_or_else(|| file.entry.clone(), |path| path.display().to_string())
}

fn suricata_errors(stderr: &str) -> String {
    stderr
        .lines()
        .map(|line| line.strip_prefix("Error: ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("; ")
}

fn print_suricata_config(
    settings: &SuricataSettings,
    dump: &Result<SuricataConfig, SuricataError>,
    rule_files: &[RuleFile],
    alert_file: Option<&Path>,
) {
    let config = &settings.config;
    let result = match dump {
        Ok(_) => "ok",
        Err(SuricataError::Failed { .. }) => "error",
        Err(_) => "unknown",
    };
    out!("{:<40} {:<12} {}", "SURICATA CONFIG", "SOURCE", "RESULT");
    out!(
        "{:<40} {:<12} {result}",
        config.value.to_string(),
        config.source.to_string()
    );
    for file in rule_files {
        let result = match file.state {
            RuleFileState::HasRules => "ok",
            RuleFileState::NoRules => "no rules",
            RuleFileState::Missing => "missing",
            RuleFileState::Unreadable(_) => "unreadable",
            RuleFileState::Wildcard | RuleFileState::NoRulePath => "not checked",
        };
        out!("{:<40} {:<12} {result}", rule_file_name(file), "rule-files");
    }
    if dump.is_ok() {
        match alert_file {
            Some(path) => out!(
                "{:<40} {:<12} alerts, read every {} ({})",
                path.display().to_string(),
                "eve-log",
                settings.eve_interval.value,
                settings.eve_interval.source
            ),
            None => out!("{:<40} {:<12} no alerts", "(none)", "eve-log"),
        }
    }
}

struct AccessRow {
    path: PathBuf,
    used_as: &'static str,
    writers: io::Result<Vec<(Writable, Option<String>)>>,
}

fn check_access(config: &Config) -> Vec<Finding> {
    let mut files: Vec<(&Path, &'static str)> = Vec::new();
    if let Some(file) = &config.file {
        files.push((file, "wnc-gw config file"));
    }
    files.push((config.nftables.path.value.as_path(), "nft command"));
    files.push((config.suricata.path.value.as_path(), "suricata command"));
    files.push((config.suricata.config.value.as_path(), "suricata config file"));
    let rows: Vec<AccessRow> = files
        .into_iter()
        .map(|(path, used_as)| AccessRow {
            path: path.to_path_buf(),
            used_as,
            writers: access::non_root_writers(path).map(|writers| {
                writers
                    .into_iter()
                    .map(|writable| {
                        let name = match writable.writer {
                            Writer::User(uid) => access::user_name(uid),
                            Writer::Group(gid) => access::group_name(gid),
                            Writer::Everyone => None,
                        };
                        (writable, name)
                    })
                    .collect()
            }),
        })
        .collect();
    print_access(&rows);
    access_findings(&rows)
}

fn access_findings(rows: &[AccessRow]) -> Vec<Finding> {
    rows.iter()
        .filter_map(|row| {
            let path = row.path.display();
            let (issue, message) = match &row.writers {
                Ok(writers) if writers.is_empty() => return None,
                Ok(writers) => (
                    Issue::WritableByNonRoot,
                    format!(
                    "{} {path} can be modified without root ({}), so those accounts could make the gateway run \
                     code with its privileges",
                    row.used_as,
                        describe_writers(writers)
                    ),
                ),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
                Err(e) => (Issue::AccessUnchecked, format!("could not check who can modify {path}: {e}")),
            };
            Some(Finding {
                severity: Severity::Warning,
                issue,
                message,
            })
        })
        .collect()
}

fn describe_writers(writers: &[(Writable, Option<String>)]) -> String {
    let mut groups: Vec<(Writer, &Option<String>, Vec<String>)> = Vec::new();
    for (writable, name) in writers {
        let path = writable.path.display().to_string();
        match groups.iter_mut().find(|(writer, _, _)| *writer == writable.writer) {
            Some((_, _, paths)) => paths.push(path),
            None => groups.push((writable.writer, name, vec![path])),
        }
    }
    groups
        .into_iter()
        .map(|(writer, name, paths)| {
            let paths = paths.join(", ");
            match writer {
                Writer::User(uid) => format!("user {} owns {paths}", name.clone().unwrap_or(uid.to_string())),
                Writer::Group(gid) => format!("group {} can write to {paths}", name.clone().unwrap_or(gid.to_string())),
                Writer::Everyone => format!("everyone can write to {paths}"),
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn print_access(rows: &[AccessRow]) {
    out!("{:<40} {:<22} {}", "FILE", "USED AS", "MODIFIABLE BY NON-ROOT");
    for row in rows {
        let result = match &row.writers {
            Ok(writers) if writers.is_empty() => "no",
            Ok(_) => "yes",
            Err(e) if e.kind() == io::ErrorKind::NotFound => "not found",
            Err(_) => "unknown",
        };
        out!("{:<40} {:<22} {result}", row.path.display().to_string(), row.used_as);
    }
}

fn print_ports(config: &Config, results: &[Result<Port, ResolveError>]) {
    out!(
        "{:<4} {:<17} {:<12} {:<15} {:<4} {:<13} {:<5} {}",
        "ROLE", "SPECIFIED", "SOURCE", "INTERFACE", "IDX", "MATCHED BY", "ADMIN", "OPER"
    );
    for ((role, setting), result) in config.ports().into_iter().zip(results) {
        let (name, index, matched_by, admin, oper) = match result {
            Ok(port) => (
                port.interface.name.clone(),
                port.interface.index.to_string(),
                port.matched_by.to_string(),
                if port.interface.admin_up { "up" } else { "down" }.to_owned(),
                port.interface.oper_state.to_string(),
            ),
            Err(_) => Default::default(),
        };
        let dash = |s: String| if s.is_empty() { "-".to_owned() } else { s };
        out!(
            "{:<4} {:<17} {:<12} {:<15} {:<4} {:<13} {:<5} {}",
            role.to_string(),
            setting.value.to_string(),
            setting.source.to_string(),
            dash(name),
            dash(index),
            dash(matched_by),
            dash(admin),
            dash(oper),
        );
    }
}

#[cfg(test)]
#[path = "../../tests/unit/cli/doctor.rs"]
mod tests;
