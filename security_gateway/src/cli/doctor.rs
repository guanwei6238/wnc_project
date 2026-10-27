use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use security_gateway::access::{self, Writable, Writer};
use security_gateway::config::{self, AbsolutePath, Config, Overrides, Setting, SuricataSettings};
use security_gateway::datapath::{CoreHook, XdpPolicy, core_hook};
use security_gateway::firewall::WhenUnavailable;
use security_gateway::forwarding::{self, EnvCheck, EnvState, Forwarding, Level, Mode};
use security_gateway::ids::spawned;
use security_gateway::ids::suricata::{
    self, Capture, Owner, RuleFile, RuleFileState, RunningSuricata, Suricata, SuricataConfig, SuricataError,
    SuricataInfo, SuricataScan,
};
use security_gateway::kernel::modules::{ModuleIndex, ModuleState, RequiredModule};
use security_gateway::kernel::netdev::{Netdev, XdpFeatures};
use security_gateway::kernel::netif::{Interface, LinkStatus, NetifError, Netlink, XdpAttachment, XdpMode};
use security_gateway::kernel::nfqueue::QueueRange;
use security_gateway::kernel::nft::{Nft, NftError, NftInfo};
use security_gateway::platform::{BootConfig, BootState, Current, Dirs, Services};
use security_gateway::ports::{self, Port, ResolveError};

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
    message: String,
}

impl Finding {
    fn print(&self) {
        let label = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Note => "note",
        };
        println!("{label}: {}", self.message);
    }
}

pub async fn run(config_path: Option<&Path>, overrides: Overrides, _args: DoctorArgs) -> ExitCode {
    let config = match config::load(config_path, overrides) {
        Ok(config) => config,
        Err(e) => {
            Finding {
                severity: Severity::Error,
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
        Some(path) => println!("config: {}", path.display()),
        None => println!("config: none ({} not found)", config::DEFAULT_PATH),
    }
    println!("mode:   {} ({})", config.mode.value, config.mode.source);
    println!("xdp:    {} ({})", config.xdp.value, config.xdp.source);
    println!();

    let interfaces = match load_interfaces().await {
        Ok(interfaces) => interfaces,
        Err(e) => {
            eprintln!("error: {e}");
            return false;
        }
    };
    let results = ports::resolve(&config.port_specs(), &interfaces);
    print_ports(config, &results);
    let mut findings = port_findings(&results);
    println!();

    let mode = config.mode.value;
    let forwarding = forwarding::for_mode(mode);
    let ports: Vec<Port> = results.iter().filter_map(|r| r.as_ref().ok().cloned()).collect();
    findings.extend(check_environment(mode, forwarding.as_ref(), &ports, &interfaces));
    println!();

    findings.extend(check_xdp(config.xdp.value, &ports).await);
    println!();

    findings.extend(check_modules(forwarding.required_modules()));
    println!();

    findings.extend(check_nft(&config.nftables.path).await);
    println!();

    findings.extend(check_suricata(&config.suricata).await);
    println!();

    findings.extend(check_other_suricata(config.suricata.queue.value, !starting).await);
    println!();

    findings.extend(check_access(config));

    if !findings.is_empty() {
        println!();
    }
    for finding in &findings {
        finding.print();
    }
    !findings.iter().any(|f| f.severity == Severity::Error)
}

fn port_findings(results: &[Result<Port, ResolveError>]) -> Vec<Finding> {
    results
        .iter()
        .filter_map(|result| match result {
            Ok(port) => link_finding(port),
            Err(e) => Some(Finding {
                severity: Severity::Error,
                message: e.to_string(),
            }),
        })
        .collect()
}

fn link_finding(port: &Port) -> Option<Finding> {
    let name = &port.interface.name;
    let (severity, problem) = match port.interface.link_status() {
        LinkStatus::Up => return None,
        LinkStatus::AdminDown => (
            Severity::Warning,
            format!("interface is administratively down; bring it up with: ip link set {name} up"),
        ),
        LinkStatus::NoCarrier => (
            Severity::Warning,
            "no carrier (link is down); check the cable and the device on the other end".to_owned(),
        ),
        LinkStatus::Unknown => (
            Severity::Note,
            "link state is not reported by the driver".to_owned(),
        ),
        LinkStatus::Other(state) => (Severity::Warning, format!("link state is {state}")),
    };
    Some(Finding {
        severity,
        message: format!("{} ({name}): {problem}", port.role),
    })
}

fn check_environment(
    mode: Mode,
    forwarding: &dyn Forwarding,
    ports: &[Port],
    interfaces: &[Interface],
) -> Vec<Finding> {
    let checks = forwarding.check_environment(ports, interfaces);
    print_environment(mode, &checks);
    env_findings(mode, &checks)
}

fn env_findings(mode: Mode, checks: &[EnvCheck]) -> Vec<Finding> {
    checks
        .iter()
        .filter_map(|check| match &check.state {
            EnvState::Met { .. } => None,
            EnvState::Unmet { problem, fix, .. } => Some(Finding {
                severity: match check.level {
                    Level::Required => Severity::Error,
                    Level::Recommended => Severity::Warning,
                },
                message: format!("{mode} mode: {problem}; {fix}"),
            }),
            EnvState::Unknown { reason } => Some(Finding {
                severity: Severity::Warning,
                message: format!("{mode} mode: cannot verify {}: {reason}", check.item),
            }),
        })
        .collect()
}

fn print_environment(mode: Mode, checks: &[EnvCheck]) {
    println!("{:<36} {}", format!("{} MODE CHECK", mode.to_string().to_uppercase()), "RESULT");
    for check in checks {
        let result = match &check.state {
            EnvState::Met { actual } if actual.is_empty() => "ok".to_owned(),
            EnvState::Met { actual } => format!("ok ({actual})"),
            EnvState::Unmet { actual, .. } => format!("not met ({actual})"),
            EnvState::Unknown { .. } => "unknown".to_owned(),
        };
        println!("{:<36} {}", check.item, result);
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
                message: format!(
                    "{role} ({name}): {program} is attached; generic XDP disables GRO on this interface and is slower \
                     than TC (detach it with: ip link set dev {name} xdpgeneric off)"
                ),
            });
        }
        if row.hook == CoreHook::GenericXdp {
            findings.push(Finding {
                severity: Severity::Warning,
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
    println!(
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
        println!(
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

const REQUIRED_MODULES: &[RequiredModule] = &[
    RequiredModule {
        name: "nf_tables",
        purpose: "nftables rules",
        must_be_loaded: false,
    },
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
    RequiredModule {
        name: "nf_conntrack",
        purpose: "connection tracking",
        must_be_loaded: false,
    },
    RequiredModule {
        name: "nft_ct",
        purpose: "matching and setting ct mark",
        must_be_loaded: false,
    },
];

fn check_modules(mode_modules: &[RequiredModule]) -> Vec<Finding> {
    let index = match ModuleIndex::load() {
        Ok(index) => index,
        Err(e) => {
            return vec![Finding {
                severity: Severity::Warning,
                message: format!("could not check kernel modules: {e}"),
            }];
        }
    };
    let states: Vec<_> = REQUIRED_MODULES
        .iter()
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
            let (severity, message) = match state {
                ModuleState::Loaded | ModuleState::Builtin => return None,
                ModuleState::Loadable if !module.must_be_loaded => return None,
                ModuleState::Loadable => (
                    Severity::Error,
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
                    format!("kernel module {} is missing (needed for {})", module.name, module.purpose),
                ),
                ModuleState::Unknown => (
                    Severity::Warning,
                    format!(
                        "cannot verify kernel module {}: it is not loaded and /lib/modules/{release} is not readable",
                        module.name
                    ),
                ),
            };
            Some(Finding { severity, message })
        })
        .collect()
}

fn print_modules(release: &str, states: &[(&RequiredModule, ModuleState)]) {
    println!("kernel: {release}");
    println!("{:<16} {:<9} {}", "KERNEL MODULE", "STATE", "NEEDED FOR");
    for (module, state) in states {
        println!("{:<16} {:<9} {}", module.name, state.to_string(), module.purpose);
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
    let (severity, message) = match info {
        Ok(NftInfo { json: Some(true), .. }) => return None,
        Ok(NftInfo { json: Some(false), .. }) => (
            Severity::Error,
            format!("{nft} is built without JSON support ({PURPOSE}); install an nftables build with JSON support"),
        ),
        Ok(NftInfo { json: None, .. }) => (
            Severity::Warning,
            format!("cannot verify JSON support of {nft}: nft -V does not report it"),
        ),
        Err(NftError::NotFound { .. }) => (Severity::Error, format!("{nft} not found ({PURPOSE}); install nftables")),
        Err(e) => (Severity::Warning, format!("could not check nft: {e}")),
    };
    Some(Finding { severity, message })
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
    println!("{:<18} {:<12} {:<10} {}", "COMMAND", "SOURCE", "VERSION", "JSON");
    println!(
        "{:<18} {:<12} {version:<10} {json}",
        path.value.to_string(),
        path.source.to_string()
    );
}

async fn check_suricata(settings: &SuricataSettings) -> Vec<Finding> {
    let suricata = Suricata::new(settings.path.value.as_path());
    let info = suricata.info().await;
    print_suricata(&settings.path, &info);
    let mut findings = suricata_findings(suricata.path(), &info);
    findings.extend(when_unavailable_finding(settings.when_unavailable.value));
    if info.is_ok() {
        findings.push(spawned_finding());
        println!();
        let config = settings.config.value.as_path();
        let dump = suricata.dump_config(config, &spawned::FORCED_SETTINGS).await;
        let rule_files = dump.as_ref().map(SuricataConfig::check_rule_files).unwrap_or_default();
        print_suricata_config(&settings.config, &dump, &rule_files);
        findings.extend(suricata_config_findings(config, &dump, &rule_files));
    }
    findings
}

async fn check_other_suricata(queue: QueueRange, check_boot: bool) -> Vec<Finding> {
    let scan = suricata::scan(&spawned::control_socket(Current.runtime_dir()));
    let service = Current.suricata_service();
    let boot = if check_boot {
        Some(Current.starts_at_boot(service).await)
    } else {
        None
    };
    print_other_suricata(&scan, service, boot.as_ref());
    other_suricata_findings(queue, &scan, service, boot.as_ref())
}

fn other_suricata_findings(
    queue: QueueRange,
    scan: &io::Result<SuricataScan>,
    service: &str,
    boot: Option<&BootState>,
) -> Vec<Finding> {
    let warning = |message: String| Finding {
        severity: Severity::Warning,
        message,
    };
    let mut findings = Vec::new();
    let running = match scan {
        Ok(scan) => {
            if scan.others_hidden {
                findings.push(warning(
                    "could not see other users' processes (/proc is mounted with hidepid), so other suricata \
                     processes may be missing"
                        .to_owned(),
                ));
            }
            scan.running.as_slice()
        }
        Err(e) => {
            findings.push(warning(format!("could not check for other suricata processes: {e}")));
            &[]
        }
    };
    let mut service_running = false;
    for other in running {
        let held = match &other.capture {
            Capture::Nfq(queues) if queues.iter().any(|q| q.overlaps(&queue)) => Some(queue_list(queues)),
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
                findings.push(warning(format!(
                    "a suricata left by a previous wnc-gw (pid {pid}) is still running{held}; it should exit by itself \
                     shortly, otherwise stop it with: kill {pid}",
                    pid = other.pid
                )));
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
        let (severity, message) = match (&other.capture, &held, other.same_net_ns) {
            (Capture::Nfq(_), Some(queues), Some(true)) => (
                Severity::Warning,
                format!(
                    "{who} is running inline on NFQUEUE {queues}, which wnc-gw is configured to use; wnc-gw's \
                     suricata cannot bind it until that one stops (wnc-gw keeps retrying); stop it with: {stop}"
                ),
            ),
            (Capture::Nfq(_), Some(queues), None) => (
                Severity::Warning,
                format!(
                    "{who} is running inline on NFQUEUE {queues}, which wnc-gw is configured to use; if it is in \
                     wnc-gw's network namespace (could not tell), wnc-gw's suricata cannot bind it until that one \
                     stops; stop it with: {stop}"
                ),
            ),
            (Capture::Nfq(queues), _, same_net_ns) => (
                Severity::Warning,
                format!(
                    "{who} is running inline on NFQUEUE {}{}; it competes with wnc-gw's suricata for CPU and uses \
                     {memory}; stop it with: {stop}",
                    queue_list(queues),
                    if same_net_ns == Some(false) { " in another network namespace" } else { "" }
                ),
            ),
            (Capture::Live(method), _, _) => (
                Severity::Warning,
                format!(
                    "{who} is capturing traffic ({method}) and inspects it separately from wnc-gw; it competes \
                     for CPU and uses {memory}; stop it with: {stop}"
                ),
            ),
            (Capture::File, _, _) => (
                Severity::Note,
                format!("{who} is reading pcap files; it competes for CPU while it runs"),
            ),
            (Capture::Test, _, _) => (
                Severity::Note,
                format!("{who} is testing its configuration (suricata-update runs suricata -T); it exits by itself"),
            ),
            (Capture::Unknown, _, _) => (
                Severity::Warning,
                format!(
                    "{who} is running, but its command line does not show how it gets packets; it may compete \
                     with wnc-gw's suricata; stop it with: {stop}"
                ),
            ),
        };
        service_running |= is_service && !matches!(other.capture, Capture::File | Capture::Test);
        findings.push(Finding { severity, message });
    }
    match boot {
        Some(BootState::Enabled) if !service_running => findings.push(warning(format!(
            "{service} is enabled, so another suricata starts at boot; disable it with: {}",
            Current.disable_service_hint(service)
        ))),
        Some(BootState::Unknown(reason)) => {
            findings.push(warning(format!("could not check whether {service} starts at boot: {reason}")))
        }
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
    println!(
        "{:<18} {:<14} {:<9} {:<8} {}",
        "RUNNING SURICATA", "CAPTURE", "RSS", "NETNS", "STARTED BY"
    );
    match scan {
        Ok(scan) if scan.running.is_empty() => println!("none"),
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
                println!("{:<18} {capture:<14} {rss:<9} {net_ns:<8} {started_by}", s.pid);
            }
        }
        Err(_) => println!("unknown"),
    }
    let at_boot = match boot {
        None => "not checked",
        Some(BootState::Enabled) => "enabled",
        Some(BootState::Disabled) => "disabled",
        Some(BootState::NotInstalled) => "not installed",
        Some(BootState::Unknown(_)) => "unknown",
    };
    println!("{:<18} {}", "SURICATA SERVICE", "AT BOOT");
    println!("{service:<18} {at_boot}");
}

fn suricata_findings(path: &Path, info: &Result<SuricataInfo, SuricataError>) -> Vec<Finding> {
    let suricata = path.display();
    let info = match info {
        Ok(info) => info,
        Err(SuricataError::NotFound { .. }) => {
            return vec![Finding {
                severity: Severity::Error,
                message: format!("{suricata} not found (needed for inspecting traffic); install suricata"),
            }];
        }
        Err(e) => {
            return vec![Finding {
                severity: Severity::Warning,
                message: format!("could not check suricata: {e}"),
            }];
        }
    };
    let mut findings = Vec::new();
    match info.nfqueue {
        Some(true) => {}
        Some(false) => findings.push(Finding {
            severity: Severity::Error,
            message: format!(
                "{suricata} is built without NFQueue support (needed for receiving the packets the gateway queues); \
                 install a suricata build with NFQueue support"
            ),
        }),
        None => findings.push(Finding {
            severity: Severity::Warning,
            message: format!("cannot verify NFQueue support of {suricata}: --build-info does not report it"),
        }),
    }
    match info.ready_notify {
        Some(true) => {}
        Some(false) => findings.push(Finding {
            severity: Severity::Error,
            message: format!(
                "{suricata} is built without systemd support (needed for the readiness notification the gateway \
                 waits for before queueing packets); install a suricata build with systemd support"
            ),
        }),
        None => findings.push(Finding {
            severity: Severity::Warning,
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
        message: "suricata is started by wnc-gw and shares its account and privileges, so a compromised suricata \
                  can do whatever the gateway can"
            .to_owned(),
    }
}

fn when_unavailable_finding(when_unavailable: WhenUnavailable) -> Option<Finding> {
    match when_unavailable {
        WhenUnavailable::Accept => Some(Finding {
            severity: Severity::Warning,
            message: "forwarded traffic passes without inspection while suricata starts, restarts or falls behind \
                      (when_unavailable = \"accept\"); set when_unavailable = \"drop\" to drop it instead"
                .to_owned(),
        }),
        WhenUnavailable::Drop => None,
    }
}

fn print_suricata(path: &Setting<AbsolutePath>, info: &Result<SuricataInfo, SuricataError>) {
    let yes_no = |value: Option<bool>| match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    };
    let (version, nfqueue, ready_notify) = match info {
        Ok(info) => (
            info.version.as_deref().unwrap_or("unknown"),
            yes_no(info.nfqueue),
            yes_no(info.ready_notify),
        ),
        Err(SuricataError::NotFound { .. }) => ("not found", "-", "-"),
        Err(_) => ("unknown", "unknown", "unknown"),
    };
    println!(
        "{:<18} {:<12} {:<10} {:<8} {}",
        "COMMAND", "SOURCE", "VERSION", "NFQUEUE", "READY NOTIFY"
    );
    println!(
        "{:<18} {:<12} {version:<10} {nfqueue:<8} {ready_notify}",
        path.value.to_string(),
        path.source.to_string()
    );
}

fn suricata_config_findings(
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
                message: format!("suricata cannot load {config}: {}", suricata_errors(stderr)),
            }];
        }
        Err(e) => {
            return vec![Finding {
                severity: Severity::Warning,
                message: format!("could not check {config}: {e}"),
            }];
        }
    }
    let fix = format!("download rules (for example with suricata-update) or set rule-files in {config}");
    if rule_files.is_empty() {
        return vec![Finding {
            severity: Severity::Error,
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
    config: &Setting<AbsolutePath>,
    dump: &Result<SuricataConfig, SuricataError>,
    rule_files: &[RuleFile],
) {
    let result = match dump {
        Ok(_) => "ok",
        Err(SuricataError::Failed { .. }) => "error",
        Err(_) => "unknown",
    };
    println!("{:<40} {:<12} {}", "SURICATA CONFIG", "SOURCE", "RESULT");
    println!(
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
        println!("{:<40} {:<12} {result}", rule_file_name(file), "rule-files");
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
            let message = match &row.writers {
                Ok(writers) if writers.is_empty() => return None,
                Ok(writers) => format!(
                    "{} {path} can be modified without root ({}), so those accounts could make the gateway run \
                     code with its privileges",
                    row.used_as,
                    describe_writers(writers)
                ),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
                Err(e) => format!("could not check who can modify {path}: {e}"),
            };
            Some(Finding {
                severity: Severity::Warning,
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
    println!("{:<40} {:<22} {}", "FILE", "USED AS", "MODIFIABLE BY NON-ROOT");
    for row in rows {
        let result = match &row.writers {
            Ok(writers) if writers.is_empty() => "no",
            Ok(_) => "yes",
            Err(e) if e.kind() == io::ErrorKind::NotFound => "not found",
            Err(_) => "unknown",
        };
        println!("{:<40} {:<22} {result}", row.path.display().to_string(), row.used_as);
    }
}

async fn load_interfaces() -> Result<Vec<Interface>, NetifError> {
    Netlink::connect()?.interfaces().await
}

fn print_ports(config: &Config, results: &[Result<Port, ResolveError>]) {
    println!(
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
        println!(
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
