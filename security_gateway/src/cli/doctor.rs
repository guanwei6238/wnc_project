use std::path::Path;
use std::process::ExitCode;

use clap::Args;
use security_gateway::config::{self, Config, Overrides};
use security_gateway::datapath::{CoreHook, XdpPolicy, core_hook};
use security_gateway::forwarding::{self, EnvCheck, EnvState, Forwarding, Level, Mode};
use security_gateway::kernel::modules::{ModuleIndex, ModuleState, RequiredModule};
use security_gateway::kernel::netdev::{Netdev, XdpFeatures};
use security_gateway::kernel::netif::{Interface, LinkStatus, NetifError, Netlink, XdpAttachment, XdpMode};
use security_gateway::kernel::nft::{self, NFT, NftError, NftInfo};
use security_gateway::platform::{BootConfig, Current};
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
    if passes(&config).await {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

pub async fn passes(config: &Config) -> bool {
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

    findings.extend(check_nft().await);

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

async fn check_nft() -> Vec<Finding> {
    let info = nft::info().await;
    print_nft(&info);
    nft_finding(&info).into_iter().collect()
}

fn nft_finding(info: &Result<NftInfo, NftError>) -> Option<Finding> {
    const PURPOSE: &str = "needed for installing the gateway's nftables rules";
    let (severity, message) = match info {
        Ok(NftInfo { json: Some(true), .. }) => return None,
        Ok(NftInfo { json: Some(false), .. }) => (
            Severity::Error,
            format!("{NFT} is built without JSON support ({PURPOSE}); install an nftables build with JSON support"),
        ),
        Ok(NftInfo { json: None, .. }) => (
            Severity::Warning,
            format!("cannot verify JSON support of {NFT}: nft -V does not report it"),
        ),
        Err(NftError::NotFound) => (Severity::Error, format!("{NFT} not found ({PURPOSE}); install nftables")),
        Err(e) => (Severity::Warning, format!("could not check nft: {e}")),
    };
    Some(Finding { severity, message })
}

fn print_nft(info: &Result<NftInfo, NftError>) {
    let (version, json) = match info {
        Ok(info) => (
            info.version.as_deref().unwrap_or("unknown"),
            match info.json {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unknown",
            },
        ),
        Err(NftError::NotFound) => ("not found", "-"),
        Err(_) => ("unknown", "unknown"),
    };
    println!("{:<16} {:<10} {}", "COMMAND", "VERSION", "JSON");
    println!("{NFT:<16} {version:<10} {json}");
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
