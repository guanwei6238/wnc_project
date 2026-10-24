use std::path::Path;
use std::process::ExitCode;

use clap::Args;
use security_gateway::config::{self, Config, Overrides};
use security_gateway::forwarding::{self, EnvCheck, EnvState, Forwarding, Level, Mode};
use security_gateway::kernel::modules::{ModuleIndex, ModuleState, RequiredModule};
use security_gateway::kernel::netif::{Interface, LinkStatus, NetifError, Netlink};
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
    // 檢查結果（含設定檔錯誤）印在 stdout；stderr 只留給 doctor 自己無法完成檢查的情況
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
    match &config.file {
        Some(path) => println!("config: {}", path.display()),
        None => println!("config: none ({} not found)", config::DEFAULT_PATH),
    }
    println!("mode:   {} ({})", config.mode.value, config.mode.source);
    println!();

    let interfaces = match load_interfaces().await {
        Ok(interfaces) => interfaces,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let results = ports::resolve(&config.port_specs(), &interfaces);
    print_ports(&config, &results);
    let mut findings = port_findings(&results);
    println!();

    let mode = config.mode.value;
    let forwarding = forwarding::for_mode(mode);
    let ports: Vec<Port> = results.iter().filter_map(|r| r.as_ref().ok().cloned()).collect();
    findings.extend(check_environment(mode, forwarding.as_ref(), &ports, &interfaces));
    println!();

    findings.extend(check_modules(forwarding.required_modules()));

    if !findings.is_empty() {
        println!();
    }
    for finding in &findings {
        finding.print();
    }
    if findings.iter().any(|f| f.severity == Severity::Error) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
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
                         load it with: modprobe {name}, and list it in /etc/modules-load.d/ to load it at boot",
                        module.purpose,
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
