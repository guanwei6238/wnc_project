use std::path::Path;
use std::process::ExitCode;

use clap::Args;
use security_gateway::config::{self, Config, Overrides};
use security_gateway::kernel::modules::{ModuleIndex, ModuleState};
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

    findings.extend(check_modules());

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

struct RequiredModule {
    name: &'static str,
    purpose: &'static str,
}

const REQUIRED_MODULES: &[RequiredModule] = &[
    RequiredModule {
        name: "nf_tables",
        purpose: "nftables rules",
    },
    RequiredModule {
        name: "nft_queue",
        purpose: "queueing packets to the IDS",
    },
    RequiredModule {
        name: "nfnetlink_queue",
        purpose: "passing queued packets to user space",
    },
    RequiredModule {
        name: "nf_conntrack",
        purpose: "connection tracking",
    },
    RequiredModule {
        name: "nft_ct",
        purpose: "matching and setting ct mark",
    },
];

fn check_modules() -> Vec<Finding> {
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
                ModuleState::Loaded | ModuleState::Builtin | ModuleState::Loadable => return None,
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
