use std::path::Path;
use std::process::ExitCode;

use clap::Args;
use security_gateway::config::{self, Config, Overrides};
use security_gateway::kernel::netif::{Interface, NetifError, Netlink};
use security_gateway::ports::{self, Port, ResolveError};

#[derive(Debug, Args)]
pub struct DoctorArgs {}

pub async fn run(config_path: Option<&Path>, overrides: Overrides, _args: DoctorArgs) -> ExitCode {
    let config = match config::load(config_path, overrides) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("error: {e}");
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

    let errors: Vec<_> = results.iter().filter_map(|result| result.as_ref().err()).collect();
    if errors.is_empty() {
        return ExitCode::SUCCESS;
    }
    println!();
    for e in errors {
        eprintln!("error: {e}");
    }
    ExitCode::FAILURE
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
