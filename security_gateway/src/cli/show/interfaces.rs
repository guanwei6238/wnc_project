use std::process::ExitCode;

use clap::Args;
use security_gateway::kernel::netif::{Interface, NetifError, Netlink};

#[derive(Debug, Args)]
pub struct InterfacesArgs {}

pub async fn run(_args: InterfacesArgs) -> ExitCode {
    match load().await {
        Ok(interfaces) => {
            print_interfaces(&interfaces);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn load() -> Result<Vec<Interface>, NetifError> {
    Netlink::connect()?.interfaces().await
}

fn print_interfaces(interfaces: &[Interface]) {
    println!(
        "{:<4} {:<15} {:<17} {:<17} {:<5} {:<14} {:<8} {:<15} {}",
        "IDX", "NAME", "MAC", "PERM", "ADMIN", "OPER", "KIND", "MASTER", "DRIVER"
    );
    for iface in interfaces {
        let master = iface.master.map(|index| {
            interfaces
                .iter()
                .find(|other| other.index == index)
                .map_or_else(|| format!("#{index}"), |other| other.name.clone())
        });
        println!(
            "{:<4} {:<15} {:<17} {:<17} {:<5} {:<14} {:<8} {:<15} {}",
            iface.index,
            iface.name,
            iface.mac.map_or_else(|| "-".to_owned(), |mac| mac.to_string()),
            iface.perm_mac.map_or_else(|| "-".to_owned(), |mac| mac.to_string()),
            if iface.admin_up { "up" } else { "down" },
            iface.oper_state.to_string(),
            iface.kind.as_deref().unwrap_or("-"),
            master.as_deref().unwrap_or("-"),
            iface.driver.as_deref().unwrap_or("-"),
        );
    }
}
