use std::path::Path;
use std::process::ExitCode;

use clap::Args;
use security_gateway::config::{self, Overrides};
use security_gateway::firewall::{self, FAMILY, TABLE};
use security_gateway::kernel::nft::Nft;
use tokio::signal::unix::{SignalKind, signal};

use super::doctor;

#[derive(Debug, Args)]
pub struct RunArgs {}

pub async fn run(config_path: Option<&Path>, overrides: Overrides, _args: RunArgs) -> ExitCode {
    let config = match config::load(config_path, overrides) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    if !doctor::passes(&config).await {
        eprintln!("error: not starting because the checks above found errors");
        return ExitCode::FAILURE;
    }
    println!();

    let (mut interrupt, mut terminate) = match (signal(SignalKind::interrupt()), signal(SignalKind::terminate())) {
        (Ok(interrupt), Ok(terminate)) => (interrupt, terminate),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("error: failed to listen for signals: {e}");
            return ExitCode::FAILURE;
        }
    };

    let nft = Nft::new(config.nftables.path.value.as_path());
    if let Err(e) = firewall::install(&nft).await {
        eprintln!("error: failed to install table {FAMILY} {TABLE}: {e}");
        return ExitCode::FAILURE;
    }
    println!("table {FAMILY} {TABLE} installed; press Ctrl-C to remove it and exit");

    tokio::select! {
        _ = interrupt.recv() => {}
        _ = terminate.recv() => {}
    }

    match firewall::remove(&nft).await {
        Ok(()) => {
            println!("table {FAMILY} {TABLE} removed");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: failed to remove table {FAMILY} {TABLE}: {e}");
            ExitCode::FAILURE
        }
    }
}
