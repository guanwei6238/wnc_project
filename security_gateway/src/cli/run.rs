use std::path::Path;
use std::process::ExitCode;

use clap::Args;
use security_gateway::config::{self, Overrides};
use security_gateway::firewall::{self, FAMILY, TABLE};
use security_gateway::kernel::nft::Nft;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info};

use super::{doctor, logging};

#[derive(Debug, Args)]
pub struct RunArgs {}

pub async fn run(config_path: Option<&Path>, overrides: Overrides, _args: RunArgs) -> ExitCode {
    logging::init();
    info!(version = env!("CARGO_PKG_VERSION"), "starting");
    let config = match config::load(config_path, overrides) {
        Ok(config) => config,
        Err(e) => {
            error!(error = %e, "cannot load the config file");
            return ExitCode::FAILURE;
        }
    };
    if !doctor::passes(&config).await {
        error!("not starting because the checks above found errors");
        return ExitCode::FAILURE;
    }
    println!();

    let (mut interrupt, mut terminate) = match (signal(SignalKind::interrupt()), signal(SignalKind::terminate())) {
        (Ok(interrupt), Ok(terminate)) => (interrupt, terminate),
        (Err(e), _) | (_, Err(e)) => {
            error!(error = %e, "failed to listen for signals");
            return ExitCode::FAILURE;
        }
    };

    let table = format!("{FAMILY} {TABLE}");
    let nft = Nft::new(config.nftables.path.value.as_path());
    if let Err(e) = firewall::install(&nft).await {
        error!(table = table.as_str(), error = %e, "failed to install table");
        return ExitCode::FAILURE;
    }
    info!(table = table.as_str(), "table installed; waiting for SIGINT or SIGTERM");

    let signal = tokio::select! {
        _ = interrupt.recv() => "SIGINT",
        _ = terminate.recv() => "SIGTERM",
    };
    info!(signal, "stopping");

    match firewall::remove(&nft).await {
        Ok(()) => {
            info!(table = table.as_str(), "table removed");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!(table = table.as_str(), error = %e, "failed to remove table");
            ExitCode::FAILURE
        }
    }
}
