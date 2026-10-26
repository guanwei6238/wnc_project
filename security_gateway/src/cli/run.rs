use std::path::Path;
use std::process::ExitCode;

use clap::Args;
use security_gateway::config::{self, Config, Overrides};
use security_gateway::firewall::{self, FAMILY, TABLE};
use security_gateway::ids::lifecycle::Lifecycle;
use security_gateway::ids::spawned::{Options, SpawnedSuricata};
use security_gateway::kernel::nft::Nft;
use security_gateway::platform::{Current, Dirs};
use tokio::signal::unix::{Signal, SignalKind, signal};
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

    let mut code = serve(&config, &mut interrupt, &mut terminate).await;

    match firewall::remove(&nft).await {
        Ok(()) => info!(table = table.as_str(), "table removed"),
        Err(e) => {
            error!(table = table.as_str(), error = %e, "failed to remove table");
            code = ExitCode::FAILURE;
        }
    }
    code
}

async fn serve(config: &Config, interrupt: &mut Signal, terminate: &mut Signal) -> ExitCode {
    let mut suricata = match SpawnedSuricata::start(suricata_options(config)) {
        Ok(suricata) => suricata,
        Err(e) => {
            error!(error = %e, "failed to start suricata");
            return ExitCode::FAILURE;
        }
    };
    let code = loop {
        tokio::select! {
            _ = interrupt.recv() => {
                info!(signal = "SIGINT", "stopping");
                break ExitCode::SUCCESS;
            }
            _ = terminate.recv() => {
                info!(signal = "SIGTERM", "stopping");
                break ExitCode::SUCCESS;
            }
            event = suricata.next_event() => {
                if event.is_none() {
                    error!("suricata supervision ended unexpectedly");
                    break ExitCode::FAILURE;
                }
            }
        }
    };
    suricata.stop().await;
    code
}

fn suricata_options(config: &Config) -> Options {
    Options {
        path: config.suricata.path.value.as_path().to_path_buf(),
        config: config.suricata.config.value.as_path().to_path_buf(),
        queue: config.suricata.queue.value,
        ready_timeout: config.suricata.ready_timeout.value,
        runtime_dir: Current.runtime_dir().to_path_buf(),
        log_dir: Current.log_dir().join("suricata"),
    }
}
