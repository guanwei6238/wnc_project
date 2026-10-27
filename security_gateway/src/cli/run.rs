use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use clap::Args;
use security_gateway::config::{self, Config, Overrides};
use security_gateway::firewall::{self, FAMILY, Inspection, TABLE, WhenUnavailable};
use security_gateway::ids::lifecycle::{Event, Lifecycle};
use security_gateway::ids::spawned::{Options, SpawnedSuricata};
use security_gateway::instance;
use security_gateway::kernel::nft::Nft;
use security_gateway::platform::{Current, Dirs};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tracing::{error, info, warn};

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
    let _lock = match instance::lock(Current.runtime_dir()) {
        Ok(lock) => lock,
        Err(e) => {
            error!(error = %e, "not starting");
            return ExitCode::FAILURE;
        }
    };
    if !doctor::passes(&config, true).await {
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
    let inspection = Inspection {
        queue: config.suricata.queue.value,
        when_unavailable: config.suricata.when_unavailable.value,
    };
    if let Err(e) = firewall::install(&nft, inspection).await {
        error!(table = table.as_str(), error = %e, "failed to install table");
        return ExitCode::FAILURE;
    }
    info!(table = table.as_str(), "table installed; waiting for SIGINT or SIGTERM");
    log_uninspected(inspection.when_unavailable);

    let mut code = serve(&config, &nft, inspection, &mut interrupt, &mut terminate).await;

    match firewall::remove(&nft).await {
        Ok(()) => warn!(table = table.as_str(), "table removed; forwarded traffic passes without inspection"),
        Err(e) => {
            error!(table = table.as_str(), error = %e, "failed to remove table");
            code = ExitCode::FAILURE;
        }
    }
    code
}

async fn serve(
    config: &Config,
    nft: &Nft,
    inspection: Inspection,
    interrupt: &mut Signal,
    terminate: &mut Signal,
) -> ExitCode {
    let mut suricata = match SpawnedSuricata::start(suricata_options(config)) {
        Ok(suricata) => suricata,
        Err(e) => {
            error!(error = %e, "failed to start suricata");
            return ExitCode::FAILURE;
        }
    };
    let mut uninspected_since = Some(Instant::now());
    let mut code = loop {
        tokio::select! {
            _ = interrupt.recv() => {
                info!(signal = "SIGINT", "stopping");
                break ExitCode::SUCCESS;
            }
            _ = terminate.recv() => {
                info!(signal = "SIGTERM", "stopping");
                break ExitCode::SUCCESS;
            }
            event = suricata.next_event() => match event {
                None => {
                    error!("suricata supervision ended unexpectedly");
                    break ExitCode::FAILURE;
                }
                Some(Event::Ready { .. }) => {
                    if let Err(e) = firewall::start_inspection(nft, inspection).await {
                        error!(error = %e, "failed to queue forwarded traffic to suricata");
                        break ExitCode::FAILURE;
                    }
                    let uninspected_ms = uninspected_since.take().map_or(0, |since| since.elapsed().as_millis() as u64);
                    info!(queue = %inspection.queue, uninspected_ms, "forwarded traffic is inspected");
                }
                Some(Event::Stopped { .. }) => {
                    if uninspected_since.is_none() {
                        if let Err(e) = firewall::stop_inspection(nft, inspection).await {
                            error!(error = %e, "failed to stop queueing forwarded traffic; not restarting suricata");
                            break ExitCode::FAILURE;
                        }
                        uninspected_since = Some(Instant::now());
                        log_uninspected(inspection.when_unavailable);
                    }
                    suricata.allow_restart();
                }
            }
        }
    };
    if uninspected_since.is_none() {
        match firewall::stop_inspection(nft, inspection).await {
            Ok(()) => log_uninspected(inspection.when_unavailable),
            Err(e) => {
                error!(error = %e, "failed to stop queueing forwarded traffic");
                code = ExitCode::FAILURE;
            }
        }
    }
    suricata.stop().await;
    code
}

fn log_uninspected(when_unavailable: WhenUnavailable) {
    let when = when_unavailable.to_string();
    match when_unavailable {
        WhenUnavailable::Accept => warn!(when_unavailable = when.as_str(), "forwarded traffic passes without inspection"),
        WhenUnavailable::Drop => warn!(when_unavailable = when.as_str(), "forwarded traffic is dropped without inspection"),
    }
}

fn suricata_options(config: &Config) -> Options {
    Options {
        path: config.suricata.path.value.as_path().to_path_buf(),
        config: config.suricata.config.value.as_path().to_path_buf(),
        queue: config.suricata.queue.value,
        ready_timeout: config.suricata.ready_timeout.value,
        stop_timeout: config.suricata.stop_timeout.value,
        fail_open: config.suricata.when_unavailable.value == WhenUnavailable::Accept,
        runtime_dir: Current.runtime_dir().to_path_buf(),
        log_dir: Current.log_dir().join("suricata"),
    }
}
