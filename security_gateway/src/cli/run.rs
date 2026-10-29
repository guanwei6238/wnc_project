use std::io;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use clap::Args;
use security_gateway::config::{self, Config, Overrides};
use security_gateway::firewall::{self, FAMILY, Inspection, TABLE, WhenUnavailable};
use security_gateway::ids::lifecycle::{Event, Lifecycle};
use security_gateway::ids::spawned::{Options, SpawnedSuricata};
use security_gateway::instance;
use security_gateway::kernel::conntrack::Conntrack;
use security_gateway::kernel::nft::Nft;
use security_gateway::platform::{Current, Dirs};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tracing::{error, info, warn};

use super::doctor;
use super::logging::{self, LogFormat};

#[derive(Debug, Args)]
pub struct RunArgs {}

pub async fn run(config_path: Option<&Path>, overrides: Overrides, log_format: LogFormat, _args: RunArgs) -> ExitCode {
    logging::init(log_format);
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

    let mut signals = match StopSignals::listen() {
        Ok(signals) => signals,
        Err(e) => {
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
    clear_earlier_trust();
    if let Err(e) = firewall::install(&nft, inspection).await {
        error!(table = table.as_str(), error = %e, "failed to install table");
        return ExitCode::FAILURE;
    }
    info!(table = table.as_str(), "table installed; waiting for SIGINT, SIGTERM or SIGHUP");
    log_uninspected(inspection.when_unavailable);

    let mut code = serve(&config, &nft, inspection, &mut signals).await;

    match firewall::remove(&nft).await {
        Ok(()) => warn!(table = table.as_str(), "table removed; forwarded traffic passes without inspection"),
        Err(e) => {
            error!(table = table.as_str(), error = %e, "failed to remove table");
            code = ExitCode::FAILURE;
        }
    }
    code
}

fn clear_earlier_trust() {
    let start = Instant::now();
    match Conntrack::connect().and_then(|mut conntrack| firewall::untrust_all(&mut conntrack)) {
        Ok(untrusted) => {
            if untrusted.cleared + untrusted.gone > 0 {
                info!(
                    cleared = untrusted.cleared,
                    gone = untrusted.gone,
                    clear_ms = start.elapsed().as_millis() as u64,
                    "cleared trust left by an earlier run"
                );
            }
            for (tuple, e) in &untrusted.failed {
                let connection = tuple.to_string();
                error!(
                    connection = connection.as_str(),
                    error = %e,
                    "cannot clear trust left by an earlier run; this connection skips inspection until it ends"
                );
            }
        }
        Err(e) => error!(
            error = %e,
            "cannot clear trust left by an earlier run; those connections skip inspection until they end"
        ),
    }
}

struct StopSignals {
    interrupt: Signal,
    terminate: Signal,
    hangup: Signal,
}

impl StopSignals {
    fn listen() -> io::Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
        })
    }

    async fn recv(&mut self) -> &'static str {
        tokio::select! {
            _ = self.interrupt.recv() => "SIGINT",
            _ = self.terminate.recv() => "SIGTERM",
            _ = self.hangup.recv() => "SIGHUP",
        }
    }
}

async fn serve(config: &Config, nft: &Nft, inspection: Inspection, signals: &mut StopSignals) -> ExitCode {
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
            signal = signals.recv() => {
                info!(signal, "stopping");
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
