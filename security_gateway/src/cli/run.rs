use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Args;
use security_gateway::agent::LocalPrivd;
use security_gateway::agent::trust::{TrustAgent, TrustPolicy};
use security_gateway::config::{self, Config, Overrides, TrustSettings};
use security_gateway::datapath::CoreProgram;
use security_gateway::firewall::{self, FAMILY, Inspection, TABLE, WhenUnavailable};
use security_gateway::ids::delivery::Delivery;
use security_gateway::ids::lifecycle::{Event, Lifecycle};
use security_gateway::ids::spawned::{self, Options, SpawnedSuricata};
use security_gateway::ids::suricata::Suricata;
use security_gateway::instance::{self, InstanceError};
use security_gateway::issue::Issue;
use security_gateway::kernel::conntrack::Conntrack;
use security_gateway::kernel::bpf;
use security_gateway::kernel::netif::Netlink;
use security_gateway::kernel::nflog;
use security_gateway::kernel::nft::Nft;
use security_gateway::monitor::alerts::AlertWatch;
use security_gateway::monitor::conntrack::ConntrackMonitor;
use security_gateway::monitor::nflog::CopyMonitor;
use security_gateway::monitor::tcx::{CoreWatch, WatchedPort};
use security_gateway::platform::{Current, Dirs};
use security_gateway::ports::{self, Port};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::time::{self, MissedTickBehavior};
use tracing::{error, info, warn};

use super::doctor;
use super::logging::{self, LogFormat, LogLevel};

#[derive(Debug, Args)]
pub struct RunArgs {}

pub async fn run(
    config_path: Option<&Path>,
    overrides: Overrides,
    log_format: LogFormat,
    log_level: LogLevel,
    _args: RunArgs,
) -> ExitCode {
    logging::init(log_format, log_level);
    info!(version = env!("CARGO_PKG_VERSION"), "starting");
    let config = match config::load(config_path, overrides) {
        Ok(config) => config,
        Err(e) => {
            error!(code = %doctor::config_issue(&e), error = %e, "cannot load the config file");
            return ExitCode::FAILURE;
        }
    };
    let _lock = match instance::lock(Current.runtime_dir()) {
        Ok(lock) => lock,
        Err(e) => {
            let issue = match e {
                InstanceError::AlreadyRunning { .. } => Issue::AlreadyRunning,
                InstanceError::Io { .. } => Issue::LockFailed,
            };
            error!(code = %issue, error = %e, "not starting");
            return ExitCode::FAILURE;
        }
    };
    if !doctor::passes(&config, true).await {
        error!(code = %Issue::ChecksFailed, "not starting because the checks above found errors");
        return ExitCode::FAILURE;
    }
    out!();
    let alert_file = alert_file(&config).await;

    let mut signals = match StopSignals::listen() {
        Ok(signals) => signals,
        Err(e) => {
            error!(code = %Issue::SignalsUnavailable, error = %e, "failed to listen for signals");
            return ExitCode::FAILURE;
        }
    };

    let table = format!("{FAMILY} {TABLE}");
    let nft = Nft::new(config.nftables.path.value.as_path());
    let inspection = Inspection {
        delivery: config.delivery(),
        when_unavailable: config.suricata.when_unavailable.value,
    };
    clear_earlier_trust();
    if let Err(e) = firewall::install(&nft, inspection).await {
        error!(code = %Issue::TableInstallFailed, table = table.as_str(), error = %e, "failed to install table");
        return ExitCode::FAILURE;
    }
    info!(table = table.as_str(), "table installed; waiting for SIGINT, SIGTERM or SIGHUP");
    log_uninspected(inspection.when_unavailable);
    let (core, core_watch) = match attach_core(&config).await {
        Some((core, watch)) => (Some(core), Some(watch)),
        None => (None, None),
    };

    let mut code = serve(&config, &nft, inspection, alert_file, core_watch, &mut signals).await;

    if let Some(core) = core {
        detach_core(core);
    }

    match firewall::remove(&nft).await {
        Ok(()) => warn!(
            code = %Issue::TableRemoved,
            table = table.as_str(),
            "table removed; forwarded traffic passes without inspection"
        ),
        Err(e) => {
            error!(code = %Issue::TableRemoveFailed, table = table.as_str(), error = %e, "failed to remove table");
            code = ExitCode::FAILURE;
        }
    }
    code
}

async fn attach_core(config: &Config) -> Option<(CoreProgram, CoreWatch)> {
    let attached = match resolve_ports(config).await {
        Ok(ports) => CoreProgram::attach(&ports).map(|core| (core, ports)).map_err(|e| e.to_string()),
        Err(e) => Err(e),
    };
    match attached {
        Ok((core, ports)) => {
            let interfaces: Vec<&str> = ports.iter().map(|port| port.interface.name.as_str()).collect();
            let interfaces = interfaces.join(",");
            info!(
                prog_id = core.id(),
                interfaces = interfaces.as_str(),
                "core ebpf program attached first on tcx ingress"
            );
            let watched = ports
                .into_iter()
                .map(|port| WatchedPort {
                    name: port.interface.name,
                    ifindex: port.interface.index,
                })
                .collect();
            let watch = CoreWatch::new(core.id(), watched);
            Some((core, watch))
        }
        Err(e) => {
            error!(
                code = %Issue::CoreProgramFailed,
                error = e.as_str(),
                "cannot attach the core ebpf program; running without it"
            );
            None
        }
    }
}

async fn resolve_ports(config: &Config) -> Result<Vec<Port>, String> {
    let netlink = Netlink::connect().map_err(|e| e.to_string())?;
    let interfaces = netlink.interfaces().await.map_err(|e| e.to_string())?;
    ports::resolve(&config.port_specs(), &interfaces)
        .into_iter()
        .map(|port| port.map_err(|e| e.to_string()))
        .collect()
}

fn detach_core(core: CoreProgram) {
    let (prog_id, packets) = (core.id(), core.packets());
    drop(core);
    match packets {
        Ok(packets) => info!(prog_id, packets, "core ebpf program detached"),
        Err(e) => info!(prog_id, error = %e, "core ebpf program detached"),
    }
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
                    code = %Issue::EarlierTrustKept,
                    connection = connection.as_str(),
                    error = %e,
                    "cannot clear trust left by an earlier run; this connection skips inspection until it ends"
                );
            }
        }
        Err(e) => error!(
            code = %Issue::EarlierTrustKept,
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

async fn serve(
    config: &Config,
    nft: &Nft,
    inspection: Inspection,
    alert_file: Option<PathBuf>,
    core_watch: Option<CoreWatch>,
    signals: &mut StopSignals,
) -> ExitCode {
    let mut core_watch = core_watch;
    let mut core_tick = time::interval(CoreWatch::INTERVAL);
    core_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut suricata = match SpawnedSuricata::start(suricata_options(config)) {
        Ok(suricata) => suricata,
        Err(e) => {
            error!(code = %Issue::SuricataStartFailed, error = %e, "failed to start suricata");
            return ExitCode::FAILURE;
        }
    };
    let mut alert_file = alert_file;
    let mut alerts: Option<AlertWatch> = None;
    let mut privd = LocalPrivd::default();
    let (mut trust_agent, mut trust_tick) = match trust_agent(config, alert_file.is_some()) {
        Some((agent, check_interval)) => {
            let mut tick = time::interval(check_interval);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            (Some(agent), Some(tick))
        }
        None => (None, None),
    };
    let mut uninspected_since = Some(Instant::now());
    let mut stop_failed = false;
    let mut conntrack_monitor = ConntrackMonitor::default();
    let mut monitor_tick = time::interval(ConntrackMonitor::INTERVAL);
    monitor_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut copying_to = None;
    let mut copy_monitor = CopyMonitor::default();
    let mut copy_tick = time::interval(CopyMonitor::INTERVAL);
    copy_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut code = loop {
        tokio::select! {
            signal = signals.recv() => {
                info!(signal, "stopping");
                break ExitCode::SUCCESS;
            }
            _ = monitor_tick.tick() => conntrack_monitor.check(Conntrack::connect().and_then(|mut c| c.stats())),
            _ = core_tick.tick(), if core_watch.is_some() => {
                if let Some(watch) = core_watch.as_mut() {
                    watch.check(bpf::tcx_ingress);
                }
            }
            found = async {
                match alerts.as_mut() {
                    Some(alerts) => alerts.next().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(agent) = trust_agent.as_mut() {
                    for alert in &found {
                        agent.on_alert(alert, &mut privd, std::time::Instant::now());
                    }
                    agent.set_alerts_current(alerts.as_ref().is_none_or(AlertWatch::is_current));
                }
            }
            _ = tick(&mut trust_tick) => {
                if let Some(agent) = trust_agent.as_mut() {
                    agent.check(&mut privd, std::time::Instant::now());
                }
            }
            _ = copy_tick.tick(), if copying_to.is_some() => {
                if let Some(pid) = copying_to {
                    copy_monitor.check(pid, nflog::netfilter_sockets(pid));
                }
            }
            event = suricata.next_event() => match event {
                None => {
                    error!(code = %Issue::SupervisionEnded, "suricata supervision ended unexpectedly");
                    break ExitCode::FAILURE;
                }
                Some(Event::Ready { pid, .. }) => {
                    if let Err(e) = firewall::start_inspection(nft, inspection).await {
                        error!(code = %Issue::StartInspectionFailed, error = %e, "failed to send forwarded traffic to suricata");
                        break ExitCode::FAILURE;
                    }
                    if let Delivery::Copy(_) = inspection.delivery {
                        copying_to = Some(pid);
                    }
                    if let Some(path) = alert_file.take() {
                        let settings = &config.suricata;
                        alerts = Some(AlertWatch::new(path, settings.eve_interval.value));
                    }
                    if let Some(agent) = trust_agent.as_mut() {
                        agent.set_inspecting(true);
                    }
                    let uninspected_ms = uninspected_since.take().map_or(0, |since| since.elapsed().as_millis() as u64);
                    info!(delivery = %inspection.delivery, uninspected_ms, "forwarded traffic is inspected");
                }
                Some(Event::Stopped { .. }) => {
                    copying_to = None;
                    if let Some(agent) = trust_agent.as_mut() {
                        agent.set_inspecting(false);
                    }
                    if uninspected_since.is_none() {
                        if let Err(e) = firewall::stop_inspection(nft, inspection).await {
                            error!(
                                code = %Issue::StopInspectionFailed,
                                error = %e,
                                "failed to stop sending forwarded traffic to suricata; not restarting suricata"
                            );
                            stop_failed = true;
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
                if !stop_failed {
                    error!(code = %Issue::StopInspectionFailed, error = %e, "failed to stop sending forwarded traffic to suricata");
                }
                code = ExitCode::FAILURE;
            }
        }
    }
    suricata.stop().await;
    if let Some(alerts) = alerts.as_mut() {
        alerts.finish();
    }
    code
}

async fn tick(interval: &mut Option<time::Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
    }
}

fn trust_agent(config: &Config, alerts: bool) -> Option<(TrustAgent, Duration)> {
    let trust = match &config.trust {
        TrustSettings::Manual { .. } => return None,
        TrustSettings::Auto(auto) => auto,
    };
    if !alerts {
        warn!(
            code = %Issue::AutoTrustOff,
            "automatic trust is off because wnc-gw cannot see suricata's alerts; every connection is inspected"
        );
        return None;
    }
    info!(
        min_packets = trust.min_packets.value,
        min_age_s = trust.min_age.value.as_secs(),
        ttl_s = trust.ttl.value.as_secs(),
        check_interval_s = trust.check_interval.value.as_secs(),
        "automatic trust is on"
    );
    let agent = TrustAgent::new(TrustPolicy {
        min_packets: trust.min_packets.value,
        min_age: trust.min_age.value,
        ttl: trust.ttl.value,
    });
    Some((agent, trust.check_interval.value))
}

async fn alert_file(config: &Config) -> Option<PathBuf> {
    let suricata = Suricata::new(config.suricata.path.value.as_path());
    let log_dir = spawned::log_dir(Current.log_dir());
    match suricata
        .dump_config(config.suricata.config.value.as_path(), &spawned::FORCED_SETTINGS)
        .await
    {
        Ok(dump) => {
            let file = dump.alert_file(&log_dir);
            if file.is_none() {
                warn!(
                    code = %Issue::NoAlertOutput,
                    "suricata does not write alerts to a regular EVE file; wnc-gw cannot see alerts"
                );
            }
            file
        }
        Err(e) => {
            warn!(code = %Issue::AlertFileUnknown, error = %e, "cannot read suricata's config; wnc-gw cannot see alerts");
            None
        }
    }
}

fn log_uninspected(when_unavailable: WhenUnavailable) {
    let when = when_unavailable.to_string();
    match when_unavailable {
        WhenUnavailable::Accept => warn!(
            code = %Issue::Uninspected,
            when_unavailable = when.as_str(),
            "forwarded traffic passes without inspection"
        ),
        WhenUnavailable::Drop => warn!(
            code = %Issue::DroppedUninspected,
            when_unavailable = when.as_str(),
            "forwarded traffic is dropped without inspection"
        ),
    }
}

fn suricata_options(config: &Config) -> Options {
    Options {
        path: config.suricata.path.value.as_path().to_path_buf(),
        config: config.suricata.config.value.as_path().to_path_buf(),
        delivery: config.delivery(),
        ready_timeout: config.suricata.ready_timeout.value,
        stop_timeout: config.suricata.stop_timeout.value,
        fail_open: config.suricata.when_unavailable.value == WhenUnavailable::Accept,
        runtime_dir: Current.runtime_dir().to_path_buf(),
        log_dir: spawned::log_dir(Current.log_dir()),
    }
}
