use std::ffi::OsString;
use std::fs::DirBuilder;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::net::UnixDatagram;
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use super::lifecycle::{Event, Exit, Lifecycle};
use crate::kernel::nfqueue::QueueRange;

const NOTIFY_SOCKET: &str = "notify.sock";
const CONTROL_SOCKET: &str = "suricata.sock";
const STOP_GRACE: Duration = Duration::from_secs(10);
const FIRST_DELAY: Duration = Duration::from_secs(1);
const MAX_DELAY: Duration = Duration::from_secs(60);
const STABLE_AFTER: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub path: PathBuf,
    pub config: PathBuf,
    pub queue: QueueRange,
    pub ready_timeout: Duration,
    pub runtime_dir: PathBuf,
    pub log_dir: PathBuf,
}

pub struct SpawnedSuricata {
    events: mpsc::UnboundedReceiver<Event>,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl SpawnedSuricata {
    pub fn start(options: Options) -> io::Result<Self> {
        for dir in [&options.runtime_dir, &options.log_dir] {
            DirBuilder::new().recursive(true).mode(0o750).create(dir)?;
        }
        let notify_path = options.runtime_dir.join(NOTIFY_SOCKET);
        match std::fs::remove_file(&notify_path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let notify = UnixDatagram::bind(&notify_path)?;
        let (events_tx, events) = mpsc::unbounded_channel();
        let (stop_tx, stop_rx) = oneshot::channel();
        let task = tokio::spawn(supervise(options, notify, events_tx, stop_rx));
        Ok(Self {
            events,
            stop: Some(stop_tx),
            task,
        })
    }
}

impl Lifecycle for SpawnedSuricata {
    async fn next_event(&mut self) -> Option<Event> {
        self.events.recv().await
    }

    async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = self.task.await;
    }
}

async fn supervise(
    options: Options,
    notify: UnixDatagram,
    events: mpsc::UnboundedSender<Event>,
    mut stop: oneshot::Receiver<()>,
) {
    let mut backoff = Backoff::new();
    loop {
        drain(&notify);
        let started = Instant::now();
        match spawn(&options) {
            Err(e) => error!(path = %options.path.display(), error = %e, "failed to start suricata"),
            Ok(mut child) => {
                let pid = child.id().unwrap_or_default();
                info!(pid, queue = %options.queue, "suricata started");
                forward_output(&mut child, pid, options.queue);
                let run = watch(&mut child, pid, started, &notify, &events, &mut stop, options.ready_timeout).await;
                let exit = run.status.ok().and_then(Exit::from_status);
                let exit_text = exit.map_or_else(|| "unknown".to_owned(), |exit| exit.to_string());
                let uptime = started.elapsed();
                let was_ready = run.ready_at.is_some();
                let _ = events.send(Event::Stopped {
                    pid,
                    exit,
                    uptime,
                    was_ready,
                });
                if run.stopped {
                    info!(pid, exit = exit_text.as_str(), "suricata stopped");
                    return;
                }
                warn!(pid, exit = exit_text.as_str(), uptime_s = uptime.as_secs(), was_ready, "suricata exited");
                if run.ready_at.is_some_and(|at| at.elapsed() >= STABLE_AFTER) {
                    backoff.reset();
                }
            }
        }
        let delay = backoff.next_delay();
        info!(delay_s = delay.as_secs(), "restarting suricata");
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = &mut stop => return,
        }
    }
}

struct Run {
    status: io::Result<ExitStatus>,
    ready_at: Option<Instant>,
    stopped: bool,
}

async fn watch(
    child: &mut Child,
    pid: u32,
    started: Instant,
    notify: &UnixDatagram,
    events: &mpsc::UnboundedSender<Event>,
    stop: &mut oneshot::Receiver<()>,
    ready_timeout: Duration,
) -> Run {
    let mut ready_at = None;
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::sleep(ready_timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            status = child.wait() => return Run { status, ready_at, stopped: false },
            received = notify.recv(&mut buf), if ready_at.is_none() => {
                if received.is_ok_and(|n| is_ready(&buf[..n])) {
                    ready_at = Some(Instant::now());
                    let startup = started.elapsed();
                    info!(pid, startup_ms = startup.as_millis() as u64, "suricata is ready");
                    let _ = events.send(Event::Ready { pid, startup });
                }
            }
            _ = &mut deadline, if ready_at.is_none() => {
                warn!(pid, ready_timeout_s = ready_timeout.as_secs(), "suricata did not become ready in time; stopping it");
                let status = terminate(child, pid).await;
                return Run { status, ready_at, stopped: false };
            }
            _ = &mut *stop => {
                info!(pid, "stopping suricata");
                let status = terminate(child, pid).await;
                return Run { status, ready_at, stopped: true };
            }
        }
    }
}

fn spawn(options: &Options) -> io::Result<Child> {
    let parent = std::process::id();
    let mut command = Command::new(&options.path);
    command
        .args(suricata_args(options))
        .env("NOTIFY_SOCKET", options.runtime_dir.join(NOTIFY_SOCKET))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM as libc::c_ulong) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() as u32 != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    command.spawn()
}

fn suricata_args(options: &Options) -> Vec<OsString> {
    let queue = match (options.queue.first(), options.queue.last()) {
        (first, last) if first == last => first.to_string(),
        (first, last) => format!("{first}:{last}"),
    };
    let mut control = OsString::from("unix-command.filename=");
    control.push(options.runtime_dir.join(CONTROL_SOCKET));
    vec![
        "-c".into(),
        options.config.clone().into(),
        "-q".into(),
        queue.into(),
        "-l".into(),
        options.log_dir.clone().into(),
        "--set".into(),
        control,
    ]
}

async fn terminate(child: &mut Child, pid: u32) -> io::Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    match tokio::time::timeout(STOP_GRACE, child.wait()).await {
        Ok(status) => status,
        Err(_) => {
            warn!(pid, grace_s = STOP_GRACE.as_secs(), "suricata did not stop in time; killing it");
            child.start_kill()?;
            child.wait().await
        }
    }
}

fn drain(notify: &UnixDatagram) {
    let mut buf = [0u8; 4096];
    while notify.try_recv(&mut buf).is_ok() {}
}

fn is_ready(datagram: &[u8]) -> bool {
    std::str::from_utf8(datagram).is_ok_and(|text| text.lines().any(|line| line == "READY=1"))
}

fn forward_output(child: &mut Child, pid: u32, queue: QueueRange) {
    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(forward(stdout, pid, queue));
    }
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(forward(stderr, pid, queue));
    }
}

async fn forward(stream: impl AsyncRead + Unpin, pid: u32, queue: QueueRange) {
    let mut lines = BufReader::new(stream).split(b'\n');
    while let Ok(Some(bytes)) = lines.next_segment().await {
        let line = String::from_utf8_lossy(&bytes);
        let (level, text) = classify(&line);
        match level {
            Level::Error => error!(source = "suricata", pid, "{text}"),
            Level::Warn => warn!(source = "suricata", pid, "{text}"),
            Level::Info => info!(source = "suricata", pid, "{text}"),
        }
        if text.contains("nfq_create_queue failed") {
            error!(pid, queue = %queue, "suricata cannot bind the queue; another program is using it");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Error,
    Warn,
    Info,
}

fn classify(line: &str) -> (Level, &str) {
    for (prefix, level) in [
        ("E: ", Level::Error),
        ("Error: ", Level::Error),
        ("W: ", Level::Warn),
        ("Warning: ", Level::Warn),
    ] {
        if let Some(rest) = line.strip_prefix(prefix) {
            return (level, rest);
        }
    }
    match line.split_once(": ") {
        Some((tag, rest)) if tag.len() == 1 => (Level::Info, rest),
        _ => (Level::Info, line),
    }
}

struct Backoff {
    next: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self { next: FIRST_DELAY }
    }

    fn next_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = (self.next * 2).min(MAX_DELAY);
        delay
    }

    fn reset(&mut self) {
        self.next = FIRST_DELAY;
    }
}

#[cfg(test)]
#[path = "../../tests/unit/ids/spawned.rs"]
mod tests;
