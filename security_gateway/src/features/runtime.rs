use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::future::{FutureExt, select_all};
use tokio::io::unix::AsyncFd;
use tokio::time::{self, Interval, MissedTickBehavior};
use tracing::{debug, error, info, warn};

use super::hook::{Hook, XdpMode};
use super::load;
use super::plan::Plan;
use crate::issue::Issue;
use crate::kernel::bpf::user::{Attach, Ring, Table, UserProgram};

pub const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
const RING_BATCH: usize = 10_000;
const REPORT_EVERY: Duration = Duration::from_secs(60);

pub struct Spec<'a> {
    pub name: &'a str,
    pub program: &'a Path,
    pub entry: &'a str,
    pub definition: &'a Path,
    pub hook: Hook,
    pub interval: Duration,
}

enum Source {
    Table { table: Table, tick: Interval, limit: usize },
    Ring(AsyncFd<Ring>),
}

struct Running {
    name: String,
    source: Source,
    plan: Plan,
    buffer: Vec<u8>,
    sink: Sink,
    _program: UserProgram,
    written: u64,
    bad: u64,
    bad_reported: u64,
    read_failing: bool,
    last_report: Instant,
}

#[derive(Default)]
pub struct Features {
    running: Vec<Running>,
}

impl Features {
    pub fn start(specs: &[Spec<'_>], ifindexes: &[u32], out_dir: &Path) -> Self {
        let running = specs.iter().filter_map(|spec| start_one(spec, ifindexes, out_dir)).collect();
        Self { running }
    }

    pub fn is_empty(&self) -> bool {
        self.running.is_empty()
    }

    /// Waits until a map is due to be read or a ring buffer has records, and handles it.
    pub async fn step(&mut self) {
        if self.running.is_empty() {
            return std::future::pending().await;
        }
        let waits = self.running.iter_mut().map(|r| r.step().boxed());
        select_all(waits).await;
    }
}

impl Drop for Features {
    fn drop(&mut self) {
        for r in &self.running {
            info!(feature = r.name.as_str(), records = r.written, bad_records = r.bad, "feature program detached");
        }
    }
}

pub fn attach_of(hook: Hook) -> Attach {
    match hook {
        Hook::Xdp(XdpMode::Native) => Attach::Xdp { generic: false },
        Hook::Xdp(XdpMode::Generic) => Attach::Xdp { generic: true },
        Hook::TcIngress => Attach::TcxIngressLast,
        Hook::TcEgress => Attach::TcxEgressLast,
    }
}

fn start_one(spec: &Spec<'_>, ifindexes: &[u32], out_dir: &Path) -> Option<Running> {
    let name = spec.name;
    let failed = |e: &dyn std::fmt::Display| {
        error!(
            code = %Issue::FeatureLoadFailed,
            feature = name,
            error = %e,
            "cannot start the feature program; running without it (forwarding and inspection are not affected)"
        );
    };
    let loaded = match load::load(spec.program, spec.definition, spec.entry, spec.hook) {
        Ok(loaded) => loaded,
        Err(e) => {
            failed(&e);
            return None;
        }
    };
    if let Some(problem) = loaded.problems.iter().find(|p| p.blocks_loading()) {
        failed(problem);
        return None;
    }
    let info = loaded.elf.maps[&loaded.definition.map];
    let mut program = match UserProgram::load(&loaded.bytes, spec.entry, attach_of(spec.hook)) {
        Ok(program) => program,
        Err(e) => {
            failed(&e);
            return None;
        }
    };
    for &ifindex in ifindexes {
        if let Err(e) = program.attach(ifindex) {
            failed(&e);
            return None;
        }
    }
    let definition = loaded.definition;
    let source = if info.kind.is_events() {
        match program.take_ring(&definition.map).map_err(|e| e.to_string()).and_then(|ring| ring.into_async().map_err(|e| e.to_string())) {
            Ok(fd) => Source::Ring(fd),
            Err(e) => {
                failed(&e);
                return None;
            }
        }
    } else {
        let key_size = definition.key.as_ref().map_or(0, |k| k.size);
        match program.take_table(&definition.map, key_size, definition.value.size, info.kind.per_cpu()) {
            Ok(table) => {
                let mut tick = time::interval(spec.interval);
                tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
                Source::Table { table, tick, limit: info.max_entries as usize }
            }
            Err(e) => {
                failed(&e);
                return None;
            }
        }
    };
    let sink = match Sink::open(out_dir, name) {
        Ok(sink) => sink,
        Err(e) => {
            failed(&format_args!("cannot open the output file in {}: {e}", out_dir.display()));
            return None;
        }
    };
    info!(
        feature = name,
        prog_id = program.id().unwrap_or_default(),
        hook = %spec.hook,
        map = definition.map.as_str(),
        output = %sink.path.display(),
        "feature program attached"
    );
    Some(Running {
        name: name.to_string(),
        plan: Plan::new(&definition, name, info.kind.per_cpu(), info.kind.is_array()),
        source,
        buffer: Vec::new(),
        sink,
        _program: program,
        written: 0,
        bad: 0,
        bad_reported: 0,
        read_failing: false,
        last_report: Instant::now(),
    })
}

impl Running {
    async fn step(&mut self) {
        let bad = match &mut self.source {
            Source::Table { table, tick, limit } => {
                tick.tick().await;
                let batched = table.reads_in_batches();
                match table.read(*limit) {
                    Ok(()) => {
                        if self.read_failing {
                            self.read_failing = false;
                            info!(feature = self.name.as_str(), "feature map can be read again");
                        }
                        if batched && !table.reads_in_batches() {
                            info!(feature = self.name.as_str(), "the kernel cannot read this map in batches; reading one entry at a time");
                        }
                        self.plan.round(&*table, Instant::now())
                    }
                    Err(e) => {
                        if !self.read_failing {
                            self.read_failing = true;
                            warn!(code = %Issue::FeatureReadFailed, feature = self.name.as_str(), error = %e, "cannot read the feature map");
                        }
                        return;
                    }
                }
            }
            Source::Ring(fd) => {
                let Ok(mut guard) = fd.readable_mut().await else { return };
                let records = guard.get_inner_mut().drain(RING_BATCH);
                if records.len() < RING_BATCH {
                    guard.clear_ready();
                }
                self.plan.round(&records[..], Instant::now())
            }
        };
        self.bad += bad;
        let now = Instant::now();
        self.buffer.clear();
        let ts_ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
        self.plan.json(&mut self.buffer, ts_ms);
        match self.sink.write(&self.buffer) {
            Ok(()) => self.written += self.plan.len() as u64,
            Err(e) => {
                if !self.sink.failing {
                    self.sink.failing = true;
                    warn!(code = %Issue::FeatureOutputFailed, feature = self.name.as_str(), error = %e, "cannot write feature records");
                }
            }
        }
        debug!(feature = self.name.as_str(), records = self.plan.len(), "feature records written");
        if self.bad > self.bad_reported && now.duration_since(self.last_report) >= REPORT_EVERY {
            warn!(
                code = %Issue::FeatureRecordsDropped,
                feature = self.name.as_str(),
                dropped = self.bad - self.bad_reported,
                "feature records did not match the definition's size and were dropped"
            );
            self.bad_reported = self.bad;
            self.last_report = now;
        }
    }
}

struct Sink {
    path: PathBuf,
    file: BufWriter<File>,
    size: u64,
    max: u64,
    failing: bool,
}

impl Sink {
    fn open(dir: &Path, name: &str) -> io::Result<Self> {
        Self::open_with(dir, name, MAX_OUTPUT_BYTES)
    }

    fn open_with(dir: &Path, name: &str, max: u64) -> io::Result<Self> {
        fs::DirBuilder::new().recursive(true).mode(0o750).create(dir)?;
        let path = dir.join(format!("{name}.jsonl"));
        let file = OpenOptions::new().create(true).append(true).mode(0o640).open(&path)?;
        let size = file.metadata()?.len();
        Ok(Self { path, file: BufWriter::new(file), size, max, failing: false })
    }

    /// Appends whole lines; the file is renamed only between writes, so no line is split.
    fn write(&mut self, lines: &[u8]) -> io::Result<()> {
        if lines.is_empty() {
            return Ok(());
        }
        self.file.write_all(lines)?;
        self.size += lines.len() as u64;
        self.file.flush()?;
        if self.size >= self.max {
            self.rotate()?;
        }
        self.failing = false;
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        fs::rename(&self.path, self.path.with_extension("jsonl.1"))?;
        let file = OpenOptions::new().create(true).append(true).mode(0o640).open(&self.path)?;
        self.file = BufWriter::new(file);
        self.size = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
