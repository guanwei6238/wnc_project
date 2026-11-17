use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

pub const DEFAULT_FILENAME: &str = "eve.json";
pub const MAX_LINE: usize = 1 << 20;
const CHUNK: usize = 1 << 20;
const READ_BUDGET: u64 = 32 << 20;
const ALERT_MARKER: &[u8] = br#""event_type":"alert""#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EveInterval(Duration);

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error(
    "invalid eve_interval {0} (expected {min} to {max} seconds)",
    min = EveInterval::MIN_MS as f64 / 1000.0,
    max = EveInterval::MAX_MS as f64 / 1000.0
)]
pub struct EveIntervalError(f64);

impl EveInterval {
    const MIN_MS: u64 = 50;
    const MAX_MS: u64 = 10_000;
    const DEFAULT_MS: u64 = 500;

    pub fn from_secs(secs: f64) -> Result<Self, EveIntervalError> {
        let ms = (secs * 1000.0).round();
        if ms >= Self::MIN_MS as f64 && ms <= Self::MAX_MS as f64 {
            Ok(Self(Duration::from_millis(ms as u64)))
        } else {
            Err(EveIntervalError(secs))
        }
    }

    pub fn duration(self) -> Duration {
        self.0
    }
}

impl Default for EveInterval {
    fn default() -> Self {
        Self(Duration::from_millis(Self::DEFAULT_MS))
    }
}

impl fmt::Display for EveInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} s", self.0.as_millis() as f64 / 1000.0)
    }
}

impl<'de> Deserialize<'de> for EveInterval {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let secs = f64::deserialize(deserializer)?;
        Self::from_secs(secs).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub flow_id: Option<u64>,
    pub protocol: String,
    pub src: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst: Option<IpAddr>,
    pub dst_port: Option<u16>,
    pub signature_id: u64,
    pub signature: String,
    pub action: String,
}

impl Alert {
    pub fn connection(&self) -> String {
        let protocol = self.protocol.to_ascii_lowercase();
        let ip = |ip: Option<IpAddr>| ip.map_or_else(|| "-".to_owned(), |ip| ip.to_string());
        match (self.src, self.src_port, self.dst, self.dst_port) {
            (Some(src), Some(sp), Some(dst), Some(dp)) => {
                format!("{protocol} {} -> {}", SocketAddr::new(src, sp), SocketAddr::new(dst, dp))
            }
            _ => format!("{protocol} {} -> {}", ip(self.src), ip(self.dst)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid EVE alert: {0}")]
pub struct ParseAlertError(String);

#[derive(Deserialize)]
struct RawEvent {
    event_type: String,
    flow_id: Option<u64>,
    #[serde(default)]
    proto: String,
    src_ip: Option<IpAddr>,
    src_port: Option<u16>,
    dest_ip: Option<IpAddr>,
    dest_port: Option<u16>,
    alert: Option<RawAlert>,
}

#[derive(Deserialize)]
struct RawAlert {
    signature_id: u64,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    action: String,
}

pub fn parse_alert(line: &[u8]) -> Result<Option<Alert>, ParseAlertError> {
    if !line.windows(ALERT_MARKER.len()).any(|w| w == ALERT_MARKER) {
        return Ok(None);
    }
    let event: RawEvent = serde_json::from_slice(line).map_err(|e| ParseAlertError(e.to_string()))?;
    if event.event_type != "alert" {
        return Ok(None);
    }
    let alert = event.alert.ok_or_else(|| ParseAlertError("missing \"alert\"".to_owned()))?;
    Ok(Some(Alert {
        flow_id: event.flow_id,
        protocol: event.proto,
        src: event.src_ip,
        src_port: event.src_port,
        dst: event.dest_ip,
        dst_port: event.dest_port,
        signature_id: alert.signature_id,
        signature: alert.signature,
        action: alert.action,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restart {
    Appeared,
    Replaced,
    Truncated,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReadReport {
    pub lines: u64,
    pub too_long: u64,
    pub restart: Option<Restart>,
    pub behind: bool,
}

#[derive(Debug)]
struct OpenFile {
    file: File,
    id: (u64, u64),
    offset: u64,
}

#[derive(Debug)]
pub struct EveFile {
    path: PathBuf,
    open: Option<OpenFile>,
    partial: Vec<u8>,
    skip_partial: bool,
    buf: Vec<u8>,
}

impl EveFile {
    pub fn open_at_end(path: impl Into<PathBuf>) -> Self {
        let mut eve = Self {
            path: path.into(),
            open: None,
            partial: Vec::new(),
            skip_partial: false,
            buf: Vec::new(),
        };
        if let Ok(file) = File::open(&eve.path)
            && let Ok(meta) = file.metadata()
        {
            let len = meta.len();
            eve.skip_partial = len > 0 && !ends_with_newline(&file, len);
            eve.open = Some(OpenFile {
                id: file_id(&meta),
                offset: len,
                file,
            });
        }
        eve
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read(&mut self, mut on_line: impl FnMut(&[u8])) -> io::Result<ReadReport> {
        let mut report = ReadReport::default();
        let current = match fs::metadata(&self.path) {
            Ok(meta) => Some(meta),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        match (self.open.as_ref().map(|open| open.id), current.as_ref()) {
            (None, None) => return Err(io::Error::new(io::ErrorKind::NotFound, "no such file")),
            (Some(_), None) => {}
            (Some(id), Some(meta)) if id == file_id(meta) => {
                if let Some(open) = self.open.as_mut()
                    && meta.len() < open.offset
                {
                    open.offset = 0;
                    self.partial.clear();
                    self.skip_partial = false;
                    report.restart = Some(Restart::Truncated);
                }
            }
            (_, Some(_)) => {
                let replaced = match self.open.take() {
                    Some(mut old) => {
                        self.read_from(&mut old, &mut on_line, &mut report)?;
                        self.partial.clear();
                        self.skip_partial = false;
                        true
                    }
                    None => false,
                };
                let file = File::open(&self.path)?;
                let id = file_id(&file.metadata()?);
                self.open = Some(OpenFile { file, id, offset: 0 });
                report.restart = Some(if replaced { Restart::Replaced } else { Restart::Appeared });
            }
        }
        if let Some(mut open) = self.open.take() {
            let result = self.read_from(&mut open, &mut on_line, &mut report);
            self.open = Some(open);
            result?;
        }
        Ok(report)
    }

    fn read_from(
        &mut self,
        open: &mut OpenFile,
        on_line: &mut impl FnMut(&[u8]),
        report: &mut ReadReport,
    ) -> io::Result<()> {
        open.file.seek(SeekFrom::Start(open.offset))?;
        let mut buf = mem::take(&mut self.buf);
        buf.resize(CHUNK, 0);
        let mut total = 0;
        let result = loop {
            if total >= READ_BUDGET {
                report.behind = true;
                break Ok(());
            }
            let n = match open.file.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => break Err(e),
            };
            open.offset += n as u64;
            total += n as u64;
            self.split(&buf[..n], on_line, report);
        };
        self.buf = buf;
        result
    }

    fn split(&mut self, mut data: &[u8], on_line: &mut impl FnMut(&[u8]), report: &mut ReadReport) {
        while let Some(end) = data.iter().position(|&b| b == b'\n') {
            let head = &data[..end];
            data = &data[end + 1..];
            if mem::take(&mut self.skip_partial) {
                self.partial.clear();
            } else if self.partial.is_empty() {
                deliver(head, on_line, report);
            } else if self.partial.len() + head.len() > MAX_LINE {
                self.partial.clear();
                report.too_long += 1;
            } else {
                self.partial.extend_from_slice(head);
                deliver(&self.partial, on_line, report);
                self.partial.clear();
            }
        }
        if data.is_empty() || self.skip_partial {
            return;
        }
        if self.partial.len() + data.len() > MAX_LINE {
            self.partial.clear();
            self.skip_partial = true;
            report.too_long += 1;
        } else {
            self.partial.extend_from_slice(data);
        }
    }
}

fn deliver(line: &[u8], on_line: &mut impl FnMut(&[u8]), report: &mut ReadReport) {
    if line.len() > MAX_LINE {
        report.too_long += 1;
    } else if !line.is_empty() {
        report.lines += 1;
        on_line(line);
    }
}

fn file_id(meta: &Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

fn ends_with_newline(file: &File, len: u64) -> bool {
    let mut last = [0];
    matches!(file.read_at(&mut last, len - 1), Ok(1) if last[0] == b'\n')
}

#[cfg(test)]
mod tests;
