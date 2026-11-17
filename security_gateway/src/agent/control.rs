use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::{fs::{MetadataExt, PermissionsExt}, net::UnixStream as StdUnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::kernel::conntrack::{FiveTuple, Protocol};

pub const SOCKET_NAME: &str = "control.sock";
const MAX_MESSAGE: u64 = 64 * 1024;
const MAX_REPLY: u64 = 16 * 1024 * 1024;
const SERVER_READ_TIMEOUT: Duration = Duration::from_secs(1);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tuple {
    pub protocol: String,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl Tuple {
    pub fn of(tuple: &FiveTuple) -> Self {
        Self {
            protocol: tuple.protocol().to_string(),
            src: tuple.src(),
            dst: tuple.dst(),
        }
    }

    pub fn five_tuple(&self) -> Result<FiveTuple, String> {
        let protocol: Protocol = self.protocol.parse().map_err(|e| format!("{e}"))?;
        FiveTuple::new(protocol, self.src, self.dst).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    Trust { connection: Tuple },
    Untrust { connection: Tuple },
    List,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flow {
    pub connection: Tuple,
    pub packets_original: u64,
    pub bytes_original: u64,
    pub packets_reply: u64,
    pub bytes_reply: u64,
    pub next_hop_original: Option<IpAddr>,
    pub next_hop_reply: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum Response {
    Done,
    Trusted { flows: Vec<Flow> },
    Error { message: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("wnc-gw run is not running (cannot connect to {0})")]
    NotRunning(PathBuf),
    #[error("permission denied on {0}; run as root")]
    PermissionDenied(PathBuf),
    #[error("{path}: {error}")]
    Io { path: PathBuf, error: io::Error },
    #[error("the message is not valid: {0}")]
    Malformed(String),
    #[error("the message is longer than {MAX_MESSAGE} bytes")]
    TooLarge,
    #[error("no complete message within {}s", SERVER_READ_TIMEOUT.as_secs())]
    Timeout,
}

pub fn socket_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join(SOCKET_NAME)
}

pub fn request(path: &Path, request: &Request) -> Result<Response, ControlError> {
    let io_error = |error: io::Error| match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => ControlError::NotRunning(path.to_owned()),
        io::ErrorKind::PermissionDenied => ControlError::PermissionDenied(path.to_owned()),
        _ => ControlError::Io {
            path: path.to_owned(),
            error,
        },
    };
    let mut stream = StdUnixStream::connect(path).map_err(io_error)?;
    stream.set_read_timeout(Some(CLIENT_TIMEOUT)).map_err(io_error)?;
    stream.set_write_timeout(Some(CLIENT_TIMEOUT)).map_err(io_error)?;
    let mut line = serde_json::to_string(request).map_err(|e| ControlError::Malformed(e.to_string()))?;
    line.push('\n');
    stream.write_all(line.as_bytes()).map_err(io_error)?;
    let mut reply = String::new();
    BufReader::new(stream.take(MAX_REPLY)).read_line(&mut reply).map_err(io_error)?;
    serde_json::from_str(&reply).map_err(|e| ControlError::Malformed(e.to_string()))
}

pub struct ControlServer {
    listener: UnixListener,
    path: PathBuf,
    owner: u32,
}

pub struct Incoming {
    stream: UnixStream,
    pub uid: Option<u32>,
    pub allowed: bool,
}

impl ControlServer {
    pub fn bind(path: &Path) -> io::Result<Self> {
        match fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let owner = fs::metadata(path)?.uid();
        Ok(Self {
            listener,
            path: path.to_owned(),
            owner,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn accept(&self) -> io::Result<Incoming> {
        let (stream, _) = self.listener.accept().await?;
        let uid = stream.peer_cred().ok().map(|cred| cred.uid());
        let allowed = uid.is_some_and(|uid| uid == 0 || uid == self.owner);
        Ok(Incoming { stream, uid, allowed })
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl Incoming {
    pub async fn read(&mut self) -> Result<Request, ControlError> {
        let mut line = String::new();
        let mut reader = tokio::io::BufReader::new((&mut self.stream).take(MAX_MESSAGE));
        let read = tokio::time::timeout(SERVER_READ_TIMEOUT, reader.read_line(&mut line)).await;
        match read {
            Err(_) => return Err(ControlError::Timeout),
            Ok(Err(e)) => return Err(ControlError::Malformed(e.to_string())),
            Ok(Ok(_)) if !line.ends_with('\n') && line.len() as u64 >= MAX_MESSAGE => return Err(ControlError::TooLarge),
            Ok(Ok(_)) => {}
        }
        serde_json::from_str(&line).map_err(|e| ControlError::Malformed(e.to_string()))
    }

    pub async fn reply(mut self, response: &Response) {
        let Ok(mut line) = serde_json::to_string(response) else { return };
        line.push('\n');
        let _ = tokio::time::timeout(SERVER_READ_TIMEOUT, self.stream.write_all(line.as_bytes())).await;
    }
}

#[cfg(test)]
mod tests;
