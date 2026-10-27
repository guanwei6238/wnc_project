use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("{} not found", .path.display())]
    NotFound { path: PathBuf },
    #[error("failed to run {}: {source}", .path.display())]
    Spawn { path: PathBuf, source: io::Error },
    #[error("{} did not finish within {} seconds", .path.display(), TIMEOUT.as_secs())]
    Timeout { path: PathBuf },
    #[error("{} failed ({status}): {stderr}", .path.display())]
    Failed {
        path: PathBuf,
        status: ExitStatus,
        stderr: String,
    },
}

#[derive(Debug)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

pub async fn output(path: &Path, args: &[&OsStr], input: &[u8]) -> Result<Output, CommandError> {
    let path_buf = || path.to_path_buf();
    let mut child = match Command::new(path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(CommandError::NotFound { path: path_buf() }),
        Err(source) => return Err(CommandError::Spawn { path: path_buf(), source }),
    };
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let output = async move {
        match stdin.write_all(input).await {
            Err(e) if e.kind() != io::ErrorKind::BrokenPipe => return Err(e),
            _ => drop(stdin),
        }
        child.wait_with_output().await
    };
    match tokio::time::timeout(TIMEOUT, output).await {
        Err(_) => Err(CommandError::Timeout { path: path_buf() }),
        Ok(Err(source)) => Err(CommandError::Spawn { path: path_buf(), source }),
        Ok(Ok(output)) => Ok(Output {
            status: output.status,
            stdout: output.stdout,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }),
    }
}

pub async fn run(path: &Path, args: &[&OsStr], input: &[u8]) -> Result<Vec<u8>, CommandError> {
    let output = output(path, args, input).await?;
    if !output.status.success() {
        return Err(CommandError::Failed {
            path: path.to_path_buf(),
            status: output.status,
            stderr: output.stderr,
        });
    }
    Ok(output.stdout)
}

#[cfg(test)]
#[path = "../tests/unit/command.rs"]
mod tests;
