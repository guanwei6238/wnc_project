use std::fs::{DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const LOCK_FILE: &str = "wnc-gw.lock";

#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
}

#[derive(Debug, thiserror::Error)]
pub enum InstanceError {
    #[error("another wnc-gw is running{}", .pid.map(|pid| format!(" (pid {pid})")).unwrap_or_default())]
    AlreadyRunning { pid: Option<u32> },
    #[error("failed to lock {}: {source}", .path.display())]
    Io { path: PathBuf, source: io::Error },
}

pub fn lock(runtime_dir: &Path) -> Result<InstanceLock, InstanceError> {
    let path = runtime_dir.join(LOCK_FILE);
    let io = |source| InstanceError::Io {
        path: path.clone(),
        source,
    };
    DirBuilder::new().recursive(true).mode(0o750).create(runtime_dir).map_err(io)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o640)
        .open(&path)
        .map_err(io)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            let mut text = String::new();
            let _ = file.read_to_string(&mut text);
            return Err(InstanceError::AlreadyRunning {
                pid: text.trim().parse().ok(),
            });
        }
        Err(TryLockError::Error(source)) => return Err(io(source)),
    }
    file.set_len(0).map_err(io)?;
    writeln!(file, "{}", std::process::id()).map_err(io)?;
    Ok(InstanceLock { _file: file })
}

#[cfg(test)]
#[path = "../tests/unit/instance.rs"]
mod tests;
