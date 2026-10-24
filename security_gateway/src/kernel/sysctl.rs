use std::io;
use std::path::PathBuf;

const PROC_SYS: &str = "/proc/sys";

#[derive(Debug, thiserror::Error)]
#[error("failed to read {}: {source}", .path.display())]
pub struct SysctlError {
    path: PathBuf,
    source: io::Error,
}

pub fn read(key: &str) -> Result<Option<String>, SysctlError> {
    let path = path(key);
    match std::fs::read_to_string(&path) {
        Ok(value) => Ok(Some(value.trim().to_owned())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(SysctlError { path, source }),
    }
}

fn path(key: &str) -> PathBuf {
    let mut path = PathBuf::from(PROC_SYS);
    path.extend(key.split('.'));
    path
}

#[cfg(test)]
#[path = "../../tests/unit/kernel/sysctl.rs"]
mod tests;
