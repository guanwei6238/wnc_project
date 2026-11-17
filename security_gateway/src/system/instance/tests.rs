use std::os::unix::fs::PermissionsExt;

use super::*;

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("wnc-gw-instance-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn creates_the_directory_and_records_the_pid() {
    let scratch = Scratch::new("pid");
    let _lock = lock(&scratch.0).unwrap();
    let mode = std::fs::metadata(&scratch.0).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o750);
    let text = std::fs::read_to_string(scratch.0.join("wnc-gw.lock")).unwrap();
    assert_eq!(text, format!("{}\n", std::process::id()));
}

#[test]
fn second_lock_names_the_holder() {
    let scratch = Scratch::new("second");
    let _first = lock(&scratch.0).unwrap();
    let err = lock(&scratch.0).unwrap_err();
    let pid = std::process::id();
    assert!(matches!(err, InstanceError::AlreadyRunning { pid: Some(p) } if p == pid), "{err:?}");
    assert_eq!(err.to_string(), format!("another wnc-gw is running (pid {pid})"));
}

#[test]
fn released_when_dropped() {
    let scratch = Scratch::new("drop");
    drop(lock(&scratch.0).unwrap());
    assert!(lock(&scratch.0).is_ok());
}

#[test]
fn unknown_holder_has_no_pid() {
    assert_eq!(
        InstanceError::AlreadyRunning { pid: None }.to_string(),
        "another wnc-gw is running"
    );
}
