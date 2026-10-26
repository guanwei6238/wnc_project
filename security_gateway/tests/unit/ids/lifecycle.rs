use super::*;

#[test]
fn exit_from_status() {
    assert_eq!(Exit::from_status(ExitStatus::from_raw(3 << 8)), Some(Exit::Code(3)));
    assert_eq!(Exit::from_status(ExitStatus::from_raw(libc::SIGSEGV)), Some(Exit::Signal(libc::SIGSEGV)));
}

#[test]
fn exit_display() {
    assert_eq!(Exit::Code(0).to_string(), "exit code 0");
    assert_eq!(Exit::Code(1).to_string(), "exit code 1");
    assert_eq!(Exit::Signal(libc::SIGSEGV).to_string(), "SIGSEGV");
    assert_eq!(Exit::Signal(libc::SIGTERM).to_string(), "SIGTERM");
    assert_eq!(Exit::Signal(libc::SIGKILL).to_string(), "SIGKILL");
    assert_eq!(Exit::Signal(40).to_string(), "signal 40");
}
