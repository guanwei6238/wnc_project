use std::fmt;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::Duration;

pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Code(i32),
    Signal(i32),
}

impl Exit {
    pub fn from_status(status: ExitStatus) -> Option<Self> {
        status.code().map(Self::Code).or_else(|| status.signal().map(Self::Signal))
    }
}

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::Code(code) => return write!(f, "exit code {code}"),
            Self::Signal(libc::SIGHUP) => "SIGHUP",
            Self::Signal(libc::SIGINT) => "SIGINT",
            Self::Signal(libc::SIGQUIT) => "SIGQUIT",
            Self::Signal(libc::SIGILL) => "SIGILL",
            Self::Signal(libc::SIGABRT) => "SIGABRT",
            Self::Signal(libc::SIGBUS) => "SIGBUS",
            Self::Signal(libc::SIGFPE) => "SIGFPE",
            Self::Signal(libc::SIGKILL) => "SIGKILL",
            Self::Signal(libc::SIGSEGV) => "SIGSEGV",
            Self::Signal(libc::SIGPIPE) => "SIGPIPE",
            Self::Signal(libc::SIGTERM) => "SIGTERM",
            Self::Signal(signal) => return write!(f, "signal {signal}"),
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Ready {
        pid: u32,
        startup: Duration,
    },
    Stopped {
        pid: u32,
        exit: Option<Exit>,
        uptime: Duration,
        was_ready: bool,
    },
}

pub trait Lifecycle {
    fn next_event(&mut self) -> impl Future<Output = Option<Event>>;
    fn allow_restart(&mut self);
    fn stop(self) -> impl Future<Output = ()>;
}

#[cfg(test)]
#[path = "../../tests/unit/ids/lifecycle.rs"]
mod tests;
