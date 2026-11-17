use std::time::Duration;

use tracing::{info, warn};

use crate::issue::Issue;
use crate::kernel::bpf::{TcxChain, TcxQueryError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Position {
    First,
    Behind(Vec<u32>),
    Detached,
    Unknown(String),
}

pub fn position(prog_id: u32, chain: Result<TcxChain, TcxQueryError>) -> Position {
    match chain {
        Ok(chain) => match chain.prog_ids.iter().position(|&id| id == prog_id) {
            Some(0) => Position::First,
            Some(i) => Position::Behind(chain.prog_ids[..i].to_vec()),
            None => Position::Detached,
        },
        Err(TcxQueryError::NoDevice(_)) => Position::Detached,
        Err(e) => Position::Unknown(e.to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedPort {
    pub name: String,
    pub ifindex: u32,
}

#[derive(Debug)]
pub struct CoreWatch {
    prog_id: u32,
    ports: Vec<(WatchedPort, Position)>,
}

impl CoreWatch {
    pub const INTERVAL: Duration = Duration::from_secs(10);

    pub fn new(prog_id: u32, ports: Vec<WatchedPort>) -> Self {
        let ports = ports.into_iter().map(|port| (port, Position::First)).collect();
        Self { prog_id, ports }
    }

    pub fn check(&mut self, query: impl Fn(u32) -> Result<TcxChain, TcxQueryError>) {
        for (port, now) in self.observe(query) {
            log(&port, self.prog_id, &now);
        }
    }

    fn observe(&mut self, query: impl Fn(u32) -> Result<TcxChain, TcxQueryError>) -> Vec<(String, Position)> {
        let mut changes = Vec::new();
        for (port, last) in &mut self.ports {
            let now = position(self.prog_id, query(port.ifindex));
            if now != *last {
                changes.push((port.name.clone(), now.clone()));
                *last = now;
            }
        }
        changes
    }
}

fn log(port: &str, prog_id: u32, now: &Position) {
    match now {
        Position::First => info!(port, prog_id, "the core ebpf program is first on tcx ingress again"),
        Position::Behind(ids) => {
            let before: Vec<String> = ids.iter().map(u32::to_string).collect();
            let before = before.join(",");
            warn!(
                code = %Issue::CoreProgramNotFirst,
                port,
                prog_id,
                before = before.as_str(),
                "other ebpf programs run before the core ebpf program on tcx ingress"
            );
        }
        Position::Detached => warn!(
            code = %Issue::CoreProgramDetached,
            port,
            prog_id,
            "the core ebpf program is no longer attached to this port"
        ),
        Position::Unknown(e) => warn!(
            code = %Issue::TcxUnchecked,
            port,
            error = e.as_str(),
            "cannot check the tcx programs on this port"
        ),
    }
}

#[cfg(test)]
mod tests;
