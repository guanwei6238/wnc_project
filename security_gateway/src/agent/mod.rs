pub mod control;
pub mod idle;
pub mod nexthop;
pub mod trust;

use std::net::IpAddr;

use crate::datapath::{CoreProgram, TrustError, TrustedFlow, firewall};
use crate::kernel::{bpf::BpfError, conntrack::{Connection, Conntrack, ConntrackError, FiveTuple}};

#[derive(Debug, thiserror::Error)]
pub enum PrivdError {
    #[error("the core eBPF program is not attached, so nothing can be trusted")]
    NoFastPath,
    #[error("connection is not trusted")]
    NotTrusted,
    #[error(transparent)]
    Trust(#[from] TrustError),
}

pub trait Privd {
    fn forwarded_connections(&mut self) -> Result<Vec<Connection>, ConntrackError>;
    fn trust(&mut self, tuple: &FiveTuple) -> Result<(), PrivdError>;
    fn untrust(&mut self, tuple: &FiveTuple) -> Result<(), PrivdError>;
    fn trusted(&self) -> Result<Vec<TrustedFlow>, PrivdError>;
}

pub struct LocalPrivd {
    conntrack: Option<Conntrack>,
    core: Option<CoreProgram>,
    newly_trusted: Option<Vec<FiveTuple>>,
}

impl LocalPrivd {
    pub fn new(core: Option<CoreProgram>) -> Self {
        Self {
            conntrack: None,
            core,
            newly_trusted: None,
        }
    }

    pub fn record_newly_trusted(&mut self, on: bool) {
        self.newly_trusted = on.then(Vec::new);
    }

    pub fn take_newly_trusted(&mut self) -> Vec<FiveTuple> {
        self.newly_trusted.as_mut().map(std::mem::take).unwrap_or_default()
    }

    pub fn route_generation(&self) -> Option<u32> {
        self.core.as_ref().map(CoreProgram::route_generation)
    }

    pub fn invalidate_next_hops(&mut self) -> Result<(), PrivdError> {
        let core = self.core.as_mut().ok_or(PrivdError::NoFastPath)?;
        core.invalidate_next_hops().map_err(|e| PrivdError::Trust(e.into()))
    }

    pub fn set_next_hops(
        &mut self,
        tuple: &FiveTuple,
        original: Option<IpAddr>,
        reply: Option<IpAddr>,
        generation: u32,
    ) -> Result<bool, PrivdError> {
        let core = self.core.as_mut().ok_or(PrivdError::NoFastPath)?;
        Ok(core.set_next_hops(tuple, original, reply, generation)?)
    }

    pub fn core(&self) -> Option<&CoreProgram> {
        self.core.as_ref()
    }

    pub fn into_core(self) -> Option<CoreProgram> {
        self.core
    }

    pub fn connection(&mut self, tuple: &FiveTuple) -> Result<Connection, ConntrackError> {
        self.with(|conntrack| conntrack.get(tuple))
    }

    fn with<T>(&mut self, op: impl FnOnce(&mut Conntrack) -> Result<T, ConntrackError>) -> Result<T, ConntrackError> {
        let conntrack = match self.conntrack.as_mut() {
            Some(conntrack) => conntrack,
            None => self.conntrack.insert(Conntrack::connect()?),
        };
        let result = op(conntrack);
        if matches!(
            result,
            Err(ConntrackError::Socket(_) | ConntrackError::NoReply | ConntrackError::Malformed(_))
        ) {
            self.conntrack = None;
        }
        result
    }
}

impl Privd for LocalPrivd {
    fn forwarded_connections(&mut self) -> Result<Vec<Connection>, ConntrackError> {
        self.with(firewall::forwarded)
    }

    fn trust(&mut self, tuple: &FiveTuple) -> Result<(), PrivdError> {
        let core = self.core.as_mut().ok_or(PrivdError::NoFastPath)?;
        core.trust(tuple)?;
        if let Some(newly) = self.newly_trusted.as_mut() {
            newly.push(*tuple);
        }
        Ok(())
    }

    fn untrust(&mut self, tuple: &FiveTuple) -> Result<(), PrivdError> {
        let core = self.core.as_mut().ok_or(PrivdError::NoFastPath)?;
        match core.untrust(tuple)? {
            true => Ok(()),
            false => Err(PrivdError::NotTrusted),
        }
    }

    fn trusted(&self) -> Result<Vec<TrustedFlow>, PrivdError> {
        let core = self.core.as_ref().ok_or(PrivdError::NoFastPath)?;
        core.trusted().map_err(|e: BpfError| PrivdError::Trust(e.into()))
    }
}
