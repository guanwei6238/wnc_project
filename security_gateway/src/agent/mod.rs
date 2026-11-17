pub mod control;
pub mod idle;
pub mod nexthop;
pub mod trust;

use std::net::IpAddr;

use crate::datapath::{CoreProgram, TrustBackend, TrustError, TrustStore, TrustedFlow, firewall::{self, CtMarks}};
use crate::kernel::conntrack::{Connection, ConntrackError, FiveTuple, LazyConntrack};

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
    fn trusted(&mut self) -> Result<Vec<TrustedFlow>, PrivdError>;
}

pub struct LocalPrivd {
    conntrack: LazyConntrack,
    core: Option<CoreProgram>,
    backend: TrustBackend,
    marks: CtMarks,
    newly_trusted: Option<Vec<FiveTuple>>,
}

impl LocalPrivd {
    pub fn new(core: Option<CoreProgram>, backend: TrustBackend) -> Self {
        Self {
            conntrack: LazyConntrack::default(),
            core,
            backend,
            marks: CtMarks::default(),
            newly_trusted: None,
        }
    }

    pub fn backend(&self) -> TrustBackend {
        self.backend
    }

    pub fn can_trust(&self) -> bool {
        self.backend == TrustBackend::CtMark || self.core.is_some()
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
        self.conntrack.with(|conntrack| conntrack.get(tuple))
    }

    fn store(&mut self) -> Result<&mut dyn TrustStore, PrivdError> {
        match self.backend {
            TrustBackend::Tc => Ok(self.core.as_mut().ok_or(PrivdError::NoFastPath)?),
            TrustBackend::CtMark => Ok(&mut self.marks),
        }
    }
}

impl Privd for LocalPrivd {
    fn forwarded_connections(&mut self) -> Result<Vec<Connection>, ConntrackError> {
        self.conntrack.with(firewall::forwarded)
    }

    fn trust(&mut self, tuple: &FiveTuple) -> Result<(), PrivdError> {
        self.store()?.trust(tuple)?;
        if let Some(newly) = self.newly_trusted.as_mut() {
            newly.push(*tuple);
        }
        Ok(())
    }

    fn untrust(&mut self, tuple: &FiveTuple) -> Result<(), PrivdError> {
        match self.store()?.untrust(tuple)? {
            true => Ok(()),
            false => Err(PrivdError::NotTrusted),
        }
    }

    fn trusted(&mut self) -> Result<Vec<TrustedFlow>, PrivdError> {
        Ok(self.store()?.trusted()?)
    }
}

