pub mod trust;

use crate::datapath::{CoreProgram, TrustError, TrustedFlow};
use crate::firewall;
use crate::kernel::bpf::BpfError;
use crate::kernel::conntrack::{Connection, Conntrack, ConntrackError, FiveTuple};

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
}

pub struct LocalPrivd {
    conntrack: Option<Conntrack>,
    core: Option<CoreProgram>,
}

impl LocalPrivd {
    pub fn new(core: Option<CoreProgram>) -> Self {
        Self { conntrack: None, core }
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

    pub fn trusted(&self) -> Result<Vec<TrustedFlow>, PrivdError> {
        let core = self.core.as_ref().ok_or(PrivdError::NoFastPath)?;
        core.trusted().map_err(|e: BpfError| PrivdError::Trust(e.into()))
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
        Ok(core.trust(tuple)?)
    }

    fn untrust(&mut self, tuple: &FiveTuple) -> Result<(), PrivdError> {
        let core = self.core.as_mut().ok_or(PrivdError::NoFastPath)?;
        match core.untrust(tuple)? {
            true => Ok(()),
            false => Err(PrivdError::NotTrusted),
        }
    }
}
