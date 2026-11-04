pub mod trust;

use crate::firewall;
use crate::kernel::conntrack::{Connection, Conntrack, ConntrackError, FiveTuple};

pub trait Privd {
    fn forwarded_connections(&mut self) -> Result<Vec<Connection>, ConntrackError>;
    fn trust(&mut self, tuple: &FiveTuple) -> Result<(), ConntrackError>;
    fn untrust(&mut self, tuple: &FiveTuple) -> Result<(), ConntrackError>;
}

#[derive(Default)]
pub struct LocalPrivd {
    conntrack: Option<Conntrack>,
}

impl LocalPrivd {
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

    fn trust(&mut self, tuple: &FiveTuple) -> Result<(), ConntrackError> {
        self.with(|conntrack| firewall::trust(conntrack, tuple))
    }

    fn untrust(&mut self, tuple: &FiveTuple) -> Result<(), ConntrackError> {
        self.with(|conntrack| firewall::untrust(conntrack, tuple))
    }
}
