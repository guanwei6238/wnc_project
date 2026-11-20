pub mod btf;
pub mod check;
pub mod definition;
pub mod derive;
pub mod elf;
pub mod hook;
pub mod load;
pub mod pcap;
pub mod plan;
pub mod record;
pub mod runtime;

use std::time::Duration;

pub const MAX_PROGRAMS: usize = 16;
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);
