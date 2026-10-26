pub mod debian;

use std::path::Path;

pub use debian::Debian as Current;

pub trait BootConfig {
    fn persist_module_hint(&self, module: &str) -> String;
    fn persist_sysctl_hint(&self, key: &str, value: &str) -> String;
}

pub trait Dirs {
    fn runtime_dir(&self) -> &'static Path;
    fn log_dir(&self) -> &'static Path;
}
