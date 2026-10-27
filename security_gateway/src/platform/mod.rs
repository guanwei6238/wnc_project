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

pub trait Services {
    fn suricata_service(&self) -> &'static str;
    fn service_of(&self, cgroup: &str) -> Option<String>;
    fn starts_at_boot(&self, service: &str) -> impl Future<Output = BootState>;
    fn stop_service_hint(&self, service: &str) -> String;
    fn disable_service_hint(&self, service: &str) -> String;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootState {
    Enabled,
    Disabled,
    NotInstalled,
    Unknown(String),
}
