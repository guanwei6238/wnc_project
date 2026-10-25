pub mod debian;

pub use debian::Debian as Current;

pub trait BootConfig {
    fn persist_module_hint(&self, module: &str) -> String;
    fn persist_sysctl_hint(&self, key: &str, value: &str) -> String;
}
