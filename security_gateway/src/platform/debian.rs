use super::BootConfig;

const MODULES_LOAD_DIR: &str = "/etc/modules-load.d/";
const SYSCTL_DIR: &str = "/etc/sysctl.d/";

pub struct Debian;

impl BootConfig for Debian {
    fn persist_module_hint(&self, _module: &str) -> String {
        format!("list it in {MODULES_LOAD_DIR} to load it at boot")
    }

    fn persist_sysctl_hint(&self, _key: &str, _value: &str) -> String {
        format!("persist it in {SYSCTL_DIR}")
    }
}

#[cfg(test)]
#[path = "../../tests/unit/platform/debian.rs"]
mod tests;
