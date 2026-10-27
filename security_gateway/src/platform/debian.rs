use std::ffi::OsStr;
use std::path::Path;
use std::process::ExitStatus;

use super::{BootConfig, BootState, Dirs, Services};
use crate::command;

const MODULES_LOAD_DIR: &str = "/etc/modules-load.d/";
const SYSCTL_DIR: &str = "/etc/sysctl.d/";
const RUNTIME_DIR: &str = "/run/wnc-gw";
const LOG_DIR: &str = "/var/log/wnc-gw";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const SURICATA_SERVICE: &str = "suricata.service";

pub struct Debian;

impl BootConfig for Debian {
    fn persist_module_hint(&self, _module: &str) -> String {
        format!("list it in {MODULES_LOAD_DIR} to load it at boot")
    }

    fn persist_sysctl_hint(&self, _key: &str, _value: &str) -> String {
        format!("persist it in {SYSCTL_DIR}")
    }
}

impl Dirs for Debian {
    fn runtime_dir(&self) -> &'static Path {
        Path::new(RUNTIME_DIR)
    }

    fn log_dir(&self) -> &'static Path {
        Path::new(LOG_DIR)
    }
}

impl Services for Debian {
    fn suricata_service(&self) -> &'static str {
        SURICATA_SERVICE
    }

    fn service_of(&self, cgroup: &str) -> Option<String> {
        let unit = cgroup.rsplit('/').next()?;
        unit.ends_with(".service").then(|| unit.to_owned())
    }

    async fn starts_at_boot(&self, service: &str) -> BootState {
        let args = [OsStr::new("is-enabled"), OsStr::new(service)];
        match command::output(Path::new(SYSTEMCTL), &args, b"").await {
            Ok(output) => boot_state(&String::from_utf8_lossy(&output.stdout), output.status, &output.stderr),
            Err(e) => BootState::Unknown(e.to_string()),
        }
    }

    fn stop_service_hint(&self, service: &str) -> String {
        format!("systemctl disable --now {service}")
    }

    fn disable_service_hint(&self, service: &str) -> String {
        format!("systemctl disable {service}")
    }
}

fn boot_state(stdout: &str, status: ExitStatus, stderr: &str) -> BootState {
    match stdout.lines().next().unwrap_or("").trim() {
        "enabled" => BootState::Enabled,
        "disabled" | "enabled-runtime" | "masked" | "masked-runtime" | "linked" | "linked-runtime" => {
            BootState::Disabled
        }
        "not-found" => BootState::NotInstalled,
        "" if stderr.is_empty() => BootState::Unknown(format!("systemctl is-enabled printed nothing ({status})")),
        "" => BootState::Unknown(format!("systemctl is-enabled failed ({status}): {stderr}")),
        other => BootState::Unknown(format!("systemctl is-enabled reports {other}")),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/platform/debian.rs"]
mod tests;
