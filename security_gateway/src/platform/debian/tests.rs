use super::*;

#[test]
fn module_hint_points_to_modules_load_d() {
    assert_eq!(
        Debian.persist_module_hint("br_netfilter"),
        "list it in /etc/modules-load.d/ to load it at boot"
    );
}

#[test]
fn sysctl_hint_points_to_sysctl_d() {
    assert_eq!(
        Debian.persist_sysctl_hint("net.ipv4.ip_forward", "1"),
        "persist it in /etc/sysctl.d/"
    );
}

#[test]
fn dirs_follow_systemd_runtime_and_logs_directories() {
    assert_eq!(Debian.runtime_dir(), Path::new("/run/wnc-gw"));
    assert_eq!(Debian.log_dir(), Path::new("/var/log/wnc-gw"));
}

#[test]
fn suricata_package_service() {
    assert_eq!(Debian.suricata_service(), "suricata.service");
}

#[test]
fn service_from_cgroup() {
    assert_eq!(Debian.service_of("/system.slice/suricata.service"), Some("suricata.service".to_owned()));
    assert_eq!(Debian.service_of("/user.slice/user-1000.slice/session-3.scope"), None);
    assert_eq!(Debian.service_of("/"), None);
}

fn exit(code: i32) -> ExitStatus {
    std::os::unix::process::ExitStatusExt::from_raw(code << 8)
}

#[test]
fn boot_states() {
    assert_eq!(boot_state("enabled\n", exit(0), ""), BootState::Enabled);
    assert_eq!(boot_state("disabled\n", exit(1), ""), BootState::Disabled);
    assert_eq!(boot_state("masked\n", exit(1), ""), BootState::Disabled);
    assert_eq!(boot_state("not-found\n", exit(4), ""), BootState::NotInstalled);
    assert_eq!(
        boot_state("static\n", exit(0), ""),
        BootState::Unknown("systemctl is-enabled reports static".into())
    );
}

#[test]
fn runtime_enablement_does_not_survive_a_reboot() {
    assert_eq!(boot_state("enabled-runtime\n", exit(0), ""), BootState::Disabled);
}

#[test]
fn failure_keeps_the_exit_status_and_stderr() {
    assert_eq!(
        boot_state("", exit(1), "System has not been booted with systemd as init system (PID 1)."),
        BootState::Unknown(
            "systemctl is-enabled failed (exit status: 1): System has not been booted with systemd as init system (PID 1)."
                .into()
        )
    );
    assert_eq!(
        boot_state("", exit(1), ""),
        BootState::Unknown("systemctl is-enabled printed nothing (exit status: 1)".into())
    );
}

#[test]
fn service_hints() {
    assert_eq!(Debian.stop_service_hint("suricata.service"), "systemctl disable --now suricata.service");
    assert_eq!(Debian.disable_service_hint("suricata.service"), "systemctl disable suricata.service");
}
