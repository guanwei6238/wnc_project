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
