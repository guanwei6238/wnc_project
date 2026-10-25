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
