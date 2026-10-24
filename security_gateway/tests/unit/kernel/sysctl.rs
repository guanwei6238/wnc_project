use super::*;

#[test]
fn key_maps_to_proc_sys_path() {
    assert_eq!(path("net.ipv4.ip_forward"), PathBuf::from("/proc/sys/net/ipv4/ip_forward"));
    assert_eq!(
        path("net.bridge.bridge-nf-call-iptables"),
        PathBuf::from("/proc/sys/net/bridge/bridge-nf-call-iptables")
    );
}

#[test]
fn absent_key_is_none() {
    assert_eq!(read("wnc_gw_test.does_not_exist").unwrap(), None);
}

#[test]
fn existing_key_is_trimmed() {
    let value = read("kernel.osrelease").unwrap().unwrap();
    assert!(!value.is_empty() && !value.ends_with('\n'), "{value:?}");
}
