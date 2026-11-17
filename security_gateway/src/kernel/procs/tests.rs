use super::*;

#[test]
fn parses_parent_and_rss() {
    let status = "Name:\tSuricata-Main\nState:\tS (sleeping)\nPPid:\t1\nVmRSS:\t   72328 kB\nThreads:\t8\n";
    assert_eq!(parse_status(status), (Some('S'), Some(1), Some(72328)));
}

#[test]
fn kernel_threads_have_no_rss() {
    assert_eq!(parse_status("Name:\tkworker/0:1\nState:\tI (idle)\nPPid:\t2\n"), (Some('I'), Some(2), None));
    assert_eq!(parse_status("Name:\tSuricata-Main\nState:\tZ (zombie)\nPPid:\t1\n"), (Some('Z'), Some(1), None));
    assert_eq!(parse_status(""), (None, None, None));
}

#[test]
fn splits_cmdline_on_nul() {
    assert_eq!(
        parse_cmdline(b"/usr/bin/suricata\0-D\0--af-packet\0"),
        ["/usr/bin/suricata", "-D", "--af-packet"]
    );
    assert_eq!(parse_cmdline(b""), Vec::<String>::new());
}

#[test]
fn reads_the_unified_cgroup() {
    assert_eq!(
        parse_cgroup("0::/system.slice/suricata.service\n"),
        Some("/system.slice/suricata.service".to_owned())
    );
    assert_eq!(parse_cgroup("12:cpu:/x\n0::/\n"), Some("/".to_owned()));
    assert_eq!(parse_cgroup("12:cpu:/x\n"), None);
}

#[test]
fn finds_this_process() {
    let me = std::process::id();
    let mine = comm(me).unwrap();
    let found = find(|c| c == mine).unwrap();
    let p = found.iter().find(|p| p.pid == me).expect("this process");
    assert_eq!(p.ppid, Some(std::os::unix::process::parent_id()));
    assert!(matches!(p.state, Some('R' | 'S')), "{:?}", p.state);
    assert!(p.rss_kb.is_some_and(|kb| kb > 0));
    assert!(!p.cmdline.is_empty());
}

#[test]
fn parses_network_namespace_links() {
    assert_eq!(parse_net_ns("net:[4026531833]"), Some(4026531833));
    assert_eq!(parse_net_ns("mnt:[4026531833]"), None);
    assert_eq!(parse_net_ns("net:[x]"), None);
}

#[test]
fn hidepid_on_proc_only() {
    let mounts = |proc_options: &str| {
        format!("sysfs /sys sysfs rw,nosuid 0 0\nproc /proc proc {proc_options} 0 0\ntmpfs /run tmpfs rw 0 0\n")
    };
    assert!(!hidepid(&mounts("rw,nosuid,nodev,noexec,relatime")));
    assert!(!hidepid(&mounts("rw,relatime,hidepid=0")));
    assert!(!hidepid(&mounts("rw,relatime,hidepid=off")));
    assert!(hidepid(&mounts("rw,relatime,hidepid=invisible")));
    assert!(hidepid(&mounts("rw,relatime,hidepid=2")));
    assert!(!hidepid("proc /mnt/proc proc rw,hidepid=2 0 0\n"));
}

#[test]
fn root_is_the_effective_uid() {
    assert!(is_root("Name:\tx\nUid:\t1000\t0\t0\t0\n"));
    assert!(!is_root("Name:\tx\nUid:\t0\t1000\t1000\t1000\n"));
    assert!(!is_root(""));
}

#[test]
fn reads_own_network_namespace() {
    let me = std::process::id();
    let mine = comm(me).unwrap();
    let found = find(|c| c == mine).unwrap();
    let p = found.iter().find(|p| p.pid == me).expect("this process");
    assert!(p.net_ns.is_some());
    assert_eq!(p.net_ns, own_net_ns());
}
