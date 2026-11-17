use super::*;

#[test]
fn defaults_to_group_10() {
    assert_eq!(GroupRange::default().to_string(), "10");
}

#[test]
fn parses_single_groups_and_ranges() {
    for s in ["1", "10", "10-11", "65535"] {
        assert_eq!(s.parse::<GroupRange>().unwrap().to_string(), s);
    }
    assert_eq!("10-12".parse::<GroupRange>().unwrap().groups().collect::<Vec<_>>(), [10, 11, 12]);
}

#[test]
fn rejects_group_0_and_bad_ranges() {
    for s in ["0", "0-3", "11-10", "x", "65536", ""] {
        assert_eq!(s.parse::<GroupRange>(), Err(ParseGroupRangeError(s.to_owned())), "{s:?}");
    }
    assert_eq!(
        "0".parse::<GroupRange>().unwrap_err().to_string(),
        "invalid group \"0\" (expected a number from 1 to 65535 such as 10, or a range such as \"10-11\")"
    );
}

#[test]
fn deserializes_numbers_and_strings() {
    #[derive(serde::Deserialize)]
    struct T {
        group: GroupRange,
    }
    assert_eq!(toml::from_str::<T>("group = 12").unwrap().group.to_string(), "12");
    assert_eq!(toml::from_str::<T>("group = \"10-11\"").unwrap().group.to_string(), "10-11");
    assert!(toml::from_str::<T>("group = 0").is_err());
}

const NETLINK: &str = "\
sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode
0000000000000000 0   1954       00000000 960      0        0     2        0        217212
0000000000000000 12  10739      00000000 0        0        0     2        337      901
0000000000000000 12  0          00000000 0        0        0     2        0        902
0000000000000000 12  4125055223 00000000 2304     0        0     2        -2       903
";

#[test]
fn keeps_only_netfilter_sockets_with_their_drops() {
    assert_eq!(
        parse_netlink(NETLINK),
        [
            NetfilterSocket { inode: 901, drops: 337 },
            NetfilterSocket { inode: 902, drops: 0 },
            NetfilterSocket { inode: 903, drops: u32::MAX - 1 },
        ]
    );
}

#[test]
fn unexpected_header_yields_nothing() {
    assert_eq!(parse_netlink(""), []);
    assert_eq!(parse_netlink("sk Eth Pid\n0 12 1\n"), []);
}

#[test]
fn reads_socket_inodes_from_fd_links() {
    assert_eq!(socket_inode("socket:[901]"), Some(901));
    assert_eq!(socket_inode("pipe:[901]"), None);
    assert_eq!(socket_inode("/dev/null"), None);
}

#[test]
fn reads_own_process() {
    let sockets = netfilter_sockets(std::process::id()).unwrap();
    assert!(sockets.iter().all(|s| s.inode > 0));
}
