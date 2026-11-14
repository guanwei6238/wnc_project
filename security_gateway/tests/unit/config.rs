use super::*;
use crate::datapath::XdpPolicy;
use crate::kernel::netif::MacAddr;

const PHY: MacAddr = MacAddr([0x9c, 0x69, 0xd3, 0x2a, 0x11, 0x54]);

fn name(s: &str) -> PortSelector {
    PortSelector::Name(s.to_owned())
}

#[test]
fn parse_ports() {
    let config = parse("[ports]\nlan = \"eth0\"\nwan = \"9c:69:d3:2a:11:54\"\n").unwrap();
    assert_eq!(config.ports.lan, Some(name("eth0")));
    assert_eq!(config.ports.wan, Some(PortSelector::Mac(PHY)));
}

#[test]
fn parse_mode() {
    let config = parse("mode = \"routed\"\n").unwrap();
    assert_eq!(config.mode, Some(Mode::Routed));
}

#[test]
fn parse_rejects_invalid_mode() {
    let err = parse("mode = \"bridged\"\n").unwrap_err();
    assert!(err.contains("invalid mode \"bridged\""), "{err}");
}

#[test]
fn parse_xdp() {
    let config = parse("xdp = \"off\"\n").unwrap();
    assert_eq!(config.xdp, Some(XdpPolicy::Off));
}

#[test]
fn parse_rejects_invalid_xdp() {
    let err = parse("xdp = \"native\"\n").unwrap_err();
    assert!(err.contains("invalid xdp setting \"native\""), "{err}");
}

#[test]
fn parse_empty_file() {
    let config = parse("").unwrap();
    assert_eq!(config.mode, None);
    assert_eq!(config.ports.lan, None);
    assert_eq!(config.ports.wan, None);
}

#[test]
fn parse_rejects_unknown_field() {
    let err = parse("[ports]\nlna = \"eth0\"\n").unwrap_err();
    assert!(err.contains("unknown field"), "{err}");
}

#[test]
fn parse_rejects_unknown_section() {
    let err = parse("[port]\nlan = \"eth0\"\n").unwrap_err();
    assert!(err.contains("unknown field"), "{err}");
}

#[test]
fn parse_rejects_invalid_selector() {
    let err = parse("[ports]\nlan = \"eth/0\"\n").unwrap_err();
    assert!(err.contains("invalid interface name or MAC address"), "{err}");
}

#[test]
fn parse_rejects_wrong_type() {
    assert!(parse("[ports]\nlan = 1\n").is_err());
}

#[test]
fn merge_from_file() {
    let file_config = parse("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n").unwrap();
    let config = merge(Some("/x.toml".into()), file_config, Overrides::default()).unwrap();
    assert_eq!(config.file, Some(PathBuf::from("/x.toml")));
    assert_eq!(config.mode, Setting { value: Mode::Bridge, source: Source::Default });
    assert_eq!(config.xdp, Setting { value: XdpPolicy::Auto, source: Source::Default });
    assert_eq!(config.lan, Setting { value: name("eth0"), source: Source::File });
    assert_eq!(config.wan, Setting { value: name("eth1"), source: Source::File });
}

#[test]
fn mode_from_file() {
    let file_config =
        parse("mode = \"routed\"\nxdp = \"generic\"\n[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n").unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(config.mode, Setting { value: Mode::Routed, source: Source::File });
    assert_eq!(config.xdp, Setting { value: XdpPolicy::Generic, source: Source::File });
}

#[test]
fn command_line_overrides_file() {
    let file_config = parse("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n").unwrap();
    let overrides = Overrides {
        lan: Some(name("eth2")),
        wan: None,
    };
    let config = merge(None, file_config, overrides).unwrap();
    assert_eq!(config.lan, Setting { value: name("eth2"), source: Source::CommandLine });
    assert_eq!(config.wan, Setting { value: name("eth1"), source: Source::File });
}

#[test]
fn missing_role_is_an_error() {
    let file_config = parse("[ports]\nlan = \"eth0\"\n").unwrap();
    let err = merge(None, file_config, Overrides::default()).unwrap_err();
    assert!(matches!(err, ConfigError::Missing { role: Role::Wan }));
    assert_eq!(
        err.to_string(),
        "WAN port is not specified (set ports.wan in the config file or pass --wan)"
    );
}

#[test]
fn port_specs_in_role_order() {
    let file_config = parse("[ports]\nlan = \"eth0\"\nwan = \"9c:69:d3:2a:11:54\"\n").unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(
        config.port_specs(),
        vec![
            PortSpec { role: Role::Lan, selector: name("eth0") },
            PortSpec { role: Role::Wan, selector: PortSelector::Mac(PHY) },
        ]
    );
}

#[test]
fn missing_default_file_uses_command_line() {
    let overrides = Overrides {
        lan: Some(name("eth0")),
        wan: Some(name("eth1")),
    };
    let config = load_from(PathBuf::from("/nonexistent/setting.toml"), false, overrides).unwrap();
    assert_eq!(config.file, None);
    assert_eq!(config.lan.source, Source::CommandLine);
}

#[test]
fn missing_explicit_file_is_an_error() {
    let overrides = Overrides {
        lan: Some(name("eth0")),
        wan: Some(name("eth1")),
    };
    let err = load(Some(Path::new("/nonexistent/setting.toml")), overrides).unwrap_err();
    assert!(matches!(err, ConfigError::Read { ref source, .. } if source.kind() == io::ErrorKind::NotFound));
}

#[test]
fn load_reads_file() {
    let path = std::env::temp_dir().join(format!("wnc-gw-config-test-{}.toml", std::process::id()));
    std::fs::write(&path, "[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n").unwrap();
    let result = load(Some(&path), Overrides::default());
    std::fs::remove_file(&path).unwrap();
    let config = result.unwrap();
    assert_eq!(config.file, Some(path));
    assert_eq!(config.wan.value, name("eth1"));
}

const EXAMPLE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/setting.example.toml"));

#[test]
fn example_sets_nothing_by_default() {
    let config = parse(EXAMPLE).unwrap();
    assert_eq!(config.mode, None);
    assert_eq!(config.xdp, None);
    assert_eq!(config.protection, None);
    assert_eq!(config.ports.lan, None);
    assert_eq!(config.ports.wan, None);
    assert_eq!(config.nftables.path, None);
    assert_eq!(config.suricata.path, None);
    assert_eq!(config.suricata.config, None);
    assert_eq!(config.suricata.queue, None);
    assert_eq!(config.suricata.group, None);
    assert_eq!(config.suricata.ready_timeout, None);
    assert_eq!(config.suricata.stop_timeout, None);
    assert_eq!(config.suricata.when_unavailable, None);
    assert_eq!(config.suricata.eve_interval, None);
    assert_eq!(config.trust.auto, None);
    assert_eq!(config.trust.min_packets, None);
    assert_eq!(config.trust.min_age, None);
    assert_eq!(config.trust.ttl, None);
    assert_eq!(config.trust.check_interval, None);
}

#[test]
fn example_values_are_valid() {
    let uncommented = EXAMPLE
        .lines()
        .map(|line| match line.strip_prefix("# ") {
            Some(rest)
                if rest
                    .split_once(" = ")
                    .is_some_and(|(key, _)| key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')) =>
            {
                rest
            }
            _ => line,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config = parse(&uncommented).unwrap();
    assert!(config.mode.is_some());
    assert!(config.xdp.is_some());
    assert!(config.protection.is_some());
    assert!(config.ports.lan.is_some());
    assert!(config.ports.wan.is_some());
    assert!(config.nftables.path.is_some());
    assert!(config.suricata.path.is_some());
    assert!(config.suricata.config.is_some());
    assert!(config.suricata.queue.is_some());
    assert!(config.suricata.group.is_some());
    assert!(config.suricata.ready_timeout.is_some());
    assert!(config.suricata.stop_timeout.is_some());
    assert!(config.suricata.when_unavailable.is_some());
    assert!(config.suricata.eve_interval.is_some());
    assert!(config.trust.auto.is_some());
    assert!(config.trust.min_packets.is_some());
    assert!(config.trust.min_age.is_some());
    assert!(config.trust.ttl.is_some());
    assert!(config.trust.check_interval.is_some());
}

#[test]
fn eve_interval_defaults_to_half_a_second() {
    let file_config = parse("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n").unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(config.suricata.eve_interval.value.duration(), Duration::from_millis(500));
    assert_eq!(config.suricata.eve_interval.source, Source::Default);
}

#[test]
fn eve_interval_from_file() {
    for (value, ms) in [("0.05", 50), ("2", 2000), ("1.5", 1500)] {
        let file_config =
            parse(&format!("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n[suricata]\neve_interval = {value}\n")).unwrap();
        let config = merge(None, file_config, Overrides::default()).unwrap();
        assert_eq!(config.suricata.eve_interval.value.duration(), Duration::from_millis(ms));
        assert_eq!(config.suricata.eve_interval.source, Source::File);
    }
}

#[test]
fn parse_rejects_eve_interval_out_of_range() {
    for value in ["0", "0.04", "10.5", "-1"] {
        let err = parse(&format!("[suricata]\neve_interval = {value}\n")).unwrap_err();
        assert!(err.contains("expected 0.05 to 10 seconds"), "{err}");
    }
}

#[test]
fn trust_defaults_to_manual() {
    let file_config = parse("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n").unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(config.trust, TrustSettings::Manual { source: Source::Default });
}

#[test]
fn automatic_trust_defaults() {
    let file_config = parse("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n[trust]\nauto = true\n").unwrap();
    let TrustSettings::Auto(trust) = merge(None, file_config, Overrides::default()).unwrap().trust else {
        panic!("expected automatic trust");
    };
    assert_eq!(trust.source, Source::File);
    assert_eq!(trust.min_packets, Setting { value: 10, source: Source::Default });
    assert_eq!(trust.min_age.value, Duration::from_secs(5));
    assert_eq!(trust.ttl.value, Duration::from_secs(900));
    assert_eq!(trust.check_interval.value, Duration::from_secs(5));
}

#[test]
fn trust_from_file() {
    let file_config = parse(
        "[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n[trust]\nauto = true\nmin_packets = 3\nmin_age = 2\nttl = 30\ncheck_interval = 1\n",
    )
    .unwrap();
    let TrustSettings::Auto(trust) = merge(None, file_config, Overrides::default()).unwrap().trust else {
        panic!("expected automatic trust");
    };
    assert_eq!(trust.min_packets, Setting { value: 3, source: Source::File });
    assert_eq!(trust.min_age.value, Duration::from_secs(2));
    assert_eq!(trust.ttl.value, Duration::from_secs(30));
    assert_eq!(trust.check_interval.value, Duration::from_secs(1));
}

#[test]
fn trust_values_without_automatic_trust_are_an_error() {
    for auto in ["", "auto = false\n"] {
        let file_config = parse(&format!("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n[trust]\n{auto}ttl = 30\nmin_age = 2\n")).unwrap();
        let err = merge(Some(PathBuf::from("/etc/wnc-gw/setting.toml")), file_config, Overrides::default()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "config file /etc/wnc-gw/setting.toml sets options that do not apply: trust.min_age (only with \
             trust.auto = true), trust.ttl (only with trust.auto = true); remove them or change the setting they \
             depend on"
        );
    }
}

#[test]
fn parse_rejects_trust_values_out_of_range() {
    for (key, value, range) in [
        ("min_packets", 0, "1 to 1000000"),
        ("min_age", 3601, "1 to 3600"),
        ("ttl", 9, "10 to 86400"),
        ("check_interval", 61, "1 to 60"),
    ] {
        let err = parse(&format!("[trust]\n{key} = {value}\n")).unwrap_err();
        assert!(err.contains(&format!("expected {range}")), "{err}");
    }
}

#[test]
fn parse_rejects_unknown_trust_field() {
    assert!(parse("[trust]\nautomatic = true\n").is_err());
}

fn path(s: &str) -> AbsolutePath {
    s.parse().unwrap()
}

#[test]
fn absolute_path_round_trips() {
    assert_eq!(path("/usr/bin/suricata").to_string(), "/usr/bin/suricata");
    assert_eq!(path("/usr/bin/suricata").as_path(), Path::new("/usr/bin/suricata"));
}

#[test]
fn relative_path_is_rejected() {
    for s in ["suricata", "bin/suricata", "./suricata", ""] {
        assert_eq!(
            s.parse::<AbsolutePath>().unwrap_err().to_string(),
            format!("invalid path {s:?} (expected an absolute path)")
        );
    }
}

#[test]
fn parse_rejects_relative_path() {
    let err = parse("[suricata]\npath = \"suricata\"\n").unwrap_err();
    assert!(err.contains("expected an absolute path"), "{err}");
}

#[test]
fn paths_default_when_not_set() {
    let file_config = parse("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n").unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(config.nftables.path, Setting { value: path("/usr/sbin/nft"), source: Source::Default });
    assert_eq!(config.suricata.path, Setting { value: path("/usr/bin/suricata"), source: Source::Default });
    assert_eq!(
        config.suricata.config,
        Setting { value: path("/etc/suricata/suricata.yaml"), source: Source::Default }
    );
}

#[test]
fn paths_from_file() {
    let file_config = parse(
        "[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n\
         [nftables]\npath = \"/opt/nft/sbin/nft\"\n\
         [suricata]\npath = \"/opt/suricata-8/bin/suricata\"\nconfig = \"/opt/suricata-8/etc/suricata.yaml\"\n",
    )
    .unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(config.nftables.path, Setting { value: path("/opt/nft/sbin/nft"), source: Source::File });
    assert_eq!(
        config.suricata.path,
        Setting { value: path("/opt/suricata-8/bin/suricata"), source: Source::File }
    );
    assert_eq!(
        config.suricata.config,
        Setting { value: path("/opt/suricata-8/etc/suricata.yaml"), source: Source::File }
    );
}

#[test]
fn parse_rejects_unknown_path_field() {
    assert!(parse("[suricata]\nbinary = \"/usr/bin/suricata\"\n").is_err());
}

#[test]
fn suricata_queue_and_ready_timeout_default() {
    let file_config = parse("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n").unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(config.suricata.delivery, Setting { value: Delivery::Copy(GroupRange::default()), source: Source::Default });
    assert_eq!(
        config.suricata.ready_timeout,
        Setting { value: std::time::Duration::from_secs(300), source: Source::Default }
    );
}

#[test]
fn suricata_queue_and_ready_timeout_from_file() {
    let file_config =
        parse("protection = \"ips\"\n[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n[suricata]\nqueue = \"2-5\"\nready_timeout = 30\n").unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(config.suricata.delivery, Setting { value: Delivery::Queue("2-5".parse().unwrap()), source: Source::File });
    assert_eq!(
        config.suricata.ready_timeout,
        Setting { value: std::time::Duration::from_secs(30), source: Source::File }
    );
}

#[test]
fn when_unavailable_defaults_to_accept() {
    let file_config = parse("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n").unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(
        config.suricata.when_unavailable,
        Setting { value: WhenUnavailable::Accept, source: Source::Default }
    );
}

#[test]
fn when_unavailable_from_file() {
    let file_config = parse("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n[suricata]\nwhen_unavailable = \"drop\"\n").unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(
        config.suricata.when_unavailable,
        Setting { value: WhenUnavailable::Drop, source: Source::File }
    );
}

#[test]
fn parse_rejects_unknown_when_unavailable() {
    let err = parse("[suricata]\nwhen_unavailable = \"open\"\n").unwrap_err();
    assert!(err.contains("invalid when_unavailable \"open\" (expected \"accept\" or \"drop\")"), "{err}");
}

#[test]
fn stop_timeout_defaults_to_90_seconds() {
    let file_config = parse("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n").unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(
        config.suricata.stop_timeout,
        Setting { value: std::time::Duration::from_secs(90), source: Source::Default }
    );
}

#[test]
fn stop_timeout_from_file() {
    let file_config = parse("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n[suricata]\nstop_timeout = 15\n").unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(
        config.suricata.stop_timeout,
        Setting { value: std::time::Duration::from_secs(15), source: Source::File }
    );
}

#[test]
fn parse_rejects_zero_stop_timeout() {
    assert!(parse("[suricata]\nstop_timeout = 0\n").is_err());
}

#[test]
fn parse_rejects_zero_ready_timeout() {
    assert!(parse("[suricata]\nready_timeout = 0\n").is_err());
    assert!(parse("[suricata]\nready_timeout = -1\n").is_err());
}

#[test]
fn protection_defaults_to_ids_with_group_10() {
    let file_config = parse("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n").unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(config.protection, Setting { value: Protection::Ids, source: Source::Default });
    assert_eq!(config.suricata.delivery.source, Source::Default);
    assert_eq!(config.delivery(), Delivery::Copy("10".parse().unwrap()));
}

#[test]
fn protection_and_group_from_file() {
    let file_config =
        parse("protection = \"ids\"\n[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n[suricata]\ngroup = \"20-21\"\n").unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(config.protection, Setting { value: Protection::Ids, source: Source::File });
    assert_eq!(config.suricata.delivery, Setting { value: Delivery::Copy("20-21".parse().unwrap()), source: Source::File });
}

#[test]
fn queue_with_ids_and_group_with_ips_are_errors() {
    let ports = "[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n";
    for (text, expected) in [
        (format!("{ports}[suricata]\nqueue = \"0-1\"\n"), "suricata.queue (only with protection = \"ips\")"),
        (format!("protection = \"ips\"\n{ports}[suricata]\ngroup = 11\n"), "suricata.group (only with protection = \"ids\")"),
    ] {
        let err = merge(Some(PathBuf::from("/x.toml")), parse(&text).unwrap(), Overrides::default()).unwrap_err();
        assert!(matches!(&err, ConfigError::Inapplicable { settings, .. } if settings == &[expected]), "{err}");
    }
}

#[test]
fn parse_rejects_unknown_protection_and_group_0() {
    let err = parse("protection = \"inline\"\n").unwrap_err();
    assert!(err.contains("invalid protection \"inline\" (expected \"ids\" or \"ips\")"), "{err}");
    let err = parse("[suricata]\ngroup = 0\n").unwrap_err();
    assert!(err.contains("invalid group \"0\""), "{err}");
}
