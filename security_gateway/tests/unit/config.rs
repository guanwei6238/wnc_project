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
    assert_eq!(config.ports.lan, None);
    assert_eq!(config.ports.wan, None);
    assert_eq!(config.nftables.path, None);
    assert_eq!(config.suricata.path, None);
    assert_eq!(config.suricata.config, None);
    assert_eq!(config.suricata.queue, None);
    assert_eq!(config.suricata.ready_timeout, None);
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
    assert!(config.ports.lan.is_some());
    assert!(config.ports.wan.is_some());
    assert!(config.nftables.path.is_some());
    assert!(config.suricata.path.is_some());
    assert!(config.suricata.config.is_some());
    assert!(config.suricata.queue.is_some());
    assert!(config.suricata.ready_timeout.is_some());
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
    assert_eq!(config.suricata.queue, Setting { value: QueueRange::default(), source: Source::Default });
    assert_eq!(
        config.suricata.ready_timeout,
        Setting { value: std::time::Duration::from_secs(300), source: Source::Default }
    );
}

#[test]
fn suricata_queue_and_ready_timeout_from_file() {
    let file_config =
        parse("[ports]\nlan = \"eth0\"\nwan = \"eth1\"\n[suricata]\nqueue = \"2-5\"\nready_timeout = 30\n").unwrap();
    let config = merge(None, file_config, Overrides::default()).unwrap();
    assert_eq!(config.suricata.queue, Setting { value: "2-5".parse().unwrap(), source: Source::File });
    assert_eq!(
        config.suricata.ready_timeout,
        Setting { value: std::time::Duration::from_secs(30), source: Source::File }
    );
}

#[test]
fn parse_rejects_zero_ready_timeout() {
    assert!(parse("[suricata]\nready_timeout = 0\n").is_err());
    assert!(parse("[suricata]\nready_timeout = -1\n").is_err());
}
