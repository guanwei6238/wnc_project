use super::*;

const V8: &str = "This is Suricata version 8.0.7 RELEASE
Features: NFQ PCAP_SET_BUFF AF_PACKET HAVE_PACKET_FANOUT LIBCAP_NG LIBNET1.1 RUST POPCNT64
compiled with LibHTP v8.0.7

Suricata Configuration:
  AF_PACKET support:                       yes
  NFQueue support:                         yes
  Npcap support:

  Unix socket enabled:                     yes
  Landlock support:                        yes
  Systemd support:                         yes

  Rust compiler version:                   rustc 1.85.1 (4eb161250 2025-03-15) (built from a source tarball)
  Configuration directory:                 /etc/suricata/
";

const V7: &str = "This is Suricata version 7.0.10 RELEASE
Features: NFQ PCAP_SET_BUFF AF_PACKET HAVE_PACKET_FANOUT LIBCAP_NG LIBNET1.1 RUST POPCNT64

Suricata Configuration:
  NFQueue support:                         yes
  Unix socket enabled:                     yes
  LUA support:                             yes, through luajit
";

#[test]
fn parses_suricata_8() {
    assert_eq!(
        SuricataInfo::parse(V8),
        SuricataInfo {
            version: Some("8.0.7".into()),
            nfqueue: Some(true),
            ready_notify: Some(true),
        }
    );
}

#[test]
fn suricata_7_does_not_report_systemd_support() {
    assert_eq!(
        SuricataInfo::parse(V7),
        SuricataInfo {
            version: Some("7.0.10".into()),
            nfqueue: Some(true),
            ready_notify: None,
        }
    );
}

#[test]
fn no_is_false() {
    let output = V8
        .replace("NFQueue support:                         yes", "NFQueue support: no")
        .replace("Systemd support:                         yes", "Systemd support: no");
    let info = SuricataInfo::parse(&output);
    assert_eq!((info.nfqueue, info.ready_notify), (Some(false), Some(false)));
}

#[test]
fn unexpected_value_is_unknown() {
    let info = SuricataInfo::parse("This is Suricata version 8.0.7 RELEASE\n  NFQueue support: maybe\n");
    assert_eq!(info.nfqueue, None);
}

#[test]
fn unexpected_first_line_has_no_version() {
    assert_eq!(
        SuricataInfo::parse("something else\n  NFQueue support: yes\n"),
        SuricataInfo {
            version: None,
            nfqueue: Some(true),
            ready_notify: None,
        }
    );
    assert_eq!(
        SuricataInfo::parse(""),
        SuricataInfo {
            version: None,
            nfqueue: None,
            ready_notify: None,
        }
    );
}

#[test]
fn field_on_first_line_is_ignored() {
    assert_eq!(SuricataInfo::parse("NFQueue support: yes\n").nfqueue, None);
}

#[tokio::test(flavor = "current_thread")]
async fn runs_the_configured_path() {
    let suricata = Suricata::new("/nonexistent/suricata");
    let err = suricata.info().await.unwrap_err();
    assert!(matches!(&err, SuricataError::NotFound { path } if path == Path::new("/nonexistent/suricata")));
    assert_eq!(err.to_string(), "/nonexistent/suricata not found");
}

const DUMP: &str = "outputs.1.eve-log.enabled = yes
outputs.1.eve-log.filename = eve.json
unix-command.enabled = yes
default-rule-path = /var/lib/suricata/rules
rule-files = (null)
rule-files.0 = suricata.rules
rule-files.1 = /etc/suricata/local.rules
classification-file = /etc/suricata/classification.config
";

#[test]
fn parses_rule_settings_from_dump() {
    assert_eq!(
        SuricataConfig::parse(DUMP),
        SuricataConfig {
            default_rule_path: Some("/var/lib/suricata/rules".into()),
            rule_files: vec!["suricata.rules".into(), "/etc/suricata/local.rules".into()],
        }
    );
}

#[test]
fn dump_without_rule_settings() {
    assert_eq!(
        SuricataConfig::parse("unix-command.enabled = yes\n"),
        SuricataConfig {
            default_rule_path: None,
            rule_files: vec![],
        }
    );
}

fn rules_config(default_rule_path: Option<&str>) -> SuricataConfig {
    SuricataConfig {
        default_rule_path: default_rule_path.map(PathBuf::from),
        rule_files: vec![],
    }
}

#[test]
fn resolves_rule_file_entries() {
    let config = rules_config(Some("/var/lib/suricata/rules"));
    assert_eq!(
        config.resolve("suricata.rules").unwrap(),
        Path::new("/var/lib/suricata/rules/suricata.rules")
    );
    assert_eq!(config.resolve("/etc/local.rules").unwrap(), Path::new("/etc/local.rules"));
    assert!(matches!(config.resolve("*.rules"), Err(RuleFileState::Wildcard)));
    assert!(matches!(config.resolve("emerging-[a-z].rules"), Err(RuleFileState::Wildcard)));
    assert!(matches!(
        rules_config(None).resolve("suricata.rules"),
        Err(RuleFileState::NoRulePath)
    ));
    assert_eq!(rules_config(None).resolve("/etc/local.rules").unwrap(), Path::new("/etc/local.rules"));
}

#[test]
fn comments_and_blank_lines_are_not_rules() {
    assert!(!has_rule(&b"# alert ip any any -> any any (sid:1;)\n\n   \n  # x\n"[..]).unwrap());
    assert!(!has_rule(&b""[..]).unwrap());
    assert!(has_rule(&b"# header\n  alert ip any any -> any any (sid:1;)\n"[..]).unwrap());
    assert!(has_rule(&b"alert tcp any any -> any any (content:\"\xff\xfe\"; sid:2;)"[..]).unwrap());
}

#[test]
fn checks_rule_files_on_disk() {
    let dir = std::env::temp_dir().join(format!("wnc-gw-rules-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.rules"), "alert ip any any -> any any (sid:1;)\n").unwrap();
    std::fs::write(dir.join("b.rules"), "# nothing enabled\n").unwrap();
    let config = SuricataConfig {
        default_rule_path: Some(dir.clone()),
        rule_files: vec!["a.rules".into(), "b.rules".into(), "c.rules".into(), "*.rules".into()],
    };
    let files = config.check_rule_files();
    std::fs::remove_dir_all(&dir).unwrap();
    let states: Vec<_> = files.iter().map(|f| (f.entry.as_str(), f.path.clone(), &f.state)).collect();
    assert!(matches!(states[0], ("a.rules", Some(ref p), RuleFileState::HasRules) if *p == dir.join("a.rules")));
    assert!(matches!(states[1], ("b.rules", Some(_), RuleFileState::NoRules)));
    assert!(matches!(states[2], ("c.rules", Some(_), RuleFileState::Missing)));
    assert!(matches!(states[3], ("*.rules", None, RuleFileState::Wildcard)));
}
