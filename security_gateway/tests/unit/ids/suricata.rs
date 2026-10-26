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
