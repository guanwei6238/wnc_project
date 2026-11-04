use std::io::Write;

use super::*;

const ICMP_ALERT: &str = r#"{"timestamp":"2025-11-04T23:46:40.000000+0000","flow_id":2510426078,"pcap_cnt":1,"event_type":"alert","src_ip":"10.9.0.1","dest_ip":"10.9.0.2","proto":"ICMP","ip_v":4,"icmp_type":8,"icmp_code":0,"pkt_src":"wire/pcap","alert":{"action":"allowed","gid":1,"signature_id":9000101,"rev":1,"signature":"wnc test ICMP \"quoted\" \\ back","category":"","severity":3},"direction":"to_server","flow":{"pkts_toserver":1,"pkts_toclient":0,"bytes_toserver":50,"bytes_toclient":0,"start":"2025-11-04T23:46:40.000000+0000","src_ip":"10.9.0.1","dest_ip":"10.9.0.2"}}"#;

const TCP6_ALERT: &str = r#"{"timestamp":"2025-11-04T23:46:40.000000+0000","flow_id":3010768422,"pcap_cnt":1,"event_type":"alert","src_ip":"2001:0db8:0000:0000:0000:0000:0000:0001","src_port":40000,"dest_ip":"2001:0db8:0000:0000:0000:0000:0000:0002","dest_port":8080,"proto":"TCP","ip_v":6,"pkt_src":"wire/pcap","alert":{"action":"allowed","gid":1,"signature_id":9000102,"rev":1,"signature":"wnc test SYN 8080","category":"","severity":3},"direction":"to_server"}"#;

const FLOW: &str = r#"{"timestamp":"2025-11-04T23:46:40.000000+0000","flow_id":3010768422,"event_type":"flow","src_ip":"2001:0db8:0000:0000:0000:0000:0000:0001","src_port":40000,"dest_ip":"2001:0db8:0000:0000:0000:0000:0000:0002","dest_port":8080,"ip_v":6,"proto":"TCP","flow":{"alerted":true}}"#;

#[test]
fn parses_an_icmp_alert() {
    let alert = parse_alert(ICMP_ALERT.as_bytes()).unwrap().unwrap();
    assert_eq!(
        alert,
        Alert {
            flow_id: Some(2510426078),
            protocol: "ICMP".into(),
            src: Some("10.9.0.1".parse().unwrap()),
            src_port: None,
            dst: Some("10.9.0.2".parse().unwrap()),
            dst_port: None,
            signature_id: 9000101,
            signature: r#"wnc test ICMP "quoted" \ back"#.into(),
            action: "allowed".into(),
        }
    );
    assert_eq!(alert.connection(), "icmp 10.9.0.1 -> 10.9.0.2");
}

#[test]
fn parses_an_ipv6_tcp_alert() {
    let alert = parse_alert(TCP6_ALERT.as_bytes()).unwrap().unwrap();
    assert_eq!(alert.signature_id, 9000102);
    assert_eq!(alert.connection(), "tcp [2001:db8::1]:40000 -> [2001:db8::2]:8080");
}

#[test]
fn other_events_are_not_alerts() {
    assert_eq!(parse_alert(FLOW.as_bytes()), Ok(None));
    assert_eq!(parse_alert(br#"{"event_type":"stats","stats":{}}"#), Ok(None));
    assert_eq!(
        parse_alert(br#"{"event_type":"http","http":{"http_user_agent":"\"event_type\":\"alert\""}}"#),
        Ok(None)
    );
}

#[test]
fn broken_alerts_are_errors() {
    assert!(parse_alert(br#"{"event_type":"alert","src_ip":"#).is_err());
    assert!(parse_alert(br#"{"event_type":"alert","proto":"TCP"}"#).is_err());
    assert!(parse_alert(br#"{"event_type":"alert","src_ip":"not an ip","alert":{"signature_id":1}}"#).is_err());
}

#[test]
fn eve_interval_bounds() {
    assert!(EveInterval::from_secs(0.049).is_err());
    assert_eq!(EveInterval::from_secs(0.05).unwrap().duration(), Duration::from_millis(50));
    assert_eq!(EveInterval::from_secs(10.0).unwrap().duration(), Duration::from_secs(10));
    assert!(EveInterval::from_secs(10.001).is_err());
    assert!(EveInterval::from_secs(f64::NAN).is_err());
    assert_eq!(EveInterval::default().duration(), Duration::from_millis(500));
    assert_eq!(EveInterval::default().to_string(), "0.5 s");
    assert_eq!(EveInterval::from_secs(2.0).unwrap().to_string(), "2 s");
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("wnc-gw-eve-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn file(&self) -> PathBuf {
        self.0.join("eve.json")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn append(path: &Path, text: &str) {
    let mut file = fs::OpenOptions::new().create(true).append(true).open(path).unwrap();
    file.write_all(text.as_bytes()).unwrap();
}

fn read_lines(eve: &mut EveFile) -> (Vec<String>, ReadReport) {
    let mut lines = Vec::new();
    let report = eve
        .read(|line| lines.push(String::from_utf8(line.to_vec()).unwrap()))
        .unwrap();
    (lines, report)
}

#[test]
fn skips_what_was_there_before() {
    let dir = TempDir::new("skip");
    append(&dir.file(), "old 1\nold 2\n");
    let mut eve = EveFile::open_at_end(dir.file());
    assert_eq!(read_lines(&mut eve).0, Vec::<String>::new());
    append(&dir.file(), "new 1\nnew 2\n");
    let (lines, report) = read_lines(&mut eve);
    assert_eq!(lines, ["new 1", "new 2"]);
    assert_eq!(report.lines, 2);
    assert_eq!(report.restart, None);
}

#[test]
fn waits_for_the_rest_of_a_line() {
    let dir = TempDir::new("partial");
    append(&dir.file(), "");
    let mut eve = EveFile::open_at_end(dir.file());
    append(&dir.file(), "first\nsec");
    assert_eq!(read_lines(&mut eve).0, ["first"]);
    append(&dir.file(), "ond\n");
    assert_eq!(read_lines(&mut eve).0, ["second"]);
}

#[test]
fn starting_in_the_middle_of_a_line_skips_it() {
    let dir = TempDir::new("middle");
    append(&dir.file(), "whole\nhalf of a li");
    let mut eve = EveFile::open_at_end(dir.file());
    append(&dir.file(), "ne\nnext\n");
    assert_eq!(read_lines(&mut eve).0, ["next"]);
}

#[test]
fn reads_again_from_the_start_after_truncation() {
    let dir = TempDir::new("truncate");
    append(&dir.file(), "a long line before truncation\n");
    let mut eve = EveFile::open_at_end(dir.file());
    fs::write(dir.file(), "").unwrap();
    append(&dir.file(), "after\n");
    let (lines, report) = read_lines(&mut eve);
    assert_eq!(lines, ["after"]);
    assert_eq!(report.restart, Some(Restart::Truncated));
}

#[test]
fn finishes_the_old_file_after_rotation() {
    let dir = TempDir::new("rotate");
    append(&dir.file(), "");
    let mut eve = EveFile::open_at_end(dir.file());
    append(&dir.file(), "before rotation\n");
    let rotated = dir.0.join("eve.json.1");
    fs::rename(dir.file(), &rotated).unwrap();
    append(&rotated, "written late to the old file\n");
    append(&dir.file(), "new file\n");
    let (lines, report) = read_lines(&mut eve);
    assert_eq!(lines, ["before rotation", "written late to the old file", "new file"]);
    assert_eq!(report.restart, Some(Restart::Replaced));
}

#[test]
fn keeps_reading_a_file_that_was_moved_away_until_a_new_one_appears() {
    let dir = TempDir::new("moved");
    append(&dir.file(), "");
    let mut eve = EveFile::open_at_end(dir.file());
    let rotated = dir.0.join("eve.json.1");
    fs::rename(dir.file(), &rotated).unwrap();
    append(&rotated, "still written to the old file\n");
    let (lines, report) = read_lines(&mut eve);
    assert_eq!(lines, ["still written to the old file"]);
    assert_eq!(report.restart, None);
    append(&rotated, "last line of the old file\n");
    append(&dir.file(), "first line of the new file\n");
    let (lines, report) = read_lines(&mut eve);
    assert_eq!(lines, ["last line of the old file", "first line of the new file"]);
    assert_eq!(report.restart, Some(Restart::Replaced));
}

#[test]
fn a_missing_file_is_read_from_the_start_once_it_appears() {
    let dir = TempDir::new("missing");
    let mut eve = EveFile::open_at_end(dir.file());
    let err = eve.read(|_| {}).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    append(&dir.file(), "first line\n");
    let (lines, report) = read_lines(&mut eve);
    assert_eq!(lines, ["first line"]);
    assert_eq!(report.restart, Some(Restart::Appeared));
}

#[test]
fn drops_lines_longer_than_the_limit() {
    let dir = TempDir::new("long");
    append(&dir.file(), "");
    let mut eve = EveFile::open_at_end(dir.file());
    append(&dir.file(), &"x".repeat(MAX_LINE + 1));
    append(&dir.file(), "\nshort\n");
    let (lines, report) = read_lines(&mut eve);
    assert_eq!(lines, ["short"]);
    assert_eq!(report.too_long, 1);
}

#[test]
fn reads_alerts_end_to_end() {
    let dir = TempDir::new("alerts");
    append(&dir.file(), "");
    let mut eve = EveFile::open_at_end(dir.file());
    append(&dir.file(), &format!("{FLOW}\n{ICMP_ALERT}\n{TCP6_ALERT}\n"));
    let mut sids = Vec::new();
    eve.read(|line| {
        if let Ok(Some(alert)) = parse_alert(line) {
            sids.push(alert.signature_id);
        }
    })
    .unwrap();
    assert_eq!(sids, [9000101, 9000102]);
}
