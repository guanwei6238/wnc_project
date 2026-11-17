use super::*;

const LINES: &str = r#"{"timestamp":"t","flow_id":1,"pcap_cnt":3,"event_type":"alert","src_ip":"203.0.113.5","src_port":23,"dest_ip":"192.168.1.10","dest_port":34916,"proto":"TCP","alert":{"signature_id":2400047,"signature":"x"}}
{"timestamp":"t","flow_id":2,"pcap_cnt":3,"event_type":"alert","src_ip":"192.168.1.10","dest_ip":"203.0.113.5","proto":"ICMP","icmp_type":8,"alert":{"signature_id":11,"signature":"x"}}
{"timestamp":"t","flow_id":3,"event_type":"alert","src_ip":"192.168.1.10","src_port":1,"dest_ip":"203.0.113.5","dest_port":2,"proto":"UDP","alert":{"signature_id":12,"signature":"alert"}}
{"timestamp":"t","event_type":"stats","stats":{"alert":3}}
{"timestamp":"t","flow_id":4,"pcap_cnt":2,"event_type":"alert","proto":"ICMP","alert":{"signature_id":13,"signature":"x"}}
{"timestamp":"t","flow_id":5,"pcap_cnt":5,"event_type":"alert","proto":"ICMP","alert":{"signature_id":14,"signature":"x"}}
{"timestamp":"t","flow_id":6,"pcap_cnt":9,"event_type":"alert","proto":"ICMP","alert":{"signature_id":15,"signature":"x"}}
"#;

#[test]
fn hands_out_alerts_packet_by_packet() {
    let mut alerts = Alerts::new(LINES.as_bytes());
    let mut out = Vec::new();
    for packet in 1..=2 {
        alerts.take(packet, &mut out).unwrap();
        assert!(out.is_empty());
    }
    alerts.take(3, &mut out).unwrap();
    let tcp = Key::new(
        Protocol::Tcp,
        "192.168.1.10:34916".parse().unwrap(),
        "203.0.113.5:23".parse().unwrap(),
    );
    assert_eq!(out, [Alert { key: Some(tcp), sid: 2400047 }, Alert { key: None, sid: 11 }]);
    alerts.take(4, &mut out).unwrap();
    assert!(out.is_empty());
    assert_eq!((alerts.unplaced, alerts.out_of_order), (1, 1));
    alerts.take(5, &mut out).unwrap();
    assert_eq!(out, [Alert { key: None, sid: 14 }]);
    assert_eq!(alerts.remaining().unwrap(), 1);
}

#[test]
fn bad_json_is_an_error() {
    let mut alerts = Alerts::new("{\"event_type\":\"alert\",".as_bytes());
    assert!(alerts.take(1, &mut Vec::new()).is_err());
}
