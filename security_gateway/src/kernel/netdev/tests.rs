use super::*;

fn nla(kind: u16, value: &[u8]) -> Vec<u8> {
    let len = 4 + value.len();
    let mut out = Vec::new();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    out.resize(len.next_multiple_of(4), 0);
    out
}

fn header() -> GenlHeader {
    GenlHeader { cmd: CMD_DEV_GET, version: FAMILY_VERSION }
}

#[test]
fn parses_ifindex_and_xdp_features() {
    let mut buf = nla(A_DEV_IFINDEX, &7u32.to_ne_bytes());
    buf.extend(nla(A_DEV_XDP_FEATURES, &0b101u64.to_ne_bytes()));
    buf.extend(nla(5, &0u64.to_ne_bytes()));
    let msg = DevMessage::parse_with_param(&buf, header()).unwrap();
    assert_eq!(msg.ifindex, Some(7));
    assert_eq!(msg.xdp_features, Some(0b101));
}

#[test]
fn missing_xdp_features_is_none() {
    let buf = nla(A_DEV_IFINDEX, &3u32.to_ne_bytes());
    let msg = DevMessage::parse_with_param(&buf, header()).unwrap();
    assert_eq!(msg.xdp_features, None);
}

#[test]
fn truncated_attribute_is_an_error() {
    let buf = nla(A_DEV_IFINDEX, &[1, 0]);
    assert!(DevMessage::parse_with_param(&buf, header()).is_err());
}

#[test]
fn request_carries_only_the_ifindex() {
    let request = DevMessage::request(7);
    let mut buf = vec![0; request.buffer_len()];
    request.emit(&mut buf);
    assert_eq!(buf, nla(A_DEV_IFINDEX, &7u32.to_ne_bytes()));
    assert_eq!(request.command(), 1);
    assert_eq!(DevMessage::family_name(), "netdev");
}

#[test]
fn feature_names() {
    assert_eq!(XdpFeatures(0).to_string(), "none");
    assert_eq!(XdpFeatures(1 | 2 | 4).to_string(), "basic,redirect,ndo-xmit");
    assert!(XdpFeatures(1).basic());
    assert!(!XdpFeatures(2).basic());
}
