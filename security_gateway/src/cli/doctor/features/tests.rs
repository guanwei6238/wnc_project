use std::time::Duration;

use security_gateway::config::ports::{MatchedBy, Role};
use security_gateway::features::hook::XdpMode;
use security_gateway::kernel::netif::{Interface, OperState, XdpAttachment, XdpMode as AttachedMode};

use super::*;

fn port(xdp: Option<XdpAttachment>) -> Port {
    Port {
        role: Role::Lan,
        interface: Interface {
            index: 2,
            name: "eth0".to_owned(),
            mac: None,
            perm_mac: None,
            admin_up: true,
            oper_state: OperState::Up,
            kind: None,
            master: None,
            driver: None,
            xdp,
        },
        matched_by: MatchedBy::Name,
    }
}

fn feature(name: &str, hook: Hook) -> FeatureSettings {
    FeatureSettings {
        name: name.to_owned(),
        program: "/f.o".parse().unwrap(),
        entry: "f".to_owned(),
        definition: "/f.json".parse().unwrap(),
        hook,
        interval: Duration::from_secs(1),
    }
}

#[test]
fn one_xdp_feature_per_port() {
    let one = [feature("a", Hook::Xdp(XdpMode::Native)), feature("b", Hook::TcEgress), feature("c", Hook::TcIngress)];
    assert_eq!(xdp_conflicts(&one, &[port(None)]), []);
    let two = [feature("a", Hook::Xdp(XdpMode::Native)), feature("b", Hook::Xdp(XdpMode::Generic))];
    let found = xdp_conflicts(&two, &[port(None)]);
    assert!(matches!(&found[..], [Finding { severity: Severity::Error, issue: Issue::FeatureXdpConflict, message }] if message.contains("a, b")));
}

#[test]
fn a_port_with_an_xdp_program_already() {
    let taken = port(Some(XdpAttachment { mode: AttachedMode::Generic, prog_id: Some(42) }));
    let found = xdp_conflicts(&[feature("a", Hook::Xdp(XdpMode::Generic))], &[taken.clone()]);
    assert!(matches!(&found[..], [Finding { message, .. }] if message.contains("XDP program 42")));
    assert_eq!(xdp_conflicts(&[feature("a", Hook::TcEgress)], &[taken]), [], "TC hooks are not limited");
}
