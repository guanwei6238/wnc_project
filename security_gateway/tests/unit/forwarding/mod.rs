use super::*;
use crate::kernel::netif::OperState;
use crate::ports::MatchedBy;

pub(super) fn iface(index: u32, name: &str, kind: Option<&str>, master: Option<u32>) -> Interface {
    Interface {
        index,
        name: name.to_owned(),
        mac: None,
        perm_mac: None,
        admin_up: true,
        oper_state: OperState::Up,
        kind: kind.map(str::to_owned),
        master,
        driver: None,
        xdp: None,
    }
}

pub(super) fn port(role: Role, interface: &Interface) -> Port {
    Port {
        role,
        interface: interface.clone(),
        matched_by: MatchedBy::Name,
    }
}

#[test]
fn default_mode_is_bridge() {
    assert_eq!(Mode::default(), Mode::Bridge);
}

#[test]
fn mode_round_trips() {
    for mode in [Mode::Bridge, Mode::Routed] {
        assert_eq!(mode.to_string().parse::<Mode>(), Ok(mode));
    }
}

#[test]
fn invalid_mode_is_rejected() {
    let err = "bridged".parse::<Mode>().unwrap_err();
    assert_eq!(err.to_string(), "invalid mode \"bridged\" (expected \"bridge\" or \"routed\")");
}

#[test]
fn each_mode_lists_its_modules() {
    let names = |mode| for_mode(mode).required_modules().iter().map(|m| (m.name, m.must_be_loaded)).collect::<Vec<_>>();
    assert_eq!(names(Mode::Bridge), vec![("bridge", false), ("br_netfilter", true)]);
    assert_eq!(names(Mode::Routed), vec![]);
}

const FORWARD: RequiredSysctl = RequiredSysctl {
    key: "net.ipv4.ip_forward",
    level: Level::Required,
    consequence: "IPv4 traffic is not forwarded",
    absent: "IPv4 forwarding is not available in this kernel",
};

fn sysctl_state(read: Result<Option<String>, String>) -> EnvState {
    let checks = sysctl_checks(&[FORWARD], |key| {
        assert_eq!(key, "net.ipv4.ip_forward");
        read.clone()
    });
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].item, "net.ipv4.ip_forward");
    assert_eq!(checks[0].level, Level::Required);
    checks[0].state.clone()
}

#[test]
fn sysctl_one_is_met() {
    assert_eq!(sysctl_state(Ok(Some("1".into()))), EnvState::Met { actual: "1".into() });
}

#[test]
fn sysctl_zero_is_unmet() {
    assert_eq!(
        sysctl_state(Ok(Some("0".into()))),
        EnvState::Unmet {
            actual: "0".into(),
            problem: "net.ipv4.ip_forward is 0, so IPv4 traffic is not forwarded".into(),
            fix: "set it with: sysctl -w net.ipv4.ip_forward=1, and persist it in /etc/sysctl.d/".into(),
        }
    );
}

#[test]
fn absent_sysctl_is_unknown() {
    assert_eq!(
        sysctl_state(Ok(None)),
        EnvState::Unknown {
            reason: "IPv4 forwarding is not available in this kernel".into()
        }
    );
}

#[test]
fn unreadable_sysctl_is_unknown() {
    assert_eq!(
        sysctl_state(Err("permission denied".into())),
        EnvState::Unknown {
            reason: "permission denied".into()
        }
    );
}
