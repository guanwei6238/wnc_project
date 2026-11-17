use super::*;
use crate::kernel::conntrack::Protocol;

fn inspection(queue: &str, when_unavailable: WhenUnavailable) -> Inspection {
    Inspection {
        delivery: Delivery::Queue(queue.parse().unwrap()),
        when_unavailable,
    }
}

fn copying(groups: &str, when_unavailable: WhenUnavailable) -> Inspection {
    Inspection {
        delivery: Delivery::Copy(groups.parse().unwrap()),
        when_unavailable,
    }
}

const BOTH: [WhenUnavailable; 2] = [WhenUnavailable::Accept, WhenUnavailable::Drop];

#[test]
fn table_is_ours() {
    let table = table(inspection("0", WhenUnavailable::Accept), TrustBackend::Tc);
    assert_eq!((table.family, table.name.as_str()), (Family::Inet, "wnc_gw"));
}

#[test]
fn every_chain_accepts_by_default() {
    for when in BOTH {
        for chain in table(inspection("0", when), TrustBackend::Tc).chains {
            assert_eq!(chain.policy, Policy::Accept, "chain {} must not drop by default", chain.name);
        }
    }
}

#[test]
fn forward_jumps_to_the_ids_chain() {
    let table = table(inspection("0", WhenUnavailable::Accept), TrustBackend::Tc);
    assert_eq!(
        table.chains[0].rules.last(),
        Some(&vec![Statement::Jump("ids".into())])
    );
    assert_eq!(table.regular_chains.len(), 1);
    assert_eq!(table.regular_chains[0].name, "ids");
}

#[test]
fn table_starts_without_queueing() {
    for when in BOTH {
        let table = table(inspection("0", when), TrustBackend::Tc);
        assert_eq!(table.regular_chains[0].rules, unavailable_rules(when));
    }
}

#[test]
fn unavailable_rules_follow_the_setting() {
    assert_eq!(
        unavailable_rules(WhenUnavailable::Accept),
        [vec![Statement::Counter, Statement::Accept]]
    );
    assert_eq!(
        unavailable_rules(WhenUnavailable::Drop),
        [vec![Statement::Counter, Statement::Drop]]
    );
}

#[test]
fn queue_bypasses_only_when_accepting() {
    let queue = "0-3".parse().unwrap();
    assert_eq!(
        inspecting_rules(inspection("0-3", WhenUnavailable::Accept)),
        [vec![Statement::Counter, Statement::Queue { queue, bypass: true }]]
    );
    assert_eq!(
        inspecting_rules(inspection("0-3", WhenUnavailable::Drop)),
        [vec![Statement::Counter, Statement::Queue { queue, bypass: false }]]
    );
}

#[test]
fn when_unavailable_round_trips() {
    for when in BOTH {
        assert_eq!(when.to_string().parse::<WhenUnavailable>(), Ok(when));
    }
    assert_eq!(WhenUnavailable::default(), WhenUnavailable::Accept);
}

#[test]
fn rejects_unknown_when_unavailable() {
    for s in ["", "Accept", "reject", "open"] {
        assert_eq!(
            s.parse::<WhenUnavailable>().unwrap_err().to_string(),
            format!("invalid when_unavailable {s:?} (expected \"accept\" or \"drop\")")
        );
    }
}

#[test]
fn forward_marks_then_sends_everything_to_ids_with_tc_trust() {
    let rules = &table(inspection("0", WhenUnavailable::Drop), TrustBackend::Tc).chains[0].rules;
    assert_eq!(
        rules,
        &vec![
            vec![Statement::Counter],
            vec![Statement::CtMarkLacks(FORWARDED_MARK), Statement::CtMarkSet(FORWARDED_MARK)],
            vec![Statement::Jump("ids".into())],
        ],
        "trust lives in the core eBPF program now; what reaches netfilter is never trusted"
    );
}

#[test]
fn ids_chain_always_ends_with_a_verdict() {
    for when in BOTH {
        for rules in [unavailable_rules(when), inspecting_rules(inspection("0-3", when))] {
            let last = rules.last().and_then(|r| r.last());
            assert!(
                matches!(last, Some(Statement::Accept | Statement::Drop | Statement::Queue { .. })),
                "ids must not return to forward, or control packets are counted twice: {rules:?}"
            );
        }
    }
}

#[test]
fn marks_are_single_distinct_bits() {
    assert_eq!(TRUSTED_MARK.count_ones(), 1);
    assert_eq!(FORWARDED_MARK.count_ones(), 1);
    assert_eq!(FORWARDED_MARK & TRUSTED_MARK, 0);
}

const BACKENDS: [TrustBackend; 2] = [TrustBackend::Tc, TrustBackend::CtMark];

fn first_verdict(rules: &[Vec<Statement>]) -> usize {
    rules
        .iter()
        .position(|r| r.iter().any(|s| matches!(s, Statement::Jump(_) | Statement::Accept)))
        .expect("a rule with a verdict")
}

#[test]
fn forwarded_connections_are_marked_once_before_any_verdict() {
    for backend in BACKENDS {
        let rules = &table(inspection("0", WhenUnavailable::Drop), backend).chains[0].rules;
        let mark = rules
            .iter()
            .position(|r| r == &vec![Statement::CtMarkLacks(FORWARDED_MARK), Statement::CtMarkSet(FORWARDED_MARK)])
            .expect("forwarded mark rule");
        assert!(mark < first_verdict(rules), "every forwarded connection must get the mark, trusted or not");
    }
}

#[test]
fn ct_mark_trust_inspects_control_packets_before_accepting_trusted_flows() {
    let rules = &table(inspection("0", WhenUnavailable::Drop), TrustBackend::CtMark).chains[0].rules;
    let ids = Statement::Jump("ids".into());
    let control = rules
        .iter()
        .position(|r| r == &vec![Statement::TcpFlagsAny(vec![TcpFlag::Fin, TcpFlag::Syn, TcpFlag::Rst]), ids.clone()])
        .expect("syn/fin/rst rule");
    let trusted = rules
        .iter()
        .position(|r| r == &vec![Statement::CtMarkHas(TRUSTED_MARK), Statement::Counter, Statement::Accept])
        .expect("trusted rule");
    assert!(control < trusted, "control packets must be checked before trusted flows are accepted");
    assert_eq!(rules.last(), Some(&vec![ids]));
}

#[test]
fn ct_mark_trust_is_cleared_by_a_bare_syn_before_anything_else_sees_it() {
    let rules = &table(inspection("0", WhenUnavailable::Drop), TrustBackend::CtMark).chains[0].rules;
    let syn = Statement::TcpFlagsEq {
        mask: vec![TcpFlag::Syn, TcpFlag::Ack],
        value: vec![TcpFlag::Syn],
    };
    let clear = rules
        .iter()
        .position(|r| {
            r == &vec![syn.clone(), Statement::CtMarkHas(TRUSTED_MARK), Statement::Counter, Statement::CtMarkClear(TRUSTED_MARK)]
        })
        .expect("syn clear rule");
    assert!(
        clear < first_verdict(rules),
        "a new connection reusing a trusted entry must lose the mark before its syn is judged"
    );
}

#[test]
fn tc_trust_has_no_ct_mark_rules() {
    let rules = table(inspection("0", WhenUnavailable::Drop), TrustBackend::Tc).chains[0].rules.concat();
    assert!(
        !rules.iter().any(|s| matches!(s, Statement::CtMarkHas(m) | Statement::CtMarkClear(m) if *m == TRUSTED_MARK)),
        "with tc trust a stale ct mark must not let packets skip inspection: {rules:?}"
    );
}

#[test]
fn connections_that_already_ended_are_not_failures() {
    let tuple = FiveTuple::new(Protocol::Tcp, "10.0.1.2:1".parse().unwrap(), "10.0.2.2:2".parse().unwrap()).unwrap();
    let failures = vec![
        (tuple, ConntrackError::NotFound),
        (tuple, ConntrackError::Kernel(std::io::Error::from_raw_os_error(libc::EINVAL))),
        (tuple, ConntrackError::NotFound),
    ];
    let u = untrusted(10, failures);
    assert_eq!((u.cleared, u.gone, u.failed.len()), (7, 2, 1));
}

#[test]
fn ct_marked_connections_list_with_their_conntrack_counters() {
    let tuple = FiveTuple::new(Protocol::Udp, "10.0.1.2:5353".parse().unwrap(), "10.0.2.2:53".parse().unwrap()).unwrap();
    let reply = FiveTuple::new(Protocol::Udp, "10.0.2.2:53".parse().unwrap(), "10.0.1.2:5353".parse().unwrap()).unwrap();
    let connection = Connection {
        id: 7,
        original: tuple,
        reply,
        tcp_state: None,
        timeout_s: Some(30),
        mark: TRUSTED_MARK | FORWARDED_MARK,
        original_counters: Some(Counters { packets: 12, bytes: 900 }),
        reply_counters: None,
    };
    let flow = trusted_flow(&connection);
    assert_eq!(flow.tuple, tuple);
    assert_eq!((flow.original.packets, flow.original.bytes, flow.original.direction), (12, 900, DIRECTION_ORIGINAL));
    assert_eq!((flow.reply.packets, flow.reply.bytes, flow.reply.direction), (0, 0, DIRECTION_REPLY));
    assert_eq!(flow.next_hop_original(Some(1)), None);
}

#[test]
fn one_group_logs_and_accepts_in_the_ids_chain() {
    for when in BOTH {
        let inspection = copying("10", when);
        assert_eq!(
            inspecting_rules(inspection),
            [vec![Statement::Counter, Statement::Log { group: 10 }, Statement::Accept]]
        );
        assert_eq!(table(inspection, TrustBackend::Tc).regular_chains.len(), 1);
    }
}

#[test]
fn several_groups_jump_by_symhash_to_one_chain_each() {
    let inspection = copying("10-12", WhenUnavailable::Drop);
    assert_eq!(
        inspecting_rules(inspection),
        [vec![
            Statement::Counter,
            Statement::JumpBySymhash(vec!["ids_g10".into(), "ids_g11".into(), "ids_g12".into()])
        ]]
    );
    let table = table(inspection, TrustBackend::Tc);
    let names: Vec<_> = table.regular_chains.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["ids", "ids_g10", "ids_g11", "ids_g12"]);
    assert_eq!(table.regular_chains[0].rules, unavailable_rules(WhenUnavailable::Drop));
    assert_eq!(
        table.regular_chains[2].rules,
        [vec![Statement::Counter, Statement::Log { group: 11 }, Statement::Accept]]
    );
}

#[test]
fn every_inspecting_rule_ends_with_a_verdict() {
    for inspection in [inspection("0", WhenUnavailable::Accept), copying("10", WhenUnavailable::Accept)] {
        for rule in inspecting_rules(inspection) {
            assert!(
                matches!(rule.last(), Some(Statement::Queue { .. } | Statement::Accept | Statement::JumpBySymhash(_))),
                "{rule:?}"
            );
        }
    }
    for chain in &table(copying("10-11", WhenUnavailable::Accept), TrustBackend::Tc).regular_chains[1..] {
        assert_eq!(chain.rules[0].last(), Some(&Statement::Accept));
    }
}
