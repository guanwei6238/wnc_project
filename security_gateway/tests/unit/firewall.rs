use super::*;

fn inspection(queue: &str, when_unavailable: WhenUnavailable) -> Inspection {
    Inspection {
        queue: queue.parse().unwrap(),
        when_unavailable,
    }
}

const BOTH: [WhenUnavailable; 2] = [WhenUnavailable::Accept, WhenUnavailable::Drop];

#[test]
fn table_is_ours() {
    let table = table(inspection("0", WhenUnavailable::Accept));
    assert_eq!((table.family, table.name.as_str()), (Family::Inet, "wnc_gw"));
}

#[test]
fn every_chain_accepts_by_default() {
    for when in BOTH {
        for chain in table(inspection("0", when)).chains {
            assert_eq!(chain.policy, Policy::Accept, "chain {} must not drop by default", chain.name);
        }
    }
}

#[test]
fn forward_jumps_to_the_ids_chain() {
    let table = table(inspection("0", WhenUnavailable::Accept));
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
        let table = table(inspection("0", when));
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
fn control_packets_go_to_ids_before_trusted_flows_are_accepted() {
    let rules = &table(inspection("0", WhenUnavailable::Drop)).chains[0].rules;
    let ids = Statement::Jump("ids".into());
    let l2 = rules
        .iter()
        .position(|r| r == &vec![Statement::TcpFlagsAny(vec![TcpFlag::Fin, TcpFlag::Syn, TcpFlag::Rst]), ids.clone()])
        .expect("syn/fin/rst rule");
    let trusted = rules
        .iter()
        .position(|r| r == &vec![Statement::CtMarkHas(TRUSTED_MARK), Statement::Counter, Statement::Accept])
        .expect("trusted rule");
    assert!(l2 < trusted, "control packets must be checked before trusted flows are accepted");
    assert_eq!(rules.last(), Some(&vec![ids]));
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
fn trusted_mark_is_a_single_bit() {
    assert_eq!(TRUSTED_MARK.count_ones(), 1);
}

#[test]
fn a_bare_syn_clears_trust_before_anything_else_sees_it() {
    let rules = &table(inspection("0", WhenUnavailable::Drop)).chains[0].rules;
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
    let first_verdict = rules
        .iter()
        .position(|r| r.iter().any(|s| matches!(s, Statement::Jump(_) | Statement::Accept)))
        .expect("a rule with a verdict");
    assert!(
        clear < first_verdict,
        "a new connection reusing a trusted entry must lose the mark before its syn is judged"
    );
}
