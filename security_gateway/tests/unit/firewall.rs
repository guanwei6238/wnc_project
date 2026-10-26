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
    assert_eq!(unavailable_rules(WhenUnavailable::Accept), [vec![Statement::Counter]]);
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
