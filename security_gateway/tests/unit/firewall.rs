use super::*;

#[test]
fn table_is_ours() {
    let table = table();
    assert_eq!((table.family, table.name.as_str()), (Family::Inet, "wnc_gw"));
}

#[test]
fn every_chain_accepts_by_default() {
    for chain in table().chains {
        assert_eq!(chain.policy, Policy::Accept, "chain {} must not drop by default", chain.name);
    }
}
