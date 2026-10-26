use super::*;

#[test]
fn parses_version_and_json() {
    let output = "nftables v1.1.3 (Commodore Bullmoose #4)\n  cli:\t\teditline\n  json:\t\tyes\n  minigmp:\tno\n";
    assert_eq!(
        NftInfo::parse(output),
        NftInfo {
            version: Some("1.1.3".into()),
            json: Some(true),
        }
    );
}

#[test]
fn json_no_is_false() {
    let output = "nftables v1.0.9 (Old Doc Yak #3)\n  json:\t\tno\n";
    assert_eq!(NftInfo::parse(output).json, Some(false));
}

#[test]
fn missing_json_line_is_unknown() {
    let output = "nftables v1.1.3 (Commodore Bullmoose #4)\n  cli:\t\teditline\n";
    assert_eq!(NftInfo::parse(output).json, None);
}

#[test]
fn unexpected_json_value_is_unknown() {
    let output = "nftables v1.1.3 (Commodore Bullmoose #4)\n  json:\t\tmaybe\n";
    assert_eq!(NftInfo::parse(output).json, None);
}

#[test]
fn unexpected_first_line_has_no_version() {
    assert_eq!(
        NftInfo::parse("something else\n  json:\tyes\n"),
        NftInfo {
            version: None,
            json: Some(true),
        }
    );
    assert_eq!(NftInfo::parse(""), NftInfo { version: None, json: None });
}

#[test]
fn json_on_first_line_is_ignored() {
    assert_eq!(NftInfo::parse("json: yes\n").json, None);
}

fn json(batch: Batch<'_>) -> serde_json::Value {
    serde_json::to_value(batch.to_nftables()).unwrap()
}

#[test]
fn delete_adds_the_table_first() {
    assert_eq!(
        json(delete_batch(Family::Inet, "demo")),
        serde_json::json!({"nftables": [
            {"add": {"table": {"family": "inet", "name": "demo"}}},
            {"delete": {"table": {"family": "inet", "name": "demo"}}},
        ]})
    );
}

#[test]
fn replace_deletes_then_recreates_in_one_batch() {
    let table = Table {
        family: Family::Inet,
        name: "demo".into(),
        chains: vec![BaseChain {
            name: "fwd".into(),
            hook: Hook::Forward,
            priority: 0,
            policy: Policy::Accept,
            rules: vec![vec![Statement::Counter]],
        }],
        regular_chains: vec![],
    };
    assert_eq!(
        json(replace_batch(&table)),
        serde_json::json!({"nftables": [
            {"add": {"table": {"family": "inet", "name": "demo"}}},
            {"delete": {"table": {"family": "inet", "name": "demo"}}},
            {"add": {"table": {"family": "inet", "name": "demo"}}},
            {"add": {"chain": {
                "family": "inet", "table": "demo", "name": "fwd",
                "type": "filter", "hook": "forward", "prio": 0, "policy": "accept",
            }}},
            {"add": {"rule": {"family": "inet", "table": "demo", "chain": "fwd", "expr": [{"counter": null}]}}},
        ]})
    );
}

#[test]
fn replace_creates_every_chain_before_any_rule() {
    let table = Table {
        family: Family::Inet,
        name: "demo".into(),
        chains: vec![BaseChain {
            name: "fwd".into(),
            hook: Hook::Forward,
            priority: 0,
            policy: Policy::Accept,
            rules: vec![vec![Statement::Jump("sub".into())]],
        }],
        regular_chains: vec![RegularChain {
            name: "sub".into(),
            rules: vec![vec![Statement::Counter, Statement::Drop]],
        }],
    };
    let ops = json(replace_batch(&table))["nftables"].as_array().unwrap().clone();
    assert_eq!(
        &ops[2..],
        [
            serde_json::json!({"add": {"table": {"family": "inet", "name": "demo"}}}),
            serde_json::json!({"add": {"chain": {"family": "inet", "table": "demo", "name": "sub"}}}),
            serde_json::json!({"add": {"chain": {
                "family": "inet", "table": "demo", "name": "fwd",
                "type": "filter", "hook": "forward", "prio": 0, "policy": "accept",
            }}}),
            serde_json::json!({"add": {"rule": {
                "family": "inet", "table": "demo", "chain": "sub", "expr": [{"counter": null}, {"drop": null}],
            }}}),
            serde_json::json!({"add": {"rule": {
                "family": "inet", "table": "demo", "chain": "fwd", "expr": [{"jump": {"target": "sub"}}],
            }}}),
        ]
    );
}

#[test]
fn replace_rules_flushes_the_chain_in_the_same_batch() {
    let rules = [vec![Statement::Counter, Statement::Queue { queue: "0".parse().unwrap(), bypass: true }]];
    assert_eq!(
        json(replace_rules_batch(Family::Inet, "demo", "sub", &rules)),
        serde_json::json!({"nftables": [
            {"flush": {"chain": {"family": "inet", "table": "demo", "name": "sub"}}},
            {"add": {"rule": {
                "family": "inet", "table": "demo", "chain": "sub",
                "expr": [{"counter": null}, {"queue": {"num": 0, "flags": ["bypass"]}}],
            }}},
        ]})
    );
}

#[test]
fn queue_ranges_and_flags() {
    let expr = |queue: &str, bypass| {
        serde_json::to_value(statement(&Statement::Queue { queue: queue.parse().unwrap(), bypass })).unwrap()
    };
    assert_eq!(expr("2", false), serde_json::json!({"queue": {"num": 2}}));
    assert_eq!(
        expr("0-3", true),
        serde_json::json!({"queue": {"num": {"range": [0, 3]}, "flags": ["bypass"]}})
    );
}

#[test]
fn family_display() {
    assert_eq!(Family::Inet.to_string(), "inet");
}

#[tokio::test(flavor = "current_thread")]
async fn runs_the_configured_path() {
    let nft = Nft::new("/nonexistent/nft");
    let err = nft.info().await.unwrap_err();
    assert!(matches!(&err, NftError::NotFound { path } if path == Path::new("/nonexistent/nft")));
    assert_eq!(err.to_string(), "/nonexistent/nft not found");
}
