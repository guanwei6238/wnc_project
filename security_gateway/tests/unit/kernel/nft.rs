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
