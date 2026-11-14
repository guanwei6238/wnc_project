use super::*;

#[test]
fn defaults_to_ids() {
    assert_eq!(Protection::default(), Protection::Ids);
}

#[test]
fn round_trips() {
    for p in [Protection::Ids, Protection::Ips] {
        assert_eq!(p.to_string().parse::<Protection>(), Ok(p));
    }
}

#[test]
fn rejects_other_values() {
    assert_eq!(
        "IDS".parse::<Protection>().unwrap_err().to_string(),
        "invalid protection \"IDS\" (expected \"ids\" or \"ips\")"
    );
}

