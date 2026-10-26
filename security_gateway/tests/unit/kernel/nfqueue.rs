use super::*;

fn queue(s: &str) -> QueueRange {
    s.parse().unwrap()
}

#[test]
fn single_queue() {
    let q = queue("0");
    assert_eq!((q.first(), q.last()), (0, 0));
    assert_eq!(q, QueueRange::default());
}

#[test]
fn queue_range() {
    let q = queue("2-5");
    assert_eq!((q.first(), q.last()), (2, 5));
    assert_eq!(queue("65535").last(), 65535);
}

#[test]
fn display_round_trips() {
    for s in ["0", "7", "0-3", "65534-65535"] {
        assert_eq!(queue(s).to_string(), s);
    }
    assert_eq!(queue("3-3").to_string(), "3");
}

#[test]
fn rejects_invalid_queues() {
    for s in ["", "-1", "65536", "3-1", "0-", "-3", "a", "0:3", " 0", "+1", "0-3-4"] {
        assert_eq!(
            s.parse::<QueueRange>().unwrap_err().to_string(),
            format!("invalid queue {s:?} (expected a number from 0 to 65535 such as 0, or a range such as \"0-3\")"),
            "{s:?} must be rejected"
        );
    }
}

#[derive(Debug, serde::Deserialize)]
struct Holder {
    queue: QueueRange,
}

fn from_toml(text: &str) -> Result<QueueRange, String> {
    toml::from_str::<Holder>(text).map(|h| h.queue).map_err(|e| e.to_string())
}

#[test]
fn deserializes_numbers_and_strings() {
    assert_eq!(from_toml("queue = 3").unwrap(), queue("3"));
    assert_eq!(from_toml("queue = \"0-3\"").unwrap(), queue("0-3"));
    assert_eq!(from_toml("queue = \"4\"").unwrap(), queue("4"));
}

#[test]
fn rejects_invalid_toml_values() {
    assert!(from_toml("queue = -1").unwrap_err().contains("invalid queue \"-1\""));
    assert!(from_toml("queue = 70000").unwrap_err().contains("invalid queue \"70000\""));
    assert!(from_toml("queue = 1.5").is_err());
    assert!(from_toml("queue = \"3-1\"").is_err());
}
