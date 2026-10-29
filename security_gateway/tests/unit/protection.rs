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

#[test]
fn ids_copies_to_the_groups_and_ips_queues() {
    let (queue, group) = ("0-1".parse().unwrap(), "10-11".parse().unwrap());
    assert_eq!(Protection::Ids.delivery(queue, group), Delivery::Copy(group));
    assert_eq!(Protection::Ips.delivery(queue, group), Delivery::Queue(queue));
}
