use super::*;

#[test]
fn defaults_to_group_10() {
    assert_eq!(GroupRange::default().to_string(), "10");
}

#[test]
fn parses_single_groups_and_ranges() {
    for s in ["1", "10", "10-11", "65535"] {
        assert_eq!(s.parse::<GroupRange>().unwrap().to_string(), s);
    }
    assert_eq!("10-12".parse::<GroupRange>().unwrap().groups().collect::<Vec<_>>(), [10, 11, 12]);
}

#[test]
fn rejects_group_0_and_bad_ranges() {
    for s in ["0", "0-3", "11-10", "x", "65536", ""] {
        assert_eq!(s.parse::<GroupRange>(), Err(ParseGroupRangeError(s.to_owned())), "{s:?}");
    }
    assert_eq!(
        "0".parse::<GroupRange>().unwrap_err().to_string(),
        "invalid group \"0\" (expected a number from 1 to 65535 such as 10, or a range such as \"10-11\")"
    );
}

#[test]
fn deserializes_numbers_and_strings() {
    #[derive(serde::Deserialize)]
    struct T {
        group: GroupRange,
    }
    assert_eq!(toml::from_str::<T>("group = 12").unwrap().group.to_string(), "12");
    assert_eq!(toml::from_str::<T>("group = \"10-11\"").unwrap().group.to_string(), "10-11");
    assert!(toml::from_str::<T>("group = 0").is_err());
}
