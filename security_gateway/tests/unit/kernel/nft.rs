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
