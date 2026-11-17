use super::*;

#[test]
fn display_names_the_mechanism_and_numbers() {
    assert_eq!(Delivery::Queue("0-3".parse().unwrap()).to_string(), "nfqueue 0-3");
    assert_eq!(Delivery::Copy("10".parse().unwrap()).to_string(), "nflog 10");
}
