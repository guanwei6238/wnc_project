use super::*;

#[test]
fn wrap_breaks_at_the_width_and_indents_the_rest() {
    let text = "word ".repeat(30);
    let wrapped = wrap(&text, "  - ", "    ");
    let lines: Vec<&str> = wrapped.lines().collect();
    assert!(lines.len() > 1);
    assert!(lines[0].starts_with("  - word"));
    assert!(lines[1..].iter().all(|line| line.starts_with("    word")));
    assert!(lines.iter().all(|line| line.chars().count() <= WIDTH));
}

#[test]
fn wrap_keeps_a_word_longer_than_the_width() {
    let long = "x".repeat(WIDTH + 10);
    assert_eq!(wrap(&long, "", ""), format!("{long}\n"));
}

#[test]
fn list_shows_every_code() {
    let text = list(Issue::ALL);
    assert_eq!(text.lines().count(), Issue::ALL.len() + 1);
    assert!(text.contains("R006  warning           the IPv4 default route does not go through WAN\n"));
}

#[test]
fn detail_has_the_header_cause_and_action() {
    let text = detail(Issue::NftNotFound.explanation());
    assert!(text.starts_with("N001: nft is not found\nseverity: error (doctor)\n\ncause:  "), "{text}");
    assert!(text.contains("\naction: Install nftables"), "{text}");
}

#[test]
fn continuation_lines_line_up_with_the_text() {
    let text = detail(Issue::RoutedDefaultRoute.explanation());
    let lines: Vec<&str> = text.lines().skip(3).collect();
    assert!(lines.len() > 2);
    for line in lines {
        assert!(line.starts_with("cause:  ") || line.starts_with("action: ") || line.starts_with("        "), "{line:?}");
    }
}
