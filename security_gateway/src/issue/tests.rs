use std::collections::HashSet;

use super::*;

#[test]
fn codes_are_unique() {
    let mut seen = HashSet::new();
    for issue in Issue::ALL {
        assert!(seen.insert(issue.code()), "duplicate code {}", issue.code());
    }
}

#[test]
fn codes_are_a_letter_and_three_digits() {
    for issue in Issue::ALL {
        let code = issue.code().as_bytes();
        assert_eq!(code.len(), 4, "bad code {}", issue.code());
        assert!(code[0].is_ascii_uppercase(), "bad code {}", issue.code());
        assert!(code[1..].iter().all(u8::is_ascii_digit), "bad code {}", issue.code());
    }
}

#[test]
fn codes_parse_back_ignoring_case() {
    for &issue in Issue::ALL {
        assert_eq!(issue.code().parse::<Issue>(), Ok(issue));
        assert_eq!(issue.code().to_lowercase().parse::<Issue>(), Ok(issue));
        assert_eq!(issue.to_string(), issue.code());
    }
}

#[test]
fn unknown_code_is_an_error() {
    assert_eq!(
        "Z999".parse::<Issue>().unwrap_err().to_string(),
        "unknown code \"Z999\" (run wnc-gw explain to list them)"
    );
}

#[test]
fn every_issue_has_a_title_and_severity() {
    for issue in Issue::ALL {
        let e = issue.explanation();
        assert!(!e.title.is_empty(), "{} has no title", e.code);
        assert!(
            ["error", "warning", "note", "error or warning"].contains(&e.severity),
            "{} has severity {:?}",
            e.code,
            e.severity
        );
    }
}

#[test]
fn every_issue_is_explained() {
    for issue in Issue::ALL {
        let e = issue.explanation();
        assert!(!e.cause.is_empty(), "{} has no cause", e.code);
        assert!(!e.action.is_empty(), "{} has no action", e.code);
        assert!(!e.reported_by.is_empty(), "{} has no reporter", e.code);
    }
}

fn rust_files(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, files);
        } else if path.extension().is_some_and(|e| e == "rs") && !path.ends_with("tests.rs") {
            files.push(path);
        }
    }
}

#[test]
fn every_warning_and_error_log_has_a_code() {
    let mut files = Vec::new();
    rust_files(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
    let mut missing = Vec::new();
    for file in files {
        let source = std::fs::read_to_string(&file).unwrap();
        for macro_name in ["warn!(", "error!("] {
            for (at, _) in source.match_indices(macro_name) {
                let args = &source[at + macro_name.len()..];
                let first = args.trim_start();
                if !first.starts_with("code = %") {
                    let line = source[..at].lines().count() + 1;
                    missing.push(format!("{}:{line}", file.display()));
                }
            }
        }
    }
    assert!(missing.is_empty(), "log events without a code: {missing:?}");
}
