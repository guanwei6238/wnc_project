use clap::CommandFactory;
use clap::error::ErrorKind;
use super::*;

#[test]
fn cli_definition_is_valid() {
    Cli::command().debug_assert();
}

#[test]
fn log_format_defaults_to_text() {
    let cli = Cli::try_parse_from(["wnc-gw", "run"]).unwrap();
    assert_eq!(cli.log_format, LogFormat::Text);
}

#[test]
fn log_format_is_accepted_before_and_after_the_subcommand() {
    for args in [["wnc-gw", "--log-format", "json", "run"], ["wnc-gw", "run", "--log-format", "json"]] {
        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(cli.log_format, LogFormat::Json, "args: {args:?}");
    }
}

#[test]
fn unknown_log_format_is_rejected() {
    let e = Cli::try_parse_from(["wnc-gw", "--log-format", "xml", "run"]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidValue);
}
