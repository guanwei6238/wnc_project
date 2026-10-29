use std::io::{self, IsTerminal};

use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
}

pub fn init(format: LogFormat) {
    let builder = tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_target(false)
        .log_internal_errors(false);
    match format {
        LogFormat::Text => builder.with_ansi(io::stderr().is_terminal()).init(),
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false)
            .init(),
    }
}
