use std::io::{self, IsTerminal};

use clap::ValueEnum;
use tracing::Level;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn level(self) -> Level {
        match self {
            Self::Error => Level::ERROR,
            Self::Warn => Level::WARN,
            Self::Info => Level::INFO,
            Self::Debug => Level::DEBUG,
            Self::Trace => Level::TRACE,
        }
    }
}

pub fn init(format: LogFormat, level: LogLevel) {
    let builder = tracing_subscriber::fmt()
        .with_max_level(level.level())
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
