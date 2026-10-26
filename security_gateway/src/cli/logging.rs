use std::io::{self, IsTerminal};

pub fn init() {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_ansi(io::stderr().is_terminal())
        .with_target(false)
        .init();
}
