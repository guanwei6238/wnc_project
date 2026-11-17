use std::io::{self, Write};
use std::process::ExitCode;

use clap::Args;
use security_gateway::issue::{Explanation, Issue};

const WIDTH: usize = 100;

#[derive(Debug, Args)]
pub struct ExplainArgs {
    #[arg(value_name = "CODE", conflicts_with = "all")]
    pub code: Option<Issue>,

    #[arg(long)]
    pub all: bool,
}

pub fn run(args: ExplainArgs) -> ExitCode {
    let text = match (args.code, args.all) {
        (Some(issue), _) => detail(issue.explanation()),
        (None, true) => Issue::ALL
            .iter()
            .map(|issue| detail(issue.explanation()))
            .collect::<Vec<_>>()
            .join("\n"),
        (None, false) => list(Issue::ALL),
    };
    let _ = io::stdout().write_all(text.as_bytes());
    ExitCode::SUCCESS
}

fn list(issues: &[Issue]) -> String {
    let mut out = format!("{:<5} {:<17} {}\n", "CODE", "SEVERITY", "TITLE");
    for issue in issues {
        let e = issue.explanation();
        out.push_str(&format!("{:<5} {:<17} {}\n", e.code, e.severity, e.title));
    }
    out
}

fn detail(e: &Explanation) -> String {
    let mut out = format!("{}: {}\n", e.code, e.title);
    out.push_str(&format!("severity: {} ({})\n\n", e.severity, e.reported_by));
    out.push_str(&wrap(e.cause, "cause:  ", "        "));
    out.push_str(&wrap(e.action, "action: ", "        "));
    out
}

fn wrap(text: &str, first: &str, rest: &str) -> String {
    let mut out = String::new();
    let mut line = first.to_owned();
    let mut empty = true;
    for word in text.split_whitespace() {
        if !empty && line.chars().count() + 1 + word.chars().count() > WIDTH {
            out.push_str(&line);
            out.push('\n');
            line = rest.to_owned();
            empty = true;
        }
        if !empty {
            line.push(' ');
        }
        line.push_str(word);
        empty = false;
    }
    out.push_str(&line);
    out.push('\n');
    out
}

#[cfg(test)]
mod tests;
