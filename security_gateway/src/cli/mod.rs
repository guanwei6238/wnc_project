pub mod doctor;
pub mod explain;
mod logging;
pub mod run;
pub mod show;
pub mod trust;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use security_gateway::config::Overrides;
use security_gateway::ports::PortSelector;

use logging::{LogFormat, LogLevel};

#[derive(Debug, Parser)]
#[command(name = "wnc-gw", version)]
pub struct Cli {
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[arg(long, global = true, value_name = "IFACE|MAC")]
    pub lan: Option<PortSelector>,

    #[arg(long, global = true, value_name = "IFACE|MAC")]
    pub wan: Option<PortSelector>,

    #[arg(long, global = true, value_name = "FORMAT", default_value = "text")]
    pub log_format: LogFormat,

    #[arg(long, global = true, value_name = "LEVEL", default_value = "info")]
    pub log_level: LogLevel,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Doctor(doctor::DoctorArgs),
    Explain(explain::ExplainArgs),
    Run(run::RunArgs),
    Show(show::ShowArgs),
    Trust(trust::TrustArgs),
}

pub async fn run() -> ExitCode {
    let cli = Cli::parse();
    let overrides = Overrides {
        lan: cli.lan,
        wan: cli.wan,
    };

    match cli.command {
        Command::Doctor(args) => doctor::run(cli.config.as_deref(), overrides, args).await,
        Command::Explain(args) => explain::run(args),
        Command::Run(args) => run::run(cli.config.as_deref(), overrides, cli.log_format, cli.log_level, args).await,
        Command::Show(args) => show::run(args).await,
        Command::Trust(args) => trust::run(args, cli.log_format, cli.log_level),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/cli/mod.rs"]
mod tests;
