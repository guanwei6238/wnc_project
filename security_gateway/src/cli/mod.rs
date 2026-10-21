pub mod doctor;
pub mod show;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use security_gateway::config::Overrides;
use security_gateway::ports::PortSelector;

#[derive(Debug, Parser)]
#[command(name = "wnc-gw", version)]
pub struct Cli {
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[arg(long, global = true, value_name = "IFACE|MAC")]
    pub lan: Option<PortSelector>,

    #[arg(long, global = true, value_name = "IFACE|MAC")]
    pub wan: Option<PortSelector>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Doctor(doctor::DoctorArgs),
    Show(show::ShowArgs),
}

pub async fn run() -> ExitCode {
    let cli = Cli::parse();
    let overrides = Overrides {
        lan: cli.lan,
        wan: cli.wan,
    };

    match cli.command {
        Command::Doctor(args) => doctor::run(cli.config.as_deref(), overrides, args).await,
        Command::Show(args) => show::run(args).await,
    }
}
