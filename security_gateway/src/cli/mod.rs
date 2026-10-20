pub mod doctor;
pub mod show;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/wnc-gw/setting.toml";

#[derive(Debug, Parser)]
#[command(name = "wnc-gw", version)]
pub struct Cli {
    #[arg(short, long, global = true, value_name = "FILE", default_value = DEFAULT_CONFIG_PATH)]
    pub config: PathBuf,

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

    match cli.command {
        Command::Doctor(args) => doctor::run(&cli.config, args).await,
        Command::Show(args) => show::run(args).await,
    }
}
