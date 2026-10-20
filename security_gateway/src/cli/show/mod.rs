pub mod interfaces;

use std::process::ExitCode;

use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct ShowArgs {
    #[command(subcommand)]
    pub command: ShowCommand,
}

#[derive(Debug, Subcommand)]
pub enum ShowCommand {
    Interfaces(interfaces::InterfacesArgs),
}

pub async fn run(args: ShowArgs) -> ExitCode {
    match args.command {
        ShowCommand::Interfaces(args) => interfaces::run(args).await,
    }
}
