use std::path::Path;
use std::process::ExitCode;

use clap::Args;

#[derive(Debug, Args)]
pub struct DoctorArgs {}

pub async fn run(config: &Path, _args: DoctorArgs) -> ExitCode {
    println!("doctor（尚未實作）  設定檔: {}", config.display());
    ExitCode::SUCCESS
}
