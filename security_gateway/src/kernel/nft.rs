use std::io;
use std::process::ExitStatus;
use std::time::Duration;

use tokio::process::Command;

pub const NFT: &str = "/usr/sbin/nft";
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftInfo {
    pub version: Option<String>,
    pub json: Option<bool>,
}

#[derive(Debug, thiserror::Error)]
pub enum NftError {
    #[error("{} not found", NFT)]
    NotFound,
    #[error("failed to run {}: {}", NFT, .0)]
    Spawn(io::Error),
    #[error("{} did not finish within {} seconds", NFT, TIMEOUT.as_secs())]
    Timeout,
    #[error("{} failed ({status}): {stderr}", NFT)]
    Failed { status: ExitStatus, stderr: String },
}

pub async fn info() -> Result<NftInfo, NftError> {
    let stdout = run(&["-V"]).await?;
    Ok(NftInfo::parse(&String::from_utf8_lossy(&stdout)))
}

impl NftInfo {
    fn parse(output: &str) -> Self {
        let mut lines = output.lines();
        let version = lines
            .next()
            .and_then(|line| line.strip_prefix("nftables v"))
            .and_then(|rest| rest.split_whitespace().next())
            .map(str::to_owned);
        let json = lines
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.trim() == "json")
            .and_then(|(_, value)| match value.trim() {
                "yes" => Some(true),
                "no" => Some(false),
                _ => None,
            });
        Self { version, json }
    }
}

async fn run(args: &[&str]) -> Result<Vec<u8>, NftError> {
    let output = Command::new(NFT).args(args).kill_on_drop(true).output();
    let output = match tokio::time::timeout(TIMEOUT, output).await {
        Err(_) => return Err(NftError::Timeout),
        Ok(Err(e)) if e.kind() == io::ErrorKind::NotFound => return Err(NftError::NotFound),
        Ok(Err(e)) => return Err(NftError::Spawn(e)),
        Ok(Ok(output)) => output,
    };
    if !output.status.success() {
        return Err(NftError::Failed {
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(output.stdout)
}

#[cfg(test)]
#[path = "../../tests/unit/kernel/nft.rs"]
mod tests;
