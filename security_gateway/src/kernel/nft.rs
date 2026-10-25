use std::fmt;
use std::io;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use nftables::batch::Batch;
use nftables::schema::{self, NfListObject};
use nftables::stmt::{self, Counter};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub const NFT: &str = "/usr/sbin/nft";
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftInfo {
    pub version: Option<String>,
    pub json: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Inet,
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Inet => "inet",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    Forward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Accept,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Statement {
    Counter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub family: Family,
    pub name: String,
    pub chains: Vec<BaseChain>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseChain {
    pub name: String,
    pub hook: Hook,
    pub priority: i32,
    pub policy: Policy,
    pub rules: Vec<Vec<Statement>>,
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
    let stdout = run(&["-V"], b"").await?;
    Ok(NftInfo::parse(&String::from_utf8_lossy(&stdout)))
}

pub async fn replace_table(table: &Table) -> Result<(), NftError> {
    apply(replace_batch(table)).await
}

pub async fn delete_table(family: Family, name: &str) -> Result<(), NftError> {
    apply(delete_batch(family, name)).await
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

fn replace_batch(table: &Table) -> Batch<'_> {
    let mut batch = delete_batch(table.family, &table.name);
    batch.add(NfListObject::Table(schema_table(table.family, &table.name)));
    for chain in &table.chains {
        batch.add(NfListObject::Chain(schema::Chain {
            family: family(table.family),
            table: table.name.as_str().into(),
            name: chain.name.as_str().into(),
            _type: Some(NfChainType::Filter),
            hook: Some(hook(chain.hook)),
            prio: Some(chain.priority),
            policy: Some(policy(chain.policy)),
            ..Default::default()
        }));
        for rule in &chain.rules {
            batch.add(NfListObject::Rule(schema::Rule {
                family: family(table.family),
                table: table.name.as_str().into(),
                chain: chain.name.as_str().into(),
                expr: rule.iter().map(|s| statement(*s)).collect::<Vec<_>>().into(),
                ..Default::default()
            }));
        }
    }
    batch
}

fn delete_batch(family: Family, name: &str) -> Batch<'_> {
    let mut batch = Batch::new();
    batch.add(NfListObject::Table(schema_table(family, name)));
    batch.delete(NfListObject::Table(schema_table(family, name)));
    batch
}

fn schema_table(f: Family, name: &str) -> schema::Table<'_> {
    schema::Table {
        family: family(f),
        name: name.into(),
        handle: None,
    }
}

fn family(family: Family) -> NfFamily {
    match family {
        Family::Inet => NfFamily::INet,
    }
}

fn hook(hook: Hook) -> NfHook {
    match hook {
        Hook::Forward => NfHook::Forward,
    }
}

fn policy(policy: Policy) -> NfChainPolicy {
    match policy {
        Policy::Accept => NfChainPolicy::Accept,
    }
}

fn statement(statement: Statement) -> stmt::Statement<'static> {
    match statement {
        Statement::Counter => stmt::Statement::Counter(Counter::Anonymous(None)),
    }
}

async fn apply(batch: Batch<'_>) -> Result<(), NftError> {
    let json = serde_json::to_vec(&batch.to_nftables()).expect("nftables schema serializes to JSON");
    run(&["-j", "-f", "-"], &json).await.map(drop)
}

async fn run(args: &[&str], input: &[u8]) -> Result<Vec<u8>, NftError> {
    let mut child = match Command::new(NFT)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(NftError::NotFound),
        Err(e) => return Err(NftError::Spawn(e)),
    };
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let output = async move {
        match stdin.write_all(input).await {
            Err(e) if e.kind() != io::ErrorKind::BrokenPipe => return Err(e),
            _ => drop(stdin),
        }
        child.wait_with_output().await
    };
    let output = match tokio::time::timeout(TIMEOUT, output).await {
        Err(_) => return Err(NftError::Timeout),
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
