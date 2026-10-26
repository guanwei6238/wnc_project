use std::collections::HashSet;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use nftables::batch::Batch;
use nftables::expr::{Expression, Range};
use nftables::schema::{self, FlushObject, NfCmd, NfListObject};
use nftables::stmt::{self, Counter, JumpTarget, QueueFlag};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::nfqueue::QueueRange;

pub const DEFAULT_PATH: &str = "/usr/sbin/nft";
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nft {
    path: PathBuf,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Statement {
    Counter,
    Jump(String),
    Queue { queue: QueueRange, bypass: bool },
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub family: Family,
    pub name: String,
    pub chains: Vec<BaseChain>,
    pub regular_chains: Vec<RegularChain>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseChain {
    pub name: String,
    pub hook: Hook,
    pub priority: i32,
    pub policy: Policy,
    pub rules: Vec<Vec<Statement>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegularChain {
    pub name: String,
    pub rules: Vec<Vec<Statement>>,
}

#[derive(Debug, thiserror::Error)]
pub enum NftError {
    #[error("{} not found", .path.display())]
    NotFound { path: PathBuf },
    #[error("failed to run {}: {source}", .path.display())]
    Spawn { path: PathBuf, source: io::Error },
    #[error("{} did not finish within {} seconds", .path.display(), TIMEOUT.as_secs())]
    Timeout { path: PathBuf },
    #[error("{} failed ({status}): {stderr}", .path.display())]
    Failed {
        path: PathBuf,
        status: ExitStatus,
        stderr: String,
    },
}

impl Nft {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn info(&self) -> Result<NftInfo, NftError> {
        let stdout = self.run(&["-V"], b"").await?;
        Ok(NftInfo::parse(&String::from_utf8_lossy(&stdout)))
    }

    pub async fn replace_table(&self, table: &Table) -> Result<(), NftError> {
        self.apply(replace_batch(table)).await
    }

    pub async fn delete_table(&self, family: Family, name: &str) -> Result<(), NftError> {
        self.apply(delete_batch(family, name)).await
    }

    pub async fn replace_rules(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        rules: &[Vec<Statement>],
    ) -> Result<(), NftError> {
        self.apply(replace_rules_batch(family, table, chain, rules)).await
    }

    async fn apply(&self, batch: Batch<'_>) -> Result<(), NftError> {
        let json = serde_json::to_vec(&batch.to_nftables()).expect("nftables schema serializes to JSON");
        self.run(&["-j", "-f", "-"], &json).await.map(drop)
    }

    async fn run(&self, args: &[&str], input: &[u8]) -> Result<Vec<u8>, NftError> {
        let path = || self.path.clone();
        let mut child = match Command::new(&self.path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => child,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(NftError::NotFound { path: path() }),
            Err(source) => return Err(NftError::Spawn { path: path(), source }),
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
            Err(_) => return Err(NftError::Timeout { path: path() }),
            Ok(Err(source)) => return Err(NftError::Spawn { path: path(), source }),
            Ok(Ok(output)) => output,
        };
        if !output.status.success() {
            return Err(NftError::Failed {
                path: path(),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(output.stdout)
    }
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
    for chain in &table.regular_chains {
        batch.add(NfListObject::Chain(schema_chain(table.family, &table.name, &chain.name)));
    }
    for chain in &table.chains {
        batch.add(NfListObject::Chain(schema::Chain {
            _type: Some(NfChainType::Filter),
            hook: Some(hook(chain.hook)),
            prio: Some(chain.priority),
            policy: Some(policy(chain.policy)),
            ..schema_chain(table.family, &table.name, &chain.name)
        }));
    }
    let rules = table.regular_chains.iter().map(|c| (&c.name, &c.rules));
    for (chain, rules) in rules.chain(table.chains.iter().map(|c| (&c.name, &c.rules))) {
        add_rules(&mut batch, table.family, &table.name, chain, rules);
    }
    batch
}

fn replace_rules_batch<'a>(family: Family, table: &'a str, chain: &'a str, rules: &'a [Vec<Statement>]) -> Batch<'a> {
    let mut batch = Batch::new();
    batch.add_cmd(NfCmd::Flush(FlushObject::Chain(schema_chain(family, table, chain))));
    add_rules(&mut batch, family, table, chain, rules);
    batch
}

fn add_rules<'a>(batch: &mut Batch<'a>, f: Family, table: &'a str, chain: &'a str, rules: &'a [Vec<Statement>]) {
    for rule in rules {
        batch.add(NfListObject::Rule(schema::Rule {
            family: family(f),
            table: table.into(),
            chain: chain.into(),
            expr: rule.iter().map(statement).collect::<Vec<_>>().into(),
            ..Default::default()
        }));
    }
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

fn schema_chain<'a>(f: Family, table: &'a str, name: &'a str) -> schema::Chain<'a> {
    schema::Chain {
        family: family(f),
        table: table.into(),
        name: name.into(),
        ..Default::default()
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

fn statement(statement: &Statement) -> stmt::Statement<'_> {
    match statement {
        Statement::Counter => stmt::Statement::Counter(Counter::Anonymous(None)),
        Statement::Jump(chain) => stmt::Statement::Jump(JumpTarget {
            target: chain.as_str().into(),
        }),
        Statement::Queue { queue, bypass } => stmt::Statement::Queue(stmt::Queue {
            num: queue_num(*queue),
            flags: bypass.then(|| HashSet::from([QueueFlag::Bypass])),
        }),
        Statement::Drop => stmt::Statement::Drop(None),
    }
}

fn queue_num(queue: QueueRange) -> Expression<'static> {
    if queue.first() == queue.last() {
        return Expression::Number(queue.first().into());
    }
    Expression::Range(Box::new(Range {
        range: [
            Expression::Number(queue.first().into()),
            Expression::Number(queue.last().into()),
        ],
    }))
}

#[cfg(test)]
#[path = "../../tests/unit/kernel/nft.rs"]
mod tests;
