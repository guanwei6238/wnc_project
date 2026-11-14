use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use security_gateway::firewall;
use security_gateway::kernel::conntrack::{Connection, Conntrack, FiveTuple, Protocol};
use tracing::info;

use super::logging::{self, LogFormat, LogLevel};

#[derive(Debug, Args)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub command: TrustCommand,
}

#[derive(Debug, Subcommand)]
pub enum TrustCommand {
    Add(ConnectionArgs),
    Del(ConnectionArgs),
    List(ListArgs),
}

#[derive(Debug, Args)]
pub struct ConnectionArgs {
    #[arg(value_name = "PROTO")]
    pub protocol: Protocol,
    #[arg(value_name = "SRC_IP")]
    pub src: IpAddr,
    #[arg(value_name = "SRC_PORT")]
    pub src_port: u16,
    #[arg(value_name = "DST_IP")]
    pub dst: IpAddr,
    #[arg(value_name = "DST_PORT")]
    pub dst_port: u16,
}

#[derive(Debug, Args)]
pub struct ListArgs {}

pub fn run(args: TrustArgs, log_format: LogFormat, log_level: LogLevel) -> ExitCode {
    match args.command {
        TrustCommand::Add(args) => change(args, true, log_format, log_level),
        TrustCommand::Del(args) => change(args, false, log_format, log_level),
        TrustCommand::List(_) => list(),
    }
}

fn change(args: ConnectionArgs, trust: bool, log_format: LogFormat, log_level: LogLevel) -> ExitCode {
    let tuple = match FiveTuple::new(
        args.protocol,
        SocketAddr::new(args.src, args.src_port),
        SocketAddr::new(args.dst, args.dst_port),
    ) {
        Ok(tuple) => tuple,
        Err(e) => return fail(e),
    };
    let mut conntrack = match Conntrack::connect() {
        Ok(conntrack) => conntrack,
        Err(e) => return fail(e),
    };
    let result = if trust {
        firewall::trust(&mut conntrack, &tuple)
    } else {
        firewall::untrust(&mut conntrack, &tuple)
    };
    if let Err(e) = result {
        return fail(format_args!("{tuple}: {e}"));
    }
    logging::init(log_format, log_level);
    let connection = tuple.to_string();
    if trust {
        info!(connection = connection.as_str(), "connection trusted, its packets other than syn/fin/rst skip inspection");
    } else {
        info!(connection = connection.as_str(), "connection no longer trusted, its packets go to inspection again");
    }
    ExitCode::SUCCESS
}

fn list() -> ExitCode {
    match Conntrack::connect().and_then(|mut conntrack| firewall::trusted(&mut conntrack)) {
        Ok(connections) => {
            print_connections(&connections);
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

fn print_connections(connections: &[Connection]) {
    out!(
        "{:<10} {:<5} {:<24} {:<24} {:<11} {:>7} {}",
        "ID", "PROTO", "SOURCE", "DESTINATION", "STATE", "TIMEOUT", "MARK"
    );
    for c in connections {
        out!(
            "{:<10} {:<5} {:<24} {:<24} {:<11} {:>7} {:#010x}",
            c.id,
            c.original.protocol().to_string(),
            c.original.src().to_string(),
            c.original.dst().to_string(),
            c.tcp_state.map_or_else(|| "-".to_owned(), |s| s.to_string()),
            c.timeout_s.map_or_else(|| "-".to_owned(), |t| t.to_string()),
            c.mark,
        );
    }
}

fn fail(e: impl fmt::Display) -> ExitCode {
    eprintln!("error: {e}");
    ExitCode::FAILURE
}
