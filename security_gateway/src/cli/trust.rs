use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use security_gateway::agent::control::{self, Flow, Request, Response, Tuple};
use security_gateway::kernel::conntrack::{FiveTuple, Protocol};
use security_gateway::platform::{Current, Dirs};

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

pub fn run(args: TrustArgs) -> ExitCode {
    let request = match args.command {
        TrustCommand::Add(args) => match tuple(&args) {
            Ok(tuple) => Request::Trust {
                connection: Tuple::of(&tuple),
            },
            Err(e) => return fail(e),
        },
        TrustCommand::Del(args) => match tuple(&args) {
            Ok(tuple) => Request::Untrust {
                connection: Tuple::of(&tuple),
            },
            Err(e) => return fail(e),
        },
        TrustCommand::List(_) => Request::List,
    };
    let path = control::socket_path(Current.runtime_dir());
    match control::request(&path, &request) {
        Ok(Response::Done) => ExitCode::SUCCESS,
        Ok(Response::Trusted { flows }) => {
            print_flows(&flows);
            ExitCode::SUCCESS
        }
        Ok(Response::Error { message }) => fail(message),
        Err(e) => fail(e),
    }
}

fn tuple(args: &ConnectionArgs) -> Result<FiveTuple, impl fmt::Display> {
    FiveTuple::new(
        args.protocol,
        SocketAddr::new(args.src, args.src_port),
        SocketAddr::new(args.dst, args.dst_port),
    )
}

fn print_flows(flows: &[Flow]) {
    out!(
        "{:<5} {:<40} {:<40} {:>10} {:>12} {:>10} {:>12}  {}",
        "PROTO", "SOURCE", "DESTINATION", "PACKETS->", "BYTES->", "PACKETS<-", "BYTES<-", "NEXT HOP -> / <-"
    );
    for flow in flows {
        let c = &flow.connection;
        let hop = |ip: Option<IpAddr>| ip.map_or_else(|| "-".to_owned(), |ip| ip.to_string());
        out!(
            "{:<5} {:<40} {:<40} {:>10} {:>12} {:>10} {:>12}  {} / {}",
            c.protocol,
            c.src.to_string(),
            c.dst.to_string(),
            flow.packets_original,
            flow.bytes_original,
            flow.packets_reply,
            flow.bytes_reply,
            hop(flow.next_hop_original),
            hop(flow.next_hop_reply)
        );
    }
}

fn fail(e: impl fmt::Display) -> ExitCode {
    eprintln!("error: {e}");
    ExitCode::FAILURE
}
