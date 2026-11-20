use security_gateway::features::hook::XdpMode;

use super::*;

#[test]
fn return_values_are_named_by_hook() {
    assert_eq!(return_name(Hook::TcEgress, u32::MAX), "TCX_NEXT");
    assert_eq!(return_name(Hook::TcIngress, 2), "TCX_DROP");
    assert_eq!(return_name(Hook::Xdp(XdpMode::Native), 2), "XDP_PASS");
    assert_eq!(return_name(Hook::Xdp(XdpMode::Generic), 9), "9");
}

#[test]
fn parses_the_test_subcommand() {
    use clap::Parser;
    let cli = crate::cli::Cli::try_parse_from(["wnc-gw", "features", "test", "flows", "/tmp/x.pcap"]).unwrap();
    let crate::cli::Command::Features(FeaturesArgs { command: FeaturesCommand::Test(args) }) = cli.command else { panic!() };
    assert_eq!(args.name, "flows");
    assert_eq!(args.pcap, Path::new("/tmp/x.pcap"));
}
