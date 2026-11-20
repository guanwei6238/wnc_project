use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use security_gateway::config::{self, FeatureSettings, Overrides};
use security_gateway::features::{hook::Hook, load, pcap, plan::Plan, runtime::attach_of};
use security_gateway::kernel::bpf::user::UserProgram;

#[derive(Debug, Args)]
pub struct FeaturesArgs {
    #[command(subcommand)]
    command: FeaturesCommand,
}

#[derive(Debug, Subcommand)]
enum FeaturesCommand {
    Test(TestArgs),
}

#[derive(Debug, Args)]
struct TestArgs {
    name: String,
    pcap: PathBuf,
}

const RING_DRAIN_EVERY: usize = 1_000;

pub fn run(config_path: Option<&Path>, overrides: Overrides, args: FeaturesArgs) -> ExitCode {
    let FeaturesCommand::Test(args) = args.command;
    match test(config_path, overrides, &args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn test(config_path: Option<&Path>, overrides: Overrides, args: &TestArgs) -> Result<(), String> {
    let config = config::load(config_path, overrides).map_err(|e| e.to_string())?;
    let feature: &FeatureSettings = config
        .features
        .iter()
        .find(|f| f.name == args.name)
        .ok_or_else(|| format!("the config has no [[features]] named {:?}", args.name))?;
    let loaded = load::load(feature.program.as_path(), feature.definition.as_path(), &feature.entry, feature.hook)
        .map_err(|e| e.to_string())?;
    for problem in &loaded.problems {
        if problem.blocks_loading() {
            return Err(format!("feature {}: {problem} (see wnc-gw doctor)", feature.name));
        }
        eprintln!("note: feature {}: {problem}", feature.name);
    }
    let file = File::open(&args.pcap).map_err(|e| format!("cannot open {}: {e}", args.pcap.display()))?;
    let packets = pcap::packets(BufReader::new(file)).map_err(|e| e.to_string())?;
    let definition = &loaded.definition;
    let info = loaded.elf.maps[&definition.map];
    let mut program = UserProgram::load(&loaded.bytes, &feature.entry, attach_of(feature.hook)).map_err(|e| e.to_string())?;
    let mut returns: BTreeMap<u32, usize> = BTreeMap::new();
    let mut plan = Plan::new(definition, &feature.name, info.kind.per_cpu(), info.kind.is_array());
    let bad = if info.kind.is_events() {
        let mut ring = program.take_ring(&definition.map).map_err(|e| e.to_string())?;
        let mut records = Vec::new();
        for (i, packet) in packets.iter().enumerate() {
            *returns.entry(program.test_run(packet).map_err(|e| e.to_string())?).or_default() += 1;
            if i % RING_DRAIN_EVERY == RING_DRAIN_EVERY - 1 {
                records.extend(ring.drain(usize::MAX));
            }
        }
        records.extend(ring.drain(usize::MAX));
        plan.round(&records[..], Instant::now())
    } else {
        let key_size = definition.key.as_ref().map_or(0, |k| k.size);
        let mut table = program
            .take_table(&definition.map, key_size, definition.value.size, info.kind.per_cpu())
            .map_err(|e| e.to_string())?;
        for packet in &packets {
            *returns.entry(program.test_run(packet).map_err(|e| e.to_string())?).or_default() += 1;
        }
        table.read(info.max_entries as usize).map_err(|e| format!("cannot read map {}: {e}", definition.map))?;
        plan.round(&table, Instant::now())
    };
    let ts_ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    let mut lines = Vec::new();
    plan.json(&mut lines, ts_ms);
    for line in String::from_utf8_lossy(&lines).lines() {
        print_line(line);
    }
    let returned: Vec<String> = returns.iter().map(|(value, n)| format!("{} ×{n}", return_name(feature.hook, *value))).collect();
    eprintln!(
        "ran {} packets from {}: returned {}; {} records{}",
        packets.len(),
        args.pcap.display(),
        if returned.is_empty() { "nothing".to_string() } else { returned.join(", ") },
        plan.len(),
        if bad > 0 { format!(", {bad} did not match the definition's size") } else { String::new() }
    );
    Ok(())
}

fn print_line(line: &str) {
    out!("{}", line.trim_end());
}

fn return_name(hook: Hook, value: u32) -> String {
    let name = match (hook, value as i32) {
        (Hook::Xdp(_), 0) => "XDP_ABORTED",
        (Hook::Xdp(_), 1) => "XDP_DROP",
        (Hook::Xdp(_), 2) => "XDP_PASS",
        (Hook::Xdp(_), 3) => "XDP_TX",
        (Hook::Xdp(_), 4) => "XDP_REDIRECT",
        (Hook::TcIngress | Hook::TcEgress, -1) => "TCX_NEXT",
        (Hook::TcIngress | Hook::TcEgress, 0) => "TCX_PASS",
        (Hook::TcIngress | Hook::TcEgress, 2) => "TCX_DROP",
        (Hook::TcIngress | Hook::TcEgress, 7) => "TCX_REDIRECT",
        _ => return format!("{}", value as i32),
    };
    name.to_string()
}

#[cfg(test)]
mod tests;
