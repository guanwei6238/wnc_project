use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::ExitCode;
use std::time::Instant;

use trust_sim::agent::Policy;
use trust_sim::eve;
use trust_sim::packet::{Key, Kind};
use trust_sim::pcap::Reader;
use trust_sim::sim::{Sim, Stats, Variant};

const USAGE: &str = "usage: trust_sim [--header] [--name NAME] [--eve EVE_JSON] [PCAP|-]";

const HEADER: &str = "name\tvariant\tpackets\tbytes\tfast_packets\tfast_bytes\tfast_packet_pct\tfast_byte_pct\t\
trusted\texpired\trevoked\trefused\tidle_ended\talerts_seen\talerts_missed\tpeak_conntrack\tpeak_trusted\t\
other_packets\tvlan_packets\tduration_s\talerts_unplaced\talerts_beyond_end\talerts_mismatched\talerts_out_of_order\tmissed_sids\t\
idle_resumed\tidle_resumed_packets\tidle_resumed_ports";

#[derive(Debug, Default)]
struct Input {
    other: u64,
    vlan: u64,
    first: Option<u64>,
    last: u64,
    unplaced: u64,
    beyond_end: u64,
    mismatched: u64,
    out_of_order: u64,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let (mut header, mut name, mut eve_path, mut pcap_path) = (false, String::from("-"), None, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--header" => header = true,
            "--name" => name = args.next().ok_or_else(usage)?,
            "--eve" => eve_path = Some(args.next().ok_or_else(usage)?),
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            _ if pcap_path.is_none() => pcap_path = Some(arg),
            _ => return Err(usage()),
        }
    }
    let mut out = io::stdout().lock();
    if header {
        writeln!(out, "{HEADER}")?;
        if pcap_path.is_none() && eve_path.is_none() {
            return Ok(());
        }
    }

    let eve: Box<dyn BufRead> = match &eve_path {
        Some(path) => Box::new(BufReader::with_capacity(1 << 20, File::open(path)?)),
        None => Box::new(io::empty()),
    };
    let mut alerts = eve::Alerts::new(eve);
    let input: Box<dyn Read> = match pcap_path.as_deref() {
        None | Some("-") => Box::new(io::stdin().lock()),
        Some(path) => Box::new(File::open(path)?),
    };
    let mut reader = Reader::new(BufReader::with_capacity(1 << 20, input))?;

    let started = Instant::now();
    let mut sims = [Variant::CtMark, Variant::Tc].map(|v| (v, Sim::new(v, Policy::default())));
    let mut seen = Input::default();
    let mut packet_alerts = Vec::new();
    let mut count = 0u64;
    while let Some((packet, vlan)) = reader.read_packet()? {
        count += 1;
        seen.first.get_or_insert(packet.ts);
        seen.last = packet.ts;
        seen.vlan += u64::from(vlan);
        alerts.take(count, &mut packet_alerts)?;
        match packet.kind {
            Kind::Other => seen.other += 1,
            Kind::Flow {
                protocol, src, dst, ..
            } => {
                let key = Key::new(protocol, src, dst);
                seen.mismatched += packet_alerts.iter().filter(|a| a.key.is_some_and(|k| k != key)).count() as u64;
            }
        }
        for (_, sim) in &mut sims {
            sim.packet(&packet, &packet_alerts);
        }
    }
    if reader.truncated {
        eprintln!("{name}: the last record is cut short; read up to the record before it");
    }
    seen.beyond_end = alerts.remaining()?;
    seen.unplaced = alerts.unplaced;
    seen.out_of_order = alerts.out_of_order;
    let elapsed = started.elapsed().as_secs_f64();
    eprintln!(
        "{name}: {count} packets in {elapsed:.1} s ({:.2} M packets/s)",
        count as f64 / elapsed.max(1e-9) / 1e6
    );
    for (variant, sim) in sims {
        writeln!(out, "{}", row(&name, variant, &sim.finish(), &seen))?;
    }
    Ok(())
}

fn usage() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, USAGE)
}

fn row(name: &str, variant: Variant, s: &Stats, seen: &Input) -> String {
    let pct = |part: u64, whole: u64| if whole == 0 { 0.0 } else { 100.0 * part as f64 / whole as f64 };
    let variant = match variant {
        Variant::CtMark => "ctmark",
        Variant::Tc => "tc",
    };
    let duration = seen.first.map_or(0.0, |first| (seen.last - first) as f64 / 1e9);
    let sids = s.missed_sids.iter().map(|(sid, n)| format!("{sid}:{n}")).collect::<Vec<_>>().join(",");
    let ports = s.idle_resumed_ports.iter().map(|(port, (c, p))| format!("{port}:{c}/{p}")).collect::<Vec<_>>().join(",");
    [
        name.to_string(),
        variant.to_string(),
        s.packets.to_string(),
        s.bytes.to_string(),
        s.fast_packets.to_string(),
        s.fast_bytes.to_string(),
        format!("{:.3}", pct(s.fast_packets, s.packets)),
        format!("{:.3}", pct(s.fast_bytes, s.bytes)),
        s.trusted.to_string(),
        s.expired.to_string(),
        s.revoked.to_string(),
        s.refused.to_string(),
        s.idle_ended.to_string(),
        s.alerts_seen.to_string(),
        s.alerts_missed.to_string(),
        s.peak_conntrack.to_string(),
        s.peak_trusted.to_string(),
        seen.other.to_string(),
        seen.vlan.to_string(),
        format!("{duration:.3}"),
        seen.unplaced.to_string(),
        seen.beyond_end.to_string(),
        seen.mismatched.to_string(),
        seen.out_of_order.to_string(),
        if sids.is_empty() { "-".to_string() } else { sids },
        s.idle_resumed.to_string(),
        s.idle_resumed_packets.to_string(),
        if ports.is_empty() { "-".to_string() } else { ports },
    ]
    .join("\t")
}
