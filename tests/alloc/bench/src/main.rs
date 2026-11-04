// EVE 解析在不同 allocator 下的成本（3d 要大量解析 Suricata 的 EVE）
//   musl：Rust 的 musl target 內建的 malloc（wnc-gw 目前的組合）；glibc：gnu target；mimalloc：--features mimalloc
//   typed = 解析成只含 3d 可能用到欄位的 struct（其他欄位略過）；value = 解析成通用的 serde_json::Value（每個欄位都配置）
// 用法：alloc-bench <eve.json> [rounds]，Pi 上用 taskset 綁單核
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::hint::black_box;
use std::time::Instant;

use serde::Deserialize;

const ALLOCATOR: &str = if cfg!(feature = "mimalloc") {
    "mimalloc"
} else if cfg!(target_env = "musl") {
    "musl"
} else {
    "glibc"
};

#[allow(dead_code)]
#[derive(Deserialize)]
struct Event {
    timestamp: String,
    flow_id: Option<u64>,
    event_type: String,
    src_ip: Option<String>,
    src_port: Option<u16>,
    dest_ip: Option<String>,
    dest_port: Option<u16>,
    proto: Option<String>,
    app_proto: Option<String>,
    alert: Option<Alert>,
    flow: Option<Flow>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct Alert {
    action: String,
    signature_id: u64,
    rev: u64,
    signature: String,
    category: String,
    severity: u8,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct Flow {
    pkts_toserver: u64,
    pkts_toclient: u64,
    bytes_toserver: u64,
    bytes_toclient: u64,
    start: String,
    end: Option<String>,
    age: Option<u64>,
    state: Option<String>,
    reason: Option<String>,
    alerted: Option<bool>,
}

fn run(name: &str, round: usize, lines: &[&str], parse: impl Fn(&str)) {
    let bytes: usize = lines.iter().map(|l| l.len() + 1).sum();
    let t = Instant::now();
    for l in lines {
        parse(l);
    }
    let s = t.elapsed().as_secs_f64();
    println!(
        "{ALLOCATOR:<8} r{round} {name:<18} lines={:<7} {:>8.0} lines/s {:>7.2} us/line {:>7.1} MB/s",
        lines.len(),
        lines.len() as f64 / s,
        s * 1e6 / lines.len() as f64,
        bytes as f64 / s / 1e6
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: alloc-bench <eve.json> [rounds]");
    let rounds: usize = args.get(2).map_or(3, |r| r.parse().expect("rounds"));
    let data = std::fs::read_to_string(path).expect("read eve.json");
    let all: Vec<&str> = data.lines().filter(|l| !l.is_empty()).collect();
    let flow_alert: Vec<&str> = all
        .iter()
        .filter(|l| l.contains(r#""event_type":"flow""#) || l.contains(r#""event_type":"alert""#))
        .copied()
        .collect();
    for round in 1..=rounds {
        run("typed all", round, &all, |l| {
            black_box(serde_json::from_str::<Event>(l).expect("typed"));
        });
        run("typed flow+alert", round, &flow_alert, |l| {
            black_box(serde_json::from_str::<Event>(l).expect("typed"));
        });
        run("value all", round, &all, |l| {
            black_box(serde_json::from_str::<serde_json::Value>(l).expect("value"));
        });
    }
}
