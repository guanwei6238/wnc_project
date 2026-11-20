//! Per-entry cost of each stage of reading a feature table: as wnc-gw run did it before the plan
//! (current, legacy.rs), with the bench's plan written as JSON, binary or not at all, or with
//! what wnc-gw runs now (gw: its Table and Plan).
//! The bench's plan can read the map the old way (table), with a GET_NEXT_KEY walk into reused
//! buffers (walk) or BPF_MAP_LOOKUP_BATCH of N entries per call (batchN).
//! Usage: feature-bench <prog.o> <definition.json> <entry> <tc-egress|tc-ingress|xdp> <entries> <rounds> <gap_ms> <out_file> <current|plan-json|plan-bin|plan-none|gw> <table|walk|batchN|gw>
mod fast;
mod legacy;
mod read;

use std::alloc::{GlobalAlloc, Layout};
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Seek, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

use security_gateway::features::{
    definition::Definition,
    hook::{Hook, XdpMode},
    load,
    plan::Plan as GwPlan,
    runtime::attach_of,
};
use security_gateway::kernel::bpf::user::{Table, UserProgram};

use fast::Plan;
use legacy::{Deriver, Entry, json_line, table_readings};
use read::{Flat, Source};

#[cfg(feature = "mimalloc")]
use mimalloc::MiMalloc as Inner;
#[cfg(not(feature = "mimalloc"))]
use std::alloc::System as Inner;
const ALLOC: &str = if cfg!(feature = "mimalloc") { "mimalloc" } else { "system" };

struct Counting;
static COUNT: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if COUNT.load(Relaxed) {
            ALLOCS.fetch_add(1, Relaxed);
        }
        unsafe { Inner.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        if COUNT.load(Relaxed) {
            ALLOCS.fetch_add(1, Relaxed);
        }
        unsafe { Inner.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        if COUNT.load(Relaxed) {
            ALLOCS.fetch_add(1, Relaxed);
        }
        unsafe { Inner.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { Inner.dealloc(p, l) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const STAGES: [&str; 6] = ["read", "decode", "derive", "format", "write", "drop"];
const MODES: [&str; 5] = ["current", "plan-json", "plan-bin", "plan-none", "gw"];
const TS_MS: u64 = 1_763_500_000_000;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let reader_ok = |r: &str| r == "table" || r == "walk" || r.strip_prefix("batch").is_some_and(|n| n.parse::<usize>().is_ok_and(|n| n > 0));
    let pair_ok = |m: &str, r: &str| match m {
        "current" => r == "table",
        "gw" => r == "gw" || r == "gw-walk",
        _ => reader_ok(r),
    };
    if a.len() != 11 || !MODES.contains(&a[9].as_str()) || !pair_ok(&a[9], &a[10]) {
        eprintln!("usage: {} <prog.o> <definition.json> <entry> <tc-egress|tc-ingress|xdp> <entries> <rounds> <gap_ms> <out_file> <{}> <table|walk|batchN|gw|gw-walk>", a[0], MODES.join("|"));
        eprintln!("current only reads with table, gw only with gw or gw-walk");
        std::process::exit(2);
    }
    let (mode, reader) = (a[9].as_str(), a[10].as_str());
    let hook = match a[4].as_str() {
        "tc-egress" => Hook::TcEgress,
        "tc-ingress" => Hook::TcIngress,
        "xdp" => Hook::Xdp(XdpMode::Generic),
        h => panic!("unknown hook {h}"),
    };
    let (n, rounds, gap): (usize, usize, u64) = (a[5].parse().unwrap(), a[6].parse().unwrap(), a[7].parse().unwrap());
    let loaded = load::load(Path::new(&a[1]), Path::new(&a[2]), &a[3], hook).expect("load");
    let def = &loaded.definition;
    let info = loaded.elf.maps[&def.map];
    let (per_cpu, is_array) = (info.kind.per_cpu(), info.kind.is_array());
    let mut program = UserProgram::load(&loaded.bytes, &a[3], attach_of(hook)).expect("program");
    let key_size = def.key.as_ref().map_or(0, |k| k.size);
    let mut table = program.take_table(&def.map, key_size, def.value.size, per_cpu).expect("table");

    let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as usize;
    for i in 0..n {
        for j in 0..3 {
            pin((i + j) % cpus);
            program.test_run(&frame(i, 100 + 200 * j)).expect("test run");
        }
    }
    pin(0);

    let names: Vec<&str> = def.names().collect();
    let max = info.max_entries as usize;
    let mut plan = Plan::new(def, "flows", per_cpu, is_array);
    let mut flat = Flat::new(read::map_fd(info.max_entries, key_size, def.value.size, per_cpu), key_size, def.value.size, per_cpu);
    let fill = |flat: &mut Flat| match reader {
        "walk" => flat.walk(max),
        b => flat.batch(b["batch".len()..].parse().unwrap(), max),
    };
    let copies = if per_cpu { read::possible_cpus() } else { 1 };
    let old_read = |fd: i32| legacy::read(fd, key_size, def.value.size, copies, per_cpu, max);
    let mut gw = GwPlan::new(def, "flows", per_cpu, is_array);
    if reader == "gw-walk" {
        table.read_one_at_a_time();
    }
    match mode {
        "current" => {}
        "gw" => verify_gw(&program, &mut table, def, max, n, cpus, &names, &mut gw, (per_cpu, is_array), &|| old_read(flat.fd)),
        _ => verify(&program, def, n, cpus, &names, &mut plan, (per_cpu, is_array), reader, &mut flat, &fill, &old_read),
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut deriver = Deriver::default();
    let mut out = BufWriter::new(OpenOptions::new().create(true).write(true).truncate(true).open(&a[8]).expect("out"));
    let mut samples: Vec<[f64; 6]> = Vec::new();
    let mut allocs = [0u64; 6];
    let mut entries_read = 0;
    let mut line_bytes = 0usize;
    for round in 0..rounds + 3 {
        let counting = round == rounds + 2;
        let mut t = [Duration::ZERO; 6];
        let mut a = [0u64; 6];
        let mut mark = |i: usize, start: Instant, t: &mut [Duration; 6]| {
            t[i] = start.elapsed();
            a[i] = ALLOCS.swap(0, Relaxed);
        };
        COUNT.store(counting, Relaxed);
        ALLOCS.store(0, Relaxed);
        let s = Instant::now();
        let entries = if reader == "table" {
            old_read(flat.fd)
        } else if reader.starts_with("gw") {
            table.read(max).expect("read");
            Vec::new()
        } else {
            fill(&mut flat);
            Vec::new()
        };
        mark(0, s, &mut t);
        entries_read = match reader {
            "table" => entries.len(),
            "gw" | "gw-walk" => table.len(),
            _ => flat.len(),
        };
        if mode == "gw" {
            let s = Instant::now();
            gw.round(&table, Instant::now());
            mark(1, s, &mut t);
            let s = Instant::now();
            mark(2, s, &mut t);
            let s = Instant::now();
            buf.clear();
            gw.json(&mut buf, TS_MS);
            mark(3, s, &mut t);
            line_bytes = buf.len() / gw.len().max(1);
            let s = Instant::now();
            out.write_all(&buf).unwrap();
            out.flush().unwrap();
            mark(4, s, &mut t);
            let s = Instant::now();
            mark(5, s, &mut t);
        } else if mode == "current" {
            let s = Instant::now();
            let (mut readings, _bad) = table_readings(def, entries, per_cpu, is_array);
            mark(1, s, &mut t);
            let s = Instant::now();
            deriver.round(def, &mut readings, Instant::now());
            mark(2, s, &mut t);
            let s = Instant::now();
            let lines: Vec<String> = readings.iter().map(|r| json_line("flows", &names, r, TS_MS as u128)).collect();
            mark(3, s, &mut t);
            line_bytes = lines.iter().map(String::len).sum::<usize>() / lines.len().max(1);
            let s = Instant::now();
            for l in &lines {
                out.write_all(l.as_bytes()).unwrap();
            }
            out.flush().unwrap();
            mark(4, s, &mut t);
            let s = Instant::now();
            drop(lines);
            drop(readings);
            mark(5, s, &mut t);
        } else {
            let s = Instant::now();
            if reader == "table" {
                plan.decode(&entries[..]);
            } else {
                plan.decode(&flat);
            }
            mark(1, s, &mut t);
            let s = Instant::now();
            if reader == "table" {
                plan.derive(&entries[..], Instant::now());
            } else {
                plan.derive(&flat, Instant::now());
            }
            mark(2, s, &mut t);
            let s = Instant::now();
            buf.clear();
            match mode {
                "plan-json" => plan.json(&mut buf, TS_MS),
                "plan-bin" => plan.binary(&mut buf, TS_MS),
                _ => {}
            }
            mark(3, s, &mut t);
            line_bytes = buf.len() / plan.rows().max(1);
            let s = Instant::now();
            out.write_all(&buf).unwrap();
            out.flush().unwrap();
            mark(4, s, &mut t);
            let s = Instant::now();
            drop(entries);
            mark(5, s, &mut t);
        }
        COUNT.store(false, Relaxed);
        out.rewind().unwrap();
        if counting {
            allocs = a;
        } else if round >= 2 {
            samples.push(t.map(|d| d.as_nanos() as f64 / entries_read.max(1) as f64));
        }
        std::thread::sleep(Duration::from_millis(gap));
    }

    let (walk, lookup) = raw_baseline(&info, key_size, def.value.size, per_cpu, cpus);
    let ppid = {
        let s = Instant::now();
        for _ in 0..200_000 {
            unsafe { libc::syscall(libc::SYS_getppid) };
        }
        s.elapsed().as_nanos() as f64 / 200_000.0
    };

    println!("{mode}, read {reader}, alloc {ALLOC}, map {} ({}), {} entries read of {} filled, {} rounds, gap {} ms, {} cpus, {} bytes/entry", def.map, info.kind, entries_read, n, rounds, gap, cpus, line_bytes);
    println!("| stage | ns/entry median | min | max | allocs/entry |");
    println!("|---|---|---|---|---|");
    let mut total = [0.0; 3];
    for (i, stage) in STAGES.iter().enumerate() {
        let mut v: Vec<f64> = samples.iter().map(|s| s[i]).collect();
        v.sort_by(f64::total_cmp);
        let (med, lo, hi) = (v[v.len() / 2], v[0], v[v.len() - 1]);
        total[0] += med;
        total[1] += lo;
        total[2] += hi;
        println!("| {stage} | {med:.0} | {lo:.0} | {hi:.0} | {:.2} |", allocs[i] as f64 / entries_read.max(1) as f64);
    }
    println!("| sum | {:.0} | {:.0} | {:.0} | {:.2} |", total[0], total[1], total[2], allocs.iter().sum::<u64>() as f64 / entries_read.max(1) as f64);
    println!("raw: get_next_key {walk:.0} ns/entry, lookup {lookup:.0} ns/entry, getppid {ppid:.0} ns");
    let mut kvl = format!("bench=features mode={mode} read={reader} alloc={ALLOC} map={} kind={} entries={entries_read} rounds={rounds} gap_ms={gap} cpus={cpus} line_bytes={line_bytes}", def.map, info.kind);
    for (i, stage) in STAGES.iter().enumerate() {
        let mut v: Vec<f64> = samples.iter().map(|s| s[i]).collect();
        v.sort_by(f64::total_cmp);
        kvl += &format!(" {stage}_ns={:.0} {stage}_allocs={:.2}", v[v.len() / 2], allocs[i] as f64 / entries_read.max(1) as f64);
    }
    kvl += &format!(" raw_next_key_ns={walk:.0} raw_lookup_ns={lookup:.0} getppid_ns={ppid:.0}");
    println!("{kvl}");
}

/// Runs the current path and the plan side by side on the same reads and the same clock, with
/// packets in between so delta and rate move, and stops if any output byte differs.
#[allow(clippy::too_many_arguments)]
fn verify(
    program: &UserProgram,
    def: &Definition,
    n: usize,
    cpus: usize,
    names: &[&str],
    plan: &mut Plan,
    (per_cpu, skip_zero): (bool, bool),
    reader: &str,
    flat: &mut Flat,
    fill: &dyn Fn(&mut Flat),
    old_read: &dyn Fn(i32) -> Vec<Entry>,
) {
    let mut deriver = Deriver::default();
    for pass in 0..3 {
        if pass > 0 {
            for i in (0..n).step_by(7) {
                pin((i + pass) % cpus);
                program.test_run(&frame(i, 300 + 50 * pass)).expect("test run");
            }
            pin(0);
            std::thread::sleep(Duration::from_millis(50));
        }
        let entries = old_read(flat.fd);
        let copy: Vec<Entry> = entries.iter().map(|e| Entry { key: e.key.clone(), values: e.values.clone() }).collect();
        let now = Instant::now();
        let (mut readings, bad) = table_readings(def, copy, per_cpu, skip_zero);
        deriver.round(def, &mut readings, now);
        let want: String = readings.iter().map(|r| json_line("flows", names, r, TS_MS as u128)).collect();
        if reader == "table" {
            plan.decode(&entries[..]);
            plan.derive(&entries[..], now);
        } else {
            fill(flat);
            plan.decode(&*flat);
            plan.derive(&*flat, now);
        }
        let mut got = Vec::new();
        plan.json(&mut got, TS_MS);
        let mut bin = Vec::new();
        plan.binary(&mut bin, TS_MS);
        let back = plan.binary_to_json(&bin);
        let order = |text: &str| -> Vec<String> {
            let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
            if reader != "table" {
                lines.sort();
            }
            lines
        };
        let wanted = order(&want);
        for (what, bytes) in [("plan json", &got), ("binary read back", &back)] {
            let text = std::str::from_utf8(bytes).unwrap();
            if let Some((w, g)) = wanted.iter().zip(order(text).iter()).find(|(w, g)| w != g) {
                panic!("pass {pass}: {what} differs\n  want {w}\n  got  {g}");
            }
            assert_eq!(want.len(), text.len(), "pass {pass}: {what} has a different length");
        }
        assert_eq!(bad, plan.bad, "pass {pass}: bad entry counts differ");
        println!("verified pass {pass} ({reader}): {} lines identical (json {} bytes, binary {} bytes)", readings.len(), got.len(), bin.len());
    }
}

/// The same check for what wnc-gw runs now: its Table and Plan against the old read path.
#[allow(clippy::too_many_arguments)]
fn verify_gw(
    program: &UserProgram,
    table: &mut Table,
    def: &Definition,
    max: usize,
    n: usize,
    cpus: usize,
    names: &[&str],
    gw: &mut GwPlan,
    (per_cpu, skip_zero): (bool, bool),
    old_read: &dyn Fn() -> Vec<Entry>,
) {
    let mut deriver = Deriver::default();
    for pass in 0..3 {
        if pass > 0 {
            for i in (0..n).step_by(7) {
                pin((i + pass) % cpus);
                program.test_run(&frame(i, 300 + 50 * pass)).expect("test run");
            }
            pin(0);
            std::thread::sleep(Duration::from_millis(50));
        }
        let now = Instant::now();
        let (mut readings, bad) = table_readings(def, old_read(), per_cpu, skip_zero);
        deriver.round(def, &mut readings, now);
        let mut want: Vec<String> = readings.iter().map(|r| json_line("flows", names, r, TS_MS as u128).trim_end().to_string()).collect();
        table.read(max).expect("read");
        let gw_bad = gw.round(&*table, now);
        let mut out = Vec::new();
        gw.json(&mut out, TS_MS);
        let mut got: Vec<String> = String::from_utf8(out).unwrap().lines().map(str::to_string).collect();
        want.sort();
        got.sort();
        assert_eq!(want.len(), got.len(), "pass {pass}: line counts differ");
        if let Some((w, g)) = want.iter().zip(&got).find(|(w, g)| w != g) {
            panic!("pass {pass}: wnc-gw differs\n  want {w}\n  got  {g}");
        }
        assert_eq!(bad, gw_bad, "pass {pass}: bad entry counts differ");
        println!("verified pass {pass} (gw, batches {}): {} lines identical", table.reads_in_batches(), got.len());
    }
}

fn pin(cpu: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set);
    }
}

/// Ethernet + IPv4 + UDP from 10.(100+i/65536).(i/256).(i) port 40000 to 10.9.0.2:5001.
fn frame(i: usize, payload: usize) -> Vec<u8> {
    let mut f = vec![2, 0, 0, 0, 2, 1, 2, 0, 0, 0, 1, 2, 0x08, 0x00];
    let total = (20 + 8 + payload) as u16;
    f.extend_from_slice(&[0x45, 0]);
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
    f.extend_from_slice(&[10, 100 + (i >> 16) as u8, (i >> 8) as u8, i as u8, 10, 9, 0, 2]);
    f.extend_from_slice(&40000u16.to_be_bytes());
    f.extend_from_slice(&5001u16.to_be_bytes());
    f.extend_from_slice(&((8 + payload) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.resize(f.len() + payload, b'x');
    f
}

#[repr(C)]
#[derive(Default)]
struct ElemAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value_or_next_key: u64,
    flags: u64,
}

fn bpf(cmd: libc::c_long, attr: &mut ElemAttr) -> i64 {
    unsafe { libc::syscall(libc::SYS_bpf, cmd, attr as *mut ElemAttr, size_of::<ElemAttr>() as libc::c_uint) }
}

/// The table's map fd, found through /proc/self/fdinfo, timed with the bare syscalls and
/// buffers allocated once.
fn raw_baseline(info: &security_gateway::features::elf::MapInfo, key_size: usize, value_size: usize, per_cpu: bool, cpus: usize) -> (f64, f64) {
    let types: &[&str] = if per_cpu { &["5", "6", "10"] } else { &["1", "2", "9"] };
    let fd = fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok()?.parse::<i32>().ok())
        .find(|fd| {
            let Ok(s) = fs::read_to_string(format!("/proc/self/fdinfo/{fd}")) else { return false };
            let field = |k: &str| s.lines().find_map(|l| l.strip_prefix(k)).map(|v| v.trim().to_string());
            field("map_type:").is_some_and(|t| types.contains(&t.as_str()))
                && field("key_size:") == Some(key_size.to_string())
                && field("value_size:") == Some(value_size.to_string())
                && field("max_entries:") == Some(info.max_entries.to_string())
        })
        .expect("map fd");
    let slot = if per_cpu { value_size.next_multiple_of(8) * cpus } else { value_size };
    let mut keys = Vec::new();
    let (mut prev, mut next) = (vec![0u8; key_size], vec![0u8; key_size]);
    let mut first = true;
    let s = Instant::now();
    loop {
        let mut attr = ElemAttr {
            map_fd: fd as u32,
            key: if first { 0 } else { prev.as_ptr() as u64 },
            value_or_next_key: next.as_mut_ptr() as u64,
            ..Default::default()
        };
        if bpf(4, &mut attr) < 0 {
            break;
        }
        first = false;
        std::mem::swap(&mut prev, &mut next);
        keys.push(());
    }
    let walk = s.elapsed().as_nanos() as f64 / keys.len().max(1) as f64;
    let mut all = Vec::with_capacity(keys.len());
    let mut k = vec![0u8; key_size];
    let mut first = true;
    loop {
        let mut n = vec![0u8; key_size];
        let mut attr = ElemAttr { map_fd: fd as u32, key: if first { 0 } else { k.as_ptr() as u64 }, value_or_next_key: n.as_mut_ptr() as u64, ..Default::default() };
        if bpf(4, &mut attr) < 0 {
            break;
        }
        first = false;
        k = n.clone();
        all.push(n);
    }
    let mut value = vec![0u8; slot];
    let s = Instant::now();
    for key in &all {
        let mut attr = ElemAttr { map_fd: fd as u32, key: key.as_ptr() as u64, value_or_next_key: value.as_mut_ptr() as u64, ..Default::default() };
        bpf(1, &mut attr);
    }
    let lookup = s.elapsed().as_nanos() as f64 / all.len().max(1) as f64;
    (walk, lookup)
}
