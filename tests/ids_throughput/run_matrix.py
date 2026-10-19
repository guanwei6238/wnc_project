#!/usr/bin/env python3
"""run_matrix.py -- 跑量測矩陣：(pcap) x (引擎) x (規則集)，各組態「輪流交錯」重複，每次一行寫進 CSV。只用標準函式庫。

用法例（在 Pi 上，native 模式直接呼叫主機的 suricata/snort；批次腳本 run_pi_*.sh 就是這樣呼叫）:
  MODE=native ./run_matrix.py --tag pi_try --pcaps C_somfy02.pcap --engines suricata,snort --rules full --reps 1 --warmup 1 --runs-dir $BIG/runs
  MODE=native ./run_matrix.py --tag pi_x --pcaps S_m39 --rules empty,gw_corp     # 不以 .pcap 結尾 -> 自動加上 S_m39.pcap 與 S_m39.small.pcap
  MODE=docker 則是在工作站的 Docker 容器（image wnc-ids-lab）裡跑同一支 measure.sh。

為什麼這樣設計:
  * 一個 round = 把「所有組態各跑 1 次」(順序每 round 重新洗牌，seed 固定可重現)。round 0 是 warm-up(丟棄)，之後才是正式。
    -> 不會把同一組態連續跑 5 次，機器負載/溫度漂移會平均分散到各組態，而不是變成「某組態比較慢」的假差異。
  * 每次量測都在『一個新的』容器/行程裡跑一次 measure.sh，前後讀 load average、溫度、throttled。
  * Pi 的 throttled 閘門（只看「這次量測期間」）: (1) 量測前或後的『目前』位元 bit0–3 不是 0；(2) bit16–19『開機後曾發生』位元
    在量測前後有改變（= 量測期間又發生一次）-> 這次標為作廢(void)。開機前就存在且沒變的高位元不算（它們要重開機才會清）。
    注意: bit16 以上是「開機以來發生過」，不會自己清掉；若曾經欠壓，要重開機才會回到 0x0。
  * 原始 log 留在 RUNS/<tag>/<run_id>/（repo 外），CSV 只放解析後的數字。
"""
import argparse, csv, json, os, random, re, shutil, signal, subprocess, sys, time, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
BIG = os.environ.get("BIG", "/home/sixsquare/datasets/throughput")
IMAGE = os.environ.get("IMAGE", "wnc-ids-lab")

# ---------------- 硬體 / 狀態讀取（Pi 才有 vcgencmd；沒有就留空，不算作廢） ----------------
VCG = os.environ.get("VCGENCMD") or shutil.which("vcgencmd")

def throttle_void(before, after):
    """throttled 閘門。before/after 是 vcgencmd get_throttled 的字串（如 '0xe0008'）；沒有 vcgencmd 時是空字串。
    回傳作廢理由的 list（空 = 通過）。只看「這次量測期間」的狀態：
      - 目前位元 bit0–3（欠壓、時脈上限、降頻、溫度上限）在前後都必須是 0
      - 『開機後曾發生』位元 bit16–19 在前後不可改變（改變 = 量測期間又發生了一次）
    開機前就存在且沒變的高位元（要重開機才會清）不算作廢。"""
    why = []
    if not before or not after:
        return why
    try:
        tb, ta = int(before, 16), int(after, 16)
    except ValueError:
        return ["throttled_unparsable:%s/%s" % (before, after)]
    if tb & 0xF: why.append("throttled_before_now=0x%x" % (tb & 0xF))
    if ta & 0xF: why.append("throttled_after_now=0x%x" % (ta & 0xF))
    if (tb & 0xF0000) != (ta & 0xF0000):
        why.append("throttle_event_during_run:0x%x->0x%x" % (tb & 0xF0000, ta & 0xF0000))
    return why


def sh(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""

def vcg(*a):
    return sh([VCG, *a]) if VCG else ""

def read_state():
    """回傳 dict: throttled(字串如 0x0)、temp(°C)、arm_clock(Hz)；沒有 vcgencmd 時是空字串。"""
    thr = vcg("get_throttled").split("=")[-1] if VCG else ""
    t = re.search(r"temp=([\d.]+)", vcg("measure_temp")) if VCG else None
    c = re.search(r"=(\d+)", vcg("measure_clock", "arm")) if VCG else None
    return dict(throttled=thr, temp=t.group(1) if t else "", clock=c.group(1) if c else "")

def read_first(path):
    try:
        return open(path).read().strip().strip("\x00")
    except Exception:
        return ""

def cpu_model():
    for line in read_first("/proc/cpuinfo").splitlines():
        if line.lower().startswith(("model name", "hardware")):
            return line.split(":", 1)[1].strip()
    return sh(["lscpu"]).split("Model name:")[-1].split("\n")[0].strip()

# ---------------- 解析引擎 log ----------------
def parse_time_v(path):
    d = {}
    try:
        txt = open(path).read()
    except Exception:
        return d
    def g(pat):
        m = re.search(pat, txt)
        return float(m.group(1)) if m else None
    d["user_s"] = g(r"User time \(seconds\): ([\d.]+)")
    d["sys_s"] = g(r"System time \(seconds\): ([\d.]+)")
    kb = g(r"Maximum resident set size \(kbytes\): (\d+)")
    d["maxrss_mb"] = round(kb / 1024, 1) if kb is not None else None
    return d

def parse_kv(path):
    d = {}
    for line in open(path):
        if "=" in line:
            k, v = line.rstrip("\n").split("=", 1); d[k] = v
    return d

def parse_suricata(rundir):
    log = open(os.path.join(rundir, "engine.log"), errors="replace").read()
    d = {}
    m = re.search(r"time elapsed ([\d.]+)s", log); d["self_s"] = float(m.group(1)) if m else None
    m = re.search(r"Threads created -> W: (\d+)", log); d["workers"] = int(m.group(1)) if m else None
    m = re.search(r"pcap: read \d+ files?, (\d+) packets, (\d+) bytes", log)
    if m: d["pcap_read_pkts"], d["pcap_read_bytes"] = int(m.group(1)), int(m.group(2))
    # stats.log 可能有多個區塊（每 8 秒一個 + 結束時一個），取最後一個 "Date:" 之後的
    try:
        st = open(os.path.join(rundir, "stats.log"), errors="replace").read().split("Date:")[-1]
        def sv(name):
            m = re.search(r"^%s\s+\|\s+Total\s+\|\s+(\d+)" % re.escape(name), st, re.M)
            return int(m.group(1)) if m else 0
        d["pkts"], d["bytes"] = sv("decoder.pkts"), sv("decoder.bytes")
        d["alerts"], d["suppressed"] = sv("detect.alert"), sv("detect.alerts_suppressed")
    except Exception:
        pass
    return d

def parse_snort(rundir):
    log = open(os.path.join(rundir, "engine.log"), errors="replace").read()
    d = {}
    # Snort 的 summary 是「區段標題 + 縮排的 key: value」
    sec, vals = None, {}
    for line in log.splitlines():
        if line and not line[0].isspace() and not line.startswith(("-", "=")):
            sec = line.strip()
        else:
            m = re.match(r"\s+([A-Za-z_ ]+):\s+([\d.]+)", line)
            if m and sec:
                vals.setdefault(sec, {}).setdefault(m.group(1).strip(), m.group(2))
    d["self_s"] = float(vals["timing"]["seconds"]) if "timing" in vals else None
    dq = vals.get("daq", {})
    d["pkts"] = int(dq.get("analyzed", 0)); d["bytes"] = int(dq.get("rx_bytes", 0))
    d["alerts"] = int(float(vals.get("detection", {}).get("alerts", 0))); d["suppressed"] = ""
    d["workers"] = 1
    m = re.search(r"total rules loaded: (\d+)", log); d["rules_loaded"] = int(m.group(1)) if m else ""
    return d

def top_sids(rundir, n=3):
    try:
        lines = [l.split() for l in open(os.path.join(rundir, "sids.txt")) if l.strip()]
        return ";".join("%s:%s" % (l[1], l[0]) for l in lines[:n])
    except Exception:
        return ""

# ---------------- 組出一次量測的指令 ----------------
def build_cmd(a, engine, rules, pcap_name, run_id):
    if a.mode == "docker":
        os.makedirs(os.path.join(a.runs, run_id), exist_ok=True)
        return ["docker", "run", "--rm", "--network", "none", "--user", "%d:%d" % (os.getuid(), os.getgid()),
                "--cpuset-cpus", a.cpuset, "--memory", a.mem, "--memory-swap", a.mem,
                "--tmpfs", "/work:rw,size=%s,mode=1777" % a.tmpfs,
                "-v", "%s:/pcaps:ro" % a.pcaps, "-v", "%s:/rules:ro" % a.rules_dir,
                "-v", "%s:/scripts:ro" % HERE, "-v", "%s:/out" % a.runs,
                "-e", "WORK=/work", "-e", "RULES_DIR=/rules", "-e", "THREADS=%d" % a.threads,
                IMAGE, "/scripts/measure.sh", engine, rules, "/pcaps/" + pcap_name, "/out/" + run_id]
    env_cpuset = a.cpuset if a.cpuset != "none" else ""
    return ["env", "WORK=" + a.work, "RULES_DIR=" + a.rules_dir, "THREADS=%d" % a.threads, "CPUSET=" + env_cpuset,
            os.path.join(HERE, "measure.sh"), engine, rules, os.path.join(a.pcaps, pcap_name), os.path.join(a.runs, run_id)]

COLS = ["ts_utc", "tag", "run_id", "mode", "round", "warmup", "order", "engine", "rules", "pcap", "kind", "threads",
        "load1", "temp_before", "temp_after", "arm_clock_before", "throttled_before", "throttled_after", "void", "void_reason",
        "exit_code", "wall_s", "self_s", "user_s", "sys_s", "cpu_s", "maxrss_mb",
        "pkts_expected", "pkts_reported", "bytes_expected", "bytes_reported", "pkts_match", "bytes_match",
        "pps_self", "mbps_self", "alerts", "suppressed", "top_sids", "workers"]

def one_run(a, man, job, rnd, order, writer, fh):
    pcap_name, engine, rules = job
    run_id = "%s_r%d_%03d_%s_%s_%s" % (a.tag, rnd, order, engine, rules, pcap_name.replace(".pcap", ""))
    m = man[pcap_name]
    before = read_state()
    load1 = os.getloadavg()[0]
    cmd = build_cmd(a, engine, rules, pcap_name, run_id)
    # 用新的行程群組執行；逾時就殺掉「整個群組」（measure.sh 底下的 time / taskset / 引擎一起殺）並記成結果，不丟例外。
    # 為什麼不用 subprocess.run(timeout=)：它逾時只殺直接的子行程，引擎可能變成孤兒繼續吃記憶體；而且逾時會丟例外讓整批崩潰。
    # 限制：docker 模式下殺掉的是 `docker run` 客戶端，容器可能留著跑完（--rm 會自己清掉）；本步驟的逾時主要用在 native（Pi）模式。
    timed_out = False
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        proc.wait(timeout=a.timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
    after = read_state()
    rundir = os.path.join(a.runs, run_id)
    row = dict(ts_utc=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), tag=a.tag, run_id=run_id,
               mode=a.mode, round=rnd, warmup=int(rnd < a.warmup), order=order, engine=engine, rules=rules, pcap=pcap_name,
               kind=m["kind"], threads=a.threads, load1=round(load1, 2), temp_before=before["temp"], temp_after=after["temp"],
               arm_clock_before=before["clock"], throttled_before=before["throttled"], throttled_after=after["throttled"])
    void = []
    if timed_out:
        row["exit_code"] = 124; row["wall_s"] = a.timeout
        void.append("timeout_%ds" % a.timeout)
    else:
        try:
            kv = parse_kv(os.path.join(rundir, "timing.kv")); row["exit_code"] = int(kv["exit_code"])
            row["wall_s"] = round(int(kv["wall_us"]) / 1e6, 4)
            row.update(parse_time_v(os.path.join(rundir, "time.txt")))
            res = parse_suricata(rundir) if engine == "suricata" else parse_snort(rundir)
            row["self_s"] = res.get("self_s"); row["workers"] = res.get("workers")
            row["pkts_reported"], row["bytes_reported"] = res.get("pkts"), res.get("bytes")
            row["alerts"], row["suppressed"] = res.get("alerts"), res.get("suppressed", "")
            row["top_sids"] = top_sids(rundir)
            if row["exit_code"] != 0: void.append("exit=%s" % row["exit_code"])
            if row["self_s"] is None: void.append("no_self_time")
        except Exception as e:                           # 任何解析失敗都要留下紀錄，不能默默略過
            void.append("parse_error:%s" % e)
    if row.get("user_s") is not None:
        row["cpu_s"] = round(row["user_s"] + row["sys_s"], 3)
    row["pkts_expected"], row["bytes_expected"] = m["packets"], m["bytes_cap"]
    row["pkts_match"] = int(row.get("pkts_reported") == m["packets"])
    row["bytes_match"] = int(row.get("bytes_reported") == m["bytes_cap"])
    if row.get("self_s"):
        row["pps_self"] = round(row["pkts_reported"] / row["self_s"]) if row.get("pkts_reported") else ""
        row["mbps_self"] = round(row["bytes_reported"] * 8 / row["self_s"] / 1e6, 2) if row.get("bytes_reported") else ""
    # throttled 閘門（有 vcgencmd 才檢查）
    void.extend(throttle_void(row["throttled_before"], row["throttled_after"]))
    row["void"] = int(bool(void)); row["void_reason"] = "|".join(void)
    writer.writerow(row); fh.flush()
    return row

def write_env(a, path):
    env = dict(date_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), mode=a.mode, tag=a.tag,
               cpu_model=cpu_model(), cpu_cores_online=os.cpu_count(),
               governor=read_first("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
               mem_total_kb=re.search(r"MemTotal:\s+(\d+)", read_first("/proc/meminfo")).group(1),
               kernel=sh(["uname", "-srm"]), device_tree_model=read_first("/proc/device-tree/model"),
               vcgencmd=bool(VCG), state_at_start=read_state(),
               params=dict(cpuset=a.cpuset, container_mem=a.mem if a.mode == "docker" else None, tmpfs=a.tmpfs if a.mode == "docker" else a.work,
                           threads=a.threads, reps=a.reps, warmup=a.warmup, seed=a.seed, pcaps=a.pcap_list, engines=a.engine_list, rules=a.rule_list),
               loadavg_at_start=os.getloadavg())
    if a.mode == "docker":
        env["docker_image_id"] = sh(["docker", "image", "inspect", "-f", "{{.Id}}", IMAGE])
        pre = ["docker", "run", "--rm", "--network", "none", IMAGE]
    else:
        pre = []
    env["suricata_version"] = sh(pre + ["suricata", "-V"])
    env["snort_version"] = sh(pre + ["snort", "-V"]).replace("\n", " ")
    env["rules_sha256"] = read_first(os.path.join(a.rules_dir, "SHA256SUMS")).splitlines()
    # 範例指令列（每次量測實際用的完整指令在 RUNS/<tag>/<run_id>/timing.kv 的 cmd= 與 docker 參數）
    env["example_docker_cmd"] = " ".join(build_cmd(a, "suricata", "full", "X.pcap", "RUN")) if a.mode == "docker" else ""
    json.dump(env, open(path, "w"), indent=1, ensure_ascii=False)

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", default=os.environ.get("MODE", "docker"), choices=["docker", "native"])
    p.add_argument("--tag", required=True, help="這批量測的名字；CSV=results/<tag>.csv，原始 log=RUNS/<tag>/")
    p.add_argument("--pcaps", default="A_scan17,B1_pay5,B2_mix3,C_somfy02", help="逗號分隔；若不是以 .pcap 結尾，會自動加上 X.pcap 與 X.small.pcap 兩個")
    p.add_argument("--engines", default="suricata,snort")
    p.add_argument("--rules", default="empty,common,full")
    p.add_argument("--reps", type=int, default=5); p.add_argument("--warmup", type=int, default=1)
    p.add_argument("--threads", type=int, default=1)
    p.add_argument("--cpuset", default="2,3", help="docker: --cpuset-cpus；native: taskset -c（'none'=不綁）")
    p.add_argument("--mem", default="3g"); p.add_argument("--tmpfs", default="1500m", help="docker 的 /work tmpfs 大小")
    p.add_argument("--work", default="/dev/shm/ids_tp", help="native 模式的 tmpfs 工作目錄")
    p.add_argument("--seed", type=int, default=20261011)
    p.add_argument("--timeout", type=int, default=3600)
    p.add_argument("--manifest", default=os.path.join(HERE, "manifest.json"))
    p.add_argument("--pcaps-dir", default=None); p.add_argument("--rules-dir", default=None)
    p.add_argument("--runs-dir", dest="runs", default=None); p.add_argument("--results-dir", default=os.path.join(HERE, "results"))
    a = p.parse_args()
    a.pcap_names = a.pcaps                      # --pcaps 是檔名清單
    a.pcaps = a.pcaps_dir or os.path.join(BIG, "pcaps"); a.rules_dir = a.rules_dir or os.path.join(BIG, "rules")
    a.runs = os.path.join(a.runs or os.path.join(BIG, "runs"), a.tag)
    os.makedirs(a.runs, exist_ok=True); os.makedirs(a.results_dir, exist_ok=True)
    if a.mode == "native": os.makedirs(a.work, exist_ok=True)

    man = {m["name"]: m for m in json.load(open(a.manifest))}
    names = []
    for x in a.pcap_names.split(","):
        names += [x] if x.endswith(".pcap") else [x + ".pcap", x + ".small.pcap"]
    a.engine_list, a.rule_list = a.engines.split(","), a.rules.split(",")
    a.pcap_list = names
    for n in names:
        if n not in man: sys.exit("manifest 裡沒有 %s" % n)
        if not os.path.exists(os.path.join(a.pcaps, n)): sys.exit("找不到 pcap %s" % n)

    jobs = [(n, e, r) for n in names for e in a.engine_list for r in a.rule_list]
    write_env(a, os.path.join(a.results_dir, a.tag + ".env.json"))
    csv_path = os.path.join(a.results_dir, a.tag + ".csv")
    print("jobs/round=%d rounds=%d (含 warm-up %d) -> %s" % (len(jobs), a.reps + a.warmup, a.warmup, csv_path), flush=True)
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS, extrasaction="ignore"); w.writeheader()
        for rnd in range(a.warmup + a.reps):
            order = jobs[:]; random.Random(a.seed + rnd).shuffle(order)      # 每 round 洗牌（固定 seed）
            for i, job in enumerate(order):
                r = one_run(a, man, job, rnd, i, w, fh)
                print("r%d %3d/%d %-8s %-6s %-26s self=%s wall=%s pk=%s/%s void=%s" % (
                    rnd, i + 1, len(order), job[1], job[2], job[0], r.get("self_s"), r.get("wall_s"),
                    r.get("pkts_reported"), r.get("pkts_expected"), r["void_reason"]), flush=True)

if __name__ == "__main__":
    main()
