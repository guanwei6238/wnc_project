#!/usr/bin/env python3
"""summarize.py — 把 run_pi.sh 的結果彙總，並和 10/19 的 offline 結果（tests/ids_throughput）逐 scenario 對照。

用法: python3 -I summarize.py results/inline1.kvl [--rounds 1,2,3] [--offline ../ids_throughput/results/pi] [--csv out.csv]

inline（每組 scenario × rule set）：
  cpu_kpps   A 模式 3 輪 us_per_pkt 的中位數換算（1000 ÷ µs）；Suricata worker 的 CPU 時間 ÷ 處理的 packets
  top_kpps   B 模式（全速）的 proc_kpps；top_loss 是全速時 queue 滿被丟掉的比例
  hwm_mb     A 模式 Suricata VmHWM 的中位數
  startup_s  A 模式從啟動 Suricata 到 READY=1 的中位數（含載入 rule）
offline（pi_scen2_S／E 的原始 CSV，warmup=0 且 void=0）：
  kpps       pps_self 的中位數；empty 用 summary 的 pps_diff（README：Suricata 的自報時間不含讀完 pcap 後的 flow 清理）
  rss_mb     maxrss_mb 的中位數（簡報用的定義）
  load_s     wall_s − self_s 的中位數
"""
import argparse
import csv
import statistics as st
from collections import defaultdict
from pathlib import Path

ORDER = ["S_m17", "S_m36", "S_m48", "S_m39", "S_m3", "S_m1", "S_m34", "S_m60", "S_m44",
         "S_h5", "S_somfy02", "S_m20", "S_m42", "S_h4"]
LABEL = {
    "S_m17": "17-1 (Kenjiro)", "S_m36": "36-1 (Okiru)", "S_m48": "48-1 (Mirai)", "S_m39": "39-1 (IRCBot)",
    "S_m3": "3-1 (Muhstik)", "S_m1": "1-1 (Hide and Seek)", "S_m34": "34-1 (Mirai)", "S_m60": "60-1 (Gafgyt)",
    "S_m44": "44-1 (Mirai)", "S_h5": "Honeypot-5-1 (Amazon Echo)", "S_somfy02": "Honeypot-7-1 (door lock)",
    "S_m20": "20-1 (Torii)", "S_m42": "42-1 (Trojan)", "S_h4": "Honeypot-4-1 (Philips HUE)",
}
RULES = ["empty", "full", "gw_corp"]


def read_kvl(path):
    rows = []
    for line in Path(path).read_text().splitlines():
        if line.strip():
            rows.append(dict(kv.split("=", 1) for kv in line.split()))
    return rows


def med(xs):
    return st.median(xs) if xs else None


def inline_summary(rows):
    a = defaultdict(list)
    b = {}
    for r in rows:
        key = (r["pcap"], r["rules"])
        if r["mode"] == "A":
            a[key].append(r)
        elif r["mode"] == "B":
            b[key] = r
    out = {}
    for key in set(a) | set(b):
        rs = a.get(key, [])
        us = med([float(r["us_per_pkt"]) for r in rs])
        out[key] = {
            "n": len(rs),
            "us_per_pkt": us,
            "cpu_kpps": 1000 / us if us else None,
            "us_cv_pct": 100 * st.pstdev([float(r["us_per_pkt"]) for r in rs]) / us if len(rs) > 1 else None,
            "a_loss_max": max([float(r["loss_pct"]) for r in rs], default=None),
            "processed": med([int(r["processed"]) for r in rs]),
            "hwm_mb": med([float(r["hwm_mb"]) for r in rs]),
            "startup_s": med([float(r["startup_s"]) for r in rs]),
            "top_kpps": float(b[key]["proc_kpps"]) if key in b else None,
            "top_loss": float(b[key]["loss_pct"]) if key in b else None,
        }
    return out


def offline_summary(base):
    base = Path(base)
    raw = defaultdict(list)
    for name in ["pi_scen2_S.csv", "pi_scen2_E.csv"]:
        for r in csv.DictReader(open(base / name)):
            if r["engine"] != "suricata" or r["warmup"] != "0" or r["void"] != "0" or r["pcap"].endswith(".small.pcap"):
                continue
            raw[(r["pcap"].removesuffix(".pcap"), r["rules"])].append(r)
    diff = {}
    for r in csv.DictReader(open(base / "pi_scen2_E.summary.csv")):
        if r["engine"] == "suricata" and r.get("pps_diff"):
            diff[r["pcap"].removesuffix(".pcap")] = float(r["pps_diff"])
    out = {}
    for (pc, rs), runs in raw.items():
        pps = med([float(r["pps_self"]) for r in runs])
        if rs == "empty" and pc in diff:
            pps = diff[pc]
        out[(pc, rs)] = {
            "kpps": pps / 1000,
            "rss_mb": med([float(r["maxrss_mb"]) for r in runs]),
            "load_s": med([float(r["wall_s"]) - float(r["self_s"]) for r in runs]),
            "pkts": int(runs[0]["pkts_reported"]),
        }
    return out


def fmt(x, nd=1):
    return "-" if x is None else f"{x:,.{nd}f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kvl")
    ap.add_argument("--offline", default=str(Path(__file__).resolve().parent.parent / "ids_throughput/results/pi"))
    ap.add_argument("--csv")
    ap.add_argument("--rounds", help="只用這幾輪的 A，例如 1 或 1,2")
    args = ap.parse_args()
    rows = read_kvl(args.kvl)
    if args.rounds:
        keep = set(args.rounds.split(","))
        rows = [r for r in rows if r["mode"] != "A" or r["round"] in keep]
    inl = inline_summary(rows)
    off = offline_summary(args.offline)

    anchors = [r for r in rows if r["mode"] == "anchor"]
    if anchors:
        print("錨點（S_m39 × full × A）：" + "、".join(f"round {r['round']} {r['us_per_pkt']} µs/pkt" for r in anchors))
        print()

    table = []
    for rs in RULES:
        print(f"## {rs}\n")
        print("| scenario | offline kpps | inline kpps（CPU） | inline／offline | µs/pkt | CV% | 全速 kpps | 全速丟失 % | A 丟失 max % | offline RSS MB | inline RSS MB | offline load s | inline 就緒 s |")
        print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
        for pc in ORDER:
            i = inl.get((pc, rs), {})
            o = off.get((pc, rs), {})
            ratio = i["cpu_kpps"] / o["kpps"] if i.get("cpu_kpps") and o.get("kpps") else None
            print(f"| {LABEL[pc]} | {fmt(o.get('kpps'))} | {fmt(i.get('cpu_kpps'))} | {fmt(ratio, 2)} | {fmt(i.get('us_per_pkt'))} "
                  f"| {fmt(i.get('us_cv_pct'))} | {fmt(i.get('top_kpps'))} | {fmt(i.get('top_loss'))} | {fmt(i.get('a_loss_max'), 3)} "
                  f"| {fmt(o.get('rss_mb'), 0)} | {fmt(i.get('hwm_mb'), 0)} | {fmt(o.get('load_s'))} | {fmt(i.get('startup_s'))} |")
            table.append({"pcap": pc, "rules": rs, **{f"inline_{k}": v for k, v in i.items()},
                          **{f"offline_{k}": v for k, v in o.items()}, "ratio": ratio})
        print()

    print("## 和簡報 p13 同樣格式（kpps）\n")
    print("| | Min | Median | Mean | Max |")
    print("|---|---|---|---|---|")
    for rs in RULES:
        for name, src, k in [("offline", off, "kpps"), ("inline（CPU）", inl, "cpu_kpps"), ("inline（全速）", inl, "top_kpps")]:
            xs = [src[(pc, rs)][k] for pc in ORDER if (pc, rs) in src and src[(pc, rs)].get(k)]
            if xs:
                print(f"| `{rs}` {name} | {min(xs):.1f} | {st.median(xs):.1f} | {st.mean(xs):.1f} | {max(xs):.1f} |")

    if args.csv:
        keys = sorted({k for t in table for k in t}, key=lambda k: (k not in ("pcap", "rules"), k))
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(table)


if __name__ == "__main__":
    main()
