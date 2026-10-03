#!/usr/bin/env python3
"""Aggregate bench CSV rows (written by run.sh) into Markdown tables.

  report.py results.csv            Markdown: summary table + ndr-result table
  report.py results.csv --csv      aggregated CSV instead
  report.py --tier3 inline.csv     Tier 3 (inline) long-format CSV from inline.sh: one table row per
                                   engine/rules/threads/test/test_args/metric, plus an NDR/PDR table
Groups by engine, mode, pcap, pps, threads, rules. Rows labelled ndr-search
are probes and are excluded from the summary; ndr-result rows get their own
table. Python 3 standard library only.
"""
import argparse, csv, math, statistics, sys

GROUP = ["engine", "mode", "pcap", "pps_req", "threads", "rules"]
METRICS = [  # (csv column, short name, scale)
    ("proc_pps", "pps", 1),
    ("eng_drop_pct", "eng_drop%", 1),
    ("kernel_drop_pct", "kern_drop%", 1),
    ("cpu_util_pct", "cpu%", 1),
    ("peak_rss_kb", "rss_MB", 1 / 1024.0),
    ("wall_s", "wall_s", 1),
    ("eng_alerts", "alerts", 1),
]


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def pctl(vals, p):
    s = sorted(vals)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * p / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def fmt(x):
    if x is None:
        return "-"
    if abs(x) >= 1000:
        return "%.0f" % x
    return "%.2f" % x


def fmt3(x):
    return "%d" % x if x is not None and x == int(x) and abs(x) < 1e12 else fmt(x)


def md(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def sortkey(k):
    return tuple((0, float(x)) if num(x) is not None else (1, x) for x in k)


T3_GROUP = ["engine", "rules", "threads", "test", "test_args", "metric"]


def tier3(path, as_csv):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    results = [r for r in rows if r.get("label") == "ndr-result"]
    data = [r for r in rows if r.get("label") not in ("ndr-search", "ndr-result")]
    groups = {}
    for r in data:
        groups.setdefault(tuple(r.get(g, "") for g in T3_GROUP), []).append(r)
    head = T3_GROUP + ["unit", "n", "median", "p95", "min", "max"]
    table = []
    for key in sorted(groups, key=sortkey):
        rs = groups[key]
        vals = [num(r.get("value")) for r in rs]
        vals = [v for v in vals if v is not None]
        unit = next((r.get("unit", "") for r in rs if r.get("unit")), "")
        if vals:
            table.append(list(key) + [unit or "-", str(len(rs)), fmt3(statistics.median(vals)), fmt3(pctl(vals, 95)),
                                      fmt3(min(vals)), fmt3(max(vals))])
        else:  # text metric (tool=sockperf, tls_cipher, ...): show the distinct values
            table.append(list(key) + [unit or "-", str(len(rs)), "/".join(sorted({r.get("value", "") for r in rs})),
                                      "-", "-", "-"])
    # NDR/PDR: pivot ndr_mbps/pdr_mbps/ndr_pps/pdr_pps per run
    runs = {}
    for r in results:
        k = (r.get("engine", ""), r.get("rules", ""), r.get("threads", ""), r.get("test_args", ""), r.get("run_id", ""))
        runs.setdefault(k, {})[r.get("metric", "")] = r.get("value", "")
    nhead = ["engine", "rules", "threads", "frame", "ndr_mbps", "ndr_pps", "pdr_mbps", "pdr_pps", "loss_thresholds", "run_id"]
    ntable = []
    for k in sorted(runs, key=sortkey):
        m = runs[k]
        kv = dict(p.split("=", 1) for p in k[3].split() if "=" in p)
        ntable.append([k[0], k[1], k[2], kv.get("frame", "-"), m.get("ndr_mbps", "-"), m.get("ndr_pps", "-"),
                       m.get("pdr_mbps", "-"), m.get("pdr_pps", "-"),
                       "NDR<=%s%% PDR<=%s%%" % (kv.get("ndr_loss", "?"), kv.get("pdr_loss", "?")), k[4]])
    if as_csv:
        w = csv.writer(sys.stdout)
        w.writerow(head)
        w.writerows(table)
        return
    print("## Tier 3 inline results (median / p95 over runs)\n")
    print(md(head, table) if table else "_no rows_")
    print("\n## NDR / PDR results (UDP offered rate, iperf3 payload Mbit/s)\n")
    print(md(nhead, ntable) if ntable else "_no ndr-result rows_")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="?")
    ap.add_argument("--tier3", metavar="FILE", help="pivot a Tier 3 long-format CSV (inline.sh) instead")
    ap.add_argument("--csv", dest="as_csv", action="store_true", help="emit aggregated CSV")
    a = ap.parse_args()
    if a.tier3:
        return tier3(a.tier3, a.as_csv)
    if not a.csv:
        ap.error("a results CSV or --tier3 FILE is required")
    with open(a.csv, newline="") as f:
        rows = list(csv.DictReader(f))
    probes = [r for r in rows if r.get("label") == "ndr-search"]
    results = [r for r in rows if r.get("label") == "ndr-result"]
    data = [r for r in rows if r.get("label") not in ("ndr-search", "ndr-result")]

    groups = {}
    for r in data:
        groups.setdefault(tuple(r.get(g, "") for g in GROUP), []).append(r)

    head = GROUP + ["n"]
    for _, name, _ in METRICS:
        head += [name + "_med", name + "_p95"]
    table = []
    for key in sorted(groups, key=sortkey):
        rs = groups[key]
        line = list(key) + [str(len(rs))]
        for col, _, scale in METRICS:
            vals = [num(r.get(col)) for r in rs]
            vals = [v * scale for v in vals if v is not None]
            if vals:
                line += [fmt(statistics.median(vals)), fmt(pctl(vals, 95))]
            else:
                line += ["-", "-"]
        table.append(line)

    rhead = ["engine", "mode", "pcap", "threads", "rules", "ndr_pps", "proc_pps", "total_drop%", "cpu%", "label_note"]
    rtable = []
    for r in results:
        rtable.append([r.get("engine", ""), r.get("mode", ""), r.get("pcap", ""), r.get("threads", ""),
                       r.get("rules", ""), r.get("pps_req", "") or "-", fmt(num(r.get("proc_pps"))),
                       fmt(num(r.get("total_drop_pct"))), fmt(num(r.get("cpu_util_pct"))),
                       "probes=%d" % sum(1 for p in probes if p.get("engine") == r.get("engine")
                                         and p.get("pcap") == r.get("pcap")
                                         and p.get("threads") == r.get("threads")
                                         and p.get("rules") == r.get("rules"))])

    if a.as_csv:
        w = csv.writer(sys.stdout)
        w.writerow(head)
        w.writerows(table)
        return
    print("## Runs (median / p95 per group)\n")
    print(md(head, table) if table else "_no runs_")
    print("\n## NDR results (highest pps with total drop <= tolerance)\n")
    print(md(rhead, rtable) if rtable else "_no ndr-result rows_")


if __name__ == "__main__":
    main()
