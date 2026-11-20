#!/usr/bin/env python3
"""nflog.py — run_nflog.sh results: per-packet CPU of ids candidate A (NFQ) vs B (NFLOG), one table per runmode.

Usage: python3 nflog.py <nflog1.kvl>
  suricata = CPU of the Suricata threads from packet receipt to verdict (worker, plus RX, TX for autofp) ÷ packets it processed (NFQ's post-verdict forwarding counts here, NFLOG's does not)
  machine = rq_cpu_time over all CPUs ÷ packets sent (incl. tcpreplay, kernel forwarding); the old fields in nflog1.kvl are tick-sampled and unusable, so they are not read
  each cell lists per-round values separated by "/"; loss is the fraction not handed to Suricata (NFQ: queue full; NFLOG: copies dropped)
"""
import sys
from collections import defaultdict

ORDER = ["S_m60", "S_m1", "S_m17"]
NAMES = {"S_m60": "60-1 (Gafgyt)", "S_m1": "1-1 (Hide and Seek)", "S_m17": "17-1 (Kenjiro)"}


def read(path):
    with open(path) as f:
        for line in f:
            yield dict(p.split("=", 1) for p in line.split())


def main():
    runs = defaultdict(list)
    for r in read(sys.argv[1]):
        r.setdefault("runmode", "workers")
        r.setdefault("path_us_per_pkt", r["us_per_pkt"])
        runs[(r["runmode"], r["pcap"], r["rules"], r["impl"])].append(r)

    def cell(key, field, fmt="{:.1f}"):
        return "/".join(fmt.format(float(r[field])) if field in r else "-" for r in runs.get(key, [])) or "-"

    for rm in sorted({k[0] for k in runs}, key=lambda m: (m != "workers", m)):
        print(f"runmode {rm}")
        print()
        print("| scenario | rules | suricata NFQ | suricata NFLOG | machine NFQ | machine NFLOG | loss NFQ | loss NFLOG |")
        print("|---|---|---|---|---|---|---|---|")
        for pc in ORDER:
            for rs in ["empty", "full"]:
                a, b = (rm, pc, rs, "nfq"), (rm, pc, rs, "nflog")
                print(f"| {NAMES[pc]} | {rs} | {cell(a, 'path_us_per_pkt')} | {cell(b, 'path_us_per_pkt')} | "
                      f"{cell(a, 'cpu_us_per_pkt')} | {cell(b, 'cpu_us_per_pkt')} | "
                      f"{cell(a, 'loss_pct', '{:.2f}')} | {cell(b, 'loss_pct', '{:.2f}')} |")
        print()
    print("µs／封包；Pi 4、1000 MHz、10,000 pps、1 個 queue／group")


if __name__ == "__main__":
    main()
