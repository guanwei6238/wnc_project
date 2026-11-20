#!/usr/bin/env python3
"""trust.py — trust_cost.sh results: per-packet savings after trust (ct mark) and the extra cost of L2.

Usage: python3 trust.py results/trust1.kvl
  each cell is the mean cpu_us_per_pkt over rounds (whole machine, µs/packet); parentheses give the max spread between rounds
  C0 forwarding only (no conntrack); C1 everything to Suricata; C2 everything trusted; C3 everything trusted + L2 (SYN/FIN/RST to Suricata)
  trust savings = C1 − C2; L2 cost = C3 − C2; conntrack + ct mark = C2 − C0
  control packets = fraction of packets taking the L2 rule in C3
  with C4, C5, also prints the cost of "clear trust bit on pure SYN": C4 has 1 rule (as in wnc-gw), C5 has K (amplified), per rule = (C5 − C3) ÷ K
"""
import statistics as st
import sys
from collections import defaultdict

from summarize import LABEL, ORDER, read_kvl


def main():
    runs = defaultdict(list)
    for r in read_kvl(sys.argv[1]):
        runs[(r["pcap"], r["cfg"])].append(r)

    def mean(pc, cfg, key="cpu_us_per_pkt"):
        xs = [float(r[key]) for r in runs.get((pc, cfg), [])]
        return (st.mean(xs), max(xs) - min(xs)) if xs else (None, None)

    def cell(pc, cfg):
        m, spread = mean(pc, cfg)
        return "-" if m is None else f"{m:.1f}（{spread:.1f}）"

    print("| scenario | C0 只轉送 | C1 全部進 Suricata | C2 全部信任 | C3 信任 + L2 | 信任省下 | L2 成本 | conntrack + ct mark | 控制封包 % |")
    print("|---|---|---|---|---|---|---|---|---|")
    for pc in ORDER:
        if not any(k[0] == pc for k in runs):
            continue
        c0, c1, c2, c3 = (mean(pc, c)[0] for c in ["C0", "C1", "C2", "C3"])
        diff = lambda a, b: "-" if a is None or b is None else f"{a - b:+.1f}"
        l2 = [int(r["l2"]) / int(r["forwarded"]) * 100 for r in runs.get((pc, "C3"), []) if int(r["forwarded"])]
        control = f"{st.mean(l2):.2f}" if l2 else "-"
        print(f"| {LABEL[pc]} | {cell(pc, 'C0')} | {cell(pc, 'C1')} | {cell(pc, 'C2')} | {cell(pc, 'C3')} "
              f"| {diff(c1, c2)} | {diff(c3, c2)} | {diff(c2, c0)} | {control} |")
    print()
    print("Suricata 自己的 CPU（µs／封包，平均）：")
    for pc in ORDER:
        if any(k[0] == pc for k in runs):
            print(f"  {LABEL[pc]}: " + "  ".join(f"{c} {mean(pc, c, 'suricata_us_per_pkt')[0]:.1f}" for c in ["C0", "C1", "C2", "C3"]
                                                 if mean(pc, c, 'suricata_us_per_pkt')[0] is not None))


    if any(k[1] in ("C4", "C5") for k in runs):
        print()
        print("| scenario | C3 信任 + L2 | C4 + 1 條清 bit | C5 + K 條 | K | C4 − C3 | 每條規則 (C5 − C3) ÷ K |")
        print("|---|---|---|---|---|---|---|")
        for pc in ORDER:
            if not any(k[0] == pc for k in runs):
                continue
            c3, c4, c5 = (mean(pc, c)[0] for c in ["C3", "C4", "C5"])
            k = int(runs[(pc, "C5")][0]["k"]) if runs.get((pc, "C5")) else None
            d4 = "-" if c3 is None or c4 is None else f"{c4 - c3:+.2f}"
            per = "-" if c3 is None or c5 is None or not k else f"{(c5 - c3) / k * 1000:.1f} ns"
            print(f"| {LABEL[pc]} | {cell(pc, 'C3')} | {cell(pc, 'C4')} | {cell(pc, 'C5')} | {k or '-'} | {d4} | {per} |")


if __name__ == "__main__":
    main()
