#!/usr/bin/env python3
"""trust.py — trust_cost.sh 的結果：信任（ct mark）之後每個封包省多少、L2 多花多少。

用法: python3 trust.py results/trust1.kvl
  每格是各輪 cpu_us_per_pkt 的平均（整台機器，µs／封包），括號是各輪的最大差距
  C0 只轉送（沒有 conntrack）；C1 全部進 Suricata；C2 全部信任；C3 全部信任 + L2（SYN/FIN/RST 進 Suricata）
  信任省下 = C1 − C2；L2 成本 = C3 − C2；conntrack + ct mark = C2 − C0
  控制封包 = C3 時走 L2 規則的封包比例
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


if __name__ == "__main__":
    main()
