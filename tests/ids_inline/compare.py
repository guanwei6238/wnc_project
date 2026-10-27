#!/usr/bin/env python3
"""compare.py — run_compare.sh 的結果：同一組 (scenario, rule set) 下 wnc-gw、Suricata 直接跑 NFQ、af-packet IPS 與 offline 並排。

用法: python3 compare.py results/compare1.kvl [--offline ../ids_throughput/results/pi]
單位都是「每個 packet 的 worker CPU µs」；offline 是 1000 ÷ kpps（kpps 的定義同 summarize.py）。
"""
import argparse
from pathlib import Path

from summarize import LABEL, ORDER, offline_summary, read_kvl


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kvl")
    ap.add_argument("--offline", default=str(Path(__file__).resolve().parent.parent / "ids_throughput/results/pi"))
    args = ap.parse_args()
    off = offline_summary(args.offline)
    got = {}
    for r in read_kvl(args.kvl):
        got[(r["pcap"], r["rules"], r["impl"])] = r
    print("| scenario | rule set | offline µs | wnc-gw µs | NFQ 直接跑 µs | af-packet IPS µs | wnc-gw／NFQ | af-packet／NFQ | 丟失 % (wnc-gw／NFQ／af-packet) |")
    print("|---|---|---|---|---|---|---|---|---|")
    for pc in ORDER:
        for rs in ["empty", "full", "gw_corp"]:
            row = {impl: got.get((pc, rs, impl)) for impl in ["wncgw", "nfq", "afpacket"]}
            if not any(row.values()):
                continue
            us = {k: float(v["us_per_pkt"]) if v else None for k, v in row.items()}
            o = off.get((pc, rs))
            ou = 1000 / o["kpps"] if o else None
            ratio = lambda a, b: f"{us[a] / us[b]:.2f}" if us[a] and us[b] else "-"
            f = lambda x: "-" if x is None else f"{x:.1f}"
            loss = "／".join(row[k]["loss_pct"] if row[k] else "-" for k in ["wncgw", "nfq", "afpacket"])
            print(f"| {LABEL[pc]} | {rs} | {f(ou)} | {f(us['wncgw'])} | {f(us['nfq'])} | {f(us['afpacket'])} "
                  f"| {ratio('wncgw', 'nfq')} | {ratio('afpacket', 'nfq')} | {loss} |")


if __name__ == "__main__":
    main()
