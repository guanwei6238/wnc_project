#!/usr/bin/env python3
"""planb.py — planb_run.sh results: the highest rate at which the Pi, under externally generated traffic, loses no packets from overload.

Usage: python3 planb.py <planb.kvl|nflog.kvl>
  forwarding limit = highest actual send rate (kpps, tcpreplay's Rated) with cap_loss_pct ≤ 0.1%; cap_loss = kernel queue-full drops + NIC drops + not received
  inspection limit = the forwarding limit's condition plus copy_loss_pct ≤ 0.1% (NFLOG only: copies Suricata missed); the two are the same for wncgw (NFQ)
  each cell lists per-round values separated by "/"; parentheses give conntrack insert failures (insert_failed) as a fraction of packets sent at that rate
  round 0 is a functional test and not counted; old results without an impl field are treated as wncgw
"""
import sys
from collections import defaultdict


def read(path):
    with open(path) as f:
        for line in f:
            kv = dict(p.split("=", 1) for p in line.split())
            if int(kv["round"]) > 0:
                kv.setdefault("impl", "wncgw")
                yield kv


def best(rs, ok):
    good = [r for r in rs if ok(r)]
    if not good:
        return f"< {float(rs[0]['actual_pps']) / 1000:.0f}"
    b = max(good, key=lambda r: int(r["pps"]))
    top = " ↑" if b is max(rs, key=lambda r: int(r["pps"])) else ""
    ct = f"（ct {int(b['ct_insert_failed']) / int(b['sent']) * 100:.1f}%）" if "ct_insert_failed" in b else ""
    return f"{float(b['actual_pps']) / 1000:.0f}{top}{ct}"


def main():
    runs = defaultdict(list)
    for r in read(sys.argv[1]):
        runs[(r["pcap"], r["impl"], int(r["trusted"]), int(r["queues"]), int(r["round"]))].append(r)
    keys = sorted({k[:4] for k in runs})
    rounds = sorted({k[4] for k in runs})
    forward = lambda r: float(r["cap_loss_pct"]) <= 0.1
    inspect = lambda r: forward(r) and float(r.get("copy_loss_pct", 0)) <= 0.1
    print("| scenario | impl | 信任 | queues | 轉送上限（kpps） | 檢查上限（kpps） |")
    print("|---|---|---|---|---|---|")
    for pc, impl, tr, q in keys:
        cols = []
        for ok in (forward, inspect):
            cols.append(" / ".join(best(runs[(pc, impl, tr, q, n)], ok) if runs.get((pc, impl, tr, q, n)) else "-" for n in rounds))
        print(f"| {pc} | {impl} | {'是' if tr else '否'} | {q} | {cols[0]} | {cols[1]} |")
    print()
    print("↑ = 量到的最高速率還沒掉包（上限更高；筆電這端最多送到約 60 kpps，S_m60 約 84 kpps）")


if __name__ == "__main__":
    main()
