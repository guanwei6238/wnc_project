#!/usr/bin/env python3
"""planb.py — planb_run.sh 的結果：外部產生流量時，Pi 不因處理不過來而掉包的最高速率。

用法: python3 planb.py <planb.kvl|nflog.kvl>
  轉送上限 = cap_loss_pct ≤ 0.1% 的最高實際送出速率（kpps，tcpreplay 的 Rated）；cap_loss = kernel queue 滿而丟 + 網卡丟 + 沒收到
  檢查上限 = 轉送上限的條件再加上 copy_loss_pct ≤ 0.1%（只有 NFLOG 有：Suricata 漏掉的複本）；wncgw（NFQ）兩者相同
  每格是各輪的值，用「/」分開；括號是那個速率下 conntrack 寫入失敗（insert_failed）佔送出封包的比例
  round 0 是功能測試，不算；沒有 impl 欄位的舊結果當成 wncgw
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
