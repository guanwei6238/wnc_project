#!/usr/bin/env python3
"""nflog.py — run_nflog.sh 的結果：ids 候選 A（NFQ）對 B（NFLOG）每個封包的 CPU，每個 runmode 一張表。

用法: python3 nflog.py <nflog1.kvl>
  suricata = Suricata 收封包到判決的執行緒（worker，autofp 再加 RX、TX）的 CPU ÷ 它處理的封包（NFQ 的判決後轉送算在這裡，NFLOG 不會）
  machine = 所有 CPU 的 rq_cpu_time ÷ 送出的封包（含 tcpreplay、kernel 轉送）；nflog1.kvl 的舊欄位是 tick 取樣、不能用，這裡不讀
  每格是各輪的值，用「/」分開；loss 是沒交給 Suricata 的比例（NFQ：queue 滿；NFLOG：複本被丟）
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
