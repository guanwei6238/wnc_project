#!/usr/bin/env python3
"""mq.py — run_mq.sh 的結果：每個 scenario 在 1／2／3 個 queue 下的處理量。

用法: python3 mq.py results/mq1.kvl [results/sym1.kvl ...]
  hash        addr = queue num 0-(N-1)（kernel 只用位址）；symhash = queue to symhash mod N（含 port 的對稱 hash）
  送入 kpps   進到 queue 規則的 packets ÷ tcpreplay 送的時間（tcpreplay 一顆 CPU 能推多快）
  處理 kpps   Suricata 判決的 packets ÷（開始送 → queue 清空）
  queue 分配  每個 queue 分到的比例（%）
  worker CPU  每個 worker 的 CPU 時間 ÷ 同一段牆鐘時間（%）
"""
import sys

from summarize import LABEL, ORDER, read_kvl


def main():
    rows = [r for path in sys.argv[1:] for r in read_kvl(path)]
    rows.sort(key=lambda r: (ORDER.index(r["pcap"]), int(r["queues"]), r.get("qhash", "addr")))
    print("| scenario | queues | hash | 送入 kpps | 處理 kpps | 丟失 % | queue 分配 % | worker CPU % |")
    print("|---|---|---|---|---|---|---|---|")
    for r in rows:
        busy = float(r["busy_s"])
        offered = int(r["to_queue"]) / float(r["send_s"]) / 1000
        perq = [int(x) for x in r["per_queue"].split("/")]
        share = "／".join(f"{100 * x / sum(perq):.0f}" for x in perq)
        cpu = "／".join(f"{100 * float(x) / busy:.0f}" for x in r["worker_cpu_each_s"].split("/"))
        print(f"| {LABEL[r['pcap']]} | {r['queues']} | {r.get('qhash', 'addr')} | {offered:.1f} | {float(r['proc_kpps']):.1f} | {float(r['loss_pct']):.1f} | {share} | {cpu} |")


if __name__ == "__main__":
    main()
