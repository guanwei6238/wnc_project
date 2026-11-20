#!/usr/bin/env python3
"""mq.py — run_mq.sh results: throughput of each scenario with 1/2/3 queues.

Usage: python3 mq.py results/mq1.kvl [results/sym1.kvl ...]
  hash           addr = queue num 0-(N-1) (kernel uses addresses only); symhash = queue to symhash mod N (symmetric hash including ports)
  offered kpps   packets reaching the queue rule ÷ tcpreplay send time (how fast tcpreplay can push on one CPU)
  processed kpps packets Suricata gave a verdict ÷ (start of sending → queue empty)
  queue share    share of packets per queue (%)
  worker CPU     each worker's CPU time ÷ the same wall-clock span (%)
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
