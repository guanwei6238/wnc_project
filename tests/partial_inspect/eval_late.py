#!/usr/bin/env python3
"""eval_late.py — exp 5 evaluation: under each policy, how many connections of each type are caught by web attack rules

Usage: python3 -I eval_late.py <late dir>
  web attack rules = SIDs seen on attack connections under the full policy (excluding those also seen on benign connections); one hit is enough to count a connection as caught
  connections are matched by client port (each connection has a different port)
"""
import json
import math
import os
import sys
from collections import defaultdict


def wilson(k, n, z=1.96):
    if n == 0:
        return (0, 0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)


def alerts(path):
    by_port = defaultdict(set)
    try:
        f = open(path)
    except OSError:
        return None
    for ln in f:
        e = json.loads(ln)
        if e.get("event_type") != "alert":
            continue
        for p in (e.get("src_port"), e.get("dest_port")):
            if p and 20000 < p < 21000:
                by_port[p].add(e["alert"]["signature_id"])
    return by_port


def main():
    d = sys.argv[1]
    truth = {t["port"]: t for t in json.load(open(os.path.join(d, "truth.json")))}
    kept = {}
    for ln in open(os.path.join(d, "pcap", "kept.tsv")):
        p = ln.split("\t")
        kept[p[0]] = float(p[3])
    full = alerts(os.path.join(d, "run", "full", "eve.json"))
    benign_sids = set().union(*[full[p] for p, t in truth.items() if t["kind"] == "benign"] or [set()])
    web = set().union(*[full[p] for p, t in truth.items() if t["kind"] != "benign"] or [set()]) - benign_sids
    kinds = ["early", "late", "pipe"]
    n = {k: sum(1 for t in truth.values() if t["kind"] == k) for k in kinds + ["benign"]}
    print(f"web 攻擊規則（full 下攻擊連線出現、benign 沒出現的 SID）：{sorted(web)}")
    print()
    print("| 策略 | 送出封包 | " + " | ".join(f"{k}（{n[k]} 條）" for k in kinds) + f" | benign 有 web alert（{n['benign']} 條） |")
    print("|---|---|" + "---|" * (len(kinds) + 1))
    for pol in kept:
        a = alerts(os.path.join(d, "run", pol, "eve.json"))
        if a is None:
            continue
        cells = []
        for k in kinds:
            hit = sum(1 for p, t in truth.items() if t["kind"] == k and a.get(p, set()) & web)
            lo, hi = wilson(hit, n[k])
            lo = max(lo, 0.0)
            cells.append(f"{hit}（{100 * hit / n[k]:.0f}%，{100 * lo:.0f}–{100 * hi:.0f}）")
        fp = sum(1 for p, t in truth.items() if t["kind"] == "benign" and a.get(p, set()) & web)
        print(f"| {pol} | {100 * kept[pol]:.1f}% | " + " | ".join(cells) + f" | {fp} |")


if __name__ == "__main__":
    main()
