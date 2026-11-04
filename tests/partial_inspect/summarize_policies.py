#!/usr/bin/env python3
"""summarize_policies.py — 實驗 4 的彙整：每個切片 × 策略，攻擊 flow 的 alert 保留率、送出比例、Benign 上的 alert

用法: python3 -I summarize_policies.py <policies 目錄> <切片名稱...>
  保留率 = 這個策略下有 alert 的攻擊 flow 數 ÷ full（同一個切片全部封包）下有 alert 的攻擊 flow 數；括號是 Wilson 95% 區間
  隨機策略（_s1/_s2/_s3）另外印三個種子的平均
"""
import json
import math
import os
import sys
from collections import defaultdict


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)


def load(o, pol):
    try:
        d = json.load(open(os.path.join(o, "run", pol, "match.json")))
    except (OSError, ValueError):
        return None
    return {lab: v["flows_alert_full"] for lab, v in d["labels"].items()}, d["alerts"]


def main():
    base = sys.argv[1]
    for sl in sys.argv[2:]:
        o = os.path.join(base, sl)
        kept = {}
        for ln in open(os.path.join(o, "kept.tsv")):
            p = ln.split("\t")
            kept[p[0]] = (float(p[3]), float(p[4]))
        full = load(o, "full")
        if not full:
            print(f"## {sl}: full 還沒跑完")
            continue
        targets = [lab for lab, n in full[0].items() if lab.startswith("Malicious") and n > 0]
        print(f"## {sl}")
        print()
        hdr = "| 策略 | 送出封包 | 送出 bytes | " + " | ".join(f"{t.replace('Malicious ', '')}（full {full[0][t]} 條）" for t in targets) + " | Benign 有 alert 的 flow | alert 總數 |"
        print(hdr)
        print("|" + "---|" * (hdr.count("|") - 1))
        avg = defaultdict(lambda: defaultdict(list))
        for pol in kept:
            r = load(o, pol)
            if not r:
                continue
            cells = []
            for t in targets:
                k, n = r[0].get(t, 0), full[0][t]
                lo, hi = wilson(min(k, n), n)
                cells.append(f"{k}（{100 * k / n:.1f}%，{100 * lo:.0f}–{100 * hi:.0f}）")
                if pol[-3:-1] == "_s":
                    avg[pol[:-3]][t].append(k / n)
            if pol[-3:-1] == "_s":
                avg[pol[:-3]]["_kept"].append(kept[pol][0])
                avg[pol[:-3]]["_benign"].append(r[0].get("Benign", 0))
            print(f"| {pol} | {100 * kept[pol][0]:.1f}% | {100 * kept[pol][1]:.1f}% | " + " | ".join(cells) + f" | {r[0].get('Benign', 0)} | {r[1]} |")
        if avg:
            print()
            print("| 隨機策略（3 個種子平均） | 送出封包 | " + " | ".join(t.replace("Malicious ", "") for t in targets) + " | Benign |")
            print("|" + "---|" * (len(targets) + 3))
            for pol, v in avg.items():
                m = lambda xs: sum(xs) / len(xs) if xs else 0
                print(f"| {pol} | {100 * m(v['_kept']):.1f}% | " + " | ".join(f"{100 * m(v[t]):.1f}%" for t in targets) + f" | {m(v['_benign']):.0f} |")
        print()


if __name__ == "__main__":
    main()
