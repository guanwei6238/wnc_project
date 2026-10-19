#!/usr/bin/env python3
"""summarize.py -- 把 run_matrix.py 的逐次 CSV 彙總成「每組態一行」的表，並做量測方法的自我檢查。只用標準函式庫。

用法: python3 -I summarize.py results/<tag>.csv [更多 csv ...] --out results/<tag>.summary.csv

規則:
  * 只用 warmup=0 且 void=0 的列；作廢/暖機的列只在最後列出數量。
  * 每組 (pcap, 引擎, 規則集) 報告 中位數 / 最小-最大 / CV(=樣本標準差/平均)。CV>5% 標 '!'。
  * 兩種「處理時間」:
      self_s   引擎自己報的 (Suricata 'time elapsed'、Snort timing seconds)  -> 主要指標 (a)
      diff_s   外部差分法: 同一輪(round)內 牆鐘(大 pcap) - 牆鐘(同切片的 small 500 封包 pcap)  (b)
               差分會扣掉啟動+載規則+關閉的固定開銷。
    兩者都是中位數；diff 對 self 做同樣的相減 (self_big - self_small) 才公平，因為 small 也有一點點處理時間。
  * 檢查: (a)決定性(alert 數、封包數每次相同) (c)單調(empty<=common<=full) (b)線性(.x2 / 原檔) (e)self 與 diff 差距>10%
"""
import csv, sys, statistics as st, argparse, collections, re

def med(x): return st.median(x) if x else None
def cv(x): return (st.stdev(x) / st.mean(x)) if len(x) > 1 and st.mean(x) else 0.0
def f(x, n=3): return "" if x is None else (round(x, n) if isinstance(x, float) else x)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("csvs", nargs="+"); ap.add_argument("--out", required=True); ap.add_argument("--md", help="另外輸出 markdown 表（每組態一行，只含大 pcap）")
    a = ap.parse_args()
    rows = []
    for p in a.csvs: rows += list(csv.DictReader(open(p)))
    nw = sum(r["warmup"] == "1" for r in rows); nv = sum(r["void"] == "1" and r["warmup"] == "0" for r in rows)
    good = [r for r in rows if r["warmup"] == "0" and r["void"] == "0"]
    G = collections.defaultdict(list)
    for r in good: G[(r["pcap"], r["engine"], r["rules"])].append(r)
    fl = lambda r, k: float(r[k]) if r.get(k) not in ("", None) else None

    out = []
    for (pcap, eng, rules), rs in sorted(G.items()):
        selfs = [fl(r, "self_s") for r in rs]
        base = pcap.split(".")[0]
        small = base + ".small.pcap"
        is_small = pcap.endswith(".small.pcap")
        o = dict(pcap=pcap, engine=eng, rules=rules, n=len(rs), self_med=med(selfs), self_min=min(selfs), self_max=max(selfs),
                 self_cv_pct=100 * cv(selfs), wall_med=med([fl(r, "wall_s") for r in rs]),
                 cpu_raw_med=med([fl(r, "cpu_s") for r in rs]), maxrss_mb_max=max(fl(r, "maxrss_mb") for r in rs),
                 pkts=rs[0]["pkts_reported"], bytes=rs[0]["bytes_reported"],
                 pps_med=med([fl(r, "pps_self") for r in rs]), mbps_med=med([fl(r, "mbps_self") for r in rs]),
                 alerts_set=",".join(sorted({r["alerts"] for r in rs})), suppressed_set=",".join(sorted({r["suppressed"] for r in rs})),
                 top_sids=rs[0]["top_sids"], pkts_match_all=int(all(r["pkts_match"] == "1" for r in rs)),
                 bytes_match_all=int(all(r["bytes_match"] == "1" for r in rs)))
        # --- 差分法: 同 round 配對 ---
        if not is_small and (small, eng, rules) in G:
            sm = {r["round"]: r for r in G[(small, eng, rules)]}
            dw, ds, dc = [], [], []
            for r in rs:
                s = sm.get(r["round"])
                if not s: continue
                dw.append(fl(r, "wall_s") - fl(s, "wall_s")); ds.append(fl(r, "self_s") - fl(s, "self_s"))
                dc.append(fl(r, "cpu_s") - fl(s, "cpu_s"))
            if dw:
                o["diff_med"] = med(dw); o["diff_cv_pct"] = 100 * cv(dw); o["self_minus_small_med"] = med(ds)
                o["diff_vs_self_pct"] = 100 * (o["diff_med"] - o["self_minus_small_med"]) / o["self_minus_small_med"] if o["self_minus_small_med"] else None
                o["cpu_proc_med"] = med(dc)       # 差分 CPU 時間 = 大 pcap 的 user+sys - small 的 user+sys（扣掉載規則的 CPU）
                o["mbps_diff"] = o["bytes"] and int(o["bytes"]) * 8 / o["diff_med"] / 1e6 if o["diff_med"] else None
                o["pps_diff"] = int(o["pkts"]) / o["diff_med"] if o["diff_med"] else None
        out.append(o)

    cols = ["pcap", "engine", "rules", "n", "pkts", "bytes", "self_med", "self_min", "self_max", "self_cv_pct", "pps_med", "mbps_med",
            "diff_med", "diff_cv_pct", "self_minus_small_med", "diff_vs_self_pct", "pps_diff", "mbps_diff",
            "wall_med", "cpu_raw_med", "cpu_proc_med", "maxrss_mb_max", "alerts_set", "suppressed_set", "top_sids", "pkts_match_all", "bytes_match_all"]
    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore"); w.writeheader()
        for o in out: w.writerow({k: f(o.get(k)) for k in cols})

    # ------- 人看的表與檢查 -------
    if a.md:
        with open(a.md, "w") as m:
            m.write("| 切片 | 引擎 | 規則 | n | self 中位數 s (min–max) | CV% | kpps | Mbps | kpps(差分) | CPU s(差分) | RSS MB | alerts |\n|---|---|---|---|---|---|---|---|---|---|---|---|\n")
            for o in out:
                if o["pcap"].endswith(".small.pcap"): continue
                m.write("| %s | %s | %s | %d | %.3f (%.3f–%.3f) | %.1f%s | %.0f | %.0f | %s | %s | %.0f | %s |\n" % (
                    o["pcap"].replace(".pcap", ""), o["engine"], o["rules"], o["n"], o["self_med"], o["self_min"], o["self_max"],
                    o["self_cv_pct"], "!" if o["self_cv_pct"] > 5 else "", o["pps_med"] / 1000, o["mbps_med"],
                    f(o["pps_diff"] / 1000 if o.get("pps_diff") else None, 0), f(o.get("cpu_proc_med"), 2), o["maxrss_mb_max"], o["alerts_set"]))
    print("rows: total=%d warmup=%d void(non-warmup)=%d used=%d" % (len(rows), nw, nv, len(good)))
    print("%-24s %-8s %-6s %3s %9s %9s %6s %7s %9s %9s %7s %8s %s" % ("pcap", "engine", "rules", "n", "self_med", "pps", "Mbps", "cv%", "diff_med", "self-sm", "d/s%", "rss_mb", "alerts"))
    for o in out:
        if o["pcap"].endswith(".small.pcap"): continue
        print("%-24s %-8s %-6s %3d %9s %9s %6s %6.1f%s %9s %9s %7s %8s %s" % (
            o["pcap"], o["engine"], o["rules"], o["n"], f(o["self_med"]), f(o["pps_med"], 0), f(o["mbps_med"], 1), o["self_cv_pct"],
            "!" if o["self_cv_pct"] > 5 else " ", f(o.get("diff_med")), f(o.get("self_minus_small_med")), f(o.get("diff_vs_self_pct"), 1),
            f(o["maxrss_mb_max"], 0), o["alerts_set"] + ("" if len(o["alerts_set"].split(",")) == 1 else "  <-- NOT DETERMINISTIC")))
    print("\n[檢查]")
    bad = [o for o in out if not o["pkts_match_all"] or len(o["alerts_set"].split(",")) > 1]
    print("(a) 決定性/封包數: %s" % ("通過" if not bad else "有問題: " + str([(o["pcap"], o["engine"], o["rules"], o["alerts_set"], o["pkts_match_all"]) for o in bad])))
    # (c) 單調
    byk = {(o["pcap"], o["engine"], o["rules"]): o for o in out}
    for (pcap, eng) in sorted({(o["pcap"], o["engine"]) for o in out}):
        t = [byk.get((pcap, eng, r)) for r in ("empty", "common", "full")]
        if all(t):
            v = [x["self_med"] for x in t]
            ok = v[0] <= v[1] <= v[2]
            # 若不成立，同時印出 common 與 full 的差距%和各自的 CV，方便判斷是不是在雜訊範圍內（仍然照實標 NOT MONOTONE）
            extra = "" if ok else "  (common-full 差 %.1f%%, cv common=%.1f%% full=%.1f%%)" % (100 * (v[1] - v[2]) / v[2], t[1]["self_cv_pct"], t[2]["self_cv_pct"])
            print("(c) %-24s %-8s empty=%.3f common=%.3f full=%.3f -> %s%s" % (pcap, eng, *v, "OK" if ok else "NOT MONOTONE", extra))
    # (b) 線性
    for (pcap, eng, rules), o in sorted(byk.items()):
        if ".x2." in pcap:
            b = byk.get((pcap.replace(".x2", ""), eng, rules))
            if b:
                r1 = o["self_med"] / b["self_med"]
                r2 = (o.get("diff_med") / b["diff_med"]) if o.get("diff_med") and b.get("diff_med") else None
                print("(b) %-18s %-8s %-6s self x2/x1=%.3f  diff x2/x1=%s  %s" % (pcap.split(".")[0], eng, rules, r1, f(r2),
                      "OK" if abs(r1 - 2) <= 0.1 else "OUT OF +-5%"))
    # (e) self vs diff
    over = [(o["pcap"], o["engine"], o["rules"], round(o["diff_vs_self_pct"], 1)) for o in out if o.get("diff_vs_self_pct") is not None and abs(o["diff_vs_self_pct"]) > 10]
    print("(e) self vs diff 差距 >10%% 的組: %s" % (over if over else "無"))

if __name__ == "__main__":
    main()
