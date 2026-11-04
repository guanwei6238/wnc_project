#!/usr/bin/env python3
"""alloc.py — CPU 分配實驗的計算與彙整

用法:
  python3 alloc.py diff "<snap0>" "<snap1>" <tcpreplay 輸出檔|-> [k=v ...]   兩次 snap 相減，印一行結果（k=v 原樣放在前面）
  python3 alloc.py cap <kvl> [篩選 k=v ...]                                  實驗 1：每個（workload, placement, round）的容量與同速率的 CPU
  python3 alloc.py ai <kvl>                                                  實驗 2：每個（strategy, ai, round）的丟包、µs／封包、AI 吞吐

忙碌時間＝經過時間 − idle − iowait（USER_HZ = 100）。
cap_loss＝處理不過來而丟：nfq queue 滿 + qdisc 丟（含 eth1 tx 丟）+ max(沒收到 + softnet backlog 丟, 網卡 miss + rx_dropped)。
網卡的 rx_dropped 已含 backlog 丟的，miss 的封包也不在 rx_packets 裡，所以兩邊取大的。loss_pct 是端到端（送出 − 轉送出去）。
容量＝cap_loss ≤ 0.1% 的最高實際速率（tcpreplay 的 Rated pps）。
ids（NFLOG）另外算 copy_loss＝Suricata 的 NFLOG socket 丟掉的複本 ÷ log 規則送出的複本；檢查容量＝copy_loss ≤ 0.1% 的最高實際速率。
"""
import re
import sys
from collections import defaultdict

HZ = 100
CPUS = range(4)


def parse(s):
    return dict(p.split("=", 1) for p in s.split() if "=" in p)


def num(d, k):
    try:
        return float(d.get(k, 0))
    except ValueError:
        return 0.0


def diff(s0, s1, tr, meta):
    a, b = parse(s0), parse(s1)
    d = lambda k: num(b, k) - num(a, k)
    out = dict(meta)
    dt = d("up")
    out["dt_s"] = f"{dt:.2f}"
    sent = actual = 0
    if tr != "-":
        t = open(tr).read()
        m = re.search(r"Actual: (\d+) packets", t)
        sent = int(m.group(1)) if m else 0
        m = re.search(r"Rated: [\d.]+ Bps, [\d.]+ Mbps, ([\d.]+) pps", t)
        actual = float(m.group(1)) if m else 0
    pi_in = d("rx0") + d("rx1")
    pi_out = d("tx0") + d("tx1")
    qd = d("qd_eth0") + d("qd_eth120") + d("qd_eth1") + d("txdrop_eth1")
    snd = sum(d(f"sn_drop{c}") for c in CPUS)
    nic = d("miss0") + d("drop0") + d("drop1")
    nfq = d("nfq_drop")
    short = max(sent - pi_in, 0)
    out.update(sent=int(sent), actual_pps=f"{actual:.0f}", pi_in=int(pi_in), pi_out=int(pi_out),
               nfq_drop=int(nfq), nic_drop=int(nic), softnet_drop=int(snd), qdisc_drop=int(qd), short=int(short))
    if sent:
        # 網卡的 rx_dropped 含 kernel backlog 丟的（= softnet dropped），沒收到的（miss）又會反映在 short，所以取大的那邊，不重複算
        out["cap_loss_pct"] = f"{100 * (nfq + qd + max(short + snd, nic)) / sent:.3f}"
        out["loss_pct"] = f"{100 * (sent - (pi_out - d('qd_eth1') - d('txdrop_eth1'))) / sent:.3f}"
    copies = d("nfl_log")
    if copies:
        out.update(copies=int(copies), copy_drop=int(d("nfl_drop")), copy_loss_pct=f"{100 * d('nfl_drop') / copies:.3f}")
    busy = []
    for c in CPUS:
        bc = dt - (d(f"idle{c}") + d(f"iow{c}")) / HZ
        busy.append(bc)
        out[f"util{c}"] = f"{100 * bc / dt:.1f}" if dt else "0"
        out[f"rq{c}_pct"] = f"{100 * d(f'rq{c}') / 1e9 / dt:.1f}" if dt else "0"
        out[f"netrx{c}"] = int(d(f"netrx_c{c}"))
        out[f"irq29_{c}"] = int(d(f"irq29_c{c}"))
        out[f"rps{c}"] = int(d(f"sn_rps{c}"))
        out[f"squeeze{c}"] = int(d(f"sn_sq{c}"))
    out["busy_s"] = f"{sum(busy):.3f}"
    if pi_in:
        out["us_per_pkt"] = f"{1e6 * sum(busy) / pi_in:.2f}"
        out["cpu0_us_per_pkt"] = f"{1e6 * busy[0] / pi_in:.2f}"
        out["sur_w_us_per_pkt"] = f"{d('sur_w_ns') / 1e3 / pi_in:.2f}"
    bt = d("burner_t")
    if bt > 0:
        out["ai_ops_per_s"] = f"{d('burner_ops') / bt:.2f}"
        cpu_s = d("burner_ns") / 1e9
        out["ai_cpu_s_per_s"] = f"{cpu_s / dt:.3f}" if dt else "0"
        out["ai_ops_per_cpu_s"] = f"{d('burner_ops') / cpu_s:.2f}" if cpu_s else "0"
    out.update(pause_tx=int(d("pause_tx0")), pause_rx=int(d("pause_rx0")), temp=b.get("temp"),
               throttled0=a.get("throttled"), throttled1=b.get("throttled"), arm_hz=b.get("arm_hz"), swap_kb=b.get("swap_kb"))
    return " ".join(f"{k}={v}" for k, v in out.items())


def read(path, filt):
    for line in open(path):
        r = parse(line)
        if "invalid" in r or "sent" not in r:
            continue
        if all(r.get(k) == v for k, v in filt.items()):
            yield r


def cap(path, filt):
    groups = defaultdict(list)
    for r in read(path, filt):
        groups[(r["workload"], r["placement"], r["round"])].append(r)
    print("| workload | placement | round | 容量 kpps | 檢查容量 kpps（ids） | 最高無丟包速率時 µs/pkt（全機） | CPU0 % | CPU1 % | CPU2 % | CPU3 % | 第一個丟包點的主因 |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for k in sorted(groups):
        rs = sorted(groups[k], key=lambda r: float(r["pps"]))
        ok = [r for r in rs if float(r["cap_loss_pct"]) <= 0.1]
        top = max(ok, key=lambda r: float(r["pps"])) if ok else None
        bad = next((r for r in rs if float(r["cap_loss_pct"]) > 0.1), None)
        why = "-"
        if bad:
            parts = {x: int(bad[x]) for x in ("nfq_drop", "nic_drop", "softnet_drop", "qdisc_drop", "short")}
            why = max(parts, key=parts.get) + f" {bad['cap_loss_pct']}%@{float(bad['actual_pps']) / 1000:.0f}k"
        mark = "" if bad else " ↑"
        insp = "-"
        if any("copy_loss_pct" in r for r in rs):
            cok = [r for r in rs if float(r.get("copy_loss_pct", 0)) <= 0.1]
            cbad = next((r for r in rs if float(r.get("copy_loss_pct", 0)) > 0.1), None)
            insp = (f"{max(float(r['actual_pps']) for r in cok) / 1000:.0f}" if cok else f"< {float(rs[0]['actual_pps']) / 1000:.0f}") + ("" if cbad else " ↑")
        if top:
            print(f"| {k[0]} | {k[1]} | {k[2]} | {float(top['actual_pps']) / 1000:.0f}{mark} | {insp} | {top.get('us_per_pkt')} | "
                  f"{top['util0']} | {top['util1']} | {top['util2']} | {top['util3']} | {why} |")
        else:
            print(f"| {k[0]} | {k[1]} | {k[2]} | < {float(rs[0]['actual_pps']) / 1000:.0f} | {insp} | - | - | - | - | - | {why} |")


def ai(path):
    print("| strategy | ai | threads | round | traffic | loss % | µs/pkt 全機 | Suricata W µs/pkt | AI ops/s | AI CPU 秒/秒 | AI ops/CPU 秒 | util0-3 |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in read(path, {}):
        if r.get("exp") != "2":
            continue
        print(f"| {r['strategy']} | {r['ai']} | {r.get('threads', '-')} | {r['round']} | {r['traffic']} | {r.get('cap_loss_pct', '-')} | "
              f"{r.get('us_per_pkt', '-')} | {r.get('sur_w_us_per_pkt', '-')} | {r.get('ai_ops_per_s', '-')} | {r.get('ai_cpu_s_per_s', '-')} | "
              f"{r.get('ai_ops_per_cpu_s', '-')} | {r['util0']}/{r['util1']}/{r['util2']}/{r['util3']} |")


if __name__ == "__main__":
    if sys.argv[1] == "diff":
        meta = dict(p.split("=", 1) for p in sys.argv[5:])
        print(diff(sys.argv[2], sys.argv[3], sys.argv[4], meta))
    elif sys.argv[1] == "cap":
        cap(sys.argv[2], dict(p.split("=", 1) for p in sys.argv[3:]))
    elif sys.argv[1] == "ai":
        ai(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(2)
