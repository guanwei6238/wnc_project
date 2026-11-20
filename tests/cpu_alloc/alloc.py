#!/usr/bin/env python3
"""alloc.py — CPU 分配實驗的計算與彙整

用法:
  python3 alloc.py diff "<snap0>" "<snap1>" <tcpreplay 輸出檔|-> [k=v ...]   兩次 snap 相減，印一行結果（k=v 原樣放在前面）
  python3 alloc.py cap <kvl> [篩選 k=v ...]                                  實驗 1：每個（workload, placement, round）的容量與同速率的 CPU
  python3 alloc.py ai <kvl>                                                  實驗 2：每個（strategy, ai, round）的丟包、µs／封包、AI 吞吐
  python3 alloc.py modes <kvl>                                               exp4：routed 對 bridge
  python3 alloc.py copies <kvl>                                              exp5–8：ids 複製多份（exp5 的 K2h、exp6 的 K0g3／K2g3 不算，用 exp7、exp8 重跑的）
  python3 alloc.py trust <kvl> [速率 kpps ...]                               exp13：U／C／T 的容量與同速率的 µs／封包（預設 20 50 80 kpps，兩輪平均）
  python3 alloc.py trust14 <kvl> [速率 kpps ...]                             exp14：K（ctmark）／T（tc）／O（加選項前的 tc）的容量與同速率的 µs／封包、T−K、T−O（預設 50 120）
  python3 alloc.py trust15 <kvl> [速率 kpps ...]                             exp15：T（不掛特徵程式）對 Fe（tc-egress）／Fi（tc-ingress）／Fx（xdp generic）的容量與 µs／封包差（預設 50 120）

忙碌時間＝經過時間 − idle − iowait（USER_HZ = 100）。
cap_loss＝處理不過來而丟：nfq queue 滿 + qdisc 丟（含 eth1 tx 丟）+ max(沒收到 + softnet backlog 丟, 網卡 miss + rx_dropped)。
網卡的 rx_dropped 已含 backlog 丟的，miss 的封包也不在 rx_packets 裡，所以兩邊取大的。loss_pct 是端到端（送出 − 轉送出去）。
容量＝cap_loss ≤ 0.1% 的最高實際速率（tcpreplay 的 Rated pps）。
ids（NFLOG）另外算 copy_loss＝Suricata 的 NFLOG socket 丟掉的複本 ÷ log 規則送出的複本；檢查容量＝copy_loss ≤ 0.1% 的最高實際速率。
額外複本（COPIES）另外算 xcopy_loss＝讀取端丟掉的複本 ÷ 送出的額外複本；讀取端容量＝xcopy_loss ≤ 0.1% 的最高實際速率。
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
    xcopies = d("nfl_xlog")
    readers = int(num(b, "fo_readers"))
    if xcopies and readers:
        # user space 分發（planb_pi.sh FANOUT）：kernel 一份，再分給 N 個讀取端；kernel 丟的算 N 份，加上環狀緩衝滿丟的
        eff, drop = xcopies * readers, d("nfl_xdrop") * readers + d("fo_drop")
        out.update(xcopies=int(eff), xcopy_drop=int(drop), xcopy_loss_pct=f"{100 * drop / eff:.3f}",
                   fo_in=int(d("fo_in")), fo_drop=int(d("fo_drop")), fo_kernel_drop=int(d("nfl_xdrop")))
    elif xcopies:
        # 額外複本（planb_pi.sh COPIES）：每個封包 N 份，丟失率用全部讀取端合計
        out.update(xcopies=int(xcopies), xcopy_drop=int(d("nfl_xdrop")), xcopy_loss_pct=f"{100 * d('nfl_xdrop') / xcopies:.3f}")
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
        out["reader_us_per_pkt"] = f"{d('reader_ns') / 1e3 / pi_in:.2f}"
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


def capacity(rs, key):
    """第一次 key（cap_loss_pct、copy_loss_pct、xcopy_loss_pct）> 0.1% 之前的最後一個實際速率（kpps 字串；↑ 表示掃到最後都沒超過）"""
    if not any(key in r for r in rs):
        return "-"
    last = None
    for r in rs:
        if float(r.get(key, 0)) > 0.1:
            return f"{float(last['actual_pps']) / 1000:.0f}" if last else f"< {float(r['actual_pps']) / 1000:.0f}"
        last = r
    return f"{float(last['actual_pps']) / 1000:.0f} ↑"


def at(rs, pps, k):
    r = next((r for r in rs if int(r["pps"]) == pps and float(r["cap_loss_pct"]) <= 0.1), None)
    return r.get(k, "-") if r else "-"


def summary(path, exps, keys, ref, skip=lambda r: False):
    """exp4（routed 對 bridge）、exp5／exp6（多份複本）：每組的轉送、Suricata、讀取端容量，和參考速率下的 µs/封包"""
    groups = defaultdict(list)
    for r in read(path, {}):
        if r.get("exp") in exps and not skip(r):
            groups[tuple(r.get(k, "-") for k in keys)].append(r)
    print("| " + " | ".join(keys) + " | 轉送容量 kpps | Suricata 容量 kpps | 讀取端容量 kpps | 參考速率 | µs/pkt 全機 | CPU0 µs/pkt | Suricata W µs/pkt | 讀取端 µs/pkt |")
    print("|" + "---|" * (len(keys) + 8))
    for k in sorted(groups):
        rs = sorted(groups[k], key=lambda r: float(r["pps"]))
        g = dict(zip(keys, k))
        pps = ref.get((g.get("workload"), g.get("pcap")), ref.get(g.get("workload"), ref.get(g.get("pcap"), 0)))
        print(f"| {' | '.join(k)} | {capacity(rs, 'cap_loss_pct')} | {capacity(rs, 'copy_loss_pct')} | {capacity(rs, 'xcopy_loss_pct')} | "
              f"{pps // 1000}k | {at(rs, pps, 'us_per_pkt')} | {at(rs, pps, 'cpu0_us_per_pkt')} | {at(rs, pps, 'sur_w_us_per_pkt')} | "
              f"{at(rs, pps, 'reader_us_per_pkt')} |")


# routed 的 <切片>.gw.rt.pcap 裡目的 MAC 是多播的幀數（tcprewrite 保留多播位元，routed 的網卡不收，算在 short；.fp 沒有）
ROUTED_MULTICAST = {"S_m60": 0, "S_h5": 40, "C17_Benign": 377, "C17_FTP-Patator": 52, "D12_Benign": 2965,
                    "I23_Benign_Final": 3120, "I23_DNS_Spoofing": 2304}


def trust(path, rates):
    groups = defaultdict(lambda: defaultdict(list))
    for r in read(path, {"exp": "13"}):
        if r["mode"] == "routed" and r["workload"] == "U":
            gone = min(int(r["short"]), ROUTED_MULTICAST[r["slice"]] * int(r["loop"]))
            r = dict(r, cap_loss_pct=f"{float(r['cap_loss_pct']) - 100 * gone / int(r['sent']):.3f}")
        groups[(r["mode"], r["protection"], r["slice"])][(r["workload"], r["round"])].append(r)

    def cap_of(rs):
        return capacity(sorted(rs, key=lambda r: float(r["pps"])), "cap_loss_pct")

    def mean_at(g, wl, pps, k="us_per_pkt"):
        v = [float(x) for (w, _), rs in g.items() if w == wl for x in [at(rs, pps, k)] if x != "-"]
        return sum(v) / len(v) if v else None

    for mode, prot in sorted({k[:2] for k in groups}):
        print(f"\n{mode} {prot}（容量 kpps：每輪；µs／封包：整台 Pi，兩輪平均）\n")
        head = ["切片", "U 容量", "U µs@5k", "C 容量", "T 容量"] + [f"{x} @{p}k" for p in rates for x in ("C", "T", "T−C")]
        print("| " + " | ".join(head) + " |")
        print("|" + "---|" * len(head))
        for key in sorted(k for k in groups if k[:2] == (mode, prot)):
            g = groups[key]
            caps = {wl: "／".join(cap_of(rs) for (w, rnd), rs in sorted(g.items()) if w == wl) or "-" for wl in "UCT"}
            u = mean_at(g, "U", 5000)
            row = [key[2], caps["U"], f"{u:.1f}" if u else "-", caps["C"], caps["T"]]
            for p in rates:
                c, t = mean_at(g, "C", p * 1000), mean_at(g, "T", p * 1000)
                row += [f"{c:.2f}" if c else "-", f"{t:.2f}" if t else "-",
                        f"{t - c:+.2f}（{100 * (t - c) / c:+.0f}%）" if c and t else "-"]
            print("| " + " | ".join(row) + " |")


def trust14(path, rates):
    groups = defaultdict(lambda: defaultdict(list))
    for r in read(path, {"exp": "14"}):
        groups[(r["mode"], r["protection"], r["slice"])][(r["workload"], r["round"])].append(r)

    def per_round(g, wl, pps):
        return {rnd: float(x) for (w, rnd), rs in g.items() if w == wl for x in [at(rs, pps, "us_per_pkt")] if x != "-"}

    def diff(g, a, b, pps):
        x, y = per_round(g, a, pps), per_round(g, b, pps)
        d = [x[k] - y[k] for k in sorted(x) if k in y]
        return f"{sum(d) / len(d):+.2f}（{'／'.join(f'{v:+.2f}' for v in d)}）" if d else "-"

    for mode, prot in sorted({k[:2] for k in groups}):
        print(f"\n{mode} {prot}（容量 kpps：每輪；µs／封包：整台 Pi，兩輪平均；差：平均（每輪））\n")
        head = ["切片", "K 容量", "T 容量", "O 容量"] + [f"{x} @{p}k" for p in rates for x in ("K", "T", "O", "T−K", "T−O")]
        print("| " + " | ".join(head) + " |")
        print("|" + "---|" * len(head))
        for key in sorted(k for k in groups if k[:2] == (mode, prot)):
            g = groups[key]
            caps = {wl: "／".join(capacity(sorted(rs, key=lambda r: float(r["pps"])), "cap_loss_pct")
                                 for (w, _), rs in sorted(g.items()) if w == wl) or "-" for wl in "KTO"}
            row = [key[2], caps["K"], caps["T"], caps["O"]]
            for p in rates:
                for wl in "KTO":
                    v = list(per_round(g, wl, p * 1000).values())
                    row.append(f"{sum(v) / len(v):.2f}" if v else "-")
                row += [diff(g, "T", "K", p * 1000), diff(g, "T", "O", p * 1000)]
            print("| " + " | ".join(row) + " |")



def trust15(path, rates):
    groups = defaultdict(lambda: defaultdict(list))
    for r in read(path, {"exp": "15"}):
        groups[(r["mode"], r["protection"], r["slice"])][(r["workload"], r["round"])].append(r)

    def per_round(g, wl, pps):
        return {rnd: float(x) for (w, rnd), rs in g.items() if w == wl for x in [at(rs, pps, "us_per_pkt")] if x != "-"}

    def diff(g, a, b, pps):
        x, y = per_round(g, a, pps), per_round(g, b, pps)
        d = [x[k] - y[k] for k in sorted(x) if k in y]
        return f"{sum(d) / len(d):+.2f}（{'／'.join(f'{v:+.2f}' for v in d)}）" if d else "-"

    wls = ["T", "Fe", "Fi", "Fx"]
    for mode, prot in sorted({k[:2] for k in groups}):
        print(f"\n{mode} {prot}（容量 kpps：每輪；µs／封包：整台 Pi，兩輪平均；差：平均（每輪））\n")
        head = ["切片"] + [f"{w} 容量" for w in wls] + [x for p in rates for x in (f"T @{p}k", f"Fe−T @{p}k", f"Fi−T @{p}k", f"Fx−T @{p}k")]
        print("| " + " | ".join(head) + " |")
        print("|" + "---|" * len(head))
        for key in sorted(k for k in groups if k[:2] == (mode, prot)):
            g = groups[key]
            caps = [("／".join(capacity(sorted(rs, key=lambda r: float(r["pps"])), "cap_loss_pct")
                              for (w, _), rs in sorted(g.items()) if w == wl) or "-") for wl in wls]
            row = [key[2]] + caps
            for p in rates:
                t = list(per_round(g, "T", p * 1000).values())
                row.append(f"{sum(t) / len(t):.2f}" if t else "-")
                row += [diff(g, w, "T", p * 1000) for w in ("Fe", "Fi", "Fx")]
            print("| " + " | ".join(row) + " |")


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
    elif sys.argv[1] == "modes":
        summary(sys.argv[2], {"4"}, ["workload", "pcap", "placement", "mode", "round"],
                {"B0": 100000, "B2": 50000, "B1": 40000, "B7": 30000})
    elif sys.argv[1] == "copies":
        summary(sys.argv[2], {"5", "6", "7", "8"}, ["pcap", "placement", "workload", "round"], {"S_m17": 30000, "bulk_fixed": 20000},
                lambda r: (r.get("exp"), r.get("workload")) in {("5", "K2h"), ("6", "K0g3"), ("6", "K2g3")})
    elif sys.argv[1] == "trust":
        trust(sys.argv[2], [int(x) for x in sys.argv[3:]] or [20, 50, 80])
    elif sys.argv[1] == "trust14":
        trust14(sys.argv[2], [int(x) for x in sys.argv[3:]] or [50, 120])
    elif sys.argv[1] == "trust15":
        trust15(sys.argv[2], [int(x) for x in sys.argv[3:]] or [50, 120])
    elif sys.argv[1] == "ai":
        ai(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(2)
