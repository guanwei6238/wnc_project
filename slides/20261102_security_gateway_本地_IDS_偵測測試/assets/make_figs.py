#!/usr/bin/env python3
"""make_figs.py — 這份簡報的 Pi 處理速度圖（SVG），樣式和 10/19 的 fig_full14／fig_corp14 相同。

和 10/19 一樣：橫向點圖、kpps 對數刻度（0.3–300）、右側一欄 full 的處理時間；圖內不放標題、註解句。
差別：只有 Suricata（8.0.7、2026-10-30 的 ET Open，和偵測測試同一份 rule）；不畫 empty
（Suricata empty 的速度用差分法，含讀完 pcap 後的 flow 清理，flood 切片的 flow 多，empty 會比 full 慢，不能和 full 比）。

輸入（repo 內，不手抄數字）：
  tests/ids_throughput/results/pi/pi_scen3_S.summary.csv   2026-10-31 同一次開機；每格 1 warm-up + 3 次的中位數
  tests/ids_throughput/results/pi/pi_scen2_S.summary.csv   10/19 的 IoT-23（Suricata 7.0.10、2026-10-11 rule），只用來對照
輸出：本目錄的 fig_speed_iot23.svg、fig_speed_cic.svg、fig_speed_ciciot.svg，以及 speed_numbers.tsv（每個切片的數字，給規格與講稿用）

需要 matplotlib：python3 -m venv <venv> && <venv>/bin/pip install matplotlib && <venv>/bin/python make_figs.py
"""
import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FixedLocator, FuncFormatter
from matplotlib.transforms import offset_copy

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
PI_RES = os.path.join(REPO, "tests", "ids_throughput", "results", "pi")

# ---- 樣式（同 10/19 make_figs.py）----
INK, INK2, GRID = "#1f1f1f", "#52514e", "#e6e5e1"
C_SU = "#2a78d6"
C_FULL, C_OLD = "#333333", "#9a9994"
plt.rcParams.update({
    "font.family": "Noto Sans CJK TC",
    "svg.fonttype": "path",
    "figure.facecolor": "none", "axes.facecolor": "none", "savefig.facecolor": "none",
    "text.color": INK, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "axes.edgecolor": GRID, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True,
    "font.size": 13, "axes.titlesize": 13, "axes.titleweight": "bold",
    "legend.frameon": False, "axes.unicode_minus": False,
})
TIME_COL_PT = 52


def log_kpps(axis, lo, hi):
    ax = axis.axes
    (ax.set_xscale if axis is ax.xaxis else ax.set_yscale)("log")
    (ax.set_xlim if axis is ax.xaxis else ax.set_ylim)(lo, hi)
    axis.set_major_locator(FixedLocator([0.3, 1, 3, 10, 30, 100, 300]))
    axis.set_major_formatter(FuncFormatter(lambda v, _: "%g" % v))
    axis.set_minor_locator(FixedLocator([]))


def fmt_time(sec):
    return ("%.1f s" % sec) if sec < 100 else ("%.0f s" % sec)


def load(name, engine="suricata"):
    cells = {}
    for r in csv.DictReader(open(os.path.join(PI_RES, name + ".summary.csv"))):
        if r["engine"] == engine and not r["pcap"].endswith(".small.pcap"):
            cells[(r["pcap"][:-5], r["rules"])] = r
    return cells


NEW = load("pi_scen3_S")
OLD = load("pi_scen2_S")
kpps = lambda r: float(r["pps_med"]) / 1000.0

# (切片, y 軸名稱, 流量型態)；群組之間空半格
IOT23 = [[("S_m17", "17-1 (Kenjiro)", "SYN scan 8081/80"), ("S_m36", "36-1 (Okiru)", "SYN probe 37215"),
          ("S_m48", "48-1 (Mirai)", "SYN scan 23"), ("S_m39", "39-1 (IRCBot)", "SYN scan 22"),
          ("S_m3", "3-1 (Muhstik)", "SSH scan + IRC"), ("S_m1", "1-1 (Hide and Seek)", "multi-port + UDP"),
          ("S_m34", "34-1 (Mirai)", "TCP/UDP mixed")],
         [("S_m60", "60-1 (Gafgyt)", "UDP flood, small"), ("S_m44", "44-1 (Mirai)", "UDP flood, large"),
          ("S_h5", "Honeypot-5-1 (Amazon Echo)", "TLS download")],
         [("S_somfy02", "Honeypot-7-1 (door lock)", "benign"), ("S_m20", "20-1 (Torii)", "C2 443"),
          ("S_m42", "42-1 (Trojan)", "file download"), ("S_h4", "Honeypot-4-1 (Philips HUE)", "benign")]]
CIC = [[("C17_Benign", "CIC-IDS2017 Benign", "benign"),
        ("C17_DoS_Hulk", "CIC-IDS2017 DoS Hulk", "HTTP flood"),
        ("C17_Portscan", "CIC-IDS2017 Portscan", "SYN scan"),
        ("C17_FTP-Patator", "CIC-IDS2017 FTP-Patator", "large-packet transfer")],
       [("D12_Benign", "CIC-DDoS2019 Benign", "benign"),
        ("D12_DrDoS_DNS", "CIC-DDoS2019 DrDoS_DNS", "UDP reflection, large"),
        ("D12_DrDoS_MSSQL", "CIC-DDoS2019 DrDoS_MSSQL", "UDP reflection, medium"),
        ("D12_DrDoS_SNMP", "CIC-DDoS2019 DrDoS_SNMP", "UDP reflection, small"),
        ("D12_DrDoS_NTP", "CIC-DDoS2019 DrDoS_NTP", "UDP reflection, few ports"),
        ("D12_DrDoS_UDP", "CIC-DDoS2019 DrDoS_UDP", "UDP flood"),
        ("D12_Syn", "CIC-DDoS2019 Syn", "SYN flood"),
        ("D12_TFTP", "CIC-DDoS2019 TFTP", "SYN + UDP mixed")]]
CICIOT = [[("I23_Benign_Final", "Benign", "benign"),
           ("I23_MITM-ArpSpoofing", "MITM-ArpSpoofing", "large TCP transfer"),
           ("I23_Recon-PortScan", "Recon-PortScan", "scan"),
           ("I23_DDoS-HTTP_Flood", "DDoS-HTTP_Flood", "HTTP flood")],
          [("I23_DDoS-SYN_Flood", "DDoS-SYN_Flood", "SYN flood"),
           ("I23_DDoS-TCP_Flood", "DDoS-TCP_Flood", "TCP flood, 1 port"),
           ("I23_DoS-TCP_Flood", "DoS-TCP_Flood", "TCP flood, many ports"),
           ("I23_DDoS-UDP_Flood", "DDoS-UDP_Flood", "UDP flood, many ports"),
           ("I23_DoS-UDP_Flood", "DoS-UDP_Flood", "UDP flood, 1 port"),
           ("I23_Mirai-udpplain", "Mirai-udpplain", "UDP flood, medium"),
           ("I23_DDoS-ICMP_Flood", "DDoS-ICMP_Flood", "ICMP flood"),
           ("I23_Mirai-greip_flood", "Mirai-greip_flood", "GRE flood")],
          [("I23_DDoS-ACK_Fragmentation", "DDoS-ACK_Fragmentation", "TCP fragments, large"),
           ("I23_DDoS-UDP_Fragmentation", "DDoS-UDP_Fragmentation", "UDP fragments, large"),
           ("I23_DDoS-ICMP_Fragmentation", "DDoS-ICMP_Fragmentation", "ICMP fragments, large")]]


def st_full(_):
    return dict(marker="s", ls="none", ms=7, color=C_FULL)


def st_gw(_):
    return dict(marker="o", ls="none", ms=8, color=C_SU)


def st_old(_):
    return dict(marker="s", ls="none", ms=8.5, mfc="white", mec=C_OLD, mew=1.6)


def plot(groups, series, name, height):
    """series = [(label, 取值函式 slice→kpps, 畫法)]；右側一欄是 8.0.7 full 的處理時間（self_med）。"""
    rows, ys, y = [], [], 0.0
    for g in groups:
        for it in g:
            rows.append(it); ys.append(-y); y += 1
        y += 0.6
    fig, ax = plt.subplots(figsize=(10.5, height))
    fig.subplots_adjust(left=0.3, right=0.9, top=0.81, bottom=0.135)
    log_kpps(ax.xaxis, 0.2, 600)
    ax.grid(axis="y", visible=False)
    ax.set_title("Suricata 8.0.7", loc="left", color=C_SU)
    for (s, _, _), yy in zip(rows, ys):
        vals = [f(s) for _, f, _ in series]
        ax.plot([min(vals), max(vals)], [yy, yy], color=GRID, lw=2.0, zorder=2)
        for (_, _, st), v in zip(series, vals):
            ax.plot([v], [yy], zorder=3, **st(None))
    ax.set_xlabel("kpps", fontsize=11)
    tr = offset_copy(ax.get_yaxis_transform(), fig=fig, x=TIME_COL_PT, units="points")
    ax.text(1.0, 1.01, "full time", transform=tr, ha="right", va="bottom",
            fontsize=11, fontweight="bold", color=C_SU, clip_on=False)
    for (s, _, _), yy in zip(rows, ys):
        ax.text(1.0, yy, fmt_time(float(NEW[(s, "full")]["self_med"])), transform=tr, ha="right", va="center",
                fontsize=11, color=C_SU, clip_on=False)
    ax.set_yticks(ys)
    ax.set_yticklabels([n for _, n, _ in rows], fontsize=10.5)
    ax.tick_params(axis="y", length=0)
    fig.canvas.draw()
    rnd = fig.canvas.get_renderer()
    maxw = max(t.get_window_extent(rnd).width for t in ax.get_yticklabels()) * 72 / fig.dpi
    W = fig.get_figwidth() * 72
    left = (6 + maxw + 8) / W
    fig.subplots_adjust(left=left)
    for t in ax.get_yticklabels():
        t.set_horizontalalignment("left")
    ax.tick_params(axis="y", pad=left * W - 6)
    fig.legend(handles=[Line2D([], [], label=lab, **st(None)) for lab, _, st in series],
               loc="upper right", bbox_to_anchor=(0.86, 1.0), ncol=len(series), fontsize=12)
    fig.savefig(os.path.join(HERE, name))
    plt.close(fig)
    print("wrote", name)


full = lambda s: kpps(NEW[(s, "full")])
gw = lambda s: kpps(NEW[(s, "gw_corp")])
old = lambda s: kpps(OLD[(s, "full")])

plot(IOT23, [("full (10/19, 7.0.10)", old, st_old), ("full", full, st_full), ("gw_corp", gw, st_gw)],
     "fig_speed_iot23.svg", 3.7)
plot(CIC, [("full", full, st_full), ("gw_corp", gw, st_gw)], "fig_speed_cic.svg", 3.4)
plot(CICIOT, [("full", full, st_full), ("gw_corp", gw, st_gw)], "fig_speed_ciciot.svg", 3.8)

with open(os.path.join(HERE, "speed_numbers.tsv"), "w") as o:
    o.write("slice\tname\ttraffic\tfull_kpps\tgw_corp_kpps\tfull_time_s\tgw_corp_time_s\tfull_rss_mb\tfull_kpps_7010\n")
    for groups in (IOT23, CIC, CICIOT):
        for g in groups:
            for s, n, t in g:
                f, c = NEW[(s, "full")], NEW[(s, "gw_corp")]
                o.write("\t".join([s, n, t, "%.1f" % kpps(f), "%.1f" % kpps(c), f["self_med"], c["self_med"],
                                   f["maxrss_mb_max"], ("%.1f" % old(s)) if (s, "full") in OLD else ""]) + "\n")
print("wrote speed_numbers.tsv")
