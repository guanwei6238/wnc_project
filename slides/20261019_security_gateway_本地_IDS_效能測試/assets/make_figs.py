#!/usr/bin/env python3
"""make_figs.py — 產生這份簡報用的圖（SVG）。

和 tests/ids_throughput/make_report_figures.py 讀同一批資料、用同一個「速度」定義，
差別只在外觀：簡報版的圖**不放標題、副標、註解句**（說明寫在投影片或講稿），
只畫 Pi 的結果、標籤用英文、字放大。

輸入（repo 內，不手抄數字）：
  tests/ids_throughput/results/pi/pi_scen2_{E,S,N}.summary.csv  IDS 量測（2026-10-17 同一次開機重跑；每格 1 暖機 + 3 次的中位數）
  tests/ids_throughput/results/rule_category_decisions_corp.tsv  ET Open 的 category 與 rule 數
  tests/iot23/results/*.json                                 IoT-23 flow alignment／packet coverage 結果
輸出：
  本目錄的 fig_align.svg、fig_labels.svg、fig_full14.svg、fig_corp14.svg、fig_etcats.svg

需要 matplotlib：
  python3 -m venv <venv> && <venv>/bin/pip install matplotlib
  <venv>/bin/python make_figs.py
"""
import csv
import glob
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from matplotlib.ticker import FixedLocator, FuncFormatter
from matplotlib.transforms import offset_copy

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
IDS_RES = os.path.join(REPO, "tests", "ids_throughput", "results")
IOT_RES = os.path.join(REPO, "tests", "iot23", "results")

# ---- 樣式 ----
# engine 顏色與報告的圖相同；empty 用空心灰、full 用深灰方塊，每張圖共用
INK, INK2, GRID = "#1f1f1f", "#52514e", "#e6e5e1"
C_SU, C_SN = "#2a78d6", "#eb6834"
C_EMPTY, C_FULL, C_BAR = "#9a9994", "#333333", "#6b7280"
plt.rcParams.update({
    "font.family": "Noto Sans CJK TC",
    "svg.fonttype": "path",            # 文字轉成路徑，Typst 嵌入時不依賴字型
    "figure.facecolor": "none", "axes.facecolor": "none", "savefig.facecolor": "none",
    "text.color": INK, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "axes.edgecolor": GRID, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True,
    "font.size": 13, "axes.titlesize": 13, "axes.titleweight": "bold",
    "legend.frameon": False, "axes.unicode_minus": False,
})
TIME_COL_PT = 52                                   # 時間欄右緣離 panel 右邊界的距離（pt）
EN = {"suricata": "Suricata", "snort": "Snort 3"}
EC = {"suricata": C_SU, "snort": C_SN}

# IoT-23 官方表（stratosphereips.org/datasets-iot23）每個 capture 的 malware／設備名稱。
# 官網拼成 "Phillips HUE"、"Soomfy Doorlock"、"Gagfyt"，這裡用一般拼法（Gafgyt 即 BASHLITE）。
FAMILY = {
    "Malware-1-1": "Hide and Seek", "Malware-3-1": "Muhstik", "Malware-7-1": "Linux.Mirai",
    "Malware-8-1": "Hakai", "Malware-9-1": "Linux.Hajime", "Malware-17-1": "Kenjiro",
    "Malware-20-1": "Torii", "Malware-21-1": "Torii", "Malware-33-1": "Kenjiro",
    "Malware-34-1": "Mirai", "Malware-35-1": "Mirai", "Malware-36-1": "Okiru",
    "Malware-39-1": "IRCBot", "Malware-42-1": "Trojan", "Malware-43-1": "Mirai",
    "Malware-44-1": "Mirai", "Malware-48-1": "Mirai", "Malware-49-1": "Mirai",
    "Malware-52-1": "Mirai", "Malware-60-1": "Gafgyt",
    "Honeypot-4-1": "Philips HUE", "Honeypot-5-1": "Amazon Echo", "Honeypot-7-1": "door lock",
}


def save(fig, name):
    path = os.path.join(HERE, name)
    fig.savefig(path)
    plt.close(fig)
    print("wrote", path)


def log_kpps(axis, lo, hi):
    """把 x 或 y 軸設成 kpps 的對數刻度。axis 是 ax.xaxis 或 ax.yaxis。"""
    ax = axis.axes
    (ax.set_xscale if axis is ax.xaxis else ax.set_yscale)("log")
    (ax.set_xlim if axis is ax.xaxis else ax.set_ylim)(lo, hi)
    axis.set_major_locator(FixedLocator([0.3, 1, 3, 10, 30, 100, 300]))
    axis.set_major_formatter(FuncFormatter(lambda v, _: "%g" % v))
    axis.set_minor_locator(FixedLocator([]))


# ============================================================
#  IDS 量測：讀 Pi 的 summary CSV
# ============================================================
def fnum(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def load_pi(tags):
    """(pcap, engine, rules) → 該格的 summary 列。只讀指定的批次（錨點批次只用來檢查漂移，不放進圖）。"""
    cells = {}
    for t in tags:
        for r in csv.DictReader(open(os.path.join(IDS_RES, "pi", t + ".summary.csv"))):
            if r["pcap"].endswith((".small.pcap", ".x2.pcap")):
                continue
            cells[(r["pcap"], r["engine"], r["rules"])] = r
    return cells


def kpps(r):
    """kpps；Suricata empty 的自報時間不可靠，改用差分法（REPORT §2.5）。"""
    pps = fnum(r["pps_diff"]) if (r["engine"], r["rules"]) == ("suricata", "empty") else fnum(r["pps_med"])
    return pps / 1000.0


# 14 個 scenario 的空規則／全量／gw_corp：2026-10-17 同一次開機重跑（run_pi_scen2.sh），全部 1 暖機 + 3
PI = load_pi(["pi_scen2_E", "pi_scen2_S", "pi_scen2_N"])

# 14 個 scenario：20 萬 packets 的 10 個排前面（處理時間可以直接比），不足 20 萬的 4 個依 packets 由多到少排最後
SCEN = [
    ("S_m17", "17-1 (Kenjiro)", "SYN scan 8081/80"), ("S_m36", "36-1 (Okiru)", "SYN probe 37215"),
    ("S_m48", "48-1 (Mirai)", "SYN scan 23"), ("S_m39", "39-1 (IRCBot)", "SYN scan 22"),
    ("S_m3", "3-1 (Muhstik)", "SSH scan + IRC"), ("S_m1", "1-1 (Hide and Seek)", "multi-port + UDP"),
    ("S_m34", "34-1 (Mirai)", "TCP/UDP mixed"),
    ("S_m60", "60-1 (Gafgyt)", "UDP flood, small"), ("S_m44", "44-1 (Mirai)", "UDP flood, large"),
    ("S_h5", "Honeypot-5-1 (Amazon Echo)", "TLS download"),
    ("S_somfy02", "Honeypot-7-1 (door lock)", "benign"), ("S_m20", "20-1 (Torii)", "C2 443"),
    ("S_m42", "42-1 (Trojan)", "file download"), ("S_h4", "Honeypot-4-1 (Philips HUE)", "benign"),
]
GROUPS = [(0, 7), (7, 10), (10, 14)]                     # 20 萬：scan／mixed、flood／download；不足 20 萬


def scen_rows():
    """每個 scenario 的 y 位置：由上往下排，分群之間空半格。"""
    ys, y = [], 0.0
    for a, b in GROUPS:
        for _ in range(a, b):
            ys.append(-y)
            y += 1
        y += 0.6
    return ys


def fmt_time(sec):
    """處理時間（s）：< 100 寫一位小數，≥ 100 寫整數。"""
    return ("%.1f s" % sec) if sec < 100 else ("%.0f s" % sec)


def scen_plot(series, name, time_rule=None):
    """14 個 scenario 的橫向點圖，左 Suricata、右 Snort 3。series = [(rules, 畫法)]。
    time_rule：在每個 panel 右側加一欄該 rule set 的處理時間（engine 自報 self_med，3 次中位數）。"""
    ys = scen_rows()
    fig, axes = plt.subplots(1, 2, figsize=(10.5, 3.7), sharey=True)
    if time_rule:
        # 右邊要留一欄放處理時間：panel 縮窄、panel 之間空出時間欄的寬度
        fig.subplots_adjust(left=0.32, right=0.915, top=0.81, bottom=0.135, wspace=0.34)
    else:
        fig.subplots_adjust(left=0.32, right=0.99, top=0.81, bottom=0.135, wspace=0.05)
    for ax, e in zip(axes, ("suricata", "snort")):
        log_kpps(ax.xaxis, 0.2, 600)
        ax.grid(axis="y", visible=False)
        ax.set_title(EN[e], loc="left", color=EC[e])
        for (s, _, _), y in zip(SCEN, ys):
            vals = [kpps(PI[(s + ".pcap", e, ru)]) for ru, _ in series]
            ax.plot([min(vals), max(vals)], [y, y], color=GRID, lw=2.0, zorder=2)
            for (ru, style), v in zip(series, vals):
                ax.plot([v], [y], zorder=3, **style(e))
        ax.set_xlabel("kpps", fontsize=11)
        if time_rule:
            # 時間欄：x 用「axes 右邊界往右 N pt」，y 用資料座標 → 每個數字與該列的點對齊
            tr = offset_copy(ax.get_yaxis_transform(), fig=fig, x=TIME_COL_PT, units="points")
            ax.text(1.0, 1.015, "%s time" % time_rule, transform=tr, ha="right", va="bottom",
                    fontsize=11, fontweight="bold", color=EC[e], clip_on=False)
            for (s, _, _), y in zip(SCEN, ys):
                t = fnum(PI[(s + ".pcap", e, time_rule)]["self_med"])
                ax.text(1.0, y, fmt_time(t), transform=tr, ha="right", va="center",
                        fontsize=11, color=EC[e], clip_on=False)
    axes[0].set_yticks(ys)
    # y 軸只寫 scenario 名稱、靠左對齊（使用者 2026-10-18：不用標流量型態、文字靠左比較清楚）
    axes[0].set_yticklabels([sid for _, sid, _ in SCEN], fontsize=10.5)
    for ax in axes:                                          # 右 panel 共用 y 軸，刻度線也要拿掉
        ax.tick_params(axis="y", length=0)
    # 依最長的名稱決定左邊留白：名稱左緣貼齊圖的左邊 6 pt，和 panel 之間留 8 pt
    fig.canvas.draw()
    rnd = fig.canvas.get_renderer()
    maxw = max(t.get_window_extent(rnd).width for t in axes[0].get_yticklabels()) * 72 / fig.dpi
    W = fig.get_figwidth() * 72
    left = (6 + maxw + 8) / W
    fig.subplots_adjust(left=left)
    for t in axes[0].get_yticklabels():
        t.set_horizontalalignment("left")
    axes[0].tick_params(axis="y", pad=left * W - 6)
    fig.legend(handles=[Line2D([], [], label=ru, **style("legend")) for ru, style in series],
               loc="upper right", bbox_to_anchor=(0.99, 1.0), ncol=len(series), fontsize=12)
    save(fig, name)


def st_empty(e):
    return dict(marker="o", ls="none", ms=8, mfc="white", mec=C_EMPTY, mew=1.6)


def st_empty_ring(e):
    """fig_corp14 用：比實心點大一圈，gw_corp 和 empty 幾乎重疊時（例如 Snort 3 Honeypot-5-1）還看得到外圈。"""
    return dict(st_empty(e), ms=10.5)


def st_full(e):
    return dict(marker="s", ls="none", ms=7, color=C_FULL)


def st_gw(e):
    return dict(marker="o", ls="none", ms=8, color=EC.get(e, INK2))


# ---- fig_full14：14 個 scenario × {empty, full}，右側一欄 full time ----
scen_plot([("empty", st_empty), ("full", st_full)], "fig_full14.svg", time_rule="full")

# ---- fig_corp14：14 個 scenario × {empty, full, gw_corp}，右側一欄 gw_corp time ----
# empty 也畫上去（使用者 2026-10-18）：看 gw_corp 離「不掛 rule」的上限還差多少
scen_plot([("empty", st_empty_ring), ("full", st_full), ("gw_corp", st_gw)], "fig_corp14.svg", time_rule="gw_corp")


# ============================================================
#  ET Open 的 category（Suricata 版，依 msg 的 ET <category> 前綴）
# ============================================================
cats = list(csv.DictReader(open(os.path.join(IDS_RES, "rule_category_decisions_corp.tsv")), delimiter="\t"))
cats.sort(key=lambda r: (-int(r["rules"]), r["category"]))   # 同票時依名稱排，結果固定
assert len(cats) == 73 and sum(int(r["rules"]) for r in cats) == 52606, (len(cats),)
TOP = 15
shown = [(r["category"], int(r["rules"])) for r in cats[:TOP]]
shown.append(("other %d categories" % (len(cats) - TOP), sum(int(r["rules"]) for r in cats[TOP:])))

# ---- fig_etcats：rule 數最多的 15 個 category + 其他 ----
fig, ax = plt.subplots(figsize=(6.4, 4.6))
fig.subplots_adjust(left=0.36, right=0.93, top=0.98, bottom=0.11)
ys = list(range(len(shown)))[::-1]
for (cname, n), y in zip(shown, ys):
    ax.barh(y, n, height=0.66, color=C_BAR if not cname.startswith("other") else GRID, zorder=3)
    ax.text(n + 250, y, "{:,}".format(n), va="center", fontsize=10.5, color=INK2)
ax.set_yticks(ys)
ax.set_yticklabels([c for c, _ in shown], fontsize=11)
ax.tick_params(axis="y", length=0)
ax.set_xlim(0, 22500)
ax.set_xlabel("rules")
ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: "{:,.0f}".format(v)))
ax.grid(axis="y", visible=False)
save(fig, "fig_etcats.svg")


# ============================================================
#  IoT-23：讀對齊結果 JSON
# ============================================================
def short_name(scenario):
    """CTU-IoT-Malware-Capture-35-1 → Malware-35-1；…-7-1__Somfy-01 → Honeypot-7-1
    IoT-23 官方是 23 個 scenario；Honeypot-7-1 底下有 Somfy-01～06 六個 pcap，只有 Somfy-01 有 label，
    所以有 label 的那一筆就代表 Honeypot-7-1（使用者 2026-10-18：整份改用 23 個 scenario 的說法）"""
    if "__" in scenario:
        return scenario.split("__", 1)[0].replace("CTU-", "").replace("-Capture", "")
    return scenario.replace("CTU-IoT-", "").replace("CTU-", "").replace("-Capture", "")


def display(name):
    """Malware-35-1 → Malware-35-1 (Mirai)"""
    return "%s (%s)" % (name, FAMILY[name])


IOT = []
for f in sorted(glob.glob(os.path.join(IOT_RES, "*.json"))):
    d = json.load(open(f))
    if not d.get("flows"):                                   # Somfy-02～06 沒有 label 檔
        continue
    IOT.append({
        "name": short_name(d["scenario"]),
        "align": 100.0 * d["aligned"] / d["flows"],
        "cover": 100.0 * d["pcap_covered_packets"] / d["pcap_packets"],
        "labels": d["labels"],
    })
assert len(IOT) == 23, len(IOT)


# ---- fig_align：23 個 scenario 的 flow alignment 與 packet coverage ----
rows = sorted(IOT, key=lambda r: (r["align"], r["cover"]))  # 由低到高，畫出來最低的在最下面
fig, ax = plt.subplots(figsize=(6.4, 4.1))
fig.subplots_adjust(left=0.40, right=0.97, top=0.99, bottom=0.07)
ys = range(len(rows))
# 實心點（flow alignment）先畫；空心圈（packet coverage）放大、畫在上層、不填色，
# 兩值相同時圈套在實心點外，兩個都看得到
ax.plot([r["align"] for r in rows], ys, "o", ms=6, color=C_SU, zorder=3)
ax.plot([r["cover"] for r in rows], ys, "o", ms=11, mfc="none", mec=INK2, mew=1.4, zorder=4)
ax.set_yticks(list(ys))
ax.set_yticklabels([display(r["name"]) for r in rows], fontsize=10.5)
ax.tick_params(axis="y", length=0)
ax.set_xlim(-3, 103)
ax.set_ylim(-0.7, len(rows) - 0.3)
ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: "%d%%" % v))
ax.grid(axis="y", visible=False)
ax.legend(handles=[                                          # 左上角沒有資料點，圖例放這裡
    Line2D([], [], marker="o", ls="none", ms=6, color=C_SU, label="flow alignment"),
    Line2D([], [], marker="o", ls="none", ms=11, mfc="none", mec=INK2, mew=1.4, label="packet coverage"),
], loc="upper left", fontsize=11)
save(fig, "fig_align.svg")


# ---- fig_labels：可用 scenario 的 label 組成 ----
# 可用 = flow alignment ≥ 99% 且 packet coverage ≥ 90%（7-1 的 Benign 有 86% 對不到，但那些是 pcap 裡沒有的 flow，算的時候略過；整體仍過門檻，所以算 usable）
usable = [r for r in IOT if r["align"] >= 99.0 and r["cover"] >= 90.0]
assert sorted(r["name"] for r in usable) == sorted(
    "Malware-%s" % s for s in ("1-1", "7-1", "9-1", "17-1", "33-1", "35-1", "36-1", "39-1", "42-1", "43-1", "48-1")
), [r["name"] for r in usable]

CATS = [("PortScan", "#2a78d6"), ("Okiru", "#7b4fc9"), ("DDoS", "#eb6834"),
        ("Other malicious", "#b3261e"), ("Benign", "#2f7d4f")]


def category(label):
    """IoT-23 label → 圖上的 category。C&C、Attack、FileDownload 在這 10 個 scenario 都不到 1%，併成 Other。"""
    if label.lower() == "benign":
        return "Benign"
    if "C&C" in label or "FileDownload" in label:
        return "Other malicious"
    if "PartOfAHorizontalPortScan" in label:
        return "PortScan"
    if "Okiru" in label:
        return "Okiru"
    if "DDoS" in label:
        return "DDoS"
    if "Attack" in label:
        return "Other malicious"
    raise ValueError("沒有對應 category 的 label：" + label)


def scen_key(r):
    return int(r["name"].split("-")[1])                     # Malware-17-1 → 17，依編號排


usable.sort(key=scen_key, reverse=True)                      # barh 由下往上畫，反過來讓小編號在上
fig, ax = plt.subplots(figsize=(6.6, 4.0))
fig.subplots_adjust(left=0.34, right=0.97, top=0.86, bottom=0.13)
for i, r in enumerate(usable):
    total = sum(v["flows"] for v in r["labels"].values())
    share = {c: 0.0 for c, _ in CATS}
    for lab, v in r["labels"].items():
        share[category(lab)] += 100.0 * v["flows"] / total
    left = 0.0
    for c, col in CATS:
        ax.barh(i, share[c], left=left, height=0.62, color=col, zorder=3)
        left += share[c]
ax.set_yticks(range(len(usable)))
ax.set_yticklabels([display(r["name"]) for r in usable], fontsize=11.5)
ax.tick_params(axis="y", length=0)
ax.set_xlim(0, 100)
ax.set_xlabel("share of labeled flows (%)")
ax.grid(axis="y", visible=False)
fig.legend(handles=[Patch(color=col, label=c) for c, col in CATS],
           loc="upper center", ncol=5, fontsize=11, handlelength=1.0, columnspacing=0.8)
save(fig, "fig_labels.svg")
