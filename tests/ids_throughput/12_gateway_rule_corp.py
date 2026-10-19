#!/usr/bin/env python3
"""12_gateway_rule_corp.py — 依「公司內網與外網之間的 security gateway」判斷 ET Open 各 category 要不要放在本地 IDS，組出 rule set gw_corp。

前提：gateway 放在公司內網與外網之間，內網除了網通與 IoT 設備，也有一般主機（Windows／macOS 桌機、瀏覽器、手機、伺服器）。
最後的 IDS 也可能是自己實作（基於 Snort／Suricata），所以以**偵測面完整**為優先，不依平台排除 category。

判斷依據：
  (1) 保護對象：公司內網（Windows／macOS 桌機、瀏覽器、手機、伺服器、網通與 IoT 設備），不依平台排除
  (2) 位置：閘道器看得到內網↔外網的流量，所以「被感染主機對外掃描、連 C2」與「外部對內網的攻擊」都看得到
  (3) 機制：長 IP 清單（TOR、CINS、DROP、COMPROMISED、Threatview、CNC）改用 nftables 的 IP 集合，不放在 IDS 規則裡
      （Snort 3 掛上這類 rule 會大幅變慢，見 README 的 sel 實驗）
  (4) 雜訊：資訊性、獵捕（HUNTING）、動態 DNS 的規則誤報多、與入侵無直接關係，不放本地；ET 已退役的規則不用；
      INFO、CHAT 只留 IRC 相關的規則（IoT 殭屍網路常用 IRC 當 C2）
  (5) 政策：P2P、遊戲、遠端桌面、檔案分享等是公司政策問題，不代表入侵，不放本地（要管的話另外設定）

篩選方式：
  - 「本地需要」的 category：保留 header 逗號數 < 8 的 rule（逗號 >= 8 視為長清單，與 04_make_sel_rules.py 同判準）
  - 「本地部分保留」的 category（INFO、CHAT）：只留 msg 含 IRC 的 rule
  - 最後補上 flowbits 依賴（isset 的 rule 需要的 set 者，只補非長清單的）
  - 已知限制：逗號 >= 8 的判準也會篩掉有比對內容、只是 port 清單很長的 rule。以 2026-10-11 快照為例，「本地需要」裡有
    21 條（20 條是 port 清單、1 條是 IP 清單加 content），照上面的原則應該保留，目前還沒有加回。

用法： python3 -I 12_gateway_rule_corp.py <規則目錄> <rule_features.tsv>
輸出：<規則目錄>/{suricata,snort}_gw_corp.rules、gw_corp_sids.txt（並附加到 SHA256SUMS）；
      results/rule_category_decisions_corp.tsv；RULE_CATEGORIES_corp.md
"""
import collections
import csv
import hashlib
import os
import re
import sys
from pathlib import Path

d = Path(sys.argv[1])
R = list(csv.DictReader(open(sys.argv[2]), delimiter="\t"))
HERE = Path(os.path.dirname(os.path.abspath(__file__)))
LONG_IP = 8
NAME = "gw_corp"


def eff_category(r):
    """GPL 舊規則依子類別歸類；Threatview 單獨一類。"""
    m = re.match(r"GPL (\S+)", r["msg"])
    if m:
        return "GPL_" + m.group(1)
    if r["msg"].startswith("ET Threatview"):
        return "THREATVIEW"
    return r["category"]


def irc_related(r):
    return "IRC" in r["msg"]


KEEP, PART, IPSET, CLOUD = "本地需要", "本地部分保留", "改用 IP 黑名單（nftables）", "不放本地（交給雲端或不需要）"
# 類別 -> (判斷, 部分保留時的篩選函式或 None, 這類規則偵測什麼, 理由)
DECISIONS = {
    "SCAN":              (KEEP, None, "掃描與偵察工具（nmap、web scanner、服務探測）", "被感染主機對外掃描、外部對內網的偵察，閘道器都看得到"),
    "TELNET":            (KEEP, None, "Telnet 暴力破解、Mirai 類 busybox 登入", "網通與 IoT 設備最常見的入侵途徑"),
    "WORM":              (KEEP, None, "蠕蟲傳播（含 TheMoon 路由器蠕蟲）", "會在內網主機與設備間擴散"),
    "DOS":               (KEEP, None, "DoS／DDoS 與放大攻擊（NTP、SSDP 等）", "內網主機被拿去發動攻擊，或公司對外服務被攻擊"),
    "SNMP":              (KEEP, None, "SNMP 未授權存取", "網通設備常開 SNMP"),
    "TFTP":              (KEEP, None, "對外 TFTP 傳輸", "惡意程式常用 TFTP 下載 payload"),
    "COINMINER":         (KEEP, None, "挖礦程式連線（Stratum 協定、礦池網域）", "被入侵的主機常被拿來挖礦"),
    "SCADA":             (KEEP, None, "工控協定與設備（Modbus、S7、DNP3 等）", "公司可能有工控／樓宇設備"),
    "DNS":               (KEEP, None, "DNS 異常（大量回應、sinkhole、可疑 TLD）", "與作業系統無關；DNS 通常不加密"),
    "JA3":               (KEEP, None, "惡意程式／工具的 TLS 指紋", "只看 TLS 握手，加密流量下仍有效"),
    "VOIP":              (KEEP, None, "SIP 洪水與探測", "公司常有 VoIP 電話"),
    "FTP":               (KEEP, None, "FTP 服務攻擊", "公司與 NAS 常開 FTP"),
    "ATTACK_RESPONSE":   (KEEP, None, "攻擊成功後的回應（指令輸出、C2 框架憑證、下載回應）", "代表主機可能已被入侵"),
    "MALWARE":           (KEEP, None, "惡意程式活動與 C2 指標（DNS 網域、TLS、HTTP、IP）", "公司內網各種平台都可能被感染"),
    "EXPLOIT":           (KEEP, None, "對特定服務或設備的漏洞利用", "公司有各種服務與設備"),
    "WEB_SPECIFIC_APPS": (KEEP, None, "特定網頁應用程式的攻擊（CMS、企業軟體、設備管理介面）", "公司可能架設這些網頁應用"),
    "WEB_SERVER":        (KEEP, None, "對網頁伺服器的攻擊", "公司可能有對外或內部的網頁伺服器"),
    "PHISHING":          (KEEP, None, "釣魚網站與憑證竊取", "員工用瀏覽器上網，是公司常見的入侵起點"),
    "EXPLOIT_KIT":       (KEEP, None, "瀏覽器漏洞利用套件", "員工的瀏覽器"),
    "MOBILE_MALWARE":    (KEEP, None, "手機惡意程式（Android／iOS）", "員工手機會連公司網路"),
    "ADWARE_PUP":        (KEEP, None, "廣告軟體與不需要的程式", "桌機上的不需要程式，常是更嚴重感染的前兆"),
    "WEB_CLIENT":        (KEEP, None, "瀏覽器端攻擊", "員工的瀏覽器"),
    "ACTIVEX":           (KEEP, None, "Windows ActiveX 元件漏洞", "公司有 Windows 桌機"),
    "USER_AGENTS":       (KEEP, None, "可疑 HTTP User-Agent", "多屬 Windows 惡意程式；公司有 Windows 桌機（需要明文 HTTP）"),
    "CURRENT_EVENTS":    (KEEP, None, "近期事件（多為 Windows 攻擊工具）", "公司有 Windows 桌機"),
    "NETBIOS":           (KEEP, None, "Windows SMB／NetBIOS 攻擊", "公司內網常有 SMB"),
    "SMTP":              (KEEP, None, "郵件相關", "公司有郵件服務"),
    "RPC":               (KEEP, None, "Windows DCERPC", "公司有 Windows 主機"),
    "SQL":               (KEEP, None, "資料庫攻擊", "公司可能有資料庫服務"),
    "SHELLCODE":         (KEEP, None, "shellcode 特徵（多為瀏覽器 heap spray）", "員工的瀏覽器與各種服務（需要明文內容）"),
    "INFO":              (PART, irc_related, "資訊性事件（雲端服務、DoH、軟體更新等）",
                          "本身不代表入侵、誤報多；只留 IRC 相關（殭屍網路常用 IRC 當 C2）"),
    "CHAT":              (PART, irc_related, "即時通訊軟體", "政策類；只留 IRC 相關（殭屍網路常用 IRC 當 C2）"),
    "TOR":               (IPSET, None, "已知 TOR 節點 IP 清單", "純 IP 比對；放在 IDS 規則會拖垮 Snort 3，改用 nftables IP 集合"),
    "CINS":              (IPSET, None, "CINS 惡名 IP 清單", "同上"),
    "DROP":              (IPSET, None, "Spamhaus DROP 網段清單", "同上"),
    "COMPROMISED":       (IPSET, None, "已知被入侵主機 IP 清單", "同上"),
    "THREATVIEW":        (IPSET, None, "Threatview.io C2 IP 清單", "同上"),
    "CNC":               (IPSET, None, "Feodo Tracker 回報的 C2 IP（銀行木馬）", "純 IP 比對；放進 IP 黑名單"),
    "DYN_DNS":           (CLOUD, None, "查詢動態 DNS 網域", "惡意程式常用，但很多設備也正常使用 DDNS，誤報高；交給雲端關聯分析"),
    "HUNTING":           (CLOUD, None, "威脅獵捕用的可疑特徵", "ET 定位為獵捕用、雜訊多；適合雲端"),
    "RETIRED":           (CLOUD, None, "ET 已退役的規則", "ET 自己已停用"),
    "FILE_SHARING":      (CLOUD, None, "檔案分享服務的網域", "政策類，不代表入侵"),
    "TA_ABUSED_SERVICES": (CLOUD, None, "常被濫用的正常服務網域", "政策類，誤報多"),
    "REMOTE_ACCESS":     (CLOUD, None, "遠端桌面軟體（TeamViewer 等）", "政策類"),
    "P2P":               (CLOUD, None, "P2P 檔案分享", "政策類"),
    "GAMES":             (CLOUD, None, "線上遊戲", "政策類"),
    "INAPPROPRIATE":     (CLOUD, None, "不當內容", "政策類"),
}
# 舊版 GPL 規則：子類別比照 ET 同名類別；ET 沒有同名類別的，IMAP／POP3（郵件）與 MISC（舊服務攻擊）保留，ICMP（ping 指紋，全部是 Informational）不放本地
GPL_KEEP = {k for k, v in DECISIONS.items() if v[0] == KEEP} | {"IMAP", "POP3", "MISC"}


def decision(cat):
    if cat in DECISIONS:
        return DECISIONS[cat]
    if cat.startswith("GPL_"):
        sub = cat[4:]
        if sub in GPL_KEEP:
            return (KEEP, None, "舊版 GPL 規則（%s）" % sub, "比照 ET 的 %s 類別" % sub)
        return (CLOUD, None, "舊版 GPL 規則（%s）" % sub, "比照 ET 的雜訊／政策類，或只是 ping 指紋")
    return (CLOUD, None, "（未分類）", "未分析，預設不放本地")


by_cat = collections.defaultdict(list)
for r in R:
    by_cat[eff_category(r)].append(r)

keep = set()
rows = []
for cat, rs in by_cat.items():
    dec, fn, what, why = decision(cat)
    if dec == KEEP:
        k = [r["sid"] for r in rs if int(r["header_commas"]) < LONG_IP]
    elif dec == PART:
        k = [r["sid"] for r in rs if fn(r)]
    else:
        k = []
    keep.update(k)
    protos = ", ".join("%s %d" % kv for kv in collections.Counter(r["proto"] for r in rs).most_common(3))
    rows.append((cat, len(rs), protos, sum(1 for r in rs if int(r["header_commas"]) >= LONG_IP), dec, len(k), what, why))

# flowbits 依賴補齊（只補非長 IP 清單的設定者）
by = {r["sid"]: r for r in R}
setters = collections.defaultdict(list)
for r in R:
    for b in r["fb_set"].split(","):
        if b and int(r["header_commas"]) < LONG_IP:
            setters[b].append(r["sid"])
base = set(keep)
todo = list(keep)
while todo:
    x = todo.pop()
    for b in by[x]["fb_isset"].split(","):
        for t in setters.get(b.strip(), []):
            if t not in keep:
                keep.add(t); todo.append(t)
added = len(keep) - len(base)

# 輸出規則檔（兩引擎同一批 sid）
ACT = re.compile(r"^(alert|drop|reject)\s")
SIDRE = re.compile(r"\bsid:\s*(\d+)\s*;")
counts, sums = {}, []
for eng in ("suricata", "snort"):
    lines = {}
    for line in (d / f"{eng}_full.rules").read_text(errors="replace").split("\n"):
        if ACT.match(line.strip()):
            m = SIDRE.search(line)
            if m:
                lines[m.group(1)] = line
    body = [lines[s] for s in sorted(keep, key=int) if s in lines]
    p = d / f"{eng}_{NAME}.rules"
    p.write_text("\n".join(body) + "\n")
    counts[eng] = len(body)
    sums.append("%s  %s" % (hashlib.sha256(p.read_bytes()).hexdigest(), p.name))
(d / f"{NAME}_sids.txt").write_text("\n".join(sorted(keep, key=int)) + "\n")
old = (d / "SHA256SUMS").read_text().rstrip("\n").split("\n")
names = [s.split("  ")[1] for s in sums]
(d / "SHA256SUMS").write_text("\n".join([l for l in old if l.split("  ")[-1] not in names] + sums) + "\n")

# IP 清單的規模（建議改用 nftables 的 IP 集合）
ip_items = 0
for r in R:
    if decision(eff_category(r))[0] == IPSET:
        ip_items += int(r["header_commas"]) + 1
n_ipset_rules = sum(len(rs) for c, rs in by_cat.items() if decision(c)[0] == IPSET)

# 決策表 TSV
order = [KEEP, PART, IPSET, CLOUD]
rows.sort(key=lambda x: (order.index(x[4]), -x[1]))
os.makedirs(HERE / "results", exist_ok=True)
with open(HERE / "results" / "rule_category_decisions_corp.tsv", "w") as f:
    f.write("category\trules\tprotocols\tlong_ip_rules\tdecision\tkept\twhat\twhy\n")
    for r in rows:
        f.write("\t".join(str(x) for x in r) + "\n")

# 說明文件
tot = len(R)
md = []
md.append("# ET Open 規則分類：公司內網與外網之間的 security gateway 需要哪些類別（gw_corp）\n")
md.append("> 由 `12_gateway_rule_corp.py` 產生；判斷表（`DECISIONS`）是**我的分析判斷，不是偵測價值的驗證**，可直接修改後重跑。\n"
          "> 規則來源：ET Open 2026-10-11 快照，Suricata 版 %s 條（類別依 `msg` 的 `ET <類別>` 前綴；舊版 GPL 規則依子類別歸類）。\n" % format(tot, ","))
md.append("## 判斷依據\n")
md.append("1. **保護對象：** 公司內網（Windows／macOS 桌機、瀏覽器、手機、伺服器、網通與 IoT 設備），不依平台排除。")
md.append("2. **位置：** 閘道器看得到內網↔外網的流量，所以「被感染主機對外掃描、連 C2」與「外部對內網的攻擊」都看得到。")
md.append("3. **機制：** 長 IP 清單（TOR、CINS、DROP 等）改用 nftables 的 IP 集合做查詢，不放在 IDS 規則裡（Snort 3 會被它們拖垮，見 README 的 `sel` 實驗）。")
md.append("4. **雜訊：** 資訊性、獵捕（HUNTING）、動態 DNS 的規則誤報多、與入侵無直接關係，不放本地；INFO、CHAT 只留 IRC 相關（殭屍網路常用 IRC 當 C2）；ET 已退役的規則不用。")
md.append("5. **政策：** P2P、遊戲、遠端桌面、檔案分享等是公司政策問題，不代表入侵，不放本地。\n")
md.append("最後的 IDS 可能自己實作（基於 Snort／Suricata），所以以**偵測面完整**為優先：只排除「放在 IDS 裡會拖垮效能」與「不代表入侵」的規則。\n")
md.append("## 結果總覽\n")
md.append("| 判斷 | 類別數 | 規則數（全部） | 放進 gw_corp 的規則數 |")
md.append("|---|---|---|---|")
for dec in order:
    rs = [r for r in rows if r[4] == dec]
    md.append("| %s | %d | %s | %s |" % (dec, len(rs), format(sum(r[1] for r in rs), ","), format(sum(r[5] for r in rs), ",")))
md.append("")
md.append("- **gw_corp**：判斷為「本地需要」與「本地部分保留」的規則，共 %s 條（含為了 flowbits 依賴補進來的 %d 條）。"
          "兩引擎實際寫入檔案的條數：Suricata %s、Snort 3 %s（Snort 版少的是 Snort 規則包沒有的 sid）。"
          % (format(len(keep), ","), added, format(counts["suricata"], ","), format(counts["snort"], ",")))
md.append("- **改用 IP 黑名單**的 %s 條規則，header 裡共約 %s 個 IP／網段項目；建議用 nftables 的 IP 集合（set）在封包轉送路徑上直接比對，"
          "單一 IP 查詢約常數時間、CIDR 區間約對數成長（**此做法尚未實作與量測**）。\n" % (format(n_ipset_rules, ","), format(ip_items, ",")))
md.append("## 各類別的判斷\n")
for dec in order:
    md.append("### %s\n" % dec)
    md.append("| 類別 | 規則數 | 主要協定 | 長 IP 清單 | 保留 | 偵測什麼 | 理由 |")
    md.append("|---|---|---|---|---|---|---|")
    for r in rows:
        if r[4] == dec:
            md.append("| %s | %s | %s | %d | %s | %s | %s |" % (r[0], format(r[1], ","), r[2], r[3], format(r[5], ","), r[6], r[7]))
    md.append("")
md.append("## 限制\n")
md.append("- 判斷只依 ET 的類別（INFO、CHAT 另用 msg 篩 IRC），沒有用 `attack_target`／`affected_product` 這些標註不完整的 metadata。")
md.append("- 判斷沒有經過偵測率驗證；需要日後用標籤可靠的場景量偵測率，或請領域專家檢查。")
md.append("- 「不放本地」不代表沒有價值，而是建議交給雲端 IDS；本實驗沒有量雲端那一側。")
(HERE / "RULE_CATEGORIES_corp.md").write_text("\n".join(md) + "\n")

print("gw_corp：%d 條 sid（flowbits 補 %d）；Suricata %d、Snort %d" % (len(keep), added, counts["suricata"], counts["snort"]))
for dec in order:
    rs = [r for r in rows if r[4] == dec]
    print("  %-28s 類別 %2d  規則 %6d  保留 %6d" % (dec, len(rs), sum(r[1] for r in rs), sum(r[5] for r in rs)))
print("IP 黑名單候選：%d 條規則、約 %d 個 IP／網段項目" % (n_ipset_rules, ip_items))
