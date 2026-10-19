# slide_implement.md — Security Gateway 本地 IDS 效能測試

> 最終版投影片的規格：每一頁投影片上有什麼、數據從哪個檔案來、數字的定義與核對方式、講稿要注意的事。
> 與 `src/main.typ` 同步；兩者不一致時以 `main.typ` 為準。講稿：`逐字稿.md`；草稿：`user_draft.md`。
> 頁碼一律用投影片右下角的顯示頁碼（p1 大綱 … p13 結論與下一步、p14 References），對照見 0.4。
> 「講稿注意」和 `>` 引言的內容不印到投影片上。

---

## 0. 全域規範

### 0.1 報告定位
- **進度報告**，這輪做了兩件事：① IoT-23 全 dataset 的 label 對齊；② 在 Pi 上量 Suricata／Snort 3 掛 ET Open rule 的處理速度與 memory，並依公司 gateway 的需求挑出本地 IDS 要掛的 rule set（`gw_corp`）。
- 主軸問題：**完整的 ET Open rules 能不能直接掛在 Pi 上？還是必須挑 rule？** 答案分 engine：
  - Suricata 掛得上（`full` 15.5–176 kpps），1 GB 時變慢；
  - Snort 3 掛 `full` 不能用（14 個 scenario 中 12 個約 6.3 kpps 以下，scan／flood 最嚴重）；
  - 挑過的 `gw_corp`（約 `full` 的 73%）讓 Snort 3 在 14 個 scenario 都 ≥ 11 kpps；Suricata 只快 1–26%，RSS 仍約 0.9–1.0 GB；
  - 結論：以 Suricata 為 base 實作能接雲端的 gateway（依取捨，不是數據證明 Suricata 全面比較好）。
- **gateway 的保護範圍是公司內網與外網之間**，內網有桌機、伺服器、手機與 IoT 設備，不是只有 IoT；最後的 IDS 可能自己實作（基於 Snort／Suricata）。所以 rule set 以**偵測面完整**為優先。
- **承接前兩次報告**（`../20260921_*/逐字稿.md`、`../20261005_*/逐字稿.md`）：
  - 09/21：封包處理管線 ① XDP → ② netfilter／nftables → ③ NFQUEUE（user space 的 Suricata／Snort 跑 ET Open rule）；當時**提過** blocklist **可以**灌進 nftables set（候選做法，不是定案）。
  - 10/05：後續測試 = 同一份 dataset 重播過 4 種設定（Suricata、Snort 3、Gateway 本地、Gateway 本地 + 雲端），同時量效能與偵測；對齊方法（5-tuple + 時間 + packet 數）已經講過。留下的問題：① IoT-23 只抽 2 個 scenario 驗證對齊，其他 scenario 有沒有 payload 沒查；② 完整 ET Open 在 Pi 上吃 memory 是社群經驗，要量過才知道；③ 測試要用哪份 dataset 未定。
  - **這輪回答 ① 與 ②，並為 ③ 提供資料**；上次規劃的 inline 整體測試是下一步。
- **老師的建議**是「可以挑合理的 rule 來做，並說明為什麼合理」，沒有指定挑哪些 → 第 3 節「Rule 篩選」回應這個建議：ET Open 有哪些 category（p9）→ 挑了什麼、為什麼（p10）→ 數據（p11、p12）。
- ❌ 不可說「老師建議挑 IoT rule」。
- ❌ RFC 9411 上次已經介紹過，投影片與 References 都不出現；被問到才說「效能測試流程沿用上次的規劃」。
- ❌ 對齊方法上次已經講過，不再用一整頁說明；講稿在 p2 定義 flow alignment 時帶過。
- ❌ 不得把 offline 數字說成 inline throughput／gateway 轉送速度。
- ❌ 不得把 alert 數說成 detection rate。這輪**沒有量 detection rate**。
- ❌ 不得說「Pi 3B+ 的結果」。這輪用的是 **Pi 4（4 GB）鎖 1000 MHz**。
- ❌ 不得說「IoT-23 對齊 100%」。上次的 100% 只抽了 2 個 scenario；這輪全 dataset 是 98.87%，逐 scenario 不均。用語是「補完上次的驗證」，不是「更正」。

### 0.2 敘述深度
**投影片只放重點，說明、理由、舉例一律放講稿。**
- 表格只留關鍵欄位，每格盡量 ≤ 12 個字；每頁要點 ≤ 3 條，盡量每條一行；留白可以接受。
- **圖片裡不放說明文字**（不放標題、副標、結論句、頁尾註記）；圖只保留軸、刻度、圖例、必要的數值標籤。
- 投影片上的內容以表格、數字為主；理由與解釋寫進講稿。
- **每張圖、每張表都要在講稿寫「怎麼讀」**：軸、每個欄位／指標的定義、符號與縮寫。

### 0.3 用詞
- **全份統一（投影片、圖、講稿都一樣）**：同一個概念只能有一種寫法。
- 專有／技術名詞一律英文：label、flow、packet、pcap、payload、scenario（不寫「場景」）、rule、rule set、category、alert、engine、kpps、RSS、memory、load time、offline、inline、scan、flood、benign、C&C／C2、port、dataset、detection rate、blocklist、tmpfs、zram 等。
- **對照表（左欄是唯一寫法，右欄不可再出現）**：

| 統一寫法 | 不可再用 |
|---|---|
| flow alignment | flow 對齊率、對齊率 |
| packet coverage | packet 涵蓋率、涵蓋率、涵蓋 |
| rule、rule set | 規則、規則集、ruleset |
| category | 分類、類別、類（一律寫 `73 個 category`） |
| memory | 記憶體 |
| load time（載入 rule 的時間） | 載入時間 |
| scan、flood | 掃描、洪水 |
| alert | 警報 |
| detection rate | 偵測率 |
| engine | 引擎 |
| blocklist | 黑名單 |
| dataset | 資料集 |
| packet | 封包 |
| usable（p3 篩出來的 11 個） | 可用（「Pi 可用的 memory」這種一般用語除外） |

- 保留中文（一般用語）：本地、雲端、處理速度、處理時間、門檻、判準、對齊（指「label 與 packet 對應」這個動作，例如「對齊結果」；**指標名稱一律用 flow alignment／packet coverage**）。
- 章節標題（大綱與章節頁一字不差）：`IoT-23 dataset 對齊`、`完整 ET Open rules`、`Rule 篩選`、`結論與下一步`。
- rule set 名稱固定用等寬字型：`empty`（不掛 rule 的基線）、`full`（ET Open 全部）、`sel`（`full` 扣掉帶長 IP 清單的 rule）、`gw_corp`（p10 定義）。`common` 只出現在 p7 講稿的被問到時。投影片與講稿都不用「空規則」「全量」。
- **scenario 一律帶 malware／設備名稱**：`Malware-35-1 (Mirai)`、`Honeypot-4-1 (Philips HUE)`、`Honeypot-7-1 (door lock)`；表格空間不夠時寫 `35-1 (Mirai)`。名稱依 IoT-23 官方表（附錄 A 第 10 條）。
- 數字單位：kpps（每秒千 packets）。速度一律是「engine 處理速度」，不是線上速率。

### 0.4 技術規格
- **Typst** 搭配 `@preview/slydekit:0.4.1`（metropolis 主題），共用 `slides/template.typ`，編譯用 `slides/build.sh`。
- 圖表由 `assets/make_figs.py` 從原始 CSV／TSV／JSON 產生（SVG，見「圖表規格」）；p3 的漏斗用 `fletcher`（0.5.8）。
- 字型：Noto Sans CJK TC／Noto Sans Mono CJK TC；比例 16:9。
- **共 20 頁** = 封面 1 + 大綱 1 + 章節頁 4 + 內容 12 + References 1 + Q&A 1。封面、章節頁、Q&A 不顯示頁碼。

| 實體頁 | 顯示頁碼 | 標題 |
|---|---|---|
| 1 | — | 封面：Security Gateway 本地 IDS 效能測試 |
| 2 | p1 | 大綱 |
| 3 | — | 章節頁：IoT-23 dataset 對齊 |
| 4 | p2 | 資料量與對齊結果 |
| 5 | p3 | 哪些 scenario 不能直接用 |
| 6 | p4 | usable scenario 的流量組成 |
| 7 | — | 章節頁：完整 ET Open rules |
| 8 | p5 | 實驗設定 |
| 9 | p6 | 效能測試的 14 個 scenario |
| 10 | p7 | `full` 的處理速度 |
| 11 | p8 | Memory：`full` 在 1／2／4 GB |
| 12 | — | 章節頁：Rule 篩選 |
| 13 | p9 | ET Open 的 rule category |
| 14 | p10 | `gw_corp`：本地 IDS 掛哪些 rule |
| 15 | p11 | `gw_corp` 的處理速度 |
| 16 | p12 | Memory：`gw_corp` 在 1／2／4 GB |
| 17 | — | 章節頁：結論與下一步 |
| 18 | p13 | 結論與下一步 |
| 19 | p14 | References |
| 20 | — | Q&A |

### 0.5 視覺
- engine 配色固定：Suricata 藍 `#2a78d6`（`#su`）、Snort 3 橘 `#eb6834`（`#sn`），圖與表格強調一致。
- p2 的大數字用 `big`（`c-stage3` 色）；p3 漏斗節點用 `boxnode`（23 scenarios 灰、11 usable `c-good`），節點標籤用英文。
- 符號：可行 `#yes`（✓）、不可 `#no`（✗）、部分 `#partly`（△）；一般強調用 `#hl`。
- 小表格用 `small-tbl(size: …)` 縮字；頁尾小字用 `note`（`c-muted`、0.65em）。
- `#callout(title: ...)` 的 title 不會渲染，標題要寫進內文第一行。
- 投影片不寫量測次數。

### 0.6 數據來源（repo 內）

| 檔案 | 內容 | 用在 |
|---|---|---|
| `tests/iot23/results/*.json` | 每個 scenario 的對齊結果（`flows`、`aligned`、`pcap_packets`、`pcap_ip_packets`、`pcap_covered_packets`、`labels`） | p2–p4 |
| `tests/iot23/report.md`、`tests/iot23/ports_summary.txt` | 對齊結果整理；各 label 的目的 port、conn_state、來源 IP 數 | p2–p4 講稿 |
| `tests/ids_rules/` | ET Open 2026-10-11 下載（`00_fetch_rules.sh`）、Snort 版 rule 下載與轉換（`13_fetch_snort_rules.sh`、`15_snort_convert.sh` 等） | p5 |
| `tests/ids_throughput/results/scenario_features.tsv` | 每個 scenario 主 pcap 前 20 萬 packets 的特徵（`10_scenario_features.py`） | p6 |
| `tests/ids_throughput/results/pi/pi_scen2_{E,S,N}.summary.csv`（`pi_scen2_anchor{0,1}` 是頭尾錨點） | 14 個 scenario × `empty`／`full`／`gw_corp` × 兩個 engine（2026-10-17 同一次開機，`run_pi_scen2.sh`） | p7、p8／p12 的 4 GB 列、p11、p13 |
| `tests/ids_throughput/results/pi/pi_E`、`pi_R1`、`pi_R2a1`、`pi_R2a2`、`pi_R2b` | 主矩陣（2026-10-11，`run_pi_main.sh`）：4 個切片 × `empty`／`full`／`sel`／`common` | p7 第 3 點（A 切片的 `sel`）與講稿備用 |
| `tests/ids_throughput/results/pi/pi_mem39_{2gb,1gb}.*`、`results/pi/logs/pi_mem39_1gb.log` | 39-1 在 2／1 GB 的量測（2026-10-18，`run_pi_mem_scen.sh`）與 VmSwap 取樣 | p8、p12 |
| `tests/ids_throughput/results/rule_features.tsv` | 每條 rule 的 sid、category、`header_commas`、flowbits、metadata、msg（`05_rule_features.py`） | p9、`sel`（`04_make_sel_rules.py`）、`gw_corp` |
| `tests/ids_throughput/results/rule_category_decisions_corp.tsv`、`tests/ids_throughput/RULE_CATEGORIES_corp.md` | 73 個 category 的 rule 數與 `gw_corp` 判斷（`12_gateway_rule_corp.py`） | p9 圖、p10 |

---

## 封面
- 標題：**Security Gateway 本地 IDS 效能測試**（這個字串決定 PDF 檔名 `Security_Gateway_本地_IDS_效能測試.pdf`）
- 日期：2026-10-19；沒有副標。

> **講稿注意**：開場接上前兩次（09/21 的管線、10/05 的測試規劃與留下的三個問題）；講清楚範圍（offline 處理上限、不是 inline；沒有量 detection rate；Pi 4 不是 3B+）；講清楚 gateway 保護公司內網與外網之間、IDS 可能自己實作、所以以偵測面完整為優先；限制是 IoT-23 只有 IoT 流量。

## p1 — 大綱
- 四項（`enum`，1.2em），**與四張章節頁一字不差**：
  1. IoT-23 dataset 對齊
  2. 完整 ET Open rules
  3. Rule 篩選
  4. 結論與下一步
- 沒有小字說明。

> **講稿注意**：第二項說明後面圖表裡 ET Open 全部的 rule 叫 `full`；第三項說明這一節回應老師「挑合理的 rule 並說明為什麼合理」的建議。

---

# 1. IoT-23 dataset 對齊（章節頁 + p2–p4）

## p2 — 資料量與對齊結果
**投影片**
- 左：四個 `big` 數字
  - `23` 個 scenario
  - `7.7 億` packets（770,313,789）
  - `3.25 億` labeled flows（325,309,946）
  - `98.87%` flow alignment
- 右：`assets/fig_align.svg`（高 10.2 cm）。
- 沒有頁尾。

**數據來源**：`tests/iot23/results/*.json`；`tests/iot23/report.md`。

**定義與核對**
- **flow alignment** = 對齊的 flow ÷ 有 label 的 flow。一條 flow 算對齊：pcap 裡 5-tuple 相同（雙向）、時間落在 `[ts, ts + duration]`（兩端各放寬 1 µs）的 packet 數**剛好等於** Zeek 記的 `orig_pkts + resp_pkts`。只處理 TCP／UDP／ICMP。
- **packet coverage** = 落在任一條 labeled flow 範圍內（5-tuple 相同、時間在範圍內）的 packet ÷ pcap 全部 packet。只看範圍，不看 Zeek 的 packet 數；ARP 等非 IP packet 沒有 flow，永遠算不涵蓋。
- 兩者方向相反：flow alignment 問「label 找不找得到自己的 packet」，packet coverage 問「packet 有沒有被 label 管到」→ 所以會有 60-1 的 flow alignment 0.02%、packet coverage 100%（p3 講稿解釋）。
- packet 數是 Zeek 從 pcap 算的（conn.log 的 `orig_pkts`／`resp_pkts`），label 是 IoT-23 作者加在每一行最後的欄位；對齊檢查的是「Zeek 的統計與 pcap 對不對得上」，不是 label 標得對不對。
- 98.87% = 321,632,849 ÷ 325,309,946，flow **加總後**再除，不是平均；扣掉 60-1 為 99.97%。368 萬條對不上的 flow 中 358 萬條（97.4%）來自 60-1；39-1、43-1、17-1、33-1 四個占全部 flow 的 76.9%。
- 23 個 scenario = 20 個 malware + 3 個 benign（Honeypot）。Honeypot-7-1（Somfy door lock）底下有 Somfy-01～06 六天的 pcap，只有 Somfy-01 有 label（對齊用它）。
- 770,313,789 = 23 個 scenario 主 pcap 的總和（Honeypot-7-1 的六個 pcap 都算；子集 pcap 不重複算）；其中沒有 label 的 Somfy-02～06 共 544,766，有 label 的部分是 769,769,023。
- 整體 packet coverage 96.42%（分母含沒有 label 的那 5 個 pcap；只算有 label 的是 96.48%）。

> **講稿注意**
> - 「怎麼讀」：每列一個有 label 的 scenario（23 列，帶 malware／設備名稱）；實心藍點 = flow alignment、空心灰圈 = packet coverage，圈比點大、畫在上層，兩值相同時圈套在點外。
> - 圖上明顯掉下來的：60-1 (Gafgyt) flow alignment 幾乎 0、34-1 (Mirai) 約 38%；packet coverage 低的 52-1 約 61%、8-1 約 71%。
> - 「補完上次的驗證」：上次抽的 Hakai 就是 Malware-8-1 (Hakai)（10,403 條 flow），這次全 dataset 的數字與上次一致。
> - 實驗怎麼做（備用）：Zenodo 那包（tar.gz md5 與 Zenodo 一致、解壓約 106 GiB、84 個檔案）；一個 scenario 有多個 pcap 時取最大的（17-1、3-1、34-1、35-1、9-1 的額外 pcap 是子集；Honeypot-4-1 的 2018-09-14 pcap 沒有對應 label）；最大的 pcap 是 60-1，22 GB（22,028,429,274 bytes = 20.5 GiB），所以用串流處理（一次讀 16 MB、flow 當索引、flow 太多時依 hash 分批）；串流版與原版在 Hakai-8-1、Honeypot-7-1（Somfy-01）輸出逐字相同（`tests/iot23/compare_small.sh`）。

## p3 — 哪些 scenario 不能直接用
**投影片**
- 上：fletcher 漏斗 `23 scenarios ──▶ 11 usable`。
- 下：表格（`small-tbl(size: 0.82em)`）

| 問題 | scenario |
|---|---|
| conn.log 把 DDoS 記成 0 packet | 34-1 (Mirai)、60-1 (Gafgyt) |
| conn.log 比 pcap 早結束 | 52-1、49-1 (Mirai) |
| 非 IP packet 多 | 8-1 (Hakai)、20-1、21-1 (Torii)、Honeypot-7-1 (door lock) |
| flow alignment 低 | Honeypot-4-1 (Philips HUE)、Honeypot-5-1 (Amazon Echo)、3-1 (Muhstik)、44-1 (Mirai) |

- 頁尾 `note` 兩行：`表中只寫編號的（如 34-1）都是 Malware-x-x`、`篩選條件：flow alignment ≥ 99% 且 packet coverage ≥ 90%`。

**數據來源**：`tests/iot23/results/*.json`；usable 的判斷與 11 個名單由 `assets/make_figs.py` 斷言。

**定義與核對**
- 表格 12 個 + 11 個 usable = 23。同一個 scenario 只列在最主要的原因（例如 34-1 的 packet coverage 也只有 75.2%，列在第一列）。
- 11 個 usable：Malware-1-1 (Hide and Seek)、7-1 (Linux.Mirai)、9-1 (Linux.Hajime)、17-1 (Kenjiro)、33-1 (Kenjiro)、35-1 (Mirai)、36-1 (Okiru)、39-1 (IRCBot)、42-1 (Trojan)、43-1 (Mirai)、48-1 (Mirai)。
- 各列的數字與原因：
  - **conn.log 把 DDoS 記成 0 packet**：34-1 flow alignment 38.35%、60-1 0.02%。Zeek `ignore_checksums` 預設 F，官方文件寫「Zeek discards any packets with checksum errors」，這些 flow 的 history 是 `C`（bad checksum）。34-1 抽檢的 packet 全部 TCP checksum 錯；60-1 用 tshark 檢查 pcap 前 2,000 個 tcp/62336 packet，2,000 個 TCP checksum 全錯，TCP flags 全部設起來、payload 1 byte、都打向 162.248.88.215（整個 60-1 的 DDoS 對外打 16 個 IP）。**沒有用 Zeek 重跑確認**。
  - 60-1 為什麼 flow alignment 0.02%、packet coverage 100%：Zeek 不計 checksum 錯的 packet，但仍為每個 packet 寫下一筆 flow 記錄（`duration` 空白、`orig_pkts`＝`resp_pkts`＝0）；packet 落在範圍內 → 算涵蓋，但 pcap 找到 1 個、Zeek 記 0 個 → 不對齊。實例與其餘 66 條 DDoS 記錄的細節見講稿。
  - **conn.log 比 pcap 早結束**：52-1 早 9.26 小時（packet coverage 61.4%）、49-1 早 0.83 小時（89.8%）；兩個的 flow alignment 都 ≥ 99.9%。
  - **非 IP packet 多**：packet coverage 8-1 70.6%、20-1 82.2%、21-1 81.8%、Honeypot-7-1（Somfy-01）85.3%；非 IP packet 占 29.4%、17.8%、18.2%、14.7%。**已確認**沒涵蓋的 packet 數 ≈ `pcap_packets − pcap_ip_packets`（只看 IP packet 時沒涵蓋的只有 0～1 個）。label 本身沒有問題。
  - **flow alignment 低**：Honeypot-4-1 70.1%、Honeypot-5-1 79.6%、3-1 96.2%、44-1 94.9%。大多是 flow 最後一個 ACK／RST 落在 Zeek 記的 duration 之外（少 1 個 packet），抽樣驗證、其餘是推測。

> **講稿注意**
> - 「怎麼讀」：每列是一種排除原因，右欄是屬於這個原因的 scenario；12 + 11 = 23。
> - ❌ 不可寫「攻擊 flow 對不回 packet」（packet 都還在 pcap 裡，60-1 的 packet coverage 是 100%）。
> - ❌ 不可寫「8-1、20-1、21-1 是 log 比 pcap 早結束」。
> - 門檻還沒定（講稿備用）：另一個選項是 packet coverage 只算 IP packet，8-1、20-1、21-1、Honeypot-7-1 會過門檻，usable 變 15 個、多出 Hakai、Torii 兩個家族；目前用頁尾的門檻。
> - 7-1 (Linux.Mirai) 算 usable（講稿備用）：Benign 75,955 條只有 10,229 條（13.5%）對得回，對不到的 65,726 條全部是 196.118.25.105 的 DNS（UDP 53、S0），pcap 裡沒有這個 IP 的 packet → 問題不在 label 內容，而是 conn.log 有 pcap 裡沒有的 flow，重播時不會出現、計算時略過。Benign 只占 7-1 全部 11,454,714 條 flow 的 0.66%；整體 flow alignment 99.43%、packet coverage 99.36%，兩個門檻都過。
> - 講稿備用：usable 是 scenario 層級；帶 payload 的攻擊 label 在這些 scenario 裡對齊很差 —— 39-1 Attack 81／677（12.0%）、C&C 683／1,530（44.6%）；42-1 FileDownload 0／6；48-1 C&C-HeartBeat-FileDownload 0／11。

## p4 — usable scenario 的流量組成
**投影片**
- 左（`1.55fr`）：`assets/fig_labels.svg`。
- 右：要點 2 條
  - Malicious flow 幾乎都是內網 IoT 設備對外送 SYN：沒有回應、沒有 payload
  - scan 的 port：23／2323（Telnet）、22（SSH）、80／81／8080／8081、37215、52869

**數據來源**：`tests/iot23/results/*.json` 的 `labels`（圖）；`tests/iot23/ports_summary.txt`（port、conn_state、來源 IP）。

**定義與核對**
- 圖是 11 個 usable scenario 的 label 組成（100% 堆疊，占該 scenario labeled flow 的比例）；label 對應見「圖表規格」。
- 「幾乎」：11 個 scenario 的 malicious flow 合計 99.16% 是 S0、0.03% 帶 payload；scan flow 的 S0 比例 1-1 是 97.6%（其中 1.6% 帶 payload），其餘查過的 6 個 scenario 100%。
- Other malicious（C&C、Attack、FileDownload）在 11 個 scenario 都 < 0.14%，圖上幾乎看不到。
- 17-1 的 DDoS label（約 25%）：13,655,172 條 tcp/52869 SYN 打 11,959,048 個不同目的 IP，不符合 IoT-23 的 DDoS 定義，是 scan 樣式。

> **講稿注意**
> - 「怎麼讀」：每列一個 usable scenario；顏色 PortScan、Okiru、DDoS、Other malicious、Benign；S0 = Zeek `conn_state`「只看到 SYN、沒有回應」；每個 malware scenario 是在 Raspberry Pi 上執行一個 malware sample 錄下的流量，pcap 包含該設備錄製期間的全部流量，所以也有 DNS、NTP 等 Benign flow。
> - 這頁回答 10/05 的第一個問題：usable 的 11 個 scenario 幾乎都是沒有 payload 的 SYN；上次 Hakai（8-1）C&C 只有 SYN 不是單一樣本的特例。
> - 「多數可以在 flow 層級判斷」是**推論**，只在講稿說。ET Open 只對少數 port（例如 SSH）有門檻型 scan rule（Suricata 版 85 條帶 threshold／detection_filter 的 ET SCAN），23、8080、8081、37215、52869 的對外 SYN scan 沒有對應 rule。❌ 不可說「簽章 rule 抓不到 scan」，要說「ET Open 的 scan rule 有覆蓋缺口」。
> - port 背景：23 Telnet；2323 是 Mirai 拿來當 Telnet 替代 port 的**慣例**（IANA 登記的不是 Telnet）；37215 = Huawei HG532（CVE-2017-17215，Okiru／Satori 利用）；52869 = Realtek SDK miniigd UPnP（CVE-2014-8361，列在 CISA KEV）；8080／8081 是常見的替代 HTTP 管理 port。資料裡只有 SYN，看不到 exploit 內容。
> - ❌ 不可說「Okiru = 利用嘗試」：Okiru label 是「具 Okiru botnet 特徵」，資料只看得到對 37215 的 SYN。
> - 「每個 scenario 只有 1 個來源 IP、目的是外部公網 IP」的精確度：目的 IP 是抽查各 scenario 第一筆 scan flow；「只有 1 個來源 IP」在 1-1、7-1、9-1、17-1、33-1、48-1 直接數 conn.log 確認，39-1、43-1 只確認「≥ 1000 條 flow 的來源只有 1 個」。
> - 講稿備用：IoT-23 label 的官方定義與資料裡實際看到的（PortScan、Okiru、DDoS、Attack、C&C／HeartBeat／FileDownload；Mirai、Torii 是家族名稱）；每條 flow 的 packet 數（附錄 A 第 16 條）；Benign label 可疑（附錄 A 第 15 條）。
> - ❌ 不可把 42-1 當成正常 Benign 的對照：42-1 (Trojan) 99.86% 的 flow 被標成 Benign，其中 44%（1,947 條）是連到外部 185.244.25.183:4975 的 IRC（pcap 有 `NICK`、`NOTICE AUTH`）；正常 Benign 的對照只能用 17-1（34 種 (protocol, port)）、36-1（10 種）。

---

# 2. 完整 ET Open rules（章節頁 + p5–p8）

## p5 — 實驗設定
**投影片**
- `punch`：`問題: 完整 ET Open rules 是否能直接掛在 Pi 上`
- `callout(kind: "info")`：這次只量 IDS engine 的處理上限：engine 直接讀 pcap，**沒有走 cli → DUT → srv**
- 表格（`small-tbl(size: 0.9em)`）

| 項目 | 設定 |
|---|---|
| Hardware | Raspberry Pi 4（4 GB），1000 MHz |
| Engine | Suricata 7.0.10、Snort 3.12.2.0 |
| Rules | ET Open 2026-10-11（約 5.2 萬） |
| Traffic | IoT-23 的 14 個 scenario |

- 沒有頁尾。

**數據來源**：`pi_scen2_*.env.json`（engine 版本）；`tests/ids_rules/`（rule 快照、Snort 版轉換）。

**定義與核對**
- 約 5.2 萬：Suricata 版載入 52,606 條；Snort 版是 ET 的 Snort 2.9 rule 包經 snort2lua 轉換，載入 52,445 條（rule 包啟用 52,491 條）。
- kpps = engine 回報的 packets ÷ engine 自報的處理秒數（不含 load time）；**例外：Suricata `empty` 用差分法**（大 pcap 牆鐘 − 同切片前 500 packets 的牆鐘），因為它的自報時間不含 EOF 後約 0.7 s 的 flow 清理。
- load time = 牆鐘時間 − engine 自報處理時間。
- 量測流程與可靠性見附錄 A 第 5 條。

> **講稿注意**
> - 「怎麼讀」並口頭定義：kpps、engine 自報的處理時間（不含 load time）、三個 rule set（`empty`、`full`、`gw_corp`）、每格 3 次取中位數。
> - cli／srv 是測試用的 client／server，DUT 是被測設備（gateway）。10/05 規劃的整體測試要走 cli → gateway → srv（inline、4 種設定）；這次只把 ③ NFQUEUE 那一段的 IDS engine 單獨拿出來 offline 量，**預期**它是整條管線最重的一段、inline 會再加上 NFQUEUE 的複製與排隊成本；①② 與 inline 都**沒有量**。
> - 為什麼 Pi 4、鎖 1000 MHz（備用）：3B+ 曾有欠壓降頻，換板；Pi 4 R1.4 在預設 `arm_boost=1` 下最高 1.8 GHz，官方寫 80°C 起逐步降頻、85°C 時 CPU 與 GPU 都降頻；沒散熱時 1.8 GHz 滿載約 30 秒到 80°C → 鎖 1000 MHz，600 秒 4 核滿載最高 77.4°C 無降頻。❌ 不可說「Pi 4 在 80°C soft throttle」。
> - matcher（備用）：Suricata `ac-ks`（Debian arm64 套件沒有 Hyperscan；官方建議「沒有 Hyperscan 時」的選項）、Snort 3 `ac_bnfa`（預設，但 Snort 自己描述為 low memory、不是最快）→ Pi 上的數字不是兩個 engine 的最快設定。
> - ❌ 不要說「ET 有 snort-3.0.0 rule 包」。
> - 差分法（備用）：在 flow 很多的 scan 流量上兩種算法差很多（17-1 前 60 萬 packets：自報 93.5 vs 差分 48.3 kpps），所以 `empty` 與其他 rule set 的比較在 scan 流量上要保守看。

## p6 — 效能測試的 14 個 scenario
**投影片**：表格（14 列，`small-tbl(size: 0.82em)`；依 packets 排序，前 10 個 20 萬 packets，後 4 個依 packets 由多到少；順序與兩張速度圖一致）

| scenario | 流量型態 | packets | 平均 packet | usable |
|---|---|---|---|---|
| 17-1 (Kenjiro) | SYN scan 8081/80 | 200,000 | 60 B | ✓ |
| 36-1 (Okiru) | SYN probe 37215 | 200,000 | 60 B | ✓ |
| 48-1 (Mirai) | SYN scan 23 | 200,000 | 85 B | ✓ |
| 39-1 (IRCBot) | SYN scan 22 | 200,000 | 124 B | ✓ |
| 3-1 (Muhstik) | SSH scan + IRC | 200,000 | 98 B | |
| 1-1 (Hide and Seek) | multi-port + UDP | 200,000 | 71 B | ✓ |
| 34-1 (Mirai) | TCP/UDP mixed | 200,000 | 602 B | |
| 60-1 (Gafgyt) | UDP flood, small | 200,000 | 61 B | |
| 44-1 (Mirai) | UDP flood, large | 200,000 | 1,360 B | |
| Honeypot-5-1 (Amazon Echo) | TLS download | 200,000 | 990 B | |
| Honeypot-7-1 (door lock) | benign | 119,638 | 261 B | |
| 20-1 (Torii) | C2 443 | 50,156 | 65 B | |
| 42-1 (Trojan) | file download | 24,484 | 103 B | ✓ |
| Honeypot-4-1 (Philips HUE) | benign | 21,664 | 196 B | |

- 沒有頁尾、沒有解釋句。

**數據來源**：`tests/ids_throughput/results/scenario_features.tsv`（`packets`、`avg_size`）；packets 也要等於 `pi_scen2_*.summary.csv` 的 `pkts`。流量型態字串與 `make_figs.py` 的 `SCEN` 表相同。

**定義與核對**
- packets = 實際送進 engine 的 packet 數：主 pcap 的前 200,000 個；20-1、42-1、Honeypot-7-1、Honeypot-4-1 不足 20 萬，用整檔。Honeypot-7-1 這一列是 Somfy-02 那天的 pcap（沒有 label），`scenario_features.tsv` 的 `Hon-7-1__Somfy-02`。
- 平均 packet = 這些 packet 的平均大小（含 header）。
- `usable` ✓ = 也在 p3 的 11 個 usable 內（6 個：17-1、36-1、48-1、39-1、1-1、42-1）。

> **講稿注意（這頁回答「前面說 11 個 usable、後面為什麼用 14 個」）**
> - detection rate 要拿 alert 跟 label 比，需要 label 正確 → 用 p3 的 11 個 usable；處理速度只需要真實的 packet、不讀 label → 依流量特徵挑選，特徵相近的只取一個（`10_scenario_features.py`：平均大小、payload 比例、TCP／UDP、SYN 比例、目的 port 數、目的 IP 數）。
> - 另外 8 個不在 usable 的原因都和 label 有關（❌ 不可說「都是 label 與 pcap 對不上」）：沒有 label（Honeypot-7-1 這個 pcap）、label 與 pcap 對不上（3-1、34-1、60-1、44-1、Honeypot-5-1、Honeypot-4-1）、被 packet coverage 門檻擋掉（20-1）。packet 本身都是真實流量。
> - 為什麼不只用 11 個 usable（備用）：它們的平均 packet 都在 60–124 B、9 個 SYN 比例 ≥ 91%，幾乎都是 SYN scan；會失去 UDP flood、大 packet（44-1 平均 1,360 B）、TLS 下載、benign IoT，也會失去「Snort 3 `full` 在 TLS 下載（Honeypot-5-1）仍有 80.8 kpps」這個反例。另外 5 個 usable（33-1、35-1、43-1、9-1、7-1）沒選，是因為特徵和已選的 scan 幾乎一樣（平均 60–78 B、SYN 97.8–99.5%；例如 7-1 是 60.2 B、SYN 99.33%、tcp/37215 占 99.4%，和已選的 36-1 的 60.1 B、99.85%、tcp/37215 幾乎相同）。
> - 用 packet 數而不是 MB 統一：IDS 的成本主要是每 packet、每 flow；統一 MB 的話小 packet 的 scenario 會多 20 倍以上的 packet。

## p7 — `full` 的處理速度
**投影片**
- `assets/fig_full14.svg`（整頁寬）。
- 要點 3 條（0.82em）
  - Suricata：14 個 scenario 都跑得動，最慢 15.5 kpps
  - Snort 3：9 個 scan／flood scenario 不到 1 kpps
  - Snort 3 慢的原因是帶 IP 清單的 rule：（換行）拿掉後 0.37 → 64.3 kpps(17-1)
- 沒有頁尾。

**數據來源**
- 圖與第 1、2 點：`pi_scen2_{E,S,N}.summary.csv`（`pps_med`；Suricata `empty` 用 `pps_diff`；時間欄是 `self_med`）。
- 第 3 點：主矩陣 A 切片（`A_scan17.pcap` = 17-1 (Kenjiro) 前 60 萬 packets）：Snort 3 `full` 366 pps（`pi_R2b`）→ `sel` 64,299 pps（`pi_R2a1`）；Snort 3 `empty` 104 kpps（`pi_E`）；Suricata `full`／`sel` 在 `pi_R1`。

**定義與核對**
- 第 1 點：Suricata `full` 最慢 39-1 (IRCBot) 15.5、最快 60-1 (Gafgyt) 176 kpps（15.5–176）。
- 第 2 點的 9 個 = p6 表的前 9 列（20 萬 packets 的 10 列中 Honeypot-5-1 以外）：0.37–0.92 kpps，處理時間 217–539 s（附錄 A 第 24 條）。
- 第 3 點的 0.37 是 A 切片的 366 pps，和圖上 14 個 scenario 的最小值 0.37（36-1，200,000 ÷ 539.4 s）是不同的量測，剛好同值；括號的 17-1 就是指 A 切片。
- `sel` = `full` 扣掉 header 逗號 ≥ 8 的 1,559 條 rule（Snort 3 載入 52,445 → 50,886；`04_make_sel_rules.py` 用 Snort 版決定 sid，兩個 engine 移除同一批 sid），約占 3%；依成本挑，不是依偵測價值挑。

> **講稿注意**
> - 「怎麼讀」：每列一個 scenario（順序同 p6，y 軸只寫名稱、流量型態看 p6）；x 軸 kpps、log 刻度（0.3、1、3、10…，每兩個刻度差 10 倍）；空心灰圈 = `empty`、深色方塊 = `full`，兩點距離越遠 rule 成本越高；右側 `full time` = 處理這個 scenario 全部 packets 的秒數，kpps = packets ÷ 時間；**時間只能在 packets 數相同的列之間比**，跨列比快慢看 kpps。
> - 分三群的意思（講稿正文）：第一群 scan 和混合流量、第二群 flood 和下載，兩群都是 20 萬 packets；第三群是不到 20 萬、用整檔的 4 個。
> - 和 `empty` 比（講稿正文第 2 點）：Snort 3 `empty` 14 個都有 38.6–97.9 kpps，不到 1 kpps 的 9 個掛 `full` 後只剩 `empty` 的 ≤ 1.6% → 慢的是 rule 不是 engine 本身。備用：Suricata `full`／`empty` 16%（Honeypot-7-1）～81%（Honeypot-5-1）；Snort 3 有 12 個 0.4%～7.9%（20-1 最高），Honeypot-7-1 26%、Honeypot-5-1 85%。
> - 第 3 點其他 scenario 沒量 `sel`，原因相同是**推論**；另外 3-1 整檔（B2 切片）也量過，0.56 → 21.2 kpps。
> - Snort 3 `full` 另外 5 個 scenario：20-1 6.3、42-1 1.5、Honeypot-5-1 80.8、Honeypot-7-1 21.4、Honeypot-4-1 1.8 kpps → 14 個中 12 個約 6.3 kpps 以下。❌ 不可說「Snort 3 只有在 scan／flood 下不能用」。
> - 1,559 條的組成（備用）：TOR 803（出口 121 + 中繼 682，每條 10 個 IP）、CINS 596（每條 50 個）、DROP 69（20–21 個）、Threatview 42（50 個）、COMPROMISED 38（30 個）、其他 11；合計 42,592 個 **IP／網段項目**。❌ 不可說「TOR 出口節點 803 條」。
> - 可能機制（**未驗證**，要用 Snort 3 rule profiler 與 `suricata --engine-analysis` 確認）：Snort 3 開發文件「Rules w/o fast patterns … evaluated for each packet for which the group is selected. These are definitely bad for performance.」、header 的 IP 清單逐項比對；Talos 建議 IP-only rule 改用 reputation；Suricata 有 radix tree 的 IP-only engine，每條 flow 每個方向查一次。
> - Suricata 對這批 rule 幾乎不受影響：`sel` 與 `full` 差 ≤ 3%。
> - `common`（兩個 engine 都載得進的 sid 交集）與 `full` 幾乎相同，被問到再說（同一個 sid 在兩個 rule 包裡文字不同，結構一致只有 38.7%）。

## p8 — Memory：`full` 在 1／2／4 GB
**投影片**
- 表格（`small-tbl(size: 0.9em)`；engine 名稱用 `#su`／`#sn` 上色）

| Memory | Suricata kpps | Suricata RSS | Snort 3 kpps | Snort 3 RSS |
|---|---|---|---|---|
| 4 GB | 15.5 | 1,240 MB | 0.39 | 376 MB |
| 2 GB | 15.3 | 1,240 MB | 0.38 | 376 MB |
| 1 GB | 13.4 | 719 MB | 0.39 | 376 MB |

- 要點 1 條：1 GB 時 Suricata 慢約 13%，Snort 3 不受影響
- 沒有頁尾。

**數據來源**
- scenario：39-1 (IRCBot) 的 20 萬 packets（`S_m39.pcap`），`full`。
- 4 GB 列：`pi_scen2_S`／`pi_scen2_N` 的 `S_m39`（= p7 的 39-1）。
- 2 GB、1 GB 列：`pi_mem39_{2gb,1gb}.csv`／`.summary.csv`（2026-10-18，`run_pi_mem_scen.sh`；每個等級重開機後 `full`、`gw_corp` × 兩個 engine，每格 1 暖機 + 3；zram 開；正式列 ARM 時脈全部 1000 MHz）。
- VmSwap：`results/pi/logs/pi_mem39_1gb.log` 的單獨取樣（Suricata `full` 峰值 794 MB）。

**定義與核對**
- kpps = 200,000 ÷ 自報處理時間的中位數（`pps_med`）。
- RSS = 每次正式量測的峰值 RSS（原始 CSV 的 `maxrss_mb`）取 3 次中位數；summary 的 `maxrss_mb_max` 是 3 次的最大值，不要拿來核對 1 GB 那一列。
- Memory 欄 = 用 `total_mem` 限制後 Pi 可用的 memory；4 GB 不設限制。1 GB 時系統可用約 905 MB（`pi_mem39_1gb.env.json` 的 `mem_total_kb`）。
- Snort 3 2 GB 實際 0.376 kpps（比 4 GB 慢約 4%，超出 3 次之間的差距，照實寫 0.38）；1 GB 回到 0.387，RSS 只有 376 MB，不是 memory 造成。
- 1 GB 多花的處理時間：12.92 → 14.89 s（約 +2.0 s）。
- 這組量測全部正常結束，dmesg 沒有 OOM 紀錄（`pi_mem39_*.dmesg.txt`）。

> **講稿注意**
> - 「怎麼讀」：Memory 欄、kpps、RSS（resident set size，3 次中位數）的定義；4 GB 列就是 p7 的 39-1。
> - 為什麼選 39-1：Suricata `full`／`gw_corp` 都是 14 個 scenario 最慢、RSS 最大（1,240／977 MB，其他 13 個是 1,184／918 MB）；Snort 3 也排在最慢的前幾個；而且在 11 個 usable 裡。
> - 接回 10/05：「完整 ET Open 在小型 ARM 上很吃 memory 是社群經驗，Pi 3B+ 只有 1 GB，要量過才知道」→ 這頁就是量的結果。1 GB 對應 3B+ 的 memory 容量，但 CPU、memory 頻寬仍是 Pi 4，不能當成 3B+ 的結果。
> - 1 GB 的 RSS 719 MB **不是用得比較少**：放不下的部分被壓進 zram（Raspberry Pi OS 預設開著），換出去的 page 不算 RSS；VmSwap 峰值約 794 MB。VmSwap 和 RSS 中位數不是同一次量的，不要相加。❌ 不可說「Suricata 在 1 GB 只需要 719 MB」「memory 不是問題」。
> - **推測**：1 GB 的代價接近一段固定的換頁時間（多約 2 秒），百分比會隨 pcap 長度改變；長時間運作的影響要 inline 才知道。
> - 沒有 swap 的情況**沒有量**（這組只量系統預設的 zram 開）。
> - 時脈（備用）：剛開機一兩分鐘內 kernel 已把上限設成 1000 MHz，但 CPU 實際還跑在 1800 MHz，所以腳本開跑前會等 `vcgencmd` 回報的 ARM 時脈降到 1000 MHz。

---

# 3. Rule 篩選（章節頁 + p9–p12）

> 這一節回應老師的建議：挑合理的 rule，並說明為什麼合理。順序：ET Open 有哪些 category（p9）→ `gw_corp` 挑了什麼、為什麼（p10）→ 速度（p11）→ memory（p12）。

## p9 — ET Open 的 rule category
**投影片**
- 左（`1.5fr`）：`assets/fig_etcats.svg`。
- 右：要點 3 條
  - 52,606 條 rule、73 個 category
  - 最大的 MALWARE 就有 19,277 條；前 5 個 category 占 74%
  - 其他 58 個 category 合計只有 3,090 條（5.9%）

**數據來源**：`rule_category_decisions_corp.tsv` 的 `rules`（圖；`make_figs.py` 斷言 73 個 category、52,606 條）；`rule_features.tsv`（每條 rule 的 category）。

**定義與核對**
- category 依每條 rule `msg` 開頭的 `ET <category>`；舊版 GPL rule 依子 category（GPL_*）。73 個 = 47 個 ET + 26 個 GPL_*（913 條）。這是 ET 的慣例加 rule 檔實證，沒有找到官方文件明文寫「msg 前綴 = category」。
- 前 5 個：MALWARE 19,277、DYN_DNS 6,096、WEB_SPECIFIC_APPS 6,074、INFO 4,548、PHISHING 2,949，合計 38,944（74.0%）。
- 前 15 個合計 49,516（94.1%）；其他 58 個 3,090（5.9%）。
- SCAN 274、DOS 59、TELNET 4，都在「其他 58 個」裡。73 個 category 裡沒有 POLICY（ET 已併入 INFO）。

> **講稿注意**
> - 「怎麼讀」：每條橫條是一個 category，長度 = rule 數（標在條尾）；畫的是 Suricata 版 rule 數最多的 15 個；最下面灰色那一條是其餘 58 個的合計，不是一個 category。
> - 為什麼不用 metadata（備用）：ET 有 `metadata`（`attack_target`、`affected_product`、`signature_severity`、`confidence` 等），但不完整（`attack_target` 有 10,750 條沒標）；`gw_corp` 只依 category（INFO、CHAT 另用 `msg` 篩 IRC）。只用 severity 篩（Major／Critical 且 `confidence` High）會留下 21,809 條，但 ET SCAN 只剩 13／274、TELNET 0／4、CHAT 0／37，而且會丟掉 2003068（SSH scan）、2019240（ELF download）、2000345、2000355、2002024（IRC）→ 不能只靠 metadata。

## p10 — `gw_corp`：本地 IDS 掛哪些 rule
**投影片**：表格（`small-tbl(size: 0.78em)`、inset `(x: 8pt, y: 5.5pt)`、欄寬 `(auto, 2.4fr, 1fr, auto)`；category 名稱用 `#box[...]` 避免中間斷行）。沒有 `punch`、沒有頁尾。

| | 第 9 頁的 category | 為什麼 | rules |
|---|---|---|---|
| ✓ 全部保留 | MALWARE、WEB_SPECIFIC_APPS、PHISHING、EXPLOIT_KIT、EXPLOIT、MOBILE_MALWARE、WEB_SERVER、ADWARE_PUP、ATTACK_RESPONSE、WEB_CLIENT ＋ 其他 40 個（SCAN、DOS、TELNET…） | 和入侵直接相關 | 38,399 → 38,399 |
| △ 只留 IRC | INFO ＋ CHAT | IRC 常被當 C2；其餘只是資訊 | 4,585 → 12 |
| ✗ 不保留 | DYN_DNS、HUNTING ＋ 其他 1 個（TA_ABUSED_SERVICES） | 官方說明：觸發不代表攻擊 | 7,567 → 0 |
| ✗ 不保留 | RETIRED ＋ 其他 11 個（P2P、REMOTE_ACCESS…） | 辨識服務使用、過時技術 | 839 → 0 |
| ✗ 不保留 | TOR ＋ 其他 5 個（CINS、DROP…） | IP blocklist | 1,216 → 0 |

- 符號：第一列 `#yes`、第二列 `#partly`、後三列 `#no`。

**數據來源**：`rule_category_decisions_corp.tsv`（`category`、`rules`、`decision`、`kept`、`long_ip_rules`）、`RULE_CATEGORIES_corp.md`、`12_gateway_rule_corp.py`。TSV 只有 4 種 decision：本地需要（50 個、38,399 條）、本地部分保留（INFO、CHAT）、IP blocklist（6 個、1,216 條）、不放本地（15 個、8,406 條）；投影片把「不放本地」依理由拆成第三列（3 個、7,567 條）與第四列（12 個、839 條）。

**定義與核對**
- rule 數：38,399 + 4,585 + 7,567 + 839 + 1,216 = 52,606。
- category 數：50 + 2 + 3 + 12 + 6 = 73；p9 圖上點名的 15 個全部在表裡（第一列 10 個 + INFO + DYN_DNS、HUNTING + RETIRED + TOR）；「其他 58 個」= 40 + 1（CHAT）+ 1 + 11 + 5。
- 第二列：INFO 4,548 → 3、CHAT 37 → 9，都是 `msg` 含 IRC 的。
- 第三列：DYN_DNS 6,096、HUNTING 1,351、TA_ABUSED_SERVICES 120。
- 第四列：RETIRED 408、FILE_SHARING 190、REMOTE_ACCESS 86、P2P 80、GAMES 23、INAPPROPRIATE 1，加 6 個舊版 GPL（GPL_CHAT 17、GPL_ICMP 14、GPL_RETIRED 9、GPL_INFO 5、GPL_P2P 5、GPL_REMOTE_ACCESS 1）。
- 第五列：TOR 803、CINS 299、DROP 68、THREATVIEW 22、COMPROMISED 19、CNC 5（header 裡約 25,924 個 IP／網段項目；CNC 的 5 條清單不長，但也是只比對 IP）。
- **表上的箭頭右邊是依 category 判斷的結果；實際產生的 rule 檔另有差異**（講稿被問到時要能說明）：
  - 排除 IP blocklist 時，除了整個 category，還用「rule header 逗號 ≥ 8」排除其他 category 裡帶長清單的 rule。這個條件也篩到第一列 21 條有比對內容的 rule（MALWARE 14、EXPLOIT 5、SCADA 1、ADWARE_PUP 1；20 條 header 是 10–13 個 port、1 條是 29 個 IP 加 content；Emotet／zgRAT C2、HeartBleed、FREAK 等），是誤篩的正常偵測 rule，之後加回。所以量測用的 `gw_corp` 第一列實際是 38,378 條（TSV 的 `kept`）。
  - flowbits 依賴：保留的 rule 要靠別的 rule 先設 flowbit 才會觸發，補進 121 條（INFO 78、HUNTING 40、GPL_CHAT 3；其中 77 條本身會產生 alert）→ rule 檔裡實際有 81 條 INFO、40 條 HUNTING。
  - `gw_corp` = 38,378 + 12 + 121 = **38,511 條**（Snort 3 版 38,086，少的是 Snort rule 包沒有的 sid），約 `full` 的 73%。header 逗號 ≥ 8 的 rule 在 `gw_corp` 是 0 條（`full` 是 Snort 3 1,559、Suricata 1,232）。
- **沒有用 metadata**，只依 category。
- category 說明依 ET 官方的 rule category 說明：HUNTING「only recommended for use when actively researching potential threats」、DYN_DNS 主要是資訊性、TA_ABUSED_SERVICES「NOT guaranteed to be threat actor activity」、RETIRED「out-dated or disused technologies」（❌ 不是「ET 已停用的 rule」）；TOR／CINS／DROP／COMPROMISED／Threatview／CNC 依 IP 清單。

> **講稿注意**
> - 「怎麼讀」：表格把 p9 圖上的 category 逐一判斷；第一欄是判斷、第二欄是屬於這一列的 category、「為什麼」是理由、rules 欄 = 挑之前 → 依判斷放進 `gw_corp` 的條數；五列左邊加起來 52,606（= `full`）。
> - `gw_corp` 的意思：依公司 gateway 的需求，從 ET Open 挑出、掛在本地 IDS 的 rule set。
> - 為什麼以偵測面完整為優先（正文）：保護公司內網與外網之間、內網什麼平台都有、最後的 IDS 可能自己實作 → 只要和入侵有關就保留，只排除三種：觸發不代表攻擊的、只是辨識服務使用或過時技術的、只比對 IP 的 blocklist。
> - 逐列理由（正文）：保護對象（不依平台排除）、位置（看得到內網↔外網兩個方向，SCAN、DOS、TELNET 全部保留）、IRC 常被當 C2（3-1、34-1、42-1 都有 IRC）、ET 自己說明觸發不代表攻擊、P2P／GAMES／REMOTE_ACCESS 等是公司政策、IP blocklist 只比對 IP 不看內容（p7 也看到它讓 Snort 3 很慢，是佐證不是主要理由）。
> - **判斷表是我們的分析，不是偵測價值的驗證** → 請老師看是否合理。
> - 不保留的 rule 之後放哪（備用，投影片不標）：IP blocklist 打算改用 ② nftables 的 IP set，在管線前段比對，**還沒實作、沒量**；接回 9/21（當時**提過** blocklist **可以**灌進 nftables set）。第三、四列的 15 個 category 交給雲端分析，或不需要 → 對應研究目標的雲端卸載候選。
> - nftables set（備用）：hash／紅黑樹實作，單一 IP 查詢約常數時間、CIDR 區間約對數成長（不是「完全不隨清單長度增加」）；**未實作、未量測**。ET 也提供防火牆用的 IP 清單（`rules.emergingthreats.net/fwrules/`）；另一個選項是 Snort 3 reputation／Suricata IP reputation。
> - ❌ 不要舉 POLICY；❌ 不要說「高信心」（`gw_corp` 沒有用 confidence／severity）。

## p11 — `gw_corp` 的處理速度
**投影片**
- `assets/fig_corp14.svg`（整頁寬）。
- 要點 2 條（0.82em）
  - Suricata：和 `full` 差不多
  - Snort 3：14 個 scenario 都 ≥ 11 kpps
- 沒有頁尾。

**數據來源**：`pi_scen2_{E,S,N}.summary.csv`（圖、兩個要點）；load time（講稿）從 `pi_scen2_S.csv`／`pi_scen2_N.csv` 的每次正式量測算（牆鐘 − 自報）。

**定義與核對**
- 第 1 點：Suricata `gw_corp` 15.8（39-1）～178（60-1）kpps，比 `full` 只快 1.01–1.26 倍（1–26%，最多的是 Honeypot-7-1）。
- 第 2 點：Snort 3 `gw_corp` 最慢 44-1 (Mirai) 11.4、最快 Honeypot-5-1 (Amazon Echo) 94.5 kpps；`full` 最慢是 0.37 kpps（36-1）。
- load time（不在投影片上，講稿被問到時）：牆鐘時間 − engine 自報處理時間，取 14 個 scenario 全部正式量測的中位數；`full` → `gw_corp`：Suricata 34.9 → 24.7 s、Snort 3 26.3 → 19.3 s。
- rule 數 Suricata 38,511、Snort 3 38,086（不在投影片上，講稿說）。
- Snort 3 `gw_corp` 在 12 個 scenario 比 `full` 快 9.6–213 倍（17-1 最多）；Honeypot-5-1、Honeypot-7-1 本來就不慢（1.17、1.14 倍）。

> **講稿注意**
> - 「怎麼讀」：同 p7；空心灰圈 = `empty`（比 p7 大一圈）、深色方塊 = `full`、engine 色實心點 = `gw_corp`；點在方塊右邊越遠，`gw_corp` 比 `full` 快越多；離空心圈越近，剩下的 rule 成本越小；右側 `gw_corp time` 同 p7 的讀法。
> - 「Suricata 只快 1–26%」是偵測面完整的代價（正文）。
> - 為什麼 Snort 3 快這麼多、Suricata 幾乎不變：p7 `sel` 扣掉的那批 header 帶長 IP 清單的 rule，`gw_corp` 一條都沒有；Suricata 本來就幾乎不受它們影響、`gw_corp` 仍保留約 73% 的 rule。**因果是推論**：`gw_corp` 同時也拿掉了 DYN_DNS 等 8,406 條，沒有單獨量，只是和 `sel` 結果一致。
> - 最差 scenario（備用）：Suricata 15.8 kpps（39-1，平均 124 B ≈ 15.7 Mbps）、Snort 3 11.4 kpps（44-1，平均 1,360 B ≈ 124 Mbps）→ 上限要用 pps 講並說明流量型態。
> - 沒有一個 engine 在所有 scenario 都比較快（備用）：大範圍 scan 下 Snort 3 `gw_corp` 較快（17-1：80.1 vs 33.7；36-1：77.2 vs 18.5 kpps，兩邊都是自報時間）；大 payload 的 UDP 則 Snort 3 較慢（44-1：11.4 vs 37.0）。目的 IP 很分散時 Suricata 連 `empty` 都變慢，**推測**是新 flow 的建立成本、**未驗證**；幅度要保守講（差分法 48-1 → 36-1 是 127 → 25.8 kpps；自報時間 138 → 66.4 kpps，約 2.1 倍）；要先排除 Debian 預設 `suricata.yaml` 開了 eve `flow` 事件。
> - ❌ 不可籠統說「Suricata 對 rule set 不敏感」：這輪只比了 `full` 和 `gw_corp`（約 73%），rule 數少很多時沒有量。
> - `gw_corp`／`empty` 逐 scenario 比例與 load time 基線（`empty`：Suricata 0.26 s、Snort 3 0.23 s）放講稿備用。

## p12 — Memory：`gw_corp` 在 1／2／4 GB
**投影片**
- 表格（格式同 p8）

| Memory | Suricata kpps | Suricata RSS | Snort 3 kpps | Snort 3 RSS |
|---|---|---|---|---|
| 4 GB | 15.8 | 977 MB | 20.0 | 302 MB |
| 2 GB | 15.7 | 977 MB | 20.0 | 302 MB |
| 1 GB | 14.2 | 749 MB | 20.0 | 302 MB |

- 要點 1 條：1 GB 時 Suricata 慢約 10%，Snort 3 不受影響
- 沒有頁尾。

**數據來源**：同 p8（39-1、`gw_corp`）；4 GB 列 = p11 的 39-1（`pi_scen2_S`／`N` 的 `S_m39`）；2 GB、1 GB 列 = `pi_mem39_{2gb,1gb}`；VmSwap 峰值 466 MB（`logs/pi_mem39_1gb.log`）。

**定義與核對**
- kpps、RSS 的算法同 p8。
- Snort 3 實際 20.00／19.89／19.90 kpps（差 0.5%，統一寫 20.0）。
- 1 GB 多花的處理時間：12.62 → 14.04 s（約 +1.4 s）。
- Suricata `gw_corp` 的 977 MB 仍超過 1 GB 時系統可用的約 905 MB。

> **講稿注意**
> - 「怎麼讀」：同 p8，只是 rule set 換成 `gw_corp`；4 GB 列就是 p11 的 39-1。
> - 和 p8 比：挑 rule 讓 Suricata 的 RSS 從 1,240 降到 977 MB、VmSwap 從約 794 降到約 466 MB，但 1 GB 時一樣要靠 zram、一樣會變慢；多花約 1.4 秒，和 `full` 的約 2 秒相近，和 p8「接近一段固定換頁時間」的**推測**一致。
> - 其他 scenario 的 RSS（備用）：Suricata 14 個中 13 個都是 918 MB（`full` 1,184 MB），只有 39-1 較大（977 MB）；Snort 3 `gw_corp` 290–360 MB（最大 48-1 360 MB；`full` 433 MB）；`empty` 基線 Suricata 165 MB、Snort 3 121 MB。
> - ❌ 不可說「`gw_corp` 解決了 Suricata 的 memory 問題」；❌ 不可說「只需要 749 MB」（約 466 MB 在 zram）。
> - 沒有 swap 的情況**沒有量**。

---

# 4. 結論與下一步（章節頁 + p13）

## p13 — 結論與下一步
**投影片**
- 表格（`small-tbl(size: 0.9em)`；engine 名稱 `#su`／`#sn` 上色；表頭英文）

| kpps | Min | Median | Mean | Max |
|---|---|---|---|---|
| Suricata `full` | 15.5 | 36.4 | 56.7 | 176 |
| Suricata `gw_corp` | 15.8 | 39.9 | 59.8 | 178 |
| Snort 3 `full` | 0.37 | 0.81 | 8.4 | 80.8 |
| Snort 3 `gw_corp` | 11.4 | 31.4 | 43.7 | 94.5 |

- 表下：→ **以 Suricata 為 base 實作能接雲端的 gateway**
  - 效能不被 rule 綁住，rule 可以照偵測需求挑
  - Suricata 在 10 個 scenario 比 Snort 3 快
- 沒有頁尾、沒有下一步清單（下一步放講稿）。

**數據來源**：`pi_scen2_{S,N}.summary.csv` 的 `pps_med`（每個 scenario 3 次中位數），對 14 個 scenario 取 min／median／算術平均／max。

**定義與核對**
- 每個 scenario 權重相同，和 packets 數無關。
- 「10 個 scenario」= 掛 `gw_corp` 時逐 scenario 比兩個 engine 的 kpps；Snort 3 較快的 4 個是 17-1、36-1、39-1、42-1。
- 備用數字：逐 scenario `gw_corp`／`full` 倍數的中位數 Suricata 1.05、Snort 3 30.9；幾何平均 Suricata 43.9／46.9、Snort 3 1.41／35.8；總 packets ÷ 總時間 Suricata 35.7／37.6、Snort 3 0.62／29.0（`full`／`gw_corp`）。

> **講稿注意**
> - 「怎麼讀」：每列是一個 engine 掛一種 rule set；念最慢（Min）、中位數（Median）、平均（Mean，算術平均）、最快（Max），說明是 14 個 scenario 的統計；平均會被少數快的 scenario 拉高（Snort 3 `full` 平均 8.4 主要來自 Honeypot-5-1 80.8），**以中位數為主**。
> - 結論只在這輪範圍內成立：Pi 4 鎖 1000 MHz、offline、single packet thread、ET Open 2026-10-11、IoT-23。
> - 選 Suricata 是**依取捨**：Suricata 的代價是 memory（p8、p12）；1 GB 的硬體上 Snort 3 + `gw_corp` 反而合適；選 Suricata 的前提是硬體 ≥ 2 GB 或之後能把 memory 壓下來；load time 25–35 s 也會影響 rule 更新。❌ 不可說「數據證明 Suricata 全面比較好」「已經能接雲端」。
> - 下一步（講稿備用）：① 實作 ② nftables IP set（接回 9/21，候選做法）；② 上次規劃的整體測試：inline、4 種設定、帶入 `gw_corp`（接回 10/05）；③ 選定 dataset：要有公司內網流量（IoT-23 只有 IoT；usable 的 11 個幾乎都是沒有 payload 的 SYN，帶 payload 的攻擊 label 對齊很差，Benign label 也可疑；上次的另一個候選是 CIC-IDS2017 修正版，還沒實測）。這是推論與待決事項，不是結論。
> - 請老師確認（講稿備用）：`gw_corp` 的判準是否合理（偵測面完整 vs. 效能；Suricata RSS 只從 1,240 降到 977 MB；如果要再縮小，例如 WEB_SPECIFIC_APPS 6,074 條依公司實際使用的軟體挑 —— 可以討論的方向，不是已決定的做法）；scenario 篩選門檻；整體測試的 dataset。
> - 還沒量的：inline（NFQUEUE）、multi-thread、detection rate、和雲端的串接；限制：offline ≠ inline、alert 數 ≠ detection rate、流量只有 IoT-23（沒有驗證 `gw_corp` 多保留的 PHISHING、WEB_CLIENT 等有沒有用）。

## p14 — References
- 只列參考網頁，每筆兩行（名稱一行、網址一行，網址用 Noto Sans Mono CJK TC），字級 0.68em，兩欄（左 9 筆、右 5 筆）。內文頁不加 [n] 標號。網址見附錄 B。

## Q&A
- `focus-slide[Q&A]`，大字置中。

---

## 圖表規格（`assets/make_figs.py`）
- 讀 repo 內的原始資料，**不手抄數字**（malware 名稱表 `FAMILY` 例外，抄自 IoT-23 官方表）：
  - `tests/ids_throughput/results/pi/pi_scen2_{E,S,N}.summary.csv`（不讀錨點批次；排除 `.small`／`.x2` pcap）
  - `tests/ids_throughput/results/rule_category_decisions_corp.tsv`
  - `tests/iot23/results/*.json`（`flows` 為空的 Somfy-02～06 跳過）
- 速度定義：`pps_med`；Suricata `empty` 用 `pps_diff`（差分法）。
- 輸出 SVG（`svg.fonttype = path`）、透明底；字型 Noto Sans CJK TC。
- 圖內**不放標題、副標、註解句、頁尾**；只保留軸標籤（英文）、刻度、圖例、必要的數值標籤。
- 配色：Suricata `#2a78d6`、Snort 3 `#eb6834`；`empty` 空心灰圈、`full` 深灰方塊、`gw_corp` engine 色實心點。
- 腳本內的斷言：有 label 的 scenario 23 個；usable 11 個（flow alignment ≥ 99% 且 packet coverage ≥ 90%）；73 個 category、52,606 條。

| 檔案 | 頁 | 長寬（in） | 內容 |
|---|---|---|---|
| `fig_align.svg` | p2 | 6.4×4.1（投影片上高 10.2 cm） | 23 個有 label 的 scenario（帶名稱），依 (flow alignment, packet coverage) 由低到高、最低的在最下面；flow alignment = 藍色實心點（ms 6），packet coverage = 灰色空心圈（ms 11、畫在上層、不填色），兩值相同時圈套在點外；x 軸 0–100%；圖例在左上 |
| `fig_labels.svg` | p4 | 6.6×4.0 | 11 個 usable scenario 的 label 組成（100% 堆疊橫條，小編號在上）；x 軸 `share of labeled flows (%)`；圖例在上方一排 5 個 |
| `fig_full14.svg` | p7 | 10.5×3.7（整頁寬） | 14 個 scenario × 2 engine × {`empty`, `full`}，左 Suricata、右 Snort 3（panel 標題用 engine 色）；橫向點圖、log x（刻度 0.3、1、3、10、30、100、300），軸標籤只寫 `kpps`；y 軸只寫 scenario 名稱、靠左對齊，順序同 p6，分三群（20 萬 packets 的 scan／mixed 7 個、flood／download 3 個、不足 20 萬的 4 個），群之間留空、不寫群名；灰線連起兩點；每個 panel 右側一欄 `full time`（engine 自報 `self_med`；< 100 s 寫一位小數、≥ 100 s 寫整數，engine 色）；圖例右上 |
| `fig_etcats.svg` | p9 | 6.4×4.6 | Suricata 版 rule 數最多的 15 個 category + `other 58 categories`（淺灰）橫條、條尾標數值；x 軸 `rules` |
| `fig_corp14.svg` | p11 | 10.5×3.7（同上） | 14 個 scenario × 2 engine × {`empty`, `full`, `gw_corp`}；`empty` 空心圈比 p7 大一圈（ms 10.5），`gw_corp` 和 `empty` 幾乎重疊時（例如 Snort 3 Honeypot-5-1）還看得到外圈；右側一欄 `gw_corp time`；圖例只寫 `empty`／`full`／`gw_corp` |

label 對應（`fig_labels.svg`）：`PartOfAHorizontalPortScan*` → PortScan；`Okiru*` → Okiru；`DDoS` → DDoS；`C&C*`、`FileDownload`、`Attack` → Other malicious；`Benign`／`benign` → Benign。

改圖之後要用 typst 編譯整份預覽，確認字沒有被切、沒有和點重疊，整份仍是 20 頁。

---

## 逐字稿要求（`逐字稿.md`）
- 只寫最終版，不寫改動紀錄。
- 頁碼採用投影片右下角的顯示頁碼；封面、章節頁、Q&A 不編號。
- 每頁三段：`>` 正文（要念的；有圖表的頁先念「**怎麼讀**」）、「**實驗怎麼做**」、「**被問到時**」（備用，不主動講）。
- 本文件每頁「講稿注意」的內容都要出現在對應頁。
- 推測／推論／未量的內容要明說；接前兩次報告的語氣不比原文強（09/21 是「提過可以」，不是「規劃了」）。
- 每張圖、每張表都有「怎麼讀」：`fig_align`（兩個指標的定義與方向、實心點／空心圈）、p3 表（每列原因）、`fig_labels`（100% 堆疊、label 類別、S0）、p5 表與 kpps／自報處理時間／差分法／rule set 定義、p6 表（packets、平均 packet、usable）、p8／p12 表（Memory、kpps、RSS）、`fig_full14`／`fig_corp14`（log 軸、marker、時間欄）、`fig_etcats`（category 來源、最後一條是合計）、p10 表（每欄、rules 欄、五列加總）、p13 表（Min／Median／Mean／Max、以中位數為主）。
- 名詞照 0.3 對照表；只引用最終投影片用到的實驗（0.6 的檔案）。
- 結尾附「不要犯的錯」清單（本文件的 ❌ 項目）。

---

## 附錄 A：不能寫錯的事實
> 數字與 `main.typ` 一致；製作與驗證都以這裡為準。

**實驗條件**
1. Hardware：Raspberry Pi 4 Model B Rev 1.4、4 GB、Debian 13（trixie）、鎖 1000 MHz（預設 `arm_boost=1` 最高 1.8 GHz）。**不是 Pi 3B+**。官方：80°C 起逐步降頻、85°C 時 CPU 與 GPU 都降頻（Pi 4 沒有 soft limit）；鎖 1000 MHz 時 600 秒 4 核滿載最高 77.4°C、無降頻。
2. 量測是 **offline**（engine 直接讀 tmpfs 上的 pcap，沒有走 cli → DUT → srv）、single packet thread；kpps = engine 回報的 packets ÷ engine 自報處理秒數（不含 load time）；**例外：Suricata `empty` 用差分法**。load time = 牆鐘 − 自報。
3. Engine：Suricata 7.0.10（Debian 套件，arm64 沒有 Hyperscan，matcher `ac-ks`）、Snort 3.12.2.0（`ac_bnfa`，預設但不是最快）。
4. Rules：ET Open 2026-10-11 快照。Suricata 版載入 52,606 條；Snort 版是 ET 的 Snort 2.9 rule 包經 snort2lua 轉換，載入 52,445 條（啟用 52,491）。ET 沒有 Snort 3 原生 rule 包。
5. 14 個 scenario 的量測（p7、p11、p13、p8／p12 的 4 GB 列）：`run_pi_scen2.sh`，2026-10-17 12:50–18:56 UTC 同一次開機，5 批（錨點 → `empty` → Suricata `full`／`gw_corp` 交錯 → Snort 3 `full`／`gw_corp` 交錯 → 錨點），每格 1 暖機 + 3 次、每輪打亂順序，取中位數；正式 348 次（含錨點 12 次）、作廢 0。自報時間 CV（不含 Suricata `empty`）中位數 0.51%、最大 6.9%（Suricata `gw_corp` Honeypot-7-1，第 1 次 2.587 s 離群，另外兩次 2.29、2.31 s；次大 6.3% 是 Suricata `gw_corp` 3-1）；Suricata `empty` 差分法 CV 中位數 1.26%、最大 2.65%。正式最高 65.2°C、`get_throttled` 全部 0x0、時脈約 1000 MHz。packet 數全部守恆；bytes 9 次不守恆（Snort 3 在 34-1，IP 分片）。錨點（Honeypot-7-1 整檔、`full`）頭→尾：Suricata 2.943 → 2.890 s（−1.8%）、Snort 3 5.579 → 5.574 s（−0.1%）；和主矩陣（2026-10-11；2.869、5.599 s）差 ≤ 2.6%。
6. 流量：14 個 scenario 各取主 pcap 前 20 萬 packets，4 個不足用整檔（20-1、42-1、Honeypot-7-1、Honeypot-4-1）；兩個 engine 讀同一個檔。Honeypot-7-1 這一列是 Somfy-02 那天的 pcap（119,638 packets，沒有 label）。
7. `sel` 實驗：主矩陣（2026-10-11，`run_pi_main.sh`）的 A 切片 = 17-1 (Kenjiro) 前 60 萬 packets；另有 B2 切片 = 3-1 (Muhstik) 整檔。
8. Memory 實驗（39-1）：`total_mem` 限制成 2／1 GB（4 GB 不設限）；2／1 GB 在 2026-10-18 量（`run_pi_mem_scen.sh`，每個等級重開機後跑，每格 1 暖機 + 3，zram 開，正式列 ARM 時脈全部 1000 MHz，全部正常結束）；4 GB 列取自 `pi_scen2_S／N` 的 39-1。1 GB 時系統可用約 905 MB。

**IoT-23**
9. 23 個 scenario（20 個 malware + 3 個 Honeypot）；Honeypot-7-1 底下有 Somfy-01～06 六天的 pcap，只有 Somfy-01 有 label。
10. **malware／設備名稱（IoT-23 官方表）**：1-1 Hide and Seek、3-1 Muhstik、7-1 Linux.Mirai、8-1 Hakai、9-1 Linux.Hajime、17-1 Kenjiro、20-1／21-1 Torii、33-1 Kenjiro、34-1／35-1／43-1／44-1／48-1／49-1／52-1 Mirai、36-1 Okiru、39-1 IRCBot、42-1 Trojan、60-1 Gafgyt；Honeypot-4-1 Philips HUE、Honeypot-5-1 Amazon Echo、Honeypot-7-1 door lock（Somfy）。官網拼成 "Phillips"、"Soomfy"、"Gagfyt"；投影片用一般拼法（Gafgyt 即 BASHLITE）。
11. 770,313,789 packets = 23 個 scenario 主 pcap 的總和（Honeypot-7-1 六個 pcap 都算；子集 pcap 不重複算）；325,309,946 labeled flows；flow alignment 98.87%（321,632,849 ÷ 325,309,946，加總後再除；扣掉 60-1 為 99.97%）；整體 packet coverage 96.42%。最大 pcap 22 GB（60-1）。
12. 不能直接用的 12 個與原因見 p3；「conn.log 比 pcap 早結束」只有 52-1（9.26 h）、49-1（0.83 h）；8-1、20-1、21-1、Honeypot-7-1 的 packet coverage 低**已確認**是非 IP packet。11 個 usable 見 p3。
13. 34-1／60-1：conn.log 把 DDoS 記成 0 packet。Zeek `ignore_checksums` 預設 F；34-1 抽檢 checksum 全錯、60-1 抽 2,000 個 tcp/62336 packet 也全錯 → 有佐證，**沒有用 Zeek 重跑確認**。60-1 的 flow alignment 0.02%、packet coverage 100% 不矛盾。
14. Okiru label 的定義是「具 Okiru botnet 特徵」；資料只看得到 SYN。37215 = CVE-2017-17215、52869 = CVE-2014-8361。2323 是 Mirai 的 Telnet 替代 port（慣例）。ET Open 沒有 23／8080／8081／37215／52869 的對外 SYN scan rule。
15. Benign label 可疑（講稿備用）：35-1 Benign 826 萬條（79%）99.9% 是 tcp/23、S0；43-1 2,057 萬條（30.6%）100% tcp/23、S0；33-1 138 萬條（2.5%）98.5% tcp/8080、S0；1-1 46.9 萬條（46.5%）分散在 79,026 種 (protocol, port)、9-1 2.3 萬條（0.35%）4,233 種。「看起來像 Mirai 的 Telnet scan」「可能是 P2P」都是**推測**。正常 Benign 的對照只能用 17-1（34 種）、36-1（10 種）；**42-1 不是**（44% 是 tcp/4975 的 IRC）。17-1 的 DDoS label 是 scan 樣式。
16. 11 個 usable scenario 的 flow（296,338,640 條，約 2.96 億）：1 個 packet 78.3%、2 個 19.2%、3 個 1.6%、4 個以上 0.9%（約 1%）；packet 數超過 100 的 flow 只占 0.02%，卻裝了 8.3% 的 packet（2026-10-18 用 mawk 重掃 11 個 conn.log.labeled 的 `orig_pkts` + `resp_pkts`；同一腳本只算 7-1 以外的 10 個得到 77.4／20.0／1.7／0.95%、8.5%，和舊數字一致）。

**結果**
17. `full`（14 個 scenario）：Snort 3 在 9 個 scan／flood scenario 0.37–0.92 kpps（217–539 s），其他 5 個 20-1 6.3、42-1 1.5、Honeypot-5-1 80.8、Honeypot-7-1 21.4、Honeypot-4-1 1.8（14 個中 12 個約 6.3 以下）；Suricata 15.5（39-1）～176（60-1）kpps。`empty`：Suricata（差分法）24.4（39-1）～256（Honeypot-7-1）、Snort 3 38.6（1-1）～97.9（17-1）kpps。
18. `sel`（A 切片）：Snort 3 `full` 0.37（366 pps）→ `sel` 64.3 → `empty` 104 kpps（176 倍）；B2（3-1）0.56 → 21.2 kpps；Suricata `sel` vs `full` 差 ≤ 3%。1,559 條 = TOR 803（出口 121 + 中繼 682）、CINS 596、DROP 69、Threatview 42、COMPROMISED 38、其他 11；42,592 個 IP／網段項目。機制**未驗證**。
19. p8（39-1、`full`）：Suricata 4／2／1 GB = 15.5／15.3／13.4 kpps、RSS 1,240／1,240／719 MB；Snort 3 0.39／0.38／0.39 kpps、376 MB。1 GB：Suricata 慢約 13%、VmSwap 峰值 794 MB、處理時間 12.92 → 14.89 s。
20. p12（39-1、`gw_corp`）：Suricata 15.8／15.7／14.2 kpps、RSS 977／977／749 MB；Snort 3 20.0（20.00／19.89／19.90）kpps、302 MB。1 GB：Suricata 慢約 10%、VmSwap 峰值 466 MB、處理時間 12.62 → 14.04 s。
21. ET Open（Suricata 版）73 個 category；前 5 個 MALWARE 19,277、DYN_DNS 6,096、WEB_SPECIFIC_APPS 6,074、INFO 4,548、PHISHING 2,949（合計 74.0%）；前 15 個 49,516（94.1%）、其他 58 個 3,090（5.9%）；SCAN 274、DOS 59、TELNET 4。沒有 POLICY。
22. `gw_corp`：p10 表 38,399 → 38,399、4,585 → 12、7,567 → 0、839 → 0、1,216 → 0（合計 52,606）。實際 rule 檔：第一列另有 21 條被 header 逗號 ≥ 8 誤篩（MALWARE 14、EXPLOIT 5、SCADA 1、ADWARE_PUP 1；之後加回）→ 38,378；`gw_corp` = 38,378 + 12 + 121（flowbits）= 38,511（Snort 3 38,086），約 `full` 的 73%。header 逗號 ≥ 8 的 rule：`full` Snort 3 1,559、Suricata 1,232，`gw_corp` 兩邊都是 0。**不用 metadata**。
23. `gw_corp`（14 個 scenario）：Suricata 15.8（39-1）～178（60-1）kpps，比 `full` 快 1.01–1.26 倍；Snort 3 11.4（44-1）～94.5（Honeypot-5-1）kpps，12 個 scenario 快 9.6–213 倍（Honeypot-5-1 1.17、Honeypot-7-1 1.14）。峰值 RSS（14 個 scenario 最大值）Suricata 1,240 → 977 MB（各 scenario 918–977）、Snort 3 433 → 360 MB（290–360）。load time Suricata 34.9 → 24.7 s、Snort 3 26.3 → 19.3 s。`empty`：Suricata 165 MB、0.26 s；Snort 3 121 MB、0.23 s。
24. 14 個 scenario 的處理時間（engine 自報 `self_med`、s；`pi_scen2_{S,N}.summary.csv`）：

| scenario | packets | `full` Suricata | `full` Snort 3 | `gw_corp` Suricata | `gw_corp` Snort 3 |
|---|---|---|---|---|---|
| 17-1 (Kenjiro) | 200,000 | 6.1 | 532 | 5.9 | 2.5 |
| 36-1 (Okiru) | 200,000 | 11.1 | 539 | 10.8 | 2.6 |
| 48-1 (Mirai) | 200,000 | 3.0 | 537 | 2.8 | 4.3 |
| 39-1 (IRCBot) | 200,000 | 12.9 | 512 | 12.6 | 10.0 |
| 3-1 (Muhstik) | 200,000 | 6.2 | 354 | 5.8 | 8.7 |
| 1-1 (Hide and Seek) | 200,000 | 3.4 | 321 | 3.2 | 5.9 |
| 34-1 (Mirai) | 200,000 | 5.6 | 266 | 5.1 | 12.6 |
| 60-1 (Gafgyt) | 200,000 | 1.1 | 217 | 1.1 | 2.8 |
| 44-1 (Mirai) | 200,000 | 6.0 | 231 | 5.4 | 17.5 |
| Honeypot-5-1 (Amazon Echo) | 200,000 | 1.6 | 2.5 | 1.6 | 2.1 |
| Honeypot-7-1 (door lock) | 119,638 | 2.9 | 5.6 | 2.3 | 4.9 |
| 20-1 (Torii) | 50,156 | 0.5 | 8.0 | 0.5 | 0.8 |
| 42-1 (Trojan) | 24,484 | 1.2 | 16.2 | 1.1 | 1.0 |
| Honeypot-4-1 (Philips HUE) | 21,664 | 0.6 | 12.2 | 0.5 | 0.8 |

   kpps = packets ÷ 時間（例：36-1 Snort 3 `full` 200,000 ÷ 539.4 s = 0.37 kpps）。圖上的時間欄由 `make_figs.py` 從 CSV 讀，這張表只供核對。
25. p13：Suricata `full` 15.5／36.4／56.7／176、`gw_corp` 15.8／39.9／59.8／178；Snort 3 `full` 0.37／0.81／8.4／80.8、`gw_corp` 11.4／31.4／43.7／94.5（Min／Median／Mean／Max）。`gw_corp` 下 Suricata 在 10 個 scenario 較快，Snort 3 較快的是 17-1、36-1、39-1、42-1。
26. 14 個 scenario 中也在 11 個 usable 內的：17-1、36-1、48-1、39-1、1-1、42-1（6 個）。效能測試不用 label。
27. 這輪**沒有**量 detection rate、inline、multi-thread；alert 數不是 detection rate；兩個 engine 的 alert 數不能直接比（Snort 3 沒有載入 snort2lua 產生的 `event_filter`）。

## 附錄 B：References（p14，照 `main.typ`）
> 網址逐字照抄。IoT-23（Zenodo DOI）與 Talos 兩個網站會擋程式請求（curl 回 403），瀏覽器可正常開啟。

左欄（dataset、rule、engine）
1. IoT-23：https://www.stratosphereips.org/datasets-iot23
2. IoT-23（Zenodo DOI）：https://doi.org/10.5281/zenodo.4743746
3. Zeek：Invoking Zeek（checksum）：https://docs.zeek.org/en/master/tutorial/invoking-zeek.html
4. ET Open rules：https://rules.emergingthreats.net/open/
5. ET Signature Metadata：https://community.emergingthreats.net/t/signature-metadata/96
6. Suricata 7.0.10 Tuning Considerations：https://docs.suricata.io/en/suricata-7.0.10/performance/tuning-considerations.html
7. Suricata Rule Types（IP-only）：https://docs.suricata.io/en/latest/rules/rule-types.html
8. Snort 3.12.2.0：https://github.com/snort3/snort3/releases/tag/3.12.2.0
9. Talos：Snort performance and IP-only rules：https://blog.talosintelligence.com/snort-performance-and-ip-only-rules/

右欄（硬體、方法、背景）

10. Raspberry Pi：Frequency management：https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/computers/raspberry-pi/frequency-management.adoc
11. Raspberry Pi：total_mem：https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/computers/config_txt/memory.adoc
12. CVE-2017-17215：https://nvd.nist.gov/vuln/detail/CVE-2017-17215
13. CVE-2014-8361：https://nvd.nist.gov/vuln/detail/CVE-2014-8361
14. Check Point：Okiru／Satori：https://research.checkpoint.com/2017/good-zero-day-skiddie/
