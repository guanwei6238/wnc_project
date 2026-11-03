# 新穎性查核報告（2026-11-03）

對象：`SCREEN.md` 定義的四個貢獻 C1–C4。
- 之前的文獻整理（`../trust-bypass/`、`../fastpath-methods/`、`../edge-colocation/`、`../paper.md`）多半靠 WebSearch 和引用追蹤。
- 這次改用學校授權的資料庫做系統性搜尋，並讀了全文。

## 0. 結論

1. **四個貢獻都沒有找到 overlap。** 標題摘要篩了 538 篇、全文讀了 20 篇（第一輪 18 篇、雪球 2 篇），沒有一篇和任何一個 Cx 做了本質上相同的事。
2. **但機制本身大多不新，貢獻要寫成「在什麼條件下、量到什麼」。** 只有 C1 的機制組合（放行後稽核＋撤銷＋量化漏報）找不到前例。
   - C2 的「只看開頭」與 HPA／DPA 都是別人的。
   - C4 的「kernel 讓已判定 flow 跳過 user space」有 Suricata 內建 bypass、Shunting、DS-nDPI、Wang & Chang。
   - C3 的「依負載調整」已有人列為 future work；跨核心記憶體頻寬干擾、SCHED_IDLE 擋不住，在一般系統文獻是已知現象。
3. **最接近的研究（逐篇差異見 §3）：**
   - C1：GLOBECOM 2025 in-network（抽 5% flow 校正模型）。它和雪球讀的 P4Pir、HALIDS 是同一條 in-network ML 脈絡，三篇都沒有 flow 層級的信任與撤銷。
   - C2：HPA（Erlacher & Dressler 2017）、Lin & Lee 2013。
   - C3：SOHO Suricata＋RF on Pi 4（IBDAP 2026）、Scheduling to the Rescue（EuroSec 2023）。
   - C4：DS-nDPI（CNSM 2017）、Wang & Chang（JNCA 2022）。
4. **ARM／Pi 上沒有可直接比的每封包成本。** 找到的 Pi 數字都只有吞吐或 CPU%，條件不全（§4）。這反而支持我們量測的價值。
5. **搜尋有已知的漏洞（§1.5）。** CS 系統類會議（USENIX Security、NDSS、CoNEXT、IMC）在 WoS 收錄差，Google Scholar 沒用。所以結論只能寫「to the best of our knowledge」，不能寫「沒有人做過」。

## 1. 搜尋流程

### 1.1 資料庫與存取
- 時間：2026-11-03（UTC 03:41–04:07，每筆查詢的時間記在各 `search_log.tsv`）。
- 存取：陽明交大 VPN（出口 140.113.0.229）。全文經學校授權下載；ScienceDirect 的人機驗證由使用者自己點。
- **Web of Science Core Collection**：9 組查詢＋FPA、HPA 的被引清單 → `wos/search_log.tsv`，匯出檔 `wos/q*.txt`。
- **IEEE Xplore**：6 組查詢＋DPA 的被引清單 → `ieee/search_log.tsv`，匯出檔 `ieee/i*.csv`。
- **ACM Digital Library**：3 組摘要欄位查詢 → `acm/search_log.tsv`，結果少、只看標題。
- **沒用上的**：
  - Scopus：學校沒有訂閱，只能看 Preview。
  - OpenAlex：未登入每天每個 IP 有額度上限，第一輪就用完，只留部分快取在 `search/cache/`、沒有進入篩選。雪球階段改用它免費的單篇查詢拿摘要。
  - Google Scholar：沒用。

### 1.2 查詢設計
每個 Cx 至少一組 WoS、一組 IEEE 查詢，用「機制詞 AND 系統詞 AND 問題詞」三段組合。完整字串見各 log。

| Cx | WoS | IEEE | ACM |
|---|---|---|---|
| C1 放行後稽核 | q1（bypass×sampling/audit/revoke）、q8（whitelist×data plane）、q9（adaptive sampling×IDS） | i1、i6（trust/whitelist×gateway×revoke/audit） | a1 |
| C2 部分檢查 | q2（cutoff/first packets×evasion）、q3（payload aggregation/truncation）、q4（Suricata/Snort×Pi/ARM/gateway） | i2、i3（payload aggregation/truncation） | a2 |
| C3 同機 IDS＋ML | q5（IDS×ML×edge×allocation/interference）、q6（memory bandwidth/cache contention×packet processing） | i5 | a3 |
| C4 kernel fast path | q7（eBPF/XDP/conntrack/NFQUEUE×IDS×bypass/offload） | i4 | — |

### 1.3 篩選
- 合併 WoS 匯出與 IEEE CSV、依 DOI／標題去重後得 538 篇（`screen_candidates.jsonl`）。各查詢的貢獻：
  - IEEE：i6 131、i1 93、i4 82、i2 50、i5 9
  - WoS：q4 76、q1 59、q5 43、q9 35、q7 33、q6 8
  - 有 76 篇同時出現在兩個以上的查詢
- 3 個 subagent 依 `SCREEN.md` 只看標題摘要標記（`screen_out_part*.tsv` → `screen_result.tsv`）：**overlap 0、related 89、none 449**。
- 少量結果沒有匯出、由主 agent 直接看標題判斷：q2、q3、q8、FPA／HPA／DPA 的被引清單、ACM 三組。標題寫在各 log 的 results 欄。
- 從 89 篇 related 中挑 17 篇最可能撞到的進全文（`shortlist.tsv`），另加 Kodialam & Lakshman 2003（賽局抽樣的源頭）。

### 1.4 全文與雪球
- **第一輪全文（18 篇）**：
  - 5 個 Sonnet subagent 分組逐篇精讀，對 C1–C4 各給標記並附章節與頁碼。每篇的引用清單也要列出可能比它更接近的文獻（雪球）。
  - 報告在 `fulltext/G1`–`G5`。
- **抽查**：主 agent 回原文核對了 11 處關鍵引文，全部一致。
  - DS-nDPI 的 eBPF 表與 idle 移除
  - SOHO 論文 IV-D 的「did not implement overload-control」
  - Scheduling to the Rescue 的「memory-bound」推測與 4.4 GB/s
  - GLOBECOM 2025 的 5% 抽樣
  - Wang & Chang 的「mirrored copies」與 Suricata「XDP-based flow bypassing」
  - Lin & Lee 的 Snort HTTP 300 bytes 與「只掃開頭」提議
  - P4Pir 的平台（Pi 4 8GB、bmv2）與 92 Mbps；HALIDS 的信心門檻觸發
- **雪球**：五組共列出約 40 筆，先和舊的文獻整理比對，已讀過的不重讀：
  - Shunting、Time Machine、Selective Discarding、HPA、DPA、Kučera
  - Wang & Chang、Suricata bypass、Gonzalez & Paxson 2006
  
  沒讀過的處理如下：
  - **全文**：P4Pir（IoT-J 2023，Pi 上的 P4 閘道）、HALIDS（TMA 2024）→ `fulltext/G6`。
  - **只看摘要**（`snowball/round2*_openalex.json`）：
    - DSN 2024 kernel eBPF NN IPS、Parola CCR 2023
    - Shah & Issac FGCS 2017、Sheeraz IEEE Access 2024
    - RPiDS 2016、Passban IoT-J 2020
    - Meng IEEE Access 2017、Lin et al. Commun. Mag. 2012
  - **只看到標題**：iGuard CoNEXT 2024、Lee et al. RAID 2002、Hu et al. JISA 2020（OpenAlex 沒有摘要）。

### 1.5 已知的漏洞
- **系統類會議收錄差。** WoS 不收或少收 USENIX Security、NDSS、CoNEXT、IMC。這些會議的論文只能靠之前的 WebSearch 整理和雪球補。
- **新論文。** 2026 年下半年的論文可能還沒被索引。
- **不是「找遍了」。** 引用網只追了第一層（被選中論文的參考文獻），沒有系統性地往下追「誰引用了它們」。只有 FPA、HPA、DPA 三篇做了被引追蹤。
- **非論文文獻。** Suricata 文件、廠商白皮書、專利不在資料庫裡。它們之前已整理在 `../trust-bypass/mechanisms.md`。

## 2. 各貢獻的判定與建議措辭

### C1 放行後的稽核與撤銷 — 可宣稱，風險最低
- **找到的最接近做法**，各缺一塊：
  - 抽 flow 送外部 IDS，但目的是校正 ML 模型，不撤銷個別 flow 的信任（GLOBECOM 2025）。
  - 抽樣後把判定傳給同 flow，但沒有信任或放行的概念（ISNCC 2025）。
  - 記錄被 rate limiter 丟掉的封包（Valgenti AINA 2014 的 audit trail）。
  - 白名單由管理員手動更新（Meng 2018）。
  - Shunting 有 sample 欄位但沒用；Time Machine 只提議。
- **理論面已有、不能宣稱的**：抽樣要隨機、不可預測才不會被規避。出處有 Goldberg & Rexford 2007、Kodialam & Lakshman 2003、Otrok 2008，Valgenti 的 RED 式隨機轉送也是。
- **可宣稱**：在 inline 有狀態 IDS 上，對已信任、已跳過檢查的 flow 做放行後稽核與撤銷，並量化「放行後才攻擊」的漏報。另一個可宣稱的發現：同一個 session 中途重新送給有狀態 IDS 會失效，稽核要等 IDS 的 flow 逾時。
- **建議措辭**：「To the best of our knowledge, prior bypass mechanisms either never re-inspect bypassed flows or re-sample traffic only to recalibrate a classifier; none revokes per-flow trust or quantifies post-bypass attacks.」

### C2 inline 的部分檢查 — 可宣稱，但只能是「應用與特性分析」，不是新機制
- **已有、不能宣稱的**：
  - 只檢查 flow 開頭：Time Machine、Selective Discarding、Kučera、Lin & Lee 2013 的提議、Lin et al. 2012 (N,M,P)、Snort／Bro 的預設深度。
  - 依訊息或對話邊界轉前 N bytes：HPA 2017、DPA 2011。
  - 「攻擊集中在開頭」的統計：Valgenti Table I 指出 98% 有告警的 flow 在前 5 個封包內出現告警。
- **沒找到的（可宣稱）**：
  1. 把部分封包直接餵給 **inline 有狀態 IDS**，並分析它能不能接受。HPA 轉的是重建的新封包、不帶 TCP 旗標，是被動模式。Wang & Chang 則顯示無狀態的前置過濾做不到有狀態規則。
  2. **填充規避**的評估：HPA／DPA 論文都沒討論；Lin & Lee 提議的「只掃前 N bytes」正好被我們量到 0%。
  3. 在 ARM 上做。
- **建議措辭**：「We adapt message-boundary payload aggregation (HPA [Erlacher 2017]) to an inline stateful IPS…」。不要把 HPA 寫成自己的方法。

### C3 同機 rule IDS＋ML 的資源分配 — 可宣稱量測結果，不能宣稱「首先提出依負載調整」
- **已有的**：
  - 同一台 Pi 4 跑 Suricata＋RF，但沒量干擾；作者自己把 overload control（sampling、batch、offload）列為未實作（SOHO IBDAP 2026，IV-D）。
  - 推測 Pi 4 的記憶體頻寬是瓶頸，但沒有實驗，且競爭發生在 ML 和 ML 之間（Scheduling to the Rescue）。
  - ARM 上 Suricata 和另一個程式分核心，但目的是省電（MCSoC 2016）。
  - 依負載調整 IDS 本身的工作量，沒有 ML：Dreger CCS 2004 依 CPU 使用率切換 filter 等級；Barlet-Ros ATC 2007 預測 CPU 後算抽樣率；Lee RAID 2002 只看到標題。前兩篇見舊整理 `../edge-colocation/E-allocation.md`。
  - **干擾現象本身在一般系統文獻已知**（舊整理 E-allocation §0 第 4 點）：
    - Caladan 的 Linux 基準顯示，SCHED_IDLE 擋不住記憶體頻寬干擾，tail latency 最高變 235×。
    - RT-Gang 在 Pi 3 上讓 DNN 和吃記憶體的任務分核心共跑，DNN 慢 10.33×。
  - 有一篇宣稱「沒有資源爭用」卻沒有量測（PeerJ 2026），可當反駁對象。
- **可宣稱**：
  - 在 Pi 4 上，量化 **IDS 封包路徑**（Suricata NFQ）和 ML 之間的干擾：跨核心的記憶體頻寬干擾讓每封包成本變 2 倍、丟包 32%；6 MiB MLP 貴 15–17%。
  - 對封包處理而言，SCHED_IDLE 無效、依比例 duty-cycle 有效。
  - 舊整理找到的空缺「沒有人把 IDS 稽核量和 ML 推論量放進同一個預算」（E-allocation §0 第 8 點），這次仍沒找到前例。
- **不能宣稱**：
  - 「跨核心記憶體頻寬干擾」或「SCHED_IDLE 無效」是新發現。這些是已知現象，我們是在 IDS gateway 上量出它的大小。
  - 「首先提出依負載調整」。
- **建議措辭**：主張「第一個在 IDS gateway 上量化」，不主張「第一個提出」。引用 SOHO 論文的 IV-D，說明已有人點出這個需求，但沒有實作、也沒有量測；引用 Caladan、RT-Gang 作為現象的來源。

### C4 kernel 的 IDS fast path — 機制不能宣稱，只能宣稱 ARM 上的量測與比較
- **已有的**：
  - Suricata 本身：NFQ bypass mark、af-packet 的 eBPF／XDP bypass（Leblond & Manev 2019）。
  - Shunting（CCS 2007）。
  - DS-nDPI（CNSM 2017）：tc eBPF 表讓已分類的 flow 跳過 user space，idle 時移除。
  - Wang & Chang（JNCA 2022）：XDP 過濾、只把可能命中的封包送 user space。
  - iKern（2024）：靜態白名單。
  - Galette（2023）：Pi 3B 上的 XDP fast path＋AF_XDP slow path，但沒有偵測功能。
- **可宣稱**：
  - Pi 4 上 inline Suricata NFQ 的每封包成本拆解：檢查 55–61 µs 對放行 14 µs。
  - 四種 kernel 機制（conntrack mark、flowtable、tc eBPF、XDP）的比較。
  - 可撤銷的 flow 信任，接到 C1。Suricata 的 bypass 不能撤銷。
- 舊整理的缺口 G5（「規則式 IDS 的 cutoff／bypass 證據全在 x86／FPGA」）這次仍然成立。
  - 全文讀過的 kernel fast path 論文都是 x86。
  - Pi 上的只有兩篇：Galette 沒有偵測功能；P4Pir 是 user space 的 bmv2，每個封包都分類，沒有 fast path。

## 3. 最接近的研究與差異

深度欄：
- 「全文」＝本次 subagent 讀完全文並經主 agent 抽查。
- 「舊全文」＝之前已精讀，見括號內路徑。
- 「摘要」＝只讀了摘要。

| Cx | 論文 | 撞到哪一點 | 缺了什麼 | 怎麼引用 | 深度 |
|---|---|---|---|---|---|
| C1 | In-Network Attack Detection, Disaggregated Inference & Online Learning（GLOBECOM 2025） | 隨機抽約 5% flow 送外部 IDS | 稽核的是模型、不撤銷 flow；外部 IDS 是標籤模擬；P4 交換器 | 比較對象 | 全文 G2 |
| C1 | Packet Sampling between Kernel and User Space for NIDS（ISNCC 2025） | 抽樣＋把判定傳給同 flow；XDP | 沒有信任、放行、撤銷；x86；吞吐是推算 | 比較對象 | 全文 G1 |
| C1 | Protecting Run-Time Filters for NIDS（Valgenti, AINA 2014） | audit trail、隨機轉送 | audit 是記錄被丟的封包；Perl 模擬、100 µs 是假設 | 背景（用詞要區分） | 全文 G1 |
| C1 | IDS in the Era of IoT（Meng, IEEE Computer 2018） | 白名單＋抽樣 | 白名單靠管理員、不稽核；trust 是節點信譽 | 背景 | 全文 G1 |
| C1 | Sampling security（Goldberg & Rexford 2007）、Kodialam 2003、Otrok 2008 | 抽樣要隨機才不被規避 | 純理論；沒有 IDS 實作 | 稽核隨機化的依據 | 全文 G1、G5 |
| C1／C4 | Shunting（CCS 2007） | IDS 決定 flow 是否繼續檢查 | 有 sample 欄位但沒用；FPGA | 前例 | 舊全文（`trust-bypass/papers/shunting.md`） |
| C1 | HALIDS（TMA 2024） | 本地信心不足的封包交給 oracle 複核 | 信心門檻觸發，不是抽樣；高信心但判錯的 benign 不會被複核；沒有 flow 信任；沒有資源量測 | 背景（同脈絡） | 全文 G6 |
| C1／C3 | P4Pir（IoT-J vol.11, 2024；2023 線上） | Pi 4 上的 IoT gateway，ML 推論和轉送同機，模型不中斷更新 | bmv2 user space 軟體交換器、每個封包都分類；沒有規則式 IDS、沒有跳過、沒有撤銷；沒量記憶體干擾 | 平台背景 | 全文 G6 |
| C2 | HPA（Erlacher & Dressler, LCN 2017） | 每個 HTTP 訊息轉前 N bytes | 轉重建封包、被動、x86；沒討論規避 | 方法出處 | 舊全文（`fastpath-methods/C-partial-inspection.md` B1） |
| C2 | DPA（Limmer & Dressler, INFOCOM WS 2011） | 每次方向改變轉前 N bytes | 同上；我們量到會被填充繞過 | 方法出處、反例 | 舊全文（同上 B2） |
| C2 | Re-examining the Bottleneck in a NIDS（Lin & Lee, JNCA 2013） | 提議負載高時只掃連線開頭；Snort HTTP 預設 300 B | 只提議沒實作；位元組深度不是訊息邊界；離線 x86 | 反例（填充 0%） | 全文 G5 |
| C2 | Time Machine（2005／2008）、Selective Discarding（2010）、Kučera（2018）、Lin et al.（2012） | 只看 flow 開頭 | 非 inline 或沒有量放行後攻擊 | 背景 | 舊全文；Lin 2012 為摘要 |
| C2 | SparseIDS（CNS 2020） | first-m 封包分類 | ML 標頭特徵、離線；假設 flow 全攻擊或全正常 | 背景 | 全文 G1 |
| C3 | Real-Time NIDS for SOHO, Hybrid Edge ML（IBDAP 2026） | 同一台 Pi 4 跑 Suricata＋RF | 沒有基準、丟包、干擾量測；overload control 是 future work | 最接近的比較對象 | 全文 G3 |
| C3 | Scheduling to the Rescue（EuroSec 2023） | Pi 4 記憶體頻寬是瓶頸 | 推測沒實驗；ML 和 ML 之間；pcap 餵入 | 比較對象 | 全文 G4 |
| C3 | 2-Step Power Scheduling for NIDS on Multicores（MCSoC 2016） | ARM 上 Suricata 和另一程式分核心 | 目標省電；沒有 ML；沒量干擾 | 背景 | 全文 G4 |
| C3 | Caladan（OSDI 2020）、RT-Gang（Pi 3） | 記憶體頻寬干擾跨核心；SCHED_IDLE 擋不住 | 不是 IDS 或封包路徑；RT-Gang 是 Pi 3 | 現象來源 | 舊全文（`edge-colocation/E-allocation.md`） |
| C3 | Dreger（CCS 2004）、Barlet-Ros（ATC 2007） | 依負載調整 IDS／監控的工作量 | 沒有 ML；準確度沒量偵測率 | 調整方法的前例 | 舊全文（同上） |
| C3 | SnortML IPS on Pi（ICIMCIS 2025）、Blockchain hybrid IDS（PeerJ 2026）、Think Fast（IoT-J 2026） | Pi 上 rule IDS＋ML | 沒量干擾；PeerJ 宣稱無爭用但沒量；Think Fast 的 LLM 在雲端 | 背景、反駁對象 | 全文 G3、G4 |
| C4 | Hybrid Kernel-User VNF / DS-nDPI（CNSM 2017） | tc eBPF 表讓已分類 flow 跳過 user space | DPI 分類不是 IPS；被動 clone；x86 VM；沒有每封包成本 | 機制前例 | 全文 G2 |
| C4 | eBPF IDS（Wang & Chang, JNCA 2022） | XDP 過濾讓大部分封包不進 user space | 以封包為單位、無 flow 狀態；mirror 被動；x86 | 機制前例 | 全文 G5；舊全文（`framework/papers/wang-chang.md`） |
| C4 | iKern（Technologies 2024） | eBPF 白名單直接轉送 | 人工靜態白名單；x86；品質疑慮 | 背景 | 全文 G2 |
| C4 | Suricata NFQ bypass／XDP bypass | 同一件事的現成實作 | 不能撤銷；bypass mark 只在單一封包 | 必須說明差異 | 舊整理（`trust-bypass/mechanisms.md`） |
| C4 | Galette（IFIP Networking 2023） | Pi 上的 XDP fast path＋AF_XDP slow path | 只有 Macswap、沒有偵測；Pi 3B | 平台前例 | 舊全文（`paper.md` #5） |
| C4 | NN IPS in kernel using eBPF（DSN 2024） | kernel 內 IPS | x86 雲端；沒有 bypass user space IDS | 背景 | 摘要 |

## 4. 可比的 ARM／Pi 數字（都不能直接比）

| 來源 | 數字 | 為什麼不能直接比 |
|---|---|---|
| MCSoC 2016（ARM A15 2 GHz、Suricata 2.0.8） | 1 核心滿載約 200–240 µs／封包；4 核心在 17 kpps 下處理 15.4–16.2 kpps | 每封包成本是 subagent 從 Fig. 3b 推算的，論文沒報；規則集未說明 |
| SOHO IBDAP 2026（Pi 4、Suricata＋RF） | 82 Mbps、CPU 62%、特徵到分類 145 ms | 封包大小與 CPU 分母沒寫；可能是旁路 |
| Scheduling to the Rescue（Pi 4） | 記憶體頻寬約 4.4 GB/s | datasheet 值，不是實測 |
| SnortML on Pi（ICIMCIS 2025） | 只有 4–65 Kbps 下的 CPU／RAM 平均 | Snort 沒載規則 |
| P4Pir（Pi 4 8GB、bmv2） | 純轉送約 92 Mbps；加 DT／RF 後約 55–80 Mbps（讀圖）；CPU 約 37% → 50–62%（讀圖）；同機跑 Passban 時 CPU >70% | 沒有封包大小與 pps；CPU 用 /proc/stat 量，和我們的 schedstat 不能並列 |
| RPiDS 2016、Wiranata 2023 | Pi 上 Snort 的吞吐；SYN flood 丟 41.48%（Wiranata，數字轉引自 SnortML 論文） | 只讀到摘要或轉引；Pi 型號與條件未確認 |

## 5. 還沒做的

- **系統類會議**：補查 USENIX Security、NDSS、CoNEXT、IMC 近 5 年。方法是看 DBLP 的會議目錄、用標題關鍵字篩。iGuard（CoNEXT 2024）就是從 WoS q8 看到標題、還沒讀的例子。
- **被引追蹤**：從最接近的幾篇往下追「誰引用了它們」。
  - 已做：FPA、HPA、DPA。
  - 還沒做：DS-nDPI、Wang & Chang、GLOBECOM 2025、SOHO 2026、Shunting。
- **只看過摘要或標題、可能要讀全文的**：
  - DSN 2024、Lee RAID 2002、Gonzalez & Paxson RAID 2006（舊整理只部分讀過）。
  - G6 的雪球：
    - CML-IDS（CNSM 2023）：HALIDS 說它最相近，要確認有沒有複核已放行的封包。
    - Building an Internet Router with P4Pi（ANCS 2022）：可能有 Pi 4 的轉送基準。

## 6. 檔案

- `SCREEN.md`：C1–C4 定義與篩選標準
- `wos/`、`ieee/`、`acm/`：搜尋紀錄與匯出
- `screen_*`：篩選輸入與結果
- `shortlist.tsv`：全文候選
- `fulltext/G1`–`G6`：逐篇全文報告
  - G1 抽樣與信任
  - G2 kernel fast path
  - G3、G4 edge IDS＋ML
  - G5 Elsevier 三篇
  - G6 雪球 in-network
- `snowball/`：第二輪雪球的查詢與 OpenAlex 摘要
- `pdfs/`：全文 PDF 與轉出的文字檔（含付費論文，已在 `.gitignore`，只在本機）
- `openalex_search.py`：OpenAlex 搜尋腳本；它的快取 `search/cache/` 只在本機、沒有 commit（額度用完，沒進入篩選）
- 論文總表 `../paper.md` 的 #45–#64 就是這 20 篇
