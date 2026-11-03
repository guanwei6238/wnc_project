# G6 全文精讀：雪球第二輪（in-network ML，2 篇）

判斷基準：`SCREEN.md` 的 C1–C4。兩篇文字檔都從頭讀到尾（含參考文獻），P4Pir 的 Fig. 10–16、Table III–IV 與 HALIDS 的 Fig. 1–4 另外用 PDF 頁面核對。
凡論文沒寫的寫「論文未說明」。從圖上讀出來的數字標「讀圖」，誤差約 ±5。頁碼是論文印出來的頁碼（P4Pir 的 PDF 第 1 頁是 DTU 封面，論文頁碼 = PDF 頁碼 − 1；HALIDS 同理）。
「雪球」一節的文獻只讀了這兩篇的引用條目與引用處上下文，沒有讀那些文獻的全文。

這兩篇都被第一輪的 GLOBECOM 2025（lit_ieee_11432439，以下簡稱 GLOBECOM）引用：P4Pir 是它的 [7]，HALIDS 是它的 [9]。三篇是同一條 P4 in-network ML 的脈絡（P4Pir 2023/24 → HALIDS 2024 → GLOBECOM 2025）。

---

## 1. P4Pir — Toward Continuous Threat Defense: In-Network Traffic Analysis for IoT Gateways

**書目**：Mingyuan Zang（DTU）、Changgang Zheng（Oxford）、Lars Dittmann（DTU）、Noa Zilberman（Oxford）。IEEE Internet of Things Journal, vol. 11, no. 6, pp. 9244–9257, 2024（DTU Orbit 封面的引用格式）。DOI 10.1109/JIOT.2023.3323771。作者以論文首頁為準，四位與推定相同。檔案是 accepted manuscript，頁眉印的 "VOL. 14, NO. 8, OCTOBER 2023" 是排版殘留，引用時用 DTU 封面那組卷期頁碼。

### 他們做了什麼

- **機制**：在 IoT gateway 的 programmable data plane 上，把 Decision Tree／Random Forest 用 Planter 的 encode-based 方法編成 match-action table，每個封包抽 header 欄位當特徵，查表得到 0（benign）或 1（malicious）；malicious 直接 drop、benign 轉送（Sec. IV-B p.4、Sec. VI-B p.6）。
- **特徵**：全是單一封包的 header 欄位（IP、port、TCP flags、seq/ack、length，加 MQTT／DNS／Modbus 的欄位；Table II p.5）。沒有 flow 狀態、沒有 payload 內容比對。
- **持續學習**：data plane 把每個封包抽到的特徵用 P4Runtime digest 同步送到 control plane（Sec. VII-A p.6），control plane 用 Isolation Forest（iForest）無監督自動標籤（Sec. VII-B p.7），再用 scikit-learn 重訓、用 Planter 轉成新的 table rules。標籤是無監督的，不是外部 IDS 給的。
- **不中斷更新**：shadow table。新 rules 先寫進影子 table，再改一個 UpdateFlag entry 一次切換（Sec. VIII p.7–8、Fig. 9）。對照組 ClearAll（清掉全部再寫）與 Selective（只重寫模型相關 rules）。
- **平台**：P4Pi（Raspberry Pi 4 Model B、8 GB RAM、P4Pi v0.0.3），data plane 是 **bmv2（v1model）**，也就是 user space 的軟體 switch（Sec. IX-A p.8）。另宣稱在 Dell EMC Edge Gateway 5200 上用 Docker 做過原型，但評估章節沒有任何 Dell 的數字（論文未說明 Dell 的結果）。client 是另一台 RPi，server 是 Xeon W-2133 桌機。
- **IDS 類型**：只有 ML（DT／RF）。沒有規則式 IDS（沒有 Snort／Suricata）。比較對象 KitNet（Kitsune）與 Passban IDS 也是 ML。
- **inline**：是，data plane 直接 drop。
- **量測**：資料集 CIC-IDS2017、EDGE-IIoTset、YTY2018（Kitsune）。用 tcpreplay 重播；吞吐、jitter、drop rate 用 iperf2；CPU 用 `cat /proc/stat`，溫度用 vcgencmd（Sec. IX-C p.9）。
- **情境**：模型第一天只學過一種攻擊，之後換成另一種「新攻擊」，比較不更新（Base）與 P4Pir 更新後的準確度（Table III、IV p.9）。這是 model drift，不是「已放行的 flow 後來才攻擊」。

### 主要數字

- 偵測：DT 在 SCAN→DoS 的 ACC 0.604→0.932，在 SYN→SCAN 的 ACC 0.156→0.945（Table III、IV p.9）；摘要稱準確度提升 >30%。
- 更新：5 分鐘一次已足夠（約 99%；Fig. 11 p.10）。ClearAll 造成約 5 秒的 drop rate 尖峰與約 2 ms 的 jitter 尖峰，shadow update 沒有（Fig. 13 p.11、Sec. IX-F p.10）。
- 吞吐／CPU：見下方「可拿來比的數字」。

### 對 C1–C4

| 貢獻 | 標記 | 證據與理由 |
|---|---|---|
| C1 | related（弱） | Sec. VII-A/B（p.6–7）與 Sec. VIII（p.7–8）：特徵同步送 control plane、iForest 自標、重訓、shadow 換模型。這是**模型層級**的回饋迴路。缺：沒有「flow 被判可信、之後不再檢查」的狀態；每個封包都過模型，沒有跳過；沒有抽樣；沒有撤銷個別 flow；沒有量「放行後才攻擊」。Sec. VII-B（p.7）明寫 "actual in-network mitigation is conducted by the supervised DT/RF model"，iForest 只拿來產訓練標籤。若要嚴格，可降成 none。 |
| C2 | none | Sec. V、Table II（p.5）只用 header 欄位，無 payload、無有狀態 IDS、無「只送開頭」。 |
| C3 | related（弱） | Sec. IX-F（p.11）在 Pi 4 上量「ML 推論放進轉送路徑」對吞吐、jitter、CPU 的代價，並與 Passban 比 CPU。缺：沒有規則式 IDS；ML 與轉送是同一個 bmv2 data plane 裡的 table lookup，不是兩個互相搶資源的工作負載；沒量記憶體頻寬、快取；沒有依負載調整 ML 工作量或核心分配（模型大小是事先挑好的，只談 accuracy／overhead 的取捨，Sec. XI）。 |
| C4 | none | bmv2 是 user space 的軟體 switch（Sec. IX-A p.8），每個封包都做分類，沒有信任／bypass，沒有 conntrack／tc／XDP／flowtable。論文把吞吐下降歸因於 "limited processing capability of bmv2 running on RPi"（Sec. IX-F p.11）。 |

### 和第一輪 GLOBECOM 的差異（重點）

- **有沒有「對已判 benign 的 flow 之後再檢查、判錯就改判／撤銷」**：沒有。P4Pir 沒有 flow 層級的信任狀態；每個封包獨立用 header 特徵分類，benign 封包放行、malicious 封包 drop（Sec. IV-B p.4）。所謂「之後改判」只是模型更新後，新模型對**之後的封包**給出不同結果，不是把已放行的 flow 拉回來重驗。
- GLOBECOM 的 5% 抽樣是「抽 flow 送外部 IDS，用外部 IDS 的標籤評估並重訓 in-network 模型」。P4Pir 則是**每個封包**都送特徵到 control plane（GLOBECOM 自己也這樣描述 [7]：「forward the features of each packet」），標籤來自無監督 iForest，沒有外部 IDS 當「真值」。所以 P4Pir 比 GLOBECOM 更遠離 C1，GLOBECOM 說 5% 就夠（Table I），正是對 P4Pir 全量回報的改進。
- 兩者都稽核「模型」，不稽核「被信任的 flow」，都沒有撤銷個別 flow 的信任。

### 特別檢查（使用者列的問題）

- **P4 data plane 在 Pi 上的實作**：bmv2 v1model，在 P4Pi（以 Raspberry Pi 為基礎、提供 data plane 可程式化的平台）上跑；`P4Pi [54]`、`Building an internet router with P4Pi [55]` 是平台參考。不是 eBPF／XDP，也不是硬體 offload。
- **轉送效能**：baseline 純轉送約 92 Mbps（Sec. IX-F p.11）。封包大小、pps、NIC 速率、單向或雙向：論文未說明；92 Mbps 是 bmv2 的上限還是鏈路上限，論文也沒有區分。
- **ML 推論與轉送是否同機**：是。推論就是 bmv2 pipeline 裡的 table lookup，「與 packet switching 同時進行」（Sec. I p.1）。但 control plane 的 iForest 標籤、scikit-learn 重訓、Planter 轉換跑在哪（Pi 上或另一台）：論文未說明；Fig. 15 的 CPU 數字是穩態轉送時量的，是否包含重訓期間：論文未說明。
- **CPU／記憶體干擾**：CPU 有量（/proc/stat、Fig. 15d），記憶體頻寬、快取、記憶體用量都沒有量（全文無相關量測）。沒有「單獨跑 vs 同時跑」的干擾比較，只有「有／無 P4Pir」的整體 CPU 增量。
- **模型更新怎麼不中斷流量**：shadow table + UpdateFlag 一次切換（Sec. VIII）。這只解決 table rules 的原子切換，與 Suricata 規則或 ML 行程的更新無關。
- **有沒有規則式 IDS**：沒有。
- **"sub-millisecond mitigation time"**：摘要與 Sec. IX-E（p.10）都這樣寫，但 Fig. 12a 的時間軸是秒、y 軸是每秒封包數；量測方法、每封包推論延遲：論文未說明。不建議直接當作可比的延遲數字。

### 可拿來比的數字

| 項目 | 數字 | 出處與量測條件 |
|---|---|---|
| 純轉送吞吐（bmv2，無 ML） | 約 92 Mbps | Sec. IX-F p.11、Fig. 15a。Pi 4 B 8 GB、P4Pi v0.0.3、iperf2（TCP／UDP）、client 為另一台 RPi。封包大小、pps、NIC 速率論文未說明 |
| 加上 ML 後吞吐（DT／RF，5／10／15 個特徵） | DT 約 80／78／74 Mbps；RF 約 73／63／55 Mbps（讀圖） | Fig. 15a。文字只確認「DT 5 特徵降 14%」 |
| 與 Passban IDS 比 | P4Pir 降約 14%，Passban 降約 17%；Passban CPU >70%（吞吐 >70 Mbps 時），P4Pir 約 60% | Sec. X p.12。兩者都跑在 Pi 上 |
| CPU 使用率 | baseline 約 37%；加 DT／RF 後約 50–62%（讀圖）；文字說「約 +21%」，是百分點還是相對值論文未說明 | Fig. 15d、Sec. IX-F p.11。量測用 /proc/stat，是整機或單核論文未說明 |
| CPU 溫度 | 約 +10% | Fig. 15c、Sec. IX-F |
| jitter | baseline 約 0.037 ms，加 ML 後增加 <0.05 ms | Fig. 15b、Sec. IX-F |
| 模型更新衝擊 | ClearAll：drop rate 尖峰約 5 秒、jitter 尖峰約 2 ms；shadow：無 | Fig. 13、Sec. IX-F p.10 |
| Fig. 12b 吞吐 | 約 77 Mbps（baseline 與 P4Pir 同） | Fig. 12b p.10。與 92 Mbps 的差異論文未說明 |

沒有每封包成本（µs）、沒有 pps、沒有記憶體數字、沒有單一封包推論延遲。方法學提醒：它用 /proc/stat 量 CPU，我們已知這在 10 kpps 級以上取樣對齊會失真，不要直接拿它的 CPU 百分比和我們的 schedstat 數字並列。

### 我們論文怎麼引用

可引為「已有人在 Raspberry Pi 4 gateway 上用 bmv2 軟體 data plane 做 in-network ML 推論並以 shadow table 不中斷更新模型，但它逐封包用 header 特徵分類、沒有規則式 IDS、沒有 flow 信任與放行後稽核，也沒有量同機工作負載的干擾」，並可用其 92 Mbps 的 bmv2 baseline 說明 user space 軟體轉送路徑在 Pi 4 上本身就是瓶頸。

### 雪球

沒有哪篇看起來比 P4Pir 本身更接近 C1、C2、C4。下列依用途排序（理由都只來自 P4Pir 的引用處與標題，未讀全文）：

1. Stoyanov, Wolnikowski, Soulé, Laki, Zilberman, "Building an internet router with P4Pi," ANCS 2022（ref [55]）。理由：同一個 P4Pi 平台的轉送效能報告，可能有 Pi 4 上的路由吞吐數字，可當 C4 的 Pi 轉送 baseline。P4Pir 只引用為平台說明。
2. Eskandari, Janjua, Vecchio, Antonelli, "Passban IDS: An Intelligent Anomaly-Based Intrusion Detection System for IoT Edge Devices," IEEE IoT J 7(8), 2020（ref [30]）。理由：P4Pir 在 Pi 上實際跑它並量吞吐與 CPU（Sec. X），是 C3 的「Pi 級 edge IDS 資源使用」先例。G3 已列為雪球候選，這裡是第二個引用它的來源。
3. Lima, Lima, Lins, Bonfim, "Beholder – a CEP-based intrusion detection and prevention systems for IoT environments," Computers & Security 120, 2022（ref [17]）與 Kim, Nam, Park, Scott-Hayward, Shin, "SODA: A software-defined security framework for IoT environments," Computer Networks 163, 2019（ref [18]）。理由：P4Pir 只把它們當作「傳統 gateway 流量分析，有誤報與彈性不足」引用（Sec. II-A p.2），內容論文未說明；從標題看是 IoT 的 IDS／IPS 框架，是否有 bypass 或部分檢查需讀全文。優先度低。
4. Hafeez, Antikainen, Ding, Tarkoma, "IoT-Keeper: Detecting malicious IoT network activity using online traffic analysis at the edge," IEEE TNSM 17(1), 2020（ref [34]）。理由：P4Pir 描述為在 SDN gateway 用 OpenFlow 收流量統計做分析（Sec. III p.3）；是 gateway 上 flow 層級分析的先例，但不看 bypass／稽核，優先度低。

---

## 2. HALIDS — A Hardware-Assisted Machine Learning IDS for in-Network Monitoring

**書目**：Belén Brandino（UdelaR／AIT）、Eduardo Grampin（UdelaR）、Katharina Dietz、Nikolas Wehner、Tobias Hoßfeld（Würzburg）、Michael Seufert（Augsburg）、Pedro Casas（AIT）。2024 8th Network Traffic Measurement and Analysis Conference (TMA), Dresden, May 21–24, 2024, pp. 1–4。DOI 10.23919/TMA62044.2024.10559083。3 頁正文加 1 頁參考文獻的短文，結果標明是 preliminary。

### 他們做了什麼

- **機制**：以 SwitchTree 的 P4 實作為基礎（每個封包用 5-tuple hash 找 flow，算 stateless 與 stateful 特徵，Random Forest 編成 match-action table，逐封包分類），加兩件事：(1) 自動化訓練；(2) **oracle**：一個在 off-band server 上、用全部資料訓練、更大的 RF（Sec. III p.2）。
- **信心門檻分流**（Fig. 3 p.3）：switch 上的 student 模型給出類別與機率；若 flow 已被標成 attack 就直接 drop；否則若最大機率 ≥ DCT（Decision Confidence Threshold）就照 student 的判定放行／丟棄；若低於 DCT，把該封包的特徵 Xi 送給 oracle，拿回 Coracle，benign 放行、attack 丟棄。
- **Active learning 回饋**：oracle 存下它做過的分類與特徵，累積到一定查詢數後用這些標籤重訓 student，經 P4Runtime 重寫 switch 的 table（Sec. III p.3）。
- **平台**：BMv2 的 SimpleSwitchGrpc，用虛擬網卡，tcpreplay 注入（Sec. IV p.3）。不是 ARM、不是真實硬體（標題的 "hardware-assisted" 在評估中沒有硬體）。
- **IDS 類型**：只有 ML（student DT／oracle RF）。沒有規則式 IDS。oracle 也是 RF，不是 Suricata 之類。
- **inline**：是（switch 上放行／丟棄），但 oracle 回應前封包怎麼處理（暫存、等待）與延遲：論文未說明。
- **量測**：UNSW-NB15 訓練，測試只用同資料集的 1000 個封包的小 trace（Sec. IV p.3）。student 是 depth 5、只用 50% 訓練資料；oracle 是 100 棵、depth 15。DCT 取 80／90／95%。沒有吞吐、延遲、CPU、記憶體、送到 oracle 的封包比例。

### 主要數字

- Fig. 4（p.3）偵測表現相對 baseline（student 與 oracle 用同一個全資料 DT）：DCT 80% 全部在 switch 判，掉到約 72%（文字：掉近 30%）；DCT 90% 約 110%（文字：高約 10%）；DCT 95% 約 115%（讀圖；文字寫 "almost 20%"，圖與文字略有出入）。測試只有 1000 個封包，論文自己說「偵測幾乎完美」所以改看 packet 層級的 recall。

### 對 C1–C4

| 貢獻 | 標記 | 證據與理由 |
|---|---|---|
| C1 | related（弱） | Fig. 3（p.3）：每個封包都重新過 student，若 flow 之後才被判成 malware，後續封包會被標成 attack（Sec. III p.2："if it is eventually detected as malware, the remaining packets ... are marked"）。這是逐封包重判，不是「信任後跳過再稽核」。oracle 只在 student 信心不足時被問，高信心的 benign 判定**從不被 oracle 複核**；oracle 標籤只用來重訓 student。缺：沒有 flow 信任狀態、沒有跳過、沒有抽樣稽核、沒有撤銷、沒有量放行後才攻擊。比 GLOBECOM 更遠（連抽樣都沒有）。若要嚴格，可降成 none。 |
| C2 | none | Fig. 3：送 oracle 的是單一封包的特徵向量 Xi，由信心觸發，不是每段對話的開頭；oracle 是 RF，不是有狀態 IDS；非 ARM、無中途接手分析。 |
| C3 | none | 沒有任何資源量測；BMv2 在虛擬網卡上；oracle 在另一台 server。 |
| C4 | none | 無 kernel fast path；BMv2；每個封包都分類。 |

### 和第一輪 GLOBECOM 的差異（重點）

- GLOBECOM 的說法是 HALIDS 在 in-network 推論信心不夠時把特徵送外部 IDS，並用回傳的標籤做 online learning（GLOBECOM Sec. II）。這與 HALIDS 全文一致。
- 觸發條件不同：HALIDS 是**信心門檻**（只送 student 沒把握的封包），GLOBECOM 是**隨機抽 flow**（約 5%，與信心無關）。因此 HALIDS 只覆蓋「模型自己覺得不確定」的流量；student 高信心但判錯的 benign（例如我們關心的「先正常、後攻擊」）不會被拉出來複核。GLOBECOM 的隨機抽樣至少會碰到一些高信心的 flow，所以比 HALIDS 更接近稽核，但稽核對象仍是模型。
- 沒有「對已判 benign 的 flow 之後再檢查、判錯就改判／撤銷」。唯一像的是 Sec. III 的「flow 之後被判 malware，剩下封包標 attack」，但那是每個封包都被 student 檢查的副作用（沒有任何封包被跳過），不是撤銷信任，也沒有成本節省或漏報量化。

### 可拿來比的數字

無。論文沒有轉送吞吐、每封包成本、推論延遲、CPU 或記憶體，也沒有被送到 oracle 的封包比例（論文未說明）。唯一的量化結果是 Fig. 4 的相對偵測表現（見上），資料只有 1000 個封包。

### 我們論文怎麼引用

可引為「confidence-based deferral 的 P4 先例：switch 內小模型對低信心封包上送 oracle 並用其標籤重訓 [Brandino et al.]」，與我們「本地判不出才送雲端」的分層同類；但它沒有 flow 信任與放行後稽核，也沒有任何資源量測，不能當 C1–C4 的先例。

### 雪球

1. Golchin, Zhou, Agnihotri, Agnihotri, Hajizadeh, Kundel, Steinmetz, "CML-IDS: Enhancing Intrusion Detection in SDN through Collaborative Machine Learning," CNSM 2023（HALIDS ref [6]）。理由：HALIDS 自己說這是 "the work most similar to ours"：data plane 的 RF，信心不足時送 oracle；它是 HALIDS 的通訊機制來源，沒有 switch 重訓（Sec. II）。若 oracle 流程中有任何對已放行封包的複核，會在這篇出現；需讀全文確認，但從 HALIDS 的描述看不像有。
2. Seufert, Dietz, Wehner, Geissler, Schüler, Wolz, Hotho, Casas, Hoßfeld, Feldmann, "MARINA: Realizing ML-driven Real-time Network Traffic Monitoring at Terabit Scale," IEEE TNSM 2024（ref [7]）。理由：硬體 switch 抽（較複雜的）特徵、送 ML server 做預測，是「本地抽特徵、重分析在外面」的 offload 分工，可能涉及「抽哪些封包／特徵送出」的成本取捨（C2 的概念鄰居）；是 Terabit 級硬體，不是 ARM，優先度低到中。
3. Busse-Grawitz et al., "pForest"（ref [5]）與 Lee & Singh, "SwitchTree"（ref [4]）：「前幾個封包就判 flow、信心夠才下判斷」，G2 已列過 pForest，這裡不重複。

---

## 本組總結

- **沒有任何一篇 overlap。** 兩篇都是 P4（bmv2）軟體 data plane 上的 ML 分類器，沒有規則式 IDS、沒有 conntrack／tc／XDP／flowtable、沒有 Suricata，也都不處理有狀態 IDS 的部分封包問題。
- **C1**：兩篇都標 related（弱），只是為了引用完整；實質上都沒有撞到。P4Pir 的回饋迴路是 data plane 特徵 → iForest 自標 → 重訓 → shadow table，稽核的是模型；HALIDS 的 oracle 只複核 student 沒把握的封包，高信心 benign 不會被複核。兩者都每個封包都過模型，沒有「信任後跳過」，因此根本沒有「放行後才攻擊」的漏報問題可量。與 GLOBECOM 相比，只有 GLOBECOM 有隨機抽 flow 這一點（約 5%），這條脈絡裡也只有它最接近「抽樣稽核」，但它稽核的仍是模型，不撤銷個別 flow 的信任。我們的 C1（flow 層級的信任、稽核窗、撤銷，及長連線「先正常後攻擊」只抽 flow 約抓 10%）在這三篇裡都沒有人做。
- **C2、C4**：none。
- **C3**：P4Pir 標 related（弱）。它是我們看到的平台最接近的一篇（Pi 4、gateway、inline、量吞吐／jitter／CPU、比較 Passban），但 ML 是 bmv2 pipeline 內的 table lookup，不是和規則式 IDS 並存的獨立工作負載；沒有記憶體頻寬／快取量測，也沒有依負載調整 ML。我們的「記憶體頻寬干擾讓 Suricata 每封包成本變 2 倍、依比例 duty-cycle 有效」不受影響。
- **可用的比較數字**只有 P4Pir 的 Pi 4 + bmv2：純轉送約 92 Mbps、加 ML 後約降 14–40%、CPU 由約 37% 升到 50–62%（讀圖）；缺封包大小與 pps，不能換算每封包成本，且它用 /proc/stat 量 CPU。這些適合放在背景說明「user space 軟體轉送在 Pi 4 上本身就慢」，不適合當成與我們 14 µs／55–61 µs 的直接對照。
- **雪球**：沒有發現比這兩篇更接近 C1、C2、C4 的文獻。值得讀的是 CML-IDS（確認 oracle 流程有無任何複核）、P4Pi 路由器那篇（Pi 4 轉送 baseline）、Passban IDS（Pi 上 IDS 資源，與 G3 重複）。要找 C1／C2／C4 的先例，這條 in-network ML 脈絡看來不會有，需從 IPS／Suricata／flow shunting 方向找。
