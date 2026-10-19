# 子題整合：信任式 Fast Path（Trust-based Bypass）——文獻、方案與論文骨架

> 撰寫日期：2026-10-16。
> 依據：
> - 本子題 7 篇精讀報告（`papers/*.md`）
> - 實作機制調查 `mechanisms.md`
> - 開放搜尋清單 `candidates.md`，共 14 篇加 3 篇範圍外
> - 先前已讀的 HorusEye、Alikhanov、Simioni（`../papers/`）
>
> 報告由 Sonnet subagent 撰寫，每篇都讀了全文或標明只讀到摘要。主 agent 只抽查了關鍵數字，對照原文 PDF 的文字檔：
> Shunting Table 2、Selective Discarding p.5–6、MUD+SDN Table 5/8、Mai Table 3/4、Kučera §III–IV、NetBeacon 討論段。抽查的數字全部吻合。
> 其餘數字以各報告的出處標記為準。標 [推測] 的是判斷，不是論文寫的。
> 「搜尋沒找到」只是弱證據。

---

## 0. 先講結論

1. **你的構想站得住，而且有清楚的研究空缺。** 文獻裡和這個構想相關的機制分成三群，彼此幾乎不相交：
   - (a) 判定後放行：Shunting、immUNITY、NetBeacon、MUD+SDN、SciPass、HorusEye
   - (b) 只看 flow 開頭：Time Machine、Selective Discarding、Kučera
   - (c) 信任撤銷與恢復：Chae on-off、NOS-Gate

   **沒有任何一篇同時做到這四件事：放行機制、放行後的抽樣複查、撤銷，以及量測「放行後才攻擊」的漏報。** 多位作者在討論段承認這個盲區，但沒有人量過：Time Machine、Selective Discarding、Kučera、NetBeacon。

2. **要更正我上一輪的說法。** 「攻擊大多在連線開頭」沒有被直接實證：
   - Time Machine、Shunting 都只是斷言或互相引用。
   - 目前最接近的量測是 Kučera 2018：Suricata 每條 flow 只看前 5 個封包，仍偵測到超過 80% 的事件；N>30 時超過 90%。但它量的是告警數比例，不是攻擊位置分布，而且用 x86、非 IoT 流量。
   - Papadogiannakis 2010：cutoff 100 個封包時仍保留 95% 告警。

3. **Shunting 等前例放行的理由是「沒東西可看了」，不是「安全」。** 例如加密已協商、媒體檔、超過 depth。「以安全判定作為放行理由」這一點是我們的新意，也是我們的風險。

4. **在 Pi + nftables + NFQUEUE 上，信任狀態必須由 kernel 的 `ct mark` 持有，不能用 Suricata 的 bypass。** Suricata NFQ bypass 只在單一封包上打 mark，而且無法撤銷（`mechanisms.md` M3、M4）。

5. **「抽樣」要換成「隨機起點的連續稽核窗」。** 逐封包隨機抽樣對 Suricata 的 stream 與 app-layer 規則幾乎無效（`midstream` 預設 false），還會因為 flow 看起來變短而誤判（Mai 2006）。

---

## 1. 文獻地圖

### 1.1 依 T 欄位比較

| 論文 | 放行依據與時點（T1） | 放行後可見性（T2） | 撤銷（T3） | 規避討論（T4） | 效益數字（T5） |
|---|---|---|---|---|---|
| **Shunting** CCS'07 | 分析器沒東西可看（DPD 前 2 KB、HTTP>10 KB 後、SSH 已認證） | 硬體表有 sample 欄位但**沒用**；SYN/FIN/RST 恆送 IPS | forward-N 超限自動回 shunt；IPS 可插 drop | 無 | 放行 54.9–91.1% bytes、43.8–88.0% packets（6 條 trace，Table 2） |
| **Time Machine** IMC'05 / SIGCOMM'08 | 每連線前 N KB（10–20 KB） | 只影響**錄製**，NIDS 仍看全量 | `suspend_cutoff`（兩週 427 次） | §6 承認「cutoff 後攻擊」是根本限制；提議隨機化 cutoff，**未實作** | 15 KB 時存量剩 <6%；91–96% 連線在 10–20 KB 內完整 |
| **Selective Discarding** EuroSec'10 | 負載驅動的全域 cutoff（前 N 封包） | 尾段丟棄 | 新連線重新從頭看 | p.6 承認 persistent HTTP 可先填滿再攻擊；只有定性反論 | cutoff 100：吞吐 3.62 倍、保留 95% 告警；276 注入攻擊全中（但都在開頭） |
| **Kučera** ICCD'18 | 前 N 封包（N 可依負載調） | 丟棄 | 無 | 明說 N 之後的攻擊偵測不到 | N=5 時 >80% 事件、N>30 時 >90%（Suricata + 13,642 ET 規則，真實 pcap） |
| **MUD+SDN** SOSR'19 | 命中廠商宣告的 MUD 規則 | **每規則每分鐘計數** + 單類異常偵測 | 無（只告警） | 核心就是「合規流量裡藏攻擊」；低速攻擊前幾分鐘漏報 | 僅 0.92% 封包被檢測；TPR 89.7%、FPR 5.1%、平均 1.92 分鐘 |
| **IoT Sentinel** ICDCS'17 | 設備 setup 階段指紋 → 三級信任 | 無 | 無 | 假設接入時 benign | 辨識率 0.815 |
| **DÏoT** ICDCS'19 | 無放行（每包都過模型） | 全量 | — | — | 偵測率 95.6%、257 ms（相反的極端） |
| **immUNITY** arXiv'26 | SmartNIC 在第 3 封包判 benign → 交換器白名單 | 不再看 | 只有快取覆寫 | 未討論 | 96 Gbps 中只 0.14 Gbps 進慢路徑；誤放行 FPR 0.0008% |
| **NetBeacon** Sec'23 | flow class table 判定後不再過 ML | 不再看 | 逾時 | 自述 stealth attack，建議「最大 flow 長度上限」，**未量測** | — |
| **HorusEye** Sec'23（已讀） | iForest 白名單 | header 仍鏡射 | 黑名單寫回 | — | 卸載 76%，但上傳 bytes 沒降 |
| **Mai** IMC'06 | （抽樣研究） | — | — | 小 flow、掃描在抽樣下最先消失 | 同 flow 數下 random flow sampling 最好（異常 21 個，N=100：flow 18 / packet 6 / smart 1 / S&H 2） |
| **Grashöfer** arXiv'19 | （攻擊論文） | — | — | **實證**以填充耗盡 IDS 的協定辨識 buffer，規避 Zeek、Snort 3、Suricata 4.1.2 | Bro 預設 buffer 1024 B |
| **Chae** TPDS'15 | （信任管理） | — | redemption 機制 | on-off 攻擊利用信任恢復 | 僅讀摘要 |
| **NOS-Gate** TCE'26 | 無放行 | 持續評分 | **K-of-M 觸發、可逆降權** | 時序控制的規避 | recall 0.952 @ 0.1% FPR（合成資料） |

### 1.2 三群文獻的定位

```
              只看開頭（便宜）                             全程檢查（貴）
  IoT Sentinel ── Shunting / Kučera / TM ──── [我們] ──── MUD+SDN ──── DÏoT / NOS-Gate
  一次性設備信任   cutoff 後完全不看          信任 + 稽核窗   計數式監看     每包都看
                                              + 撤銷 + 上雲
```

[推測] 論文的 related work 可以照這條軸線寫，我們的定位就是「在兩端之間，用可撤銷的信任換成本」。

---

## 2. 四個核心問題的證據

### Q1. 只看 flow 開頭就決定，有沒有依據？
- **成本面有強證據：**
  - Time Machine：heavy-tail 分佈，>20 KB 的連線只占 12–15%，卻含 87–99.86% 的 bytes。
  - Shunting：最多放行 91% bytes。
  - Kučera：前 5 封包就有 >80% 事件。
- **偵測面只有間接證據：**
  - Kučera 和 Papadogiannakis 量的是「告警還剩多少」，不是「攻擊落在 flow 哪裡」。
  - 注入的攻擊本來就在開頭（Selective Discarding 報告 T4）。
- **攻擊類型差異大：**
  - Giryes 2024（預印本，CICIDS2017）：前 4 封包準確率 0.97，但 FTP/SSH-Patator 只有 0.74 和 0.79。
  - [推測] 觀察期不能是固定值，要依協定或設備調整。
- **IoT 特性：** 本專案的 IoT-23 約 98% 封包沒有 payload（`tests/ids_throughput/REPORT.md`）。payload 簽章在 IoT 上的作用本來就有限，flow 計數類的監看反而更重要。

### Q2. 放行後還要保留什麼可見性？
- 四個獨立的前例都選了同一個設計：**SYN/FIN/RST 一律不放行**。分別是 Shunting、Time Machine、Zeek BPF shunt、nftables flowtable。
- MUD+SDN 證明，**放行後只留計數**也能抓 volumetric 攻擊：TPR 89.7%，只有 0.92% 封包需要檢測。
  - 同組 2023 年的延伸版改成常駐封包檢測：26% 封包被檢測，TPR 只到 91.0%、FPR 8.6%。
  - [推測] 這支持「信任後只需輕量監看」。
- 在 NFQ 模式下，Suricata 的 EVE flow 計數在 bypass 之後不完整（`mechanisms.md` M4）。**給雲端的 flow record 應從 conntrack 產生。**

### Q3. 抽樣要怎麼做？
- Mai 2006：在相同 flow 預算下，random flow sampling 最好，smart sampling 和 sample-and-hold 最差。
- 逐封包抽樣會造成 flow shortening：N=10 時 TRWSYN 的誤報率從約 0.72 升到約 2.26。所以**抽樣結果不能直接觸發 ban**。
- Bernaille 2006 也說：封包抽樣下準確度「掉得很快」，flow 抽樣則不受影響。
- 規則式 IDS 需要連續封包才能做 stream 重組（`mechanisms.md` §7.5）。
- [推測] 結論：抽樣單位是 **flow 內一段連續時間窗**，起點隨機。

### Q4. 信任怎麼撤銷？會被怎麼利用？
- 現有 IDS 都**沒有**對單一 flow 撤銷 bypass 的 API：Suricata、Snort 3、Zeek（`mechanisms.md` §7.6）。撤銷只能在 kernel 或控制面做。
- 已知的規避手法：
  1. **先乖後壞（stealth）**：NetBeacon、Time Machine、Selective Discarding 都自述這個盲區，沒人量過。
  2. **填滿判定窗**：Grashöfer 有實證。
  3. **預測抽樣或逾時時機**：Ptacek & Newsham 1998；Time Machine 依賴「攻擊者無法預測 timeout」。
  4. **on-off 利用信任恢復**：Chae 2015。
  5. **耗盡狀態表**：Time Machine 的連線表在 flood 下 30 秒內暴增 6–8 倍。
- 可以借用的撤銷範本：
  - NOS-Gate 的 K-of-M 持續觸發加可逆動作。
  - Time Machine 的 `suspend_cutoff`。

---

## 3. Research Gap（可以在論文裡宣稱的）

依「搜尋沒找到」與「作者自述未做」整理。宣稱時要用「to the best of our knowledge」措辭。

| # | 缺口 | 證據 |
|---|---|---|
| G1 | 沒有論文在**放行後**做隨機稽核並量化漏報率 | Time Machine 只提議、Shunting 有 sample 欄位但沒用；搜尋未找到（candidates「沒找到」#2） |
| G2 | 沒有論文**量測**「判定後才攻擊」打穿 bypass/白名單的漏報 | NetBeacon、Kučera、TM、Papadogiannakis 都只是討論段自述（#3） |
| G3 | 「依**安全判定**而放行」、而且判定來自**雲端**的 edge-cloud IDS：沒找到 | 前例放行依據都是「沒東西可看」或廠商宣告（MUD） |
| G4 | 以**上傳 bytes** 為主要指標，比較「全量封包、flow record、抽樣」三種上傳方式 | 沒找到；最近的 HybridMon 是 Tbps 骨幹（#6） |
| G5 | 規則式 IDS 的 cutoff/bypass 證據全在 x86/FPGA，**沒有 ARM / Pi 級** | Kučera、Papadogiannakis 都是 x86（#1、#7） |

[推測] G1 + G2 + G4 組合起來就是論文的主要貢獻，G5 是平台面的補強。

---

## 4. 可行方案（設計草案，全部 [推測]，待討論）

### 4.1 狀態機（以 flow 為單位，ct mark 編碼狀態）

```
        新連線
          │
          ▼
   ┌─────────────┐  觀察期結束 + 雲端判定 benign   ┌──────────┐
   │ OBSERVE      │ ─────────────────────────────▶  │ TRUSTED   │
   │ 全量本地 IDS │                                  │ fast path │
   │ + 上傳雲端   │ ◀── 撤銷（稽核窗命中 /           │ 只上傳     │
   └─────────────┘     計數異常 / TTL 到期）         │ flow record│
          │                                          └──────────┘
          │ 雲端判定 malicious                            │ 隨機時點
          ▼                                               ▼
   ┌─────────────┐  確認惡意（K-of-M）            ┌──────────┐
   │ BANNED       │ ◀────────────────────────────── │ AUDIT     │
   │ drop         │                                  │ 連續窗全量 │
   └─────────────┘                                  │ 回 slow path│
                       稽核窗內未異常 ───────────▶   └──────────┘
                       回 TRUSTED
```

### 4.2 各元件與文獻依據

| 元件 | 設計 | 依據 |
|---|---|---|
| **觀察期** | 依 bytes 和封包數雙門檻，例如「≥N 封包且 ≥B bytes，或協定里程碑（TLS 握手完成）」；兩個方向都要滿足；N 依協定可調 | Shunting、Corelight（>1 MB 且 >10 封包）、Kučera（N=5→80%，N=30→90%）、Giryes（攻擊類型差異） |
| **信任判定** | 雲端判 benign **且**本地 Suricata 沒有告警 | 我們的新意（G3） |
| **放行實作** | `ct mark` 加上 queue 前的 accept chain；**不用** Suricata bypass，**第一版不用** flowtable | `mechanisms.md` M4、M14、M15 |
| **放行後可見性 L1** | conntrack 計數（bytes、packets、時間）定期匯出成 flow record 上雲 | MUD+SDN 計數式監看、Mai（計數不抽樣） |
| **放行後可見性 L2** | SYN/FIN/RST 不放行 | 四個獨立前例 |
| **稽核（L3）** | 隨機起點、固定長度的連續窗（例如 T 秒或 M 個封包），窗內回到 slow path；抽樣率依 flow 風險調整 | Mai、TM 隨機化 cutoff、`mechanisms.md` §7.5 |
| **稽核樣本** | 另外保留 1–5% 的已信任 flow 完全不放行，作為 ground-truth 對照 | Mai 報告 T6 |
| **撤銷觸發** | (a) 稽核窗本地或雲端告警；(b) L1 計數異常，例如速率突變、新目的地；(c) TTL 或位元組上限到期 | NetBeacon「最大 flow 長度」、TM `suspend_cutoff`、MUD 計數 |
| **ban 條件** | K-of-M 確認，不因單次抽樣命中就 ban | NOS-Gate、Mai 的 flow shortening 誤報 |
| **防 on-off** | 被撤銷過的 flow 或設備，下次信任門檻提高、TTL 縮短 | Chae 2015 |
| **狀態上限** | 信任表要有大小上限與逾時 | TM 的連線表暴增、Zeek XDP 的 unbounded state |

### 4.3 可調參數（就是實驗的自變數）

觀察期 N/B、信任 TTL、稽核率 p、稽核窗長 W、稽核樣本比例、K-of-M。

---

## 5. 研究問題（論文的 RQ）

- **RQ1 成本：** 信任式 fast path 能把上傳到雲端的 bytes，以及 Pi 端的 CPU 降多少？和「全量上雲」比、和「純 cutoff（Kučera 式）」比。
- **RQ2 偵測代價：** 對一般攻擊，偵測率和 time-to-detection 損失多少？
- **RQ3 規避：** 對「信任建立後才攻擊」的流量，稽核窗加計數監看能抓回多少？撤銷延遲多少？（對應 G1、G2）
- **RQ4 參數：** 稽核率、窗長、TTL 和成本、漏報之間的取捨曲線為何？在 Pi 3B+ 的資源限制下，可行的操作點在哪裡？

---

## 6. 評估設計（草案）

- **平台：** Pi 3B+ inline（nftables + NFQUEUE + Suricata 7.0.10）。邏輯可以先在筆電 netns 驗證，結果要說明哪些和實機等價。
- **資料：**
  - IoT-23 replay（已有 `tests/iot23/`）。注意它幾乎沒有 payload。
  - 需要補一個有應用層內容的 IoT 資料集，候選是 CICIoT2023，**待確認**。
- **延遲攻擊（自建）：** 把攻擊段接到一條正常 flow 的後段，位置參數化為第 k 個封包或第 k 秒。這是 G2 的核心實驗，現有資料集沒有。
- **Baseline：**
  1. 全量上雲
  2. 本地 Suricata + 全量上雲
  3. 純 cutoff（Kučera 式，放行後完全不看）
  4. 純計數監看（MUD+SDN 式）
  5. 我們的方法
- **指標：**
  - 上傳 bytes
  - Pi 的 CPU、RAM
  - 轉送 throughput 與 latency
  - recall、FPR
  - time-to-detection
  - 延遲攻擊的 recall
  - 撤銷反應時間
- **可重複性：** n≥10、95% CI。Galette 的做法是先前文獻中唯一做到的（見 `../SYNTHESIS.md` §3）。

---

## 7. 論文骨架（建議）

1. **Introduction**：IoT gateway 加雲端 IDS 的傳輸成本問題。現有 bypass 依據是「沒東西可看」，而且放行後就看不到了（G1–G3）。
2. **Background**：Suricata 的 stream depth、bypass，nftables conntrack 和 NFQUEUE。引用 `mechanisms.md`。
3. **Related Work**：照 §1.2 的軸線寫。
   - cutoff 類：Time Machine、Selective Discarding、Kučera
   - 放行類：Shunting、immUNITY、NetBeacon、HorusEye、MUD+SDN
   - 抽樣：Mai、Brauckhoff、Alikhanov
   - early detection：Bernaille、Giryes
   - 信任撤銷：Chae、NOS-Gate
   - 規避：Ptacek & Newsham、Grashöfer
4. **Threat Model**：攻擊者知道有信任機制、可以先乖後壞、不知道稽核時點。這是假設，要討論。
5. **Design**：§4 的狀態機和元件。
6. **Implementation**：Pi 上的 nft 規則、控制程式、conntrack 匯出。
7. **Evaluation**：RQ1–RQ4。
8. **Discussion**：
   - 加密流量
   - 長連線多工（HTTP/2、MQTT）
   - 設備層級信任和 flow 層級信任的關係（IoT Sentinel）
   - flowtable 升級作為第二層 fast path
9. **Conclusion**

---

## 8. 待驗證與風險（依優先順序）

1. **NFQ 加 ct mark 的放行是否如讀碼推論般運作**：`mechanisms.md` §8 的第 1 項。這是整個方案的地基，建議第一個實驗就在 netns 驗證。
2. **`numgen` 加 `queue` 的語法、Pi kernel 是否有 flowtable 模組**：未確認。
3. **Suricata 收到「稽核窗」中途開始的 TCP 封包時，`midstream` 要開還是關**，以及開了之後簽章的可靠度。這決定 L3 稽核有沒有意義，文獻中沒有量測。
4. **雲端判定延遲期間的 fail-open 或 fail-closed 選擇**：會直接影響 K1 轉送效能。
5. **報告裡讀圖估的數字**：Mai Fig.5/6、Selective Discarding Fig.3–5。正式引用前要重新確認。

---

## 9. 參考文獻（已確認存在；標 * 者只讀到摘要或部分章節）

- J. M. Gonzalez, V. Paxson, N. Weaver. Shunting: A Hardware/Software Architecture for Flexible, High-Performance Network Intrusion Prevention. CCS 2007. doi:10.1145/1315245.1315264
- S. Kornexl, V. Paxson, H. Dreger, A. Feldmann, R. Sommer. Building a Time Machine for Efficient Recording and Retrieval of High-Volume Network Traffic. IMC 2005. doi:10.1145/1330107.1330137
- G. Maier, R. Sommer, H. Dreger, A. Feldmann, V. Paxson, F. Schneider. Enriching Network Security Analysis with Time Travel. SIGCOMM 2008. doi:10.1145/1402958.1402980
- A. Papadogiannakis, M. Polychronakis, E. P. Markatos. Improving the Accuracy of Network Intrusion Detection Systems Under Load Using Selective Packet Discarding. EuroSec 2010. doi:10.1145/1752046.1752049
- L. Kučera, L. Kekely, A. Piecek, J. Kořenek. General IDS Acceleration for High-Speed Networks. ICCD 2018. doi:10.1109/ICCD.2018.00062
- J. Mai, C.-N. Chuah, A. Sridharan, T. Ye, H. Zang. Is Sampled Data Sufficient for Anomaly Detection? IMC 2006. doi:10.1145/1177080.1177102
- D. Brauckhoff et al. Impact of Packet Sampling on Anomaly Detection Metrics. IMC 2006. doi:10.1145/1177080.1177101 *
- J. Alikhanov et al. Investigating the Effect of Traffic Sampling on ML-Based NIDS. IEEE Access 2022. doi:10.1109/ACCESS.2021.3137318（`../papers/`）
- L. Bernaille, R. Teixeira, I. Akodjenou, A. Soule, K. Salamatian. Traffic Classification on the Fly. SIGCOMM CCR 2006. doi:10.1145/1129582.1129589
- Giryes, Shafir, Wool. arXiv:2405.07232, 2024（預印本）*
- A. Hamza, H. Habibi Gharakheili, T. A. Benson, V. Sivaraman. Detecting Volumetric Attacks on IoT Devices via SDN-Based Monitoring of MUD Activity. SOSR 2019. doi:10.1145/3314148.3314352
- E. Lear, R. Droms, D. Romascanu. RFC 8520: Manufacturer Usage Description Specification. 2019.
- M. Miettinen et al. IoT Sentinel. ICDCS 2017. doi:10.1109/ICDCS.2017.283
- T. D. Nguyen et al. DÏoT. ICDCS 2019. doi:10.1109/ICDCS.2019.00080
- G. Zhou, Z. Liu, C. Fu, Q. Li, K. Xu. An Efficient Design of Intelligent Network Data Plane（NetBeacon）. USENIX Security 2023.
- C. Wei et al. immUNITY. arXiv:2603.20573, 2026（預印本）
- Y. Dong et al. HorusEye. USENIX Security 2023（`../papers/`）
- J. Grashöfer, C. Titze, H. Hartenstein. Attacks on Dynamic Protocol Detection of Open Source Network Security Monitoring Tools. arXiv:1912.03962, 2019
- T. H. Ptacek, T. N. Newsham. Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection. Secure Networks Tech. Report, 1998
- Y. Chae, L. DiPippo, Y. L. Sun. Trust Management for Defending On-Off Attacks. IEEE TPDS 26(4), 2015. doi:10.1109/TPDS.2014.2317719 *
- M. Bilal, O. Tariq, H. Ahmed. NOS-Gate. arXiv:2601.00389（IEEE TCE 2026, doi:10.1109/TCE.2026.3682516，出版社頁未讀）
- I. B. Fink et al. HybridMon. NOMS 2025. doi:10.1109/NOMS57970.2025.11073723
- J. A. Simioni et al. Energy-efficient IDS Offloading（稿件，`../papers/`）
