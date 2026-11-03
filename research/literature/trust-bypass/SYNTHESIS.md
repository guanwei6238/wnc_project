# 子題整合：信任式 Fast Path（Trust-based Bypass）——文獻、方案與論文骨架

> 初版：2026-10-16。整合決定：2026-10-20（見 §10、§11）。
> 依據：
> - 本子題 7 篇精讀報告（`papers/*.md`）
> - 實作機制調查 `mechanisms.md`
> - Suricata 整合介面調查 `suricata-integration.md`
> - 開放搜尋清單 `candidates.md`，共 14 篇加 3 篇範圍外
> - 延遲攻擊資料集搜尋 `datasets.md`
> - IoT-23 C&C 長連線分析 `iot23-heartbeat/REPORT.md`
> - 先前已讀的 HorusEye、Alikhanov、Simioni（`../papers/`）
>
> 報告由 Sonnet subagent 撰寫，每篇都讀了全文或標明只讀到摘要。主 agent 只抽查了關鍵數字，對照原文 PDF 的文字檔：
> - Shunting Table 2、Selective Discarding p.5–6、MUD+SDN Table 5/8、Mai Table 3/4、Kučera §III–IV、NetBeacon 討論段
> - Simioni 出版版 p.14–15
> - IoT-23 分析的 CSV（重算）
>
> 抽查的數字全部吻合，其餘數字以各報告的出處標記為準。標 [推測] 的是判斷，不是論文寫的。「搜尋沒找到」只是弱證據。

---

## 0. 先講結論

1. **研究主軸是「省成本」，不是「偵測演算法」。** 信任式 fast path 是降低地端運算、上傳和雲端推論成本的手段。「flow 前段正常、後段才攻擊」是這個手段製造出來的盲點，論文要量的是這個代價有多大、能壓到多低。偵測本身交給 Suricata 和雲端 IDS。

2. **研究空缺很清楚。** 文獻裡相關的機制分成三群，彼此幾乎不相交：
   - (a) 判定後放行：Shunting、immUNITY、NetBeacon、MUD+SDN、SciPass、HorusEye
   - (b) 只看 flow 開頭：Time Machine、Selective Discarding、Kučera
   - (c) 信任撤銷與恢復：Chae on-off、NOS-Gate

   **沒有任何一篇同時做到這四件事：放行機制、放行後的抽樣複查、撤銷，以及量測「放行後才攻擊」的漏報。** 多位作者在討論段承認這個盲區，但沒有人量過。

3. **更正：「攻擊大多在連線開頭」沒有被直接實證。**
   - Time Machine、Shunting 只是斷言。
   - 最接近的量測是 Kučera 2018：Suricata 每條 flow 只看前 5 個封包，仍偵測到超過 80% 的事件；N>30 時超過 90%。但它量的是告警數比例，不是攻擊落在 flow 的哪裡。

4. **前例放行的理由是「沒東西可看」，不是「判定安全」。** 以安全判定作為放行理由，是我們的新意，也是風險。

5. **真正的盲點只在「明文 flow 內容層」的攻擊（§2.5 的 D 類）。**
   - 加密 flow 的後段內容，不管有沒有信任機制，payload IDS 本來就看不到。
   - 流量和行為的變化（C 類）不需要 payload，靠 kernel 計數就能看。

6. **信任狀態必須由 kernel 持有。** Suricata 的 NFQ bypass 只在單一封包上打 mark，而且無法撤銷（`mechanisms.md` M3、M4）。現階段用 ct mark，之後改用 tc eBPF map（§4）。

7. **「抽樣」要換成「隨機起點的連續稽核窗」，而且只對明文 flow 做。** 逐封包隨機抽樣對 Suricata 的 stream 與 app-layer 規則幾乎無效（`midstream` 預設 false），還會因為 flow 看起來變短而誤判（Mai 2006）。

8. **雲端不看 payload，所以「資料完整性」的重點變成 flow 特徵是否完整。** 已信任的封包如果不經過算特徵的地方，雲端拿到的特徵就只算到觀察期為止。這讓 tc eBPF 算特徵從「最佳化」變成「需求」（§4.4）。

---

## 1. 文獻地圖

### 1.1 依 T 欄位比較

| 論文 | 放行依據與時點（T1） | 放行後可見性（T2） | 撤銷（T3） | 規避討論（T4） | 效益數字（T5） |
|---|---|---|---|---|---|
| **Shunting** CCS'07 | 分析器沒東西可看（DPD 前 2 KB、HTTP>10 KB 後、SSH 已認證） | 硬體表有 sample 欄位但**沒用**；SYN/FIN/RST 恆送 IPS | forward-N 超限自動回 shunt；IPS 可插 drop | 無 | 放行 54.9–91.1% bytes、43.8–88.0% packets（6 條 trace，Table 2） |
| **Time Machine** IMC'05 / SIGCOMM'08 | 每連線前 N KB（10–20 KB） | 只影響**錄製**，NIDS 仍看全量 | `suspend_cutoff`（兩週 427 次） | §6 承認「cutoff 後攻擊」是根本限制；提議隨機化 cutoff，**未實作** | 15 KB 時存量剩 <6%；91–96% 連線在 10–20 KB 內完整 |
| **Selective Discarding** EuroSec'10 | 負載驅動的全域 cutoff（前 N 封包） | 尾段丟棄 | 新連線重新從頭看 | p.6 承認 persistent HTTP 可先填滿再攻擊；只有定性反論 | cutoff 100：吞吐 3.62 倍、保留 95% 告警；276 個注入攻擊全中（但都在開頭） |
| **Kučera** ICCD'18 | 前 N 封包（N 依負載調） | 丟棄 | 無 | 明說 N 之後的攻擊偵測不到 | N=5 時 >80% 事件、N>30 時 >90%（Suricata + 13,642 條 ET 規則，真實 pcap） |
| **MUD+SDN** SOSR'19 | 命中廠商宣告的 MUD 規則 | **每規則每分鐘計數** + 單類異常偵測 | 無（只告警） | 核心就是「合規流量裡藏攻擊」；低速攻擊的前幾分鐘漏報 | 只有 0.92% 封包被檢測；TPR 89.7%、FPR 5.1%、平均 1.92 分鐘 |
| **IoT Sentinel** ICDCS'17 | 設備 setup 階段的指紋 → 三級信任 | 無 | 無 | 假設接入時 benign | 辨識率 0.815 |
| **DÏoT** ICDCS'19 | 無放行（每包都過模型） | 全量 | — | — | 偵測率 95.6%、257 ms（相反的極端） |
| **immUNITY** arXiv'26 | SmartNIC 在第 3 封包判 benign → 交換器白名單 | 不再看 | 只有快取覆寫 | 未討論 | 96 Gbps 中只 0.14 Gbps 進慢路徑；誤放行 FPR 0.0008% |
| **NetBeacon** Sec'23 | flow class table 判定後不再過 ML | 不再看 | 逾時 | 自述 stealth attack，建議「最大 flow 長度上限」，**未量測** | — |
| **HorusEye** Sec'23 | iForest 白名單 | header 仍鏡射 | 黑名單寫回 | — | 卸載 76%，但上傳 bytes 沒降 |
| **Simioni** IoT-J'25 | early-exit 信心 ≥ 門檻就在本地定案 | 每 15 s 事件窗都重新判斷（**沒有跨窗的信任快取**） | — | — | Pi 3B 上本地全跑每事件 1385 ms（AlexNet），卸載約 10% 後時間降到 1% |
| **Mai** IMC'06 | （抽樣研究） | — | — | 小 flow、掃描在抽樣下最先消失 | 同 flow 數下 random flow sampling 最好（異常 21 個，N=100：flow 18 / packet 6 / smart 1 / S&H 2） |
| **Grashöfer** arXiv'19 | （攻擊論文） | — | — | **實驗室實證**以填充耗盡協定辨識 buffer，規避 Zeek、Snort 3、Suricata 4.1.2 | Bro 預設 buffer 1024 B |
| **Chae** TPDS'15 | （信任管理） | — | redemption 機制 | on-off 攻擊利用信任恢復 | 只讀到摘要 |
| **NOS-Gate** TCE'26 | 無放行 | 持續評分 | **K-of-M 觸發、可逆降權** | 時序控制的規避 | recall 0.952 @ 0.1% FPR（合成資料） |

### 1.2 三群文獻的定位

```
              只看開頭（便宜）                             全程檢查（貴）
  IoT Sentinel ── Shunting / Kučera / TM ──── [我們] ──── MUD+SDN ──── DÏoT / NOS-Gate
  一次性設備信任   cutoff 後完全不看          信任 + 稽核窗   計數式監看     每包都看
                                              + 撤銷 + 上雲
```

[推測] related work 可以照這條軸線寫，我們的定位是「在兩端之間，用可撤銷的信任換成本」。Simioni 是另一條軸線上的近鄰：有 edge–cloud 分工，但沒有時間維度的信任快取。

---

## 2. 核心問題的證據

### Q1. 只看 flow 開頭就決定，有沒有依據？
- **成本面有強證據：**
  - Time Machine：heavy-tail 分佈，>20 KB 的連線只占 12–15%，卻含 87–99.86% 的 bytes。
  - Shunting：最多放行 91% bytes。
  - Kučera：前 5 個封包就有 >80% 的事件。
- **偵測面只有間接證據：** Kučera 和 Papadogiannakis 量的是「告警還剩多少」，不是「攻擊落在 flow 哪裡」。注入的攻擊本來就在開頭。
- **攻擊類型差異大：** Giryes 2024（預印本，CICIDS2017）：前 4 個封包準確率 0.97，但 FTP/SSH-Patator 只有 0.74 和 0.79。[推測] 觀察期不能是固定值，要依協定調整。
- **流量特性：** 本專案的 IoT-23 約 98% 封包沒有 payload（`tests/ids_throughput/REPORT.md`）。gateway 保護的是公司內外網，IoT 只是其中一部分，評估不能只用 IoT 流量。

### Q2. 放行後還要保留什麼可見性？
- 四個獨立的前例都選了同一個設計：**SYN/FIN/RST 一律不放行**。分別是 Shunting、Time Machine、Zeek BPF shunt、nftables flowtable。
- MUD+SDN 證明**放行後只留計數**也能抓 volumetric 攻擊（TPR 89.7%，只有 0.92% 封包要檢測）。同組 2023 延伸版改成常駐封包檢測，26% 封包被檢測，TPR 也只到 91.0%、FPR 8.6%。
- 在 NFQ 模式下，Suricata 的 EVE flow 計數在 bypass 後不完整（`mechanisms.md` M4）。**給雲端的 flow 特徵不能靠 Suricata EVE**，要由 kernel 產生（§4.4）。

### Q3. 抽樣要怎麼做？
- Mai 2006：相同 flow 預算下，random flow sampling 最好，smart sampling 和 sample-and-hold 最差。逐封包抽樣會造成 flow shortening：N=10 時 TRWSYN 的誤報率從約 0.72 升到約 2.26。所以**抽樣結果不能直接觸發 ban**。
- Bernaille 2006：封包抽樣下準確度「掉得很快」，flow 抽樣不受影響。
- 規則式 IDS 需要連續封包做 stream 重組（`mechanisms.md` §7.5）。
- [推測] 抽樣單位應是 **flow 內一段連續時間窗**，起點隨機，**只對明文 flow 做**。

### Q4. 信任怎麼撤銷？會被怎麼利用？（依證據層級分）
- 現有 IDS 都**沒有**對單一 flow 撤銷 bypass 的 API（Suricata、Snort 3、Zeek；`mechanisms.md` §7.6；Suricata unix socket 對單一 flow 只有唯讀查詢，`suricata-integration.md`）。撤銷只能在 kernel 或控制程式做。

| 規避手法 | 證據層級 | 依據 |
|---|---|---|
| **先乖後壞** | 同類行為**在實際攻擊中出現過**，但沒有針對 IDS 放行的案例 | 沙箱的時間型規避：MITRE ATT&CK T1497.003（Clop、Egregor、Bazar）。IoT 設備被感染後等 C2 指令：Mirai（USENIX Sec'17，5 個月 15,194 次攻擊指令）。IoT-23 有 20 條 C2 長連線在 heartbeat 後才收到指令（§2.6） |
| **把攻擊推到判定窗外** | IDS 上是**實驗室示範**；檔案層級的同類手法**在實際攻擊中出現過** | Grashöfer 2019 規避 Zeek、Snort 3、Suricata 4.1.2。MITRE T1027.001 Binary Padding（APT29、Akira、Black Basta）。針對 Suricata/Snort depth 的實際案例或 CVE：沒找到 |
| **預測抽樣或逾時時機** | **只是理論** | Ptacek & Newsham 1998 描述了 Sneakers 攻擊，但測試章節（§7–8）沒有測這項。「預測抽樣」是從 Time Machine 一句話推論的 |
| **on-off 利用信任恢復** | **只是學術模型** | Chae 2015 是 WSN 模擬，只讀到摘要 |
| **灌爆狀態表** | **實際部署中遇到過**，但不是刻意針對 | Maier 2008：MWN 的 flood 讓連線表 30 秒內從約 50 萬增到 300–400 萬，耗盡記憶體。「刻意製造小連線」是作者的假設 |
| **對決策模型的輸入注入** | **二手來源的測試** | Jev 的評測文章稱，在輸入中藏文字可讓它以 >70% 信心選錯（未驗證）。流量中 SNI、Host、User-Agent、DNS 名稱都是攻擊者控制的 |

- 寫進 threat model 時，應定位成「**實際攻擊中已有的策略，合理延伸到 gateway 信任機制**」，不能寫成「已觀察到的攻擊」。預測抽樣和 on-off 放進 Discussion 當作預防性設計。
- 可以借用的撤銷範本：NOS-Gate 的 K-of-M 持續觸發加可逆動作；Time Machine 的 `suspend_cutoff`。

### 2.5 依「和信任機制的關係」給攻擊分類

| 類型 | 例子 | 信任機制有沒有影響 | 由誰抓 | 需要 payload？ |
|---|---|---|---|---|
| **A. 第一個封包就是惡意** | 掃描、大部分 exploit、多數資料集裡的攻擊 | 沒影響，觀察期就抓到 | 本地 Suricata + 雲端 | 視規則 |
| **B. 惡意行為開新的 flow** | botnet 收到指令後去掃描、DDoS 別人 | 沒影響，新 flow 一樣走觀察期 | 同上 | 視規則 |
| **C. 已信任 flow 內流量或行為突變** | 同一條 flow 變成 flood、外洩量暴增 | 有影響（內容不再檢查） | kernel 計數 + 雲端 flow 特徵 | **不需要** |
| **D. 已信任 flow 內藏惡意內容** | keep-alive 後段夾帶 exploit、C2 長連線後來才下的指令 | **有影響，真正的盲點** | 只能靠稽核窗（機率性） | **需要，而且只在明文 flow 有意義** |

- 加密 flow（TLS、SSH、QUIC）的後段內容，沒有信任機制 Suricata 也看不到。所以 D 類的損失只發生在明文協定上。[推測] 公司網路以 TLS 為主，D 類的實際影響可能有限，要量目標流量中明文 flow 的比例。
- botnet 的指令即使在已信任的 C2 連線中漏掉（D），指令造成的後果通常會開新 flow（B），所以會被延後發現，不會完全看不到。

### 2.6 IoT-23 的實際延遲（`iot23-heartbeat/REPORT.md`）
- 57,486 條 C&C flow 中 93% 沒有 payload。時長 > 60 s 的只有 102 條，其中 **20 條**在 heartbeat 穩定後才收到 C2 指令。
- 延遲中位數：第 138 個封包、842 bytes、約 20 分鐘。範圍：20 封包／136 s 到 1,538 封包／27,867 s。
- 樣本相依：7 個場景、9 個 C2、16 個指令時刻，只能當「存在性證據 + 粗略範圍」。
- **封包數和秒數不成比例**（每分鐘 2–8 個封包，多數是純 ACK），所以 k 要同時掃兩種單位。
- **延遲由操作者排程決定**（例如 Muhstik 每小時整點過 15 分廣播）。
- **這 20 條在開頭就有可辨識的 bot 註冊字串**（Mirai `00 00 00 01`、IRC `NICK/USER`、Gafgyt `arch …`）。[推測] 如果規則抓得到，它們在觀察期就不會拿到信任，真正的威脅是「開頭真的乾淨」的 flow。這要用 Suricata + ET 規則重播才能確認。

---

## 3. Research Gap（可以在論文裡宣稱的）

依「搜尋沒找到」與「作者自述未做」整理。宣稱時要用「to the best of our knowledge」措辭。

| # | 缺口 | 證據 |
|---|---|---|
| G1 | 沒有論文在**放行後**做隨機稽核並量化漏報率 | Time Machine 只提議、Shunting 有 sample 欄位但沒用；搜尋未找到（`candidates.md`「沒找到」#2） |
| G2 | 沒有論文**量測**「判定後才攻擊」打穿 bypass/白名單的漏報 | NetBeacon、Kučera、TM、Papadogiannakis 都只是討論段自述（#3）；也沒有現成的「同 flow 延遲攻擊 + 封包層級標籤」資料集（`datasets.md`） |
| G3 | 「依**安全判定**放行」、判定來自**雲端**的 edge–cloud IDS：沒找到 | 前例放行依據都是「沒東西可看」或廠商宣告（MUD）；Simioni 有 edge–cloud 分工但沒有跨時間的信任快取 |
| G4 | 信任機制下，**雲端 flow 特徵的完整性**與取得成本：沒找到 | eBPF/XDP-DL 在 kernel 算特徵但沒有放行；有放行的論文都不管放行後的特徵 |
| G5 | 規則式 IDS 的 cutoff/bypass 證據全在 x86/FPGA，**沒有 ARM / Pi 級** | Kučera、Papadogiannakis 都是 x86（#1、#7） |

原本的 G4（上傳 bytes 指標）併入 RQ1：雲端只收 flow 特徵時，上傳 bytes 的差異可能很小（§4.5）。

**2026-11-03 系統性查核**：結果在 `../novelty-check/REPORT.md`。
- 做法：用 WoS、IEEE Xplore、ACM DL 篩 538 篇，讀全文 20 篇。
- G1、G2、G5 仍成立。最接近的是 GLOBECOM 2025：抽 5% flow 送外部 IDS，但目的是校正模型、不撤銷個別 flow 的信任。在 Pi 上的只有 P4Pir（bmv2，沒有 fast path）。
- G3、G4 不在這次查核範圍。
- 各貢獻可以宣稱和不能宣稱的措辭見 REPORT §2。HPA、DPA 和 kernel bypass 機制都已有前例。

---

## 4. 方案（設計草案，全部 [推測]，待實驗確認）

### 4.1 平台與前提（2026-10-20 的決定，詳見 §10）
- **Pi 4**、**不做 NAT**、以 **Suricata 為 base**、gateway 保護**公司內外網**。
- 雲端 IDS **不看 payload**：一部分用決策模型（Jev 類），一部分用 ML，特徵格式未定。
- **地端有 rule 和 edge AI，再加上雲端**（2026-11-02 老師討論）。edge AI 和雲端一樣是合作方的部分，內容未定；跑在 gateway 同一台機器，和 Suricata、轉送共用 CPU（`decisions.md` O19）。

### 4.2 狀態機（以 flow 為單位）

```
        新連線
          │
          ▼
   ┌─────────────┐  觀察期結束 + 判定 benign     ┌──────────┐
   │ OBSERVE      │ ───────────────────────────▶  │ TRUSTED   │
   │ 全量本地 IDS │                                │ fast path │
   │ + 特徵上雲   │ ◀── 撤銷（稽核窗命中 /         │ 特徵照算   │
   └─────────────┘     計數異常 / TTL 到期）       │ 降頻上傳   │
          │                                        └──────────┘
          │ 判定 malicious                              │ 隨機時點（只限明文 flow）
          ▼                                             ▼
   ┌─────────────┐  確認惡意（K-of-M）           ┌──────────┐
   │ BANNED       │ ◀───────────────────────────── │ AUDIT     │
   │ drop         │                                │ 連續窗全量 │
   └─────────────┘                                │ 回 slow path│
                       稽核窗內未異常 ──────────▶  └──────────┘
                       回 TRUSTED
```

### 4.3 各元件與文獻依據

| 元件 | 設計 | 依據 |
|---|---|---|
| **觀察期** | 封包數和 bytes 雙門檻，或協定里程碑（TLS 握手完成）；兩方向都要滿足；N 依協定可調 | Shunting、Corelight（>1 MB 且 >10 封包）、Kučera、Giryes |
| **信任判定** | 本地 Suricata 無告警 **且** 判定模型判 benign 的機率 ≥ 門檻 | 我們的新意（G3）；Simioni 的信心門檻 |
| **判定快取** | 結果快取在「設備 + 目的地 + port」層級，新 flow 命中就沿用 | [推測] 減少決策模型呼叫次數（§4.6） |
| **放行實作** | 階段 1：`ct mark` + queue 前的 accept chain；階段 2 之後：tc eBPF（§4.4）。**不用** Suricata bypass | `mechanisms.md` M4、M14、M15 |
| **放行後可見性 L1** | flow 計數與特徵（kernel 產生）定期匯出上雲 | MUD+SDN、Mai（計數不抽樣） |
| **放行後可見性 L2** | SYN/FIN/RST 不放行 | 四個獨立前例 |
| **稽核（L3）** | 隨機起點、固定長度的連續窗，窗內回到 slow path；**只對明文 flow**；稽核率依風險調 | Mai、TM 隨機化 cutoff、§2.5 |
| **稽核樣本** | 另留 1–5% 的已信任 flow 完全不放行，當 ground-truth 對照 | Mai 報告 T6 |
| **撤銷觸發** | (a) 稽核窗告警；(b) L1 計數或特徵異常；(c) TTL 或 bytes 上限到期 | NetBeacon、TM、MUD |
| **ban 條件** | K-of-M 確認，不因單次命中就 ban | NOS-Gate、Mai 的 flow shortening |
| **防 on-off** | 被撤銷過的 flow 或設備，下次門檻提高、TTL 縮短 | Chae 2015 |
| **狀態上限** | 信任表要有大小上限與逾時 | TM 的連線表暴增、Zeek XDP 的 unbounded state |
| **判定模型輸入** | 只餵數值特徵；字串欄位（SNI、UA、DNS 名稱）先正規化或雜湊 | §2 Q4 的輸入注入風險 |

### 4.4 Fast path 放在哪一層（tc，分階段）

依專家建議用 **tc（clsact）eBPF**，不用 XDP：
- XDP 只能處理 ingress，而且要網卡驅動支援。
- Pi 4 只有一個板載網口（bcmgenet），第二個 port 要接 USB 網卡。兩者的 native XDP 支援都**未確認**：bcmgenet 的 XDP patch 在 2026 年還在 netdev 審查，合併狀態未確認；USB 網卡通常沒有 native XDP。
- tc 的 ingress、egress 都能掛，任何網卡都能用。

分三階段，每階段都要量測後才進下一階段：

| 階段 | 做什麼 | 解決的問題 | 信任狀態 |
|---|---|---|---|
| **1** | nftables + NFQUEUE + `ct mark`；控制程式讀 EVE、改 ct mark | 把信任、稽核、撤銷的邏輯跑通 | ct mark |
| **2（T1）** | tc eBPF 只觀察：每個封包更新 eBPF map 裡的 flow 特徵，再交回 netfilter | **資料完整性**：已信任 flow 的特徵照算（G4） | ct mark |
| **3（T2）** | tc eBPF 直接轉送已信任的封包，跳過 netfilter | 轉送效能 | eBPF map |

- **不做 NAT，讓 T2 可行很多**：跳過 netfilter 不會壞掉位址轉換。
- **T2 剩下的問題**：conntrack 看不到被跳過的封包，逾時和計數要自己管；撤銷要改 map；SYN/FIN/RST 要繼續交給 netfilter。
- **和 CLAUDE.md 的關係**：CLAUDE.md 寫「eBPF/XDP 都是後期的事」。階段 2 是為了資料完整性的**需求**，不只是效能最佳化，是否提前要由開發者決定（§11 D6）。

### 4.5 成本模型（RQ1 要量的三個維度）

| 成本 | 信任機制怎麼省 | 備註 |
|---|---|---|
| **地端運算** | 已信任 flow 不走 NFQUEUE 往返、不做 Suricata payload 比對 | Pi 上最貴的部分（10/19 簡報的 throughput 實驗） |
| **雲端推論** | 已信任 flow 不必重新問決策模型或 ML；判定快取再省一層 | 決策模型每次呼叫都有成本和延遲 |
| **上傳 bytes** | 已信任 flow 的特徵降頻上傳 | 省多少取決於雲端特徵格式：flow 結束時一筆摘要 → 幾乎不省；定期特徵 → 看頻率差；逐封包 header 特徵 → 省很多 |

### 4.6 判定模型放在哪裡

| 放法 | 可行性 | 依據 |
|---|---|---|
| Pi 上每條新 flow 都問決策模型 | **不可行** | 0.8B 仿製模型（gutsy、Decider）粗估每次判斷要數秒；公司 gateway 每秒可能有數十到數百條新 flow。**未實測** |
| Pi 上只問少數拿不定主意的 flow，加速率上限 | 可能可行，要量 | Simioni：AlexNet 在 Pi 3B 上每事件 1.4 s，作者的解法就是只讓約 10% 往上送 |
| 放雲端 | 可行 | 原本的規劃 |
| Pi 上的第一層用小模型 | 可行 | eBPF/XDP-DL：Pi 4B 上 GRU 每 flow 10.38 ms |

每秒需要的判斷數 ≈ 新 flow 率 × 拿不定主意的比例 × 快取沒命中的比例。[推測] 信任機制和判定快取讓決策模型在 Pi 上變得可行，可以當論文的一個結果。

### 4.7 可調參數（實驗的自變數）
觀察期 N/B、判定門檻、信任 TTL、稽核率 p、稽核窗長 W、稽核樣本比例、K-of-M、快取粒度。

---

## 5. 研究問題

- **RQ1 成本：** 信任式 fast path 能把地端 CPU、雲端推論次數、上傳 bytes 各降多少？和「全量檢查、全量上雲」比，也和「純 cutoff（Kučera 式）」比。
- **RQ2 A、B 類：** 一般攻擊（從頭就惡意、或開新 flow）的偵測率與 time-to-detection 有沒有損失？用現有資料集。
- **RQ3 C 類：** 只靠 kernel 計數和 flow 特徵，能抓到多少已信任 flow 內的流量或行為突變？
- **RQ4 D 類：** 稽核率、窗長、TTL 和偵測機率、偵測延遲、成本的取捨曲線。可先寫解析模型再驗證：抓到機率約 1−(1−p)^(T/W)（[推測]，假設各稽核窗獨立）。要用自建資料集（G2）。
- **RQ5 資料完整性：** 信任機制下，雲端需要的 flow 特徵有多少能完整取得？在 Pi 4 上各要多少成本（conntrack／tc eBPF／user space）？（G4）

---

## 6. 評估設計（草案）

- **平台：** Pi 4 inline（nftables + NFQUEUE + Suricata，階段 2 起加 tc eBPF）。邏輯先在筆電 netns 驗證，結果要說明哪些和實機等價。Suricata 版本見 §11 D1。
- **資料：**
  - RQ2：CIC-IDS2017 修正版、CIC-DDoS2019、IoT-23 等現有資料集。
  - RQ1：需要像公司網路的正常流量，**flow 長度分佈要接近真實**；IoT-23 不具代表性。
  - RQ4：**自建**。`datasets.md` 沒找到「同 flow 延遲攻擊 + 封包層級標籤」的現成資料。
- **自建延遲攻擊資料（建議做法）：**
  - 在 netns 或容器中跑真實 server 和自寫 client，在**同一條 TCP 連線**內先送 k 個正常請求，再送攻擊。由產生器記錄攻擊從第幾個封包、第幾秒開始。
  - 再依時間軸混進真實資料集的正常背景流量。前例：Papadogiannakis 2010 把 120 段攻擊 trace 隨機插入一小時的真實 trace。
  - 先用 suricata-verify 的 `bypass-depth-*`、`nfq-ips-bypass` 等測試確認 Suricata 的行為。
  - k 同時掃封包數和秒數（範圍見 `iot23-heartbeat/REPORT.md` §5），或用「連線建立到下一次廣播」的 uniform 模型。
  - **對照組**：同一批資料不開信任機制、全量給 Suricata，先證明偵測得到，才能把漏報歸因到信任機制。
  - 情境：HTTP keep-alive 夾帶 exploit、長連線 C2、正常 session 後段外洩量突變（C 類）、TLS 情境（呈現限制）。
  - 用專案自己的四條可復現準則檢驗，並列入老師要的資料集狀態綜整表。
- **Baseline：**
  1. 全量檢查、全量上雲
  2. 純 cutoff（Kučera 式，放行後完全不看）
  3. 純計數監看（MUD+SDN 式）
  4. 每窗重新判斷（Simioni 式，沒有信任快取）
  5. 我們的方法
- **指標：** 地端 CPU/RAM、轉送 throughput 與 latency、雲端推論次數、上傳 bytes、recall/FPR、time-to-detection、延遲攻擊的 recall、撤銷反應時間、特徵完整度。
- **可重複性：** n≥10、95% CI（Galette 的做法，見 `../SYNTHESIS.md` §3）。

### 6.1 信任機制的濫用測試（2026-11-02 加入）

**目的：** 回答「攻擊者能不能利用信任機制」。§2.5 的 A–D 類之外，再加一類**狀態層級攻擊**：目標是信任狀態本身（conntrack entry、5-tuple、判定快取），不是偵測規則。

**新意的定位：** 連線重用、偽造封包、塞滿狀態表都是已知手法。貢獻是在信任式 fast path 上系統性量出它們的影響和緩解成本，不是發現新攻擊。

**每一項都要報：**
- 能不能繞過檢查
- 漏掉多少封包、多長時間
- 緩解方式
- 緩解在 Pi 上的成本（CLAUDE.md：每個決策都要實測效能）

| # | 情境 | 要量什麼 | 資料來源 | 現況 | 工作量 |
|---|---|---|---|---|---|
| 1 | TCP 舊連線無聲消失後，重用同一個 5-tuple | 修正前，新連線有多少封包繞過 Suricata、裡面的攻擊有沒有告警；修正後是否歸零 | 自己產生（`synreuse_docker.sh` 的做法） | Docker 重現過、Pi 測過；修正在 commit `7207f5d`，規則每封包 52–159 ns。缺：把攻擊 payload 放進新連線 | 低 |
| 2 | TCP 正常結束後重開 | 確認不會沿用信任（對照組） | 自己產生 | 依 kernel 原始碼（`nf_conntrack_proto_tcp.c` 重開連線的處理）推論，沒有單獨實測 | 很低 |
| 3 | UDP 在逾時內沿用信任 | 信任後送攻擊會不會漏；緩解方式（例如閒置一段時間就清信任）的效果與成本 | 自己產生 | 沒做 | 低–中 |
| 4 | 偽造相同 header 注入 | TCP 窗外（預期標成 INVALID、送 Suricata）、TCP 窗內（on-path 攻擊者）、UDP 偽造來源；比較 ct mark、flowtable、tc 三種後端。flowtable 會關掉 TCP 序號窗檢查（BE_LIBERAL） | 自己產生（scapy 之類的工具，只在 testbed） | 沒做 | 中 |
| 5 | 塞滿 conntrack 表 | 攻擊者能不能因此拿到信任，或只會讓信任被清掉、CPU 上升 | 現有資料集的掃描與 flood（IoT-23 39-1、CIC-DDoS2019 Syn、CICIoT2023 SYN flood） | 部分做過（commit `56b63f2` 等）：被信任的 TCP entry（assured）不受影響；單向 UDP 的信任約 4 秒被 early drop 清掉，回到 Suricata | 低 |
| 6 | 判定快取被濫用 | 被信任一次之後，對同一個目的地開新連線、攻擊放在開頭；比較新連線有／沒有觀察期 | 自己產生 | 判定快取還沒實作（§4.3） | 中 |
| 7 | 信任之後才攻擊（D 類，RQ4） | 稽核率、窗長和偵測率、成本的取捨 | 自建（§6 的延遲攻擊資料）；自然樣本：IoT-23 的 20 條 quiet_then_cmd（§2.6）、CIC-IDS2017 Heartbleed | 沒做 | 高 |
| 8 | on-off（Chae 2015） | 被撤銷後好壞交替，能不能反覆拿回信任；提高門檻的效果 | 自己產生 | 要先有政策層 | 高 |

**資料集現況：**
- 沒有現成資料集涵蓋上面任何一項「針對信任機制」的情境。
  - `datasets.md` 只查了第 7 項（延遲攻擊）：沒有資料同時具備「同一條 flow 先正常後攻擊、封包層級標籤、原始 pcap」三個條件。
  - 2026-11-02 補搜「既有連線被 TCP 劫持或偽造注入」的有標籤 pcap，也沒找到。ID2T 能注入攻擊並產生標籤檔，但注入的是新的 TCP 流。
- 能用的零件：
  - suricata-verify：bypass、midstream 行為
  - PYROLYSE：重疊與插入
  - HTTP Evader：編碼歧義，可以測稽核窗看不看得懂內容
  - tcpliveplay
- 所以第 1、3、4、6、8 項要由產生器自己記錄 ground truth（哪些封包是攻擊、從什麼時候開始）。這套產生器和結果本身可以當資料集貢獻，和 §11 D2 一起決定。

**順序：**
- 先做第 1、3、5 項，script 大多已經有。
- 第 4 項要新工具。
- 第 6–8 項要等雲端迴路和稽核窗。
- 第 2 項放附錄。

---

## 7. 論文骨架（建議）

1. **Introduction**：gateway + 雲端 IDS 的成本問題。現有 bypass 的依據是「沒東西可看」，放行後就看不到了（G1–G3）。
2. **Background**：Suricata 的 stream depth 與 bypass，nftables conntrack、NFQUEUE，tc eBPF。
3. **Related Work**：照 §1.2 的軸線。
   - cutoff 類：Time Machine、Selective Discarding、Kučera
   - 放行類：Shunting、immUNITY、NetBeacon、HorusEye、MUD+SDN
   - edge–cloud 分工：Simioni、eBPF/XDP-DL
   - 抽樣：Mai、Brauckhoff、Alikhanov
   - early detection：Bernaille、Giryes
   - 信任撤銷：Chae、NOS-Gate
   - 規避：Ptacek & Newsham、Grashöfer
4. **Threat Model**：攻擊者知道有信任機制、可以先乖後壞、不知道稽核時點、可能控制送給判定模型的字串欄位。定位見 §2 Q4；狀態層級攻擊（連線重用、偽造注入、塞滿狀態表、判定快取、on-off）見 §6.1。
5. **Design**：§4。
6. **Implementation**：Pi 4 上的 nft 規則、tc eBPF、控制程式、特徵匯出。
7. **Evaluation**：RQ1–RQ5。
8. **Discussion**：加密流量；長連線多工（HTTP/2、MQTT）；設備層級和 flow 層級信任的關係（IoT Sentinel）；判定模型的輸入注入。
9. **Conclusion**

---

## 8. 待驗證與風險（依優先順序）

1. **NFQ + ct mark 的放行是否如讀碼推論般運作**（`mechanisms.md` §8 第 1 項）。整個方案的地基，建議第一個實驗在 netns 驗證。
2. **EVE → 控制程式 → ct mark 撤銷的端到端延遲與丟事件行為**（`suricata-integration.md`）。EVE 讀太慢會默默丟事件。
3. **IoT-23 的 20 條 C2 連線在觀察期內是否已被 ET 規則抓到**（§2.6）。決定 D 類威脅的實際範圍。
4. **Suricata 收到「稽核窗」中途開始的 TCP 封包時，`midstream` 要開還是關**，以及開了之後簽章的可靠度。決定 L3 稽核有沒有意義。
5. **Pi 4 的 kernel 是否支援所需功能**：tc clsact + eBPF JIT、flowtable、`numgen` + `queue` 的 nft 語法。
6. **雲端判定延遲期間要 fail-open 還是 fail-closed**：直接影響轉送效能。
7. **報告裡讀圖估的數字**：Mai Fig.5/6、Selective Discarding Fig.3–5、Simioni 出版版的 Table IV。正式引用前要重新確認。

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
- M. Antonakakis et al. Understanding the Mirai Botnet. USENIX Security 2017, pp. 1093–1110 *
- MITRE ATT&CK T1497.003（Time Based Checks）、T1027.001（Binary Padding）
- Y. Chae, L. DiPippo, Y. L. Sun. Trust Management for Defending On-Off Attacks. IEEE TPDS 26(4), 2015. doi:10.1109/TPDS.2014.2317719 *
- M. Bilal, O. Tariq, H. Ahmed. NOS-Gate. arXiv:2601.00389（IEEE TCE 2026, doi:10.1109/TCE.2026.3682516，出版社頁未讀）
- I. B. Fink et al. HybridMon. NOMS 2025. doi:10.1109/NOMS57970.2025.11073723
- J. A. Simioni, E. K. Viegas, A. O. Santin, E. de Matos. An Energy-Efficient Intrusion Detection Offloading Based on DNN for Edge Computing. IEEE Internet of Things Journal 12(12), 2025. doi:10.1109/JIOT.2025.3544060（`../papers/simioni-offload.md`）
- eBPF/XDP-DL：Real-Time eBPF/XDP-Based Deep Learning Framework for Anomaly Traffic Detection in IoT Networks. IEEE Internet Computing, 2026. doi:10.1109/MIC.2026.3692726（`../papers/ebpf-xdp-dl.md`）

---

## 10. 決策紀錄

| 日期 | 決定 | 來源 | 影響 |
|---|---|---|---|
| 2026-10-17 | gateway 保護**公司內外網**，不只 IoT | 開發者 | 資料集、規則不能假設內網只有 IoT |
| 2026-10-18 | 以 **Suricata 為 base** | 開發者（老師未表示意見） | 整合介面見 `suricata-integration.md` |
| 2026-10-20 | 雲端 IDS **不看 payload**；一部分用決策模型（Jev 類），一部分用 ML；特徵格式**未定** | 開發者 | §4.5 上傳成本、RQ5 特徵完整性 |
| 2026-10-20 | Fast path 用 **tc**，不用 XDP | 專家建議，開發者認為第三種（kernel eBPF 算特徵）較好 | §4.4 分階段 |
| 2026-10-20 | **不做 NAT** | 開發者 | T2（tc 直接轉送）不會破壞位址轉換；衍生 D3（L2 或 L3） |
| 2026-10-20 | 目標平台改為 **Pi 4** | 開發者 | 記憶體夠放 Suricata（約 1 GB）和小型模型；第二個 port 要接 USB 網卡；CLAUDE.md 仍寫 Pi 3B+ |
| 2026-10-20 | Suricata 改用 **8.0.7**（trixie-backports）；專案以 **Rust** 實作 | 開發者 | 沿用同一份 ET 規則快照與 gw_mix 挑選；要重做的是**效能和偵測結果**的量測，因為 8.0 的 stream 重組、app-layer 檢查時機、HTTP 解析器都變了 |
| 2026-10-22 | **框架只定描述語法**（型別、合併規則、CEL 計算式）。要載入的 eBPF 程式、它輸出的欄位、送雲端的欄位和計算方式，都由使用者在設定裡定義 | 開發者 | 框架負責載入、讀取、解碼、per-CPU 合併、計算、驗證、上傳；D5 的特徵清單變成「第一支程式」的內容，不屬於框架 |
| 2026-10-22 | **Suricata 走 NFQUEUE**，不用 AF_PACKET＋XDP；Suricata 的行為由使用者設定，**預設不做 inline drop**（verdict 一律 accept，擋人由政策層用 nft 執行） | 開發者 | Suricata 的 XDP bypass 是給鏡像流量用的；NFQ 模式不佔用 XDP，也不繞過 nftables 和 conntrack |
| 2026-10-22 | **eBPF 外掛支援完整功能**：掛點不限，可以 drop 或 redirect；掛在哪、做什麼由管理者負責。框架負責揭露：doctor 列出每個 port 上的 eBPF 程式 | 開發者 | 取代 O3 原本傾向的「只允許 EXT 分析外掛」；`gateway-architecture` skill 的 `ebpf-plugins.md` §1、§4 已改寫 |
| 2026-10-24 | **L2 bridge 和 L3 routing 都支援**，由使用者在設定裡選（`mode`），**預設 bridge**。bridge 預設由 OS（例如 NetworkManager）建立，wnc-gw 只檢查；之後可以用設定改成由 wnc-gw 建立。依模式而不同的功能寫成 trait | 開發者 | Pi 上沒有 `nf_conntrack_bridge`，bridge 模式走 `br_netfilter`，nft 規則和 L3 共用 `inet`。判斷方向不能靠 `iifname`（都是 `br0`），改在 netdev ingress 打 mark。wire mode 還沒決定 |
| 2026-10-24 | **XDP 預設用已知最快的方式**：可以設定要不要用 XDP。預設是 port 有 native XDP 才掛，否則核心程式改掛 TC，不會自動選 generic；generic 只在使用者明確指定時使用。使用者的 XDP 外掛遇到沒有 native XDP 的網卡就不載入，請使用者改成 TC 程式。doctor 顯示每個 port 用的是 native 還是 generic | 開發者 | generic XDP 比 TC 慢：省不到建 skb、可能要複製封包，而且整張網卡會跳過 GRO。Pi 4 兩個 port 都會走 TC。和 10-20「fast path 用 tc」的關係待確認（`ebpf-plugins.md` §7） |
| 2026-10-25 | **nftables 用 nft JSON 操作**（`nftables` crate 產生 JSON，spawn `nft`），不自己寫 netlink，也不連結 libnftnl | 開發者 | 專案可能閉源，連結 GPL 函式庫的選項都排除。Pi 實測：nft 每次寫入約 7.7 ms，netlink 約 53 µs，只影響寫入、不影響轉送，所以 set 元素要批次寫入。interval set 的寫入會隨 set 大小線性變慢（10 萬個元素時，nft 每次約 1.9 s）（`decisions.md` O4） |
| 2026-10-25 | **nft table 的骨架由程式固定**，只有參數從設定檔讀；使用者只能管理 set 的內容。**黑名單放在 nft set**，Suricata 只負責偵測 | 開發者 | 程式依賴 table 的結構（ct mark 的值、queue 編號、set 名稱），開放修改會讓程式出錯、破壞信任模型。已信任的 flow 和 fast path 不經過 Suricata，黑名單放在 Suricata 會擋不到（`decisions.md` O11） |
| 2026-10-25 | **雲端 API 由設定檔描述**：endpoint、path、上傳欄位（型別加 CEL 計算式，輸入可以是使用者 eBPF 的輸出、EVE、conntrack）。**回應先做可設定的對應**（R2），動作固定只有 trust/block/observe；和計畫方討論後可能改成固定格式（R1） | 開發者 | 延伸 10-22「框架只定描述語法」。不用等雲端的格式確定，先接自己的模擬雲端。只上傳數值、bool、enum 的底線不變（`decisions.md` O12） |
| 2026-10-25 | **最小的雲端迴路排在階段 2 前面**：階段 1 的地端執行點做完後，先接雲端（特徵先用 EVE 和 conntrack）；**模擬的雲端由我們自己做** | 開發者 | 研究核心的卸載成本（上傳 bytes、判定延遲、送雲端比例）可以早點量。D6 的選項 (a) 不成立；O1 拆 process 的時機跟著提前，要再決定（`decisions.md` O13） |
| 2026-10-25 | **Suricata 整合方式 A**：Suricata 是獨立的 process（原版套件），封包經 NFQUEUE 送給它處理，結果經 EVE 回來，控制走 unix socket；不把 libsuricata 內嵌進 wnc-gw，也不寫 Suricata plugin | 開發者 | B（plugin）的 plugin 要 GPL，C（library mode）要連結 GPL 的 libsuricata；專案可能閉源。doctor 只檢查能力：NFQueue 支援和就緒通知（`READY=1`），版本只顯示 |
| 2026-10-26 | **Suricata 先由 wnc-gw 自己啟動**，之後加上 systemd 管理，兩者都保留；wnc-gw 啟動時 doctor 和啟動訊息給 warning。**queue 編號由設定指定**（預設 0，型別是範圍），被佔用就報錯。**Suricata 沒在運作時預設放行**，但一定要記 log 標出沒檢查的時間段。執行檔和設定檔路徑可設定 | 開發者 | Suricata 在 NFQ 初始化時收到封包會 segfault，`READY=1` 之後才能裝 queue。wnc-gw 自己啟動時 Suricata 和它共用帳號；用 systemd 才能分開。自動找 queue 編號時，wnc-gw 讀不到 root 才能讀的 `/proc` 檔案，也無法確認沒有別人的規則在用（`decisions.md` O14） |
| 2026-10-26 | **wnc-gw 的 log 用自己的 journald namespace 保存**（systemd 的 `LogNamespace=wnc-gw`，Debian）；OpenWrt 另外決定 | 開發者 | Raspberry Pi OS 的 journald 預設只存在記憶體，重開機就消失，無法事後定位 Suricata 什麼時候掛掉；獨立 namespace 只讓 wnc-gw 的 log 寫 SD 卡（`decisions.md` O15） |
| 2026-10-27 | **Suricata 在 IPS 模式要接受從中間開始的連線**：wnc-gw 強制 midstream 不丟包並開啟 `stream.midstream`（Debian 預設的 `exception-policy: auto` 在 NFQ 模式會丟掉這些 flow） | 開發者 | AUDIT 稽核窗和 Suricata 重啟都會產生 midstream flow；其他 exception policy 未定（`decisions.md` O16） |
| 2026-10-27 | **多個 queue 改用 symhash 分流**（含 port、對稱），和階段 1 的 ct mark 一起實作；開多個 queue 時要確認 conntrack 已啟用 | 開發者 | 位址 hash 讓同一對主機的連線擠在一個 worker（42-1：12.9 → 26.4 kpps）；沒有 conntrack 時 symhash 會把分片分到別的 worker（`decisions.md` O14） |
| 2026-10-28 | **信任狀態用 ct mark，以 ctnetlink 寫入**（N5 的 (a)），不用五元組的 nft set | 開發者 | 信任以連線為單位，port 重用和偽造封包繞不過；地基實驗：ct mark 放行在 Docker／Pi 成立，信任每個封包省 39–67 µs（`decisions.md` O17） |
| 2026-10-28 | **L2 要放**：SYN／FIN／RST 一律送 Suricata，規則在信任之前 | 開發者 | 長連線每個封包約 +1 µs；掃描類幾乎全是控制封包，但本來就不會被信任。連線表被掃描塞滿時靠 early drop，被信任的連線不受影響（`decisions.md` O17） |
| 2026-10-28 | **ctnetlink 由 wnc-gw 手寫**（不用 netlink-proto、netlink-packet-netfilter 只當測試對照）；手動信任 `wnc-gw trust` 沒有 TTL，TTL 放 3d；**純 SYN 經過時清掉信任 bit** | 開發者 | Pi 實測設一筆 netlink-proto 51、crate 編碼 20、手寫 13 µs，讀一筆 crate 74、手寫 20 µs；TCP 舊連線沒有 FIN／RST 就消失時，同五元組的新連線會沿用舊 entry 的 mark |
| 2026-10-28 | **`run` 啟動時、裝 table 之前清掉上一次留下的信任 bit**（列出再批次清，不刪 entry、不用世代值）；清不掉照常啟動並記 ERROR | 開發者 | 被強制結束時 table 和 mark 都會留下；拒絕啟動等於所有流量都不經檢查。Pi 上表 6 萬筆時啟動多 37 ms（信任 100 筆）到 636 ms（全部信任） |
| 2026-10-28 | **停止時移除 table**（wnc-gw 沒在跑時流量直接通過）；SIGHUP 最後再決定 | 開發者 | 「沒 run 當然就是通過」 |
| 2026-10-28 | **Suricata 的其他 exception policy 跟著 `when_unavailable`**（accept → ignore，drop → drop-flow／drop-packet），wnc-gw 強制 | 開發者 | Suricata 只告警，記憶體不夠不該變成丟正常流量；Debian 的 `auto` 在 NFQ 模式等於 drop。Pi 實測 flow memcap 用完：accept 全部送達，drop 丟掉約 58% |
| 2026-10-28 | **強制 `engine.init-failure-fatal=no`**，有規則載入失敗時記 WARN | 開發者 | 一條壞規則不該讓整個網路失去檢查；完整驗證放在規則管線 |
| 2026-10-29 | **SIGHUP 和 SIGINT、SIGTERM 一樣正常停止**（移除 table） | 開發者 | SSH 斷線時不再留下 table；`drop` 模式下原本會讓所有轉送流量被丟到重啟為止。SIGHUP 不用來重新載入設定 |
| 2026-10-29 | **log 可以輸出 JSON**：命令列 `--log-format text\|json`，預設 text | 開發者 | 給程式分析 log（例如沒檢查的時間 `uninspected_ms`）；放命令列是因為 log 比設定檔先開始 |
| 2026-10-29 | **`run` 監控 conntrack**：每 10 秒讀筆數、上限、`drop`、`insert_failed`、`early_drop`，接近滿或有丟包、清除時記 WARN | 開發者 | 信任存在 conntrack entry 上；表滿會丟新連線、清掉單向 UDP 的信任，原本只能事後跑 `conntrack -S` |
| 2026-10-29 | **加 ids／ips 模式**：ids 只標記不擋、用 NFLOG 送複本給 Suricata；ips 用 NFQ。**觀察期間有 alert 的連線不信任** | 開發者 | Pi 實測：NFLOG 的轉送不受 Suricata 影響、不會有 NFQ 造成的 conntrack 撞號，Suricata 那個 worker 每封包成本約一半（整台 CPU 相同）；代價是要 `-k none`（GRO 合併的封包 checksum 不完整）、跟不上時複本悄悄漏掉（`decisions.md` O18） |
| 2026-10-30 | **wnc-gw 強制 Suricata `runmode=workers`**，多核靠多個 queue／group（kernel symhash 分流） | 開發者 | Pi 實測 10 kpps：autofp 每封包比 workers 貴（Suricata 多 15–30 µs），貴在執行緒交接；kernel 分流每封包只多 0.7–1.8 µs、分得一樣平均；1 核時 workers 也較好。autofp 單一 queue 的容量沒量 |
| 2026-11-02 | **地端有 rule（Suricata）和 edge AI，再加上雲端**。edge AI 和雲端一樣是和其他教授合作的部分，輸入、任務、模型未定；**跑在 gateway 同一台機器**（研究在 Pi 4，正式設備不是 Pi） | 老師討論（開發者轉述） | edge AI 和 Suricata、轉送搶 CPU，CPU 分配變成設計問題；介面、payload、替身見 `decisions.md` O19 |

---

## 11. 待決事項與選項分析

### D1. Suricata 版本：7.0.10 還是 8.0.7（2026-10-20 已決定：8.0.7，見 §10）

| 面向 | 7.0.10（trixie） | 8.0.7（trixie-backports） |
|---|---|---|
| 支援 | 上游已 EOL（7.0.17 為最後一版）；Debian 自己 backport 安全修補 | 上游支援中。[推測] backports 不在 Debian security team 的範圍內，由維護者跟進，更新可能比較慢 |
| TLS 加密後 bypass | 要 `encryption-handling: bypass` **加** `stream.bypass: yes` | 和 `stream.bypass` 脫鉤；SSH 另有獨立設定 |
| 偵測行為 | — | stream reassembly 提早觸發（官方說可能「告警變多」）；FTP、HTTP 以外的 app-layer 改在請求或回應完成時檢查，部分原本的比對可能不再命中；HTTP 解析庫 libhtp 換成 Rust 版 |
| 規則 | 目前用 ET Open `suricata-7.0.10` 包，52,606 條全部載入（`tests/ids_rules/README.md`） | **ET 對兩版提供同一個檔案**（2026-10-20 下載 `suricata-7.0.10` 與 `suricata-8.0.7` 兩個網址，sha256 相同）。本地 2026-10-11 快照中，沒有規則用到 8.0 移除的 `ssh.protoversion`／`ssh.softwareversion`，也沒有用 `requires`。gw_mix 的挑選依據是 category 和保護對象，與引擎版本無關，**不用重挑**。但「全部載入成功」要在 8.0.7 上用 `suricata -T` 確認 |
| 擴充性 | 只有 capture 和 EVE 輸出 plugin；**沒有 library mode**；Debian arm64 版沒編 Lua | library mode、EVE callback、**flow callback**（可記錄稽核窗看到幾個封包）；內建 Lua 5.4（沙盒） |
| datasets | 有 | 字串長度計入 memcap；每個 dataset 的 hashsize 預設上限 65536 |
| 對既有成果 | 10/19 的離線 throughput 基線直接可用 | 基線要重量 |

**取捨：**
- 10/19 的數字是**離線**量測。inline（NFQUEUE）的數字還沒有，無論選哪一版都要量。所以現在換版的額外成本主要是「離線基線重跑一次 + 規則包重做」。
- 換版越晚，要重做的實驗越多。
- [推測] 如果論文的實驗要以單一版本為準，現在換 8.0.7 的總成本最低。如果下次雙月會要先求能跑，可以用 7.0.10 先跑通階段 1，但要訂好換版的時間點。

### D2. 自建延遲攻擊資料集的四個問題

| 問題 | 選項 | 取捨 | 傾向（[推測]） |
|---|---|---|---|
| **攻擊段來源** | (a) 公開 exploit PoC；(b) Metasploit 擷取；(c) ET 規則附的樣本 | (a)(b) 真實但要處理授權和環境；(c) 方便但會被質疑「挑來配合規則」 | (a) 或 (b)，選有 ET 規則對應的 CVE，對照組再確認偵測得到 |
| **k 的單位** | 封包、請求、bytes、秒 | IoT-23 顯示封包和秒數不成比例；請求數只適用 HTTP 類 | 封包數 + 秒數雙軸，HTTP 情境另加請求數 |
| **正常 session 來源** | (a) 自己擷取；(b) 既有資料集；(c) 純合成 | (a) 最真實但有隱私問題；(b) 可復現但不一定像公司網路；(c) 太乾淨 | 延遲攻擊 session 自己產生，背景混 (b)（例如 CIC-IDS2017 週一） |
| **要不要加密情境** | 要／不要 | 加密時 payload IDS 看不到，只能測 C 類監看；不放會被問 | 要，但定位成「呈現限制」，不是證明方法有效 |

### D3. gateway 是 L3 路由還是 L2 橋接（不做 NAT 衍生的問題；2026-10-24 已決定：兩種都支援、預設 bridge，見 §10）

**2026-10-24 實測**（筆電 kernel 7.0、Pi 6.18.50+rpt-rpi-v8，Suricata 7.0.10；全部在自建的 netns 裡做，沒動實體網卡）：
- 沒載入 `br_netfilter`，或 `bridge-nf-call-iptables=0` 時，`inet` 的 forward chain 看到 **0 個**橋接封包，等於完全繞過規則。
- 載入之後：
  - forward chain 看得到全部封包，`iifname` 是 `br0`（不是實體 port）。
  - netdev ingress 打的 mark 能帶到 forward chain，ct mark 可以用。
  - `queue` 沒有程式接收時封包被丟掉；Suricata 用 `-q 0` 接收時，6 個封包全部進 queue（`id_sequence=6`），verdict 之後照常轉送，而且有告警。
- Pi 上 `nf_conntrack_bridge` 確認沒有（missing），`br_netfilter` 可以載入。

| 面向 | L3 路由（內外網不同網段） | L2 橋接（透明，同網段） |
|---|---|---|
| 部署 | 內網要改 gateway 位址或路由 | 插在中間即可，不改內網設定 |
| nftables | `inet` family，NFQUEUE、conntrack 都是成熟用法 | 兩條路：(1) `bridge` family：kernel 接受 `queue`（`nft_queue_validate` 列了 `NFPROTO_BRIDGE`，commit 47f4f510ad58，2022-07，約 6.0 起），但 conntrack 要 `nf_conntrack_bridge`，它的 Kconfig 預設是 n，rpi-6.18.y 的 bcm2711_defconfig 也沒開，Pi 上大概沒有（要用 doctor 確認）。(2) `br_netfilter`（Pi 是 m）：橋接的 IP 封包也走 `inet` 的 hook，規則和 conntrack 可以和 L3 共用。Suricata 在橋接模式下用 NFQ 收封包，兩條路都還沒測（2026-10-22 查） |
| tc T2 轉送 | `bpf_fib_lookup` + `bpf_redirect_neigh` | 直接 `bpf_redirect` 到另一個 port，比較簡單 |
| 既有實驗 | `scripts/lab-net.sh` 等用的是哪種要再確認 | — |

這會影響階段 1 的 nft 規則怎麼寫，要在動手前決定。

### D4. 要不要在 Pi 4 上量決策模型

- **做什麼：** 用 llama.cpp 跑一個 Jev 仿製模型（例如 gutsy-0.8b 的 Q4，約 505 MB），給約 150 token 的 flow 描述，量每次判斷的延遲；再量和 Suricata 同時跑時的 CPU 與延遲。
- **為什麼：** §4.6 的「每次數秒」是粗估，決定判定模型能不能放在本地。
- **代價：** 要在 Pi 上安裝 llama.cpp、下載模型（需要開發者同意）。
- **替代：** 先假設判定模型全放雲端，本地只放小模型。等雲端格式確定再量。

### D5. 要不要先做特徵來源表

- **內容：** 列出候選雲端模型常用的特徵（CICFlowMeter 77 個、文獻裡為 IoT 精簡的子集），每個標出「conntrack 免費取得／tc eBPF 能算／只能在 user space 算」。
- **用途：** 可以拿去和計畫方討論雲端要吃什麼；決定階段 2 要實作到什麼程度；回答 RQ5。
- **代價：** 一個 subagent 的文件調查，不動程式。
- **風險：** 雲端特徵還沒定，表可能要隨之修改。

### D6. 階段 2（tc eBPF 算特徵）要不要提前、CLAUDE.md 要不要改

- **CLAUDE.md 目前寫：** 「前期原型：Raspberry Pi 3 Model B+」、「eBPF / XDP / DPDK 都是後期的事」。
- **和新決定的衝突：** 平台已改為 Pi 4；tc eBPF 算特徵是資料完整性的需求。
- **選項：**
  - (a) 改 CLAUDE.md，把階段 2 明確列為第二步。
  - (b) 不改規則，只在 CLAUDE.md 註明「tc eBPF 特徵計算是需求，不算預先最佳化」。
  - (c) 先和老師或計畫方確認再改。
