# slide_implement.md — Security Gateway 調查進度

> 定義每一頁投影片要有什麼內容。**本文件與 `src/main.typ` 同步**，是重做或交接時的依據。
> 對應草稿：`user_draft.md`　原始素材：`reference/`（上次報告者提供）　查證紀錄：`查證_RFC與工具.md`、`查證_資料集.md`、`查證_可復現準則.md`、`查證_資料集x準則.md`　講稿：`逐字稿.md`

---

## 0. 全域規範

### 0.1 報告定位
- **調查進度報告**，三個主題篇幅均等：測試方法、Datasets、測試工具
- 主要成果在 Datasets：**上次報告的四個資料集可不可以復現**，其中 IoT-23 已實測
- ❌ **不得說「已實作 RFC 9411」**，只能說「後續會依此方法測試」
- ❌ **不得說「dataset 可以當 benchmark」**。只能說「可復現」「可以搭配 tcpreplay 當測試輸入」
- ❌ **不得推估效能數字**（還沒量過）

### 0.2 敘述深度原則 ★最重要
**投影片只放重點，說明、理由、舉例一律放講稿。**
- 表格只留關鍵欄位，每格盡量 ≤ 8 個字
- 每頁要點 ≤ 3 條，每條一行
- 留白可以接受，不要為了填滿版面加東西
- 寫給製作者看的註記（`>` 引言、⚠️）**不得印到投影片上**

### 0.3 不能寫錯的事實 ★每一條都查證過
1. **RFC 9411**：2023/03 發布，屬 Informational，**取代 RFC 3511**。對象是 **inline 模式的 next-generation network security devices**，NGFW／NGIPS 是原文舉的例子（Abstract："including NGFWs and NGIPSs"；Scope："network security devices ... configured in Active (Inline) mode"）。但安全功能清單（Table 2／3）只針對 NGFW 與 NGIPS 定義 → 我們的 gateway 要選一個較接近的清單並註明（放講稿）。作者來自 EANTC、NetSecOPEN。
2. **RFC 3511 有狀態**：已有併發 TCP、HTTP 交易等測試。被取代的原因是**缺少 TLS、IPS／App-ID 等 L7 安全功能，也沒有 CVE 有效性驗證**。❌ 不可寫「3511 只測無狀態流量」。
3. **RFC 2544**：1999 年，網路互連設備（router／switch），以 frame 為單位測試。
4. **RFC 9411 不能用 tcpreplay 量測，這是推論，不是原文**。原文要求真實三向交握、FIN 關閉、模擬 client／server。
5. **RFC 9411 Appendix A 的 CVE 驗證**：≥ 500 個 CVE、10 年內、CVSS High（7–10）。
6. **RFC 9411 排除依賴 ML／行為分析的功能**（測試時應停用）→ P6 要點以「RFC 9411 不涵蓋 ML 與送雲端路徑」帶到；細節（§3 原文）放講稿。
7. **CIC-IDS2017**：
   - `MachineLearningCSV` 版本只保留 Destination Port，對不回封包；`GeneratedLabelledFlows` 版本才有五元組與時間。
   - 時間只精確到「分」，12 小時制且沒有 AM/PM（週一例外，精確到秒）。
8. **CIC-IDS2017 有已知的標籤錯誤**：Engelen et al., IEEE SPW 2021 指出超過 20% 的 trace 被重建或重新標註，並釋出了修正版。
9. **CIC-DDoS2019**：CSV 有五元組與微秒級時間。**CSV 與 PCAP 內的日期一致（12/01）**，只有（2020 年版）官網寫的 2019/1/12 不同（依據：鏡像 CSV 第一列 2018-12-01 09:17:11.183810，與 CICFlowMeter issue #69 中官方 PCAP 的 Wireshark 截圖到微秒都相同；PCAP 部分是第三方截圖，我們沒有自己下載）→ 不影響標籤對回封包；照官方時間表裁切時，日期與時刻都以資料內為準（放講稿）。❌ 不可寫「日期錯置」。
10. **CICIoT2023**：
    - CSV 沒有 IP、port、timestamp，且已打亂順序。
    - **標籤以整個 PCAP 檔為單位** → 可以對到「檔案」，對不到 flow。❌ 不可寫「完全對不回」。
11. **IoT-23**：Zenodo DOI 10.5281/zenodo.4743746，CC BY 4.0。
    - light 版沒有 PCAP，**只在 Stratosphere 網站上，不在 Zenodo**。
12. **Hakai C&C 標籤**：8,222 條 flow 全是 S0（只有 SYN，沒有回應），12,334 個封包裡 payload 為 0。
13. **tcpreplay 不是網路協定堆疊**：不建立連線，也不管對方有沒有回應。
14. **hping3 最後一次 commit 是 2014 年**。
15. **RFC 9411 Appendix A（安全有效性）**：背景流量（模擬）同時送入攻擊流量；攻擊流量依原文是挑選過的 **CVE**。必填 KPI 為擋下／未擋下的數量與比例、背景流量是否受影響、DUT 回報是否正確；驗收條件包含背景流量**不得誤擋**。背景流量依 §7 量出的最大 HTTP(S) 吞吐量各取 45%，必須與 §7 同一個 testbed。
   **（2026-10-04 修正方向）RFC 9411 沒有規定要用 dataset**。本報告的規劃是兩項測試：測試一照 RFC 9411（本地、CVE）；測試二為整體測試，用同一份 dataset 對照「只有本地」與「本地 + 雲端」。❌ 不可再寫「RFC 9411 的攻擊流量改用 dataset」。
   RFC 9411 測不到完整方法的理由：(a) §3 Scope 排除依賴 ML／行為分析的系統（should be disabled）；(b) 背景流量與 CVE 都有已知答案，沒有「未知」類，送雲端路徑幾乎不會觸發；(c) §4.3.3 balanced mesh 反覆連同一批 server IP，若有雲端判定快取，命中率會偏高；(d) KPI 沒有送雲端比例、雲端延遲、雲端斷線降級。RFC 允許 SUT（多元件系統），但 (a) 仍適用。
16. **比較對象**：上次報告的開源引擎中，Suricata、Snort 3 可 inline 阻擋；**Zeek 是被動分析，不能 inline 擋流量**，不放入比較（放講稿）。
17. **現階段無法在 Pi 上做「可與市售報告比較」的完整 RFC 9411 測試**：(1) 缺少 RFC 9411 等級的開源流量產生器（wrk、h2load 能建立 TLS 連線，但不能當成測試設備；TRex 尚不支援 TLS）；(2) gateway 尚未具備 RFC 建議開啟的安全功能（TLS inspection、IPS、anti-malware 等）。❌ 不可寫成「RFC 9411 不能在 Pi 上做」。
19. **RFC 9411 架構參數**：見 `查證_RFC與工具.md` 末節「架構參數」，P4b／P4c 的內容只能取自那裡。Fail-Open MUST 關、Inline MUST、Reference test MUST、Sustain ≥ 300 s 是 RECOMMENDED（不是 MUST）。
18. **NetSecOPEN**：資安廠商與測試實驗室組成的產業組織，依 RFC 9411 認證市售 NGFW 並公開報告 → 只放講稿。實際案例（Cisco Secure Firewall 1220CX，UNH-IOL，2025-08）的數字見 `查證_RFC與工具.md`「NetSecOPEN 實際認證報告」，放在「後續測試規劃」頁的講稿備用段。

### 0.4 技術規格
- **Typst** 搭配 `@preview/slydekit:0.4.1`（metropolis 主題），共用 `slides/template.typ`，編譯用 `slides/build.sh`
- 繪圖：`fletcher`（必要時用 `cetz`）
- 字型：Noto Sans CJK TC／Noto Sans Mono CJK TC；比例 16:9
- **實體 16 頁** = 封面 1 + 大綱 1 + 章節分隔頁 3 + 內容 9 + References 1 + Q&A 1（P4b、P4c、P15b 為 2026-10-04 新增，規劃文件沿用舊編號避免全部重排）

### 0.5 視覺一致性（沿用上次報告）
- **架構圖的節點與邊標籤一律用英文**，內文說明用中文
- LAN 畫左、WAN 畫右、雲端畫上
- 語意色：LAN `c-lan`、WAN `c-wan`、雲端 `c-cloud`、強調 `c-stage3`；可行 `yes`、不可 `no`、部分 `partly`
- `#callout(title: ...)` 的 title 不會渲染，標題要寫進內文第一行
- **不使用 reference 裡 AI 生成的示意圖**，全部自己繪製

---

## P1 — 封面
- 標題：**Security Gateway 調查進度**（這個字串決定 PDF 檔名）
- 日期：2026-10-05
- 不要副標

## P2 — 大綱
三項，**必須與三張章節分隔頁一字不差**：
1. 測試方法
2. Datasets 可復現性
3. 測試工具

---

# 1. 測試方法（P3 分隔頁 + P4、P4b、P4c、P5、P6）

## P4 — RFC 9411
**圖（fletcher，橫向，英文標籤）**
```
┌ Test Equipment ┐                            ┌ Test Equipment ┐
│ Client Emulator│ ──→ DUT (Security Gateway) ──→ │ Server Emulator│
└────────────────┘                            └────────────────┘
```
- 依 RFC 9411 Figure 1：兩側各一台 Test Equipment，**DUT 在兩框之間、不在框內**
- 兩端的 Emulator 同色（`c-muted`），DUT 用 `c-stage3` 強調

**表格（2 欄）**

| 項目 | 內容 |
|---|---|
| 發布 | IETF，2023 |
| 對象 | Inline 網路安全設備（例：NGFW／NGIPS） |
| 量測 | Inspected Throughput、Connections Per Second、TTFB／TTLB、Concurrent Connections |
| 前提 | 建議安全功能全開、≥ 500 個 CVE 驗證 |

> **製作者注意**：量測項目用 RFC 9411 §6.3 的英文 KPI 名稱（專有名詞翻成中文反而難懂）；字太長可縮小該格字級。九項測試的名稱、Sustain ≥ 300 秒放講稿。

## P4b — RFC 9411：DUT 的要求（快速帶過）
**左：DUT 要求表（重點）；右：`assets/security_features_table.png`（由使用者提供的 `security_features.png` 裁掉底部原文標題；RFC 9411 Table 3，NGIPS 建議安全功能，已核對與原文一致），圖下小字「RFC 9411 Table 3（NGIPS）」**

| DUT 的要求 |
|---|
| Inline 模式 |
| Fail-Open 關閉 |
| 建議安全功能全開（右表） |
| 以 flow 記錄 log |

（使用者決定：不顯示 MUST／SHOULD 等級，因為之後都會照做；等級只放講稿）

**頁尾小字一行**：測試設備端（TCP、TLS、Client IP）也有規定；所有參數與偏離原文之處都要寫進測試報告

> **製作者注意**：
> - 等級依原文：Inline MUST、Fail-Open 關閉 MUST、RECOMMENDED 功能全開（未開 MUST 報告原因）、realistic ACL SHOULD、logging MUST 開但「以 flow 記錄」是 SHOULD → 表中寫 SHOULD 指的是 flow 粒度。
> - 右圖是 NGIPS 清單（Table 3）；NGFW 的 Table 2 不同（多 IDS/IPS、Anti-Virus，另有 4 項 OPTIONAL），講稿要說明。
> - 測試設備端參數（TCP、HTTP、TLS、Client IP、IPv4/IPv6）全部移到講稿備用段。
> - ACL 不上投影片（使用者決定）。依據：§4.2「acceptable not to configure ACLs in an NGIPS」，且 Table 4 Note 3 要求不配 ACL 時 MUST 在報告註明。講稿備用要說明：nftables Tier 0 的 allow/deny 本質上就是 ACL，不能說「我們沒有 ACL」。
> - 「我們目前的對應」只放講稿。

## P4c — RFC 9411：測試流程
**上方：兩步驟（fletcher，橫向，英文標籤）**
```
① Reference test (no DUT)  ──→  ② Benchmark with DUT
```

**下方：負載曲線時間軸（cetz 或 fletcher，英文標籤）**
```
 load
  │            ┌──────────────────┐
  │           ╱      Sustain       ╲
  │          ╱      ≥ 300 s         ╲
  │ ────────╱   (measure here)       ╲────────
  └─ Init ── Ramp up ─────────── Ramp down ── Collection ──→ time
     ≥ 5 s
```
- Sustain 段用 `c-stage3` 強調，其他段 `c-muted`

**要點一條**：只在 Sustain 段量測（取樣間隔 < 2 秒）

> **製作者注意**：Reference test 的目的（確認 testbed 本身不是瓶頸、記錄環境的 loss／latency）、Init 不能發起連線、Ramp up 不能壓垮 DUT，放講稿。

## P5 — 為什麼選 RFC 9411
**比較表**

| 方法 | 年份 | 有狀態流量 | L7 安全功能 | 適用對象 |
|---|---|---|---|---|
| RFC 2544 | 1999 | `no` | `no` | Router／Switch |
| RFC 3511 | 2003 | `yes` | `no` | 防火牆 |
| **RFC 9411** | 2023 | `yes` | `yes` | 網路安全設備（NGFW／NGIPS 等） |

**不放要點。**

> **製作者注意**：
> - 「適用對象」依各 RFC 標題：2544 "Network Interconnect Devices"、3511 "Firewall Performance"、9411 "Network Security Device"（2026-10-04 由「跨廠商比較」改來：原欄名不準、與 L7 欄重複）。
> - 理由全部放講稿；NetSecOPEN（業界用此方法認證市售 NGFW）只放講稿。

## P6 — 後續測試規劃
**表格**

| | 一、RFC 9411 基準 | 二、整體測試 |
|---|---|---|
| 受測範圍 | Gateway 本地 | 本地 vs 本地 + 雲端 |
| 樣本 | CVE（≥ 500 個，依 RFC 規定挑選） | 選定的公開 dataset（本地與本地 + 雲端用同一份，放講稿） |
| 測試內容 | 效能、已知攻擊阻擋率（講稿補：分別對應 §7 與 Appendix A） | 兩種設定的偵測率差異、延遲與吞吐量代價 |
| 比較對象 | Suricata、Snort 3（inline） | 同一個 gateway，雲端關／開 |

**要點一條**
- RFC 9411 只能測本地端（雲端的 ML 不在範圍內）

（使用者已將「現階段限制」從投影片移除；內容保留在講稿）

> **製作者注意**：
> - （2026-10-04 使用者修正）整體測試的主軸是「同一份 dataset，對照只有本地 vs 本地 + 雲端」；「送雲端比例 vs 吞吐量」只是其中一項指標，放講稿。
> - 講稿要講到 RFC 9411 測不到完整方法的四個理由（事實 15 的 a–d，(b)(c) 標明是推論）、SUT（RFC 2285 §3.1.2）、兩項測試在同一 testbed、偏離原文要註明。
> - NetSecOPEN、Zeek、TRex、商用工具等備用段保留。
> - ❌ 不可寫「RFC 9411 搭配 dataset」「攻擊流量改用 dataset 重播」。

---

# 2. Datasets 可復現性（P7 分隔頁 + P8–P11）

## P8 — 要復現需要什麼、做不做得到
> **製作者注意（講稿開場）**：這個題目的由來是上次報告提到這些資料集可以拿來做 ML training；ML 訓練與評估要能被別人重現，前提是資料可復現。這也對應 P6 的整體測試。
> **（2026-10-04 改版）** 舊的「三個條件（封包＋標籤＋對應鍵）」是自行推導、綁定 tcpreplay，已撤除。新版只放兩個有出處的需求，且不綁工具。依據：`查證_可復現準則.md`、`查證_資料集x準則.md`。

**上表：要復現需要什麼（2 列）**

| 需要什麼 | 出處 |
|---|---|
| ① 拿得到同一份原始資料 | ACM Artifacts Available、Ring 2019 |
| ② Label 能與原始流量對齊 | Engelen 2021 |

**下表：實際上做不做得到**

| Dataset | ① 拿得到 | ② 時間維度 | 能復現嗎 |
|---|---|---|---|
| IoT-23 | `yes` 有 DOI | `yes` 微秒 | `yes` **已驗證** |
| CIC-IDS2017 | `partly` 需登記、無 DOI | `partly` 分 | `partly` 用修正版 |
| CIC-DDoS2019 | `partly` 需登記、無 DOI | `yes` 微秒 | `partly` 無 DOI |
| CICIoT2023 | `partly` 需登記、無 DOI | `no` 無 | `no` 對不到 flow |

（2026-10-04 第六輪驗證修正：① 依 ACM Artifacts Available 需封存庫＋DOI，CIC 三份為 △；② 只看「能否追溯」，CIC-IDS2017 的 △ 理由改為時間精度；CIC-DDoS2019 CSV 有微秒時間可追溯，② 為 ✓，「官網時程對不上」為第三方回報，放講稿；② 出處只留 Engelen 2021，Ring「Labeled」只分類有無標籤，不支持可追溯）

**不放要點。** 兩張表可上下排或左右排，字級縮小以一頁放完。

> **製作者注意**：
> - 「復現」依 ACM 定義：獨立團隊用原作者的 artifact 得到相同結果；我們的用途是「別人用同一份資料重現我們的測試」→ 只需 ①②。
> - 準則 ③（產生過程紀錄）、④（處理流程可重做）屬於「重做資料集本身」，不是我們的用途，不上投影片；講稿備用要能說明（出處：FAIR R1.2、ACM Functional、Gebru §3.4）。
> - 講稿備用段需涵蓋（取自 `查證_資料集x準則.md`）：
>   - IoT-23 有 v2（v2 changelog 說 fewer errors，等於承認 v1 部分標籤有錯但無明細；README 的感染時間軸 often incomplete and not accurate，指 README 文字而非資料時間戳；v2 用 pcapfix 修 PCAP 壞標頭；v2 為 WIP、無 DOI；我們用 v1）
>   - IoT-23 標籤由 Zeek 產生 flow、分析師判斷後以 Flaber 套規則；Flaber GitHub repo 2022 年才建立；Hakai C&C 標籤反推可由「目的 IP + port 50」完全重現（port 50 單獨也能，是其中一種等價寫法）→ 呼應「只能測 IP／port 封鎖」
>   - CIC-IDS2017 官方標註程式未公開；修正版：Engelen 2021（https://intrusion-detection.distrinet-research.be/WTMC2021/）、Liu 2022
>   - CIC-DDoS2019 官網時程與 PCAP 對不上：僅 issue #69 第三方回報、官方未確認；擷取可能長於攻擊時段，8:18 對 7:52 非強證據；CICFlowMeter 版本說法不一致（官網 V3、repo 說明 V4.0），無法確認實際版本
>   - 「需登記」：CIC 三份都需填表下載、無 DOI；IoT-23 有 Zenodo DOI、CC BY 4.0
>   - MachineLearningCSV 沒有五元組與時間、IoT-23 light 沒有 PCAP
> - 第六輪驗證同步（逐字稿須寫到）：
>   - IoT-23「實測對齊」只抽 2／23 個 scenario（Hakai-8-1、Somfy-01）；v1 有作者承認的標籤錯誤。
>   - 實測樣本是從 mcfp 個別 scenario 目錄下載，不是 Zenodo；`01_verify.sh` 只比對自己記錄的 SHA-256，從未與 Zenodo 比對（P9 的 Verify 也要寫）。
>   - CICIoT2023「只到檔案」依賴 PCAP 分檔方式，我們未驗證，須加但書。
>   - ACM 是借用：原本評論文自己的 artifact；講稿只說一次。
>   - ① 用 ACM 標準（封存庫＋DOI）：IoT-23 ✓、CIC 三份 △；② 出處只留 Engelen 2021，不得引 Ring 為 ② 的出處；CIC-IDS2017 ② 理由為時間只到分；CIC-DDoS2019 ② ✓。
>   - 用字：「官網時程對不上」（非「不準」）、「說法不一致」（非「矛盾」）、「GitHub repo 2022 年才建立」（非「2022 才公開」）。
> - ❌ 不可說「四個都沒辦法復現」，也不可說「三個條件」。

## ~~P9 怎麼驗證 IoT-23~~（2026-10-04 刪除）
- 使用者決定：意義不大，改放講稿（P10 的備用段「怎麼驗證 IoT-23（三個步驟）」）。

## P10 — IoT-23 實測：Label 對齊
**截圖**：`assets/align.png`（使用者提供，`02_align.py` 的 Hakai 輸出），佔頁面主體

**右側三個數字**（用 `hl` 強調）
- 10,403 條 flow，**100%** 對齊
- C&C：8,222 條，全部是 S0
- C&C 封包有 payload：**0**

> **製作者注意**：Somfy 也是 130／130 對齊、ARP 佔 29.4% 沒有標籤，放講稿。這頁對應需求 ②。

## P11 — IoT-23：能不能拿來測 gateway
**定位：另一個問題，不是可復現性。** 標題用「IoT-23：能不能拿來測 gateway」。

**上方小圖：Docker lab（LAN 左、WAN 右，英文標籤）**
```
cli (tcpreplay) ──LAN──→ gw (nft counter + tcpdump ×2) ──WAN──→ srv
```
**截圖**：`assets/replay_cc.png`

**要點兩條**
- 規則啟用：入口 3 → 出口 **0**，計數器 3；停用／啟用各 3 次結果一致
- C&C 只有 SYN → **只能測 IP／port 封鎖，不能測偵測**

> **製作者注意**：
> - 圖與截圖同頁若太擠，Docker lab 圖可縮小或改成一行文字；以截圖清楚為優先。
> - tcpreplay 只是這次使用的工具，不是唯一方式；srv 回 RST 的意義（tcpreplay 不建立連線）、tcprewrite 改位址、拆方向重播、對應到 Pi，都放講稿。

---

# 3. 測試工具（P12 分隔頁 + P13–P15）

## P13 — 六種候選工具
**定位：實作 gateway 時，用這些工具快速測試規則。**

**表格**

| 工具 | 產生的流量 | 可以測哪類規則 |
|---|---|---|
| Nping | TCP／UDP／ICMP | 標頭欄位、TCP flags、速率門檻 |
| hping3 | 自訂 TCP/IP | 同上（Nping 的備選） |
| Scapy | Python 自訂封包 | 規則邊界（只差一個欄位的命中／不命中） |
| Nmap | 連接埠掃描 | 掃描偵測 |
| SlowHTTPTest | 慢速 HTTP | 慢速連線、逾時 |
| Tcpreplay | 重播 PCAP | 已知攻擊樣本（dataset） |

**頁尾小字一行**：都有 Debian trixie 官方套件，Docker lab 與 Pi 都能直接安裝

> **製作者注意**：hping3 自 2014 年後未更新、nping 包含在 nmap 套件裡，放講稿。

## ~~P14 規則測試迴圈、P15 Tcpreplay 能做／不能做~~（2026-10-04 刪除）
- 使用者決定：工具段只介紹「實作時可以拿哪些工具測試」，P13 的表已足夠；篇幅不需與其他段均等。
- 兩頁內容移到講稿「六種候選工具」頁的備用段。

## P15b — References
**只列參考網頁：每筆兩行（名稱一行、網址一行），不用論文書目格式。** 字級約 0.7em，兩欄（左：方法、資料集與 ACM／Ring 出處，共 9 筆；右：修正版、issue、NetSecOPEN 與工具，共 10 筆），一頁放完。內文頁不加 [n] 標號。

左欄
- RFC 9411：https://www.rfc-editor.org/info/rfc9411/
- RFC 3511：https://www.rfc-editor.org/info/rfc3511/
- RFC 2544：https://www.rfc-editor.org/info/rfc2544/
- IoT-23：https://www.stratosphereips.org/datasets-iot23
- CIC-IDS2017：https://www.unb.ca/cic/datasets/ids-2017.html
- CIC-DDoS2019：https://www.unb.ca/cic/datasets/ddos-2019.html
- CICIoT2023：https://www.unb.ca/cic/datasets/iotdataset-2023.html
- ACM Artifact Review and Badging：https://www.acm.org/publications/policies/artifact-review-and-badging-current
- Ring et al. 2019（NIDS 資料集綜述）：https://arxiv.org/abs/1903.02460

右欄
- CIC-IDS2017 修正版（Engelen et al.）：https://intrusion-detection.distrinet-research.be/WTMC2021/
- CIC-IDS2017 修正版（Liu et al. 2022）：https://intrusion-detection.distrinet-research.be/CNS2022/
- CICFlowMeter issue #69：https://github.com/ahlashkari/CICFlowMeter/issues/69
- NetSecOPEN：https://www.netsecopen.org/
- NetSecOPEN 認證報告（Cisco 1220CX）：https://www.netsecopen.org/_files/ugd/914193_96dabf1eec4a42f1935d442d99011004.pdf
- Tcpreplay：https://tcpreplay.appneta.com/
- Nping：https://nmap.org/nping/
- hping3：https://github.com/antirez/hping
- SlowHTTPTest：https://github.com/shekyan/slowhttptest
- Scapy：https://scapy.net/

> **製作者注意**：網址已確認 HTTP 200（2026-10-04）；ACM 頁面對程式請求回 403（Cloudflare），瀏覽器可正常開啟，內容已經由 Wayback 核對。逐字照抄。網址可用等寬字型。右欄較長時可把工具類移到左欄，以一頁放完為準。

## P16 — Q&A
- 只放「Q&A」大字置中，不放其他內容
- 用 `focus-slide` 或 `punch`

---

## 附錄：素材清單
| 檔案 | 來源 | 狀態 |
|---|---|---|
| `assets/align.png` | 使用者截圖 `tests/dataset/02_align.py` | 已提供 |
| `assets/replay.png` | 使用者截圖 `tests/dataset/03_replay.sh` | 已提供（原圖） |
| `assets/security_features.png` | 使用者提供，RFC 9411 Table 3 截圖（原圖） | 已提供 |
| `assets/security_features_table.png` | 由上圖裁掉底部標題（P4b 使用） | 已產生 |
| `assets/replay_cc.png` | 由 replay.png 裁切出 C&C 案例段落（P11 使用；完整輸出字太小） | 已產生 |

> （2026-10-04 使用者要求）投影片上的專有名詞用英文：label、dataset、packet、detection、latency、throughput、port scan、replay 等。P8 第 2 欄統一為「時間精度＋是否實測」：IoT-23 label 的 ts 為 epoch 微秒（例 1533042911.474174）、PCAP 為 classic 微秒格式（magic d4c3b2a1）。
> （2026-10-04 使用者要求）P8 第 2 欄改名「時間維度」，只寫精度（微秒／分／無），不寫實測與否；實測與否由「能復現嗎」欄與講稿表達。

> （2026-10-04 最終審閱後修正，投影片）第 2 頁對象「Inline network security device」；第 3 頁頁尾「Test equipment」；第 6 頁要點「RFC 9411 只能測本地端（排除 ML／行為分析）」；第 7 頁「能復現嗎」CIC-IDS2017「△ 修正版、未實測」、CIC-DDoS2019「△ 未實測」；第 9 頁「counter」、「Hakai 的 C&C 只有 SYN」。

> （2026-10-04 老師 comment 後修正，投影片已改）P4（第 2 頁）量測欄改為 4 個 KPI 附中文說明、前提改「CVE 驗證（近 10 年、CVSS 7–10）」；P6 樣本「CVE（近 10 年、CVSS 7–10）」、測試內容寫具體指標、比較對象「單獨的 Suricata、Snort 3（自行架設、同硬體同規則）」、新增要點「本地規則比對用 Suricata／Snort，我們的重點是本地／雲端分流」；P11（第 9 頁）要點改為「Dataset 的 packet 改位址後可重播穿過 gateway，處置結果可觀察、可重複」「限制：這筆 C&C 樣本只有 SYN，目前只驗證到 IP／port 層級的處置」。依據見 user_draft.md「老師 comment 與決定」。

> （2026-10-05 老師 comment 後改版，投影片已改，見 user_draft.md「範圍收斂」）P4b（DUT 的要求）刪除；P4 量測改「效能（Throughput、Latency 等）」並刪「前提」列；P6 改為「一、效能測試／二、偵測測試」，要點「效能測試流程參考 RFC 9411（Reference test → Sustain）」；References 移除 NetSecOPEN。實體 15 頁。此後 CVE、Appendix A、安全功能清單、NetSecOPEN 皆不在報告範圍。

> （2026-10-05 再改版）P6（第 5 頁）改為「Dataset → 4 種設定」流程圖＋效能／偵測兩個指標框，要點一條「效能測試流程參考 RFC 9411（Reference test → Sustain）」。偵測以 flow 為單位：TP／FP／FN／TN，Detection rate = TP/(TP+FN)、FPR = FP/(FP+TN)；packet loss 要扣除規則丟棄的封包。
