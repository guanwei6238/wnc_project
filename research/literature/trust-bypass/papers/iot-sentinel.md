# IoT Sentinel

> 頁碼說明：本報告引用的 `p.N` 是我下載的 arXiv v2 PDF 的頁序（共 11 頁，pdfinfo），不是 IEEE 正式版頁碼。圖表編號沿用論文內編號。

## A. 書目與取得狀況

- 標題：IoT Sentinel: Automated Device-Type Identification for Security Enforcement in IoT
- 作者：Markus Miettinen, Samuel Marchal, Ibbad Hafeez, N. Asokan, Ahmad-Reza Sadeghi, Sasu Tarkoma
- 年份 / 出處：2017 年 6 月，2017 IEEE 37th International Conference on Distributed Computing Systems (ICDCS)，pp. 2177–2184（Crossref 查證）
- DOI：10.1109/ICDCS.2017.283（Crossref 回傳書目與作者清單，已確認）
- arXiv：1611.04880（v1 2016-11-15；v2 2016-12-13）。URL：https://arxiv.org/abs/1611.04880 ，PDF：https://arxiv.org/pdf/1611.04880v2
- 與給定資訊的差異：無。標題、作者、年份、會議皆與給定資訊一致。
- 取得程度：**全文**。但讀的是 **arXiv v2 預印本**，不是 IEEE 出版版；兩者內容可能有差異（例如實驗細節、章節），我無法比對出版版。
- 本地檔案：`research/literature/trust-bypass/pdfs/iot-sentinel/iot-sentinel.pdf`（及逐頁文字檔）。

## B. 核心貢獻（≤3）

1. 以 SDN 為基礎的 Security Gateway + 雲端 IoT Security Service（IoTSSP）架構：gateway 產生設備指紋、上傳，雲端回傳「隔離等級」，gateway 本地強制執行 [原文 p.2–3, Fig.1]。
2. 以設備**接入網路時的 setup 階段**封包序列為指紋（23 個 header 層級特徵 × n 個封包；不用 payload），搭配「每個 device-type 一個 Random Forest + Damerau-Levenshtein edit distance 仲裁」做 device-type 辨識 [原文 p.3–5, Table I]。
3. 三級隔離（strict / restricted / trusted），用 Open vSwitch + 客製 Floodlight 模組在 Raspberry Pi 2 上強制執行，量測延遲/CPU/記憶體開銷 [原文 p.5, p.8, Table V–VI, Fig.6]。

## C. 指定的 9 項

**1. Research Problem**：家用/小辦公室 IoT 設備常有漏洞又無法修補，需「棕地（brownfield）」做法，讓有漏洞的設備與其他設備共存而不危及網路 [原文 p.1]。具體任務是：辨識新設備的 device-type（make + model + software version）並依其漏洞狀況限制其通訊 [原文 p.2]。

**2. Architecture**（Packet、Flow、Edge、Cloud 分工）[原文 p.2–5, Fig.1–3]：

```
新設備 --(setup 階段封包)--> Security Gateway (OVS + Floodlight 模組)
   gateway：以 MAC 辨識新設備 → 記錄 n 個封包 → 抽 23×n 特徵 = 指紋
   --指紋--> IoT Security Service（雲）：RF 分類 → 必要時 edit distance → 查 CVE
   <--隔離等級 (+ restricted 的允許 IP/DNS 清單)--
   gateway：把等級編譯成「以 MAC 為 key」的 enforcement rule，存 hash table cache，由 OVS 執行
```
- 沒有「封包處理優化」層：封包轉送靠 OVS，控制邏輯在 SDN controller。沒有 flow record。
- 雲端只存指紋→等級的映射，不存 gateway 客戶資訊；gateway 可經 Tor 匿名查詢（作者設想）[原文 p.3]。

**3. Processing Location**：指紋抽取與規則執行在 gateway（OVS 資料路徑 + Floodlight 控制器模組）；分類與漏洞評估在雲端 IoTSSP；論文未說明 OVS 是 kernel datapath 還是 userspace，也未說明規則是 reactive（packet-in 後安裝）或 proactive。[推測] 從「intercepts all traffic flows」與「找到匹配規則的延遲」的敘述看較像 reactive [原文 p.5]。

**4. Hardware**：gateway 評估用 Raspberry Pi 2（寫作 "R-Pi II"），同機跑 OVS 與自訂 SDN controller，USB WiFi dongle 或內建 WiFi + hostapd [原文 p.8]。論文未列 Pi 2 的 CPU/RAM 規格。指紋蒐集用另一台跑 Kali Linux 的筆電（hostapd + tcpdump），規格未列 [原文 p.6]。IoTSSP 的硬體：論文未說明（Table IV 的計時在哪台機器上跑也未說明）。備選部署：OpenWRT 路由器 + OVS（OF-AP），controller 在另一台機器；未用於評估 [原文 p.8]。

**5. Dataset**：自己在實驗室蒐集的真實流量，27 種 device-type（Table II，2016 Q1 歐洲市售消費性設備），每種重複 setup 20 次、每次後 factory reset，共 540 個指紋 [原文 p.6–7]。非 IoT-23 / CICIoT2023。資料集「available on request for research use」[原文 p.6]，不是公開下載。程式碼：論文未提。

**6. Baseline**：**沒有**與其他辨識系統在同資料上重跑比較；related work 只做文字比較（GTID、Gao et al. 等，說它們不適用低流量設備）[原文 p.9]。enforcement 的 baseline 是「同一台 Pi 有/無 filtering」[原文 Table V–VI]。

**7. Metrics**：辨識正確率（per-type、整體）、混淆矩陣（Table III）、辨識時間（Table IV）、設備間/設備到伺服器延遲（Table V）、CPU 使用率與記憶體 vs 並行 flow 數/規則數（Fig.6, Table VI）。**未量**：throughput、封包速率上限、能耗、傳輸 bytes、任何攻擊偵測指標。

**8. Limitations（作者承認的）**：
- 假設設備使用固定 MAC，否則無法以 MAC 識別 [原文 p.5]。
- 同 AP 的兩台無線設備之間流量走橋接、不經路由層，OVS 管不到，需借 AP 的 wireless isolation + OpenWRT 重導 [原文 p.5]。
- 有外部通道（Bluetooth、LTE）的設備無法由 gateway 控制，只能通知使用者移除 [原文 p.3]。
- 辨識依賴 setup 階段；既有（legacy）安裝要另外處理，需靠設備待機/運作期流量，作者「假設」這些也具特徵性，但尚未驗證 [原文 p.9–10]。
- 軟體更新的影響只在 3 台設備上觀察到，未全面研究 [原文 p.10]。
- 10 種設備辨識率僅約 0.5，作者解釋為同廠牌同硬體/韌體的設備本來就難分、且漏洞共通，所以對目的影響不大 [原文 p.7]。

**9. Research Gap**：
- 作者自述：待機/運作階段的流量能否辨識設備（future work）；軟體更新後的指紋行為；legacy 網路支援 [原文 p.9–10]。
- [推測]：(a) 信任一旦給定（trusted）後沒有執行期監控與撤銷機制，論文未討論；(b) 完全沒有攻擊流量實驗；(c) 沒有「前 N 個封包 vs 準確率」的曲線；(d) 沒有 throughput 量測；(e) 沒有未知設備（被所有分類器拒絕）的偵測評估。

## D. 補充欄位

**D1. 與研究主題對照**
- C1 封包處理：× — 轉送完全交給 OVS，無封包處理優化 [原文 p.5]。
- C2 Flow 資料收集：× — 蒐集的是 setup 階段的逐封包 header 特徵矩陣，不是 flow record [原文 p.3–4]。
- C3 雲端卸載：△（架構上是，目的不同）— 辨識與漏洞評估卸載到 IoTSSP，gateway 只上傳指紋、接收等級 [原文 p.3, p.5]；但卸載的是「設備類型判決」，不是流量 IDS 分析，且每台設備只做一次。
- C4 降成本：△ — 量了 gateway CPU/記憶體開銷（Table VI），沒量傳輸成本。
- K1 轉送效能：部分。量了有/無 filtering 的延遲（Table V，每個設備對 15 次迭代 [原文 p.8]）與 ≤150 並行 flow 的 CPU/延遲（Fig.6）；**沒量 throughput**，延遲的量測方法與流量型態論文未說明。
- K2 資料完整性：× — 不涉及 IDS 資料壓縮；只有辨識準確率。
- K3 即時性：部分。辨識計算 157.7 ms（Table IV）；但指紋需等 setup 結束（1–2 分鐘）才完整 [原文 p.7]。無攻擊 time-to-detection。

**D2. 卸載與資料**
- 送雲端的是**特徵（設備指紋）**：23×n 矩陣，另有固定 276 維版本（前 12 個不重複封包 × 23）[原文 p.3–4]。不含 payload，可用於加密流量 [原文 p.4]。論文未報告指紋 bytes 大小。
- 誰決定送：gateway 在偵測到新 MAC 開始通訊時自動啟動；setup 結束以「封包速率下降」判定，門檻未給 [原文 p.3]。
- 縮減比 / 偵測力損失：論文未報告。

**D3. 成本記帳**
- 地端 CPU/RAM：有（Table VI：CPU +0.63% ±1.8%、記憶體 +7.6% ±4.6%；Fig.6b CPU 約 41–45% 讀圖估計、Fig.6c 記憶體約 28 MB 增至約 50 MB 於 20000 條規則，讀圖估計）[原文 p.8, Fig.6]。能耗：無。
- 傳輸 bytes/頻寬：無。雲端運算：有計時（Table IV）但硬體未說明。
- end-to-end：辨識 157.7 ms ±171.4 [原文 Table IV]；setup 階段 1–2 分鐘 [原文 p.7]。
- 觀察 [推測]：Fig.6b 顯示 0 個並行 flow 時 CPU 已約 41%，表示 OVS + Floodlight 在 Pi 2 上的基礎負載不低，論文未解釋。

**D4. 偵測方法與威脅模型**
- 方法：ML 做設備辨識（Random Forest ×27 + edit distance），漏洞評估靠 CVE 資料庫查詢 [原文 p.3–4]。**不是**攻擊偵測。
- 威脅：設備接入時 benign 但可能有漏洞；攻擊者目標是外洩、橫向攻擊、注入假資料 [原文 p.2]。
- 能否套到 Suricata/Snort 成本模型：[推測] 不能直接套；可借的是控制面機制（雲端判決 → 編譯成本地規則）。

**D5. 實驗可信度**
- 流量：真實設備在受控實驗室重現 setup；不是重播；速率不適用。
- 切分：stratified 10-fold CV 重複 10 次；負類取 10×n 個其他類指紋 [原文 p.6]。未報告折間變異或信賴區間（Fig.5 是否有誤差線：我只看到長條圖，未能確認）。
- 洩漏風險 [推測]：同一實體設備的 20 次 setup 分散在訓練/測試折，是封閉集合（closed-world），不能推論對「別人家同型號設備」或環境差異的泛化。SmarterCoffee/iKettle2 在蒐集期間韌體更新，新舊指紋混在資料中 [原文 p.7]。
- Ablation：n=12 僅說「preliminary analysis concluded」，無數據 [原文 p.4]；特徵無 ablation。
- 公開性：資料需索取；程式碼論文未提。

**D6. 移植到我們平台的障礙**
- Pi 2 上跑 OVS + Floodlight 由作者驗證 [原文 p.8]；Pi 3B+ 是否可行：[推測] 應可（未驗證）。
- 我們用 nftables + NFQUEUE，沒有 OVS；把「MAC → 等級 → 規則」改成 nftables set/map [推測]。
- 本論文非 XDP/eBPF 類，D6 的 XDP 驅動檢查不適用。
- 辨識所需的雲端元件（RF 模型、CVE 對映）需自建；論文未提供。

**D7. 對六個假說方向的證據（僅本論文）**
- Edge–Cloud IDS 分工：弱支持——「gateway 蒐集+強制、雲端判決」分工可行，但判決不是 IDS 偵測。
- Flow Feature Compression：無關（無 flow 壓縮；也無壓縮 vs 準確率實驗）。
- Dynamic Flow Monitoring：無關。
- XDP-eBPF 真正省多少：無關。
- Cloud Data Offloading 成本-時效平衡：弱支持——單次上傳、雲端計算 157.7 ms；無 bytes 數據。
- 不同硬體限制下是否仍有效：僅有 Pi 2 單一硬體、≤150 flows、≤20000 規則 [原文 p.8, Fig.6]；無跨硬體比較。

**D8. 可借用與可改進**
- 可借用：
  1. 三級隔離當作狀態機：strict（未知，無 Internet）/ restricted（限定目的地，如廠商雲）/ trusted [原文 p.5]。
  2. 預設拒絕：未知設備一律 strict [原文 p.3]。
  3. 規則以 hash table 存放、限制 cache 大小並清除不用的規則 [原文 p.5, p.8]。
  4. 只用 header/行為特徵，不依賴 payload [原文 p.4]。
  5. 評估方法：有/無 filtering 對照、隨並行 flow 數與規則數掃描 [原文 Fig.6]。
- 可能的改進（全部 [推測]）：
  1. 加入執行期的信任撤銷，因論文未描述 trusted 之後的監控（對應限制 8、9a）。
  2. 把設備層級信任當作 session 層級信任的先驗，而非取代（對應：device-level 粒度粗、MAC 假設）。
  3. 補量「前 N 個封包 vs 準確率」曲線（對應：n=12 無數據）。
  4. 補 throughput 與基礎 CPU 負載來源分析（對應 D3 觀察）。
  5. 評估未知設備拒絕率與 MAC 偽造情境（對應：未評估 unknown、假設固定 MAC）。

**D9. 引用網路**（Semantic Scholar 至少取回 737 筆引用此文；分頁中途曾遇 429 限流，筆數可能不完整。以下為依標題關鍵字篩選的建議，非全面調查）

1. **DÏoT: A Federated Self-learning Anomaly Detection System for IoT** — Thien Duc Nguyen, Samuel Marchal, Markus Miettinen, Hossein Fereidooni, N. Asokan, Ahmad-Reza Sadeghi。IEEE ICDCS 2019，pp. 756–767，DOI 10.1109/ICDCS.2019.00080（Crossref 確認），arXiv 1804.07474（v5，2019-05-10）。**已確認書目，且我已讀其全文（約 12 頁）**中與信任/放行相關的部分。與信任/放行的關係：
   - 它是 IoT Sentinel 的**後續工作**（同一批作者，且引用 IoT Sentinel）。IoT Sentinel 是「接入時判一次、之後以等級放行」；DÏoT 補上**執行期偵測**：gateway 持續監控每台已辨識設備的通訊，用 device-type 專屬 GRU 模型給每個封包機率，在 w=250 個封包的視窗內異常比例超過 γ 就觸發警報 [DÏoT Sect. III、V-B]。
   - 它**沒有放行/抽樣**：每個封包都被打分；論文把隔離被入侵設備列為「countermeasure 目標」，但**沒有實作**隔離，只評偵測 [DÏoT Sect. II-B]。
   - 數字：偵測率 95.6%、平均偵測延遲 257±194 ms（Mirai 各階段）、一週真實智慧家庭部署（14 台設備、10 種類型）0% FPR（參數 δ=0.01、γ=0.5、w=250）；pre-infection 階段約 223 個封包即偵測（Mirai 該階段產生超過 900 個）[DÏoT Sect. VI-A]。每個封包推論 0.592 ms（筆電 i7-4600 CPU）/0.081 ms（桌機 GPU）；沒有 Pi 數據 [DÏoT Sect. VI-E]。
   - 與我們的關係：它的假設 A1（設備出廠時 benign、可學正常行為）與「開頭 benign 後來變壞」同構；它對 mimicry 的回應是「device-type 專屬模型使攻擊者難以模仿」（Sect. VII-C）。這是支持「持續監控能抓先乖後壞」的證據，但代價是每個封包都過模型，與我們想省成本的方向相反。
2. **IoT-KEEPER: Detecting Malicious IoT Network Activity Using Online Traffic Analysis at the Edge** — Ibbad Hafeez, Markku Antikainen, Aaron Yi Ding, Sasu Tarkoma。IEEE TNSM 17(1)，2020，pp. 45–59，DOI 10.1109/TNSM.2020.2966951（Crossref 確認）。理由：IoT Sentinel 共同作者的後續，邊緣 gateway 上的線上流量分析；與「gateway 本地偵測」同題。**內容未讀，僅確認書目與標題。**
3. **AuDI: Toward Autonomous IoT Device-Type Identification Using Periodic Communication** — Marchal, Miettinen, Nguyen, Sadeghi, Asokan。IEEE JSAC 37(6)，2019，pp. 1402–1412，DOI 10.1109/JSAC.2019.2904364（Crossref 確認）。理由：後續改進者，標題顯示以週期性通訊辨識，對應 IoT Sentinel 的 setup 階段限制。**內容未讀。**
4. **Early-Stage IoT Device Identification Using Passive Network Traffic Analysis** — Ciechonski, Palmese, Redondi, Mandalari。IFIP Networking 2026，pp. 1–6，DOI 10.23919/IFIPNetworking70592.2026.11579207（Crossref 確認；S2 顯示引用 IoT Sentinel）。理由：同題更貼近「只看開頭就決定」的準確率與所需封包數。**內容未讀。**
5. **NOS-Gate: Queue-Aware Streaming IDS for Consumer Gateways Under Timing-Controlled Evasion** — Bilal, Tariq, Ahmed。IEEE Trans. Consumer Electronics，2026-05，pp. 4788–4798，DOI 10.1109/TCE.2026.3682516（Crossref 確認；S2 顯示引用 IoT Sentinel）。理由：標題顯示 gateway IDS 的時序規避，可能對應 T4。**僅憑標題判斷相關，內容未讀，可能不相關。**

## T. 信任式 Fast Path 專屬欄位

**T1 判定依據與時點**：依據是 ML 辨識（Random Forest + edit distance）加上 CVE 查詢：有已知漏洞→restricted、無已知漏洞→trusted、未知→strict [原文 p.3]。時點是 setup 階段結束後（setup 歷時 1–2 分鐘 [原文 p.7]）；分類只用前 12 個不重複封包，但約 55% 的指紋需要用完整指紋做 edit distance [原文 p.4, p.7]。論文**未給** N vs 準確率；也未說明辨識完成前設備的存取等級（只有 legacy 流程明說起始為 untrusted [原文 p.10]）。

**T2 放行後可見性**：論文只描述以 MAC 為 key 的允許/拒絕規則 [原文 p.5]。對 trusted 設備，沒有描述抽樣、計數、flow record 或回溯 buffer；論文未說明。

**T3 撤銷**：論文**未描述**執行期撤銷。僅有間接機制：enforcement cache 可由定期查詢更新（restricted 的 IP 清單）[原文 p.5]；漏洞評估可用 crowdsourced 事件交叉比對更新 [原文 p.3]；韌體更新會改變指紋、導致重新辨識 [原文 p.7]。反應時間未量。

**T4 規避風險**：
- 作者的威脅模型明說設備「接入時 benign」[原文 p.2]，也明說本系統是 **preventive**，在惡意通訊開始前減輕風險 [原文 p.8]。「先正常後攻擊」的設備若無已知漏洞→trusted，其後被攻陷的情形，論文**未討論、未量測**。
- 沒有「攻擊放在 cutoff 之後」、「抽樣漏報」的討論；全文無攻擊流量實驗。
- [推測] 規避路徑：(a) 零日漏洞設備被判 trusted；(b) 偽造 MAC/重放 setup 流量取得較寬鬆等級（論文自承假設固定 MAC [原文 p.5]，但未討論偽造）；(c) 設備型號被誤判為近似型號（Table III 顯示同廠牌相近型號混淆，作者認為因漏洞共通而可接受 [原文 p.7]）。
- 後續 DÏoT 以執行期偵測補此缺口（見 D9）。

**T5 量化效益**：被放行的 flow/bytes 比例：論文未報告。省下的資源：無；本文不是為省成本設計。偵測損失：不適用（無偵測評估）。可引用的僅有 enforcement 開銷（Table VI）。

**T6 對我們構想的意涵**（全部 [推測]）：
- 支持：「由雲端判一次、結果編譯成 gateway 本地規則」的機制可行且在 Pi 級硬體上開銷小（≤150 flows、≤20000 規則 [原文 Fig.6]）；三級狀態 + 預設拒絕可直接當作 session 狀態機的藍本。
- 無法支持：「只看開頭就決定」的**安全性**——論文沒有任何攻擊或規避實驗，不能拿來證明開頭判定足夠。
- 反駁 / 差異：它是**設備層級**、判定後無監控；我們是 session 層級、且要抽樣與撤銷，這兩項在本文是空白，不是已有結論。
- 設計建議：保留 restricted 概念作為「放行但限目的地」的中間級；撤銷與抽樣需另找文獻（如 DÏoT 的視窗式偵測，或 Suricata 的 bypass/cutoff 類文獻）。

## E. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| 設備類型數 / 指紋數 | 27 types / 540 | 每型 20 次 setup | [原文 p.6–7] |
| 整體辨識正確率 | 0.815 | stratified 10-fold CV ×10 | [原文 p.7] |
| 準確率 >0.95 的設備數 | 17 | 同上 | [原文 p.7] |
| 準確率約 0.5 的設備數 | 10 | 同廠牌近似型號互混 | [原文 p.7, Table III] |
| 需 edit distance 仲裁比例 | 55% | 每次 2–5 型候選 | [原文 p.7] |
| 單次 RF 分類時間 | 0.014 ms ±0.003 | 硬體未說明 | [原文 Table IV] |
| 單次 edit distance | 23.36 ms ±24.37 | 同上 | [原文 Table IV] |
| 指紋抽取 | 0.850 ms ±0.698 | 同上 | [原文 Table IV] |
| 平均辨識總時間 | 157.7 ms ±171.4 | 平均 7 次 edit distance | [原文 Table IV] |
| setup 階段長度 | 1–2 分鐘 | 封包蒐集同步進行 | [原文 p.7] |
| 延遲（有/無 filtering） | 例：D1→D4 24.8 / 24.5 ms；D3→Sremote 20.6 / 19.9 ms | Pi 2，15 次迭代，Sremote 在 Amazon EC2 | [原文 p.8, Table V] |
| filtering 額外開銷 | D1D2 延遲 +5.84% ±4.76%；D1D3 +0.71% ±5.88%；CPU +0.63% ±1.8%；記憶體 +7.6% ±4.6% | 同上 | [原文 Table VI] |
| 並行 flow 上限 | 約 150 | 延遲、CPU 掃描範圍 | [原文 p.8, Fig.6a–b] |
| 規則數上限 | 約 20000 | 記憶體掃描範圍；約 28 MB→約 50 MB（讀圖估計） | [原文 Fig.6c] |
| CPU 使用率 | 約 41%→約 45%（讀圖估計） | 0→140 flows | [原文 Fig.6b] |
| throughput | 未量 | — | — |

## F. 自評

**未能確認的欄位**：IoTSSP 與 Table IV 計時的硬體；Pi 2 規格；延遲的量測方法（工具、封包大小、流量型態）；Fig.5 是否有誤差線；指紋 bytes 大小；是否有程式碼公開；IEEE 出版版與 arXiv v2 的差異。D9 第 2–5 篇只確認書目，未讀內容。

**最不確定的三件事**：
1. 我讀的是 arXiv v2 而非 IEEE 版，圖表數值（Fig.6 的 CPU/記憶體）是讀圖估計，不是表列數字。
2. 「論文未討論執行期撤銷與規避」是基於我讀完全文未見相關段落；若 IEEE 版有增補（例如討論攻擊情境），此結論需修正。
3. 把設備層級的辨識與放行，類比到 session 層級的信任，屬於我的推測；兩者的威脅模型與時間尺度差距很大（setup 一次 vs 每條連線），T6 的建議可能高估了可借用程度。
