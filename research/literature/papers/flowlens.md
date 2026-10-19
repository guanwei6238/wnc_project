# FlowLens

## A. 書目與取得狀況

- 標題：FlowLens: Enabling Efficient Flow Classification for ML-based Network Security Applications
- 作者：Diogo Barradas, Nuno Santos, Luís Rodrigues, Salvatore Signorello, Fernando M. V. Ramos, André Madeira（INESC-ID / IST, Universidade de Lisboa；Signorello 為 LASIGE）[原文 p.1]
- 年份 / 出處：NDSS Symposium 2021（2021-02-21~24，San Diego）[原文 p.1]
- DOI：10.14722/ndss.2021.24067 [原文 p.1]
- URL：https://www.ndss-symposium.org/ndss-paper/flowlens-enabling-efficient-flow-classification-for-ml-based-network-security-applications ；全文 PDF：https://cs.uwaterloo.ca/~dbarrada/papers/barradas_ndss21.pdf ；程式碼：https://github.com/dmbb/FlowLens

與給定資訊的差異：給定「NDSS 2021，主題為在網路設備中低成本收集 Flow 特徵」。書目（NDSS 2021）正確。主題描述不完整：FlowLens 的對象是 **Barefoot/Intel Tofino P4 可程式交換器**，不只「收集特徵」，還在交換器控制平面（switch CPU）上**直接做 ML 分類**，目標是 ML 式安全應用（covert channel / website fingerprinting / botnet）[原文 p.1, p.7]。它不是 IoT gateway 論文，也不是 IDS 卸載論文。

取得程度：**全文**（下載 PDF 並以 pdftotext 閱讀；頁碼為 PDF 頁碼，與印刷頁碼相同）。GitHub 僅用 WebFetch 看頁面摘要，未下載程式碼。

## B. 核心貢獻（≤3 條）

1. **Flow marker**：用 quantization（封包長度/IPT 右移 QL 位元合併成粗 bin）加 truncation（只保留對分類最重要的 top-N bin）得到固定大小、低記憶體的 per-flow 封包長度/到達間隔分佈摘要 [原文 p.2, p.5]。
2. **Flow Marker Accumulator (FMA)**：只用位元位移、exact-match 表與 register 加一即可在 PISA 資料平面實作，換用途時由控制平面改表項，不必重載 P4 程式（避免交換器 downtime）[原文 p.3-5, p.8]。
3. **Automatic profiler**：以 Bayesian optimization（Hyperopt）搜尋 (QL, truncation) 參數，支援三種準則：給定準確率求最小 marker、給定大小求最高準確率、reward = α·accuracy + (1-α)/size [原文 p.6-7]。

## C. 指定的 9 項

**1. Research Problem**
現有交換器上的安全方案都綁定單一任務；要支援「用封包長度/到達間隔分佈 + 監督式 ML」的一類應用，完整分佈太耗交換器有限的 SRAM，而把特徵外送到伺服器又耗頻寬 [原文 p.1-3]。問題是：在 SRAM 與指令集受限下，用多小的 per-flow 表示仍能維持分類準確率。

**2. Architecture**
```
Flows -> [Tofino ASIC 資料平面: FMA (flow table / truncation table / register grid)]
              |  控制平面讀取 flow markers（collection window 結束後批次讀）
              v
         [Switch CPU: collector + classifier (ML 模型)] -> 分類結果給 operator
         [離線 Profiler Server: 訓練集 + 分類器 -> FMA 參數 (QL, truncation)]
```
- Packet 層：資料平面逐封包做 flow table lookup、quantization、truncation、register +1 [原文 p.5]。
- Flow 層：collector 以 FCFS 為新 flow 配置 marker；滿了就裝 wildcard ignore rule；window 結束批次讀取並清空 [原文 p.5]。
- Edge/Cloud：**沒有雲端**。分類在 switch 控制平面完成，只輸出每 flow 分類分數；作者刻意避免依賴 edge middlebox 或外送到專用伺服器 [原文 p.3]。

**3. Processing Location**
交換器資料平面（ASIC，P4_16 約 500 行）做收集；交換器控制平面 CPU 做分類；Profiler 在獨立伺服器離線執行 [原文 p.4, p.7]。無 Kernel/User space 之分。

**4. Hardware**
- 資料平面：Barefoot/Intel Tofino ASIC；SRAM 容量因 NDA 不揭露，作者引用他處稱「數百 MB」[原文 p.9]。
- 控制平面：Intel Broadwell 8 核 2 GHz，32 GB RAM [原文 p.9]。
- 無 ARM / Raspberry Pi / 低功耗設備實驗。

**5. Dataset**
- Covert channel：作者自行錄製的 Skype 流量，含 Facet 與 DeltaShaper 隱蔽通道（平衡的 covert/legit 樣本）[原文 p.8]；公開程度論文未說明，未能確認。
- Website fingerprinting：Herrmann et al. 的 OpenSSH 網頁存取 trace，公開資料集 [原文 p.9]。
- Botnet：Rahbarinia et al. 的 P2P 流量（uTorrent/Vuze/Frostwire/eMule 對 Waledac/Storm）[原文 p.9]。
- 皆非 IoT-23 / CICIoT2023，也非真實部署流量。分類是「在軟體中模擬」依樣本計算，而非實際讓流量通過 Tofino 後分類 [原文 p.9]。

**6. Baseline**
- 壓縮方法：Online Sketching (OSK, Coskun et al.) 與 Compressive Traffic Analysis (CTA, Nasr et al.)，比較準確率對 marker 大小的 Pareto 前緣；兩者需矩陣乘法/浮點，交換器無法實作，故只在準確率層面比較 [原文 p.12]。
- 遙測外送方案 *Flow：只做**分析式估算**，非實測 [原文 p.12-13]。
- 內部基準：未壓縮（QL=0、不 truncation）的完整分佈 [原文 p.9]。
- 沒有在同一硬體重跑別人的系統。

**7. Metrics**
Accuracy、FPR、FNR、precision、recall [原文 p.8]；marker 大小（bytes）與可監控 flow 倍數 [原文 p.9]；資料平面資源用量 [原文 p.9]；分類單 flow 延遲中位數；模型記憶體；通訊量（估算）。**未量**：交換器吞吐、轉送延遲、能耗、端到端 time-to-detection。

**8. Limitations（作者承認）**
- 新 flow 在控制平面裝好規則前的封包會被漏掉 [原文 p.5]。
- 讀取並重設 register 需數秒，期間無法收集，需級聯多台交換器交錯 window [原文 p.6]。
- 一個 FMA 同時只載入一個 profile，多應用需多台交換器 [原文 p.6]。
- 因 truncation 需特徵排名，只用單次 50/50 holdout 而非 cross-validation [原文 p.9]。
- 過度粗的 marker 會讓準確率陡降（例如 QL=7）[原文 p.10]。
- 防禦措施（ensemble / 隨機化分類器）的效能開銷未實測 [原文 p.14]；對抗式 ML 防禦不在本文範圍 [原文 p.13]。
- 全空間窮舉 botnet 任務耗時一天，profiler 僅得近似最佳 [原文 p.6]。

**9. Research Gap**
- 作者自述：多 profile 並行、對抗式 ML 強健性、最佳化器改良屬後續（"outside the scope"）[原文 p.6, p.13]。
- [推測]：(a) 完全沒有雲端卸載與「何時送」的決策機制；(b) 沒有串流/即時量測，collection window 加批次讀取使偵測延遲至少是一個 window，且未量 TTD；(c) 僅評估三類 ML 任務，沒有針對 IoT 攻擊（DDoS、掃描、C2）的評估，也沒有與規則式 IDS 的整合；(d) 假設專用 ASIC，軟體低階裝置上的成本模型完全空白。

## D. 補充欄位

**D1. 與研究主題對照**
- C1 封包處理：△ — 逐封包 shift + 表查找 + register 加一，設計簡單，但目標是 ASIC 而非 Linux 封包路徑 [原文 p.5]。
- C2 Flow 資料收集：○ — 核心貢獻是壓縮的 flow marker [原文 p.2]。
- C3 雲端卸載：× — 刻意不外送，只比較外送成本 [原文 p.3, p.12-13]。
- C4 降成本：△ — 降的是交換器 SRAM（20~302B vs 3000~10200B/flow）與外送頻寬，不是 Pi 類設備的 CPU/能耗 [原文 p.9]。
- K1 轉送效能：未量測。僅報資源用量（Table II），並主張 SRAM 剩 60% 以上可與其他轉送功能共存 [原文 p.9]；ASIC 線速是設計前提，非實驗結果。
- K2 資料完整性：有量，且是主軸，用準確率/FPR/FNR 對 marker 大小（Fig. 6-11）。
- K3 即時性：只量「收集完成後分類單 flow 100~200 µs」[原文 p.9]；collection window 長度與讀取需數秒的影響未量成偵測延遲。

**D2. 卸載與資料**
- 送到雲端的東西：無雲端。若類比，送出的是「判決結果」：每 flow 13B flow ID + 4B 分數 [原文 p.13]。
- 誰決定、依據什麼：沒有卸載決策。收集階段由 collector 決定 FCFS / 允許-拒絕清單 / LRU 淘汰 [原文 p.5-6]；與信心值無關。
- 縮減比與偵測力損失：marker 3000B→20B（150×），準確率 93%，比完整分佈低 3%（covert channel）[原文 p.9, p.11]；網站指紋 32×、botnet 34× 且準確率損失「至多 3%」[原文 p.9]。外送量估算：*Flow 約 7.78 GB / window，FlowLens 約 4.25 MB，約三個數量級，前提為 250k 並行 flow、每 flow 15k 封包、30 秒 window，且是紙上估算 [原文 p.12-13]。

**D3. 成本記帳**
- 地端運算：資料平面資源以百分比（Match xBar 8.46%、Gateway 5.21%、VLIW 3.39%、TCAM 0%、SRAM 38.54%）[原文 Table II]；控制平面模型記憶體最大 140 MB（botnet），covert channel 64 KB [原文 p.9]。無 CPU 使用率、能耗。
- 傳輸：僅估算（見 D2）。
- 雲端運算：N/A。
- time-to-detection / 端到端延遲：未量測。

**D4. 偵測方法與威脅模型**
ML 監督式：XGBoost、Multinomial Naive Bayes、Random Forest [原文 p.8]；特徵為封包長度分佈與 IPT 分佈，不需解密或 payload [原文 p.2]。偵測隱蔽通道、網站指紋、P2P botnet。成本模型能否套用到 Suricata/Snort：[推測] 不能直接套用。規則式 IDS 的成本在 payload 比對與規則數，而非 per-flow 分佈記憶體；但「先在地端算輕量 flow 統計，用以決定哪些流量進深度檢測」的分流想法可能有參考價值。

**D5. 實驗可信度**
- 流量：錄製資料集的離線模擬，非即時、非重播到實體交換器 [原文 p.9]；速率範圍：論文未說明。
- 重複次數 / 變異量：單次 50/50 holdout，未報信賴區間 [原文 p.9]；profiler 的 Bayesian 迭代次數 i=10 或 4 [原文 p.12]。
- Ablation：有 quantization 單獨、truncation 單獨效果（Fig. 6-10）。
- 洩漏檢查：truncation 的 top-N 特徵排名在訓練集上預訓練取得，論文未明確說明排名是否排除測試資料，未能確認。
- 公開性：GitHub 有 FMA 的 P4_16 改寫版（跑在 BMv2，完整 Tofino 版因 NDA 未公開）與安全任務評估程式；資料集未隨附，需看各子目錄 README（WebFetch 摘要，[二手]）。

**D6. 移植到我們平台的障礙**
- 依賴：Tofino ASIC 與 P4 Studio；Pi 3B+ 沒有可程式資料平面。
- 能否在 Pi 3B+ 上直接跑：不能（[推測]，未驗證）。
- 概念層面可移植（[推測]）：位移量化 + 查表 truncation + 計數器陣列，在 userspace 或 eBPF map 中幾乎不費運算。每 flow 20~302 B 在 1 GB RAM 下不是瓶頸，瓶頸會是 NFQUEUE 逐封包進 userspace 的成本，論文對此沒有任何資料。
- 非 XDP 論文，故不展開 USB 網卡驅動。

**D7. 對六個假說方向的證據**
- Edge–Cloud IDS 分工：無關／間接。論文主張全部在交換器完成，並以估算說明外送原始特徵的頻寬代價 [原文 p.12-13]；沒有分工實驗。
- Flow Feature Compression：支持。多任務下 marker 縮小 1~2 個數量級、準確率損失至多 3% [原文 p.9]；同時也顯示過度壓縮會陡降（QL=7）[原文 p.10]。
- Dynamic Flow Monitoring：部分。有 discretionary filtering、window 調整、LRU 的設計描述 [原文 p.5-6]，無實驗。
- XDP-eBPF 真正省多少：無關。
- Cloud Data Offloading 成本-時效平衡：無關（僅有外送量估算，無時效量測）。
- 不同硬體限制下是否仍有效：無證據（只在 Tofino 上）。

**D8. 可借用與可改進**
可借用：
- 以位移量化 + top-N 特徵 truncation 做壓縮（[原文 p.5]），profiler 的 reward = α·acc + (1-α)/size，α=0.5（[原文 p.7]）。
- 用分類器特徵重要性排名決定保留哪些 bin（[原文 p.6-7]）。
- 與 OSK/CTA 比 Pareto 前緣的評估方法（[原文 p.12]）。
- 外送量估算公式（[原文 p.12-13]）可改成我們的 flow record 外送量比較。

可能改進（皆 [推測]）：
1. 把 marker 在 Pi 上以 user space 或 eBPF map 實作，並量 CPU/RAM/吞吐——基於「K1 未量測、硬體限定 Tofino」。
2. 將 marker 作為雲端卸載的觸發條件（本地輕量分類，低信心才送 flow record）——基於「無卸載決策機制」。
3. 以流式或短 window 取代批次讀取，並量 time-to-detection——基於「讀取需數秒、K3 未量」。
4. 對 IoT 攻擊資料集（IoT-23 / CICIoT2023）重做壓縮-準確率曲線——基於「資料集非 IoT」。
5. 加入 cross-validation 與信賴區間——基於「單次 holdout」。

**D9. 引用網路（建議追加閱讀）**
1. Sonchack et al., "Scaling Hardware Accelerated Network Monitoring to Concurrent and Dynamic Queries With *Flow," USENIX ATC 2018 — FlowLens 比較的「外送 GPV 到伺服器」基準，與雲端卸載成本議題最貼近。存在確認：頁面確認（https://www.usenix.org/conference/atc18/presentation/sonchack），DOI 未驗證。
2. Zhou et al., "An Efficient Design of Intelligent Network Data Plane"（NetBeacon），USENIX Security 2023, pp.6203-6220 — 後續於交換器上做 per-flow 狀態與 ML 的方法，屬替代方案/後續者。存在確認：USENIX 頁面確認，DOI 未驗證。
3. Mittal, Kotha, Krishna, Tammana, "AdaFlow," IFIP Networking 2024 — 同樣處理「分類準確率 vs 記憶體」權衡，在 Tofino 上評估，屬後續者。存在確認：搜尋找到 PDF（https://dl.ifip.org/db/conf/networking/networking2024/1571003969.pdf），標題完整書目與 DOI 未驗證；未讀內容，與 FlowLens 的比較數字未知。
4. Nasr, Houmansadr, Mazumdar, "Compressive Traffic Analysis," ACM CCS 2017 — FlowLens 的壓縮基準之一，來自 FlowLens 參考文獻 [55]。存在確認：僅見於 FlowLens 引用，書目細節未驗證。
5. Coskun et al., Online sketching of network flows（FlowLens 參考文獻 [22]）— 另一壓縮基準。存在確認：僅見於 FlowLens 引用，完整書目未驗證。

## E. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| Covert channel marker 大小 | 20 B vs 3000 B（150×），準確率 93%，比完整分佈低 3% | QL=4, Top-N=10；XGBoost；Facet | [原文 p.9, p.11, Table I] |
| Website fingerprinting marker | 94 B vs 3000 B（32×） | QL=5；Multinomial NB | [原文 Table I] |
| Botnet marker | 302 B vs 10200 B（34×） | QL_PL=4, QL_IPT=6；Random Forest | [原文 Table I] |
| Botnet recall | 0.96 vs 完整資訊 0.99 | 同上 | [原文 p.11] |
| QL=4 covert channel 準確率 | Facet 下降不到 5%，DeltaShaper 下降不到 1%；marker 188 B | 全部 bin 量化 | [原文 p.10] |
| QL=7 準確率落差 | Facet 超過 20%、DeltaShaper 超過 10% | | [原文 p.10] |
| Website 單站 amazon.com | FPR 0.016%，FNR 9.333%，壓縮 17.2×（1500:87 bins） | QL=4，手動 bin 選擇 | [原文 p.11] |
| 資料平面資源 | Match xBar 8.46%、Gateway 5.21%、VLIW 3.39%、TCAM 0%、SRAM 38.54%，SRAM 尚餘 60% 以上 | Tofino，平均跨 stage | [原文 Table II, p.9] |
| 分類延遲 | 中位數約 100~200 µs / flow | Covert channel，switch CPU Broadwell 8 核 2 GHz | [原文 p.9] |
| 控制平面模型記憶體 | Botnet 140 MB（壓縮儲存 5.6 MB）；covert channel 64 KB（儲存 24 KB） | 32 GB RAM | [原文 p.9] |
| 外送量（估算） | *Flow 7.78 GB / window vs FlowLens 約 4.25 MB | 250k flow，15k 封包/flow，30 秒 window | [原文 p.12-13] |
| Profiler 搜尋時間 | 全空間搜尋 botnet 約一天；Bayesian 優化約數小時 | | [原文 p.6, p.7] |
| 與 OSK 比較 | DeltaShaper：FlowLens 最高 0.89（10 bins），OSK 最準 0.76（16 bins） | | [原文 p.12] |
| 自動 profiler 輸出 | Facet：10 bins，準確率 0.944，比最佳低 1.6% 且小 37× | i=10 | [原文 Table V, p.12] |

## F. 自評

未能確認的欄位：
- Covert channel 資料集是否公開、取樣流量速率與規模：論文未說明。
- Top-N 特徵排名是否與測試集隔離（資料洩漏問題）：論文未明述。
- 實際通過 Tofino 的吞吐、延遲、封包漏失：論文未量。
- Tofino SRAM 絕對容量：受 NDA 限制，論文未揭露。
- cited-by：未能查詢 Semantic Scholar/OpenAlex 的完整引用清單，D9 的後續論文來自一般網路搜尋，其中 AdaFlow 只讀到搜尋摘要。

最不確定的三件事：
1. Pi 3B+ 上的可移植性評估全為 [推測]，論文沒有提供非 ASIC 的成本數據。
2. D9 中 AdaFlow、NetBeacon 與 FlowLens 的實際比較關係，我沒有讀這兩篇全文。
3. GitHub 程式碼與資料的公開範圍，只用 WebFetch 摘要判斷（[二手]），未實際檢視。
