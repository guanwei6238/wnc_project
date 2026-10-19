# host-aggregation-ids（Katsura et al., IEEE Access 2025）

頁碼約定：`[原文 p.N]` 的 N 是 PDF 實際頁碼（共 14 頁）；IEEE 印刷頁碼 = 125405 + N（PDF p.1 = 125406）。標「讀圖」的數字是從長條圖目測，已渲染放大核對，誤差約 ±1 格刻度。

## A. 書目與取得狀況
- 標題：Efficient IDS for IoT Networks Using Host-Based Data Aggregation and Multi-Entropy Analysis
- 作者：Yusei Katsura, Arata Endo, Ismail Arai, Kazutoshi Fujikawa（NAIST）[原文 p.1]
- 出處：IEEE Access, vol. 13, pp. 125406–125419, 2025；received 5 Jun 2025, accepted 5 Jul 2025, published 14 Jul 2025 [原文 p.1, p.14]
- DOI：10.1109/ACCESS.2025.3589057；CC BY 4.0 [原文 p.1]
- URL：https://doi.org/10.1109/ACCESS.2025.3589057

**與給定資訊的差異：** 給定標題少了後半「and Multi-Entropy Analysis」；其餘（作者、年份、期刊、DOI、頁碼 125406–125419）與全文一致 [原文 p.1, p.14]。
**取得程度：全文**（使用者提供的 PDF，複製到 scratchpad 以 pdftotext 逐頁抽取；表格與圖為渲染後目視）。

## B. 核心貢獻（≤3 條）
1. 把偵測單位從 packet / flow 改成 host（source IP），每個固定時間窗為每個 source IP 產生一列特徵，使輸入列數不隨 flow 組合數膨脹 [原文 p.4, p.6]。
2. 只用 7 個特徵（5 個 entropy + 封包數 + 位元組數）配 XGBoost，10 s 窗、10-fold CV 準確率 99.97% [原文 p.6, p.8]。
3. 在 Raspberry Pi 3B+ 量推論時間、在 Xeon 伺服器量記憶體峰值，相對 AD-IoT 與 Alani 式 flow-based IDS 報告大幅下降 [原文 p.7–9]。

## C. 指定的 9 項
1. **Research Problem**：packet/flow-based ML IDS 在 DoS/DDoS 下輸入列數暴增，造成 gateway 記憶體與處理時間負擔，甚至影響封包轉送 [原文 p.2, p.4]；flow-based 特徵需等 session 結束或 timeout，對持續送包或無 session 的 UDP 裝置不即時 [原文 p.2, p.4]。
2. **Architecture**：四階段——(1) 固定時間窗收集封包 → (2) 依 source IP 分類 → (3) 每個 host 算特徵 → (4) XGBoost 判該 host 正常/異常 [原文 p.6, Fig.1]。假設部署在 IoT gateway，與 IoT 裝置同一網段（無 NAT），所以 source IP 能對應到個別裝置 [原文 p.4]。無 edge–cloud 分工，論文未涉及雲端。
3. **Processing Location**：假設在 gateway 本地執行 [原文 p.4]；實驗中特徵由離線 Python 腳本處理切好的 pcap（flow 特徵用 Zeek），不是 kernel/NFQUEUE/即時擷取 [原文 p.7, Fig.3]。
4. **Hardware**：見 Q2。實際平台為 Raspberry Pi 3 Model B+（推論時間）與雙 Xeon 伺服器（訓練、測試、記憶體）[原文 p.7–8, Table 5/6]。
5. **Dataset**：Bot-IoT（UNSW Canberra）與 CIC IoT Dataset 2022（60 個 IoT 裝置、約 3 個月）；皆公開、皆為 pcap 離線檔；不是 IoT-23 或 CICIoT2023 [原文 p.7]。
6. **Baseline**：AD-IoT（Random Forest，12 特徵）與 Alani 式 Flow-based IDS（XGBoost，5 個 Zeek 特徵）；兩者由作者在同資料上自行重現 [原文 p.6–7, Table 4]。Alani 原方法的 packet-based 部分被刻意省略 [原文 p.7]。
7. **Metrics**：準確率（10-fold CV）、推論時間、記憶體峰值、模型大小 [原文 p.8–9, p.11]。
8. **Limitations（作者承認）**：見 Q7。
9. **Research Gap**
   - 作者自述：entropy 被操縱的攻擊、slow scan 難偵測；sliding window 與最佳窗寬待研究；可能再減特徵 [原文 p.12]。
   - [推測]：見 D8。

## Q1–Q9 明確回答

**Q1 三個數字的完整條件**（皆為 10 s 窗那一個模型 [原文 p.8–9]，但**不是同一個運作點**）
- Baseline：「99.7%」是對 **AD-IoT（RF、12 特徵）** 的平均處理時間 2924 ms vs 提案 8.46 ms，差 2916 ms（2916/2924 = 99.7%）[原文 p.8]。對較公平的 **Flow-based IDS（同為 XGBoost）** 是 263 ms vs 8.46 ms，論文只寫「少 263 ms」[原文 p.8, p.10]；換算約 96.8% [推測，算式 (263−8.46)/263]。
- 「最多」的真相：摘要的「maximum reduction」其實是「相對較差的 baseline（AD-IoT）」且是**各類別平均**，不是最壞類別 [原文 p.8, Fig.5 "Average"]。單看 DDoS TCP，AD-IoT 約 4×10^4 ms（讀圖），降幅更大。
- 記憶體 86.4%（633 MiB）：= (733−100)/733，733 MiB 是 AD-IoT 的**最大值**（Fig.6 DDoS TCP 類別）、提案約 100 MiB 且各類別持平 [原文 p.9, p.11]。這是**最大類別**，與時間的「平均」口徑不同。對 Flow-based IDS 最多省 270 MiB [原文 p.11]（Flow-based 峰值約 370 MiB，讀圖；約 73% [推測]）。
- 硬體：**時間在 Pi 3B+ 量，記憶體與訓練/準確率在 Xeon 伺服器量** [原文 p.7]。所以三個數字來自兩台機器、兩種彙總方式（平均 vs 最大）。
- 範圍：「推論時間」只計「特徵送入模型到輸出結果」，**不含特徵產生**（Zeek 或自寫 Python 的分類/entropy 計算）[原文 p.8]；以 Python `time` 量。
- 輸入：每類別取檔案大小前 100 大的 pcap（16 類 × 100 = 1,600 檔），偏向最大檔 = DoS/DDoS 的最壞情況 [原文 p.8]。「每個 dataset 輸入模型」的量測單位疑似是整個檔案批次而非每筆 [推測：原文為 "each dataset ... was input"，未說明單位]。

**Q2 硬體、資料集、窗長**
- Table 1（OpenBlocks IoT VX2：Atom E3805 1.33GHz/2GB；Armadillo-IoT G4：Cortex-A53 1.6GHz/2GB；CONEXIO BlackBear：Cortex-A9 1.0GHz/2GB）**只是商用 gateway 規格參照**，用來論證「現有 DL 模型放不進」[原文 p.2, p.4, Table 1]，**不是實驗平台**。
- 實際：Pi 3 Model B+，Cortex-A53、1 GB、Debian 12、Python 3.9.12、scikit-learn 1.4.1、xgboost 2.1.2（表中誤植 "Coretex-A53"，時脈未寫）[原文 p.7–8, Table 6]；伺服器 2× Xeon Gold 6238L、6 TB RAM、RHEL 8.10 [原文 p.8, Table 5]。
- 注意：Pi 的 1 GB 小於 Table 1 的 2 GB 機器；記憶體 100 MiB 並**不是在 Pi 上量的**。
- 資料集：Bot-IoT 與 CIC IoT 2022（pcap），用 editcap 切成 1–30 s 檔 [原文 p.7, Fig.2]。時間窗掃 1–30 s，**10 s 準確率最高**被選用 [原文 p.8]。

**Q3 host 聚合**
- 單位：source IP 為 host；每窗每 host 一列 7 特徵：dst IP entropy、src port entropy、dst port entropy、packet size entropy、transmission time interval entropy、傳送封包數、傳送位元組數 [原文 p.5–6, Table 3]。
- 時間窗：固定 1–30 s，採用 10 s [原文 p.8]。
- 狀態位置：論文只描述概念上的「收集 → 分類 → 抽特徵」，**未說明**在 gateway 內存的資料結構、per-host 狀態大小、記憶體如何隨 host 數成長，也未量測（量的是分類階段的程序峰值）。
- 位置：假設在 gateway，且須無 NAT，否則多裝置會被合成同一個 host [原文 p.4]。
- time-to-detection：**未量測**。論文只在質性上說明：flow-based 要等 session 結束/timeout（p.2, p.4）、前作需 5 分鐘窗不適用（p.3, p.5）；承認提案「每個偵測週期在收集期結束後才開始」，將 sliding window 列為未來工作 [原文 p.12]。[推測] 最壞偵測延遲 ≥ 窗長（10 s）+ 處理時間。

**Q4 Multi-entropy**
- 5 個 entropy：dst IP、src port、dst port、packet size、transmission time interval（Shannon，Eq.1，機率 = 該值在窗內出現次數/窗內總封包數）[原文 p.6]。src IP entropy 因 host 固定而捨去；前作的 data-size entropy 因需先分 flow 而捨去 [原文 p.5]。
- 特徵重要度：time interval entropy 0.3592、packet size entropy 0.3122、src port entropy 0.0923（前三名）[原文 p.9, Table 7]。
- 資料集中的攻擊：Bot-IoT 的 DDoS/DoS（TCP/UDP/HTTP）、OS scan、service scan、keylogging、data exfiltration；CIC IoT 2022 的 DoS（HTTP/UDP/TCP）與 RTSP brute force [原文 p.7, Fig.5 類別]。
- 不擅長（作者承認）：攻擊者操縱封包間隔/大小/數量使 entropy 不變；slow scan [原文 p.12]。1 s 窗準確率掉到約 93.6%（讀圖，Fig.4；文字稱 1 s 下降 p.10）。
- 注意：各 Bot-IoT 攻擊類別的**偵測率沒有單獨報告**，Fig.5 只有時間；Table 8 是 CIC 的各裝置類型準確率（98.7–100%）[原文 p.10]。

**Q5 轉送效能/雲端卸載**：兩者**都沒有**。無 throughput、轉送 latency、CPU 使用率、能耗；無雲端、無上傳量。「影響封包轉送」只作為動機敘述 [原文 p.2, p.4, p.12]。

**Q6 實驗可信度**
- 切分：準確率用 10-fold CV；是否分層、是否按 host/時間/pcap 分組**論文未說明**；標籤如何貼到 host-window 也未說明。
- 重複：無多次隨機種子、無變異量、無信賴區間（Fig.4 無誤差棒）；時間 / 記憶體只報平均與峰值，無標準差。
- 洩漏風險 [推測]：相鄰窗、同 pcap、同 host 的樣本可同時落在訓練與測試折；且 10 s 是用同一 CV 從 30 個窗長中挑最高者，有挑選偏誤。Table 8 各裝置類型 98.7–100% 也未說明是否為留出設定。
- 不平衡 [讀圖，推測]：Fig.8 benign 頻率尺度 10^6（約 9–10M 個觀測），Fig.9 anomalous 峰值約 1.7×10^4，總量約 10^5 以下，比例約 1% 內量級；論文未講類別比例。**只報 accuracy，沒有 precision / recall / F1 / FPR**，在不平衡下 99.97% 資訊量有限。
- 訓練時 Flow-based baseline 用 Zeek 處理被切成 1–10 s 的 pcap，flow 會被窗界截斷 [推測：切法見 Fig.2]，可能使 baseline 較差；AD-IoT 的 12 個特徵在文中未列，也未說明如何由 Zeek 產生。
- 模型大小：提案約 300 KiB 上下，Flow-based 約 330–400 KiB（讀圖 Fig.13），遠小於 100 MiB，論文把記憶體下降歸因於模型小 [原文 p.11]，但 [推測] 100 MiB 更像 Python+xgboost 執行環境底線。

**Q7 限制**
- 作者承認：entropy 可被操縱；slow scan；sliding window 需多程序，Pi 上可能吃緊；特徵還可再減 [原文 p.12]。
- 未承認 [推測]：(a) 時間量測排除特徵產生，而每個封包仍需被摸過一次才能更新 histogram；(b) 缺 K1、K3 量測；(c) 無 precision/recall/FPR；(d) 兩台機器兩種彙總；(e) host = source IP，遇到 spoofed source 的 DDoS 會使 host 列數反而膨脹；(f) 需無 NAT 的位置；(g) 無跨資料集測試（訓練與測試皆含兩資料集混合，原文未說明是否分開）。

**Q8 公開性**：資料集公開；工具（Zeek、editcap、XGBoost）公開；**論文內未見程式碼或自製 feature generator 的連結或 artifact 聲明** [原文 p.1–14 檢索 github/availability 無相關]。

**Q9 [推測] 能否搬到「gateway flow 收集 + 選擇性卸載」**
- 可搬：以 host-window 為鍵的緊湊向量（7 個數值）作為「是否需要卸載/深檢」的輕量分流訊號；host 列數遠少於 flow 列數，上傳 host 向量的 bytes 預期遠小於 flow record（論文未量，需自測）。
- 不成立或未證明的前提：(1) 節省只在推論階段，抽特徵與擷取成本沒量；(2) baseline 是 per-flow ML，若我們本來就只用 conntrack/flow 計數器，節省幅度不同；(3) 窗長 ≥ 10 s 即有下限延遲，1 s 窗準確率崩跌；(4) 需 gateway 位於 NAT 內側；(5) host 級判決無法指出哪條 flow 要送 Suricata；(6) 偵測力只有 accuracy，不能當作「卸載後完整性」證據。

## D. 補充欄位
**D1.** C1 ×（無封包捕獲優化）；C2 △（host 粒度特徵 vs flow 特徵，p.6）；C3 ×（無雲端）；C4 ○（推論時間與記憶體，p.8–9）。K1 未量；K2 △（只有 accuracy，p.8）；K3 未量，僅質性討論（p.12）。
**D2.** 無卸載。縮減的是模型輸入列數；列數縮減比未直接報告，僅以時間/記憶體間接反映。偵測力：對 Flow-based 在 2–30 s 窗準確率較高（Fig.4, p.10），1 s 較低。
**D3.** 地端 CPU：未量；RAM：量（伺服器，非 Pi）；能耗：未量；傳輸：未量；雲端：無；time-to-detection：未量（processing time 不含收集窗與特徵產生）。
**D4.** ML（XGBoost）、anomaly 式二元判決；不需 payload/解密（只用標頭欄位與時間戳，p.6）。套用到 Suricata/Snort [推測]：不能直接套，成本結構是逐包規則比對；可作為旁路分流訊號。
**D5.** 流量為離線 pcap，無即時或速率掃描；無重複與變異量；有窗長掃描（1–30 s）可視為部分敏感度分析，但無特徵 ablation；artifact 未公開。
**D6.** Pi 3B+ 上推論已實測可跑（p.7–8）；整條 pipeline（擷取+特徵+推論）未在 Pi 上實測，此為未驗證。非 XDP/eBPF 論文。
**D7.** Edge–Cloud 分工：無關。Flow Feature Compression：部分支持（host 列數縮減使推論成本降，但偵測力無 precision/recall 佐證）。Dynamic Flow Monitoring：無關（固定窗）。XDP-eBPF：無關。Cloud Offloading 成本-時效：無關，僅提供「窗長 vs 準確率」曲線（Fig.4）。不同硬體限制：弱支持（Pi 3B+ 實測推論，但記憶體沒在 Pi 上量）。
**D8.** 可借用：host-window 7 特徵與 Eq.1 entropy 定義（p.6）、窗長掃描方法（p.7–8）、Zeek 5 特徵 baseline（Table 4）。改進方向 [推測]：
1. 在 Pi 上量完整 pipeline（含擷取與抽特徵）的 CPU/RAM——基於推論時間排除特徵產生。
2. 量化 time-to-detection vs 窗長 vs 準確率——基於 K3 未量、sliding window 未實作（p.12）。
3. 補 precision/recall/FPR 與按 host/時間分組的切分——基於 Q6。
4. 用 host 向量作為「是否送 Suricata/雲端」的分流器並量傳輸量——基於無卸載實驗。
5. 測 spoofed-source DDoS 下 host 表記憶體與 slow scan——基於 (e) 與 p.12。

**D9. 建議追加閱讀**（皆為本論文 references 所列，已在全文確認出現；DOI/內容未另開啟驗證）
1. Katsura et al., "Lightweight intrusion detection using multiple entropies of traffic behavior in IoT networks," GCAIoT, Dec 2022, pp.138–145 [原文 ref 23]——直接前作，原型與單一資料集結果。
2. M. M. Alani and A. I. Awad, "An intelligent two-layer intrusion detection system for the Internet of Things," IEEE TII vol.19 no.1 pp.683–692, 2023 [ref 33]——被比較的 flow-based 基準。
3. I. Alrashdi et al., "AD-IoT," IEEE CCWC 2019 [ref 32]——被比較的另一基準。
4. H. Nguyen-An et al., "Entropy-based IoT devices identification," APNOMS 2020 pp.73–78 [ref 34]——entropy 特徵來源。
5. T. Yamashita et al., "Slow scan attack detection based on communication behavior," 2020, doi:10.1145/3442520.3442525 [ref 41]——作者指定的 slow scan 補強方向。
（前一版列的「引用本文」論文本次未重新驗證，故不沿用。）

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| 準確率 | 99.97% | 10 s 窗、10-fold CV、兩資料集（是否混合未明）| [原文 p.8] |
| 其他窗長準確率 | ≥99.6%（除 1 s）；Baseline ≥98.5% | 同上 | [原文 p.8] |
| 1 s 窗準確率 | 約 93.6% | 讀圖 | [原文 Fig.4] |
| 推論時間 AD-IoT | 2924 ms（平均）| Pi 3B+，1,600 檔 | [原文 p.8] |
| 推論時間 Flow-based | 263 ms（平均）| 同上 | [原文 p.8] |
| 推論時間 提案 | 8.46 ms（平均）| 同上 | [原文 p.8] |
| 時間降幅 | 99.7%（2916 ms）vs AD-IoT；約 96.8% vs Flow-based [推測：自算] | 平均 | [原文 p.8] |
| 記憶體 AD-IoT 最大 | 733 MiB | 伺服器，`time -v` 峰值 | [原文 p.9] |
| 記憶體 提案 | 約 100 MiB（各類別持平）| 同上 | [原文 p.9, p.11] |
| 記憶體降幅 | 633 MiB = 86.4% vs AD-IoT（最大類別）；最多 270 MiB vs Flow-based | 同上 | [原文 p.9, p.11] |
| 樹平均葉數 | Flow-based 47.38；提案 42.5 | 10 s、depth 6 | [原文 p.11] |
| 各裝置類型準確率 | 98.7–100% | CIC IoT 2022 | [原文 Table 8, p.10] |
| 特徵重要度 | 0.3592 / 0.3122 / 0.0923 | 前三名 | [原文 Table 7] |

## F. 自評
**未能確認：** 標籤方式、CV 切分單位、資料混合/分開、AD-IoT 特徵清單、時間量測單位、Pi 時脈、類別比例（僅讀圖推估）、代碼公開（論文內無，外部未查）。

**與前一版相比被推翻或補足的結論**
1. 取得程度「僅摘要」→「全文」，C 節大部分「未能確認」已補上。
2. 前一版推測 Armadillo/OpenBlocks 可能是實驗平台：**被推翻**，那是 Table 1 規格參照；實際為 Pi 3B+ 與 Xeon 伺服器（p.4, p.7–8）。
3. 前一版把「記憶體 633 MiB」視為與時間同一環境：**被推翻**，記憶體在伺服器量，時間在 Pi 量。
4. 「baseline 未能確認」→ 補足：AD-IoT(RF) 與 Alani 式 Flow-based(XGBoost)；99.7% 是對較差者的平均，對同為 XGBoost 的 Flow-based 約 96.8%（自算）。
5. 前一版把 99.7% 當「最多」：被修正為「各類別平均」；記憶體 86.4% 才是最大類別值。
6. 資料集補足：Bot-IoT + CIC IoT 2022（不是 IoT-23/CICIoT2023）；Mirai source code 只是背景引用，不是資料。
7. 演算法補足：XGBoost；特徵 7 個與 entropy 清單；窗長 1–30 s 掃描，採 10 s。
8. K1/K3、傳輸量、雲端：前一版「未能確認」→ 確認為**未量測**；K3 只有質性討論與 sliding window 未來工作（p.12）。
9. 前一版 D8 推測「低速攻擊會漏檢」：**作者已自承** slow scan 與 entropy 操縱（p.12），但 spoofed-source 與 NAT 外側失效等為新增觀察。
10. 前一版 D5 推測要查切分洩漏：補足為 10-fold CV、窗長以同一 CV 選取、無 precision/recall/FPR、無變異量；仍無法排除洩漏。
11. 前一版 D9 的 cited-by 與兩篇 Pi/低效能 IDS 引用，本次未沿用（後者僅為前言引用，且未驗證）；引用次數 3–4 次的二手數字也未重驗。

**最不確定的三件事：**
1. 99.97% 的資料混合、標籤與切分方式（原文未寫）與洩漏程度。
2. 8.46 ms 的量測單位（每檔批次 vs 每筆）以及排除特徵產生後，實際 Pi 上端到端成本。
3. 類別不平衡比例與記憶體 100 MiB 底線成因，皆來自讀圖與推論。
