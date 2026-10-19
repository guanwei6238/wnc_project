# ebpf-xdp-dl（Real-Time eBPF/XDP-Based DL Framework, Liu et al.）

頁碼約定：[原文 p.N] 一律為 PDF 實際頁碼（共 12 頁）；期刊頁碼 = PDF 頁碼 + 16（PDF p.1 = 期刊 p.17）。圖 1 的內容為渲染 p.4 後目視（讀圖）。

## A. 書目與取得狀況
- 標題：Real-Time eBPF/XDP-Based Deep Learning Framework for Anomaly Traffic Detection in Internet of Things Networks [原文 p.1]
- 作者：Shuangxing Liu, K. L. Eddie Law, Zien Zhang, Chan-Tong Lam（Macao Polytechnic University, Faculty of Applied Sciences）[原文 p.1]
- 年份 / 出處：IEEE Internet Computing, vol.30 no.3, pp.17–28, May/June 2026；刊登日 12 May 2026（Theme Article: Securing the Internet of Things）[原文 p.1, p.12]
- DOI：10.1109/MIC.2026.3692726 [原文 p.1]
- URL：https://doi.org/10.1109/MIC.2026.3692726 ；https://ieeexplore.ieee.org/document/11516610/
- 與給定資訊的差異：無實質差異（給定 vol/頁碼/DOI 與全文一致）。前一版書目頁的「© 2025 IEEE」差異，全文版權頁為 © 2026 IEEE [原文 p.1]，該差異已消失。
- 取得程度：**全文**（使用者經學校訂閱取得的 PDF；pdftotext 逐頁抽取，圖 1 渲染核對）。

## B. 核心貢獻（≤3 條）
1. 兩階段 adaptive feature selection（Gini Gain 預篩 top-K=20 + 以 GRU 為 proxy 的貪婪增量評估，改善門檻 ε=0.001），**離線**執行，輸出 S_opt 與預訓練模型 M [原文 p.3, p.4, p.5 Alg.1]。
2. 在三個資料集上把特徵壓到 5–9 個：CICDDoS2019 77→5（92.73%）、IoT-23 18→6（92.57%）、TON_IoT 44→9（93.49%）[原文 p.7, p.8 Table 1]。
3. Pi 4B 上的 profiling：kernel 攔截平均 1.85 μs（peak 20.11 μs）、GRU 推論平均 10.38 ms（peak 57.89 ms）、agent CPU 0.67%、RSS 5.63 MB [原文 p.10 Table 3]。

## C. 指定的 9 項
1. **Research Problem**：IoT/邊緣節點資源受限，卻需跨異質協定做即時異常（含低速率 DDoS）偵測；既有 eBPF 方案缺少嚴格記憶體界限、DL 模型過重、靜態特徵集不能泛化、77 維特徵在窄頻鏈路（LoRaWAN）傳輸不可行 [原文 p.1–2]。
2. **Architecture**：Phase A 離線（Z-score/one-hot → Gini 預篩 → 增量選特徵 → 訓練 GRU）；Phase B 線上：kernel 的 eBPF/XDP 依 S_opt 抽特徵寫入共享 BPF hash map，user space 以輪詢（Sleep(Interval)）讀 map → Z-score → GRU → 良性則從 map 淘汰（benign-first eviction），惡意則告警並保留供鑑識 [原文 p.3, p.6 Alg.2, p.4 Fig.1]。
   ```
   封包 → [XDP: 抽 five-tuple、更新 flow 統計到 BPF hash map、return XDP_PASS]
        → [user space 輪詢 map → GRU 推論 → 良性:刪 entry / 惡意:告警+保留]
   離線(Phase A) --S_opt、M--> 設定 kernel 抽取邏輯 / 載入權重
   ```
   無 cloud 組件；全文無任何雲端卸載敘述。
3. **Processing Location**：Kernel（XDP 抽特徵、維護 flow 狀態）+ User space（GRU 推論、淘汰決策）；特徵選擇在離線訓練端 [原文 p.3, p.6]。
4. **Hardware**：僅部署端：Raspberry Pi 4B（Quad-core Cortex-A72 @1.5 GHz、4 GB RAM）當 IoT Gateway [原文 p.10]。OS、kernel 版本、網卡/驅動、推論框架、訓練機器：論文未說明。
5. **Dataset**：CICDDoS2019（引用為 Kaggle dhoogla 版，[原文 p.11 ref 10]）、IoT-23、TON_IoT [原文 p.6]。皆為公開資料集；只有 CICDDoS2019 用於硬體 profiling [原文 p.10]。使用哪些攻擊子集、類別數、切分比例：論文未說明。論文自己把 CICDDoS2019 定位為「Enterprise Edge」、並「模擬」port 被偽造/混淆（p.6），不是 IoT 專屬流量。
6. **Baseline**：只有「8 個其他 DL 模型」的比較（RNN、MLP、LSTM、CNN-LSTM、Slim Transformer、ResNet1D、CKAN、Mamba-ECANet），用於選 GRU，在 CICDDoS2019 全 77 特徵上訓練 [原文 p.9 Table 2]。無系統層 baseline（無 Snort/Suricata、無 iptables/nftables、無非 XDP 路徑）。Table 2 的訓練/測試時間所用硬體論文未說明，因此不能視為 Pi 4B 數據。
7. **Metrics**：Accuracy/Precision/Recall/F1/Train/Test time（Table 2）；Tkernel、Tuser、CPU、RSS（Table 3）。未量：throughput、forwarding latency、packet loss、能耗、傳輸量、FPR。
8. **Limitations（作者承認的）**：論文**沒有**獨立的 limitations 段落。僅在 Future Work 列三項：跨異質邊緣叢集部署（Pi 4B、Jetson Nano）、擴充到 QUIC/SRv6 等協定、加入圖式多感測器關聯分析 [原文 p.11]。
9. **Research Gap**：
   - 作者自述：上述三項 Future Work [原文 p.11]（隱含：目前只在單一硬體、單一資料集上做硬體驗證）。
   - [推測]：見 D5、Q7。

## 對指定問題的回答（Q1–Q9）
**Q1（特徵在哪算）**：Alg.2 寫的是 kernel 端「抽 header context K（例 five-tuple）、更新共享 map 中的 flow 統計（bytes、packets）；**若特徵 f∈S_opt 可在 kernel 計算則計算並更新 map**」[原文 p.6]，user space 再從 map 取 S_opt 對應的向量。論文**沒有**列出 5 個特徵中哪些在 kernel、哪些在 user space 算，也沒說明不可在 kernel 算的特徵怎麼處理（論文未說明）。每 flow 一個 map entry，key 為 five-tuple（「e.g.」）[原文 p.6]。狀態量：成長/淘汰規則只有「user space 判良性即刪除，惡意保留」[原文 p.6]；map 的 max_entries、滿了怎麼辦、flow 過期（timeout）機制、輪詢 Interval：論文未說明。論文宣稱記憶體為「deterministic 5.63 MB（RSS），不受流量影響」並歸功於 map 設計與 benign-first eviction [原文 p.10]。[推測] 這個 RSS 是 user-space agent 的，BPF map 在 kernel 計費，不會出現在 RSS；而「惡意保留」使攻擊期間的 entry 只增不減，故該宣稱只在所測的單一流量下成立。此外 IoT-23/TON_IoT 的 conn_state_RSTOS0 等欄位是連線狀態欄位，論文未說明如何在 XDP 重現（只驗證 CICDDoS2019 的線上部署，p.10）。

**Q2（77→5）**：方法見 B1：離線，Z-score 標準化 → 以 Decision Tree 算 Gini Gain 取 top-K(=20) → 從 S_base（CICDDoS2019 為 {Protocol}）起，以 GRU 驗證準確率貪婪逐一加入，增益 ≥0.001 才保留 [原文 p.4–5, Alg.1]。結果 5 特徵＝Protocol + Packet Length Min + Init Fwd Win Bytes + Avg Fwd Seg Size + Flow Bytes/s [原文 p.8 Table 1]。**對應關係（推翻前一版）：93.30% 是 GRU 用全部 77 特徵訓練的「upper bound」，92.73% 是 5 特徵** [原文 p.9]；縮減讓準確率下降 0.57 個百分點，不是「略高」。資料集為「preprocessed CICDDoS2019」，子集、類別數、切分方式論文未說明。洩漏風險 [推測，附證據]：(a) Alg.1 第 2 行先對整個 D 做 Z-score，p.5 未說明只用訓練集統計；(b) 選特徵的迴圈用 Acc_val 做決策，而 Table 1 最終 92.73% 就是迴圈最後一步的數字，並在 p.6 當作最終結果，論文沒說另有獨立 test set；(c) 一個 Protocol 單特徵只有 11.94% 準確率 [原文 p.6]，[推測] 代表多類別任務，而 CICDDoS2019 為 flow 層級資料常有大量相近 flow，隨機切分會高估。

**Q3（量了什麼）**：Tkernel「每個封包」的 XDP 程式處理延遲，平均 1.85 μs、peak 20.11 μs，peak 歸因於新 flow entry 的 hash map 初始化 [原文 p.10]；Tuser 是「每 flow」GRU 推論平均 10.38 ms、peak 57.89 ms [原文 p.10]。量測工具、樣本數、時鐘來源、是否含 NIC/驅動/NAPI、10.38 ms 是否含 map 讀取與正規化：論文未說明（僅稱 "software profiling"，p.2）。條件：重播 CICDDoS2019 攻擊流量持續 100 s [原文 p.10]；重播工具與速率論文未說明。Pi 4B：Cortex-A72 @1.5 GHz、4 GB；OS、kernel 版本：論文未說明。

**Q4（XDP 模式）**：論文只說 XDP「attached to the driver hook」「in the driver path」[原文 p.1, p.10]，並稱 "wire-speed"；native/generic/offload、NIC、驅動：論文未說明，也無法由敘述確切推論。[推測] Pi 4B 板載為 Broadcom GENET（bcmgenet），這是我的背景知識，非論文所述。[二手] netdev 上 2026-03 至 2026-05 有 "net: bcmgenet: add XDP support" 系列（v1–v9），顯示此驅動在那之前沒有 native XDP，合併狀態我未能確認（https://ratatoskr.run/netdev/2026/05/7948178/t）。若實驗在此之前做，[推測] 可能跑的是 generic XDP，但論文沒有證據。

**Q5**：沒有量轉送效能（throughput/latency/packet loss 皆無）。「wire-speed」與 "does not become a bottleneck" [原文 p.10] 只由 1.85 μs 推出，無線速數據。Alg.2 的 XDP 一律 `XDP_PASS`（p.6），所以沒有任何在 kernel 內丟包的路徑；圖 1 寫 "Malicious: Alert & Block"（讀圖，p.4）但 Alg.2 是 "Alert and Retain"，論文未說明阻擋機制。無雲端卸載；與 Snort/Suricata/iptables/nftables 的成本比較：無。Baseline 只有其他 DL 模型。p.1 稱規則式系統「resource-intensive」，無數據支持。

**Q6**：量了 CPU（agent 平均 0.67%、peak 2%）與 RSS（5.63 MB，peak 同值）[原文 p.10 Table 3]。CPU 是 per-core 還是全機、是否含 softirq/XDP 本身：論文未說明。能耗：未量。重複次數、標準差、信賴區間：論文未說明；只有單次 100 s 的 avg/peak。

**Q7**：作者承認的限制見 C8（僅 Future Work）。[推測] 未承認的限制：(1) 吞吐：10.38 ms/flow 若單執行緒序列推論，上限約 96 flows/s（1/0.01038，由論文數字推算）；且 Alg.2 每輪掃描整個 map，flow 數大（尤其 spoofed DDoS）時掃描時間與延遲線性成長；CPU 0.67% 與「stress」並存，暗示重播的 flow 率很低，但速率論文未報。(2) 資料集代表性：CICDDoS2019 非 IoT 流量；三個資料集的特徵來自離線 flow 工具輸出，只在 CICDDoS2019 驗證了線上抽取，且未驗證線上算出的特徵與離線 CSV 一致。(3) concept drift：「adaptive」實為每個環境離線重跑一次選擇，部署後 S_opt 固定；摘要與 p.1 的 "dynamically ... under evolving attacks" 容易讓人誤解為線上自適應，未經實驗。(4) 重現性：切分、超參數、GRU 輸入序列長度皆未交代（Alg.2 第 13–15 行輸入是單一 flow 向量 x，但 p.2–3 強調時序依賴）。(5) 引用：「XDP 26 Mpps/core」的引用是 Netfilter 封包路徑示意圖（p.3 對 p.11 ref 1），[推測] 該引用不支持此數字。(6) 內部不一致：p.4 文字說 S_base 含 IPs，Alg.1 註記排除 IP；Table 1 出現 "66.7.5%" 打字錯誤。

**Q8**：論文未提供程式碼、資料處理腳本或 artifact 連結（全文搜尋 github/repository/source code 無結果）。

**Q9 [推測] 不能直接套用到我們的 Pi 3B+ 平台**：(a) 1.85 μs 與「wire-speed」的前提（native XDP、板載 NIC）在 Pi 3B+ 的 USB 網卡（lan78xx/smsc95xx，已核對無 XDP）不成立，只有 generic XDP，在 skb 配置之後才執行，數字需重測；(b) 10.38 ms 是 A72 @1.5 GHz 的數字，A53 @1.4 GHz 的倍數未知；(c) 0.67% CPU 與 5.63 MB 不含 map、不含 NIC 軟中斷，且重播速率未知，不能當我們的成本預算；(d) 模型準確率來自離線資料，不等於規則式 IDS 的偵測力，也不提供 payload；(e) 本論文無雲端卸載，其「傳輸成本」只是 motivation。

## D. 補充欄位
### D1. 與研究主題對照
- C1 封包處理：○ — XDP 在 driver 路徑抽特徵並維護 flow 狀態 [原文 p.6]；但模式未明。
- C2 Flow 資料收集：○ — five-tuple 為鍵的 BPF hash map 做 flow 統計 [原文 p.6]。
- C3 雲端卸載：× — 全文無雲端。
- C4 降成本：△ — 特徵縮減與 CPU/RAM 低 [原文 p.10]，無傳輸量實測。
- K1 轉送效能：未量（無 throughput/latency/loss）。
- K2 資料完整性：△ — 只量模型準確率 92.73 vs 93.30（p.9）；未與原始資料的雲端 IDS 偵測力比。
- K3 即時性：△ — 只有分段延遲（Tkernel、Tuser），無端到端 time-to-detection（含 flow 累積與輪詢間隔）。

### D2. 卸載與資料
- 送到雲端的內容、決策者、門檻：論文未說明（無雲端）。
- 縮減比：特徵維度 77→5（93.5%）、18→6（66.7%）、44→9（79.5%）[原文 p.7]；CICDDoS2019 偵測力損失 0.57 個百分點（93.30→92.73，p.9）。注意 Recall/F1/Precision 只報 77 特徵版（Table 2），5 特徵版只有 accuracy。這是特徵維度縮減，不是資料 bytes 縮減，bytes 未量。

### D3. 成本記帳
- 地端 CPU 0.67%、RSS 5.63 MB [原文 p.10]；能耗未量；傳輸 bytes/頻寬未量；雲端運算：無。端到端延遲：未量。

### D4. 偵測方法與威脅模型
- DL（GRU，監督式分類，輸出 argmax 類別），偵測 CICDDoS2019 的 DDoS、IoT-23 的 Mirai/Torii 類、TON_IoT 的 data injection [原文 p.6–7]；僅用 flow 統計，不需解密或 payload（論文未提 payload）。
- 成本模型套用到 Suricata/Snort [推測]：「XDP 先抽統計 → user space 判斷 → 良性淘汰」的狀態管理與量測方法可借鑑；但規則式 IDS 要 payload 與協定解析，且 GRU 的 per-flow 成本不等於規則比對成本，不能直接套。

### D5. 實驗可信度
- 流量來源：重播 CICDDoS2019 100 s（非即時、非合成）[原文 p.10]；速率範圍：未說明；重複與變異量：無；ablation：有特徵選擇軌跡（Table 1）與 8 模型比較（Table 2），無 XDP/無 XDP、無特徵選擇 on/off 的系統層 ablation；切分與洩漏：見 Q2；程式碼資料：論文未說明公開（Q8）。

### D6. 移植到我們平台的障礙
- 依賴：XDP 能附掛的網卡驅動、BPF hash map、user space GRU 框架（論文未說明）、Pi 4B 級 CPU。
- Pi 3B+：[推測] 能跑 generic XDP + user space 推論，但未驗證；USB 網卡只有 generic XDP（已核對原始碼，使用者提供），XDP 在 skb 後執行，Tkernel 的優勢預期縮水且 1.85 μs 不可轉移。

### D7. 對六個假說方向的證據（僅本論文）
- Edge–Cloud IDS 分工：無關（無雲端）。
- Flow Feature Compression：支持（弱）— 77→5 掉 0.57 個百分點 [原文 p.9]；但針對模型輸入，且僅單一資料集有 77 特徵版對照的完整指標。
- Dynamic Flow Monitoring：部分 — benign-first eviction 控制 map 大小 [原文 p.6]，但線上不會動態改特徵（S_opt 離線決定、部署時設定，p.3）。
- XDP-eBPF 真正省多少：證據不足 — 無與非 XDP 路徑（NFQUEUE/libpcap）對照；只有 Tkernel 絕對值。
- Cloud Data Offloading 的成本-時效：無關。
- 不同硬體限制下是否仍有效：無 — 只有一個硬體點。

### D8. 可借用與可改進
- 可借用：Gini 預篩 + GRU 增量選特徵演算法與 ε=0.001、K=20（p.4–5）；Tkernel / Tuser 分開量測與報 avg/peak（p.10）；「良性即淘汰、惡意保留」的 map 管理想法（p.6）。
- 可能改進（全為 [推測]）：
  1. 在 Pi 3B+ + USB NIC 的 generic XDP 下重量 Tkernel 並與 NFQUEUE 對照（基於 Q4/Q9：模式與驅動未交代）。
  2. 補量 throughput/latency/loss（基於 Q5：K1 未量）。
  3. 把 S_opt 特徵做成上傳雲端的 flow record，量傳輸量與雲端 IDS 偵測力（基於無雲端卸載）。
  4. 加 map 上限、timeout 與攻擊下的 eviction 實驗（基於 Q1/Q7：惡意保留、max_entries 未說明）。
  5. 以獨立 test 集或時間切分重做選特徵，報 recall/FPR/time-to-detection（基於 Q2 洩漏風險）。

### D9. 引用網路
OpenAlex（二手）顯示本文 cited-by 0、referenced_works 10 筆（過新，無後續工作可查）。本文 references 多為資料集與模型（CKAN、Mamba-ECANet 等），與主題最相關者為下列（內容由我於 2026-10-10 抓取 arXiv 摘要頁確認）：
1. Tolay, "eBPF-Based Real-Time DDoS Mitigation for IoT Edge Devices", arXiv:2508.00851 — 同題更貼近：kernel 內 rate-based 阻擋，Pi 4 上報 >97% mitigation（100 Mbps flood）。存在確認：arXiv 頁面已確認；頁面未寫程式碼連結。
2. Wu et al., "A Feature-Rich Embedded NIDS with eBPF/XDP: Detector and Architecture Trade-offs", arXiv:2609.12605 — 同題更貼近：Pi 5 + Isolation Forest + eBPF/XDP 過濾，比較傳輸（gRPC vs Kafka）。存在確認：arXiv 頁面已確認（2026-09-11）。
3. Dai et al., "PSketch: A Priority-Aware Sketch Architecture for Real-Time Flow Monitoring via eBPF", arXiv:2509.07338 — Dynamic Flow Monitoring 的替代方案（kernel sketch、10 Gbps 下 0.7% throughput loss）。存在確認：arXiv 頁面已確認。
4. SmartX Intelligent Sec（arXiv:2410.20244，BiLSTM + eBPF/XDP）— 替代方案；未驗證（沿用前一版，本次未重查）。
5. Keio "Overcoming eBPF Constraints: Towards Practical ML/NN-based Anomaly Detection" — 在 eBPF 內做 ML 的限制；未驗證（無 DOI）。

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| 特徵數 | 77→5（-93.5%）| CICDDoS2019 | [原文 p.7, Table 1] |
| 特徵數 | 18→6 / 44→9 | IoT-23 / TON_IoT | [原文 p.7] |
| Accuracy | 0.9330 | GRU，全 77 特徵 | [原文 p.9 Table 2] |
| Accuracy | 92.73% | GRU，5 特徵 | [原文 p.6, p.8, p.9] |
| Accuracy | 92.57% / 93.49% | IoT-23 6 特徵 / TON_IoT 9 特徵 | [原文 p.7, Table 1] |
| Precision/Recall/F1（GRU）| 0.9217 / 0.9330 / 0.919 | 77 特徵 | [原文 p.9 Table 2] |
| 5 特徵版的 P/R/F1 | 論文未說明 | — | — |
| Protocol 單特徵準確率 | 11.94% | CICDDoS2019 baseline | [原文 p.8 Table 1] |
| GRU Train/Test time | 151.27 s / 0.26 s | 77 特徵；硬體論文未說明 | [原文 p.9 Table 2] |
| Mamba-ECANet / CKAN Test time | 1.05 s / 1.21 s | 同上 | [原文 p.9] |
| Slim Transformer Accuracy | 0.6487 | 同上 | [原文 p.9] |
| Kernel 攔截延遲 | avg 1.85 μs / peak 20.11 μs | Pi 4B，重播 CICDDoS2019 100 s；XDP 模式未說明 | [原文 p.10 Table 3] |
| GRU 推論 | avg 10.38 ms / peak 57.89 ms（每 flow）| Pi 4B，5 特徵 | [原文 p.10 Table 3] |
| Agent CPU | avg 0.67% / peak 2% | Pi 4B | [原文 p.10 Table 3] |
| RSS | 5.63 MB（avg=peak）| Pi 4B | [原文 p.10 Table 3] |
| Pi 4B 規格 | Cortex-A72 ×4 @1.5 GHz、4 GB | OS/kernel/NIC 未說明 | [原文 p.10] |
| 三資料集平均準確率 | 92.93% | 5–9 特徵 | [原文 p.8] |
| 推導：推論吞吐上限 | 約 96 flows/s | 1/10.38 ms，假設單執行緒序列 | [推測] |

## F. 自評
未能確認（論文未說明）：OS/kernel、NIC/驅動、XDP 模式、量測工具與樣本數、重播工具與速率、資料切分、map 大小與輪詢間隔、5 特徵中哪些在 kernel 計算、程式碼是否公開（僅確認論文內無連結）。原因：論文是短篇（12 頁）theme article，無實驗細節。

最不確定的三件事：
1. 洩漏判斷（Q2）：我只能由 Alg.1 與 Table 1 的文字推測「選特徵與最終報告共用驗證集」，論文並未明說，可能實際有獨立 test set。
2. bcmgenet XDP 的合併與時程：只看到 netdev 補丁串（二手），未確認何時合併，也不知作者用的 kernel；Q4 結論僅為「論文未說明」。
3. 0.67% CPU 與 10.38 ms 的相容性（Q7 的「重播 flow 率偏低」）完全是我的推算，論文沒給 flow 率或 CPU 的分母。

### 與前一版相比被推翻或補足的結論
1. **推翻**：前一版（D2、E）猜 93.30% 為 5 特徵版；全文為 93.30%＝77 特徵（upper bound）、92.73%＝5 特徵 [原文 p.9]。「縮減後準確率反而略高」錯誤，實際低 0.57 個百分點。
2. **推翻/修正**：前一版據摘要把 "dynamically identifies ... under evolving attacks" 當成線上動態調整；全文是離線選擇，部署時只把 S_opt 設定進 kernel [原文 p.3]。D7 的 Dynamic Flow Monitoring 「隨攻擊演變調整特徵」不成立。
3. **補足**：Architecture 由「未能確認」變為完整：BPF hash map、user space 輪詢、benign-first eviction、Phase A/B [原文 p.3, p.6]。前一版「特徵如何傳到 user space」答案是共享 hash map。
4. **補足**：Hardware：Pi 4B = Cortex-A72 @1.5 GHz、4 GB [原文 p.10]；OS/kernel/NIC/XDP 模式仍論文未說明，前一版的「未能確認」現改為「論文未說明」。
5. **補足**：CPU 0.67%（peak 2%）、RSS 5.63 MB [原文 p.10]，前一版只有 "negligible"。
6. **補足**：Baseline 現為 8 個 DL 模型（Table 2），非系統層；證實無 Suricata/Snort/nftables 比較（前一版為「未能確認」）。
7. **補足/證實**：雲端卸載確認全文沒有（前一版 C3 × 僅基於摘要缺席）；轉送效能確認未量（K1）。
8. **補足**：Limitations：論文無限制段落，僅 Future Work 三項；前一版「未能確認」。
9. **補足**：程式碼：全文未見公開連結（Q8）。
10. **補足**：前一版 D4/D5 的「攻擊類型 [推測]」與「無資料切分資訊」：攻擊類型已證實（p.6–7），切分仍論文未說明，並新增洩漏風險證據。
11. **補足**：前一版推測 CICDDoS2019「非 IoT 專屬」：論文自己稱之為 Enterprise Edge 並「模擬」port 混淆 [原文 p.6]，與推測吻合。
12. **補足**：D6 的 lan78xx 未驗證一項，已由使用者核對（無 XDP）；本版另補 Pi 4B 的 bcmgenet XDP 補丁串（二手，合併狀態未確認）。
13. **補足**：D1 評分改為 C1 ○、C2 ○、C4 △（前一版為 △）；C3、K1 維持 ×/未量。
14. **補足**：D9 更新：OpenAlex 顯示 cited-by 0；前一版 3 篇 arXiv 中 2508.00851、2609.12605、2509.07338 現已確認存在，其餘兩篇仍未驗證。
