# G4（edge IDS＋ML／排程）全文查核 b 組：n=3、n=435、n=486

查核基準：`../SCREEN.md` 的 C1–C4。三篇都已讀完整全文（文字檔全部＋PDF 的圖表頁：n=3 的 Fig. 3–8、n=435 的 Fig. 3–5、n=486 的 Fig. 1、2、14、16）。以下「論文未說明」表示全文找不到，不是推測。

## 一覽

| n | 論文 | C1 | C2 | C3 | C4 |
|---|---|---|---|---|---|
| 3 | 2-Step Power Scheduling…NIDS on Multicores（MCSoC 2016） | none | none | related | none |
| 435 | Scheduling to the Rescue（EuroSec 2023） | none | none | related | none |
| 486 | Think Fast（IEEE IoT-J 2026） | none | none | related（弱） | none |

三篇**都沒有 overlap**。三篇都不含「rule IDS（Suricata/Snort）和 ML 推論同機同時跑並量測互相干擾」這個完整組合。

---

## 1. n=3：2-Step Power Scheduling with Adaptive Control Interval for NIDS on Multicores

### 書目
Lau Phi Tuong, Keiji Kimura（Waseda University）。2016 IEEE 10th International Symposium on Embedded Multicore/Many-core Systems-on-Chip（MCSoC），pp. 69–76，DOI 10.1109/MCSoC.2016.18。

### 他們做了什麼
- **目的**：降低 Suricata 在嵌入式多核心上的功耗（DVFS），同時維持封包處理量。這是功耗論文，不是丟包或干擾論文。
- **架構**：只有 Suricata，**沒有任何 ML**。另外有一個「another program」和 Suricata 同機多工（Sec. III-C），但這個程式是什麼、做什麼，論文未說明。
- **平台**：ODROID-XU3，4 顆 big Cortex-A15 2.0 GHz ＋ 4 顆 small Cortex-A7 1.4 GHz，2 GB RAM，Ubuntu 15.04（Sec. IV, p.73）。
- **IDS 版本與模式**：Suricata 2.0.8（p.73），當作 NIDS。capture 方式（pcap／af-packet／NFQ）、是否 inline、規則集，**論文未說明**。文中說 Suricata 跑在 router 上偵測封包，但沒說是轉送路徑上的 inline。
- **排程方法**：
  - Step 1（packet receiver，Sec. III-A, Algorithm 1, p.71–72）：依緩衝區封包數與最近 ≤10 次的歷史，估計處理時間，決定控制間隔 Tdeadline（5 µs–30 ms）與可行頻率。
  - Step 2（detection phase，Sec. III-B, Algorithm 2, p.73）：處理到 50%／75%／100% 封包時對照 deadline，調高或降到最低頻率。
  - Algorithm 3（Sec. III-C, p.73）：Suricata 預設跑在所有核心；「有其他程式」時把 Suricata 執行緒和其他程式的執行緒切到**不同核心**，只有 Suricata 時再切回全部核心。這是**事件觸發的靜態核心切分**，不依封包負載比例調整。
- **量測**：tcpreplay 當流量來源（p.73）；流量 1,000／5,000（A7）／10,000／17,000 packets/s；變數是核心數 1–4、big／small 核心、6 種排程（Performance／Ondemand governor、固定 15／30 ms、1-step adaptive、2-step adaptive）。量的是平均功耗（W）與「processed packets/s」。功耗量測儀器、延遲、丟包率、快取、記憶體頻寬，**論文都未說明或未量**。
- **主要數字**：
  - 1,000 pps、4 顆 big core：2-step 比 Ondemand 省 75%、比 Performance 省 87%（Abstract）。
  - 10,000 pps、4 顆 big core：Performance 約 3.8 W、Ondemand 約 3.2 W、2-step 約 1.2 W（p.74）。
  - 17,000 pps 供應：2-step adaptive 處理 2,100／7,515／11,290／15,445 pps（1／2／3／4 顆 A15）；Performance governor 為 2,224／7,918／12,351／16,205（Fig. 3c, p.74）；固定 30 ms 只有 525／4,335／8,902／12,822。
  - 共機實驗（10,000 pps，Suricata＋another program，Table I, p.75）：Ondemand 10,122 pps、2-step 10,067 pps；功耗 2-step 為 big 1.25 W＋small 0.362 W，Ondemand 為 3.42 W＋0.251 W（Fig. 7）。

### 特別檢查
- **同機互相干擾**：沒有。共機實驗只比功耗與處理量，沒有快取、記憶體頻寬、IPC、別的程式被影響的量測，也沒有拿「不共機」當基線。
- **依負載調整 ML 工作量或核心分配**：沒有 ML。DVFS 頻率依負載調整；核心分配只有「有／無其他程式」兩種狀態，不依負載比例。
- **fast path／放行後不檢查**：沒有。所有進入 buffer 的封包都走 detection phase（Sec. III-A 的 Tmean×x 假設全部處理）。
- **只檢查部分封包／flow**：沒有。固定 30 ms 間隔「只處理 50–80% 封包」是因為來不及處理（效能違規），不是設計。

### C1–C4 標記
- **C1：none**。全文沒有信任、放行、稽核或撤銷的概念。
- **C2：none**。每個封包都檢查，沒有「只送開頭」，也沒有處理有狀態 IDS 接受部分封包的問題。
- **C3：related**。證據：Abstract「multiplexing NIDS and them simultaneously on the same device」；Sec. III-C Algorithm 3（p.73）把 Suricata 與其他程式分到不同核心。缺的關鍵要素：(a) 沒有 ML／DNN 推論；(b) 沒有量測互相干擾（快取、記憶體頻寬）；(c) 核心切分是開關式、不是依負載調整工作量；(d) 另一個程式未說明；(e) 目標是功耗不是丟包。
- **C4：none**。沒有 kernel fast path；Suricata 的 capture 機制也未說明。

### 可與我們實測比較的數字
都要加註：Suricata **2.0.8**、規則集未說明、ARM A15 2 GHz（非 A72 1.5–1.8 GHz）、2016 年，只能當量級參考。
- 1 顆 A15 核心：供應 10,000 pps 時處理 4,166–5,110 pps；供應 17,000 pps 時降到 2,224（Performance）／2,100（2-step）pps（Fig. 3b、3c）。若視為單核滿載，粗估每封包約 200–240 µs（10 kpps 時）；這是**我們的推算**，論文未報每封包成本。過載時處理量下降而不是持平，這個現象可和我們 Pi 上 NFQ 滿載後的行為對照。
- 4 顆 A15 核心：供應 17,000 pps 時處理 15,445–16,205 pps（Fig. 3c）。我們的 Pi 4 是 2–4 個 queue 整台約 60 kpps、每封包 55–61 µs，約為此處的 3.7–4 倍；差異來自 Suricata 版本與規則集不同，不能直接當作硬體差距。
- A7（small core）：5,000 pps 供應下 4 核心處理 4,201–4,556 pps（Fig. 5b）。

### 我們論文怎麼引用
作為背景（ARM 上跑 Suricata 的早期效能數字，以及 Suricata 與其他程式同機時用核心切分的先例）。可在 C3 的 related work 寫一句：該工作以功耗為目標、同機程式未指明、無干擾量測、核心分配為開關式。

### 雪球
沒有比它本身更接近 C1–C4 的引用。參考文獻幾乎都是 DVFS／資料中心功耗。旁支（不優先）：
- [8] Jiang, Xie, Salamatian, "Load Balancing by Ruleset Partition for Parallel NIDS on Multi-Core Processors", ICCCN 2013。切的是規則集不是封包，與 C2 無關，與 C3 只有「多核分配」的邊。
- [6] Lama et al., APPLEware, IWQoS 2013。同機 web 應用的干擾與資源分配，不是 IDS。

---

## 2. n=435：Scheduling to the Rescue; Improving ML-Based Intrusion Detection for IoT

### 書目
Aria Mirzai, Ali Zülfükar Coban, Magnus Almgren, Wissam Aoudi, Tobias Bertilsson（RISE／Chalmers／Clavister）。16th European Workshop on System Security（EuroSec '23），Rome，2023-05-08，pp. 44–50，DOI 10.1145/3578357.3589460。

### 他們做了什麼
- **目的**：讓資源有限的 IoT 裝置能同時跑多個輕量 ML 異常偵測實例，並在裝置上平行重訓模型而不停掉偵測。
- **架構**（Sec. 4, p.46）：單一程式。producer 執行緒開 socket 抓流量、只取 header 欄位（payload 丟棄）、放進每個偵測實例專屬的 buffer（滿了就覆寫最舊的）；consumer 執行緒從 task pool 取偵測模型（PASAD，一個 anomaly detector，視為 black box）執行；一個獨立執行緒負責重訓（測試時固定佔 4 核心中的 1 顆，Sec. 5.1, p.47）。**沒有規則式 IDS**，沒有 Suricata／Snort，沒有轉送路徑。所有東西都在同一台裝置上，不上雲。
- **排程方法**（user-level scheduler，Sec. 4.2）：
  - Dynamic Resource Prioritisation（4.2.1）：依三個條件提高某模型的優先權：buffer 超過 80%、anomaly score 超過 soft 門檻、超過 hard 門檻。
  - WMPA（4.2.2）：依優先權加權隨機挑下一個要跑的模型。
  - consumer 執行緒數 = 核心數（4），避免 time slicing（p.47）。
- **平台**（Sec. 5.3, p.47）：Raspberry Pi 4 Model B 4 GB LPDDR4（單通道、約 4.4 GB/s）與 NVIDIA Jetson Nano 4 GB（雙通道、25.6 GB/s、L2 2 MB，是 Pi 的兩倍）。CPU 頻率、OS 版本、kernel 版本論文未說明。
- **量測**（Sec. 5–6）：流量不是即時來源，而是從 pcap 檔（約 190,000 個 Ethernet 封包）讀取，循環 50 次，producer「每秒對所有 buffer 平均灌入一批資料」（p.47）。量三件事：最大吞吐（每秒 anomaly score 數，直到 consumer 開始漏資料）對偵測實例數、alarm 偵測時間（人為把某模型的 soft/hard 門檻設得比平常分數低）、scale-up（290 秒內處理的資料點數）。**沒有**量 CPU%、功耗、封包延遲、轉送丟包。
- **主要數字**（Fig. 3–4、Table 1–2、Sec. 6.3）：
  - Pi 4：scheduler 最高約 150,000 scores/s（約 5 個實例），baseline 約 70,000（讀圖，約略值）；超過約 9–10 個實例後 scheduler 撞到「performance wall」，超過約 50 個實例後兩者都約 35,000–37,000，行為與 baseline 相同。Pi 4 上**平行重訓失敗**（Fig. 3 綠線恆為 0）。
  - Jetson Nano：75 個實例時 scheduler 約 84,000 scores/s、baseline 約 39,000；scale-up 1.64×（不重訓）、1.24×（重訓同時）。
  - Table 1：alarm 偵測時間 98.167 s（有優先權）、104.963 s（無優先權）、187.252 s（baseline）；Table 1 的平台論文未明講，由 75 模型的數字看應是 Jetson。

### 特別檢查
- **同機互相干擾**：部分有。Sec. 7.1（p.49）討論 Pi 4 的「performance wall」，推測是記憶體頻寬問題：「most likely a memory-bound issue between the CPU and RAM」；從約 10 個模型起超過 L2 cache、約 20 個模型後 RAM 被持續存取；單通道記憶體讓只有一個 consumer 能同時存取；也用這個解釋 Pi 4 為何無法同時重訓與推論。**這只是推測**，沒有 perf counter、沒有隔離實驗、沒有改變記憶體競爭程度的對照。而且干擾發生在「ML 實例之間」和「ML 推論與 ML 重訓之間」，**不是 ML 與規則式 IDS 或封包轉送之間**。這是本組中最接近我們 C3「記憶體頻寬是共機瓶頸」的一句話。
- **依負載調整 ML 工作量或核心分配**：部分有，但層次不同。優先權會隨 buffer 占用率（>80%）和 anomaly 分數動態調整，哪個模型多跑幾次；這是「ML 實例之間」的時間分配。重訓固定一顆核心。沒有「ML 工作量依 IDS／封包路徑的負載比例縮放」，也沒有 duty-cycle。
- **fast path／放行後不檢查**：沒有。
- **只檢查部分封包／flow**：沒有刻意設計。buffer 滿了覆寫最舊資料是被動丟棄，不是選擇性檢查；每個資料點都由模型處理。

### C1–C4 標記
- **C1：none**。無放行、稽核、撤銷。
- **C2：none**。無有狀態 IDS，無部分封包檢查。
- **C3：related**。證據：Sec. 7.1 p.49 以 L2 cache 與單通道記憶體頻寬解釋 Pi 4 上 ML 工作撞牆；Sec. 4.2.1 p.46 依 buffer 占用與異常分數動態分配 consumer 時間。缺的關鍵要素：(a) 沒有規則式 IDS（Suricata／Snort）或封包轉送與 ML 同機；(b) 干擾是 ML 內部的、屬推測、沒有量測驗證；(c) 沒有依 IDS 負載縮放 ML 工作量的機制；(d) 流量由檔案餵入，不是即時 inline 流量。這是本組最接近 C3 的一篇，需在文中明確區分。
- **C4：none**。

### 可與我們實測比較的數字
- Pi 4 記憶體頻寬約 4.4 GB/s（單通道，作者引用 datasheet，非實測，Sec. 5.3）。可對照我們「吃記憶體頻寬的負載綁在別顆核心仍讓 Suricata 每封包成本 2 倍」。
- Pi 4 上 ML 實例數超過約 10 個後吞吐掉到約 1/4 以下（Fig. 3 讀圖；單位是 anomaly score／s，不是封包／s）。支持「ML 工作集超過 L2 後變記憶體受限」，可作為我們 6 MiB MLP 讓 Suricata 貴 15–17% 的旁證，但條件完全不同（他們沒有 Suricata）。
- Pi 4 無法同時重訓與推論（Fig. 3，Sec. 6.1.1、7.1）。
- 其餘（score/s、alarm 時間）與我們的封包／flow 指標無法直接比。

### 我們論文怎麼引用
作為背景並作為「相近但不同」的比較對象：同為 Pi 4 上 ML 偵測的資源競爭，且作者同樣認為記憶體頻寬／L2 是瓶頸；但他們沒有規則式 IDS、沒有 inline 轉送、沒有量測驗證、沒有依 IDS 負載縮放 ML。可引用其 Pi 4 單通道記憶體論點支持我們的觀察，同時說明我們用替身負載對 Suricata 每封包成本做了直接量測。

### 雪球
沒有比它本身更接近 C1–C4 的引用。參考文獻是 ML-IDS 綜述與雲端／fog 任務排程（[12] Pham & Huh 2016、[16] HUNTER、[7] HunterPlus），都不是同機 IDS 與 ML 的干擾。
- [1] Almgren et al., "The Nuts and Bolts of Deploying Process-Level IDS in Industrial Control Systems", ICSS 2018（Midbro，本文 baseline 的來源），ICS 場景，不接近。
- 搜尋建議（不是論文引用的）：作者群 Mirzai／Almgren／Aoudi（Chalmers／Clavister）若有後續，可查「邊緣裝置上排程多個 IDS／ML 實例」。

---

## 3. n=486：Think Fast: Real-Time IoT Intrusion Reasoning Using IDS and LLMs at the Edge Gateway

### 書目
Saeid Jamshidi, Omar Abdul Wahab, Rolando Herrero, Foutse Khomh, Martine Bellaïche, Samira Keivanpour, Negar Shahabi, Amin Nikanjam, Kawser Wazed Nafi。IEEE Internet of Things Journal，vol. 13, no. 8，2026-04-15，pp. 15485–15513，DOI 10.1109/JIOT.2026.3656738。

### 他們做了什麼
- **「IDS」的意思**：本文的 IDS 全部是 **ML 分類器**（DT、KNN、RF、CNN、LSTM、CNN+LSTM），**沒有規則式 IDS**（全文沒有 Suricata、Snort、規則、NFQUEUE）。標題的「IDS and LLMs」容易誤解。
- **架構**（Sec. IV, Fig. 1, Algorithm 1, p.15490–15495）：
  1. Edge gateway 上對流量抽統計／時間／entropy 特徵（Eq. 3–6），ML 分類器逐筆算 anomaly score s_t。
  2. s_t ≥ τ_alert 時，收集 telemetry（CPU、記憶體、延遲、能耗、anomaly score），組成 ≤1.2 kB 的 prompt，用 API 送到**雲端外部** LLM（GPT-4-turbo、DeepSeek-V2、LLaMA 3.5），做 zero-shot／few-shot／chain-of-thought，回傳攻擊分類、信心、嚴重度、緩解建議。LLM 只收 telemetry，不收封包或 flow 特徵（Sec. IV-E）。
  3. 文中形式化了「本地小語言模型 SLM_edge」的備援選擇（Eq. 34），但實驗只用外部 LLM；on-device LLM 列為 future work（Sec. XII）。
  4. 退化機制（Sec. IV-K, Eq. 47, p.15496）：閘函數 g_t 在 T_t ≤ T_max 且上行延遲／連線狀態 L_t ≤ L_max 時才呼叫 LLM，否則只用本地 ML；LLM 呼叫「conditional, asynchronous, and nonblocking」。
- **ML 與 LLM 不在同一台機器上跑**：ML 在 Pi，LLM 在雲端。所以沒有「同機 ML 推論和別的東西搶資源」的情境。
- **inline 與否**：Sec. XI-B（p.15510–15511）明確說「not intended to operate as an inline intrusion prevention system」（意思：不是 inline IPS，是決策支援層）；緩解由 SOAR 等外部機制執行。
- **平台**（Sec. V-C, p.15497）：兩台 Raspberry Pi 4 Model B，8 GB RAM，1.5 GHz 四核；NodeMCU 為被保護裝置，Kali Linux 發動攻擊（Fig. 2, p.15498）。Fig. 2 畫的是 Pi 接在 router 與 NodeMCU 之間，流量是被轉送還是被鏡像給 Pi，論文未說明。OS 與 kernel 論文未說明。資料集 IoTID20（Sec. V-B）。
- **量測**：CPU%、記憶體（MB）、頻寬（MB/s）、能耗（J，10 ms 積分，wattmeter）、延遲，每種組態 62 次獨立試驗，對 LLM 種類做 ANOVA＋Tukey（Sec. VI–VII）；準確率（F1）。攻擊：brute force、DoS、DDoS、port scan。攻擊的封包速率（pps／Mbps）論文未說明。
- **主要數字**：
  - Abstract：延遲 <1.5 s、每個 prompt <1.2 kB、能耗 <75 J、準確率最高 98%。
  - Sec. VII-B（p.15506）：記憶體 950–1380 MB、CPU 72–95%、頻寬 <120 MB/s、能耗 61–80 J、延遲 8–14 ms。
  - 模型大小（Table I）：CNN 3,497 參數、CNN+LSTM 12,795、LSTM 56,386。
  - LLM 延遲：zero-shot 約 1.15 s、CoT 約 1.45 s（Sec. IX-C，Fig. 16）。
  - 結論：換 LLM 對 CPU／記憶體／能耗差異不顯著（只有 DoS 時 LLaMA3.5 記憶體較高、DDoS 時 GPT-4-turbo 頻寬較高）。

### 數字的可信度問題（注意，不要拿來比）
- Abstract 說能耗 <75 J，但 Sec. VII-B 報 61–80 J（超過 75）。
- Sec. VII-B 報延遲 8–14 ms，但 Fig. 14（p.15508）的延遲軸是 1.0 s（加 LLM 前）到 1.2–1.35 s（加 LLM 後），並說「延遲增加 <35%」；ms 與 s 兩組數字沒有被解釋。
- CPU 72–95% 是整個 ML＋遙測流程的整體使用率，沒有拆出「單筆推論」成本。
- 所以本文不適合當可比數字來源。

### 特別檢查
- **同機互相干擾**：沒有。LLM 在雲端，沒有第二個同機工作與 ML 競爭；也沒有針對快取、記憶體頻寬、核心爭用的實驗。
- **依負載調整 ML 工作量或核心分配**：沒有核心分配。唯一的動態調整是 (a) 只有 s_t 超過門檻才呼叫 LLM（事件觸發）、(b) g_t 依延遲／連線狀態抑制 LLM 呼叫、(c) 能耗與延遲預算（T_max=1.5 s、E_budget=100 J）。這些是依「異常與網路狀態」開關遠端呼叫，不是依本機負載比例縮放本機 ML 工作。
- **fast path／放行後不檢查**：沒有。本地 ML 對所有流量算特徵與分數。
- **只檢查部分封包／flow**：LLM 只看被標異常的事件的 telemetry（不是封包），但本地 ML 看全部。不是我們的「部分封包檢查」。

### C1–C4 標記
- **C1：none**。無放行後稽核。
- **C2：none**。非 inline，無有狀態 IDS，無部分封包。
- **C3：related（弱）**。證據：Sec. V-C p.15497（Pi 4、ML IDS 資源量測）；Sec. IV-K p.15496（閘函數依延遲決定是否呼叫 LLM）。缺的關鍵要素：(a) 沒有規則式 IDS；(b) ML 與 LLM 不同機（LLM 在雲端）、沒有同機爭用；(c) 沒有量測互相干擾；(d) 沒有依負載調整本機 ML 工作量或核心分配。
- **C4：none**。Sec. XI-B 明說不是 inline，沒有 kernel fast path。

### 可與我們實測比較的數字
沒有。沒有 Suricata／Snort，沒有每封包成本、沒有吞吐（pps）、沒有丟包；延遲與能耗數字內部不一致（見上）。唯一可借用的是 Table I 的小模型參數量（3.5 K–56 K 參數），可用來說明「文獻中 edge ML-IDS 的模型比我們替身的 6 MiB MLP 小很多」，但這條與我們的 C 無關。

### 我們論文怎麼引用
作為背景／反襯：說明 edge gateway 上「ML＋LLM」的文獻多半把重推論放到雲端（只送 telemetry），所以不會碰到同機干擾；而我們的情境是 edge AI 與 Suricata 同機。不要把它當成 C3 的先行研究。

### 雪球
沒有明確比它本身更接近 C1–C4 的引用（參考文獻以 ML-IDS 綜述、XAI、LLM 為主）。低優先度的弱候選：
- [40] Otoum, Asad, Nayak, "LLM-based threat detection and prevention framework for IoT ecosystems", arXiv:2505.00240, 2025。BERT 變體＋規則式決策引擎做即時緩解、Docker 容器、受限資源評估；從本文的描述看可能有「prevention」路徑，但是否有 rule IDS 或同機資源分析不明，需讀全文。
- [9] Jamshidi, Nafi, Nikanjam, Khomh, "Evaluating machine learning-driven intrusion detection systems in IoT: Performance and energy consumption", Computers & Industrial Engineering 204 (2025)。同作者先前的邊緣 ML-IDS 資源與能耗量測，可能量到 Pi 上的 CPU／記憶體，但不太可能有 rule IDS 與干擾。
- [44] Adjewa et al., "Efficient federated intrusion detection in 5G ecosystem using optimized BERT-based model", WiMob 2024，Raspberry Pi 上推論 0.45 s，只是延遲數字。

---

## 本組總結

- **C1、C2、C4：三篇都沒有碰到。** 沒有任何一篇有 bypass／信任放行、部分封包檢查、或 kernel fast path；n=486 還明說不是 inline IPS。
- **C3 是這組最可能被碰到的，但程度只到 related，不到 overlap。**
  - 最接近的是 **n=435**：同樣是 Pi 4、同機多個工作，且作者以 L2 cache 與單通道記憶體頻寬解釋 ML 工作撞牆、無法同時推論與重訓，並有依 buffer 占用與異常分數動態分配 consumer 時間的排程。但它沒有規則式 IDS 或封包轉送、干擾只是推測而沒有隔離實驗、動態分配發生在 ML 實例之間而不是 ML 與 IDS 之間、流量由檔案餵入。
  - **n=3**：ARM 上 Suricata 與其他程式同機，並用核心切分，但目標是功耗、其他程式未說明、沒有 ML、沒有干擾量測、切分是開關式。
  - **n=486**：「IDS＋LLM」，但 IDS 是 ML 分類器、LLM 在雲端，所以沒有同機爭用。
- **我們 C3 仍可站得住的部分**：「規則式 IDS（Suricata NFQ）與 ML 替身負載同機、分別量測記憶體頻寬、快取（6 MiB MLP）、同核心 SCHED_IDLE、依比例 duty-cycle 的 Suricata 每封包成本與丟包」，這三篇都沒有。寫 C3 時要明講的區分點是「同機的是**規則式 IDS 的封包路徑**與 ML，不是 ML 與 ML」，以及「用實驗而非推測」。n=435 的記憶體頻寬論點可當旁證引用，讀者容易拿它質疑我們，建議在 related work 主動說明差異。
- **這組沒有雪球漏網的明顯證據**：三篇的引用文獻都沒有更接近 C1–C4 的標題；唯一值得低優先度確認的是 n=486 的 [40]。
