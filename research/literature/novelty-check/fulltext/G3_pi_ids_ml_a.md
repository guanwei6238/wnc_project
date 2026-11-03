# G3 全文精讀：Pi 上 rule IDS＋ML（a 組，3 篇）

判斷基準：`SCREEN.md` 的 C1–C4。三篇文字檔皆完整讀過；Fig./Table 以 PDF 頁面核對（paper 1 Fig. 1–3、paper 2 p.1–3 的 Fig. 1–7、paper 3 Fig. 7 / p.18）。
凡論文沒寫的寫「論文未說明」。「雪球」一節的文獻只讀了引用條目（標題／年份），沒有讀全文，標示為「未讀」。

---

## 1. n=408　Monsakul — Real-Time Network IDS for SOHO Using Hybrid Edge ML Techniques

**書目**：Techit Monsakul（Assumption College, Bangkok）。2026 7th Int. Conf. on Big Data Analytics and Practices (IBDAP 2026)，DOI 10.1109/IBDAP69915.2026.11678008。

### 他們做了什麼

- **架構**：Suricata 當主要偵測（Emerging Threats ruleset），只有「產生 alert 的 flow」才轉成 feature vector 丟給 ML（Random Forest）做二次分類與 alert enrichment，結果經 Discord webhook 送出。ML 不看沒有 alert 的流量（Sec. III-D：「Flows without a corresponding Suricata alert are not processed by the ML component」）。沒有 decision-level fusion。Suricata 與 ML 都在同一台 edge 設備上（Pi 4 或 Mini-PC）。分工是「順序式」：先 Suricata、後 ML，ML 負載由 alert 率決定。
- **平台**：Raspberry Pi 4，4 GB RAM，Quad-core Cortex-A72 @ 1.5 GHz，Raspbian（Sec. IV-A）。對照機：Mini-PC Intel Celeron J4125、8 GB、Ubuntu Server。兩台接同一個 Gigabit Ethernet switch。
- **IDS 版本與模式**：本文未寫 Suricata 版本與 inline／IDS／IPS／NFQ／af-packet／pcap 模式。Fig. 3B 的終端機截圖（解析度低）疑似顯示 `Suricata version 8.0.0-dev`，本文沒有提，不採信。Fig. 1 看起來 Pi 接在 L2 switch 旁，不是串在 router/firewall 與內網之間，推測是旁路 IDS，但論文未明講。論文把它當偵測＋通知系統，沒有講 drop。訓練用 Suricata offline mode 解析 CIC-IDS2017 pcap（Sec. III-A step 1），即時部分寫 "Suricata processed the live network traffic"（Sec. IV-F）。
- **ML**：RF／DT／XGBoost／KNN／LR 比較，RF 最好（accuracy 0.9959、weighted F1 0.9959），資料是 CIC-IDS2017 中「有 Suricata alert 的約 20 萬筆 flow」（約 12% 為攻擊）。推論時機：每個「完成的 alert flow」一次（Sec. III-F）。Table I 是離線結果，confusion matrix 顯示 DDoS、SlowHTTPTest、Heartbleed、Misc 常被判成 benign（Fig. 5）。
- **量測**：lab 內 10 分鐘 feasibility test。正常流量（web／檔案傳輸／影片）加 hping3 DDoS flood、Hydra SSH brute force、port scan（Sec. IV-A）。速率、封包大小、封包數：論文未說明。量了 CPU 平均、feature-to-classification 延遲平均、「不累積 backlog 的持續吞吐」。沒有量丟包、每封包成本、記憶體、變異數；沒有重複次數。結論明寫「Future work will ... examine packet loss and latency during longer high-load tests」。
- **主要數字**（Table II）：Pi 4：CPU 62%、延遲 145 ms、82 Mbps；Mini-PC：CPU 37%、72 ms、310 Mbps。

### 特別檢查

- **同機互相干擾**：沒有。沒有「只跑 Suricata」的基準，所以 62% CPU 無法拆成 Suricata 與 ML 各多少；CPU 的分母（4 核平均或單核）論文未說明；無快取、記憶體頻寬、CPU 爭用的量測。
- **依負載調整 ML 或核心分配**：沒有實作。Sec. IV-D 說「The current prototype did not implement overload-control mechanisms」，但列了未來可做的緩解：bounded processing queue、高嚴重度 alert 優先、batch inference、「temporary sampling of low-priority flows」、超過 CPU／queue／丟包門檻就把部分 flow offload 到 Mini-PC、通知限速。這些是點子，不是實作也沒有數據，並明說「require evaluation」。
- **fast path／放行後不檢查**：沒有。
- **只檢查部分封包**：Suricata 看所有流量（論文未說明有任何部分檢查）。「只有 alert flow 進 ML」是 ML 側的過濾，不是 IDS 的部分檢查。

### 對 C1–C4

| 貢獻 | 標記 | 證據與理由 |
|---|---|---|
| C1 | none | 沒有放行／信任／稽核；ML 是 alert 的後處理（Sec. III-D）。方向相反（先檢查、後分類），不是「放行後拉回檢查」。 |
| C2 | none | Suricata 處理全部即時流量（Sec. IV-F），無只送訊息開頭的概念，也沒有討論有狀態 IDS 接受部分封包。 |
| C3 | related | 同機 Suricata＋RF 跑在 Pi 4，量 CPU／延遲／吞吐（Table II）。缺：沒有量干擾（無 Suricata-only 基準、無記憶體頻寬／快取、無丟包）；沒有依負載調整的實作（只在 Sec. IV-D 列為未來緩解：batch、sampling、offload）。 |
| C4 | none | 沒有 conntrack／tc／XDP／flowtable／bypass，沒有每封包成本。 |

### 可拿來比的數字

- Pi 4（A72 @ 1.5 GHz，4 GB）＋Suricata（ET ruleset）＋RF：持續 82 Mbps、CPU 平均 62%、feature-to-classification 平均 145 ms（Table II，10 分鐘 lab、混合正常＋攻擊流量、無 backlog）。
- 封包大小與 pps 論文未說明，無法換算每封包成本。僅供數量級對照（這是我算的，不是論文數字）：若平均封包 500／1000／1500 B，82 Mbps 約 20.5／10.3／6.8 kpps，我們的 NFQ 整台約 60 kpps。但規則集、模式、流量都不同，只能當背景。
- 時脈：論文 1.5 GHz，與我們的 Pi 設定（1.8 GHz）不同。

### 引用方式

作為**比較對象**（C3 的 related work）：已有人在 Pi 4 同機跑 Suricata＋ML，但只報整體 CPU／吞吐／延遲，沒有干擾量測、沒有丟包、沒有調整。也可以用它的 Sec. IV-D 說明「業界已意識到需要 overload control，但未實作未量測」。引用時不要寫成「沒有人在 Pi 上同機跑 IDS＋ML」，要寫成「沒有人量化同機干擾」。

### 雪球

- [21] Hafeez, Ding, Suomalainen, Tarkoma, "Demo abstract: SecureBox—A platform to safeguard network edge," IEEE/ACM SEC 2016。標題是 edge 安全閘道平台，paper 1 引它說明「在 smart-home／edge 的 NIDS 受 CPU／記憶體限制」。可能比本篇更接近我們的整體定位（gateway 上的流量處理／卸載）；demo abstract，內容可能很短。未讀。
- [20] Alsakran, Bendiab, Shiaeles, Kolokotronis, "Intrusion detection systems for smart home IoT devices: Experimental comparison study," Springer CCIS 1208, 2020。標題是 IDS 在家用設備上的實驗比較，可能有 Pi 上 Snort／Suricata 等的資源與效能基準，可作為可比數字來源。未讀。
- [14][15] Shapira & Shabtai, "Intrusion detection system for home IoT devices," ICC 2020／JISA 2020。paper 1 說它們顯示「lightweight ML 可補強 rule-based」；可能有 gateway 上 rule＋ML 並存，但是否量資源未知。未讀。
- [11] Kim, Choi, Kim, "Lightweight anomaly detection for IoT environment," ICCE 2018。paper 1 用來說明 ML 搬到 Pi 的計算成本。可能有 Pi 上推論成本數字。未讀。

以上都沒有看出 C1／C2／C4 層面的線索（引用標題都與 fast path、部分檢查無關）。

---

## 2. n=293　Hidayatullah, Karna, Dewanta — IoT Network Security with IPS Based on SnortML

**書目**：Fajar Hadi Hidayatullah, Nyoman Karna, Favian Dewanta（Telkom University, Bandung）。2025 Int. Conf. on Informatics, Multimedia, Cyber and Information System (ICIMCIS)，pp. 1520–1525，DOI 10.1109/ICIMCIS68501.2025.11327354。

### 他們做了什麼

- **架構**：Pi 當閘道，「all traffic is routed through the host device, which functions as the gateway」（Sec. II，Fig. 1）。流程（Fig. 1）：封包先比對 Snort 規則，有 match 就 drop；沒 match 才交給 SnortML 推論，機率 ≥ 80% 就 drop，否則放行（Sec. II：「if no match is found, inference is performed」）。規則與 ML 在同一個 Snort 進程、同一台機器、串聯。但實驗時「Snort is implemented without any rules」（Sec. III），所以實際只有 ML 在判斷。
- **平台**：Raspberry Pi 3B 與 Raspberry Pi 4。CPU 型號／頻率、RAM 容量：論文未說明（只說 Pi 4 的 RAM 比較大，且 RAM 使用率約 9%，Pi 3B 約 58–80%）。OS：論文未說明。
- **IDS 版本與模式**：Snort 版本論文未說明（提到 SnortML 只有最新 Snort 才有，推斷是 Snort 3，但論文沒寫）。inline／NFQ／DAQ：論文未說明（只說 IPS 會 drop）。
- **ML**：CNN（Conv1D 16 filters）與 LSTM（16 units），UNSW-NB15 訓練（45 特徵，70% 訓練，SMOTE，5 epochs，8-fold）。二元分類。推論頻率：論文未說明（只說沒有規則 match 時做推論）。論文未說明 SnortML 如何載入／餵這些 flow-feature 模型。
- **量測**：三種情境（benign、LOIC DDoS、Caldera exploit），記錄 CPU%、RAM%、traffic（Kbps）、alert 與 pcap，算 accuracy／recall／precision。每個情境的時間長度、重複次數、攻擊速率：論文未說明。
- **主要數字**（Table I／II）：Pi 4 CNN accuracy 65.86%、recall 52.11%、precision 100%；Pi 4 LSTM 61.61%；Pi 3B CNN 59.08%、LSTM 60.39%。Pi 4 CPU 8.95–9.77%、RAM 8.3–9.5%、traffic 4.67–36.92 Kbps；Pi 3B CPU 9.99–11.5%、RAM 57.9–79.6%、traffic 3.8–65.5 Kbps。

### 特別檢查

- **同機互相干擾**：沒有。沒有基準對比，只回報平均 CPU／RAM；流量只有幾 Kbps 到幾十 Kbps，不可能讓 CPU 或記憶體頻寬成為瓶頸。
- **依負載調整**：沒有。結論只建議未來「integrate real-time adaptive learning methods to enable dynamic rule adjustments」（那是調規則，不是調 ML 工作量或核心）。
- **fast path／放行後不檢查**：沒有。
- **只檢查部分封包**：沒有（所有封包先比規則、再進 ML）。

### 對 C1–C4

| 貢獻 | 標記 | 證據與理由 |
|---|---|---|
| C1 | none | 無信任／放行／稽核；所有封包都走規則→ML（Fig. 1）。 |
| C2 | none | 無部分檢查，無有狀態 IDS 的缺口分析。 |
| C3 | related（弱） | Pi 4 上同一 Snort 進程內「規則→ML」並量 CPU／RAM（Table II）。缺：規則為空；流量僅 Kbps 等級；無基準、無干擾量測、無丟包、無調整；ML 準確率只有約 66%。 |
| C4 | none | 無 conntrack／eBPF／XDP／flowtable，無每封包成本。 |

### 可拿來比的數字

- Pi 4：CPU 約 9–10%、RAM 約 9%，伴隨 4.7–36.9 Kbps 流量（Table II）。流量量級比我們低 5 個數量級以上（我們 60 kpps），不能比吞吐或每封包成本。
- 論文轉述前人數字（二手，非本篇量測）：Pi 上 Snort IPS 對 SYN flood 丟 41.48%、UDP flood 丟 28.27%（Sec. I，引 [5]）。這是 Pi 上 inline Snort 的丟包基準，來源是 [5]，需讀 [5] 原文才能引。
- 模型大小：論文只寫 Conv1D 16 filters／LSTM 16 units，與我們 6 MiB MLP 差很多，不能直接比。

### 引用方式

作為**背景**（Pi 上 Snort＋ML 的示範性嘗試），同時是**反駁對象**：效能量測只報 CPU／RAM 平均、流量只有 Kbps，無法回答同機 IDS＋ML 是否互相干擾；準確率 66% 也不足以作為可行性證據。

### 雪球

- [5] Wiranata, Karna, Irawan, Prakoso, "Implementation and analysis of network security in raspberry pi against dos attack with hips snort," ICCoSITE 2023。Pi 上 inline（HIPS）Snort 對洪水攻擊的丟包 41.48%／28.27%。與我們的 C3／C4 量測對象（Pi 上 Snort 的處理上限）更接近，是 Pi 上 inline 規則式 IDS 的基準，值得讀全文。
- [9] Shah & Issac, "Performance comparison of intrusion detection systems and application of machine learning to Snort system," Future Generation Computer Systems 80, 2018。在 Snort 內加 ML 並比較 IDS 效能，可能最接近「rule IDS＋ML 同機」的老牌工作，是否量資源與干擾要讀才知道。
- [11] Eskandari, Janjua, Vecchio, Antonelli, "Passban IDS: An intelligent anomaly-based IDS for IoT edge devices," IEEE IoT Journal 7(8), 2020。在 Pi 級 edge 閘道上跑 ML IDS，可能報 CPU／記憶體；是否與規則 IDS 並存未知。
- [8] de la Cruz et al., "Intrusion detection and prevention system for production supervision in small businesses based on Raspberry Pi and Snort," INTERCON 2020。Pi＋Snort IPS 的實作，可能有效能數字。
- [17] Fadhlillah, Karna, Irawan, "IDS performance analysis using anomaly-based detection method for DoS attack," IoTaIS 2021（Pi 上 Snort）。
- [16] Soe et al., "Implementing lightweight IoT-IDS on Raspberry Pi using correlation-based feature selection and its performance evaluation," AINA 2019（Pi 上 ML IDS 成本）。

以上都未讀，也看不出 C1／C2／C4 的線索；其中 [5] 與 [9] 最值得補讀。

---

## 3. n=4　Stolz & Zhang — A blockchain-enabled hybrid intrusion detection framework for resource-constrained devices

**書目**：Charles Stolz, Jielun Zhang（University of North Dakota）。PeerJ Computer Science 12:e3899，2026-06-30 發表，DOI 10.7717/peerj-cs.3899。為 IEEE MILCOM 2025 會議版的擴充。

### 他們做了什麼

- **架構**：分散式混合 IDS。每個 Pi 節點同機跑：Snort（簽章）、FL client（ANN 異常偵測）、host-based transformer（BERT-mini 分析系統 log）、Hyperledger Fabric peer／orderer、Prometheus／Glances 監控（p.6–7）。ESP32 以 MQTT 送 metadata 到 Pi。區塊鏈用來記錄 model hash 與 reputation 分數（防 FL 投毒與 Sybil）。各偵測層「operates independently」（Threat Model 節），沒有 Snort 與 ML 的串接／分工（Future work 才說要 "more tightly fuse"）。
- **平台**（Table 1，p.9）：Pi 4B 4 GB ×2（alpha、beta）、Pi 5 8 GB ×2（epsilon、zeta）、ESP32 ×6；Debian-based 64-bit。資源量測是在 node-beta（Pi 4B 4 GB）。CPU 頻率論文未說明。模型訓練（transformer）在工作站（Ryzen 9 5900XT、RTX 5070 Ti），不在 Pi 上。
- **IDS 版本與模式**：Snort 2.9（p.8）；inline／IDS／NFQ／DAQ：論文未說明。Snort 驗證是 hping3 SYN flood 打 node-beta 的 port 80，自訂規則 SID 1000002，「Snort successfully detected the attack」（p.14）。看起來是主機上的偵測，不是 inline 閘道。ESP32「forwarding traffic to Raspberry Pi gateways」（p.8），但沒說 Snort 串在路徑上。
- **ML**：ANN 78-64-32-1（CICIDS2017 二元）FL 訓練；BERT-mini（11M 參數）／DistilBERT／ELECTRA-small 做 HDFS log 異常偵測。推論頻率：log 每行一次推論（Algorithm 3），網路流量的 ANN 推論頻率論文未說明。
- **量測**：Table 12 是 node-beta 上的「resource utilization snapshot」，同時跑 Flower client、Fabric、Snort、監控；Fig. 7／Table 13 是 BERT-mini 等推論延遲（「with concurrent blockchain services」）；Table 14 是 Fabric 交易吞吐。沒有流量速率（只有 SYN flood 一次定性）、沒有丟包、沒有 Snort 每封包成本。
- **主要數字**：Snort SYN flood 時 CPU 約 47%（p.14，僅此一句）；Table 12（p.17）：總 CPU 35.5%、Flower client 33%（佔總 CPU）、Fabric 約 20%、Snort <3%（31 MB）、記憶體 1.46/3.76 GB、CPU 溫度 50 °C；BERT-mini 推論 58.8 ± 23.7 ms（P95 103 ms；圖說寫 57.8 ± 23.1，與 Table 13 不一致）；Fabric 21.47 TPS／736 ms。

### 特別檢查

- **同機互相干擾**：沒有量。只有利用率快照。論文結論句是「without overwhelming the platform or introducing latency due to resource contention」（p.17），但全文沒有任何量測支持「沒有 contention」：沒有 Snort-alone 基準、沒有丟包／延遲對照、沒有快取或記憶體頻寬、沒有改變 ML 負載觀察 Snort。Snort <3%（快照）與 47%（SYN flood）是不同時間點、不同條件，也不在同一個負載下與 ML 並存比較。
- **依負載調整**：沒有實作。Glances 的用途寫成「to support resource-aware model adaptation and benchmarking」（p.7），後文未見任何 adaptation 機制或數據。
- **fast path／放行後不檢查**：沒有。「trust」「reputation」全部指 FL 節點信任，與 flow 信任無關。
- **只檢查部分封包**：沒有。

### 對 C1–C4

| 貢獻 | 標記 | 證據與理由 |
|---|---|---|
| C1 | none | 「trust／reputation」是 FL 節點與區塊鏈上的信任（p.6、Algorithm 2），不是 flow 放行；無放行後稽核。 |
| C2 | none | 無部分檢查。 |
| C3 | related（弱） | Pi 4 上同機跑 Snort＋FL client＋Fabric＋監控，並給 CPU／記憶體快照（Table 12，p.17）。缺：沒有量干擾（無基準、無頻寬／快取、無丟包）、Snort 負載不是穩定壓力、ML 是 FL 訓練與 log transformer 推論而非封包推論、「resource-aware model adaptation」只是動機未實作。 |
| C4 | none | 無 conntrack／eBPF／XDP／flowtable／bypass，無每封包成本。 |

### 可拿來比的數字

- Pi 4B 4 GB 同時跑 FL client＋Fabric＋Snort 的快照：總 CPU 35.5%、Snort <3% CPU／31 MB（Table 12，p.17）。條件不明（Snort 是否有流量、速率），不能當作 Snort 處理成本。
- Snort 2.9 在 SYN flood 下 CPU 約 47%（p.14），流量速率論文未說明。
- BERT-mini 推論 58.8 ± 23.7 ms、P95 103 ms；DistilBERT 291.7 ms；ELECTRA-small 386.7 ms，Pi 4、有區塊鏈服務並行（Table 13，p.18–19；沒有 Snort 並行）。
- ANN 78-64-32-1 約 7.2k 參數（我算的：5056＋2080＋33），遠小於我們的 6 MiB MLP；其推論成本論文未量。

### 引用方式

作為**背景**（證明 Pi 級設備上同機跑多個 IDS 元件在業界被當成可行）以及**反駁對象**：它只用利用率快照宣稱「沒有 resource contention」，我們用 Suricata 每封包成本與丟包證明，利用率快照會漏掉記憶體頻寬干擾。

### 雪球

- Stolz, Li, Zhang, "Implementing lightweight intrusion detection system on resource constrained devices," 2024 CARS（自引）。可能有 Pi 上 IDS 與 ML 的效能量測；從標題看比本篇更聚焦於資源受限設備上的 IDS 實作，值得讀。未讀。
- Stolz & Zhang, "Blockchain-enabled distributed IDS for securing IoT networks," MILCOM 2025（本篇的會議版）。預期內容是本篇的子集，不太可能有更多資源量測。未讀。
- Gujarati et al., "Serving DNNs like clockwork: performance predictability from the bottom up," OSDI 2020（本篇引用來說明 100 ms 推論延遲界線）。談的是 DNN serving 的延遲可預測性（資源隔離），屬於 C3 的 ML 端思路，但不是 IDS／edge，不是同機 IDS＋ML。可當「推論延遲要可預測」的引用。未讀。
- Gurung et al. 2022 "CIDS: collaborative IDS using blockchain," IEEE CSR（Snort＋Fabric）。與 C1–C4 無關。

沒有發現比本篇本身更接近 C1／C2／C4 的引用。

---

## 本組總結

- **C1、C2、C4：三篇全部 none。** 三篇的引用清單裡也沒有任何標題談 flow bypass／信任放行／NFQUEUE 卸載／部分封包檢查／conntrack／tc／XDP，因此這組不是這三點的好雪球來源。
- **C3 是這組唯一被碰到的點，程度是「related」（弱到中）。**
  - 最接近的是 paper 1（n=408）：同一台 Pi 4 上跑 Suricata＋RF，有 CPU 62%、82 Mbps、145 ms，而且 Sec. IV-D 列出未實作的緩解方向（bounded queue、batch inference、temporary sampling、超門檻 offload），與「依負載調整 ML 工作量」概念相近。它沒有任何干擾量測（無 Suricata-only 基準、無丟包、無記憶體頻寬／快取）、沒有實作調整、ML 只對 alert flow 動作（工作量由 alert 率決定，不是被調的）。
  - 因此 C3 不能寫成「首先提出要依負載調整 ML」，要寫成「首次量化同機干擾（記憶體頻寬、SCHED_IDLE 同核、MLP 大小、duty-cycle 比例）並驗證 duty-cycle 有效」，並引用 paper 1 的 Sec. IV-D 作為「已有人點出需要 overload control，但未實作、未量測」。
  - paper 2、3 只有利用率快照；paper 3 還直接宣稱「沒有 resource contention」卻沒有量，正好是我們的反駁對象。
- **這組三篇的量測嚴謹度偏低**（流量 Kbps 到幾十 Mbps、無丟包、無每封包成本、無重複與變異），不能當成 Pi 4 上 Suricata 吞吐的比較基準；唯一像樣的比較數字是 paper 1 的 82 Mbps／CPU 62%，但封包大小未說明。
- **後續建議**：雪球優先讀 [paper 2 引用的] Wiranata 2023（Pi 上 inline Snort 丟包）、Shah & Issac 2018（Snort＋ML）、Passban 2020（Pi 級 edge 上 ML IDS），以及 paper 3 的自引 Stolz 2024 CARS，用來確認 C3 在「同機 IDS＋ML」的先前量測。要查 C1／C2／C4 需要從別的種子出發（建議搜尋關鍵字，非本組引用內容：Suricata bypass／flow shunting、IPS flow offload、elephant flow 卸載、partial packet inspection、TCP reassembly midstream）。
