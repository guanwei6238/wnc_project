# D 組：類似的框架（同一台 gateway/edge 上 rule IDS + ML + 雲端）

查證日期 2026-11-02。邊界、證據標記、格式照 `../fastpath-methods/SPEC.md` §3–§7 與 `SPEC.md`。頁碼 `p.N` 是 PDF 頁序（Realguard 沒有頁碼，因為取自 PMC 的 JATS XML，改標章節或表號）。下載與轉出的文字在 `pdfs/<slug>/`。

## 0. 結論

1. **D1**：我沒有找到「同一台資源受限 gateway 上同時跑規則 IDS 和 ML、並有流量分工策略」的系統。找到的共存例子都是把同一份流量複製給各引擎平行跑，事後用時間／IP 關聯告警：Hybrid-NIDS（Suricata + RF，SPAN 鏡像，虛擬機）[原文 p.2–3]；Merkhoufi 碩士論文（Snort + Suricata + DL，Pi 5，Fig.5.7 "Traffic Cloned"）[原文 p.64–65]；SUKRY（Suricata + OPNids kNN，Pi，只有部署步驟）[原文 §4.5]。三者都沒有「哪些流量給規則、哪些給模型、誰決定」的規則，也沒有把雲端放進偵測迴路。
2. **D2**：沒有一篇有核心／記憶體分配機制（固定或動態），也沒有一篇量兩者互相干擾。Hybrid-NIDS 自承 CPU、RAM、Disk I/O、丟包「尚待在受控負載下量化」[原文 p.4]；Merkhoufi 只有一句定性敘述（三個引擎同時跑時處理力受限）[原文 p.65]。唯一有「加了 ML IDS 後轉送變慢」數字的是 Passban，但它沒有規則引擎，而且我只拿到二手：Pi 轉送上限 93.9 → 77.2 Mb/s（−17.8%），CPU 18.42% → 47.17% [二手 SNU 研討會投影片]。
3. **D3**：Pi 4B 上有 ML-only 數字，沒有「Suricata + ML 同機」數字。Realguard（Pi 4B）每封包 DNN 10,600 pkt/s、CPU 36%、RAM 114.5 MB [原文 Table 6/7]；EcoDefender（Pi 4B）每 flow 27 ms、CPU 22%，但同一篇的 Table XIX 是 31.7 ms／19.8%，內部不一致 [原文 p.1, p.15]。
4. **D4**：沒有找到「ML 決定哪些 flow 跳過 IDS」或「IDS 結果決定哪些流量給 ML」的實作與量測。最接近的是 Wu 等人（Pi 5）：Isolation Forest 每窗算門檻 → per-IP blocklist → XDP_DROP [原文 p.12–13]，方向是「模型 → 丟棄」，不是「模型 → 信任」。規則 → ML 的升級只見於二手（Sedjelmaci 2016、Meng 2015，經由 Spadaccino & Cuomo 綜述）[二手 arXiv 2012.01174 p.6–7, §6.2]。
5. **D5**：空缺 [推測] 有三個：(a) 流量分工與預算（誰進規則、誰進模型、誰上雲）沒人做；(b) 同機共存的干擾沒人量（規則丟包、模型延遲、轉送三者一起量）；(c) 模型輸出接到「信任」（ct mark）的迴路沒人做，現有只有模型接到「封鎖」。可借用的是量測方法（Passban 的有／無對照）和 Wu 等人的「模型 → 核心端 map」介面設計。

---

## 1. 逐篇

### Hybrid-NIDS（Tang, Huynh, Phan, Nguyen-An，arXiv:2609.24393 [cs.CR]，2026-09-21）

- **書目／取得程度**：Passive Hybrid Network-Based Intrusion Detection System (Hybrid-NIDS) Combining Suricata and Random Forest。Ho Chi Minh City College of Transport 等。arXiv 預印本，未見同儕審查標記。**全文**（7 頁，逐頁讀過）。這篇是我搜尋時 Suricata + ML 同機最直接的一篇，派工書目沒列到。
- **機制**：流量經 SPAN／port mirroring 複製，感測器不在轉送路徑上 [原文 p.2]。Suricata 產生 EVE JSON 告警；NFStream 從 PCAP／即時流量抽 21 個 flow 特徵給 RF-21；兩邊告警用時間（預設 ±60 s）和 IP／port 關聯，再進 Logstash／Elasticsearch／Kibana [原文 p.2–3, Table I]。沒有任何「哪些流量給誰」的規則：兩個分支看到同樣的鏡像流量。系統只偵測，不封鎖 [原文 p.1]。
- **偵測面**：UNSW-NB15 離線 hold-out：RF-41 F1 0.9714、RF-21 F1 0.9701 [原文 p.4 Table IV]。換到實驗室流量就垮：標註 PCAP 上 RF-21 recall 0.0095（105 個攻擊事件只抓到 1 個），Suricata 抓到 61/105 但有 97 個誤報；另外 5 段各 60 秒攻擊 session，RF-21 一個告警都沒有，Suricata 平均 recall 0.87 [原文 p.4–5 Table VII/VIII]。作者的結論：ML 分支幾乎無聲時，關聯不能提升召回，有用的偵測量由 Suricata 承擔 [原文 p.4]。
- **成本面**：虛擬機上的 Ubuntu 平台（CPU／核數／記憶體論文未說明）[原文 p.2]。純模型推論（不含抓包、flow 組裝、NFStream、I/O）：batch=1 為 49.11 ms/flow（20.4 flows/s），batch=1024 為 0.066 ms/flow（15,154 flows/s），差約 744 倍 [原文 p.5 Table VI]；每次 5 次重複，100,000 筆 hold-out。儀表板快照 CPU 57.1%、RAM 75.5%，作者明說只是單一時點、不是受控平均，也不隔離 NFStream 成本 [原文 p.4]。未標註的一般流量 mini test：1,946,816 個封包、4,732 個丟包（約 0.24%），2,375 個 flow，RF-21 發 439 個告警，推論 14.831 s [原文 p.5 Table IX]；沒有「不開 ML」的對照組，所以不能說 0.24% 是否由 ML 造成。
- **對我們的意涵（[推測]）**：(1) 證實「同機放 rule + ML」本身沒有現成的資源分配做法可抄；(2) batch size 對每 flow 成本的影響（約 3 個數量級）要在我們的 edge AI 介面上被當成一階參數，邊緣模型若是一 flow 一次呼叫，成本會落在這個表的最左邊；(3) 評估框架的教訓：benchmark 分數和實際流量差距極大，gateway 要有「各引擎各自貢獻多少告警」的紀錄才能發現模型靜默。
- **限制**：作者承認 hold-out 只做了精確特徵雜湊去重，未排除時間洩漏；實驗室測試只有 538 個事件和 5 個 60 s session；最大吞吐、flow 到告警延遲、丟包計數「尚待量化」[原文 p.4]。我觀察到：資源數字不在 Pi 上、也沒有 baseline（不開 RF）對照，所以對 D2/D3 的貢獻只是「沒有人量過」的證據 [推測]。

### Merkhoufi 碩士論文（Univ. of El-Oued，2025）

- **書目／取得程度**：Build an Intrusion Detection System on a Raspberry Pi，Merkhoufi Mohamed Naoui，指導 Dr. Saci Medileh，Option: IoT and Cybersecurity，2024/2025 學年；機構庫 https://archives.univ-eloued.dz/handle/123456789/39216 。**全文下載（97 頁）；讀了摘要、第 2 章文獻與架構、第 4 章測試環境與結果表、第 5 章架構／實作／挑戰、結論；資料集與模型訓練章（第 3 章）只掃過**。這是碩士論文，沒有同儕審查，品質參差 [推測]。
- **機制**：Raspberry Pi 5、Kali Linux。Scapy 在 wlan0 抓包 → 特徵抽取 → "Traffic Cloned" 同時送給 Snort、Suricata、DL 模型三條路 [原文 p.64–65 Fig.5.7]；Snort 寫文字 alert 檔，Suricata 寫 eve.json，DL 結果顯示在 Flask 網頁 [原文 p.64]。三個引擎之間沒有分工，也沒有告警融合邏輯。論文內部不一致：§2.2.3 寫「本專案採用 signature-based 方法」[原文 p.12]，但摘要和第 5 章都稱混合。
- **偵測面**：Table 4.2 用 High／Medium／Low／Very High 等定性評等比較三者，沒有數字。例如 Slowloris：Snort Low、Suricata Limited、ML Very High；Heartbleed：Snort Very Low、Suricata Partial、ML High [原文 p.54]。作者的解讀是預設規則抓不到慢速與應用層攻擊，ML 補上 [原文 p.55]。
- **成本面**：全文沒有任何 CPU／RAM／延遲／吞吐數字（我 grep 過 CPU、RAM、latency、throughput、drop，皆無）。唯一資源敘述是挑戰清單：「Pi 的硬體限制了高吞吐即時處理，特別是 Snort、Suricata 與 ML 模型同時跑時」；「整合模型帶來分類延遲」[原文 p.65]。建議做法是把 ML 推論卸載到更強的 edge server 或雲端 [原文 p.66]。
- **對我們的意涵（[推測]）**：它是「同機三引擎都開」在 Pi 級硬體上確實會撞到資源上限的第一手（但無數字）證據，同時它的「卸載推論到雲端」建議與我們的方向一致。它沒有任何可借用的機制。
- **限制**：封包以 Python Scapy 在 wlan0 抓，不是 inline 轉送路徑；沒有負載實驗；ML 模型在第 3 章用 CSE-CIC-IDS2018 離線訓練，與即時流量的差距未討論（我只掃過第 3 章，這點未能確認 [推測]）。

### Realguard（Nguyen 等，Sensors 22(2):432，2022）

- **書目／取得程度**：Realguard: A Lightweight Network Intrusion Detection System for IoT Gateways，Xuan-Ha Nguyen, Xuan-Duong Nguyen, Hoang-Hai Huynh, Kim-Hung Le（PMC XML 作者欄），DOI 10.3390/s22020432，PMID 35062393，PMC8778231。**全文**（透過 NCBI efetch 取得 JATS XML 轉文字；MDPI 與 PMC 網頁／PDF 對自動下載回 403，沒有繞過）。派工書目沒列，從搜尋找到。
- **機制**：封包觀察元件（可用 NFQueue／afpacket／tshark）→ 以 Damped Incremental Statistics 做 O(1) 特徵抽取（100 個特徵）→ 5 個隱藏層、34,315 個參數的 DNN 判 10 種攻擊 → 動作管理（記錄、封鎖、寄信）[原文 §3.1–3.3]。每個封包都進特徵抽取與推論。沒有規則引擎，也沒有雲端。
- **偵測面**：CIC-IDS2017 重新逐封包標註；200,000 個封包／攻擊類型、400,000 個正常封包，5-fold；TPR 99.57%、FPR 0.04% [原文 §4.4]。最低的是 DoS Hulk 與 Botnet（約 98.45%），原因是這些攻擊封包本身和正常封包相似 [原文 §4.4]。
- **成本面**：Raspberry Pi 4B（Cortex-A72 ×4，1.5 GHz，8 GB），64-bit Ubuntu，Keras 2.4.3 / TF 2.4.0 [原文 §4.1, Table 2]。執行率（Exec Rate）Pi 上 10,600 pkt/s，PC（i7-9750H）88,200 pkt/s；Pi 上訓練率 1,150 pkt/s [原文 Table 6]。資源（Table 7）：Realguard CPU 36.0%、RAM 114.5 MB；Kitsune 33.8%／156.3 MB；RF 76.8%／180.3 MB；LSTM 47.6%／143.1 MB。CPU% 以整機還是單核為基準、執行率是否含抓包，論文未說明。Table 6 中 Kitsune 在 PC 的 37,300 與在 Pi 的 5,400，與 Kitsune 原論文數字相同 [既有筆記 research/literature/papers/kitsune.md Q1]（Kitsune 原文是 Pi 3B 單核），所以 [推測] 是引用而非在 Pi 4B 上重量；因此「雙倍於 Kitsune」的比較不是同硬體實測。
- **對我們的意涵（[推測]）**：10,600 pkt/s 換算約每封包 94 µs 牆鐘時間（1/10,600，單緒與否未說明），大約是我們量到「進 NFQ + Suricata 每封包約 40 µs 固定成本」的 2 倍 [fastpath-methods/SPEC.md §1]。若每個封包都進 DNN，和 Suricata 同機搶 4 顆核心不可行，ML 必須做在 flow／窗層級，且輸入要來自核心端已聚合的資料。
- **限制**：作者承認需要大量標註資料、模型對 adversarial 樣本脆弱、需頻繁重新訓練 [原文 §5]。我觀察到：資料集是 2017 年實驗室流量，與實際流量的差距沒討論（同 Hybrid-NIDS 的教訓）；Python／TF 2.4 的實作在新 Pi 上的成本要重測 [推測]。

### Jamshidi 等：Evaluating ML-Driven IDS in IoT（arXiv:2504.09634，2025；preprint submitted to Elsevier）

- **書目／取得程度**：Evaluating Machine Learning-Driven Intrusion Detection Systems in IoT: Performance and Energy Consumption，Saeid Jamshidi, Kawser Wazed Nafi, Amin Nikanjam, Foutse Khomh，Polytechnique Montréal。**全文**（21 頁）。**關鍵修正**：搜尋引擎摘要說它「量了 ML vs Snort 的 CPU」，這是錯的：第 6 節與 Table 17 的 Snort 欄全部引用「其他研究」[原文 p.15–17, refs 67–71]，他們自己的測試床只跑 ML 模型。
- **機制／成本面**：兩台 Raspberry Pi 4B（8 GB、1.5 GHz）當 edge gateway，測 DT、KNN、RF、LSTM、CNN、LSTM+CNN、EIDM 七種模型；攻擊用 Kali 產生 DoS/DDoS/暴力破解/port scan；量 CPU usage、CPU load、PowerTop 能耗，ANOVA 比較；加 Mininet+Ryu 的 SDN 版 [原文 p.6–8]。結果只以長條圖與笑臉表呈現，**內文沒有絕對數值**：結論是 KNN／DT／RF 的 CPU 和能耗高，LSTM／CNN 類低 [原文 p.10–12, Table 11/12]。
- **偵測面**：離線準確率 DT 0.9985、KNN 0.9967、RF 0.9981、LSTM 0.9386 等（CICIDS2017）[原文 p.7 Table 3]。
- **對我們的意涵（[推測]）**：這篇對 D3 幾乎沒有可用數字（沒有條件完整的數值）；它的價值是反例：想從公開論文得到「ML 與 Snort 在同一台 gateway 上誰吃多少 CPU」的答案，此篇不提供。
- **限制**：作者承認缺乏大規模與複雜網路的評估 [原文 p.18]。我觀察到：CPU 是否含抓包、批次大小、模型輸入速率都沒寫；「DL 比傳統 ML 省 CPU」與常識（推論成本取決於模型大小與實作）相反，可能是 sklearn 單緒實作對比 Keras 批次的結果，論文沒有解釋 [推測]。

### EcoDefender（Jamshidi, Bellaïche, Abdul Wahab，arXiv:2511.18235v3，2026-06-10）

- **書目／取得程度**：EcoDefender: Energy-Efficient Hybrid Anomaly Detection for IoT Edge Gateways，Polytechnique Montréal。**全文**（17 頁；讀了摘要、測試床、結果與表格；理論推導章只掃過）。「hybrid」指 Autoencoder + Isolation Forest，**不是**規則 + ML。
- **機制**：8 個 flow 特徵（pkts_total、bytes_total、duration…）→ AE 8-32-16-8 取潛在表示 → Isolation Forest（100 棵樹）在潛在空間打分 → 可學習融合 [原文 p.8 Table I/II]。無規則引擎，無雲端。
- **偵測面**：leave-family-out，部署時 accuracy 94%、F1 0.92 [原文 p.8]。資料為 Bot-IoT 攻擊流重播加良性 PCAP [原文 p.8]。
- **成本面**：10 台 Pi 4B（4 GB、Cortex-A72 1.5 GHz）加一台 head gateway，Gigabit 交換器，CPU 頻率固定、熱條件受控 [原文 p.8]。**摘要與正文的數字互相矛盾**：摘要與 Fig.13 說平均 CPU 22%、端到端延遲 27 ms、吞吐「最高 5,000 samples/s」[原文 p.1, p.13]；但 Table XIX（十節點）寫 CPU 平均 19.8%（10.0–27.4）、延遲平均 31.7 ms（15.31–39.58）、吞吐平均 8,360 samples/s（6,485–12,780）、RAM 平均 113.2 MB、能耗 0.45 J/inference 與 8.9 J/node [原文 p.15]。CPU 的定義是「EcoDefender 行程在推論窗內的 user-space CPU 時間百分比」[原文 p.10]，是否以單核為基準未說明。延遲是「每 flow、含前處理、AE、IF、融合、決策，不含訓練與記錄」[原文 p.10]。
- **對我們的意涵（[推測]）**：是 Pi 4B 上「每 flow 約 15–40 ms」的 ML 推論量級參考，但輸入只有 8 個特徵、模型很小，且不含抓包／flow 組裝；若 edge AI 是 ms 級，每個 flow 的決策延遲遠大於 ctnetlink 改 mark 的 13–14.5 µs（[fastpath-methods/SPEC.md §1]），信任更新的瓶頸會是模型而不是 mark 寫入。另外它的 Pi 都是各自獨立跑模型的 10 個節點，沒有同機的規則引擎，所以對 D2 沒有貢獻。
- **限制**：作者承認只用單一資料集（Bot-IoT）、只用 flow 級統計特徵、不建模細粒度時間依賴、能耗與碳排用固定電網強度係數換算、訓練集中式 [原文 p.16 §VII]。我觀察到上述摘要／表格不一致，引用時只能用範圍，不能用單點數字；吞吐「sample」是特徵向量不是封包，不能換算 pps。

### Wu 等：Feature-Rich Embedded NIDS with eBPF/XDP（arXiv:2609.12605，2026-09-11）

- **書目／取得程度**：A Feature-Rich Embedded NIDS with eBPF/XDP: Detector and Architecture Trade-offs，Shiqi Wu, Oleksii Koshovyi, Georgios Pseiridis Pseiras, Victor Morel, Romaric Duvignau，Chalmers／Gothenburg／Ericsson，是碩士論文改寫。**全文**（23 頁）。
- **機制**：Go 實作的 NIDS，Raspberry Pi 5（A76 2.4 GHz，16 GB）。XDP 程式查 blocklist map：命中 XDP_DROP，未命中 XDP_PASS 並用 perf ring buffer 把封包 metadata 送使用者空間；每個時間窗結束後 GoFlowMeter 算 80 個 flow 特徵、Isolation Forest 打分，超過 per-IP 速率門檻的來源寫進 blocklist map，之後由核心直接丟 [原文 p.12–13 §4.4]。比較三種部署：單體、Kafka 微服務、gRPC 微服務 [原文 p.11–12]。**這是目前找到唯一把 ML 判定接到核心端 fast path 的做法，但方向是「封鎖」，不是「信任」。**
- **偵測面**：CIC-DDoS2019，1,533 個窗；單體 + IF 的 live F1 0.965、recall 0.936；統計 baseline recall 僅 0.396；Kafka 版 recall 0.841，比單體低約 9 個百分點 [原文 p.15 Table 2]。調參與評估用同一個資料集，作者自承沒有 hold-out [原文 p.14]。
- **成本面**：每窗處理時間（平均／p99，µs）：單體 baseline 352／886，單體 IF 9,901／42,164，gRPC IF 12,244／49,554，Kafka IF 44,418／87,870；傳輸時間 gRPC 平均 <2 ms、Kafka >27 ms [原文 p.16 Table 3, p.17]。引擎堆積記憶體：單體 IF 平均 25.5 MB [原文 p.16 Table 4]。時間量測不含抓包與窗累積，只是窗結束後的偵測側延遲 [原文 p.15]；窗長在 live 引擎我沒在內文看到明確數字（只知道離線調參用 1 秒窗），未能確認。Pi OS 非即時、有背景工作，作者只主張趨勢不主張絕對值 [原文 p.16, p.19]。重播器不帶人工延遲時可到 3 Gbps [原文 p.19]。
- **對我們的意涵（[推測]）**：(1) 「ML 輸出寫入核心端 map，由核心直接動作」和我們的「ct mark／nft set」同構，可以借這個介面形狀；(2) edge AI 與 gateway 之間的傳輸方式是可量測的一階參數：同機 loopback 上同步 gRPC <2 ms，非同步 Kafka >27 ms 且連偵測品質都變差（作者假設是模型更新順序，未驗證）；(3) 這篇沒有規則引擎，XDP 在 Pi 4 的 bcmgenet 上不能 native，所以不能直接搬。
- **限制**：作者承認單一硬體、合成資料集、同集調參、未排除單體在重負載下的瓶頸、對分散式低速來源較弱 [原文 p.19]。

### SUKRY（Syamsuddin & Barukab，Electronics 11(5):737，2022）

- **書目／取得程度**：SUKRY: Suricata IDS with Enhanced kNN Algorithm on Raspberry Pi for Classifying IoT Botnet Attacks，DOI 10.3390/electronics11050737。**全文**（取自 Politeknik Negeri Ujung Pandang 機構庫的作者稿；MDPI 站台對自動下載回 403，沒有繞過）。PDF 轉文字排版破損，只能讀要點。
- **機制**：整個研究在 RapidMiner 離線做：Bot-IoT（約 0.78 GB、300 萬筆），比較 kNN 搭配 Information Gain／Forward Selection／Backward Elimination，選 kNN-FS [原文 §2–§4]。「SUKRY」是第 4.5 節的部署配方：Pi OS → 裝 Suricata → 裝 OPNids → 讓 OPNids 在 Suricata 上載入 ML 模型 [原文 §4.5, Fig.15]。
- **偵測面／成本面**：kNN-FS accuracy 99.89%，recall 97.82%，precision 99.77%，F1 98.78%；執行時間 7 秒（kNN-BE 18 秒）[原文 §4.4, 結論]。這個「執行時間」是 RapidMiner 處理整個資料集的時間，**不是 Pi 上的量測**。論文沒有 Pi 型號，沒有 Pi 上的 CPU／RAM／延遲／吞吐數字，也沒有 Suricata 在有／無 ML 時的比較（grep "Pi 4"、"Model B"、"CPU" 皆無）。
- **對我們的意涵（[推測]）**：SUKRY 的價值只有一個：標題宣稱的「Suricata + ML 在 Pi 上」實際沒有 Pi 上的量測。引用 SUKRY 來支持「Pi 上可同跑」不成立。
- **限制**：作者承認 kNN 在大資料集表現不佳，並計畫將硬體包裝成商品 [原文 §4.5, 結論]。我觀察到 OPNids 的 ML 模組如何與 Suricata 執行緒共用 CPU，論文沒說 [推測]。

### Passban IDS（Eskandari, Janjua, Vecchio, Antonelli，IEEE IoT-J 7(8), 2020）

- **書目／取得程度**：Passban IDS: An Intelligent Anomaly-Based Intrusion Detection System for IoT Edge Devices，DOI 10.1109/JIOT.2020.2970501（Crossref、OpenAlex、Semantic Scholar 互證），FBK CREATE-NET。IEEE 版為付費，OpenAlex 與 Semantic Scholar 皆標 closed，沒有開放全文，我沒有繞過。**僅二手**：(a) SNU MMLab 研討會投影片（24 頁，第三方導讀，不是作者簡報）https://mmlab.snu.ac.kr/wp-content/uploads/2025/06/passban_slide-20250609-073051.pdf ；(b) Spadaccino & Cuomo 綜述 arXiv:2012.01174 p.6。與派工資訊的差異：Passban 是**純異常偵測**（Isolation Forest、LOF），沒有 Snort／Suricata／Zeek；Raspberry Pi 型號在二手資料裡沒寫，未能確認。
- **機制**：訓練階段（抓包 → 特徵 → 訓練 → 存模型）和預測階段；Action manager 可記錄、封鎖 flow、通知、關閉關鍵裝置 [二手 slides]。在 AGILE 框架實作，打包成 Docker [二手 slides]。偵測 port scan、HTTP／SSH 暴力破解、SYN flood，iForest F1 0.99/0.96/0.96/0.90 [二手 slides]。
- **成本面**（全部 [二手 slides「Resource utilization」頁]，硬體與流量條件未說明）：記憶體 24.68%（有 Passban）對 19.41%（無），Passban 需 54 MB；平均 CPU 負載 47.17% 對 18.42%；Pi 最大可處理 93.9 Mb/s，加 Passban 後降為 77.2 Mb/s（−17.8%）。93.9 Mb/s 接近 100 Mb Ethernet 的 TCP 有效載荷上限，所以 [推測] 測試的是百兆網卡等級的 Pi，不是 Pi 4。
- **對我們的意涵（[推測]）**：它是目前我看到唯一的「有／無 ML IDS 對照」量測方法：同一台 Pi 的轉送吞吐與 CPU 在有無偵測器下各量一次。這個方法可以直接擴充為「rule only／rule + AI／AI only」三組。
- **限制**：二手資料來自導讀簡報，數字條件不完整；原文的方法細節（量測方式、重複次數）我沒看到。作者（經投影片）承認需要良性訓練期、網路變動需重訓、SYN flood 會耗盡資源 [二手 slides]。

### SnortML（Cisco，產品白皮書，日期未標示）

- **書目／取得程度**：Detecting Zero-days with SnortML，Cisco 白皮書，https://www.cisco.com/c/en/us/products/collateral/security/firewalls/detecting-zero-days-with-snortml-wp.html 。**僅透過 WebFetch 的摘要轉述取得（非逐字、非全文閱讀）**，標 [文件]，細節以頁面為準。是產品文件，不是論文。
- **機制**：Snort 3 內的 ML 引擎載入已訓練分類器，inspector 訂閱 Snort 架構提供的資料，把 HTTP 資料（測試資料為 URL query）交給二元 DNN 分類器，回傳「這是 exploit」的機率，可告警或阻擋；與簽章比對引擎「平行跑」[文件]。也就是 ML 只看 Snort 已解析的 HTTP 欄位，不是整條流量。
- **成本面**：「只需要 350 微秒完成計算」，在 64-bit AMD CPU 4.7 GHz 上 [文件]；沒有 CPU／記憶體總量數字，頁面也沒說推論是否在 Snort 封包執行緒內 [文件]。
- **對我們的意涵（[推測]）**：同進程整合的好處是 ML 與規則共用已解析的 payload 欄位，壞處是推論成本進入封包路徑、與 worker 搶同一顆 CPU；350 µs 是桌機等級，Cortex-A72 上的倍數未知。
- **限制**：頁面只有測試準確率表（Alexa、Common Crawl、BreakingPoint），沒有負載下的資源曲線。

### （用作二手線索，未單獨成條）Spadaccino & Cuomo 綜述（arXiv:2012.01174）

只讀了與本題有關的段落。它轉述兩個規則 → ML 的升級設計，**我沒有讀原論文**：Sedjelmaci, Senouci, Al-Bahri, "A lightweight anomaly detection technique for low-resource IoT devices: A game-theoretic methodology"，ICC 2016：平時只開耗能較低的簽章式 IDS，簽章式告警才轉給異常式 IDS 確認或丟棄，以 Nash 均衡決定何時啟動異常偵測，綜述指出缺點是雲端必須一直在線 [二手 arXiv 2012.01174 p.6–7]；Meng, Li, Kwok, "Design of intelligent KNN-based alarm filter using knowledge-based alert verification in intrusion detection"，Security and Communication Networks：KNN 多層過濾 Snort 的告警以去除誤報 [二手 arXiv 2012.01174 §6.2]。Sedjelmaci 的作者列表：綜述列 Al-Bahri，DBLP 列 Messous（搜尋結果的描述），二者不一致，未能確認。

---

## 2. 各問題的回答

**D1（有沒有系統同機跑 rule IDS + ML、有沒有雲端；分工誰決定）**
- 同機共存的實例有三個：Hybrid-NIDS（Suricata + RF，鏡像，VM）、Merkhoufi（Snort + Suricata + DL，Pi 5）、SUKRY（Suricata + OPNids kNN，Pi）。三者都是「同一份流量平行給所有引擎」[原文 Hybrid-NIDS p.2–3；Merkhoufi p.64–65；SUKRY §4.5]。沒有流量分工策略。
- 單一引擎內整合 ML：SnortML 讓分類器與簽章並行，ML 只吃 Snort 已解析的 HTTP 資料 [文件 Cisco 白皮書]。
- 雲端：同機共存的三例都沒有雲端分析；Hybrid-NIDS 的 ELK 是告警彙整，不是分析卸載 [原文 Hybrid-NIDS p.1]；Merkhoufi 只在建議裡提卸載推論 [原文 p.66]。ML + 雲端的卸載有 Simioni 的 early-exit DNN [既有筆記 research/literature/papers/simioni-offload.md]，但那是 ML-only，沒有規則引擎。
- 規則 → 異常 → 雲端的升級式設計：Sedjelmaci 2016 [二手 arXiv 2012.01174 p.6–7]，沒讀原文。
- 搜尋範圍：我用「Snort／Suricata + ML + Raspberry Pi／edge gateway」「two-stage／cascade」「OpenWrt／IoT gateway Suricata isolation forest」等多種組合各搜了一輪，沒再找到其他同機共存實例；搜尋引擎只保證索引到的結果，不能證明「不存在」。

**D2（CPU／核心／記憶體分配；有沒有量互相干擾）**
- 固定分配、動態調整、無處理三類中，已讀論文全部屬於「沒處理」：Hybrid-NIDS 一台 VM 內全開 [原文 p.2]；Merkhoufi 三條路平行 [原文 p.65]；Wu 等是單一 Go 行程加（或不加）外部 broker，Pi OS 非即時、非隔離 [原文 p.19]；EcoDefender 只固定 CPU 頻率與控溫 [原文 p.8]。
- 干擾量測：只有 Passban（二手、ML-only）有 forwarding throughput 與 CPU 的有／無對照 [二手 slides]。Hybrid-NIDS 有丟包率 0.24%，但沒有不開 ML 的對照 [原文 p.5 Table IX]。規則 IDS 丟包、ML 推論延遲在負載下的變化：**沒有任何論文量**。
- Merkhoufi 以定性方式承認三個引擎同跑時資源受限 [原文 p.65]。

**D3（Pi／ARM 實測數字）**
- 見第 3 節表。Pi 4B 上有兩組 ML-only 數字（Realguard、EcoDefender），Pi 5 上有 Wu 等人的窗級延遲。
- 「Pi 上規則 IDS + ML 同跑」的數字：未能確認，沒有找到。SUKRY 的 7 秒是 RapidMiner 離線時間，不是 Pi 數字。
- 既有筆記裡的相關數字：Kitsune 在 Pi 3B 單核 1,000–5,400 pps [既有筆記 papers/kitsune.md]；eBPF/XDP-DL 在 Pi 4B 上 GRU 每 flow 推論 10.38 ms、核心端平均 1.85 µs [既有筆記 papers/ebpf-xdp-dl.md]。

**D4（fast path／bypass／信任與 ML 結合）**
- ML → 核心端動作：Wu 等人，ML 門檻 → blocklist map → XDP_DROP [原文 p.12–13]；EcoDefender 與 Realguard 只是記錄或封鎖，沒有核心端 fast path [原文 EcoDefender p.8；Realguard §3.1]。
- ML → 信任（讓 flow 跳過 IDS）：**沒找到**。我搜過「ML 分類首幾個封包後 bypass DPI／Suricata」等組合；搜尋只回傳 Suricata 內建 flow bypass 文件、SmartNIC 綜述中「前幾個封包最重要」的敘述，以及不相干的 ML 分類教學，未見把兩者接起來的論文。
- 規則 → ML 路由：Sedjelmaci（告警才啟動異常偵測）與 Meng（ML 過濾 Snort 告警）[二手 arXiv 2012.01174]；Hybrid-NIDS 的 "strict" 關聯是對告警取 AND，不是路由 [原文 p.4 Table VII]。

**D5（可借用與空缺，皆 [推測]）**
- 可借用：
  1. Passban 的有／無對照量測法，擴成「rule only」「rule + AI」「AI only」三組，量轉送 throughput、Suricata 丟包、AI 延遲。
  2. Wu 等人的「模型寫核心端 map」形狀；對應到我們就是 AI 輸出 → nft plain set 或 ct mark，而 ctnetlink 改 mark 是 13–14.5 µs/筆 [fastpath-methods/SPEC.md §1]，遠小於 ML 推論時間，所以瓶頸在模型端。
  3. batch size 當一階參數（Hybrid-NIDS 744 倍差異）；edge AI 若吃 flow 特徵，應批次，而不是每 flow 呼叫一次。
  4. edge AI ↔ gateway 的傳輸方式要量：同機同步 RPC <2 ms vs 非同步 broker >27 ms（Pi 5，Wu 等人）。
  5. Hybrid-NIDS 的教訓：每個引擎的告警貢獻必須分開記錄，否則模型靜默（recall 0.0095、無告警）不會被發現。
- 空缺：
  1. 沒有流量分工與預算：沒人決定哪些流量進規則、進模型、上雲，也沒人在 CPU 不夠時降低其中一個的量。
  2. 沒有同機干擾的完整量測（轉送、Suricata 丟包、AI 延遲三者同時），也沒有核心配置（把網卡中斷所在的 CPU 0 讓出來）的實驗。
  3. 沒有「ML → 信任」迴路與其安全性分析；現有只做「ML → 封鎖」。我們已有的 ct mark 信任和 SYN/FIN/RST 全檢查可以是起點，但模型判斷錯誤時的攻擊面（模型被當成信任來源）沒有人討論。
  4. 依負載調整稽核量與推論量的方法，在本組讀到的 edge IDS 論文裡完全沒有；負載自適應的抽樣／降載（load shedding）屬於傳統規則式監控文獻，不在本組範圍，我沒有讀。

---

## 3. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| 每封包 DNN 執行率（含 100 特徵抽取） | 10,600 pkt/s（PC 88,200） | Pi 4B 8 GB、Ubuntu 64-bit、Keras 2.4.3/TF 2.4.0；是否含抓包未說明 | Realguard [原文 Table 2, 6] |
| 同上資源 | CPU 36.0%、RAM 114.5 MB | 同上；CPU 基準（單核或整機）未說明；Kitsune 33.8%／156.3 MB | Realguard [原文 Table 7] |
| Pi 上訓練率 | 1,150 pkt/s | 同上 | Realguard [原文 Table 6] |
| 每 flow 端到端推論延遲 | 摘要 27 ms；Table XIX 平均 31.7 ms（15.31–39.58） | Pi 4B 4 GB、1.5 GHz 固定頻率、AE 8-32-16-8 + IF 100 棵、8 特徵、Bot-IoT 重播；含前處理與融合 | EcoDefender [原文 p.1, p.15] |
| CPU 使用率 | 摘要 22%；Table XIX 平均 19.8%（10.0–27.4）；AE-only 35% | 同上；user-space 時間百分比 | EcoDefender [原文 p.1, p.10, p.13, p.15] |
| 吞吐 | 摘要「最高 5,000 samples/s」；Table XIX 平均 8,360（6,485–12,780） | 同上；單位是特徵向量不是封包 | EcoDefender [原文 p.1, p.15] |
| 每推論能耗 | 0.45 J | 同上；device-level 功率監測 | EcoDefender [原文 p.1] |
| Isolation Forest 每窗偵測時間 | 平均 9,901 µs／p99 42,164 µs（baseline 352／886） | Pi 5（A76 2.4 GHz、16 GB）、Go、單體、80 特徵窗向量；不含抓包 | Wu 等 [原文 p.16 Table 3] |
| 同機 IPC 傳輸時間 | gRPC 平均 <2 ms；Kafka >27 ms | Pi 5 loopback | Wu 等 [原文 p.16–17] |
| 引擎堆積記憶體 | 單體 IF 平均 25.5 MB／最大 38.6 MB | Go runtime heap；不含 broker 與 detector 行程 | Wu 等 [原文 p.16 Table 4] |
| RF 每 flow 推論延遲 | batch=1 49.11 ms；batch=1024 0.066 ms（約 744×） | 平台未說明（Ubuntu VM）；sklearn RF 200 棵、depth 12；純推論 | Hybrid-NIDS [原文 p.5 Table VI] |
| 同機 Suricata + RF 丟包 | 4,732／1,946,816（0.24%） | 未標註 mini 測試、VM、無不開 ML 的對照 | Hybrid-NIDS [原文 p.5 Table IX] |
| 儀表板快照 | CPU 57.1%、RAM 75.5% | 單一時點，作者聲明不能當基準 | Hybrid-NIDS [原文 p.4] |
| Suricata 對 RF-21 偵測 | 61/105 攻擊（97 誤報）對 1/105（0 誤報） | 標註 PCAP，538 事件 | Hybrid-NIDS [原文 p.5 Table VII] |
| 轉送吞吐有／無 ML IDS | 93.9 → 77.2 Mb/s（−17.8%） | Pi，型號與測法未說明；iForest/LOF 異常 IDS | Passban [二手 SNU slides] |
| CPU 平均負載有／無 | 47.17% 對 18.42% | 同上 | Passban [二手 SNU slides] |
| SnortML 單次計算 | 350 µs | AMD 64-bit 4.7 GHz | Cisco [文件] |
| Pi 上 Suricata + ML 同跑任何資源數字 | 未能確認 | — | 全部已讀來源皆無 |

---

## 4. 建議追加閱讀（≤ 5 篇）

1. **Sedjelmaci, Senouci, Al-Bahri (or Messous), "A Lightweight Anomaly Detection Technique for Low-Resource IoT Devices: A Game-Theoretic Methodology", IEEE ICC 2016**：D4 的規則 → 異常升級設計，用 Nash 均衡決定何時啟動異常偵測以省能耗。存在確認：dblp 與綜述都有列，HAL 有期刊版 "An Accurate Security Game for Low-Resource IoT Devices"（IEEE TVT 2017，hal-01557963），但 HAL 全文被反爬蟲關卡擋住，沒有取得；僅二手。
2. **Meng, Li, Kwok, "Design of Intelligent KNN-Based Alarm Filter Using Knowledge-Based Alert Verification in Intrusion Detection", Security and Communication Networks**：ML 作為 Snort 告警的後級過濾，與我們「規則先判、AI 複核」的方向相同。存在確認：僅綜述 arXiv:2012.01174 ref [93] 的書目（年份我沒核對，綜述的頁碼資料指向 2015 一帶 [推測]）；未取得。
3. **Alsakran, Bendiab, Shiaeles, Kolokotronis, "Intrusion Detection Systems for Smart Home IoT Devices: Experimental Comparison Study", SSCC 2019, Springer CCIS 1208, pp.87–98 (2020), DOI 10.1007/978-981-15-4825-3_7**：在受限硬體上比較 Snort、Suricata、Bro 的 CPU 與記憶體，是規則引擎那一側的資源基準。存在確認：Portsmouth 研究入口網頁已查，作者稿 PDF 對自動下載回 403 未取得；硬體型號未能確認；僅摘要。
4. **Iaeme IJECET 17(2), Paper 003（Suricata 告警 + Isolation Forest，Raspberry Pi 5）**：搜尋摘要稱同機組合 Suricata 告警與 IF，並說 CPU／記憶體剖析留待未來；下載逾時，未取得。存在確認：僅搜尋結果摘要；品質未知（期刊名聲疑似低）[推測]。優先度低。
5. **Telkom University 學位論文：SnortML（CNN/LSTM 在 Snort 內）於 Raspberry Pi 3B 與 4 上測 CPU／RAM**：搜尋摘要稱 Pi 4 上 accuracy 約 61–66%，是少數說明在 Pi 4 上量「規則引擎內嵌 ML」資源的資料。存在確認：僅搜尋結果摘要，未取得全文，可信度低。優先度低。

另外我查了但不採用：PLOS ONE 2025 的 Pi 4 ML-NIDS（doi:10.1371/journal.pone.0331123）——其與 Snort／Suricata 的比較表（89.2%／91.5%）沒有說明量測方法，作者自己也寫 "the paper does not assess its ability to handle high network traffic loads"，不是同機共存。

---

## 5. 自評：最不確定的三件事

1. **「沒有找到」不等於「不存在」**。D1、D4、D2 的核心結論是負面的，依據是我用多種關鍵字組合的網路搜尋加上讀 7 篇全文。搜尋工具是搜尋引擎摘要，有明確出錯的例子：它說 Jamshidi 2504.09634 量了 Snort 的 CPU（實際只有引用他人研究），也說某篇高速 IDS 論文提到 softirq 造成 Snort／Suricata 丟包（我下載該 arXiv 論文後全文找不到這段，已刪除該下載）。所以我所有「全文已讀」的敘述可信，但「別處也沒有」只是低信心的結論。IEEE、Elsevier、Springer 的付費論文我沒進去（Passban 就是一例）。
2. **Passban 的數字是二手**，來自第三方導讀簡報；測試硬體不明，所以 −17.8% 的轉送下降只能當作「方法示範」，不能當作 Pi 4 的成本估計。而 Passban 沒有規則引擎，能不能類推到「rule + AI」是我的推測。
3. **EcoDefender 與 Realguard 的 Pi 4B 數字不能直接當我們的成本**。EcoDefender 摘要與表格互相矛盾（22% 對 19.8%、27 ms 對 31.7 ms、5,000 對 8,360）；Realguard 的 CPU% 基準與執行率是否含抓包都沒說，且其 Kitsune 對照數字應是引用原論文（Pi 3B），不是同硬體重量。兩篇的模型都是小型 Python／TF 實作，我們合作方的 edge AI 模型大小與框架不同，數字只能當量級（每 flow 十幾到幾十 ms、每封包約 94 µs）。
