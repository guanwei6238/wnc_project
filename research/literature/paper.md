# 專案論文清單

更新：2026-11-03

範圍：
- `research/literature/pdfs/` 和 `research/literature/trust-bypass/pdfs/` 裡的 38 篇論文。
- 有精讀報告、但 PDF 沒留在資料夾的 6 篇。
- 2026-11-03 新穎性查核讀過全文的 20 篇（#45–#64），PDF 在 `novelty-check/pdfs/`。
- 共 64 篇。

怎麼讀：

- 「在說什麼」和數字都抄自各篇筆記，路徑寫在每篇最後。出處標記（`[原文 p.N]` 等）留在筆記裡，這裡省略。
- 「跟我們的關係」是我們的判斷，不是論文寫的。
- 閱讀深度分四級：
  - **精讀**：subagent 讀完全文，照 `SUBAGENT_SPEC.md` 寫了獨立報告。#45–#64 則是照 `novelty-check/SCREEN.md` 對 C1–C4 逐篇判定，報告在 `novelty-check/fulltext/G1`–`G6`，主 agent 抽查過關鍵引文。
  - **全文條目**：讀過全文，在 `trust-bypass/candidates.md` 有一節重點，沒有獨立報告。
  - **部分章節**：只讀了相關章節，大多是在別篇報告的延伸閱讀（D9）裡讀的。
  - **摘要**：只讀到摘要，數字是作者自己宣稱的，條件沒有確認。

## 總覽

| # | 論文 | 出處 | 一句話 | 深度 |
|---|---|---|---|---|
| 1 | Simioni | IEEE IoT-J 2025 | early-exit DNN，信心不夠才上雲 | 精讀 |
| 2 | HorusEye（無 PDF） | USENIX Sec 2023 | 交換器白名單先過濾，可疑的才送 GPU | 精讀 |
| 3 | Edge Multi-agent IDS（無 PDF） | ICPS 2024 | edge agent 投票，判不出就交給別的 agent | 精讀 |
| 4 | eBPF/XDP-DL | IEEE Internet Computing 2026 | Pi 4B 上 kernel 抽特徵、GRU 判斷 | 精讀 |
| 5 | Galette（無 PDF） | IFIP Networking 2023 | Pi 上 XDP fast path + AF_XDP slow path | 精讀 |
| 6 | SAPO-BOI（無 PDF） | JBCS 2026 | XDP 先掃規則 fast pattern，命中才送 user space | 精讀 |
| 7 | Kitsune（無 PDF） | NDSS 2018 | 增量統計特徵 + autoencoder 集成 | 精讀 |
| 8 | Host-Based Aggregation | IEEE Access 2025 | 以來源 IP 為單位、7 個 entropy 類特徵 | 精讀 |
| 9 | FlowLens（無 PDF） | NDSS 2021 | 交換器上壓縮 flow 特徵 | 精讀 |
| 10 | Alikhanov | IEEE Access 2022 | 封包抽樣對 ML NIDS 的傷害 | 精讀 |
| 11 | Mai IMC'06 | IMC 2006 | 四種抽樣對異常偵測的影響 | 精讀 |
| 12 | Mai JSAC'06 | IEEE JSAC 2006 | 封包抽樣對 portscan 偵測的影響 | 部分章節 |
| 13 | XNET | arXiv 2026 | XDP 依安全價值動態抽樣 | 摘要 |
| 14 | HybridMon | NOMS 2025 | 封包級紀錄 + 選擇性聚合，看輸出 bytes | 全文條目 |
| 15 | Shunting | CCS 2007 | IPS 判完後下放到硬體表放行 | 精讀 |
| 16 | Selective Packet Discarding | EuroSec 2010 | Snort 過載時丟掉每條 flow 的後段 | 精讀 |
| 17 | Kučera | ICCD 2018 | Suricata 只看每條 flow 前 N 個封包 | 全文條目 |
| 18 | Time Machine（Kornexl） | IMC 2005 | 每條連線只錄前 N bytes | 精讀 |
| 19 | Time Machine（Maier） | SIGCOMM 2008 | NIDS 動態控制錄製 cutoff | 精讀 |
| 20 | SciPass | SC14 | Bro 判好 flow 後讓它繞過 IDS | 全文條目 |
| 21 | Retina | SIGCOMM 2022 | 多層過濾，盡早丟掉不需要的流量 | 全文條目 |
| 22 | P4-ONIDS | SBRC 2021 | P4 前置過濾，只送前 N 封包給 Snort | 全文條目 |
| 23 | Kabasele | ICS-CSR 2018 | P4 白名單 + DPI 兩層 IDS（工控） | 全文條目 |
| 24 | immUNITY | arXiv 2026 | 第 3 個封包判 benign 就進交換器白名單 | 全文條目 |
| 25 | NetBeacon | USENIX Sec 2023 | 多階段推論，判定後寫進 flow class table | 全文條目 |
| 26 | Bernaille | CCR 2006 | 前 5 個資料封包大小辨識應用 | 精讀 |
| 27 | Ahmad | ICSTW 2022 | web 攻擊平均 1–3 個封包就判 | 部分章節 |
| 28 | Liu | GLOBECOM 2023 | transformer 早期偵測 | 部分章節 |
| 29 | Giryes | arXiv 2024 | 不同攻擊需要的封包數差很多 | 部分章節 |
| 30 | Panopoulos（DTPE） | SpliTech 2025 | IoT 早期偵測，Pi Zero 2 W 實測 | 部分章節 |
| 31 | A-THENA | arXiv 2026 | 30 的擴充版 | 部分章節 |
| 32 | CATO | NSDI 2025 | 決策時點和端到端成本一起最佳化 | 部分章節 |
| 33 | FastFlow | SIGMETRICS 2025 | 模型自己決定每條 flow 看幾個封包 | 全文條目 |
| 34 | IoT Sentinel | ICDCS 2017 | 接入時指紋辨識設備，給三級信任 | 精讀 |
| 35 | DÏoT | ICDCS 2019 | 每個封包都過設備專屬模型 | 部分章節 |
| 36 | Hamza IoT S&P'18 | IoT S&P 2018 | MUD 轉成 SDN 規則 | 部分章節 |
| 37 | Hamza SOSR'19 | SOSR 2019 | 用 MUD 規則計數器抓容量型攻擊 | 精讀 |
| 38 | Hamza arXiv'23 | arXiv 2023 | SOSR'19 的 microflow 延伸 | 部分章節 |
| 39 | Grashöfer | arXiv 2019 | 塞滿協定辨識 buffer 規避 Zeek/Snort/Suricata | 全文條目 |
| 40 | NetMasquerade | NDSS 2026 | 讓攻擊 flow 模仿良性流量 | 部分章節 |
| 41 | NOS-Gate | IEEE TCE 2026 | 家用 gateway 上可逆的持續評分 | 全文條目 |
| 42 | Zero Trust Multi-RAT | arXiv 2026 | trust decay 模型（質性） | 部分章節 |
| 43 | Closing the Loop | arXiv 2026 | 802.1X 逐出設備的反應時間 | 摘要 |
| 44 | Niedermaier | arXiv 2019 | 工控 MCU 上的分散式 IDS agent | 摘要 |
| 45 | Meng | IEEE Computer 2018 | IDS 前面放白名單過濾＋固定間隔抽樣 | 精讀 |
| 46 | Goldberg & Rexford | IEEE Sarnoff 2007 | 固定週期抽樣可被預測規避 | 精讀 |
| 47 | Kodialam & Lakshman | INFOCOM 2003 | 用賽局分配各鏈路的抽樣率 | 精讀 |
| 48 | Otrok | Comput. Commun. 2008 | 賽局模型：攻擊拆成多封包對抗抽樣 | 精讀 |
| 49 | Giacometti | ISNCC 2025 | XDP 抽樣送 KitNET，判定傳給同 flow | 精讀 |
| 50 | Valgenti | AINA 2014 | NIDS 前的 rate limiter，隨機轉送＋audit trail | 精讀 |
| 51 | SparseIDS | IEEE CNS 2020 | RL 決定每條 flow 要看哪些封包 | 精讀 |
| 52 | Lin & Lee | JNCA 2013 | Snort／Bro 的每階段成本拆解 | 精讀 |
| 53 | Wang & Chang | JNCA 2022 | XDP 掃 fast pattern，命中才送 user space | 精讀 |
| 54 | DS-nDPI（Van Tu） | CNSM 2017 | 已分類的 flow 由 tc eBPF 表擋在 kernel | 精讀 |
| 55 | iKern | Technologies 2024 | eBPF 白名單直接轉送、黑名單丟 | 精讀 |
| 56 | Sárközi | GLOBECOM 2025 | P4 推論，抽 5% flow 送外部 IDS 重訓 | 精讀 |
| 57 | P4Pir | IEEE IoT-J 2024 | Pi 4 上 bmv2 做 in-network ML、不中斷換模型 | 精讀 |
| 58 | HALIDS | TMA 2024 | 交換器信心不足時交給 oracle | 精讀 |
| 59 | Monsakul | IBDAP 2026 | 同一台 Pi 4 跑 Suricata＋RF | 精讀 |
| 60 | Hidayatullah | ICIMCIS 2025 | Pi 上 Snort＋SnortML 的 inline IPS | 精讀 |
| 61 | Stolz & Zhang | PeerJ CS 2026 | Pi 上 Snort＋FL＋區塊鏈 | 精讀 |
| 62 | Tuong & Kimura | MCSoC 2016 | ARM 上 Suricata 的 DVFS 省電排程 | 精讀 |
| 63 | Mirzai | EuroSec 2023 | Pi 4 上排程多個 ML IDS 實例 | 精讀 |
| 64 | Think Fast（Jamshidi） | IEEE IoT-J 2026 | edge ML IDS＋雲端 LLM 推理 | 精讀 |

---

## 1. 雲端卸載與 edge–cloud 分工

### 1. Simioni — An Energy-Efficient Intrusion Detection Offloading Based on DNN for Edge Computing

- 出處：IEEE Internet of Things Journal 12(12), 2025-06，DOI 10.1109/JIOT.2025.3544060
- PDF：`pdfs/An_Energy-Efficient_Intrusion_Detection_Offloading_Based_on_DNN_for_Edge_Computing.pdf`；深度：精讀
- 在說什麼：用 early-exit DNN 做 NIDS。Pi 3B 先跑第一個分支，信心夠就在本地判，不夠才把中間層輸出送到雲端跑第二個分支。各分支的門檻用 NSGA-II 在「能耗 vs 錯誤率」之間找。
- 數字：AlexNet 版每事件能耗降到全本地的 1.0%、時間 0.9%，約 10% 事件上雲。MobileNetV2 版是 41.2% / 32.5%，約 8% 上雲。每個上雲事件約 7.2 KB / 14.5 KB。
- 跟我們的關係：最接近的 edge–cloud 分工前例。但上雲依據是 DNN 信心值，而且每 15 秒的事件窗都重新判斷，沒有跨窗的信任快取。
- 筆記：`papers/simioni-offload.md`

### 2. HorusEye — A Realtime IoT Malicious Traffic Detection Framework using Programmable Switches

- 出處：USENIX Security 2023
- PDF：不在資料夾；深度：精讀
- 在說什麼：把 iForest 轉成 Tofino 交換器上的白名單範圍規則（Gulliver Tunnel），先過濾正常流量。可疑的才送到 x86 + GPU 上的 autoencoder（Magnifier）複查。
- 數字：摘要宣稱資料平面偵出 99% 異常、卸載 76% 流量，但這兩個數字的實驗條件不同。Gulliver Tunnel + Magnifier（int8）可達 12M pps。
- 跟我們的關係：白名單前置過濾的前例。但正常流量的 header 仍然鏡射上去，上傳 bytes 沒有降。
- 筆記：`papers/horuseye.md`

### 3. Edge Multi-agent Intrusion Detection System Architecture for IoT Devices with Cloud Continuum

- 出處：IEEE ICPS 2024
- PDF：不在資料夾；深度：精讀
- 在說什麼：兩層 multi-agent IDS。edge agent 跑輕量模型（RF / SVM / LR）並加權投票，判不出來的事件交給其他 edge agent 重判。cloud agent 負責全域觀察與更新模型。
- 數字：CICIoT2023 上 Accuracy 0.9938、F1 0.9388。
- 跟我們的關係：雲端層只出現在架構圖上，實作和評估只有 edge 層，也沒有量成本。
- 筆記：`papers/edge-multiagent-ids.md`

## 2. Gateway 上的封包處理與特徵抽取

### 4. eBPF/XDP-DL — Real-Time eBPF/XDP-Based Deep Learning Framework for Anomaly Traffic Detection in IoT Networks

- 出處：IEEE Internet Computing 30(3), 2026，DOI 10.1109/MIC.2026.3692726
- PDF：`pdfs/Real-Time_eBPF_XDP-Based_Deep_Learning_Framework_for_Anomaly_Traffic_Detection_in_Internet_of_Things_Networks.pdf`；深度：精讀
- 在說什麼：在 kernel 用 eBPF/XDP 抽 flow 特徵，user space 跑 GRU。離線用兩階段特徵選擇，把特徵數壓到 5–9 個。
- 數字：CICDDoS2019 77→5 個特徵（準確率 93.30%→92.73%）、IoT-23 18→6。Pi 4B 上 kernel 攔截平均 1.85 μs、GRU 推論平均 10.38 ms、agent CPU 0.67%。
- 跟我們的關係：最接近我們階段 2「Pi 4 上 kernel 算特徵」的前例。沒有量轉送效能，也沒有卸載。
- 筆記：`papers/ebpf-xdp-dl.md`

### 5. Galette — a Lightweight XDP Dataplane on your Raspberry Pi

- 出處：IFIP Networking 2023
- PDF：不在資料夾；深度：精讀
- 在說什麼：給 Raspberry Pi 這類 SBC 的兩層 dataplane。XDP 當 fast path，AF_XDP 的 userland 當 slow path，昂貴的 NF 放到 userland，避免拖累一般流量。同一個 Rust NF 可以編成 eBPF，也可以編成 native。
- 數字：1518 B、100 Mbit/s、IRQ 模式時，CPU 是 XDP 10.4% 對 AF_XDP 32.4%。這個優勢在 Poll 模式或 ≤1 Mbit/s 時就消失。每組 n=10，有 95% CI。
- 跟我們的關係：fast/slow path 分層在 Pi 上的實測，也是第一輪十篇裡唯一做重複量測的。測試機是 Pi 3B，不是 Pi 4，而且只跑 Macswap，沒有偵測功能。
- 筆記：`papers/galette.md`

### 6. SAPO-BOI — Bypassing Linux Kernel Network Stack in the Implementation of an XDP-based NIDS

- 出處：Journal of the Brazilian Computer Society 32(1), 2026
- PDF：不在資料夾；深度：精讀
- 在說什麼：兩段式 NIDS。XDP 程式在 kernel 用 Aho-Corasick 掃每條規則的 fast pattern，沒命中就直接丟，命中才經 AF_XDP 送到 user space 做完整比對。規則用 Snort/Suricata 格式。
- 數字：規則 ≥2000 條時丟包約 2.2%，而且對規則數不敏感。Snort 在 8000 條規則、2 Gbps 起丟包超過 50%。測試平台是 x86 + 10G 網卡。
- 跟我們的關係：第一輪十篇裡唯一用規則式 IDS 的。但它是被動鏡像，不在 ARM 上跑。
- 筆記：`papers/sapo-boi.md`

### 7. Kitsune — An Ensemble of Autoencoders for Online Network Intrusion Detection

- 出處：NDSS 2018
- PDF：不在資料夾；深度：精讀
- 在說什麼：AfterImage 用 damped incremental statistics，每個封包輸出 115 維特徵，O(1) 更新。KitNET 用一組小 autoencoder 做無監督的線上異常偵測。
- 數字：在 Pi 3B 單核上量了 KitNET 的處理速率，但不含特徵抽取。
- 跟我們的關係：線上、增量式的特徵計算可以借用。Pi 上的數字不能當端到端成本。NetMasquerade 對它的攻擊成功率是 0.991（見 #40）。
- 筆記：`papers/kitsune.md`

### 8. Efficient IDS for IoT Networks Using Host-Based Data Aggregation and Multi-Entropy Analysis

- 出處：IEEE Access 13, 2025，DOI 10.1109/ACCESS.2025.3589057
- PDF：`pdfs/Efficient_IDS_for_IoT_Networks_Using_Host-Based_Data_Aggregation_and_Multi-Entropy_Analysis.pdf`；深度：精讀
- 在說什麼：把偵測單位從 flow 改成 host（source IP），每個時間窗每個來源 IP 一列。只用 7 個特徵（5 個 entropy、封包數、bytes）配 XGBoost。
- 數字：10 s 窗、10-fold CV 準確率 99.97%。推論時間在 Pi 3B+ 上量，記憶體在 Xeon 上量。
- 跟我們的關係：降低資料列數的另一種思路。論文說「時間降 99.7%」，但這不含特徵產生；記憶體也是在 Xeon 上量的。
- 筆記：`papers/host-aggregation-ids.md`

### 9. FlowLens — Enabling Efficient Flow Classification for ML-based Network Security Applications

- 出處：NDSS 2021
- PDF：不在資料夾；深度：精讀
- 在說什麼：在 Tofino P4 交換器上，把每條 flow 的封包長度和到達間隔做 quantization + truncation，存成固定大小的 flow marker，再在交換器 CPU 上跑 ML 分類。參數用 Bayesian optimization 自動找。
- 數字：依任務不同，marker 縮小 32–150 倍，準確率損失最多 3%。
- 跟我們的關係：flow 特徵壓縮的代表作。它在 ASIC 上做，卸載量只有紙上估算。NetMasquerade 對它的攻擊成功率是 0.9717。
- 筆記：`papers/flowlens.md`

## 3. 抽樣

### 10. Alikhanov — Investigating the Effect of Traffic Sampling on Machine Learning-Based Network Intrusion Detection Approaches

- 出處：IEEE Access 10, 2022，DOI 10.1109/ACCESS.2021.3137318
- PDF：`pdfs/Investigating_the_Effect_of_Traffic_Sampling_on_Machine_Learning-Based_Network_Intrusion_Detection_Approaches.pdf`；深度：精讀
- 在說什麼：先抽樣封包、再組成 flow record，量這樣對 ML NIDS 的影響。在 CSE-CIC-IDS2018 上比較 4 種抽樣器 × 3 種分類器。
- 數字：抽樣率 1/10、1/100、1/1000 時，RF 的 Majority DR 從 98.31% 降到約 80% / 39% / 15%（讀圖）。短 flow 攻擊最先消失。
- 跟我們的關係：「靜態抽樣會傷偵測」的證據。放行後如果要抽樣，不能只做單純的封包抽樣。
- 筆記：`papers/alikhanov-sampling.md`

### 11. Mai — Is Sampled Data Sufficient for Anomaly Detection?

- 出處：IMC 2006
- PDF：`trust-bypass/pdfs/sampled-anomaly/imc06-isand.pdf`；深度：精讀
- 在說什麼：用 Tier-1 backbone trace，在保留 flow 數相同的條件下，比較 random packet、random flow、smart、sample-and-hold 四種抽樣，對三個異常偵測器（wavelet、TRWSYN、TAPS）的影響。
- 數字：random flow sampling 失真最小。packet sampling 會把多封包 flow 切成只剩 SYN 的短 flow，讓 TRWSYN 的假陽性暴增。偏向大 flow 的 smart 和 S&H 最差。
- 跟我們的關係：放行後要抽樣的話，以 flow 為單位比以封包為單位好。這篇沒有討論只看開頭就放行。
- 筆記：`trust-bypass/papers/sampled-anomaly.md`

### 12. Mai — Impact of Packet Sampling on Portscan Detection

- 出處：IEEE JSAC 24(12), 2006
- PDF：`trust-bypass/pdfs/sampled-anomaly/jsac06-isand.pdf`；深度：部分章節（摘要、§III-C、結論）
- 在說什麼：#11 掃描偵測部分的期刊完整版，另外提出 TAPS-SYN。
- 數字：結論說抽樣率低於 1/100 時，thinning 會造成顯著誤差。
- 跟我們的關係：給抽樣率的下限參考。
- 筆記：`trust-bypass/papers/sampled-anomaly.md`（D9）

### 13. XNET — Intelligent Dynamic Sampling for High-Speed Network Security Monitoring

- 出處：arXiv:2608.18349，2026-08，預印本
- PDF：`trust-bypass/pdfs/time-machine/xnet_2608.18349.pdf`；深度：摘要（PDF 在資料夾，但筆記只寫到摘要）
- 在說什麼：用 XDP 依「安全價值」把封包分類，再依政策動態抽樣，放大 APT、C2 這類低速但高價值流量的比例。
- 數字（摘要宣稱）：在真實網路中，流量最多減 84% 且沒有丟包，低速流量的可見度提高約 5 倍。壓力測試到 100 Gbps。抽樣後的流量餵給 IDS，偵測率 99.6%。
- 跟我們的關係：「依價值抽樣，而不是均勻抽樣」的最新做法。它的規模是 SOC 級，能不能縮到 Pi 要讀全文才知道。
- 筆記：`candidates.md` #11

### 14. HybridMon — Advancing Network Monitoring with Packet-Level Records and Selective Flow Aggregation

- 出處：IEEE NOMS 2025
- PDF：`trust-bypass/pdfs/search/fink_hybridmon_2025.pdf`；深度：全文條目
- 在說什麼：Tofino 對每個封包輸出濃縮的封包級紀錄，較不重要的流量選擇性地聚合成 flow。IDS 可以回饋暫時的 filter 規則，例如停止監控已經偵測到的高流量攻擊。
- 數字：輸出頻寬降到封包監控的 12–20%。再加上 heavy-hitter 子抽樣，降到原 trace 的 4.5–10.5%（4 個 CAIDA trace、各跑 10 次）。
- 跟我們的關係：少數把「輸出 bytes」當主要指標的實測，量測方法可以借。但輸出對象是 collector，場景是 Tbps 骨幹網路。
- 筆記：`trust-bypass/candidates.md` #13

## 4. 只看開頭、放行與 cutoff

### 15. Shunting — A Hardware/Software Architecture for Flexible, High-Performance Network Intrusion Prevention

- 出處：ACM CCS 2007
- PDF：`trust-bypass/pdfs/shunting/shunting.ccs07.pdf`；深度：精讀
- 在說什麼：in-line 硬體 Shunt 只看 header，用 IP 表、5-tuple 表和 TCP flag 規則，對每個封包決定 forward、drop 或 shunt（轉給 IPS）。這些表是 IPS 可以寫的 cache，由 IPS（Bro）決定什麼時候放行連線剩下的部分。
- 數字：在 6 條 trace 上可以放行 54.9–91.1% 的 bytes、43.8–88.0% 的 packets。
- 跟我們的關係：「IPS 判完就下放到硬體表」的經典架構。它放行的依據是「分析器沒東西可看了」（例如 HTTP 超過 10 KB、SSH 已認證），不是「判定安全」。硬體表有 sample 欄位，但沒有用到。
- 筆記：`trust-bypass/papers/shunting.md`

### 16. Papadogiannakis — Improving the Accuracy of NIDS Under Load Using Selective Packet Discarding

- 出處：EuroSec 2010
- PDF：`trust-bypass/pdfs/selective-discarding/discarding.eurosec10.pdf`；深度：精讀
- 在說什麼：Snort 過載時，主動丟掉每條 flow 超過 cutoff 的後段封包，而不是讓 kernel 隨機丟。cutoff 依丟包、CPU 和處理時間自動調整。
- 數字：90% 的告警由 flow 前 30 個封包觸發，第 100 個封包之後只佔 3%。cutoff 設 100 時吞吐量提高 3.62 倍，仍保留 95% 的告警。276 個人工注入的攻擊全部抓到，但這些攻擊都放在連線開頭。
- 跟我們的關係：規則式 IDS 上最直接的 cutoff 實證。作者承認攻擊者可以先用良性請求把 stream 填滿再攻擊。它讓新連線一定從頭檢查，對應到我們的設計，就是信任不能因為重連而繼承。
- 筆記：`trust-bypass/papers/selective-discarding.md`

### 17. Kučera — General IDS Acceleration for High-Speed Networks

- 出處：IEEE ICCD 2018
- PDF：`trust-bypass/pdfs/search/kucera_iccd18_ids_accel.pdf`；深度：全文條目
- 在說什麼：在 Suricata 前面加一層，每條 flow 第 N 個封包之後全部 bypass，N 依 buffer 溢位的情況動態調整。
- 數字：用 13,642 條 ET 規則和真實 pcap。只看前 5 個封包仍偵測到 80% 以上的事件，N>30 時超過 90%。每條 flow 前 50 個封包加起來不到全部封包的 20%。
- 跟我們的關係：唯一用 Suricata + ET 量出「前 N 個封包 vs 偵測率」曲線的論文。作者明說 N 之後的攻擊偵測不到，可以當我們「不抽樣的 cutoff」的基線。硬體是 Xeon + FPGA。
- 筆記：`trust-bypass/candidates.md` #1

### 18. Kornexl — Building a Time Machine for Efficient Recording and Retrieval of High-Volume Network Traffic

- 出處：IMC 2005（short paper）
- PDF：`trust-bypass/pdfs/time-machine/kornexl_imc05.pdf`；深度：精讀
- 在說什麼：封包錄製系統，每條連線只錄前 N bytes。利用的是流量的 heavy-tail：多數連線很短，少數大連線佔掉大部分 bytes。
- 數字：在 LBNL 實機跑兩週，20 KB cutoff 加 90 GB 儲存可以保留 3–5 天的 TCP。
- 跟我們的關係：cutoff 概念的源頭之一。它影響的是錄製，不是偵測。
- 筆記：`trust-bypass/papers/time-machine.md`

### 19. Maier — Enriching Network Security Analysis with Time Travel

- 出處：ACM SIGCOMM 2008
- PDF：`trust-bypass/pdfs/time-machine/maier_sigcomm08.pdf`；深度：精讀
- 在說什麼：Time Machine 的完整版。NIDS 可以動態控制錄製：對觸發告警的連線取消 cutoff，或把掃描來源放進 cutoff 較大的類別。
- 數字：91–94% 的連線短於 10 KB，cutoff 20 KB 可以完整保留 94–96% 的連線，錄下來的量不到原流量的 6%。兩週內 NIDS 發出 427 次 suspend_cutoff。
- 跟我們的關係：「cutoff + 風險升高時撤銷」最早、最完整的描述。§6 明說「把攻擊延到 cutoff 之後」是根本限制，作者提議隨機化 cutoff，但沒有實作。
- 筆記：`trust-bypass/papers/time-machine.md`

### 20. SciPass — a 100Gbps capable secure Science DMZ using OpenFlow and Bro

- 出處：SC14（年份和會議來自二手資料）
- PDF：`trust-bypass/pdfs/search/scipass_sc14.pdf`；深度：全文條目
- 在說什麼：Bro 判定某條 flow 是好的之後通知控制器，控制器在 OpenFlow 交換器上加高優先權規則，讓這條 flow 繞過防火牆和 IDS。規則靠 idle timeout 自動失效。
- 數字：從偵測到規則生效共 64 ms。繞過後，同一條 10 GbE 路徑的吞吐從 1.30 升到 9.9 Gbit/s。
- 跟我們的關係：「IDS 判好 → 下規則 → 走旁路」最直接的先例。沒有討論放行後的 flow 會不會變壞。
- 筆記：`trust-bypass/candidates.md` 範圍外 C

### 21. Retina — Analyzing 100GbE Traffic on Commodity Hardware

- 出處：ACM SIGCOMM 2022
- PDF：`trust-bypass/pdfs/search/retina_sigcomm22.pdf`；深度：全文條目
- 在說什麼：在 100 GbE 商用硬體上做流量分析的框架。多層過濾（硬體 flow rule → 封包 → 連線 → session），依使用者訂閱的內容決定連線什麼時候停止解析。
- 數字：一個 100 GbE 範例中，只有 35.4% 的封包通過封包過濾，1.54% 需要重組。
- 跟我們的關係：分層量成本的方法可以借。它依「分析範圍」丟棄流量，不是依信任，而且它不是 IDS。
- 筆記：`trust-bypass/candidates.md` #11

### 22. P4-ONIDS — A P4-based NIDS optimized for constrained programmable data planes in SDN

- 出處：SBRC 2021
- PDF：`trust-bypass/pdfs/search/p4onids_sbrc.pdf`；深度：全文條目
- 在說什麼：把 Snort 規則編成 P4 規則做前置過濾，可疑的 flow 只送前 N 個封包給 Snort，N 由控制平面動態調整。
- 數字：在 CICIDS2017 上，N=100 時平均過濾約 40% 的封包，告警準確度接近 90%。實驗是 BMv2 emulation。
- 跟我們的關係：點出速率型規則的盲區。例如要超過 200 pps 才觸發的 SID 40063，在 flow 被 bypass 之後永遠不會觸發，所以放行前要先決定哪些規則不能被繞過。
- 筆記：`trust-bypass/candidates.md` #5

### 23. Kabasele — A Two-level Intrusion Detection System for Industrial Control System Networks using P4

- 出處：ICS-CSR 2018
- PDF：`trust-bypass/pdfs/search/kabasele_ics-csr18.pdf`；深度：全文條目
- 在說什麼：第一層是 P4 交換器上的 flow 白名單和 Modbus 白名單，沒命中的封包送到第二層 DPI。第二層透過 SDN 控制器更新白名單。
- 數字：用 Mininet + bmv2 emulation，對通訊延遲的影響小。
- 跟我們的關係：論文列出「什麼時候把 flow 加進白名單」的選項：立即、觀察一定數量的封包後、永遠不加。原型的做法是 TCP 三向交握成功且封包分析通過才加。這些可以直接當我們的設計變數。另外，它放行後仍然逐封包檢查 Modbus function code。
- 筆記：`trust-bypass/candidates.md` #8

### 24. immUNITY — Detecting and Mitigating Low Volume & Slow Attacks with Programmable Switches and SmartNICs

- 出處：arXiv:2603.20573，2026-03，預印本
- PDF：`trust-bypass/pdfs/search/arxiv_2603.20573.pdf`；深度：全文條目
- 在說什麼：交換器上有一份 benign-flow 白名單，命中就直接轉發，只有未知流量送 SmartNIC 做 ML + 規則分析。SmartNIC 在 flow 的第 3 個封包判為 benign，就把它寫進白名單。
- 數字：96 Gbps 中只有 0.14 Gbps 進到 SmartNIC。誤放行封包的 FPR 是 0.0008%（trace 模擬）。
- 跟我們的關係：2026 年最貼近「判定後放行」的完整系統。放行後就不再看，白名單靠快取覆寫來淘汰，沒有討論放行後變惡意的情況。
- 筆記：`trust-bypass/candidates.md` #3

### 25. NetBeacon — An Efficient Design of Intelligent Network Data Plane

- 出處：USENIX Security 2023
- PDF：`trust-bypass/pdfs/search/netbeacon_usenixsec23.pdf`；深度：全文條目
- 在說什麼：交換器資料平面上的多階段 ML，在 flow 的第 2、4、8、32… 個封包做推論。某階段信心夠了，就把結果寫進 flow class table，之後的封包直接查表，不再過模型。
- 跟我們的關係：flow class table 就是現成的「信任快取」。作者自己列出 stealth attack（先送良性封包，等判定後才攻擊），建議設「最大 flow 長度上限」，但沒有量。
- 筆記：`trust-bypass/candidates.md` #2

## 5. 早期分類（看幾個封包就能判）

### 26. Bernaille — Traffic Classification on the Fly

- 出處：ACM SIGCOMM CCR 36(2), 2006
- PDF：`trust-bypass/pdfs/early-classification/bernaille-ccr06.pdf`；深度：精讀
- 在說什麼：只看 TCP 前 5 個資料封包的大小和方向（不看 payload，也不看 port），用 K-Means 分群辨識應用。這是 4 頁的 editorial，只有 Matlab 概念驗證。
- 數字：十種應用中有九種的正確率 ≥81.8%，POP3 是 0%。
- 跟我們的關係：「只看開頭」的早期源頭。它判的是「什麼應用」，不是「安不安全」，資料裡也沒有惡意流量。
- 筆記：`trust-bypass/papers/early-classification.md`

### 27. Ahmad — Early Detection of Network Attacks Using Deep Learning

- 出處：IEEE ICSTW 2022
- PDF：`trust-bypass/pdfs/early-classification/d9/2201.11628.pdf`；深度：部分章節
- 在說什麼：用 CICIDS2017 週四的 web 攻擊，看模型最少要幾個封包就能判斷。
- 數字：balanced accuracy 0.803，平均只需 1–3 個封包。SQL Injection 的訓練資料只有 15 條 flow，recall 0.528。
- 筆記：`trust-bypass/papers/early-classification.md`（D9）

### 28. Liu — Multidomain transformer-based deep learning for early detection of network intrusion

- 出處：IEEE GLOBECOM 2023
- PDF：`trust-bypass/pdfs/early-classification/d9/2309.01070.pdf`；深度：部分章節
- 在說什麼：用 transformer 做早期入侵偵測。
- 數字：在 SCVIC-TS-2022（衍生自 CICIDS2017）上，只看前 2 個封包時 macro F1 不到 70%，超過 10 個封包才超過 80%。
- 筆記：`trust-bypass/papers/early-classification.md`（D9）

### 29. Giryes — A Flow is a Stream of Packets: A Stream-Structured Data Approach for DDoS Detection

- 出處：arXiv:2405.07232，2024，預印本
- PDF：`trust-bypass/pdfs/early-classification/d9/2405.07232.pdf`；深度：部分章節
- 在說什麼：用完整 flow 訓練的分類器，看它只拿到前幾個封包時表現如何。
- 數字：CICDDoS2019 只看前 2 個封包 0.99975（完整 flow 0.99980）。CICIDS2017 只看前 2 個封包 0.8098，完整 flow 0.9965。FTP-Patator、SSH-Patator 看前 4 個封包只有 0.74 / 0.79。
- 跟我們的關係：最能說明不同攻擊需要的封包數差很多，所以放行時點不能每種流量都一樣。
- 筆記：`trust-bypass/papers/early-classification.md`（D9）

### 30. Panopoulos — Dynamic Temporal Positional Encodings for Early Intrusion Detection in IoT

- 出處：SpliTech 2025
- PDF：`trust-bypass/pdfs/early-classification/d9/2506.18114.pdf`；深度：部分章節
- 在說什麼：transformer 加上時間感知的位置編碼，做 IoT 早期偵測，並在 Raspberry Pi Zero 2 W 上實測。
- 注意：CICIoT2023 那部分只有 6 類 × 3 條，共 18 個樣本。
- 筆記：`trust-bypass/papers/early-classification.md`（D9）

### 31. A-THENA — Early Intrusion Detection for IoT with Time-Aware Hybrid Encoding and Network-Specific Augmentation

- 出處：arXiv:2604.21623，2026-04（期刊註記 ACM Transactions on AI Security and Privacy）
- PDF：`trust-bypass/pdfs/early-classification/d9/2604.21623.pdf`；深度：部分章節
- 在說什麼：#30 的擴充版。
- 數字：CICIoT23-WEB 準確率 99.87%，平均 1.2 個封包就判出來。IoTID20 是 94.41%，但要看滿 30 個封包。作者自己提醒近乎滿分的結果要謹慎解讀。
- 筆記：`trust-bypass/papers/early-classification.md`（D9）、`candidates.md` #12

### 32. CATO — End-to-End Optimization of ML-Based Traffic Analysis Pipelines

- 出處：USENIX NSDI 2025
- PDF：`trust-bypass/pdfs/early-classification/d9/2402.06099.pdf`；深度：部分章節
- 在說什麼：把「看到第幾個封包才判」、特徵選擇和端到端延遲／吞吐一起最佳化的 ML 流量分析 pipeline。它不是 IDS。
- 數字：IoT 裝置分類只用前 3 個封包，F1 0.979、延遲 0.1 s，比用前 10 個封包的 RFE10（F1 0.970、7.9 s）好。
- 跟我們的關係：少數把決策時點和成本放在一起算的工作。
- 筆記：`trust-bypass/papers/early-classification.md`（D9）

### 33. FastFlow — Early Yet Robust Network Flow Classification using the Minimal Number of Time-Series Packets

- 出處：ACM SIGMETRICS 2025
- PDF：`trust-bypass/pdfs/search/arxiv_2504.02174_fastflow.pdf`；深度：全文條目
- 在說什麼：LSTM 加強化學習，讓模型自己決定每條 flow 要看幾個封包，判不出來就回 unknown。
- 數字：在校園網路部署一週，共 2,290 萬條 flow。平均只看 8.37 個封包、約 0.5 秒，應用類型準確率超過 91%。
- 跟我們的關係：adaptive inspection depth 的最新做法。「unknown → 繼續看」可以類比我們的「判不準 → 送雲端」。它做的是應用分類，不是 IDS。
- 筆記：`trust-bypass/candidates.md` #12

## 6. IoT 設備信任與 MUD

### 34. IoT Sentinel — Automated Device-Type Identification for Security Enforcement in IoT

- 出處：IEEE ICDCS 2017
- PDF：`trust-bypass/pdfs/iot-sentinel/iot-sentinel.pdf`；深度：精讀（讀的是 arXiv v2）
- 在說什麼：SDN security gateway 在設備接入時錄下 setup 階段的封包，用 23 個 header 特徵做指紋，送到雲端辨識 device type。雲端回傳隔離等級（strict / restricted / trusted），由 gateway 執行。
- 數字：辨識率 0.815。在 Pi 2 + Open vSwitch 上量了執行的開銷。
- 跟我們的關係：「一次性設備信任」的極端例子。接入時判一次，之後既不撤銷也不抽樣。
- 筆記：`trust-bypass/papers/iot-sentinel.md`

### 35. DÏoT — A Federated Self-learning Anomaly Detection System for IoT

- 出處：IEEE ICDCS 2019
- PDF：`trust-bypass/pdfs/iot-sentinel/diot-ref/diot.pdf`；深度：部分章節（與信任、放行相關的部分）
- 在說什麼：IoT Sentinel 的後續。gateway 對每台設備用 device-type 專屬的 GRU 模型給每個封包打分，250 個封包的窗內異常比例超過門檻就告警。模型用 federated learning 訓練。
- 數字：偵測率 95.6%，平均偵測延遲 257 ms，一週真實部署 0% FPR。每個封包推論 0.592 ms（筆電 CPU），沒有 Pi 的數據。
- 跟我們的關係：另一個極端：每個封包都過模型，能抓到「先乖後壞」，但跟我們省成本的方向相反。
- 筆記：`trust-bypass/papers/iot-sentinel.md`（D9）

### 36. Hamza — Combining MUD Policies with SDN for IoT Intrusion Detection

- 出處：ACM IoT S&P 2018
- PDF：`trust-bypass/pdfs/mud-sdn/iotsnp18.pdf`；深度：部分章節（摘要、第 3–4 節）
- 在說什麼：把廠商宣告的 MUD 檔轉成 SDN flow rule。符合規則的流量由交換器直接處理，只有少數封包要送到軟體。
- 數字：送去檢查的封包約 1%，大多是 DNS 回應。28 台設備平均約 33 條規則，idle-timeout 改成 2 分鐘後降到約 25 條。
- 筆記：`trust-bypass/papers/mud-sdn.md`（D9）

### 37. Hamza — Detecting Volumetric Attacks on IoT Devices via SDN-Based Monitoring of MUD Activity

- 出處：ACM SOSR 2019
- PDF：`trust-bypass/pdfs/mud-sdn/sosr19.pdf`；深度：精讀
- 在說什麼：MUD 只管允許或拒絕，不管速率，所以合規的流量仍能拿來做容量型攻擊。這篇用每條 MUD 規則的 OpenFlow 計數器做兩階段異常偵測，還能指出是哪條 flow 出問題。
- 數字：只有 0.92% 的封包被檢查。TPR 89.7%、FPR 5.1%，平均 1.92 分鐘偵測到。低速攻擊在前幾分鐘會漏掉。
- 跟我們的關係：「放行不等於安全」的實證。它也證明放行後只留計數器、不看 payload，就能抓到相當比例的容量型攻擊，對應我們分類中的 C 類攻擊。
- 筆記：`trust-bypass/papers/mud-sdn.md`

### 38. Hamza — Detecting Anomalous Microflows in IoT Volumetric Attacks via Dynamic Monitoring of MUD Activity

- 出處：arXiv:2304.04987，2023
- PDF：`trust-bypass/pdfs/mud-sdn/arxiv2304.pdf`；深度：部分章節
- 在說什麼：#37 的延伸。偵測到異常時才鏡像流量，並插入 5-tuple 規則追到 microflow。
- 數字：第三階段常駐檢查時，26.0% 的封包要檢查（只開前兩階段時不到 1%）。TPR 91.0%、FPR 8.6%。作者承認極短暫的攻擊可能繞過偵測。
- 筆記：`trust-bypass/papers/mud-sdn.md`（D9）

## 7. 規避與撤銷

### 39. Grashöfer — Attacks on Dynamic Protocol Detection of Open Source Network Security Monitoring Tools

- 出處：arXiv:1912.03962，2019
- PDF：`trust-bypass/pdfs/search/arxiv_1912.03962.pdf`；深度：全文條目
- 在說什麼：IDS 用連線開頭一小段資料辨識協定，辨識完就固定。作者用大量無用資料（例如 CRLF stuffing）把這段 buffer 塞滿，讓協定辨識失敗。提出 Deferred Start 和 Misleading Start 兩種手法。
- 數字：Bro 的協定辨識 buffer 預設只有 1024 bytes。Snort 3 和 Suricata 4.1.2 會被 HELO 手法規避。Suricata 要大約十萬個 CRLF 才會被 CRLF stuffing 規避。規避成功後，Suricata 不再產生 HTTP log，HTTP 規則也不再比對。
- 跟我們的關係：唯一在主流 IDS 上實證「固定截斷點可以被填滿」的論文。我們的信任窗口如果固定、可預測，也會有同樣的問題（這是類比）。
- 筆記：`trust-bypass/candidates.md` #4

### 40. NetMasquerade — A Hard-Label Black-Box Evasion Attack against ML-based Malicious Traffic Detection Systems

- 出處：NDSS 2026
- PDF：`trust-bypass/pdfs/search/ndss26_netmasquerade.pdf`；深度：部分章節（摘要、攻擊設計、受測系統）
- 在說什麼：只靠偵測器輸出的 hard label，用強化學習在攻擊 flow 裡加入非功能封包、改變封包大小和間隔，讓攻擊看起來像良性流量。
- 數字：對 6 個偵測系統、80 個情境，攻擊成功率超過 96.65%。受測系統包括 FlowLens、Kitsune、NetBeacon。
- 跟我們的關係：如果放行判斷靠 ML 和 flow 特徵，攻擊者就可以讓開頭看起來良性。我們的雲端不看 payload，正好屬於這類偵測器。
- 筆記：`trust-bypass/candidates.md` #9

### 41. NOS-Gate — Queue-Aware Streaming IDS for Consumer Gateways under Timing-Controlled Evasion

- 出處：IEEE Transactions on Consumer Electronics 2026（讀的是 arXiv:2601.00389 v2）
- PDF：`trust-bypass/pdfs/search/arxiv_2601.00389.pdf`；深度：全文條目
- 在說什麼：家用 gateway 上的串流 IDS，只看 metadata。每條 flow 有一個兩狀態單元，K-of-M 規則觸發後，暫時降低這條 flow 在 WFQ 裡的權重，這個動作可以恢復。威脅模型是攻擊者在預算內重塑時序和封包大小，去模仿良性設備。
- 數字：0.1% 誤報下 incident recall 0.952，最佳基線是 0.857。每個 flow-window 評分約 2.09 µs。用的是合成資料。
- 跟我們的關係：「持續評分 + K-of-M + 可逆動作」可以直接借來設計撤銷機制。但它沒有放行機制，也沒有 Pi 實測。
- 筆記：`trust-bypass/candidates.md` #14

### 42. Shelby — Zero Trust for Multi-RAT IoT: Trust Boundary Management in Heterogeneous Networks

- 出處：arXiv:2602.08989，2026-02
- PDF：`trust-bypass/pdfs/search/arxiv_2602.08989.pdf`；深度：部分章節（§4.3、結論）
- 在說什麼：質性分析。提出指數衰減的 trust decay 模型，也討論 Weibull 和事件觸發式衰減。作者明說衰減率需要實測校準，論文沒有實驗。
- 跟我們的關係：信任衰減的公式可以參考，但這篇跟封包檢測無關。
- 筆記：`trust-bypass/candidates.md`「找到但未列入」

### 43. Korkmaz — Closing the Loop: An Access-Control Architecture for Automated, Anomaly-Driven Response

- 出處：arXiv:2607.11649，2026-07
- PDF：`trust-bypass/pdfs/search/arxiv_2607.11649_closingloop.pdf`；深度：摘要
- 在說什麼：異常偵測觸發後，用 802.1X + RADIUS CoA 把設備踢出網路，再撤銷它的憑證。
- 數字：逐出設備 335.8 ms，撤銷憑證再加 111.5 ms。受測裝置只有一台 Raspberry Pi 感測器。
- 跟我們的關係：唯一找到有量撤銷反應時間的論文，但它是設備層級，不是 flow 層級。
- 筆記：`trust-bypass/candidates.md`「找到但未列入」

## 8. 其他

### 44. Niedermaier — Efficient Intrusion Detection on Low-Performance Industrial IoT Edge Node Devices

- 出處：arXiv:1908.03964，2019
- PDF：`trust-bypass/pdfs/search/arxiv_1908.03964.pdf`；深度：摘要（2026-10-20 讀了摘要和前言開頭）
- 在說什麼：工控網路改用 Modbus/TCP 這類 IP 協定之後，只靠邊界防禦不夠。作者在每個 IIoT 邊緣設備（跑 FreeRTOS + LwIP 的 MCU）上放分散式 agent，再集中收 log。只做了 PoC。
- 跟我們的關係：這是分散在設備端的 IDS，跟我們集中在 gateway 的方向不同。沒有卸載決策，所以沒列入主清單。
- 筆記：`trust-bypass/candidates.md`「找到但未列入」

## 9. 新穎性查核補進的論文（2026-11-03）

從 WoS、IEEE Xplore、ACM DL 的系統性搜尋與雪球挑出來讀全文。這些論文和 C1–C4 的差異總表在 `novelty-check/REPORT.md` §3。

### 45. Meng — Intrusion Detection in the Era of IoT: Building Trust via Traffic Filtering and Sampling

- 出處：IEEE Computer 51(7), 2018, pp.36–43
- PDF：`novelty-check/pdfs/lit_ieee_8423129.pdf`；深度：精讀
- 在說什麼：IoT 情境下，在 IDS 前面加管理員維護的白名單過濾和固定間隔抽樣來降低負載，再用 trust 計算處理內部節點。
- 數字：作者說的「重流量」是平均 9,792 pps、最高 12,530 pps。沒有每封包成本或偵測率。
- 跟我們的關係：白名單流量不會被抽回檢查，只靠管理員更新。trust 是節點信譽，不是 flow 信任。固定間隔抽樣正是 #46 說會被規避的做法。
- 筆記：`novelty-check/fulltext/G1_sampling_trust.md` §1

### 46. Goldberg & Rexford — Security Vulnerabilities and Solutions for Packet Sampling

- 出處：IEEE Sarnoff Symposium 2007
- PDF：`novelty-check/pdfs/lit_ieee_4567339_sampling_security.pdf`；深度：精讀
- 在說什麼：安全分析。攻擊者知道抽樣週期，就能讓自己的封包完全避開抽樣；所以抽樣必須不可預測。
- 數字：無，是理論分析。
- 跟我們的關係：稽核時間點要隨機的依據，呼應我們實測固定稽核窗只抓到約 10%。
- 筆記：`novelty-check/fulltext/G1_sampling_trust.md` §2

### 47. Kodialam & Lakshman — Detecting Network Intrusions via Sampling: A Game Theoretic Approach

- 出處：IEEE INFOCOM 2003, pp.1880–1889
- PDF：`novelty-check/pdfs/kodialam_infocom2003.pdf`；深度：精讀
- 在說什麼：把偵測者和入侵者建成賽局，在總抽樣預算下決定各鏈路的抽樣率。
- 數字：無，純理論。
- 跟我們的關係：「抽樣預算＋對抗隨機化」的早期理論背景。
- 筆記：`novelty-check/fulltext/G1_sampling_trust.md` §5

### 48. Otrok — Game Theoretic Models for Detecting Network Intrusions

- 出處：Computer Communications 31 (2008) 1934–1944
- PDF：`novelty-check/pdfs/lit_elsevier_comcom2007.12.028_game_sampling.pdf`；深度：精讀
- 在說什麼：有線網路上 IDS 在 link 抽封包，攻擊者把攻擊拆成多個封包、走多條路徑；在全網的抽樣預算下求均衡。只在一張九節點的範例圖上做數值計算。
- 數字：沒有實作或量測。
- 跟我們的關係：純理論，沒有信任放行和撤銷。「把攻擊拆成多封包」和我們的「先塞資料再攻擊」只是概念相鄰。
- 筆記：`novelty-check/fulltext/G5_elsevier.md`

### 49. Giacometti — An Investigation on Packet Sampling between Kernel and User Space for NIDS

- 出處：ISNCC 2025
- PDF：`novelty-check/pdfs/lit_ieee_11250446_kernel_user_sampling.pdf`；深度：精讀
- 在說什麼：XDP 擷取特徵，只把一部分封包交給 KitNET；其餘封包查「已判惡意的 flow 表」處置。平台是 x86、10 GbE。
- 數字：特徵擷取 >5 Gbit/s，KitNET 約 16 Mbit/s。Mirai 的 recall 在每 1000 個封包抽 1 個時是 79.054%（不抽樣 88.149%）。抽樣後的吞吐是推算的。
- 跟我們的關係：結構最像 C1（抽樣＋把判定傳給同 flow），但沒有信任、放行、稽核、撤銷，也沒有「放行後才攻擊」的情境。
- 筆記：`novelty-check/fulltext/G1_sampling_trust.md` §4

### 50. Valgenti — Protecting Run-time Filters for Network Intrusion Detection Systems

- 出處：IEEE AINA 2014, pp.116–122
- PDF：`novelty-check/pdfs/lit_ieee_6838655_runtime_filters.pdf`；深度：精讀
- 在說什麼：NIDS 前面加 rate limiter，用 RED 式的隨機轉送避免被攻擊者預測。audit trail 記錄被丟掉的封包可能符合哪些規則。用 Perl 模擬器評估，NIDS 每封包 100 µs 是假設值。
- 數字：8,089 個有告警的 flow 中，7,931 個在前 5 個封包內就出現告警（98%）。
- 跟我們的關係：用詞最像 C1，但它的 audit 是記錄被丟的封包，不是再檢查已放行的流量。它的 FEF 公式可以借來呈現 fast path 的成本帳。
- 筆記：`novelty-check/fulltext/G1_sampling_trust.md` §6

### 51. SparseIDS — Learning Packet Sampling with Reinforcement Learning

- 出處：IEEE CNS 2020（arXiv:2002.03872）
- PDF：`novelty-check/pdfs/lit_arxiv_2002.03872_sparseids.pdf`；深度：精讀
- 在說什麼：LSTM 用標頭特徵分類 flow，再用 RL 決定要看哪些封包。資料集是 CIC-IDS-2017，每條 flow 截到 20 個封包，離線執行。
- 數字：跳過 76.3% 封包時，RL 的 accuracy 99.4%；只看前 m 個封包是 98.3%。
- 跟我們的關係：「只看開頭就夠」的 ML 側證據。但作者假設每條 flow 不是全攻擊就是全正常（Sec III-B），排除了先正常後攻擊的情況。
- 筆記：`novelty-check/fulltext/G1_sampling_trust.md` §3

### 52. Lin & Lee — Re-examining the Performance Bottleneck in a NIDS with Detailed Profiling

- 出處：JNCA 36 (2013) 768–780
- PDF：`novelty-check/pdfs/lit_elsevier_jnca2012.12.009_nids_bottleneck.pdf`；深度：精讀
- 在說什麼：用 profiling 拆解 Snort 2.8.5 和 Bro 各階段的 CPU cycles，並提議負載高時動態改成只掃連線開頭。只是提議，沒有實作。環境是離線 PCAP、Core2 Q9400。
- 數字：
  - HTTP 每封包 13.88K cycles，其中 preprocessing 占 29%，preprocessing 裡 stream5 又占 53%。
  - Snort 預設 HTTP 每方向只掃前 300 bytes，Bro 只重組前 1 kB。
  - 改成整條掃，HTTP 總 cycles 增加約 10.7 倍。
- 跟我們的關係：C2「只掃開頭」的前人。我們量到「只送前 N bytes」會被填充繞過，正是它的反例。stream5 的占比支持 C4 的動機：跳過 IDS 省下的不只是 pattern matching。
- 筆記：`novelty-check/fulltext/G5_elsevier.md`

### 53. Wang & Chang — Design and Implementation of an Intrusion Detection System by Using Extended BPF in the Linux Kernel

- 出處：JNCA 198 (2022) 103283
- PDF：`novelty-check/pdfs/lit_elsevier_jnca2021.103283_ebpf_ids.pdf`；深度：精讀
- 在說什麼：在 XDP 用 Aho–Corasick 掃 payload，不含任何規則 fast pattern 的封包直接在 kernel 丟掉，有的才送 user space 的 Snort。處理的是 mirror 複本（被動模式），不支援 flow、flowbits 這類有狀態的規則選項。
- 數字：Xeon E-2134、10 GbE。Snort 零遺失約 2000 Mbps，他們約 6000 Mbps。9500 Mbps 負載下 softirq 是 400% 對 600%。
- 跟我們的關係：C4 的機制前例（kernel 擋掉大部分封包）。以封包為單位、沒有 flow 狀態，也就無法撤銷。作者自己提到 Suricata 已有 XDP flow bypass。
- 筆記：`novelty-check/fulltext/G5_elsevier.md`；`framework/papers/wang-chang.md`

### 54. DS-nDPI — Architecture for Building Hybrid Kernel-User Space Virtual Network Functions

- 出處：CNSM 2017（Nguyen Van Tu、Kyungchan Ko、James Won-Ki Hong）
- PDF：`novelty-check/pdfs/lit_ieee_8256051_hybrid_kernel_user_vnf.pdf`；深度：精讀
- 在說什麼：hybrid kernel／user VNF 架構。DS-nDPI 由 user space 的 nDPI 分類，分類完就把 flow 寫進 tc eBPF 表，之後同一條 flow 不再送 user space，idle 時移除。是被動 clone，平台是 VirtualBox VM（1 core）。
- 數字：tcpreplay 最大吞吐 DS-nDPI 降 21%，標準 nDPI 降 43%。沒有 pps 或每封包成本。
- 跟我們的關係：「user space 判定後寫進 kernel 表、之後跳過」的直接前例。但它是 DPI 分類不是 IPS、是被動模式、在 x86，只有 idle 到期、沒有稽核。
- 筆記：`novelty-check/fulltext/G2_kernel_fastpath.md`

### 55. iKern — Advanced Intrusion Detection and Prevention at the Kernel Level Using eBPF

- 出處：Technologies 12(8):122, 2024（MDPI）
- PDF：`novelty-check/pdfs/lit_mdpi_technologies12080122_ikern.pdf`；深度：精讀
- 在說什麼：eBPF 依白名單直接轉送、依黑名單丟，其餘才送 user space。白名單是人工設定的靜態 IP。平台是 Xeon x86。
- 數字：沒有 pps，無法換算每封包成本。
- 跟我們的關係：只當背景。資料路徑描述不清，引用編號也有錯，不引用它的數字。
- 筆記：`novelty-check/fulltext/G2_kernel_fastpath.md`

### 56. Sárközi & Vörös — In-Network Attack Detection Using Disaggregated Inference & Online Learning

- 出處：IEEE GLOBECOM 2025
- PDF：`novelty-check/pdfs/lit_ieee_11432439_innetwork_disagg.pdf`；深度：精讀
- 在說什麼：把決策樹拆到多台交換器（Tofino／eBPF）做 in-network 推論。隨機抽約 5% flow 的特徵送外部 IDS 當標籤，線上重訓。外部 IDS 是用 CIC-IDS-2017 的標籤模擬的。
- 數字：抽 1%–100% 的 F1 都在 0.91–0.96。Tofino 推論加轉送約 0.7 µs。
- 跟我們的關係：和 C1 最接近的一篇。它有隨機抽 flow 送外部檢查，但稽核的是模型，不撤銷個別 flow 的信任，也沒量放行後的漏報。
- 筆記：`novelty-check/fulltext/G2_kernel_fastpath.md`

### 57. P4Pir — Toward Continuous Threat Defense: In-Network Traffic Analysis for IoT Gateways

- 出處：IEEE IoT-J 11(6):9244–9257, 2024（2023 線上）（Zang、Zheng、Dittmann、Zilberman）
- PDF：`novelty-check/pdfs/lit_jiot2023_p4pir.pdf`；深度：精讀
- 在說什麼：IoT gateway 上的 in-network ML。在 P4Pi（Pi 4 8GB）的 bmv2 上，每個封包用 header 特徵分類。特徵送 control plane，用 iForest 自己標註後重訓，再用 shadow table 不中斷地換模型。
- 數字：
  - 純轉送約 92 Mbps；加 DT／RF 後約 55–80 Mbps（讀圖）。
  - CPU 約 37% → 50–62%（用 /proc/stat 量，讀圖）。
  - 對照組 ClearAll 換模型時，有約 5 秒的丟包尖峰。
- 跟我們的關係：平台最接近的一篇（Pi 4 gateway、ML 和轉送同機）。但 bmv2 跑在 user space、每個封包都分類；沒有規則式 IDS、fast path、撤銷，也沒量記憶體干擾。
- 筆記：`novelty-check/fulltext/G6_snowball_innetwork.md` §1

### 58. HALIDS — A Hardware-Assisted Machine Learning IDS for in-Network Monitoring

- 出處：TMA 2024（Brandino 等 7 人；3 頁短文）
- PDF：`novelty-check/pdfs/lit_tma2024_halids.pdf`；深度：精讀
- 在說什麼：BMv2 上的 P4 student 模型逐封包分類，信心低於門檻的交給 off-band 的 RF oracle 判斷，做 active learning。
- 數字：只測了 1000 個封包。信心門檻 90%／95% 時，recall 比 baseline 高約 10%／15–20%。
- 跟我們的關係：「本地判不出來才往上送」的架構和我們一致。但它由信心門檻觸發，高信心卻判錯的 benign 不會被複核。沒有 flow 信任，也沒有資源量測。
- 筆記：`novelty-check/fulltext/G6_snowball_innetwork.md` §2

### 59. Monsakul — Real-Time Network IDS for SOHO Using Hybrid Edge Machine Learning Techniques

- 出處：IBDAP 2026
- PDF：`novelty-check/pdfs/lit_ieee_11678008_soho_hybrid_ml.pdf`；深度：精讀
- 在說什麼：SOHO 網路，同一台 Pi 4 跑 Suricata（ET ruleset）＋Random Forest，ML 只處理有 Suricata alert 的 flow。
- 數字：10 分鐘可行性測試：持續 82 Mbps、CPU 62%、特徵到分類 145 ms（Table II）。沒寫封包大小。
- 跟我們的關係：C3 最接近的比較對象。沒有只跑 Suricata 的基準，也沒量丟包和干擾。作者在 IV-D 把 overload control（bounded queue、batch、temporary sampling、offload）列為沒有實作。
- 筆記：`novelty-check/fulltext/G3_pi_ids_ml_a.md` §1

### 60. Hidayatullah — Internet of Things Network Security with Intrusion Prevention System Based on SnortML

- 出處：ICIMCIS 2025, pp.1520–1525
- PDF：`novelty-check/pdfs/lit_ieee_11327354_snortml_ips.pdf`；深度：精讀
- 在說什麼：Pi 3B／Pi 4 上的 inline Snort＋SnortML。規則沒命中才做 ML 推論，機率 ≥80% 就 drop。
- 數字：實驗時 Snort 沒載規則，流量只有 4–65 Kbps。準確率 59–66%。
- 跟我們的關係：只當背景。量測條件太輕，不能當 Pi 上 IPS 的基準。
- 筆記：`novelty-check/fulltext/G3_pi_ids_ml_a.md` §2

### 61. Stolz & Zhang — A Blockchain-Enabled Hybrid Intrusion Detection Framework for Resource-Constrained Devices

- 出處：PeerJ Computer Science 12:e3899, 2026
- PDF：`novelty-check/pdfs/lit_peerj_cs3899_blockchain_hybrid.pdf`；深度：精讀
- 在說什麼：同一台 Pi 4B 4GB 同時跑 Snort 2.9、FL client、Hyperledger Fabric 和監控程式。
- 數字：只有一張利用率快照（Table 12）：總 CPU 35.5%，Snort <3%。
- 跟我們的關係：宣稱沒有資源爭用，但沒有任何量測支持，可當反駁對象。文中的 trust 指 FL 節點的信任，和 flow 無關。
- 筆記：`novelty-check/fulltext/G3_pi_ids_ml_a.md` §3

### 62. Tuong & Kimura — 2-Step Power Scheduling with Adaptive Control Interval for NIDS on Multicores

- 出處：MCSoC 2016, pp.69–76
- PDF：`novelty-check/pdfs/lit_ieee_7774422_arm_power_sched.pdf`；深度：精讀
- 在說什麼：ARM（A15 2 GHz）上 Suricata 2.0.8 的 DVFS 省電排程。有其他程式要跑時，把雙方的執行緒切到不同核心。
- 數字：
  - 4 核心在 17 kpps 輸入下處理 15.4–16.2 kpps。
  - 1 核心滿載約 200–240 µs／封包。這是 subagent 從 Fig. 3b 推算的，論文沒報。
- 跟我們的關係：ARM 上 Suricata 少數有的數字。但目標是省電，沒有 ML，也沒量干擾。
- 筆記：`novelty-check/fulltext/G4_edge_ids_ml_b.md` §1

### 63. Mirzai — Scheduling to the Rescue; Improving ML-Based Intrusion Detection for IoT

- 出處：EuroSec 2023, pp.44–50
- PDF：`novelty-check/pdfs/lit_acm_3578357.3589460_sched_rescue.pdf`；深度：精讀
- 在說什麼：在 Pi 4 4GB 和 Jetson Nano 上排程多個 ML 異常偵測實例（PASAD）和重訓，依 buffer 占用與異常分數調整執行頻率。流量從 pcap 餵入。
- 數字：Pi 4 記憶體頻寬約 4.4 GB/s（datasheet 值）。
- 跟我們的關係：同樣認為 Pi 4 的記憶體頻寬是瓶頸，但只是推測（Sec. 7.1），而且競爭發生在 ML 和 ML 之間，沒有規則式 IDS。
- 筆記：`novelty-check/fulltext/G4_edge_ids_ml_b.md` §2

### 64. Think Fast — Real-Time IoT Intrusion Reasoning Using IDS and LLMs at the Edge Gateway

- 出處：IEEE IoT-J 13(8):15485–15513, 2026（Jamshidi 等）
- PDF：`novelty-check/pdfs/lit_ieee_11359684_think_fast.pdf`；深度：精讀
- 在說什麼：edge 上跑 ML 分類器（DT、KNN、RF、CNN、LSTM），雲端用 LLM API 推理。由閘函數依延遲和上行狀態決定要不要呼叫 LLM。不是 inline IPS。
- 數字：能耗和延遲的數字前後不一致，例如延遲內文寫 8–14 ms、Fig. 14 約 1.0–1.35 s，不要引用。
- 跟我們的關係：只當背景。LLM 在雲端，沒有同機爭用。
- 筆記：`novelty-check/fulltext/G4_edge_ids_ml_b.md` §3

---

## 附錄

**重複的檔案**（sha256 相同，只是放在兩個子資料夾）：

| 論文 | 檔案 1 | 檔案 2 |
|---|---|---|
| #37 Hamza SOSR'19 | `trust-bypass/pdfs/mud-sdn/sosr19.pdf` | `trust-bypass/pdfs/search/hamza_sosr19.pdf` |
| #19 Maier SIGCOMM'08 | `trust-bypass/pdfs/time-machine/maier_sigcomm08.pdf` | `trust-bypass/pdfs/search/timemachine_sigcomm08.pdf` |
| #16 Papadogiannakis EuroSec'10 | `trust-bypass/pdfs/selective-discarding/discarding.eurosec10.pdf` | `trust-bypass/pdfs/search/papadogiannakis_eurosec10.pdf` |

**不是論文的 PDF**：`trust-bypass/pdfs/search/p4id_coseners.pdf` 是 P4ID 第一作者在 Coseners 2019 的演講投影片。對應的論文 P4ID（IEEE NFV-SDN 2019）和後續的 4MIDable（JNSM 2023）只讀到摘要。這兩篇在講把 Snort/Suricata 規則轉成 P4 表項做前置過濾，再由 IDS 回饋給過濾器（`trust-bypass/candidates.md` #6）。

**有引用但沒有 PDF、只讀到摘要的**：

- Chae, DiPippo, Sun — Trust Management for Defending On-Off Attacks（IEEE TPDS 2015）：惡意節點可以利用信任恢復（redemption）機制，好壞交替地攻擊。這是 WSN 的模擬研究（`trust-bypass/candidates.md` #10）。
- 其他只讀到摘要或二手描述的候選，列在 `candidates.md` 和 `trust-bypass/candidates.md` 的「找到但未列入」。
