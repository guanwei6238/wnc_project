# 開放搜尋候選論文清單

搜尋日期：2026-10-10。範圍：資源受限閘道器／邊緣設備上「本地先檢測、複雜流量才卸載」的 IDS 架構，以及 flow 資料收集／壓縮、封包處理、卸載決策與傳輸成本。
不重複精讀清單：FlowLens、HorusEye、Edge Multi-agent IDS、Efficient IDS for IoT Networks Using Host-Based Data Aggregation、Real-Time eBPF/XDP-Based Deep Learning Framework。

證據標記沿用 SUBAGENT_SPEC 第 4 節：`[原文]` 在全文看到、`[摘要]` 只在摘要／出版社頁面看到、`[二手]` 別人的描述、`[推測]` 我的判斷、`未能確認`。
說明：全文是以 pdftotext 抽取，沒有頁碼，所以 `[原文]` 後面只寫章節／圖表編號或「內文」，不寫頁碼。本清單所有 `[原文]`/`[摘要]` 皆來自我實際打開的頁面或 PDF。

C1 高效率封包處理、C2 Flow 資料收集、C3 雲端卸載、C4 降低地端運算與傳輸成本；K1 轉送效能、K2 資料完整性、K3 即時性。

## 總覽表

| # | 簡稱 | 角度 | 存在確認 | 取得 | 優先度 |
|---|---|---|---|---|---|
| 1 | Simioni 2024/25 Early-exit 卸載 | a, f | 已確認（見下方備註） | 全文 | 高 |
| 2 | LocKedge 2020 | a, c | 已確認（arXiv） | 全文 | 中 |
| 3 | CECN-DNN 2026 | a | 僅見二手（聚合站 + 搜尋結果） | 僅摘要級二手 | 低（待查證） |
| 4 | Kitsune 2018 | b, c | 已確認（arXiv、NDSS 投影片） | 全文 | 高 |
| 5 | Palmese 2026 Lossy Compression | b, f | 已確認（arXiv） | 僅摘要 | 中 |
| 6 | Alikhanov 2022 Sampling vs ML NIDS | b, e | 已確認（出版社 DOI 頁） | 僅摘要 | 高 |
| 7 | Torres 2025 Zeek 探針 | c | 已確認（SBC 出版頁） | 僅摘要 | 中 |
| 8 | Galette 2023 | c, d | 已確認（Glasgow eprint） | 全文（作者版） | 高 |
| 9 | Sapo-boi 2026 | d | 已確認（JBCS） | 全文 | 高 |
| 10 | Braun 2013 Load-Aware Sampling | e | 已確認（arXiv） | 僅摘要 | 中 |
| 11 | XNET 2026 | e, b | 已確認（arXiv 預印本） | 僅摘要 | 中 |
| 12 | A-THENA 2026 | e, c | 已確認（arXiv） | 僅摘要 | 中 |

12 篇中 11 篇已在出版社／arXiv／機構庫確認存在；1 篇（CECN-DNN）僅見二手。

---

## 1. Simioni et al. — An Energy-efficient Intrusion Detection Offloading Based on DNN for Edge Computing（角度 a、f）

- 書目：João A. Simioni, Eduardo K. Viegas, Altair O. Santin, Everton de Matos。稿件模板為 IEEE Internet of Things Journal（頁首 "VOL. X, NO. X, 2024"，未見正式卷期）。URL：https://secplab.ppgia.pucpr.br/files/papers/2025_3.pdf 。另有 SBC 版：SBSeg 擴充版 https://sol.sbc.org.br/index.php/sbseg_estendido/article/view/44445 與 CTD 2026 版 https://sol.sbc.org.br/index.php/ctd/article/view/43048（DOI 10.5753/ctd.2026.19705，此 DOI 來自 SBC 引用外掛頁的搜尋結果 [二手]）。碩士論文版：PUCPR 2025。
- 存在確認：已確認（作者機構 PDF 全文、SBC 頁面）。IEEE IoT-J 正式刊登與 DOI **未能確認**，目前看到的是稿件版。
- 取得：全文（PUCPR 稿件版）。
- 對應：C3、C4、K3 為核心，K2 部分。Edge 端 DNN 早期出口（early exit）分類，信心不足才把中間層輸出卸載到雲端第二分支；用多目標最佳化決定門檻，並加 reject option 與信心校準。[原文 摘要、Fig.5] 這是目前找到最直接把「本地先判、判不準才上雲」做成可調門檻並量測能耗的論文。
- 與已知清單比較：[推測] 與 Edge Multi-agent IDS 互補。它給出「卸載比例 vs 能耗 vs 準確率」的量化框架與門檻最佳化方法，可直接借來設計我們的卸載決策；缺點是處理單位是「event（已抽好的特徵）」，不是封包／flow 收集。
- 硬體與資料集：End device 為 Raspberry Pi 3 Model B（4 核 Broadcom、1 GB、Pi OS kernel 6.1），雲端為 IBM Cloud VM（2 vCPU、8 GB）；用電表量能耗。[原文 §VI 實作、§VII-B] 資料集為自建 MAWIFlow（由公開 MAWI 流量衍生，一年、超過 7 TB）。[摘要][原文 §VII-A] 程式碼與實驗：https://github.com/jasimioni/ids-ee-offload [原文 結論後]
- 數字：邊緣能耗與處理成本降至 1%、僅卸載 10% 事件、準確率維持。[摘要]
- 優先度：**高**。原因：同硬體等級（Pi 3B）、有能耗實測、有公開程式碼、卸載比例與準確率的取捨直接對應 C3/C4。注意：[推測] 它處理的是 DNN 特徵事件，若我們的本地檢測是 Suricata 規則，「信心值」要換成規則命中／未命中的其他訊號。

## 2. LocKedge — Low-Complexity Cyberattack Detection in IoT Edge Computing（角度 a、c）

- 書目：Truong Thu Huong 等 7 人，HUST，2020，arXiv:2011.14194。https://arxiv.org/abs/2011.14194 。arXiv 註記投稿 IEEE Access，**是否正式刊登未能確認**。
- 存在確認：已確認。取得：全文。
- 對應：C3、C4、K1（部分）。Edge 閘道器跑偵測，雲端做資料探勘／模型彙整（centralized 與 federated 兩種模式）。[原文 §III Fig.2] 論文有一節量測 Pi 3B+ 上的 CPU／RAM。
- 硬體與資料集：Raspberry Pi 3B+（1.4 GHz 四核、1 GB），Python 3 實作；資料集 BoT-IoT。[原文 §V-D][摘要] 結果：到 2400 samples/s 時單核 100%，整體估計可承受 9,600 samples/s；超過 1800 samples/s 後 parser 堆積、RAM 被耗盡。[原文 §V-D, Fig.18–20]
- 為何貼近：少數明確用 **Pi 3B+** 量資源的 edge-cloud IDS 論文，與我們目標平台完全同款。互補性：它的雲端角色偏向「訓練／聚合」，不是對疑難流量做重量級推論。[推測]
- 優先度：**中**。原因：平台吻合、可作 Pi 3B+ 上 ML 偵測能力的參考上限，但偵測方法是 Python ML，且樣本率（samples/s）不是封包率，不能直接換算。

## 3. CECN-DNN — A Cloud-Edge Collaborative Inference Approach to Intrusion Detection（角度 a）

- 書目：Jieying Zhou 等（頁面僅顯示第一作者，其餘 9 人未列出），Computer Networks，2026-03-03，DOI 10.1016/j.comnet.2026.112127（此 DOI 來自聚合站）。聚合站：https://www.synapsesocial.com/de/papers/69a761b2c6e9836116a2fbdc 。搜尋結果也列出 ScienceDirect 條目（S1389128626001398），但我打開時遇 403。
- 存在確認：**僅見二手**（聚合站有標題、作者、日期、DOI；出版社頁面無法開啟）。
- 取得：僅二手描述。聚合站稱以雲邊協同推論降低延遲、提升準確率 [二手]；我沒有看到摘要、硬體、資料集與任何數字（均「未能確認」）。另一則搜尋摘要稱延遲相對 SOTA 改善 6%–18%、能依網路狀況調整 [二手，來源為搜尋引擎摘要，未能對照原文]。
- 對應：[推測] 可能對應 C3、K3；是否涉及 flow 收集或傳輸成本未能確認。
- 優先度：**低（待查證）**。原因：內容無法驗證。建議先在有 Elsevier 權限的環境確認摘要再決定是否精讀。

## 4. Kitsune — An Ensemble of Autoencoders for Online Network Intrusion Detection（角度 b、c）

- 書目：Yisroel Mirsky, Tomer Doitshman, Yuval Elovici, Asaf Shabtai，NDSS 2018，arXiv:1802.09089。https://arxiv.org/abs/1802.09089 ；NDSS 投影片 https://www.ndss-symposium.org/wp-content/uploads/2018/03/NDSS2018_03A-3_Mirsky_Slides.pdf 。
- 存在確認：已確認。取得：全文（arXiv v2）。
- 對應：C2、C4、K1/K3。核心是 AfterImage：用阻尼窗（damped window）增量統計維護每條「channel」的特徵，記憶體小、單封包更新；加上 KitNET 小型 autoencoder 集成，做無監督線上偵測。[原文 §III–IV；內文稱 incremental statistics 與 small memory footprint] 它是「Flow／channel 特徵怎麼在地端低成本維護」的經典做法。
- 硬體與資料集：【2026-10 更正：原稿誤寫「Pi 3B 做 active wiretap 橋接」。經精讀與原文核對（p.10、p.11 Table III），active wiretap 是論文中的**攻擊項目**，Pi 3B 是攻擊者工具，不是 Kitsune 的部署方式。Pi 的數字是 KitNET 在 C++、單核、n=198 特徵下的 benchmark（p.14 Fig.10 圖說），是否含特徵抽取論文未說明。】Raspberry Pi 3B 在單一邏輯核心上測封包處理速率：Pi 約 1,000 pps（單一 autoencoder 於 L(1)），35 個 autoencoder 時約 5,400 pps；PC（Ubuntu VM）約 7,500 與 37,300 pps。[原文 §V 效能評估、Fig.10–11、Table V] 資料集為作者自建的 Kitsune Network Attack Dataset（含 Mirai 等多種攻擊；Table III）。
- 為何貼近：給出 **Pi 3B 上的封包處理速率上限**，可作為我們「本地能做多少事」的下界；其增量統計結構可用於壓縮 flow 資料。互補性：無雲端卸載、無轉送路徑（旁路鏡像）。
- 優先度：**高**。原因：與目標硬體同級、特徵抽取成本結構可直接拿來設計 C2；pps 數字能校準我們的預期。注意：2018 年資料，攻擊型態較舊 [推測]。

## 5. Lossy Compression of Network Feature Data: When Less Is Enough（角度 b、f）

- 書目：Fabio Palmese, Gabriele Merlach, Damiano Ravalico, Martino Trevisan, Alessandro E. C. Redondi，2026-02-25，arXiv:2602.21891；註記投稿 IEEE Communications Magazine。https://arxiv.org/abs/2602.21891 。
- 存在確認：已確認（arXiv）。取得：僅摘要。
- 對應：C2、C4、K2。研究 task-aware 的有損壓縮：網路特徵比原始封包小，但仍造成儲存瓶頸；以網站分類（核心網路）與 IoT 裝置識別為用例，結論是簡單且保留語意的壓縮技術呈現「穩定的操作區間」。[摘要] 這正是 K2「壓縮後偵測力損失多少」要的證據類型。
- 硬體與資料集：未能確認（摘要未載）。用例是裝置識別與網站分類，**不是入侵偵測** [摘要]。
- 為何貼近：目前唯一找到明講「特徵資料有損壓縮 vs 下游任務表現」的論文，且包含 IoT 設定；與 FlowLens（已有人讀）互補，FlowLens 偏分佈截斷，這篇偏數值精度／量化 [推測]。
- 優先度：**中**。原因：任務不是 IDS，需要自行判斷能否遷移；預印本尚未同行審查。

## 6. Investigating the Effect of Traffic Sampling on Machine Learning-Based Network Intrusion Detection Approaches（角度 b、e）

- 書目：Jumabek Alikhanov, Rhongho Jang, Mohammed Abuhamad, David Mohaisen, Daehun Nyang, Youngtae Noh。IEEE Access, vol.10, pp.5801–5823, 2022。DOI 10.1109/ACCESS.2021.3137318。頁面：https://pure.ewha.ac.kr/en/publications/investigating-the-effect-of-traffic-sampling-on-machine-learning-/
- 存在確認：已確認（Ewha 機構庫頁面含 DOI）。取得：僅摘要。
- 對應：C2、C4、K2。系統性量測封包取樣對 ML/DL NIDS 的偵測率與誤報率影響；取樣率 1/10、1/100、1/1000；四種取樣器（含 SketFlow、Sketch Guided Sampling、Fast Filtered）、三種分類器。結論：封包數少的惡意 flow 在 1/10、1/100 的溫和取樣下就容易被漏掉；SketFlow + Random Forest 組合最佳；SGS 在 1/100→1/1000 時急遽下降。[摘要]
- 硬體與資料集：資料集名稱摘要頁**未能確認**；硬體與此題無關（離線評估）[推測]。
- 為何貼近：直接量化「減少資料量（取樣）換來多少偵測力損失」，是 K2 的核心實證，也警告短 flow 攻擊（掃描、低速）最先被犧牲。
- 優先度：**高**。原因：方法學可直接套用（我們可用同樣流程評估自己的壓縮／取樣策略），且不依賴特殊硬體。

## 7. Torres, Mansilha, Kreutz — Análise de Desempenho e Eficácia da Sonda Zeek（角度 c）

- 書目：Rafael B. Torres, Rodrigo Brandão Mansilha, Diego Kreutz（UNIPAMPA）。ERRC 2025，SBC。DOI 10.5753/errc.2025.17791。https://sol.sbc.org.br/index.php/errc/article/view/39173 。語言為葡萄牙語。
- 存在確認：已確認。取得：僅摘要（頁面只有葡萄牙語摘要，我自行翻譯重點）。
- 對應：C4、K3（延遲）。評估 Zeek 作為 GT-IoTEdu 專案的資安探針：五種攻擊、兩種 Zeek 模式（Default 與 Intel Framework）、四種硬體設定，皆以 Docker 資源限制模擬；結論是在 1 GB RAM（以 Raspberry Pi 4 為例）可行，在 <256 MB 的低記憶體路由器上不可行，Intel Framework 會增加延遲。作者自述結果依賴資源模擬，非原生 ARM 效能。[摘要]
- 資料集：綁定 GT-IoTEdu 專案、五種攻擊；具體資料集未能確認。
- 為何貼近：少數針對「規則／行為式 IDS（非 ML）在受限記憶體下可行性」的 Zeek 研究，與我們以 Suricata/Snort 為基準的立場一致；但是**模擬硬體**，數字不能當 Pi 實測。
- 優先度：**中**。原因：可作為記憶體門檻參考與方法範例，需補原生 ARM 實測才可信。

## 8. GALETTE — a Lightweight XDP Dataplane on your Raspberry Pi（角度 c、d）

- 書目：Kyle A. Simpson, Chris Williamson, Douglas J. Paul, Dimitrios P. Pezaros（Glasgow）。IFIP Networking 2023。DOI 10.23919/IFIPNetworking57963.2023.10186412。https://eprints.gla.ac.uk/296605/
- 存在確認：已確認（機構庫作者版，檔頭含出版資訊）。取得：全文（作者版，可能與出版版有差異）。
- 對應：C1、C4、K1、K3。以 XDP 快速路徑 + userland（AF_XDP）慢速路徑分流，適配 SBC；比較 XDP、AF_XDP 與 AF_PACKET 的吞吐、延遲、CPU 與功耗。[摘要] 在 RPi（IRQ 模式）上，純 XDP 資料路徑對 1518 B 封包相較 userland 最多減少 3.1 倍 CPU、省約 7.4% 功耗；對比 AF_PACKET 亦較省 CPU 與功耗。[原文 Table I/II，§VI 討論]
- 硬體與資料集：Raspberry Pi 3 Model B（4×1.2 GHz、1 GiB、Pi OS 11 AArch64、kernel 5.15.74-v8+，自行重編譯以啟用 XDP、eBPF JIT、BTF），其網卡為 USB 2.0 的 SMSC LAN9514、僅 100BASE-T，最小 USB polling 1 ms 影響封包到達時序；流量產生器為 NUC + Pktgen-DPDK；速率 0.1–100 Mbit/s、7 種封包大小，每組 10 次試驗，表中誤差為 95% CI；功耗以 USB 電表量。[原文 §V 測試環境與實驗] 無真實流量資料集，用合成流量與 Macswap NF。
- 為何貼近：**與我們平台幾乎同款（Pi 3 系列 + USB 網卡）**，並有信賴區間與功耗實測。可直接回答 D6 的疑問：Pi 的 USB NIC 下 XDP/AF_XDP 的實際行為。注意：論文內文未明說該 LAN9514 驅動採 native 還是 generic XDP 模式，**未能確認**。
- 互補性：它比的是 AF_PACKET，不是 NFQUEUE 或 Suricata；NF 只是 MAC swap，不含偵測成本。[原文]
- 優先度：**高**。原因：同平台的 XDP 實測，且是唯一同時有 CI 與功耗的 Pi XDP 論文；可作 C1/K1 成本模型的基礎。

## 9. Sapo-boi — Bypassing Linux Kernel Network Stack in the Implementation of an XDP-based NIDS（角度 d）

- 書目：Raphael Kaviak Machnicki, João Ribeiro Andreotti, Ulisses Penteado, Jorge Pires Correia, Vinicius Fulber-Garcia, André Grégio。Journal of the Brazilian Computer Society, 2026, 32(1)。DOI 10.5753/jbcs.2026.5551。https://journals-sol.sbc.org.br/index.php/jbcs/article/view/5551 。擴充自 SBSeg 2024 版。
- 存在確認：已確認。取得：全文。
- 對應：C1、K1。Suspicion Module（XDP 程式）在核心丟棄「看起來安全」的封包，可疑封包以 AF_XDP 送 user space 的 Evaluation Module，常數時間找到對應規則並告警。[摘要] 與 Snort、Suricata 及 kernel 層方案比較封包分析率與 CPU 使用率；在 Snort 載入 8000 條規則時，2 Gbps 即漏掉超過 50% 封包、8 Gbps 超過 90%。[原文 §6、Table 4]
- 硬體與資料集：伺服器級 x86（12th Gen Intel Core i7-12700、16 GB、Mellanox ConnectX-3 10 Gbps），流量用 tcpreplay 以 pcap 重播並調整頻寬。[原文 §5 實驗環境]；**非 ARM、非 IoT 閘道器**。使用的是規則子集（作者自述限制，見 §7）。
- 為何貼近：這是「kernel 內先篩、可疑才交 user space 規則比對」的第二層架構，與我們「先本地檢測、疑難再上送」的分層概念同構，而且直接和 Snort/Suricata 比。[推測] 其篩選條件（埠對等簡單條件）若能與 nftables 預過濾對應，可評估把前段放進 nftables 或 XDP 的成本差。
- 優先度：**高**。原因：直接的規則式 IDS 成本對照；缺口是無 ARM 資料，我們能補。

## 10. Adaptive Load-Aware Sampling for Network Monitoring on Multicore Commodity Hardware（角度 e）

- 書目：Lothar Braun, Cornelius Diekmann, Nils Kammenhuber, Georg Carle。IFIP Networking 2013；arXiv:1604.02322（2016 上傳）。https://arxiv.org/abs/1604.02322
- 存在確認：已確認。取得：僅摘要。
- 對應：C1、K1、K2。提出自適應取樣演算法：依目前流量與監控應用（DPI）處理能力調整取樣上限，讓 DPI 系統處理的封包數接近其容量；支援單核與多核；在 10G 實際鏈路上用真實監控工具做現場驗證。[摘要]
- 硬體與資料集：「multicore commodity hardware」、「heavily used 10G link」，具體型號與工具名稱**未能確認**。
- 為何貼近：這是「依負載動態調整監控量」的經典設計，思路可以直接套到 Pi 的 Suricata：以 NFQUEUE 佇列深度或 CPU 負載作為回饋訊號 [推測]。比較新的後繼 Sosnowski & Wiśniewski（Adaptive sampling method for network traffic, IJET 2024, DOI 10.24425/ijet.2024.152081）我只確認到書目，未讀到內容，未列入。
- 優先度：**中**。原因：年代較舊、x86 10G；但方法簡單，適合作為負載自適應的起點，需補在 ARM 上的效果。

## 11. XNET — Intelligent Dynamic Sampling for High-Speed Network Security Monitoring（角度 e、b）

- 書目：Thomas Papastergiou, Karthika Subramani, Joseph Reilly, Boladji Vinny Adjibi, Pierros-Christos Skafidas, Roberto Perdisci, Manos Antonakakis。2026-08-18，arXiv:2608.18349（cs.CR）。https://arxiv.org/abs/2608.18349
- 存在確認：已確認（arXiv 頁面）。預印本、未見同行審查。取得：僅摘要。
- 對應：C1、C2、C4、K2。用 Linux XDP 處理封包，依「安全價值」分類並依政策動態取樣，放大 APT／C2 等低速高價值流量的可見度。[摘要] 摘要數字：流量最多減少 84%、真實部署無封包遺失、低速流量可見度約 5 倍、控制測試達 100 Gbps、取樣後流量餵 IDS 的偵測率 99.6%。[摘要，條件未能確認]
- 硬體與資料集：「commodity hardware」，具體規格與資料集名稱**未能確認**；部署於「大型真實網路」[摘要]。
- 為何貼近：同時涵蓋 XDP、取樣、IDS 資料完整性（K2）；與已知清單的 eBPF/XDP 論文互補，因為它的重點是「取樣策略」而非模型。注意其規模（100 Gbps、SOC 級）與我們差很多。
- 優先度：**中**。原因：策略值得借鏡，但需先看全文確認取樣政策是否可降到 Pi 規模，且為預印本。

## 12. A-THENA — Early Intrusion Detection for IoT with Time-Aware Hybrid Encoding and Network-Specific Augmentation（角度 e、c）

- 書目：Ioannis Panopoulos 等 6 人，arXiv:2604.21623，2026-04-23；期刊註記：ACM Transactions on AI Security and Privacy（April 2026）。https://arxiv.org/abs/2604.21623
- 存在確認：已確認（arXiv 頁面）。取得：僅摘要。
- 對應：C4、K3。「早期偵測」：僅用 flow 的部分封包序列就分類，目標是輕量模型；用 Transformer + 時間感知編碼。[摘要] 在 Raspberry Pi Zero 2 W 上做即時偵測測試，頁面未給具體延遲與記憶體數字。[摘要]
- 資料集：CICIoT23-WEB、MQTT-IoT-IDS2020、IoTID20；平均準確率比最佳傳統位置編碼高 6.88 個百分點等（相對基準的比較）。[摘要] 無雲端角色。
- 硬體補充：Pi Zero 2 W 的 SoC 為 Cortex-A53，與 3B+ 同核心 [推測：頁面未載明，是我依一般知識判斷，需再核對]，但記憶體只有 512 MB [推測，同上]。
- 為何貼近：「看多少封包就能下決定」直接影響 flow 收集量與 time-to-detection，可作為動態調整監控深度的依據。與雲端卸載無關，所以是互補。
- 優先度：**中**。原因：K3 角度有價值，但無成本模型、無卸載，且 IoT 裝置端流量與閘道器聚合流量情境不同 [推測]。

---

## 搜尋中看到但未列入的（原因）

- Passban IDS（Eskandari 等，IEEE IoT-J 2020，IEEE Xplore 8976157）：已確認存在，僅見摘要與二手；摘要稱可部署於廉價閘道器、偵測 port scan、HTTP/SSH brute force、SYN flood [摘要/二手]；Pi 硬體細節未能確認，且無雲端卸載。若需「單板電腦上輕量異常偵測」基準可補讀。
- Sonata（Gupta 等，SIGCOMM 2018；arXiv:1705.01049）：已確認。把查詢切成交換器與串流處理器兩部分，並以 iterative refinement 縮小需要追蹤的流量，亦用 sketch 換取較少狀態。[摘要] 概念上類似閘道器／雲端分工，但依賴可程式交換器，不適用 Pi，所以排在 12 篇之外。
- Scholz 等 "Performance Implications of Packet Filtering with Linux eBPF"（ITC 30, 2018，TUM）：已確認、讀到摘要與前言；談 XDP 與 socket 層 eBPF 過濾的效能，環境是 10 Gbit/s 級 x86，與我們差距大。
- Tolay "eBPF-Based Real-Time DDoS Mitigation for IoT Edge Devices"（arXiv:2508.00851，單一作者預印本）：已讀全文；Pi 4 上 100 Mbps UDP flood 丟棄 >97%，CPU 負載約 85% 單核（ksoftirqd）；作者自述未與 iptables/nftables 直接比較。[原文] 偏向速率閥值式 DDoS，非 IDS，且為預印本，所以未列入。
- Yang 等 "Efficient intrusion detection toward IoT networks using cloud–edge collaboration"（Computer Networks 228, 109724, 2023, DOI 10.1016/j.comnet.2023.109724）：已確認；重點在聯邦學習降低訓練時間／記憶體 >50% [摘要]，不是推論期的流量上傳，所以未列入。
- Hosseininoorbin 等 "Exploring Edge TPU for Network Intrusion Detection in IoT"（arXiv:2103.16295）：已確認；比較 Edge TPU 與 ARM Cortex-A53 嵌入式 CPU，結論是小模型時 CPU 勝出 [摘要]；非卸載架構。
- 2018 IDAP "Snort vs Suricata on two Raspberry Pis"（Coşar & Kıran，DOI 10.1109/IDAP.2018.8620784）：僅見二手（搜尋摘要）；全文封閉、數字看不到，未列入。這是唯一找到的 Pi 上 Snort/Suricata 對比，值得有權限時查。
- 找不到：沒有找到「Pi 3B+ 上 Suricata 以 NFQUEUE/nftables 做 inline IPS」的同行審查論文或論文級實測；NFQUEUE 的資料只見郵件列表軼事（OISF 論壇），不當論文引用。也沒有找到直接量測「閘道器只上傳可疑 flow 到雲端」節省頻寬的論文。

## 觀察（≤200 字，全部 [推測]）

[推測] 邊緣 IDS 論文常用 Raspberry Pi 3/4 或 Jetson，但多半只量 ML 推論的準確率、CPU/RAM，很少量封包轉送吞吐與 K3 端到端延遲；資料集多為 BoT-IoT、UNSW-NB15、CICIDS 系列或自建，離線切分居多。XDP/eBPF 論文多用 x86 10G 網卡，在 ARM 與 USB 網卡上的實測很少（只找到 Galette）。把「Suricata/Snort 規則式本地檢測」與「雲端卸載」合在一起並量傳輸 bytes 的論文，我沒找到。flow 壓縮多半是離線評估，缺少放在閘道器上量成本的。動態粒度調整的文獻主要來自 x86 或交換器環境。

