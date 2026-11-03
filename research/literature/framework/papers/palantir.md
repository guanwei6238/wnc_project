# PALANTIR（NFV-based SecaaS 威脅緩解架構）

## A. 書目與取得狀況
- 標題：PALANTIR: An NFV-Based Security-as-a-Service Approach for Automating Threat Mitigation
- 作者：Maxime Compastié, Antonio López Martínez, Carolina Fernández, Manuel Gil Pérez, Stylianos Tsarsitalidis, George Xylouris, Izidor Mlakar, Michail Alexandros Kourtis, Valentino Šafran [原文 p.1]
- 年份／出處：2023-02-02 發表；Sensors 2023, 23(3), 1658（MDPI，CC BY 開放存取）[原文 p.1]
- DOI：10.3390/s23031658
- 全文來源：MDPI 網站對 curl／WebFetch 回 HTTP 403，未嘗試繞過；改用 UPF 機構庫的開放全文 PDF（https://repositori.upf.edu/server/api/core/bitstreams/9da523e2-2f17-4045-a937-1ca1c076e141/content），首頁有 MDPI 版權頁與「Sensors 2023, 23, 1658」抬頭，頁碼標示 N of 37，本報告頁碼依此。本機：`research/literature/framework/pdfs/palantir/palantir.pdf`（37 頁，另有 `palantir.txt`）。
- 與給定資訊的差異：無。標題、年份、期刊、卷期、文章編號、DOI 都與給定資訊一致。
- 取得程度：**全文**
- 既有報告：`research/literature/papers/` 沒有這篇，不是補讀模式。

## B. 核心貢獻（作者自述，≤3 條）
1. 一套把「威脅事件 → 選哪個安全元件 → 部署／重新設定」串起來的 SecaaS 架構：IR（Incident Response）執行 FSM 政策，SM（Service Matching）用限制式求解挑元件，SO（Security Orchestrator）透過 ETSI NFV MANO（OSM）部署 SC（Security Capability）[原文 p.3、p.8–11]。
2. 三個資料模型：7 個 class 的 ontology、以 FSM 表示並匯出成 UML 的 remediation policy、擴充 NFV-SOL006 的 SC 描述欄位（含資源需求、計費、GDPR 欄位，Table 1）[原文 p.14–21]。
3. 三種部署模型（Lightweight／Edge／Cloud）與原型實作，量化評估只有兩項：SM 的求解時間與記憶體隨模型規模的變化、SO 對 SC 的 instantiation／reinstantiation／configuration 時間 [原文 p.3、p.27–33]。

## C. 指定的 9 項
**1. Research Problem**：中小企業缺乏資安人力與預算，需要把監控與緩解外包，但外包又要避免資產暴露給外部。作者認為偵測研究很多、緩解（remediation）被低估，所以做「已偵測之後」的緩解自動化 [原文 p.1–2]。偵測不在本文範圍，本文說偵測由「external detection tool」完成並通知 IR [原文 p.9]；偵測工作引用 [58, 59]（見 D9）。

**2. Architecture**
```
protected site（Lightweight CPE / Edge / Cloud）           central layer（所有模型共用）
  SC: IDS(Snort/Suricata) DPI  DC(NetFlow/Zeek)  FW(iptables)  SIEM(Wazuh)   Portal  SCC  SM  SO
   └ 每個 SC = SEM + xNF（容器，K8s）                                         
  SEM -- Filebeat --> Kafka topic（告警／flow 資料）--> [外部偵測/分類，本文未描述]
                                       --> IR（FSM，處理層）--Kafka/REST--> SM（CSP 求解）--> SO --OSM/Juju--> SC
```
圖依 Fig. 1、Fig. 2 與 §4.2–4.6 重畫 [原文 p.8–12]。Central layer（Portal、SCC、SM、SO）所有部署共用；processing layer 在受保護端附近，放 IR、SCHI（VIM + NFVI）與 SC [原文 p.12]。

**3. Processing Location**：全部在 user space 的容器與 Java／Python 服務；SC 跑在 Kubernetes pod 內 [原文 p.11、p.26]。論文未討論 kernel、eBPF 或交換器資料平面，封包路徑只出現在「iptables SC」「Snort／Suricata SC」這類名稱，實作細節論文未說明。

**4. Hardware**：評估用兩種環境。SM：8-core Intel i7-8550U 1.8 GHz、16 GB RAM、Linux 5.15.81、JRE 11.0.17 [原文 p.27]。SO：K8s 叢集 1 control + 2 worker，worker「full」為 3 sockets × 4 cores、20 GB，「constrained」為 1 socket × 4 cores、8 GB；OSM 另一台 VM，2 CPU、8 GB、60 GB 磁碟 [原文 p.30–31, Table 4]。「constrained」對應 Lightweight CPE，作者說是約 2k EUR 等級的低階伺服器 [原文 p.31]。沒有 ARM、沒有 Pi 級裝置。

**5. Dataset**：沒有封包資料集、沒有 IoT-23／CICIoT2023。SM 實驗用人工放大的「deployment configuration 數量」（固定 40 個 SC，5–125 個 infrastructure configuration，Table 2）[原文 p.27–28]。SO 實驗只觸發生命週期操作。兩個用例（e-health、e-commerce）只有拓樸圖與 FSM 範例，沒有量測結果 [原文 p.22–23, Fig. 5–7]。

**6. Baseline**：沒有。沒有跟其他框架、手寫版本或其他求解器比；唯一的對照是 full vs constrained 資源 [原文 p.30–33]。

**7. Metrics**：SM：JVM heap 記憶體（ThreadMXBean／MemoryMXBean）、procedure 執行時間、solver 時間（Choco timeCount）[原文 p.28]。SO：三種操作的端到端時間 [原文 p.30–31]。沒有 CPU 使用率、吞吐、封包延遲、偵測準確率、傳輸量。

**8. Limitations（作者承認）**：ontology 還沒納入被保護資源的特性；SM 還沒利用被保護資源暴露的監控與設定介面；FSM 政策還沒有標準化的、對 security mechanism 的介面（目前會有 vendor lock-in 問題）；框架目前只做反應式，未做主動式威脅管理 [原文 p.33–34]。作者以拐點分析指出模型規模大時 SM 需要擴充資源或拆批處理 [原文 p.27、p.29]。

**9. Research Gap**
- 作者自述：上述 Limitations 即未來工作 [原文 p.33–34]。
- [推測]：(a) 沒有端到端「偵測→緩解」時間；(b) 沒有任何資料平面指標，不知道這套架構對轉送效能的影響；(c) 沒有異常情境（broker、SM、SO 掛掉）的驗證；(d) 沒有在真正資源受限裝置上跑。

## D5. 實驗可信度
- 流量來源：無封包流量。SM 實驗為合成的模型規模掃描，SO 與 SCC 以 JSON 檔 + HTTP server **mock**，Kafka 與 PostgreSQL 在本機 [原文 p.27]。SO 實驗是真實 K8s + OSM，但只量管理平面操作。
- 重複次數：SM 每個複雜度 50 次請求，同一個 prototype instance 內連續送，各複雜度用不同 instance [原文 p.28]。SO 每個 SC 每種操作 100 次，3 操作 × 3 SC = 每環境 900 筆，循序執行 [原文 p.31]。
- 變異量：以 boxplot（Fig. 8–13）與 mean／median（Table 3、5）呈現；沒有信賴區間、沒有顯著性檢定；沒有 warm-up 的說明（JVM 的 JIT 暖機論文未說明）。
- Ablation：沒有。ML 切分洩漏：不適用（本文無 ML）。
- 論文內部不一致（我的觀察，見 F）：configuration 時間的敘述與 Table 5 不符。
- 作者對 memory 拐點的解釋（JVM 記憶體節省機制）沒有驗證 [原文 p.29]。
- Artifact：GitHub `palantir-h2020/paper-nfv-aas-threat-mitigation` 含 `6_3_1-sc-selection/`、`6_3_2-sc-orchestration/`，README 稱為重現量化結果的資料與腳本 [二手：GitHub 頁面，https://github.com/palantir-h2020/paper-nfv-aas-threat-mitigation；目錄內容未能展開確認]。論文自己的 Data Availability 寫的是「qualitative evaluation 的資料集」[原文 p.34]，與 README 描述不一致。授權未確認。

## D6. 移植到 Pi 4 的障礙
- 依賴：Java 11 + Spring Boot / Camel / Statemachine、Quarkus、Kafka、MongoDB、PostgreSQL、Keycloak、OSM、Kubernetes、Juju、Docker [原文 p.23–27]。
- SM 單一元件 heap 約 417–654 MB（Table 3 的 mean，x86 + JVM）。OSM 單獨就配 2 CPU / 8 GB / 60 GB 磁碟 [原文 p.31]。「constrained」場景還需要兩個 8 GB worker + OSM。
- [推測]：整套不可能跑在 Pi 4 上；即使 Pi 4 的 4 核 8 GB 在數字上等於「constrained worker」，那是 VM 內的 vCPU，宿主 CPU 型號論文未說明，不是 Cortex-A72。**沒有驗證**，只是依資源需求推算。
- 可移植的是「概念」（FSM 政策、SC 描述欄位、Kafka 式事件匯流排），不是實作。
- XDP/eBPF：本文不涉及，Pi 4 無 native XDP 的限制與本文無關。

## D9. 引用網路
OpenAlex 顯示被引 11 次 [二手：https://api.openalex.org/works/doi:10.3390/s23031658]；我沒能取得 cited-by 清單，下列只來自本文 references 與搜尋。
1. IETF RFC 8329, "Framework for Interface to Network Security Functions"（I2NSF），2018-02，Informational。為什麼：本文明說考慮採用此介面 [原文 p.6]；可對照我們「雲端回應只允許 trust/block/observe」的介面設計。**已確認**（IETF datatracker）。
2. Gardikis et al., "SHIELD: A Novel NFV-based Cybersecurity Framework," IEEE NetSoft 2017，DOI 10.1109/NETSOFT.2017.8004228。為什麼：本文引為前驅 NFV 資安框架 [原文 p.4, ref 19]；同樣是偵測 + 緩解的分工。**已確認**（recercat 紀錄），我沒讀全文。
3. Sanvito et al., "syslrn: Learning What to Monitor for Efficient Anomaly Detection," EuroMLSys 2022，DOI 10.1145/3517207.3526979，arXiv 2203.15324。為什麼：PALANTIR 偵測端引用 [原文 p.21, ref 59]；搜尋結果稱其用 eBPF 只收集學到的特徵，貼近我們「只送必要欄位」。**已確認**，內容僅看搜尋摘要。
4. Bélair, Laniepce, Menaud, "SNAPPY: Programmable Kernel-Level Policies for Containers," ACM SAC 2021，DOI 10.1145/3412841.3442037。為什麼：本文引為 eBPF 執行安全政策的例子 [原文 p.6, ref 39]；摘要稱可堆疊 eBPF 政策，對應我們 G2/G7 的外掛串接與權限。**已確認**（HAL 紀錄），我沒讀全文。
5. Kompougias et al., "IoT Botnet Detection on Flow Data using Autoencoders," IEEE MeditCom 2021, pp. 506–511（本文 ref 58）。為什麼：本文偵測端的 flow 資料來源，能補本文沒寫的 flow 欄位。**未驗證**（搜尋沒找到）。

## G. 框架專屬欄位
**G1 框架的抽象**：框架定義的是「資料模型 + 元件角色」：(a) ontology 的 7 個 class：Data Type、Protection Method（Detection／Mitigation Method）、Security Capability、Threat、Billing Model、Deployment Model、Incident Response [原文 p.14, Fig. 4]；(b) SC entry 欄位 [原文 p.20–21, Table 1]，含 `detection_method`、`mitigation_method`、`control_data_type`、`monitor_data_type`、`nbCpu`、`amountRam`、`amountStg`、`deployment_model`、計費與 SLA 欄位、GDPR 欄位；(c) FSM 政策格式（Eclipse Papyrus 畫 → UML → Spring Statemachine 執行）[原文 p.15、p.24]。留給使用者／插件：SC 的內容（Docker image + Juju charm + NS/xNF descriptor）[原文 p.26]、每個客戶的 FSM 內容、偵測工具本身。Fig. 5 的兩個 FSM 都是線性序列（START→S1→…→S4／S6，只有 e-commerce 有一條回到 START 的更新箭頭），未見分支條件 [原文 Fig. 5, p.16]；所以實際表達力像 playbook，這是我對圖的觀察 [推測]。IR 收到的威脅事件格式、IR→SM 請求的 schema，論文未說明。

**G2 擴充與生命週期**：新 SC 由認證開發者上架 SCC，之後 SO 經 OSM 部署成 K8s pod（Juju model、Juju operator、主容器）；Day-0／1／2 動作由 Juju charm 執行 [原文 p.10–11、p.26]。Lightweight 模型有「最小 SC service chaining」(filter + IDS + SIEM) 且 filter SC 要當客戶端路由器 [原文 p.13]，但串接機制論文未說明。重配置時間有量：instantiation 約 47–67 s、reinstantiation 約 101–123 s、configuration 約 1.8 s（見 E）。換 SC 期間封包怎麼處理、是否原子切換：論文未說明。

**G3 分層與通道**：central layer（Portal、SCC、SM、SO）與 processing layer（IR、SCHI、SC）[原文 p.12]。通道：IR↔SM 用 message-oriented middleware（Kafka）[原文 p.10]；IR 對外 REST + Kafka，Camel 在兩者間路由 [原文 p.23]；SC→平台用 Filebeat 把 log 送到 Kafka 指定 topic [原文 p.12、p.26]；SO↔MANO 用 Or-Vi、Ve-Vnfm 等 ETSI 參考點，SC 間通訊經 SO 走 TLS [原文 p.8、p.11]。狀態：SO 各服務共用資料庫、SCC 用 MongoDB、Portal 用 PostgreSQL、使用者放 Keycloak [原文 p.24–27]；SM 快取 SCC 與 SO 的資訊並定期更新 [原文 p.24]。

**G4 外部依賴可選性**：作者說 Lightweight CPE 可獨立運作且不暴露本機資料，只對外做 CPE 狀態管理與分享攻擊資訊 [原文 p.22]；Fig. 2 把 SO、SM 放在所有模型共用的 central layer，盒內明確列出的只有 SCHI、SC、IR [原文 p.12–13]。central layer 掛掉時 fail-open／closed 或降級、broker 斷線時事件是否緩衝：論文未說明，也沒有實驗驗證。SM 找不到可行解時廣播通知人工操作員 [原文 p.10]。

**G5 價值如何證明**：照論文實際做的：(a) 實作敘述（§6.2，逐元件列技術堆疊，主張標準相容與可擴充）；(b) 兩個用例的 FSM 範例；(c) 兩組量化實驗（SM 規模掃描、SO 生命週期）。**沒有**：overhead 比較、與其他框架比較、LoC 或開發時間、可擴充性案例數（只示範 4 類 SC：IDS/DPI、FW、DC、SIEM [原文 p.26]）、端到端緩解時間、資料平面指標。

**G6 效能量測方法**（可重做程度）：
- SM：i7-8550U／16 GB／Linux 5.15.81／JRE 11.0.17；SO、SCC 以 JSON 檔經 HTTP server 模擬；Kafka 2.7.1、PostgreSQL 14.6 本機；固定 40 個 SC，infrastructure configuration 從 5 到 125（步長 10），deployment configuration = 40 × 數量；每個複雜度 50 次，同一 instance 連續送、不同複雜度用不同 instance；用 ThreadMXBean／MemoryMXBean 取 CPU 與記憶體，Choco 的 timeCount 取求解時間；Choco 用預設搜尋策略 [原文 p.24、p.27–28]。
- SO：K8s 1+2 節點（Table 4）、OSM 另一台 VM；Python 腳本循序觸發三種操作，各 SC 各 100 次；時間戳取得方式、warm-up、鏡像是否已預載（會影響 instantiation 時間）論文未說明 [原文 p.30–31]。
- 未依循 RFC 2544／9411 或其他標準；沒有流量產生器（無封包）。

**G7 安全模型**：SC 套件由「認證的 SC 開發者」註冊，SCC 以可信方式存放 metadata 與 integrity indicators [原文 p.10]；SCC REST API 用 JWT 做角色過濾 [原文 p.24]；SC 之間經 SO 走 TLS [原文 p.8]；Portal 用 Keycloak [原文 p.27]；TAR 元件監控 SCHI 與 SC，可用 TPM [原文 p.8、p.11]。integrity indicators 如何驗證、框架本身的威脅模型（SO 被入侵會怎樣）論文未說明。

**G8 與我們設計對照（逐元件）**
| 我們的元件 | PALANTIR 對應 | 差異 |
|---|---|---|
| Suricata EVE（偵測） | Snort／Suricata SC，log 經 Filebeat 送 Kafka [p.26] | 它們跑在容器 VNF；我們是同機 process + NFQUEUE |
| flow 特徵 | DC SC：iptables+NetFlow、Zeek，`monitor_data_type` 如 pcap [p.21, p.26] | 整包 flow／log 送出，論文未提欄位選擇或壓縮 |
| agent | SEM（log 與狀態出口、Juju 控制入口）[p.11–12] | 角色相近；SEM 含生命週期管理，我們的 agent 只做資料與判定 |
| 雲端 | central layer（SM、SO、SCC、Portal）；偵測／分類另有元件，本文未描述 | 它的雲端負責「挑元件、部署」，我們的雲端負責「判定」 |
| 判定 | IR 的 FSM 在 processing layer 本地執行 [p.9, p.15] | 它的決策在本地、動作集合開放；我們是雲端回 trust/block/observe |
| 改 nft set／ct mark | iptables SC 經 Juju Day-2 action 設定，整條鏈約 1.8 s [p.33, Table 5] | 它們沒有 flow 級信任標記；兩者層級不同，不能直接比數字 |

- **這篇做過、我們不能宣稱是新的**：偵測→決策→執行的政策驅動閉環與元件拆分 [p.8–10, p.15]；以描述欄位宣告元件的資料型別與資源需求 [Table 1]；本地優先、CPE 可獨立運作 [p.22]；Suricata／Snort + iptables + NetFlow／Zeek 的組合 [p.26]；元件必須冪等（idempotence）的要求 [p.7]；元件套件由認證開發者上架並附 integrity 資訊 [p.10]。
- **這篇做了、我們沒有，值得考慮 [推測]**：(1) 冪等性要求，可套到雲端重送或重複判定寫入 nft set；(2) 外掛宣告資源預算（nbCpu、amountRam）並在上線前檢查，可用於 Pi 上的 eBPF 外掛與規則集；(3) 對多步緩解用有限狀態表示（observe→block→到期），目前我們的回應只有三個動詞；(4) 找不到可行解時明確通知人工；(5) 資料外送的隱私描述欄位（`sharing_descr` 等）可對應我們「送雲端欄位由設定描述」的揭露。
- **我們有、這篇沒有 [推測，不誇大]**：量測過的封包路徑成本（µs 級）；雲端不在封包路徑上、`when_unavailable` 的降級行為已設計；回應詞彙封閉，雲端不能下發可執行物；Pi 級硬體的數字；ct mark 級的 flow 信任。
- **不同取捨（論文有說明理由的）**：它們用「部署或重配容器」實施緩解，理由是 SecaaS 外包、多租戶與計費需求 [p.1–3]；central SO 可直接在被保護基礎設施上執行安全動作（例如隔離叢集）[p.11]，這與我們「雲端不能下發可執行的東西」相反。成本模型它們用金錢（授權、instantiation、每小時，公式 8–9）[p.19]，我們用 CPU／頻寬。

**G9 對碩士論文的用途**
1. 相關工作：可引為「政策驅動、元件化的 SecaaS 緩解框架」的前例，說明我們與它的差別在於資料平面成本與封閉的回應詞彙 [p.8–10, p.15]。
2. 論點「框架論文常只量管理平面」：本文量 SM 求解與 SO 生命週期，沒有封包路徑指標 [p.27–33]；我們的論文補這一塊。
3. 借用設計原則：冪等性（idempotence）作為規則寫入的要求 [p.7]。
4. 借用實驗設計：對決策元件做「規模掃描 + 每點多次 + 記憶體／CPU 時間／求解時間」並找拐點 [p.28–30]；但要補 warm-up 與信賴區間。
5. 引用 Table 1 的欄位分類（方法、資料型別、資源、部署模型）作為外掛描述的對照。

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| SM procedure 時間 | mean 0.0311 s／median 0.0235 s（5 infra, 200 configs） | i7-8550U，50 次，SO／SCC 為 mock | Table 3, p.30 |
| 同上 | 0.9759／0.9499 s（55 infra, 2200 configs）；3.4581／3.3699 s（65 infra, 2600）；19.5654／18.5535 s（125 infra, 5000） | 同上 | Table 3, p.30 |
| SM solver 時間 | 0.019／0.016 s（5）→ 19.238／18.066 s（125） | 同上 | Table 3, p.30 |
| 時間斜率 | 55 以下每增 1 個 infra configuration +18.2 ms；75–125 為 +279.9 ms | 同上 | p.29 |
| SM heap | 416.9 MB（5）、419.5 MB（55）、600.7 MB（65）、549.5 MB（125）（mean） | 同上；JVM | Table 3, p.30 |
| instantiation（mean/median） | full：iptnetflow 47.798/47.403 s、snort 65.609/65.419 s、suricata 63.811/63.361 s | K8s 1+2 節點，100 次 | Table 5, p.33 |
| 同上 | constrained：50.125/49.517、66.748/66.342、66.587/65.695 s | 同上 | Table 5, p.33 |
| reinstantiation | full：101.576/100.747、120.043/119.478、118.564/117.843 s；constrained：104.049/103.054、123.275/121.932、121.451/119.651 s | 同上 | Table 5, p.33 |
| configuration | 約 1.79–1.82 s（full 與 constrained，三個 SC） | 同上；配置內容論文未說明 | Table 5, p.33 |
| constrained 相對 full | 作者稱 instantiation 中位數最多 +4.2%、reinstantiation 最多 +2.2% | 同上 | p.31–32 |
| 被引次數 | 11 | OpenAlex | [二手] |

## F. 自評
**未能確認**：(1) GitHub 內容與授權（頁面未展開目錄）；(2) 本文偵測元件實際吃哪些 flow 欄位（本文未寫，需讀 ref 58）；(3) cited-by 清單；(4) D9 第 5 篇存在與否。

**論文內部不一致（我的計算，不是作者承認）**：
- p.32 說 configuration 在 constrained 環境「平均而言一樣或更久」，但 Table 5 中三個 SC 的 constrained mean 與 median 都略低於 full（例如聚合 mean 1.795 vs 1.811 s）。
- p.31 說 instantiation 中位數最多 +4.2%，我用 Table 5 算 iptnetflow 為 +4.5%（49.517／47.403）。
- Data Availability 寫 qualitative，GitHub README 寫 quantitative。

**最不確定的三件事**：
1. G4：Lightweight 盒內是否含 SO／SM 靠 Fig. 2 與 p.13 的字面解讀，論文沒明說 central layer 斷線時的行為；我寫「未說明」，但作者可能在別的出處（project deliverable）有交代。
2. G8 中「我們有、他們沒有」的部分基於我對本專案設計的理解與本文沒寫，不代表他們的實際系統沒有。
3. D6 的「不可能跑在 Pi 4」是依資源需求推算，沒有實測；且 OSM、Kafka 等元件在 Lightweight 實際是否精簡部署，論文未說明。
