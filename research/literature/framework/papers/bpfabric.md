# BPFabric

標記說明：`[原文 p.N]` 的 p.N 是 PDF 頁碼（Enlighten 封面頁為 p.1，論文本文第 1 頁 = PDF p.2；accepted version 沒有印頁碼）。
`[repo 檔:行]` 是作者 Simon Jouet 的原始碼，**不是論文**：原 repo（論文頁註 p.7 的 github.com/UofG-netlab/BPFabric）在 2026-10-27 回 404，
我讀的是第三方複本 simpsonst/BPFabric（commit 作者為 Simon Jouet，最後 commit 2017-02-17，早於 ANCS 2017 定稿）。
視同 `[二手]`，只用來補論文沒寫的實作細節，**我沒有編譯或執行過**，所有 repo 結論都是讀程式碼的推論。

## A. 書目與取得狀況
- 標題：BPFabric: Data Plane Programmability for Software Defined Networks
- 作者：Simon Jouet, Dimitrios P. Pezaros（University of Glasgow, School of Computing Science）
- 年份／出處：2017，ACM/IEEE ANCS 2017（Beijing, 18–19 May 2017），pp. 38–48
- DOI：10.1109/ANCS.2017.14；全文：https://eprints.gla.ac.uk/138952/13/138952.pdf（accepted version，12 頁含封面，977 kB）
- 與給定資訊的差異：無。標題、年份、會議、DOI、機構庫連結都吻合。
- 取得程度：**全文**（accepted version；封面註明「與出版版本可能有差異」[原文 p.1]，IEEE 出版版我沒有讀）。
- PDF：`research/literature/framework/pdfs/bpfabric/bpfabric.pdf`

## B. 核心貢獻
1. 提出 controller 以「eBPF ELF」為單位，在執行時把資料平面行為部署到 switch 的架構：switch 本身沒有預設行為，行為完全由部署的 eBPF pipeline 或 controller 請求決定 [原文 p.3, p.5]。
2. 定義一組 protobuf 南向 API（10 種訊息，TCP 傳輸）：install ELF、列出／讀／寫／刪 table、packet in/out、資料平面主動 notify [原文 Table 2, p.7]。
3. 兩套實作（Linux raw socket、Intel DPDK）共用同一個 control-plane agent，並以 5 個範例程式（L2 switch、telemetry、EWMA 異常偵測）展示表達力；DPDK 版在 L2 learning switch 上吞吐量超過 OVS [原文 p.7–8, Fig.6a, Table 3]。

## C. 指定的 9 項
1. **Research Problem**：OpenFlow 只能改有限的 match field 與 action，無法表達新協定、telemetry、middlebox 類功能 [原文 p.2]。目標是讓 controller 能定義並動態換掉每台 switch 的封包處理邏輯，同時讀寫其內部狀態。
2. **Architecture**：
   ```
   Controller (Python/Twisted, 當 TCP server)  <--protobuf/TCP-->  Agent (switch 內; 當 client)
                                                                    ├ eBPF ELF Loader (配置 table、JIT)
                                                                    └ Tables (hash / array)
   Port RX → 前置 metadata → RX queue(RR) → eBPF engine(s) → TX queue → Port   [原文 Fig.3, p.5]
   ```
   Packet、flow、edge、cloud 的分工不適用（沒有 flow 概念）；等價分工是 controller（全域視野與決策）／switch（逐封包執行 eBPF）。資料平面程式可回傳 CONTROLLER 把決策交回 controller，或用 notify 非同步通知，不影響封包轉送 [原文 p.6]。
3. **Processing Location**：eBPF 在**使用者空間**由 ubpf JIT 執行（原作只支援 x86_64），不經 Linux kernel 的 eBPF 子系統 [原文 p.8]；封包收發用 raw socket（mmap ring）或 DPDK poll-mode driver [原文 p.7]。Controller 在遠端／同機 user space。
4. **Hardware**：效能實驗跑在「high-end modern commodity machine」，Linux 4.4、Intel X710 4x10G NIC [原文 p.8]；CPU 型號、核心數、記憶體論文未說明。NetFPGA 硬體版「進行中」，沒有結果 [原文 p.7]。
5. **Dataset**：沒有資料集。Telemetry／EWMA 示範使用的流量來源論文未說明；Fig.10 的異常是人為注入的 link failure（t=600 s）[原文 p.11]。
6. **Baseline**：P4 behavioural model v1/v2（bmv1、bmv2）、Open vSwitch 的預設 learning 行為，只比 L2 learning switch [原文 p.8, Fig.6a]。是否同硬體同流量重跑：論文寫「these experiments have all been run on」同一台機器，但沒有說流量產生器或設定。
7. **Metrics**：吞吐量（Gbit/s）對封包大小（64、128、256、512、1024、1100、1200、1500 B，從 Fig.6 軸讀得）[原文 Fig.6]；程式複雜度（LoC、eBPF 指令數、table 數、lookup／update 次數、state bytes）[原文 Table 3]。**沒有**延遲、CPU、記憶體、重配置時間、重複次數。
8. **Limitations（作者承認）**：user-space switch 受 networking stack 開銷限制，跟不上 production 網路線速 [原文 p.7]；P4 bmv 沒有針對速度最佳化 [原文 p.8]；table 操作是軟體實作中最貴的 [原文 p.8]；要求有界執行，無界或長迴圈要禁止、無浮點數運算 [原文 p.11]；verifier「out-of-scope」[原文 p.6]；packet scheduling 與 buffer 管理「implementation independent」未探討 [原文 p.6]。
9. **Research Gap**：
   - 作者自述：硬體實作（NetFPGA/Verilog）進行中 [原文 p.7]；P4→eBPF 編譯器只是可能方向 [原文 p.5]；verifier 未做 [原文 p.6]。
   - [推測]：沒有安全模型（見 G7）；沒有重配置語意與量測（G2）；沒有 controller 斷線行為（G4）；效能只有單機吞吐量，沒有延遲／CPU／重複實驗（G6）。

## D5. 實驗可信度
- 流量來源（重播／即時／合成）、產生器、速率、測試時間：論文未說明。
- 重複次數、變異量、信賴區間：沒有。Ablation：沒有（Fig.6b 的 `wire.o` 可算一個「無處理」對照，見 G5）。
- 無 ML，無訓練／測試切分問題。
- 程式碼：論文承諾開源 [原文 p.7 頁註]，但原 repo 目前 404（查 2026-10-27），只剩第三方複本。論文沒有給 commit 或版本，不易重現。
- Fig.6 的數字只能從圖上讀，沒有表格或原始數據。

## D6. 移植到 Pi 4 的障礙
- 資料平面 JIT 只支援 x86_64 [原文 p.8]；Pi 4 是 ARM64，需用 ubpf 的 interpreter 或自己寫後端。repo 的 ubpf 有 interpreter（`ubpf_vm.c`），但 softswitch 只呼叫 JIT 函式指標 [repo softswitch/main.c:443]，所以要改程式 [推測]。Interpreter 的速度沒有任何數據。
- DPDK 版「只支援有限的實體 NIC」[原文 p.7]。bcmgenet 與 USB 網卡有沒有 DPDK PMD：**我沒有查**，[推測] 沒有。
- raw socket 版只需要 Linux AF_PACKET，原則上能在 Pi 4 兩個 port 上跑 [推測，未驗證]；單執行緒 [原文 p.7]，在高階 x86 上 64 B 約 0.5 Gbit/s（讀圖，Fig.6a），Pi 4 只會更低 [推測]。
- BPFabric **完全不用 kernel eBPF**，所以 Pi OS 沒有 BTF、沒有 native XDP 都不影響它；代價是封包離開 kernel 的 netfilter 路徑，由 BPFabric 行程自己轉送，跟 nftables／conntrack／NFQUEUE 如何共存論文未說明。
- Python 控制器（Twisted、protobuf）本身可在 Pi 上跑 [推測]。

## G. 框架專屬欄位
**G1 抽象**：框架只定義：(a) eBPF ELF 為部署單位，ELF 內含指令與每個 table 的 metadata（id、type、key size、value size、max entries），由裝置端 loader 配置 [原文 p.5]；(b) 每個封包前置 metadata（input port、timestamp sec/nsec、length）[原文 Fig.4, p.6]；(c) 回傳值即轉送決策，三個保留值 FLOOD 0xFFFFFFFD／CONTROLLER 0xFFFFFFFE／DROP 0xFFFFFFFF，其餘數字是 port [原文 Table 1]；(d) 南向 API [原文 Table 2]。留給使用者：解析、match 邏輯、狀態、何時 notify、controller 應用。HLL 是受限 C，用 LLVM 的 ebpf backend 編譯；P4→eBPF 只是可能 [原文 p.5]。Table 型別論文只提 hash 與 array，Fig.3 的 TCAM、LPM 是虛線框。Helper 函式在論文只提 table 操作與 notify；helper ID 與 bpf_debug 只見於 repo [repo agent.c:511-515]。

**G2 擴充與生命週期**：
- 載入：controller 送 Install（C→S，帶 ELF）；agent 轉成裝置適用格式、配置 table、JIT [原文 p.3, p.5]。Controller 不必先知道裝置型號，可分發預編譯的 ELF [原文 p.5]。
- 替換：論文說 pipeline「連同 table 整個重構」，而不是只更新表項 [原文 p.3]。**論文沒說**是否原子、替換中的封包怎麼處理、中斷多久，也沒有量測。
- Chaining／停用：論文沒有。Table 3 註記「* 含 self-learning switch 邏輯」[原文 Table 3]，我解讀為功能組合靠原始碼層級併成同一個程式 [推測]。
- repo 觀察（讀碼）：每台 switch 只有一個全域 vm 與一個函式指標；install 在 agent 執行緒裡載入 ELF、JIT，再直接寫入 `*(agent.ubpf_fn) = ebpfprog`，沒有 lock 或 quiesce，也沒有回 InstallReply（程式內有 TODO）[repo agent.c:82-113]。我找不到任何 mutex。
- repo 與論文不一致處：(1) JIT 失敗時 NULL 也會被寫入，資料平面看到 NULL 就**不轉送**（封包被丟掉）[repo softswitch/main.c:443]；(2) `ubpf_compile` 在 `vm->jitted` 已存在時直接回傳舊的 JIT 碼 [repo ubpf_jit_x86_64.c:528]，所以第二次 install 看起來不會真的換程式（我沒跑過）；(3) 同名 table 會被沿用而不是重建，且不檢查 key/value size 是否相符 [repo ubpf_loader.c:190-192]，與論文「table 一併重構」的說法不同。

**G3 分層與通道**：
- Controller：全域視野、決策、應用（EWMA、traffic histogram 等）；核心 < 200 行 Python [原文 p.8]。
- Agent（switch 控制面）：握手（版本、功能、datapath id）、loader、table 讀寫 [原文 p.6]。Controller 是 TCP server，switch 是 client [原文 p.7]。
- 資料平面：raw socket 版單執行緒，同一執行緒完成收、處理、送，用 mmap 與 kernel 共享 ring；DPDK 版每核心一個 eBPF engine、hugepage ring [原文 p.7]。
- 狀態在 switch 內的 table；controller 可 pull（Table List）或由資料平面 push（notify）[原文 p.10]。Packet In 帶觸發的封包與 metadata [原文 p.6]。
- 通道：TCP + protobuf，訊息頭 64 bits（opcode、payload 長度）[原文 Fig.5, p.7]；實作上是 10 bytes（protobuf 編碼）[repo agent.c:541-543]。

**G4 外部依賴可選性**：論文**未說明** controller 斷線時的行為，也沒有實驗。論文只說 switch「dumb」、沒有內建邏輯，行為由已部署的 pipeline 或 controller 請求決定 [原文 p.5]。repo 讀碼：斷線後 agent 關 socket、每 5 秒重連 [repo agent.c:564-569]；資料平面繼續用**最後裝入的函式指標**處理封包，packet in／notify 往已關閉的 socket 送（`MSG_NOSIGNAL`，錯誤被忽略），事件就此遺失、沒有緩衝 [repo agent.c:447, 482]。從沒裝過程式時所有封包不轉送 [repo softswitch/main.c:443]。依賴 controller 解析的功能（Fig.8a 的 centralized learning switch）在 controller 掉線時查不到 destination，只能靠資料平面程式自己的預設 [推測]。

**G5 價值證明**（照論文實際做的寫）：
- Overhead：**沒有**對手寫 C 或 kernel 原生轉送的比較。唯一比較是 L2 learning switch 對 bmv1／bmv2／OVS。Fig.6b 有 `wire.o`（只轉送、無 table）可當「框架本身成本」基準：DPDK 版在所有封包大小都約 10 Gbit/s，raw 版 64 B 約 1 Gbit/s [原文 Fig.6b，讀圖約值]。
- 可擴充性：5 個程式（Table 3）＋ controller 應用，沒有第三方使用者案例。
- 開發成本：程式 10–37 行 C、25–99 條 eBPF 指令；controller 核心 < 200 行 [原文 Table 3, p.8]。沒有開發時間，沒有維護性討論。
- 沒有：延遲、CPU、記憶體、重配置時間、更新 table 的吞吐量。

**G6 效能量測方法**（能重做的程度很低）：
- 已知：單台機器，Linux 4.4，Intel X710 4x10G；封包大小 64–1500 B 共 8 點；指標為 Gbit/s；DPDK 為每核心一個 engine；`wire` 是「兩個 port 之間單純轉送」[原文 p.8, Fig.6]。
- 論文**未說明**：流量產生器、拓樸（幾個 port、單向或雙向、port 對應）、CPU 型號與核心數、DPDK 用幾核心、throughput 是否算 L1 overhead、是否有丟包容忍（zero-loss／RFC 2544 式 binary search）、測試時間、warm-up、重複次數、CI、時間戳方式。沒有引用 RFC 2544 或 RFC 9411。
- 結果：bmv1／bmv2 從不超過 200 Mbit/s；DPDK 版在 512 B 達到 10G；raw 版隨封包大小大致線性成長；沒有 table lookup 的程式連最小封包都達線速 [原文 p.8]。

**G7 安全模型**：
- 誰能推程式：**controller 透過 Install 訊息推可執行的 eBPF ELF**，agent 收到就載入。論文沒有授權、身分驗證、TLS、簽章或完整性檢查（全文搜尋無這些詞）。它只說 in-band／out-of-band 由使用者依「可靠性與安全等級」選擇 [原文 p.6]。
- 驗證：論文說 loader「應該」含 verifier，檢查終止、記憶體存取、無迴圈、最大執行深度，能防止惡意或錯誤的函式，但 verifier 是「out-of-scope」[原文 p.4–6]。repo 載入時只有 `validate()`（opcode、跳躍範圍、call 目標）；我在其中只看到擋 offset == -1 的自跳，沒看到禁止其他向後跳的檢查，與論文「forward-only」的設計要求不同 [repo ubpf_vm.c:530, 646]。interpreter 有執行期邊界檢查，註解寫「Needed since we don't have a verifier yet」[repo ubpf_vm.c:375-377]；JIT 檔（ubpf_jit_x86_64.c）我搜尋 bounds 沒有找到對應檢查（只做字串搜尋，未逐行確認）。
- 隔離：ELF 在 switch 的使用者空間行程內執行（該行程需要 raw socket／DPDK，通常需要特權 [推測]），沒有行程隔離。Agent 直連 `inet_pton` 的 IPv4 位址與埠 [repo agent.c:494-505]。
- 威脅模型：論文沒有。相關工作只提 active network 因效能與安全疑慮未普及 [原文 p.11]。
- **與我們的設計正好相反**：我們規定雲端不能下發可執行的東西、插件只能本機管理者安裝且驗簽章。BPFabric 的核心賣點（遠端集中程式化）就是我們排除的那條路，而且它在論文與（我讀到的）程式碼裡沒有任何機制防止偽造的 controller 或被入侵的 controller 推惡意程式。

**G8 與我們設計對照**：
- 這篇已做過、我們不能宣稱是新的：
  - 「框架不定義功能，資料平面行為由使用者的 eBPF 程式決定，框架只定 loader、metadata 與 API」[原文 p.3–5]。
  - 程式宣告自己的 table（型別、key/value 大小、上限），由裝置端配置 [原文 p.5]。
  - 外部以通用 API 列出／讀／寫／刪 table，資料平面用 notify 主動通知，payload 由使用者定義 [原文 Table 2, p.6]。
  - Edge 端主動連外（agent 是 TCP client）[原文 p.7]。
- 這篇做了、我們沒有，值得考慮 [推測]：
  - 通用 table 查詢 API（Table 2）：doctor 目前只列「每個 port 掛了哪些程式」，可以延伸成列出每個外掛宣告的 map 與大小。
  - 握手帶版本與功能協商 [原文 p.6]。
  - 「`wire` 空程式」基準：用來分離框架成本與功能成本 [原文 Fig.6b]。
  - Table 3 式的複雜度表，作為開發成本證據。
- 我們有、這篇沒有 [推測，不誇大]：簽章驗證與「雲端只回 trust/block/observe」的受限回應；kernel verifier（它用自己的 ubpf，verifier 是 out-of-scope）；與 nftables／conntrack／Suricata 的整合；ARM 低資源硬體的實測（我們有 per-packet µs 數據，它只有 Gbit/s 且硬體是 x86 高階機）；失敗事件記錄與降級政策（它對斷線沒有說明）。
- 不同取捨，論文裡要說明理由：
  1. controller 推可執行碼 vs. 本機管理者簽章安裝。
  2. 使用者空間執行 eBPF（ubpf + raw socket／DPDK，封包離開 kernel stack）vs. kernel eBPF 掛 tc，後面接 nftables／NFQUEUE。
  3. 「dumb switch、決策交給 controller」vs. 本地優先、雲端非同步且不在封包路徑上。
  4. 替換語意：它整個 pipeline 重構且沒有量測；我們若要宣稱「不中斷替換」，必須自己量（沒有可借的數據）。

**G9 對碩士論文的用途**（≤5）：
1. Related work：證明「由使用者 eBPF 程式決定行為、框架只提供 loader 與通用 map／notify API」在 2017 年就有前例，因此貢獻要放在別處（與 Suricata／nftables 整合、Pi 4 實測、安全約束）[原文 p.3–6]。
2. 安全論點的對照組：它是「遠端推可執行碼」的設計點，而論文自己把 verifier 留作 out-of-scope [原文 p.6]；可支撐「雲端只回判決」的理由。建議搭配 D9 的 Rose et al. 2025。
3. 評估設計：有／無 table lookup 的多個程式 × 8 種封包大小 × `wire` 基準，可拆出框架成本與 table 成本 [原文 Fig.6b]。但它沒有 CI、延遲、CPU，我們補上這些就是差異。
4. 開發成本指標：Table 3 的欄位（LoC、指令數、table 數、lookup／update 次數、state 大小公式）可直接用於我們的外掛案例 [原文 Table 3]。
5. 反面教材：整篇沒有重配置時間、斷線行為、延遲，說明這些是同類框架論文常缺的量測。

## D9. 引用網路
查詢方式：OpenAlex（`cites:W2612997776`，2026-10-27 查到 43 筆引用，OpenAlex 顯示被引 45 次）。以下只讀了 OpenAlex 的書目與摘要，**未讀全文**，DOI 字串來自 OpenAlex。
1. Rose, Cook, Holík, Pezaros, "We're eBPF'd: Exploring Adversarial Manipulation of ELF Files in eBPF-Based Programmable Network Stacks", IEEE CNS 2025, DOI 10.1109/CNS66487.2025.11194984。原因：直接談 BPFabric 這類「推 ELF 到資料平面」缺乏完整性檢查的攻擊（摘要：四種攻擊、DoS 使封包數增加 100%）；G7 最需要的後續。是否以 BPFabric 為實驗平台，摘要沒說。確認程度：OpenAlex 紀錄，未讀全文。
2. Holík, Cook, Shah, Pezaros, "Network-Wide Service Deployment Using Centrally Orchestrated, eBPF-Based Programmable Dataplanes", EuCNC/6G Summit 2025, DOI 10.1109/EuCNC/6GSummit63408.2025.11036869。原因：同組後續，集中編排 eBPF 函式；可看他們是否補了部署流程與失效處理。確認程度：OpenAlex 紀錄，未讀全文。
3. Santoyo-González, Cervelló-Pastor, Pezaros, "High-performance, platform-independent DDoS detection for IoT ecosystems", IEEE LCN 2019, DOI 10.1109/LCN44214.2019.8990862。原因：同題更貼近我們，把 BPFabric 當 IoT 邊緣偵測器（摘要：偵測延遲 < 5 ms、準確率 93–95%、頻寬開銷 < 1%）。確認程度：OpenAlex 紀錄，未讀全文。
4. Simon, Stubbe, Gallenmüller, Carle, "Honey for the Ice Bear – Dynamic eBPF in P4", 2024（ACM），DOI 10.1145/3672197.3673436。原因：專談在更新時避免服務降級，直接補 BPFabric 缺的 G2。確認程度：OpenAlex 紀錄，未讀全文。
5. Nguyen Van Tu, Yoo, Hong, "Accelerating Virtual Network Functions With Fast-Slow Path Architecture Using eXpress Data Path", IEEE TNSM 2020, DOI 10.1109/TNSM.2020.3000255。原因：快路徑（XDP）加慢路徑（user space）的架構，和我們的 fast path 規劃同方向。確認程度：OpenAlex 紀錄，未讀全文。

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| bmv1／bmv2 吞吐量 | 不超過 200 Mbit/s | L2 learning switch，x86 + X710 | [原文 p.8, Fig.6a] |
| DPDK 版達線速 | 10 Gbit/s @ 512 B | 同上 | [原文 p.8] |
| DPDK 版 64／128／256 B | 約 2.0／3.6／6.7 Gbit/s | learning switch，讀圖 | [原文 Fig.6a，約值] |
| OVS 64／128／256／512 B | 約 1.2／2.2／4.1／7.9 Gbit/s，1024 B 起 10 | 同上 | [原文 Fig.6a，約值] |
| raw socket 64／512／1024／1500 B | 約 0.5／3.7／6.7／9.5 Gbit/s | 同上，單執行緒 | [原文 Fig.6a，約值] |
| wire.o（無 table）DPDK／raw 64 B | 約 10／1 Gbit/s | 兩 port 單純轉送 | [原文 Fig.6b，約值] |
| 有 table 的程式 DPDK 64 B | 約 2 Gbit/s | learning、interarrival、ewma 差異很小 | [原文 Fig.6b，約值] |
| 範例程式 LoC | 10–37 行 C | Table 3 五個程式 | [原文 Table 3] |
| eBPF 指令數 | 25–99 條 | 其中 44／98／99 含 learning switch 邏輯 | [原文 Table 3] |
| 訊息頭大小 | 64 bits（論文）／10 bytes（repo 實際） | protobuf | [原文 Fig.5] / [repo agent.c:541-543] |
| Controller 核心 | < 200 行 Python | Twisted + protobuf | [原文 p.8] |
| EWMA 檢查間隔／α | 5 s／0.125（2^-3，用位移實現） | per-port array map | [原文 p.11] |
| interarrival 上報 | 每 2048 個封包 push 一次 | 兩個 table | [原文 p.10] |
| agent 重連間隔 | 5 s | 斷線後 | [repo agent.c:569] |
| table 名稱長度／table 數上限 | 32 字元／64 個 | meta table 與 bpf_maps 陣列 | [repo ubpf_vm.c:55, bpfmap/bpfmap.c:8] |
| 重配置時間、延遲、CPU、記憶體 | 未量測 | | 論文未說明 |

## F. 自評
- 「未能確認」：controller 斷線行為（論文與實驗都沒寫，只有 repo 讀碼）；重配置語意與時間；流量產生器與測試細節；DPDK 對 bcmgenet／USB NIC 的支援（我沒查）。
- `research/literature/papers/` 沒有這篇的舊報告，也沒有其他報告提到 BPFabric（用檔名與 grep 查過），因此沒有「既有報告錯誤」要列。
- 最不確定的三件事：
  1. **repo 結論的可靠度**：來自第三方複本、2017-02 的 commit，不一定等於論文定稿或出版版，我只讀沒跑。特別是「第二次 install 不會真的換掉 JIT 碼」（`vm->jitted` 快取）與「無 lock」，需要實際執行才能確認；寫進論文前不要當事實引用。
  2. **Fig.6 數字**是我從圖上讀的近似值（±0.2 Gbit/s 左右），不是論文給的數字；引用時請改用文字敘述的那幾句（bmv ≤ 200 Mbit/s、DPDK 512 B 達 10G）。
  3. **D9 五篇的內容**只看過 OpenAlex 摘要，尤其 Rose et al. 2025 是否以 BPFabric 為平台、結論是否適用於 BPFabric，我沒有證據。
