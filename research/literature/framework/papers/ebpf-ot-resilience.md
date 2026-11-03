# ebpf-ot-resilience：An eBPF-Based Programmable Network Architecture for OT Digital Resilience Use-Cases

頁碼說明：`p.N` 指我讀的 accepted manuscript PDF 的第 N 頁（共 7 頁，第 7 頁是機構庫的授權封面）。IEEE 正式版頁碼與內容可能不同（p.7 自述 "There may be differences between this version and the published version"）。圖中數值若寫「目測」，是我從圖上讀的近似值，論文本文沒有給數字。

## A. 書目與取得狀況

- 標題：An eBPF-Based Programmable Network Architecture for OT Digital Resilience Use-Cases
- 作者：Filip Holik, Simon Jouet, Dimitrios Pezaros（University of Glasgow, School of Computing Science）[原文 p.1]
- 出處：30th IEEE Symposium on Computers and Communications (ISCC 2025), Bologna, Italy, 2–5 July 2025；ISBN 9798331524203 [原文 p.7]
- DOI：10.1109/ISCC65549.2025.11325939 [原文 p.7]
- URL（全文）：https://eprints.gla.ac.uk/354500/2/354500.pdf（accepted manuscript，自述 CC BY 4.0 [原文 p.7]）；本地副本在 `research/literature/framework/pdfs/ebpf-ot-resilience/paper.pdf`
- 與給定資訊的差異：
  - 給定的標題、會議、DOI 都正確，沒有差異。
  - 年份：機構庫記為 2026（IEEE Xplore 上線 2026-01-13）[二手 https://eprints.gla.ac.uk/354500/]；OpenAlex 記為 2025-07-02 [二手 https://api.openalex.org/works/doi:10.1109/ISCC65549.2025.11325939]。會議本身是 2025 年 7 月。引用時應寫 ISCC 2025。
  - 版本標示：論文自己寫「author accepted manuscript」（p.7）；OpenAlex 寫成 submitted 版、CC BY-SA，兩者不一致，我以論文 p.7 為準。
- 取得程度：**全文**（accepted manuscript；沒有讀 IEEE 正式版）

## B. 核心貢獻

1. 把 BPFabric（Jouet & Pezaros, ANCS 2017）擴充成三層 SDN 架構：新增 **eBPF execution engine pipeline**（用 `NEXT` action 串接任意數量的 eBPF function）、controller 的 **service broker**、REST **northbound API**、以及應用/服務層 [原文 p.2–3]。
2. 資料平面有兩種實作：給開發與 Mininet 用的 software switch，以及給最高效能用的 DPDK switch [原文 p.2]。
3. 在 Mininet 模擬的變電站網路上，用四個 OT resilience 服務（network segmentation、asset discovery、network monitoring、DoS mitigation）做功能驗證 [原文 p.3–5]；只有 asset discovery 一項與 OpenFlow/Ryu 比延遲 [原文 p.4、Fig.5]。

## C. 指定的 9 項

**1. Research Problem**
SDN（OpenFlow）可程式化程度有限，P4 的高效能實作綁特定硬體，P4 軟體實作 BMv2 功能受限 [原文 p.1]。作者主張 eBPF 可部署在小型、低容量、堅固型的 OT 設備上，並需要類似 SDN 的集中式 controller 來管理 [原文 p.1]。問題是「怎麼用 eBPF 做出完整的、可集中編排的可程式化網路」，不是偵測演算法。

**2. Architecture**
```
Application layer (3rd-party services)   Dashboard / Monitoring / Asset Discovery / DoS Mitigation
        | Northbound API (REST + JSON, Flask)
Controller: Service Broker + Northbound/Southbound event handler
            µNF source -> Clang/LLVM pre-compile -> .o   (Fig.2 列出 ProtoBuf、Twisted、Clang、LLVM)
        | Southbound API (install/remove/list function; list map; add/remove/list entry)
Device agent: Connection Manager + eBPF ELF Loader + Maps (Hash/Array/TCAM/LPM)
Data plane:  RX -> Metadata Prepend -> [NF0 -> NF1 -> ... NFx] -> Tx   (software switch 或 DPDK switch)
```
[原文 Fig.2、p.3]。Pipeline 內 function 可用 `NEXT`（可帶 offset 跳過中間 function）；`PORT`/`FLOOD`/`CONTROLLER`/`DROP` 會讓封包離開 pipeline；pipeline 不允許 loop，以保持執行時間可預期 [原文 p.3]。沒有雲端。

**3. Processing Location**
全部在 **user space**。BPFabric 用的是 eBPF 的 userspace implementation，作者說它最彈性、可部署在任何能做封包進出並能執行 eBPF（interpretation、JIT 或硬體支援）的設備上 [原文 p.2]。論文沒有指名用哪個 userspace eBPF VM。控制面（controller、agent）也在 user space。核心（kernel）的 XDP / generic eBPF、NIC offload 只在 Fig.1 和 Section II 當背景介紹，不是本文實作 [原文 p.2]。

**4. Hardware**
**論文未說明任何實體硬體**。整個拓樸跑在 Mininet 內，software switch 裝在所有交換設備上 [原文 p.3]；沒有寫 host 的 CPU、RAM、kernel 版本、VM 規格。Fig.3 有 "VM 1" 與 attacker VM，規格也沒寫。DPDK switch 只在架構中提到，**沒有在實驗中使用或量測**（實驗只提 software switch [原文 p.3、p.5]）。

**5. Dataset**
沒有資料集。流量由 Smart Grid Simulator (SGSim) 模擬 IEC 60870-5-104、GOOSE、Sampled Values [原文 p.3]；SGSim 引自作者前作 [18]（Electronics 2024）。不是 IoT-23、CICIoT2023，也不是真實流量。攻擊用 netdiscover（ARP 掃描）與 hping3（volumetric flood）[原文 p.4、p.5]。

**6. Baseline**
- Fig.5：asset discovery 的 eBPF 版 vs OpenFlow + Ryu controller 版。因為 OpenFlow 不支援 custom counter，OpenFlow 版只能把每個封包送 packet-in / packet-out 給 controller 處理，所以延遲大 [原文 p.4]。這是「功能做在 data plane」對「做在 controller」的比較，不是兩個同等實作的比較。
- Fig.7：DoS mitigation 開 / 關。Fig.4：network segmentation 的有 / 無，以及 ACL 裝在不同位置。
- 沒有和 NetEdit、Polycube、L3AF 等其他 eBPF 框架重跑；也沒有和「沒有 pipeline 的單一 function」或原版 BPFabric 比。相關工作只做文字比較 [原文 p.5–6]。Ryu baseline 的 switch 實作（例如是否 OVS）論文未說明。

**7. Metrics**
Fig.5：IED1 → HMI 的 end-to-end latency（ms）；Fig.4：每台設備收到的訊息數（千則）；Fig.6：每台設備流量（Kbps，1 秒間隔）；Fig.7：流量（pps）與 IED1–HMI latency（ms）[原文 p.4–5]。**沒有量**：throughput 上限、封包遺失率、CPU、RAM、能耗、pipeline 長度對延遲的影響、重配置時間。

**8. Limitations（作者承認的）**
論文**沒有專門的限制章節**。散見的自述：(a) software switch 是「the slowest eBPF implementation」[原文 p.5]；(b) 範圍限縮在 OT resilience 服務 [原文 p.2]；(c) 結論說這是 proof-of-concept，真實高效能場景要靠 DPDK offload 等 [原文 p.6]；(d) 整個 map 內容只能 list，map 隨 function 一起新增、移除 [原文 p.3]；(e) pipeline 禁止 loop [原文 p.3]。

**9. Research Gap**
- 作者自述：高效能實際部署（DPDK）尚待展示 [原文 p.6]。
- [推測] 沒有實體硬體上的量測；摘要說 "minimum performance overhead"，但全文沒有 overhead 量測（沒有和不經 pipeline、不同鏈長、原生轉送比）；沒有重配置時間與切換期間封包行為；controller 斷線時的行為沒討論；southbound / REST 的認證與 function 完整性沒討論。

## D. 補充欄位（只保留 D5、D6、D9）

**D5. 實驗可信度**
- 流量來源：Mininet 內的模擬流量，單一時間序列（30 + 1 + 30 秒、60 秒、30 秒）[原文 p.4–5]。
- 速率：GOOSE burst 是 1 秒、每 10 ms 一則 [原文 p.4]；DoS 流量約 10^4 pps 量級（Fig.7 目測）。這些速率遠低於會壓到 data plane 的程度，所以 latency 差異主要反映「有沒有經 controller」，不是 data plane 的處理極限 [推測]。
- 重複次數：每張圖看起來只有一次執行，沒有變異量、沒有信賴區間 [原文 Fig.4–7；論文未說明重複]。
- Ablation：沒有。
- [推測] DoS 函式是「丟掉不是 GOOSE / SV / ARP 的所有流量」[原文 p.5]，hping3 flood 被這種 allow-list 擋掉近乎必然，不代表真實 DoS 緩解的難度。
- 程式碼與資料：論文沒有給自己這份工作的程式碼連結。BPFabric 有 GitHub 專案（UofG-netlab/BPFabric，[二手 https://github-wiki-see.page/m/UofG-netlab/BPFabric/wiki/Getting-Started]，wiki 目標 Ubuntu 22.04），但我抓 repo 首頁得到 404，無法確認其中是否包含本文的 pipeline / service broker 擴充。artifact 可得性：**未能確認**。

**D6. 移植到 Pi 4 的障礙**
- 本文的 data plane 是 user space switch，不依賴 XDP、BTF、BPF LSM；所以 Pi OS kernel 沒有 BTF、兩個 port 都沒有 native XDP，對**本文的實作**沒有直接影響 [推測，論文未驗證]。
- software switch 能不能在 Pi 4 上跑：論文說「可部署在任何能做封包進出與執行 eBPF 的設備」[原文 p.2]，但沒有在 Pi 或任何 SBC 上驗證。已驗證的只有 Mininet [原文 p.3]。
- 成本方向 [推測]：userspace switch（原版 BPFabric 摘要寫用 raw socket [二手 https://eprints.gla.ac.uk/138952]）每個封包要經 kernel 到 user space 再回去。同實驗室的 GALETTE 摘要寫 XDP 在 Raspberry Pi 上比 AF_PACKET 更省效率與電力 [二手 https://eprints.gla.ac.uk/296605/]，暗示這條路在 Pi 上不便宜。我們量過 Pi 4 bridge 轉送約 3.1 µs/封包，userspace 路徑沒有數字，需要自己量。
- DPDK 版：需要 DPDK 支援的 NIC driver。Pi 4 的 bcmgenet 與 USB 網卡有無對應 PMD 我沒有查證，**未能確認**。

**D9. 引用網路（建議追加閱讀，≤5 篇）**
OpenAlex 顯示本文被引用 0 次、引用 15 篇 [二手 OpenAlex，查詢日 2026-10-27]，所以沒有「後續改進者」可挑；下面全部是前作、姊妹作、或本文自己比較的對象。
1. Kyle A. Simpson, Chris Williamson, Douglas J. Paul, Dimitrios P. Pezaros, "GALETTE: a Lightweight XDP Dataplane on your Raspberry Pi," IFIP Networking 2023, DOI 10.23919/IFIPNetworking57963.2023.10186412。原因：同題更貼近我們（Pi、XDP fast path + userland、SFC、功耗）。存在確認：**已確認 DOI**（eprints 紀錄）。本文只把它當 [9] 引用，用來支持「generic kernel eBPF 比 native 慢」與「XDP 擋 DoS 有效」[原文 p.2、p.5]。
2. Simon Jouet, Dimitrios P. Pezaros, "BPFabric: Data Plane Programmability for Software Defined Networks," ANCS 2017, pp.38–48, DOI 10.1109/ANCS.2017.14。原因：本文的前作，要知道原版有什麼才能判斷本文新增多少。存在確認：**已確認 DOI**。
3. F. Holik, M. M. Cook, D. Pezaros, "Resilient Network Architecture with eBPF-based Programmability and Centralised Orchestration," IEEE INFOCOM 2025 Workshops, DOI 10.1109/INFOCOMWKSHPS65812.2025.11152786。原因：姊妹作，同一架構的 pipeline slot 設計與 DDoS 實驗有更多細節（我只快速翻讀，沒精讀，結果僅供參考）。存在確認：**已確認 DOI**，PDF 開放。
4. Sebastiano Miano, Fulvio Risso, et al., "A Framework for eBPF-Based Network Functions in an Era of Microservices," IEEE TNSM 18(1):133–151, 2021, DOI 10.1109/TNSM.2021.3055676（Polycube）。原因：本文比較的對象 [28]，fast path / slow path 分離，用 tail call 串接；是框架類論文的代表。存在確認：**已確認 DOI**。
5. T. A. Benson et al., "NetEdit: An Orchestration Platform for eBPF Network Functions at Scale," ACM SIGCOMM 2024, pp.721–734。原因：本文列為第一個 production-grade eBPF orchestration（Meta）[原文 p.5]，要看框架在生產環境怎麼證明價值。存在確認：書目由 DBLP 搜尋摘要確認，**DOI 未驗證**。

## G. 框架專屬欄位

**G1. 框架的抽象**
框架定義：(a) eBPF function（µNF）+ 它專屬的 map 為單位，map 隨 function 新增、移除 [原文 p.3]；(b) pipeline 模型：線性、`NEXT` 帶可選 offset 可跳過、有四種離開 pipeline 的 action、禁止 loop [原文 p.3]；(c) 三層 API：southbound（function / map / entry 三類管理，Table I）與 northbound（REST + JSON）[原文 p.3]；(d) 服務到 function 的對應由 service broker 處理 [原文 p.2–3]。留給使用者：function 的內容（C 原始碼編譯成 `.o`）、服務邏輯、dashboard。論文**沒有**描述設定檔格式或欄位描述語言；function 與 map 的 schema 沒有統一描述，服務自己知道 map 結構 [推測，論文未說明]。TCAM / LPM 兩種 map 在 Fig.2 是虛線框，論文沒解釋是否已實作。

**G2. 擴充與生命週期**
載入：controller 把預先編譯好的 ELF 經 southbound API 的 Install function 送到 agent，由 eBPF ELF Loader 載入 [原文 Fig.2、Table I]。移除：Remove function；列出：List function / List map(s) [原文 Table I]。串接：`NEXT` 與 offset [原文 p.3]。執行中切換：Fig.4 的實驗是在運行中依序把 ACL 裝到 DSS GW、DPS GW、DPS RS [原文 p.4]，所以確實是執行期安裝。**論文沒有說明**：function 放進 pipeline 的哪個位置如何指定、替換是否原子、切換期間封包被丟、放行或走舊 function，也**沒有量測重配置時間或中斷**。（姊妹作 INFOCOM 2025 WKSHPS 說 pipeline 可不重開機重排，攻擊到緩解約 2 秒，主要來自 monitoring service 的查詢間隔 [另一篇論文，只快速翻讀]，本文沒有這些。）

**G3. Kernel / User space / 外部分工**
- 資料平面（RX、metadata prepend、pipeline、Tx）、agent、maps：全在 user space（Fig.2）。沒有 kernel eBPF 掛點。
- Controller（service broker + API handler）：獨立 process；與 agent 走 southbound API（Fig.2 列 ProtoBuf、Twisted；傳輸層協定論文未說明）；服務層經 REST 取得 map 內容 [原文 p.3]。
- 狀態放哪：集中在各設備的 eBPF map；monitoring service 每 1 秒拉一次並寫入 CSV [原文 p.4]。封包送 controller 用 `CONTROLLER` action 產生 packet-in [原文 p.3]。
- 通道：socket（southbound）、HTTP REST（northbound）。沒有 AF_XDP、shared memory。

**G4. 外部依賴可選性**
論文沒有討論 controller 斷線、關閉時 data plane 繼續如何運作，也沒驗證（fail-open / fail-closed 都未說明）。間接資訊：已安裝的 eBPF function 在設備上執行，不需要每個封包問 controller；OpenFlow baseline 才需要 packet-in [原文 p.4]。不過「控制面掛掉時設備是否仍保持已安裝的 function」是 [推測]，論文沒測。沒有雲端。

**G5. 框架價值怎麼證明**
- 和手寫版本 / 原生 kernel / 其他框架比 overhead：**沒有**。
- 可擴充性示範：4 個服務、對應 ACL、AD、monitoring、DoS function [原文 p.3–5]；沒有鏈長掃描，沒有測 pipeline 多長仍可用。「unlimited number of eBPF functions」是設計宣稱（對比 tail call 的 32 個上限 [原文 p.3]），沒有實測。
- 開發成本（LoC、時間、修改量）：**沒有**。
- 可維護性：**沒有**。
- 唯一的量化對照：AD 的 eBPF 版延遲 vs Ryu 版，eBPF 多數點在 GOOSE 3 ms 線以下（目測約 0.1–2.7 ms），Ryu 約 4.5–42 ms（目測）[原文 Fig.5、p.4]。摘要的 "minimum performance overhead" [原文 p.1] 沒有直接對應的 overhead 量測 [推測]。

**G6. 效能量測方法（能不能照著重做）**
- 拓樸：變電站網路，含 2 個 Digital Secondary Substation（各有 gateway 與 RTU）、1 個 Digital Primary Substation（GW、Ring Switch、HV / MV switch、IED1–4、HMI）、control center（含 SCADA）、2 個 WAN router、attacker VM [原文 Fig.3]。
- 平台：Mininet + SGSim，software switch 裝在所有交換設備 [原文 p.3]。Host 規格、kernel、Mininet 鏈路頻寬 / 延遲設定：論文未說明。
- 流量產生：SGSim 模擬 IEC104 / GOOSE / SV；GOOSE 事件 1 秒、10 ms 間隔；攻擊用 netdiscover、hping3，hping3 於 t=35 s 發動 [原文 p.4–5]。封包大小：論文未說明。
- 量測：IED1 → HMI end-to-end latency（時間戳方式未說明）；其他指標以 1 秒間隔回報 [原文 p.4]。
- warm-up、重複次數、CI：論文未說明（圖上看起來是單次）。
- 標準：沒有依循 RFC 2544 / RFC 9411；GOOSE 3 ms 是引自 [22] 的應用層需求 [原文 p.4]。
- 結論：**無法只靠論文重做**，缺 host 規格、SGSim 參數、延遲量測方法、Ryu 實作細節。

**G7. 安全模型**
論文只在引言泛稱 eBPF verifier 保證程式會執行完且不會卡死設備 [原文 p.1]；但 BPFabric 用的是 userspace 實作 [原文 p.2]，論文沒說這個執行環境是否有等價的 verifier。誰能裝 function：controller 經 southbound API；REST API 是否認證、southbound 是否加密、ELF 是否簽章，**論文都沒說**。相關工作提到 L3AF 的簽章 program marketplace 與 bpfman 的安全部署 [原文 p.6]，但那是別人的功能。本文的威脅模型是「OT 網路被掃描、DoS」，不是框架自己的攻擊面。

**G8. 與我們設計（SPEC_ADDENDUM 第 2 節）對照**
- 這篇已經做過、不能宣稱是新的：
  - Controller 集中管理、在執行期對設備安裝 / 移除 eBPF function、列出 / 讀寫 map [原文 Table I、p.3]。
  - 由外部服務讀 map 後更新另一個 map（例如 blacklist）做緩解 [原文 p.4–5；姊妹作有細節]。
  - 把 eBPF 當作可替換的網路功能，並比較「功能在 data plane」與「功能在 controller（packet-in）」的延遲 [原文 p.4、Fig.5]。
  - 其他框架（NetEdit、Polycube、L3AF、bpfman）已有 function 串接、生命週期管理、fast / slow path 分離 [原文 p.5–6]。
- 這篇做了、我們沒有，值得考慮 [推測]：
  - 明確的 pipeline 串接語意（`NEXT` + 跳過 offset），鏈長不受 tail call 上限限制。我們目前是「外掛可掛任何掛點」，多個外掛在同一掛點的順序語意論文裡沒有對應設計。
  - 把 function 與其 map 綁成一個生命週期單位，移除 function 時自動清理 map [原文 p.3]。
- 我們有、這篇沒有 [推測]：
  - 真的在 kernel hook（tc/TCX、可選 XDP）上跑，並與 nftables、NFQUEUE、Suricata 整合；這篇的 data plane 是自帶的 userspace switch，轉送就是 eBPF 決定。
  - 在 Pi 4 上實測的每封包成本數字；這篇沒有任何硬體量測。
  - 可選雲端與 fail 行為（含 log）、插件簽章、特權最小化；這篇沒有討論。
- 取捨不同、論文裡要說明理由：
  - **userspace eBPF（可攜、鏈長無限）vs kernel eBPF（快、有 verifier）**。這篇選前者，自己承認 software switch 是最慢的實作（p.5）。我們選 kernel hook，要說明為何轉送路徑不自己做 switch（因為 kernel 的 bridge / nftables 已經在做）。
  - **框架取代轉送 vs 框架附加在轉送旁**：這篇的 eBPF function 會決定 PORT / FLOOD / DROP，等於替換 switch；我們的 eBPF 外掛附加在 OS 既有轉送上。

**G9. 對碩士論文的用途（≤5）**
1. 引用為「eBPF 可程式化 data plane + controller + 服務層」已有前例的證據，我們的定位要避開這個說法，改強調單一 gateway 上與 IDS 的整合與實測 [原文 p.2–3]。
2. 借用 Fig.1 的分類（generic kernel / native XDP / offloaded / userspace）來定位我們：generic kernel（tc）為預設，native XDP 可選 [原文 p.2]。
3. 作為「controller round trip 不應在每封包路徑上」的例子：OpenFlow 版延遲約 4.5–42 ms，eBPF 版低於 3 ms（目測）[原文 Fig.5、p.4]。這支持我們「雲端不在封包路徑上」的設計，但這是 [推測] 的連結，條件不同（OT 變電站、Mininet）。
4. 作為框架論文評估不足的反例：只做功能展示，沒有 overhead、重配置時間、重複次數、硬體；我們的實驗設計應該補這幾項（對照 G5、G6 的「沒有」）。
5. 引用 tail call 上限 32 與 pipeline 禁止 loop 的設計理由，說明外掛串接的取捨 [原文 p.3]。

**與 GALETTE / BPFabric 的關係（任務指定問題）**
- **是 BPFabric 的直接延續**：作者寫明 "In our previous work, we introduced BPFabric" 並「modify the original BPFabric architecture」[原文 p.1]；Jouet 與 Pezaros 是 BPFabric 原作者，也在本文作者列 [原文 p.1、參考文獻 [8]]。
- **和 GALETTE 不是延續**：本文只把 GALETTE 當作參考文獻 [9]，支持「kernel generic 實作效能較低」與「XDP 擋 DoS 有效」兩個背景論點 [原文 p.2、p.5]。作者重疊只有 Pezaros；GALETTE 作者是 Simpson 等人，摘要中沒有提到 BPFabric [二手 https://eprints.gla.ac.uk/296605/，只看摘要]。兩者是同一實驗室（Pezaros 團隊）的兩條線：BPFabric 線（userspace eBPF、集中控制、OT）與 GALETTE 線（Raspberry Pi、XDP fast path + userland、SFC）。
- **本文在 BPFabric 上新增的東西**（依論文 Fig.2 紅字標示與 p.2–3 文字）：eBPF execution engine pipeline 與 `NEXT` action（含 offset）；southbound API 新增 function 與 map 管理（Table I，並透過修改協定、agent 的 connection manager、controller 的 event handler 實作）；service broker 取代原本的 CLI 核心應用；REST northbound API；應用 / 服務層與 dashboard；四個 OT resilience 服務與 function [原文 p.2–3]。原版 BPFabric 本來有什麼，論文只說 "centralized controller, programmable networking devices and the southbound API ... lacks the application layer"（p.2），我沒有讀 ANCS 2017 全文，細節未能確認。

## E. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| GOOSE 延遲上限 | 3 ms | 變電站需求，引自 [22] | [原文 p.4] |
| AD eBPF 版端到端延遲 | 多數 < 3 ms（目測約 0.1–2.7 ms） | Mininet、BPFabric software switch、IED1→HMI | [原文 Fig.5a/5b，目測] |
| AD OpenFlow/Ryu 版延遲 | 目測約 4.5–42 ms | 同上；需 packet-in/out | [原文 Fig.5a/5b，目測] |
| GOOSE burst | 1 秒、10 ms 間隔；前後各 30 秒正常期 | 實驗設計 | [原文 p.4] |
| 掃描流量 vs 正常流量 | 攻擊 > 100 Kbps；正常設備 < 100 Kbps | netdiscover，監控間隔 1 秒 | [原文 p.5、Fig.6] |
| DoS 流量 | 約 10^4 pps 量級（目測）；t=35 s 開始 | hping3 | [原文 p.5、Fig.7，目測] |
| DoS 緩解效果 | 有緩解時 latency 影響可忽略；無緩解時合法封包被丟 | software switch（最慢的實作） | [原文 p.5] |
| tail call 串接上限 | 32 個 program | 對比本文 pipeline 無上限 | [原文 p.3、p.6] |
| XDP vs iptables/nftables | 4 倍 | 引自 [11]，非本文實驗 | [原文 p.2] |
| eBPF 需求版本 | 3.18+（基本）、5.3+（bounded loop）、XDP 4.8+ | 背景介紹 | [原文 p.2] |

## F. 自評

- 未能確認：實體硬體（論文沒寫）、傳輸層協定與 userspace eBPF VM 名稱、重配置語意（原子性、位置指定）、controller 斷線行為、程式碼是否公開、原版 BPFabric 提供的功能清單（沒讀 ANCS 2017 全文）。
- 數值多數是從圖上目測；只讀 accepted manuscript，IEEE 正式版可能有差異。
- 最不確定的三件事：
  1. 「新增了什麼」的判斷依賴本文 Fig.2 的紅字標示與敘述，沒有和 BPFabric 原文逐項對照，可能漏列或多列。
  2. G2 / G4 的「論文未說明」是以全文只有 6 頁正文為依據；姊妹作有更多細節，我只快速翻讀，沒有精讀，不能當成本文的證據。
  3. D6 關於 userspace switch 在 Pi 4 上的成本，只是用 GALETTE 摘要與一般認知做的 [推測]，沒有本文或我們的實測支持。
