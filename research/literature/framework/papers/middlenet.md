# MiddleNet

## A. 書目與取得狀況

- 標題：MiddleNet: A Unified, High-Performance NFV and Middlebox Framework with eBPF and DPDK
- 作者：Shixiong Qi, Ziteng Zeng, Leslie Monis, K. K. Ramakrishnan（UC Riverside）[原文 p.1]
- 出處：IEEE Transactions on Network and Service Management, vol. 20, no. 4, pp. 3950–3967, 2023-12 [二手：Crossref API https://api.crossref.org/works/10.1109/TNSM.2023.3256891]
- DOI：10.1109/TNSM.2023.3256891（IEEE Xplore 轉址到 https://ieeexplore.ieee.org/document/10068810/，內容未能抓取）
- 預印本：https://arxiv.org/abs/2303.04404（v1 2023-03-08、v2 2023-03-30；頁面沒有 journal reference、沒有程式碼連結）
- 本地 PDF：`research/literature/framework/pdfs/middlenet/middlenet.pdf`（arXiv v2，17 頁）

**與給定資訊的差異：** 標題、年份、期刊、DOI 全部正確，無差異。需要補充的是：
(1) 我讀的 arXiv v2 是 UCR 技術報告編號 NET-2023-0307，首頁註腳說它是 NetSoft 2022 與 TNSM 版的「延伸版」，額外加入 shared memory 的 overhead auditing（Appendix B）[原文 p.1 註腳 1]。**所以下面的頁碼是 arXiv v2 的頁碼，不是 TNSM 排版頁碼；TNSM 正式版全文我沒讀到，內容可能有出入。**
(2) NetSoft 2022 的前身論文標題與作者順序不同（Zeng 為第一作者）[二手：DBLP/搜尋結果]。
(3) arXiv v2 參考文獻有 46 筆且 [2] 是 TNSM 版本身，Crossref 記錄 TNSM 版為 45 筆，兩者相容 [推測：TNSM 版應該就是去掉自我引用後的同一組參考文獻]。

**取得程度：全文**（arXiv v2 延伸版；TNSM 排版版未讀）

## B. 核心貢獻

1. 把 L2/L3 NF 與 L4/L7 middlebox 放進同一個框架，但**兩者走不同的資料路徑**：L2/L3 用 DPDK（kernel-bypass、polling、shared memory）；L4/L7 用 kernel protocol stack + eBPF（AF_XDP / SKMSG / sockmap，event-driven）；用 SR-IOV 的 VF 與 flow bifurcation 依 5-tuple 把 flow 分到兩條路徑 [原文 p.1, p.13]。
2. 不直接宣稱選擇，而是把兩種機制各做一遍（D-MiddleNet 與 E-MiddleNet，L2/L3 與 L4/L7 各一組）並實測，再導出「哪一層用哪種」的結論 [原文 p.2, p.8–12]；另用拷貝、interrupt、context switch 次數做解析式 overhead auditing [原文 Table I, II, IV, V]。
3. 實測 L4/L7 的 eBPF 路徑 CPU 平均省 3.2×、吞吐在高負載與 DPDK 差在 1.05× 內；統一部署時 L2/L3 與 L4/L7 互不明顯干擾 [原文 p.15, p.14]。

## C. 指定的 9 項

**1. Research Problem：** L2/L3 NF（bump-in-the-wire，重效能）與 L4/L7 middlebox（需完整協定堆疊，重功能）通常由不同平台、不同節點處理，但網路需要兩者同時支援不同甚至同一條 flow [原文 p.1]。

**2. Architecture：**
```
NIC (SR-IOV, NIC 內建 5-tuple classifier)
 ├─ VF-A (DPDK PMD) → NF manager → [RTE ring polling] → NF chain      （L2/L3，user space，shared memory）
 └─ VF-B (kernel)   → TCP/IP stack → socket → message broker
                         → [SKMSG + sockmap 傳 descriptor] → MF chain  （L4/L7，payload 在 shared memory）
```
[原文 Fig. 12 p.13, §IV p.7–8, §V p.10–11]。function 以 container 部署、DPDK secondary process 共用 private memory pool，NF manager / message broker 持有 routing table 做 chain 轉送 [原文 p.7–8, p.14]。論文沒有 edge/cloud 分工，全部在單一節點內。

**3. Processing Location：** L2/L3 與 L4/L7 的 function 本身都在 user space；差別在封包怎麼進 shared memory。L2/L3：NIC DMA 直接進 user space，不經 kernel。L4/L7：經 kernel stack 後以 socket 交給 broker，再搬進 shared memory（NIC 到 shared memory 兩次拷貝）[原文 p.7, p.16 Table V]。eBPF 在這裡只用於 AF_XDP、SK_MSG/sockmap 與 descriptor 過濾，**不是 XDP/tc 內執行 NF 邏輯** [原文 p.8, p.14]。

**4. Hardware：** NSF CloudLab 三個節點，每台 40 核 CPU、192 GB RAM、10 Gbps NIC（CPU 與 NIC 型號論文未說明）；Ubuntu 20.04、kernel 5.15、DPDK v21.11、libbpf v0.6.0 [原文 p.9]。完全沒有 ARM 或嵌入式設備。

**5. Dataset：** 沒有資料集。L2/L3 用 Pktgen（DPDK）產生合成封包；L4/L7 用 Apache Benchmark 產生 HTTP 請求 [原文 p.9, p.11]。

**6. Baseline：** L2/L3：OVS-DPDK、OVS-AF_XDP（interrupt / polling 兩種）[原文 p.9]。L4/L7：Linux bridge + veth + container（K-vSwitch，Fig. 1(d)）、單體 NGINX [原文 p.11]。全部由作者在同一測試床重跑，OVS 啟用 multiple PMD threads 以求最佳 [原文 p.9]；不是引用他人數字。

**7. Metrics：** L2/L3：Maximum Loss Free Rate（MLFR）、MLFR 下的 CPU 用量與 end-to-end latency，封包 64–1024 B；L4/L7：RPS、response latency、CPU，concurrency 1–512；另有 chain 長度 2–10 的 scalability [原文 p.9–12]。

**8. Limitations（作者承認）：** (a) D-MiddleNet 的 polling 恆常耗核（每個 NF 一核、NF manager 兩核），作者只說可借 NFVnice 的排程緩解 [原文 p.10]；(b) 64 B 時 D-MiddleNet 因核數限制只到 12.6 Mpps（約 84% line rate）[原文 p.10]；(c) event-driven 路徑有 receive-livelock／過載行為差的風險 [原文 p.8, p.10]；(d) eBPF program 有大小限制且必須 run-to-completion [原文 p.2]；(e) SKMSG 每次 descriptor 傳遞約 20 µs，需要再優化 [原文 p.16]；(f) 共享記憶體弱化隔離，信任模型假設 MiddleNet 內的 function 彼此信任 [原文 p.14]。

**9. Research Gap：**
- 作者自述：SKMSG 需更進一步優化（讓 descriptor 不經 broker 直接傳）[原文 p.16–17]；function 共用與 Kubernetes 編排只列為可能 [原文 p.12]。
- [推測]：沒有重配置、failover、flow 路徑切換延遲的量測；沒有低功耗/ARM 評估；沒有 IDS 類 function（只用 L3 routing、L2 forwarding、reverse proxy、URL rewrite、素數產生）。

## D. 補充欄位

**D5. 實驗可信度**
- 流量：全為合成（Pktgen、ab），單一測試床。
- L2/L3：「5 次重複、每次 60 秒，取平均」[原文 p.10]；**圖中沒有誤差線，文中沒有變異量或信賴區間**。L4/L7 與統一部署的重複次數與時間論文未說明（只說沿用 §IV-D 的測試床）[原文 p.11]。warm-up 論文未說明。
- Ablation：有 polling vs interrupt（E-MN-p vs E-MN-i）、DPDK vs eBPF 兩種機制對比；**adaptive batching 只報告開啟的結果，沒有關閉的對照** [原文 p.11–12]。
- 統一部署的干擾測試只有一種 L4/L7 負載（concurrency 256，約 0.22 Gbps）疊在 128 B 滿速 L2/L3 上，L2/L3 從 10 降到 9.78 Gbps，差值約等於新增的 L4/L7 流量 [原文 p.14]；較強的 L4/L7 負載下是否仍無干擾，論文沒有測。
- 公平性：E-MiddleNet 是作者自己的實作，其 L2/L3 的不佳（3.2 / 6.3 Mpps）有多少來自 AF_XDP 本質、多少來自實作（三個 thread 管 ring）無法判斷 [推測]。
- 程式碼：arXiv 頁面無連結，網路搜尋未找到公開 repo [二手：搜尋結果]；artifact 未公開（以我查到的為準）。
- 小瑕疵：p.10 引用 L2/L3 的 interrupt/context switch 時寫 Table V，實際 L2/L3 是 Table IV（p.16）。

**D6. 移植到 Pi 4 的障礙**（全部為 [推測]，沒有人在 Pi 上驗證過；規格已知兩個 port 都沒有 native XDP、Pi OS kernel 無 BTF）
- DPDK PMD 路徑：需要 DPDK 支援的 NIC、hugepage、專用 polling 核。Pi 4 只有 4 核，D-MiddleNet 的配置（2 核 manager + 每 NF 1 核）[原文 p.10] 光一條兩 NF 的 chain 就吃掉 4 核中的 4 核。bcmgenet 與 USB NIC 是否有可用的 DPDK PMD，我沒有查證。
- SR-IOV flow bifurcation：依賴 NIC 內建 switch 與 5-tuple classifier [原文 p.13]；Pi 4 的 bcmgenet 是 SoC MAC，我不認為有 SR-IOV [推測]，所以「硬體依 flow 分流」要改成軟體分類（nftables / tc / ct mark），成本由 CPU 負擔。
- AF_XDP：論文沒說明用的是 native zero-copy 還是 copy 模式。Pi 4 沒有 native XDP，只能 generic（copy）模式，「零拷貝、閒置不耗 CPU」的優勢會縮水。
- SK_MSG/sockmap：理論上不需要 BTF，但 Pi OS kernel 是否開啟相關 config 未驗證；而且它用在 function 之間傳 descriptor，我們只有單一 IDS，用不上。

**D9. 引用網路**（Semantic Scholar 有 18 筆 cited-by，多與 NFV/serverless/5G 有關，直接相關者少）
1. Van Tu, Yoo, Hong, "Accelerating Virtual Network Functions With Fast-Slow Path Architecture Using eXpress Data Path," IEEE TNSM 17(3):1474–1486, 2020, DOI 10.1109/TNSM.2020.3000255。MiddleNet 參考文獻 [45]；eVNF 把簡單處理放 XDP、複雜處理（含 DPI VNF）放 user space，和我們 fast/slow path 最貼近。存在確認：已確認書目（二手搜尋結果），未讀全文。
2. Miano et al., "A Framework for eBPF-Based Network Functions in an Era of Microservices," IEEE TNSM 18(1):133–151, 2021（Polycube，MiddleNet [43]）。同題更貼近；repo 已有 `pdfs/polycube/`，確認存在（MiddleNet 參考文獻 + 已下載）。
3. Abranches, Michel, Keller, "Getting back what was lost in the era of high-speed software packet processing," HotNets 2022, pp. 228–234（MiddleNet [44]，被歸為 in-kernel eBPF NF [原文 p.15]）。存在確認：DBLP/NSF PAR 已確認書目，DOI 未驗證，未讀。
4. Tu, Wei, Antichi, Pfaff, "Revisiting the Open vSwitch Dataplane Ten Years Later," ACM SIGCOMM 2021, pp. 245–257（MiddleNet [18]，OVS-AF_XDP 基準）。存在確認：僅取自 MiddleNet 參考文獻，未驗證。
5. "XenFlow: An XDP/eBPF-Based Multi-Tenant NFV Framework Considering System Security and High-Performance," IEEE Access, 2026, DOI 10.1109/ACCESS.2026.3687522（引用 MiddleNet，標題含安全面向，可補 G7）。存在確認：僅 Semantic Scholar 紀錄，網頁搜尋未能驗證。

## G. 框架專屬欄位

**G1. 框架的抽象：** 框架定義的是：packet descriptor 指向 shared memory 的 buffer、NF manager / message broker 持有的 routing table（以目的 NF ID 決定下一跳）、function = DPDK secondary process [原文 p.7–8]。chain 內容、function 邏輯由使用者寫（論文範例：L3 routing、L2 forwarding、reverse proxy、URL rewrite）。**沒有描述語言、設定檔格式或 API 規格**；flow 規則只說「attach flow rules to the packet classifier」，語法未說明 [原文 p.13]。

**G2. 擴充與生命週期：** function 以 container 啟動，用相同 file prefix 接上 memory pool，由 shared memory manager（DPDK primary process）在初始化時建立 pool [原文 p.7, p.15 Appendix A]；chain 靠 routing table 串接。替換、停用、原子切換、切換期間封包如何處理：論文未說明；重配置時間與中斷：**沒有量測**。Fig. 13(b) 只展示 25 秒時加入 L4/L7 負載，是共存而不是重配置 [原文 p.14]。

**G3. Kernel / User / 外部分工與取捨理由**

| 層 | L2/L3 路徑 | L4/L7 路徑 |
|---|---|---|
| NIC → shared memory | DPDK PMD，DMA 直入，polling | kernel stack → socket → broker（兩次拷貝）|
| chain 內傳遞 | RTE ring polling（約 0.5 µs/次）| SKMSG + sockmap（約 20 µs/次，event-driven）[原文 p.16] |
| 狀態 | NF manager 內 routing table | eBPF socket map（kernel）|
| 過濾 | NF manager 查 filtering map [原文 p.14] | SKMSG program 查 eBPF map [原文 p.14] |

取捨理由（作者）：L2/L3 只做 switch 式轉送，不需要協定堆疊，重點是 line rate 與過載行為，polling 避免 receive-livelock [原文 p.1, p.5, p.15]；L4/L7 需要完整、經過驗證的 kernel stack（user-space stack 常漏掉 corner case、每個 function 各帶一份 stack 增加記憶體）[原文 p.1, p.4]；L4/L7 因為走有流量控制的傳輸協定，receive-livelock 較不嚴重，且 interrupt 不像 polling 吃滿 CPU [原文 p.11]。單一 DPDK NIC 與 kernel stack 互斥，所以用 SR-IOV 的 VF 切開 [原文 p.3–4, p.13]。external controller/cloud：本論文沒有，只提到 Kubernetes 之類編排可能 [原文 p.12]。

**G4. 外部依賴可選性：** 無 controller/cloud，故不適用；NF manager 或 broker 當掉時的行為（fail-open/closed）論文未說明，也沒驗證。

**G5. 框架價值怎麼證明：**
- Overhead：與 OVS-DPDK、OVS-AF_XDP、Linux bridge+veth、單體 NGINX 比；E-MiddleNet 比單體 NGINX 只差 1.04×（RPS）[原文 p.12]。
- 可擴充性：兩個 NF 的 L2/L3 chain、兩個 MF 的 L4/L7 chain、2–10 個 CPU 密集 MF 的 scalability（Fig. 11）[原文 p.12]。總共 4 種 function 加素數產生。
- 開發成本（LoC、時間）：**沒有**；可維護性：僅定性（微服務的彈性與 scale、container vs VM）[原文 p.12, p.6]。
- 另一種證明方式：用 copy / interrupt / context switch / 協定處理次數的解析表格說明 overhead 來源 [原文 Tables I, II, IV, V]，這是我們可借的寫法。

**G6. 效能量測方法（可重做程度）**

| 項目 | 設定 |
|---|---|
| 拓樸 | CloudLab 三節點：node1 流量產生器與 latency 量測點；node2 受測；node3 L2/L3 時把封包原樣送回 node1，L4/L7 時為兩台 NGINX web server [原文 p.9, p.11] |
| 軟體 | Ubuntu 20.04、kernel 5.15、DPDK 21.11、libbpf 0.6.0；Pktgen（L2/L3）、Apache Bench（L4/L7）[原文 p.9, p.11] |
| L2/L3 chain | L3 routing（改 IP）→ L2 forwarding（改 MAC）[原文 p.9] |
| L2/L3 負載 | 封包 64/128/256/512/1024 B；找 MLFR（loss 容忍值與搜尋演算法未說明）；在 MLFR 下量 CPU 與 E2E latency [原文 p.9] |
| 次數 | L2/L3：5 次 × 60 秒，取平均，無變異量 [原文 p.10]；L4/L7：未說明 |
| L4/L7 chain | reverse proxy（round-robin 到兩個 backend）→ URL rewrite；concurrency 1,2,4,…,512；E-MN 啟用 adaptive batching [原文 p.11] |
| scalability | chain 2–10 個 MF，每個 MF 收到請求就算 sieve-of-Atkin 素數，每個 MF 專用 1 核，concurrency 512 [原文 p.11–12] |
| 統一部署 | node2 設兩個 VF；Pktgen 在 node1、ab 在 node3；NF/MF 改為 hairpin 回原節點避免兩個產生器互擾；L2/L3 維持 MLFR、ab concurrency 256；時間序列 100 秒，25 秒時開始 L4/L7 [原文 p.14] |
| CPU 配置 | OVS 啟用 multiple PMD threads，3 個 PMD thread；每個 virtio-user 專用 1 核；E-MN manager 3 個 thread [原文 p.9] |
| 未說明 | NIC 與 CPU 型號、時間戳方法、CPU 用量取得工具、warm-up、NUMA/中斷親和性、是否依循 RFC 2544 / RFC 9411（全文無 RFC 引用；MLFR 概念近似 RFC 2544 的 zero-loss throughput，但這是我的類比 [推測]）|

**G7. 安全模型：** 信任模型假設只有 MiddleNet 內的 function 彼此信任；每條 chain 一個 private memory pool，用 DPDK file prefix 隔離，並對 function 做「authenticated」的 admission control（驗證機制細節未說明）；另用 descriptor filtering 阻擋未授權的 NF 間傳遞 [原文 p.14]。沒有簽章、沒有 verifier 以外的 eBPF 檢查、沒有威脅模型章節。

**G8. 與我們設計對照**
- **這篇已做、我們不能宣稱新的：** (1) 依「是否需要完整協定處理」把處理分到 kernel path 與 user-space path，並用實測說明取捨 [原文 p.5, p.15]；(2) 依 flow 5-tuple 選路徑，且兩種路徑共存 [原文 p.13–14]；(3) 用 shared memory + event-driven eBPF 降低 CPU 並與 polling 比較 [原文 p.12]；(4) 過載下 interrupt 驅動路徑表現較差的觀察 [原文 p.10]。
- **這篇做了、我們沒有，值得考慮：** (1) 分流規則由 NIC classifier 執行，不佔 CPU，我們在 Pi 上只能軟體分類（nftables/tc/ct mark）；(2) adaptive batching，一次 interrupt 取多筆 descriptor，高負載差距縮到 1.05× [原文 p.11–12]，NFQUEUE 的 verdict 批次化是否有類似效果可以量 [推測]；(3) 用 copy/interrupt/context switch 次數做解析式 overhead 拆解，可套在 tc 路徑與 NFQ 路徑上；(4) 「同時實作兩種機制再選」的方法論。
- **我們有、這篇沒有（不誇大）：** 外掛的簽章驗證與信任邊界；可選的雲端與其斷線行為；flow 判定後動態升降級路徑（本文是靜態、依 VF 決定）；ARM 低資源設備上的實測；IDS 類 function。
- **設計不同、論文需說明取捨：**
  - 本文兩條路徑的 function 都在 user space，差別在封包如何進 user space；我們的 fast path 是 kernel 內 tc eBPF，慢路徑才進 user space。MiddleNet 把 in-kernel eBPF NF（[43]–[45]）歸類為「只能做 L2–L4、L7 要付出 kernel→user 傳輸成本、interrupt 驅動過載行為差」[原文 p.15]，這個批評直接指向我們的做法，我們要說明為何在 1 GbE、單一 IDS 的場景可接受 [推測]。
  - 本文選 kernel stack 的理由是「要終止連線並依賴成熟協定堆疊」；Suricata 是被動檢測、自行在 user space 重組 TCP stream，不屬於本文討論的 kernel stack 路徑 [推測]。
  - 本文以解析 chain 長度成長的拷貝成本來說明 shared memory 價值，Appendix B 還明說兩個 function 的 chain 與最佳 kernel 模型相比沒有顯著好處 [原文 p.16]；我們 chain 長度為 1，這個機制幾乎不適用 [推測]。

**kernel 路徑 vs user-space 路徑結論的可類比性**（對照我們的 tc eBPF fast path vs NFQUEUE→Suricata）
- 可類比（方向）：
  1. 路徑切分準則「是否需要更深的處理」，與我們「per-packet/flow 狀態可判定走 fast path，需要 L7 語意才進 Suricata」形狀相同；差別是本文依服務類型靜態分，我們依 flow 狀態動態分 [推測]。
  2. polling 恆常耗核、event-driven 隨負載（L4/L7 在 concurrency 1 時 37% vs 404% CPU）[原文 p.12]：Pi 4 只有 4 核，不能養 polling，結論方向更強 [推測]；NFQUEUE 本身是 event-driven 的。
  3. kernel/user 邊界每次交接都有固定成本（SKMSG 約 20 µs vs ring 0.5 µs）[原文 p.16]，與我們量到 bridge 約 3.1 µs 對 NFQ→Suricata 約 27–29 µs 的落差方向一致；**兩者量的東西不同（本文只量 descriptor 傳遞，我們含 Suricata 處理），數字不可直接比** [推測]。
  4. 批次化可攤平 interrupt/context switch [原文 p.12]。
- 不可類比（硬體）：
  1. 結論以 40 核 x86、10 GbE、DPDK 21.11、kernel 5.15 取得，64 B 的 Mpps 差距在 1 GbE（最高約 1.49 Mpps）的 Pi 上未必會成為瓶頸；絕對數字與 Pi 4 的 A72 核無關 [推測]。
  2. SR-IOV 硬體分流、DPDK PMD、native AF_XDP 在 Pi 4 都不可得（見 D6）[推測]。
  3. 「DPDK 比 eBPF 快 2–4×」的 L2/L3 結論建立在 AF_XDP 零拷貝與 interrupt 路徑；Pi 的 generic XDP/tc 路徑成本結構不同，不能引用這個倍數 [推測]。

**G9. 對碩士論文的用途**
1. 支撐「依處理深度分路徑已有前例，且兩條路徑必須同時存在」：[原文 p.1, p.13–14]。
2. 引用「polling 對資源受限設備不經濟、event-driven 負載成比例」的實測對比（concurrency 1 時 37% vs 404% CPU；3.2× 平均 CPU 節省）[原文 p.12, p.15]，作為我們選 NFQUEUE 而非 busy-poll 的佐證（加註不同硬體）。
3. 借用 overhead auditing 表格形式（拷貝、interrupt、context switch 次數）解釋 tc 路徑與 NFQ 路徑的成本差 [原文 Tables I, II]。
4. 借用「同一機制做 polling/interrupt 兩種變體」與「adaptive batching」的對照設計 [原文 p.9, p.11]；但要補上論文缺的重複次數與信賴區間。
5. 作為「in-kernel eBPF NF 被批評之處」的反方論點，在我們的設計章節要正面回應 [原文 p.15]。

## E. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| D-MN L2/L3 轉送率 | 12.6 Mpps（約 84% line rate） | 64 B，2 NF chain，manager 核數受限，40 核 x86 / 10 GbE | [原文 p.10] |
| E-MN-i / E-MN-p 轉送率 | 3.2 / 6.3 Mpps（D-MN 的 25% / 50%） | 同上，64 B | [原文 p.10] |
| E-MN-i kernel CPU 占比 | NF manager 53%、NFs 67% | MLFR 下 | [原文 p.10] |
| L2/L3 latency | D-MN 比 E-MN-i 好 2.6×、比 E-MN-p 好 1.8× | MLFR 下 | [原文 p.10] |
| 大封包 CPU | E-MN-i/p 為 D-MN 的 63% / 58% | 1024 B | [原文 p.10] |
| D-MN 恆常 CPU | 每 NF 1 核、manager 2 核 | polling | [原文 p.10] |
| L4/L7 concurrency 1 CPU | E-MN 37% vs D-MN 404%（約 10×） | 2 MF chain，ab | [原文 p.12] |
| L4/L7 吞吐差 | D-MN 比 E-MN 高 1.09–1.3×（concurrency 1–32）；>64 時差 <1.05× | 同上，E-MN 啟用 adaptive batching | [原文 p.12] |
| K-vSwitch | RPS 約為其他的 42%、latency 約 2.3× | concurrency 512；CPU >10 核（c=32）、30 核（c=512） | [原文 p.12, Fig. 10 caption] |
| E-MN vs 單體 NGINX | RPS 低 1.04×、latency 高 1.04× | 同上 | [原文 p.12] |
| CPU 密集 MF | E-MN RPS 高約 10%、latency 低約 10%；D-MN 多用 1 核 | 2–10 MF，concurrency 512 | [原文 p.12–13] |
| SKMSG vs RTE ring 傳遞延遲 | 約 20 µs vs 約 0.5 µs（每個 descriptor） | 論文未說明量測條件 | [原文 p.16] |
| SR-IOV 統一部署 | 總吞吐約 10 Gbps；L4/L7 加入（0.22 Gbps）後 L2/L3 10 → 9.78 Gbps | 128 B 滿速 L2/L3，ab concurrency 256 | [原文 p.14, Fig. 13] |
| 統一方案內部 overhead | NIC switch：2 interrupt/1 copy/1 ctx switch；virtio-user+TUN/TAP：2/2/2 | NF manager 與 broker 之間 | [原文 Table III p.13] |
| 摘要結論 | L2/L3 DPDK 小封包吞吐比 interrupt 式 eBPF 高 4×、latency 低 2×；L4/L7 eBPF 平均省 3.2× CPU | 同上 | [原文 p.15] |

## F. 自評

**未能確認的欄位與原因：** TNSM 排版版內容（只讀 arXiv v2，IEEE Xplore 抓不到）；NIC/CPU 型號、AF_XDP 實際模式、MLFR 搜尋方法、CPU 量測工具、L4/L7 重複次數、warm-up、時間戳方法（論文未說明）；程式碼是否公開（只確認 arXiv 頁面與搜尋結果沒有）；D9 第 3–5 項的 DOI。

**對既有資訊的檢查：** 無舊報告可對照（這是首次精讀）。

**最不確定的三件事：**
1. arXiv v2（延伸版）與 TNSM 正式版的差異：p.1 註腳說 Appendix B 的 overhead auditing 是延伸版新增的，TNSM 版可能沒有；引用時若引 TNSM，需要使用者經學校取得 IEEE 全文再核對頁碼與 Appendix B 的數字（SKMSG 20 µs 等）。
2. 把 D6 的 Pi 4 障礙（bcmgenet 無 SR-IOV 與 DPDK PMD、generic 模式下 AF_XDP 的成本結構）都標為 [推測]：我沒有在 Pi 上實測，也沒有逐項查 DPDK 的驅動支援清單。
3. G8 中「MiddleNet 對 in-kernel eBPF NF 的批評直接指向我們」是我的詮釋：論文原話只針對 [43]–[45] 這類 XDP/tc NF，把它對應到我們的 tc fast path + NFQUEUE 分工是 [推測]，因為我們的 fast path 不做 NF 鏈、慢路徑也不是 shared-memory function。
