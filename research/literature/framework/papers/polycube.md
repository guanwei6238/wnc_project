# Polycube
（本報告頁碼一律用期刊印刷頁碼 p.133–151；「原文 G1–G4」指論文自己的設計目標，和下面本檔的 G1–G9 欄位無關。Fig. 的數值若寫「目視讀值」，是我從圖上讀出的近似值，不是論文給的數字。）

## A. 書目與取得狀況
- 標題：A Framework for eBPF-Based Network Functions in an Era of Microservices
- 作者：Sebastiano Miano, Fulvio Risso, Mauricio Vásquez Bernal, Matteo Bertrone, Yunsong Lu
- 年份／出處：2021（2021-01-29 上線，3 月號）；IEEE Transactions on Network and Service Management, vol. 18, no. 1, pp. 133–151
- DOI：10.1109/TNSM.2021.3055676（PDF 內嵌 metadata 與 OpenAlex W3128928115 皆吻合；OpenAlex 2026-10-27 顯示被引 95 次）
- URL：https://sebymiano.github.io/publication/2021-polycube/2021-polycube.pdf（已存 `pdfs/polycube/polycube.pdf`）
- 與給定資訊的差異：無。標題、年份、期刊、DOI 都正確。
- 取得程度：**全文**（作者主頁提供的 IEEE 排版版；頁尾有 Politecnico di Torino 的 IEEE licensed-use 字樣，來源是作者自己的網站）。

## B. 核心貢獻
1. 把 NFV 的「模組＋統一控制」搬進 kernel：每個 NF 叫 Cube，由 eBPF fast path（可再拆成 µCube）、user-space slow path、control/management plane 組成，由單一 service-agnostic 的 user-space daemon `polycubed` 管理；管理 API 由 YANG 模型自動產生 REST [原文 p.136–137, 142]。
2. 在 eBPF 沒有「port」概念的前提下，用虛擬 port、PatchPanel（PROG_ARRAY + tail call）與框架自動加上的 pre/post-processor 實現 in-kernel service chaining；Cube 可執行中載入、`pcn_reload()` 重新編譯後原子替換 [原文 p.137–140]。
3. 評估：實作多個 NF（Table II），與 Linux bridge、OVS、iptables、nftables、ipvs、Katran、K8s CNI 比較，並量化框架本身相對 vanilla eBPF 的 overhead（Table III、Fig. 10）[原文 p.143–147]。

## C. 指定的 9 項
**1. Research Problem**：現有 NFV 框架多靠 kernel bypass（DPDK 等），需獨佔 CPU、重做整個網路 stack、依賴特製驅動；而 kernel 內的網路功能又難演進、難客製 [原文 p.133–134]。目標是讓 in-kernel 封包處理也有 NFV 的模組化、動態更新與統一管理。

**2. Architecture**
```
REST client / orchestrator
        │ REST（由 YANG 自動產生）
  polycubed（user space，C++）
   ├ Service Proxy → Service Controller（每個 NF 實例）
   ├ Control/Mgmt plane（每 Cube）、Slow path（packet_in 回呼）
   └ Kernel abstraction layer ── eBPF map ──┐
        ▲ perf ring buffer（fast→slow）      │
        ▼ TAP + Decapsulator（slow→fast）    ▼
  Kernel：Cube（µCube…）fast path，掛 TC 或 XDP；Cube 間靠 PatchPanel tail call
```
（對應 Fig. 1、Fig. 2、Fig. 3 [原文 p.136–139]）。沒有 Flow／Edge／Cloud 之分；這是純網路功能框架，不是 IDS。

**3. Processing Location**：fast path 在 kernel（TC/XDP eBPF）；slow path 與 control plane 在 user space；Cube 與外部服務（資料庫、通知）的互動交給 control plane，再轉成 map 寫入 [原文 p.147]。無雲端。

**4. Hardware**：DUT 為 Xeon Gold 5120 14 核 2.2 GHz、雙埠 Intel XL710 40 Gbps、Ubuntu 18.04.1、kernel v5.6；發包機為 Xeon E3-1245 v5；K8s 實驗為 3 節點 Xeon E3-1245v5、kernel v4.15 [原文 p.143, 145]（細節見 G6）。沒有 ARM 或低功耗設備。

**5. Dataset**：沒有資料集。全為合成流量：Pktgen-DPDK 的 64 B UDP；規則由 classbench 產生 [原文 p.143–145]（細節見 G6）。

**6. Baseline**：Linux bridge v1.5、OVS v2.13（跑在 kernel 5.0，因為它不支援更早版本 [原文 p.144 fn.9]）、ipvs v1.28、Katran、iptables、nftables、OVS OpenFlow 規則、OVS-DPDK、NFVnice、K8s CNI（Fig. 8 圖例：calico v3.3、cilium v1.3、kube-router、romana、weavenet）；框架 overhead 的基準是 Linux samples 的 `xdp_redirect`、`tc_redirect` 與標準 tail call [原文 p.144–146]。在同一台 DUT 上重跑；iptables／nftables 版本與是否用 ipset／set 優化，論文未說明。

**7. Metrics**：吞吐（Mpps，1–6 核）、latency／jitter（µs）、單核 CPU% 對 offered rate、TCP 吞吐（Gbps）、LoC、reload 時間（ms）、slow path 比例對吞吐。沒有 RAM、能耗。

**8. Limitations（作者承認，p.147–148）**：µCube 不能跨 NF 共用；`polycubed` 的 Demultiplexer 是所有 Cube 共用的單一元件，slow-path 密集的服務會成為瓶頸；不支援多租戶；只支援 TC/XDP，不支援 socket 層；eBPF sandbox 限制（無無界迴圈、tail call 最多 32 層）；用 BCC 編譯比 CO-RE 受限（作者自己說「looks more limiting」，並說之後可改為遠端編譯）[原文 p.141, 143]。

**9. Research Gap**
- 作者自述：跨 NF 共用 µCube 並在執行期移除重複功能；每 Cube 一個 perf ring buffer；slow path 改用 AF_XDP；P4 作為資料平面描述語言 [原文 p.146–148]。
- [推測]：沒有量測 reload 期間的封包遺失／延遲尖峰（見 G2）；沒有 RAM／能耗／低資源平台數據；沒有失效情境（`polycubed` 掛掉時資料平面行為）；沒有安全模型。

## D5. 實驗可信度
- 流量：合成、硬體發包；封包大小只有 64 B（沒有 IMIX 或大封包）；offered rate 與測試時長論文未說明（只有 reload 實驗說明用「封包遺失 <1% 的吞吐」[原文 p.147]，其他圖是否以 NDR／零遺失定義吞吐，**未能確認**）。
- 重複與變異：Setup 寫「All tests」重複 10 次，誤差條為 standard error（不是 CI、不是標準差）[原文 p.143]；K8s 實驗用另一組機器，是否同樣 10 次未明說，Fig. 8/9 目視也沒有誤差條。warm-up 只有 bridge 先雙向送流量讓 MAC table 學好 [原文 p.144]。CPU 量測工具、CPU 頻率／governor／IRQ affinity 論文皆未說明。
- Ablation：沒有。firewall 的 31.8x／7.5x 同時混了「LBVS 演算法 vs 線性掃描」和「動態 reload 特化」兩個因素，作者自己承認有兩個原因 [原文 p.145]，但沒有拆開；LB 贏過／追平 Katran 也歸因於動態 reload，沒有關掉 reload 的對照 [原文 p.144]。
- 比較公平性：OVS 在 kernel 5.0、其他在 5.6、K8s 在 4.15；Fig. 6、Fig. 7 的倍率沒說對應幾核。目視 Fig. 7 單核（約 1.45 vs 0.2 vs 0.05 Mpps）與 7.5x、31.8x 相符；Fig. 6 的 6.5x 與 2 核那組相符，6 核時 XDP 版只約 ipvs 的 3.9 倍 [推測，目視]。
- 開放程度：框架本身開源（Apache-2.0，GitHub polycube-network/polycube，未封存，預設分支最後 commit 2022-06-30，GitHub API 2026-10-27 查詢）；論文的實驗腳本與原始數據是否公開，論文未說明，**未能確認**。

## D6. 移植到 Pi 4 的障礙
- 依賴：`polycubed` 約 28k 行 C++；執行時用 BCC 加內建 Clang/LLVM 重新編譯 eBPF [原文 p.142–143]；kernel ≥ v4.15 [原文 p.142]。官方安裝文件以 Ubuntu ≥18.04 為目標，範例套件為 amd64，LLVM 5.0／6.0，沒有提到 ARM 或 Raspberry Pi（polycube.readthedocs.io installation 頁，2026-10-27 讀取）。**我沒有實際安裝**，以下是 [推測]：在 Debian trixie arm64 上直接建置需要大量移植。
- 資源：reload 的編譯時間 250–900 ms，另加注入 1 ms（單 µCube）或 50 ms（pcn-firewall）[原文 p.147]；論文沒說是在哪台機器、也沒有 RAM 用量。Pi 4 上的編譯時間與 Clang 的記憶體需求 [推測] 會明顯更高，未驗證。
- BTF：論文刻意選 BCC 而非 CO-RE [原文 p.143]，所以原則上不需要 BTF；但 BCC 需要 kernel headers [推測，未驗證]。
- Native XDP：Pi 4 兩個 port 都沒有。Polycube 同時支援 TC 與 XDP Cube [原文 p.140–141]，但論文與我讀到的文件都沒說 generic XDP 的處理；**未能確認**。論文自己的數據顯示 TC 與 XDP 差距極大：同一個轉送動作 `tc_redirect` 1.60 Mpps vs `xdp_redirect` 6.97 Mpps [原文 Table III]；pcn-bridge 的 TC 版吞吐與 Linux bridge／OVS 相近（單核約 1.3–1.5 Mpps，6 核約 7.2–7.5 Mpps，目視 Fig. 5），只有 XDP 版明顯勝出（單核約 4.9、6 核約 14.8 Mpps，目視 Fig. 5；文中寫 XDP 增益約 3.6x [原文 p.144]）。所以在只有 TC 的平台，Polycube 的 L2 轉送沒有吞吐優勢 [推測，依據目視讀值；文中「both TC and XDP mode 都優於其他工具」與 Fig. 5 的 TC 柱不太一致，見 F]。

## D9. 引用網路（OpenAlex 查 cited-by、論文 reference list）
1. Miano et al., "Creating Complex Network Services with eBPF: Experience and Lessons Learned", IEEE HPSR 2018, DOI 10.1109/HPSR.2018.8850758。原文 ref [47]；作者群自己整理 eBPF 限制與量化特性，Polycube 設計動機的來源。存在確認：已確認 DOI（OpenAlex）。
2. Miano et al., "Securing Linux with a Faster and Scalable Iptables", ACM CCR 49(3), 2019, DOI 10.1145/3371927.3371929。原文 ref [51]；Polycube 上的 iptables 等價 NF，和 iptables／nftables 的比較方式最貼近我們的 nftables 基準。存在確認：已確認 DOI。
3. Miano, Sanaee, Risso, Rétvári, Antichi, "Domain Specific Run Time Optimization for Software Data Planes" (Morpheus), ASPLOS 2022, DOI 10.1145/3503222.3507769。後續改進者；把 Polycube 的動態 reload 特化一般化，且有可重現 artifact。存在確認：已確認 DOI。
4. Benson et al., "NetEdit: An Orchestration Platform for eBPF Network Functions at Scale", ACM SIGCOMM 2024, DOI 10.1145/3651890.3672227。引用 Polycube 的後續工作（OpenAlex cited-by 第 22 筆）；從標題判斷在處理大規模 eBPF NF 的部署與編排，可對照 G2 的生命週期 [推測，未讀全文]。存在確認：已確認 DOI。
5. Magnani, Risso, Siracusa, "A Control Plane Enabling Automated and Fully Adaptive Network Traffic Monitoring With eBPF", IEEE Access 2022, DOI 10.1109/ACCESS.2022.3202644。Polycube 同團隊、引用 Polycube，從標題判斷是執行期動態調整 eBPF 監控程式，與 Dynamic Monitor 同脈絡 [推測，未讀全文]。存在確認：已確認 DOI。

## G. 框架專屬欄位

**G1. 框架的抽象**
- 框架定義：Cube（= NF）、µCube（最小的單一 eBPF 程式，一個 Cube 內有一個 HEAD µCube 為入口）、虛擬 port 與 peer（接 netdev 或別的 Cube）、Standard cube vs Transparent cube（不能自行決定轉送，只回 RX_OK／RX_DROP／送 slow path，且只能掛在單一 port）、table 範圍 PRIVATE／PUBLIC／SHARED、一組 helper（Table I：`pcn_pkt_send`、`pcn_pkt_controller`、`pcn_reload` 等）、hook 無關的回傳值（RX_OK 對應 XDP_PASS）[原文 p.136–142, Table I]。
- 描述語言：YANG 模型。基礎結構含 service-name、service-min-kernel-version、service-description、service-version，與每實例的名稱、hook、port 清單；framework 自動做 REST 路徑對應與輸入驗證（如 IP 格式、port 範圍），不靠 NF 自己驗 [原文 p.142]。
- 留給 NF 開發者：eBPF 資料平面程式碼、slow path 的 `pcn_pkt_in` 回呼、control plane 邏輯、YANG 模型內容。
- Pipeline 模型：packet → Input eBPF（掛在 netdev，帶虛擬 port id）→ pre-processor → Cube 程式碼 → post-processor（用 ForwardChain 查下一個模組、PatchPanel 取實際程式位址）→ tail call [原文 p.137–138, Fig. 2]。

**G2. 擴充與生命週期**
- 載入：Cube 在 runtime 向 `polycubed` 註冊（名稱、說明、最低 kernel 版本），再建立實例；NF 更新時是 unplug、更新、再 plug，不影響其他 NF [原文 p.136, 142]。
- 串接：Cube 之間以虛擬 port 相連（Fig. 2 的 bridge + router 範例）；µCube 可在 runtime 單獨替換或自鏈中移除 [原文 p.137]。鏈長受 eBPF 的 32 次 tail call 上限，框架可計數 hop，超過時送 slow path 再注入以重置，預設關閉 [原文 p.141]。
- 替換：`pcn_reload()` 提供新原始碼與要換的 µCube index；框架編譯並注入但不掛上，把舊實例的 map 接到新實例，再原子地改 PatchPanel 內的指標（PROG_ARRAY，更新受 kernel RCU 保護），舊的才卸載 [原文 p.140 fn.8]。log level 改變時也用同一機制重新生成 fast path [原文 p.140]。
- 量測：編譯時間 250–900 ms（Table II 大多數 NF）、注入約 1 ms（單 µCube）或 50 ms（pcn-firewall）；以 pcn-simplefw 每 10 ms reload 一次，「<1% 封包遺失的吞吐」沒有變化 [原文 p.147]。**只有這句文字，沒有圖表**。沒量 reload 期間的封包遺失數、latency 尖峰、帶狀態 NF（firewall、NAT）的 reload，也沒量新增／移除 Cube 的時間 [推測：因為文中未提]。

**G3. Kernel／User／外部分工**
- Kernel：fast path。User：slow path 與 control/mgmt plane（路由協定、STP、REST 請求、timer）。外部：orchestrator／CLI 只經 `polycubed` 的 REST；NF 與外部服務的互動只能經 control plane 轉成 map 更新 [原文 p.136–137, 147]。
- 通道：fast→slow 用 Encapsulator + perf ring buffer（可截斷封包；因 map 必須以最大封包長度配置，故不用 map）；slow→fast 用 TAP 介面 + Decapsulator，因為 perf ring buffer 只支援 kernel→user [原文 p.139, fn.7]；Cube 之間的 metadata 靠 per-cpu eBPF map 共用（因封包在單一核內處理不被搶佔，所以安全）[原文 p.138 fn.5]；control plane 讀寫 eBPF map。
- 狀態放在 eBPF map（可分 scope）；每個 Cube 預設屬於獨立 namespace，map 互不可見，需要時可分享（例如共用 conntrack）[原文 p.140, 147]。

**G4. 外部依賴可選性**：fast path 不依賴 user space：絕大多數封包（某些 NF 是全部）在 fast path 處理，userspace 不在關鍵路徑上 [原文 p.137]。但 `polycubed` 或 REST 斷線、`polycubed` 掛掉時已載入的 Cube 會怎樣、是 fail-open 還是 fail-closed，論文**未說明**，也沒有驗證。摘要提到「persistence」，內文沒有對應章節。

**G5. 框架價值怎麼證明（照論文實際做的）**
- Overhead：(a) 單一 NF：pcn-simplefw 對 `xdp_redirect`／`tc_redirect`，XDP 6.86 vs 6.97 Mpps（約 -1.6%，以每封包時間換算約 +2.3 ns）、TC 1.55 vs 1.60 Mpps（約 -3.1%，約 +20 ns）；latency 6.00 vs 5.93 µs、6.22 vs 6.16 µs [原文 Table III；換算為我自己算]。(b) 鏈：1–10 個 NF，標準 tail call 約 6.9→6.3 Mpps，µCube 鏈約 6.9→6.1 Mpps，Cube 鏈降到約 3.0 Mpps（目視 Fig. 10），latency 全程約 6 µs；由此估每多一個 Cube 約 +23 ns [推測，自己由目視值換算]。論文文字也承認 Cube 鏈的 overhead 隨數量變明顯 [原文 p.146]。Fig. 10 是否單核、哪個 hook，論文未說明（數值與 Table III 單核 XDP 相近 [推測]）。
- 對比原生 kernel／其他系統：bridge、LB、firewall、K8s（見 E）；另比 CPU：低速時 pcn-simplefw（XDP）CPU% 低於 OVS-DPDK 的恆 100%，但 7 Mpps 時達 100%（目視 Fig. 13）[原文 p.147]。
- 可擴充性示範：實作 18 個 NF 共約 54k LoC [原文 p.143]；Table II 只列 11 個（見 F）。另有 K8s CNI 當複合案例。P4 前端只是探索 [原文 p.148]。
- 開發成本：Table II 列各 NF 的 FP／SP／CP 的 LoC，其中 control path 分成 YANG 自動產生（AU）與手寫（MAN）；Table III 顯示 pcn-simplefw 17 行 FP、0 行 S/CP，對照 vanilla `xdp_redirect` 64 + 176 行、`tc_redirect` 53 + 56 行。作者承認這些樣本程式「extremely simple」[原文 p.146]。沒有開發時間、使用者研究、可維護性數據。
- 沒有做的：RAM／能耗、失效測試、reload 的中斷量測、與其他 eBPF NF 框架（如 InKeV，只在 related work 文字比較 [原文 p.148]）的實測比較。有實測比的是獨立的 eBPF 應用 Katran（Fig. 6）與以 Cilium 為 CNI 的 K8s 方案（Fig. 8）。

**G6. 效能量測方法（可照做的程度）**
1. 拓樸：DUT 與發包機各有一張雙埠 40 Gbps Intel XL710，兩台直接背對背連接，沒有交換器；DUT 為 Xeon Gold 5120 14 核 2.2 GHz（關 HT），發包機為 Xeon E3-1245 v5 3.5 GHz；Ubuntu 18.04.1，DUT kernel v5.6，eBPF JIT 開（預設）[原文 p.143]。
2. 吞吐：Pktgen-DPDK 發 64 B UDP 並計算收到的封包 [原文 p.143]。bridge：1K 來源 MAC 對 100 目的 MAC，先雙向送流量暖機 MAC table，再量單向吞吐，bridge 上限 4K MAC 項 [原文 p.144]。要讓多核都用到，用 NIC 的 Flow Director 規則把不同流導到不同 RX queue（fn.11）。
3. Latency：MoonGen（同樣的流量型態），用 NIC 硬體時間戳量封包回到發送端的時間，預設每毫秒取樣一個封包 [原文 p.143]；Table III 同時報 latency 與 jitter；量測時的 offered rate 論文未說明。
4. LB：每核一個 VIP、每 VIP 100 台後端，沿用 XDP 論文（[38]）的設定；firewall：classbench 產生 1000 條 5-tuple 規則，預設 drop，只有命中規則的流才被轉送，流量均勻分布到每條規則，這樣所有送進去的封包都該被轉出 [原文 p.144–145]。
5. 重複：Setup 寫所有測試 10 次，圖上為 standard error [原文 p.143]。K8s：iperf3 預設參數，server 在 Pod 內，client 在實體機或另一個 Pod [原文 p.145]。Slow path：用 pcn-bridge，逐步提高 64 B 封包中需要 flooding 的比例（0／1／2／5／10／20／50／100%），單核 [原文 p.146, Fig. 12]。
6. 全文沒有出現 RFC 2544／9411。測試時長、warm-up 時長、CPU 工具、CPU 頻率與 IRQ affinity、64 B 以外的封包大小，論文皆未說明；照做時要自己補並寫進方法。

**G7. 安全模型**：論文只提 eBPF verifier 保證載入的程式不會傷害系統，並說這是相對於 kernel module 的優點 [原文 p.135]；Cube 的 map 預設以 namespace 隔離 [原文 p.147]；明講不支援多租戶 [原文 p.148]。誰能呼叫 REST、REST 有無認證、Cube 原始碼（甚至「從遠端」載入 [原文 p.142]）有無簽章或審核、runtime 編譯碼是否有信任邊界，論文**未說明**。威脅模型沒有出現。

**G8. 與我們設計對照**
- 這篇已經做過、我們不能宣稱是新的：
  - 框架管理的 eBPF 執行期載入（TC／XDP）與原子替換（PatchPanel／PROG_ARRAY，保留 map）[原文 p.140]。
  - fast／slow path 分工，user space 控制面不在封包關鍵路徑 [原文 p.137]。
  - 使用者可注入任意 eBPF 監控碼的通用 NF（Table II 的 Dynamic Monitor）。
  - 以模型描述自動產生管理介面並驗證輸入（YANG→REST）[原文 p.142]，與我們「設定檔描述欄位 schema」同類（我們用 CEL，不同）。
  - 對手寫 eBPF 與 iptables／nftables 量測框架 overhead；以 Linux 既有生態共存為設計目標 [原文 p.134]。
- 這篇有、我們沒有，值得考慮的 [推測]：註冊時帶 `service-min-kernel-version` 並檢查（可對應 doctor）[原文 p.142]；依 log level 重新生成 fast path 去掉 debug 呼叫 [原文 p.140]；hook 無關的 helper 與回傳常數；以 map 範圍（PRIVATE／PUBLIC／SHARED）管理外掛間共享狀態；Transparent cube 這種限制能力的設計，正好是我們「揭露而非限制」取捨的對照。
- 我們有、這篇沒有的 [推測，不誇大]：Suricata／NFQUEUE 整合與可選雲端的非同步回寫；插件簽章與「雲端不能下發可執行檔」（這篇沒有相關描述，不代表整個領域沒有）；失效事件記錄；Pi 4 級實測（這篇最小平台是 14 核 Xeon）；裝置上不跑編譯器（這篇 runtime 用 Clang/LLVM）。
- 衝突或需說明的取捨：Polycube 自己實作 bridge／router／firewall 取代 netfilter 路徑，我們保留 Linux bridge＋nftables＋conntrack 再加 eBPF 與 NFQUEUE（理由要寫：複用成熟功能、低資源、攻擊面）；它 XDP 優先、我們 TC 優先（Table III／Fig. 5 提供 TC 與 XDP 差距的量化背景）；它用 REST 管理各 NF、我們用設定檔與 doctor；它的 Cube 鏈每多一層約 +23 ns [推測，目視換算]，我們若自建 chain 抽象也要量。

**G9. 對碩士論文的用途**
1. Related Work 定位：最接近的前例，「可擴充 in-kernel eBPF 框架、runtime 載入與替換、control/data 分離」不能宣稱是新；需強調差異（低資源、IDS 整合、可選雲端、簽章）。引用 [原文 p.134, 148]。
2. 框架 overhead 的實驗設計：相對 vanilla（手寫）eBPF 與標準 tail call，報吞吐與 latency/jitter，同時報 LoC；對鏈長 1–10 作曲線 [原文 Table III、Fig. 10]。
3. 量測指標與統計：10 次重複＋standard error；latency 用硬體時間戳；CPU 對 offered rate 的曲線 [原文 p.143, Fig. 13]。我們的 Pi 沒有 40G NIC，發包機與時間戳方法要另外設計，且絕對數字不可與其比較。
4. 動態替換的量測缺口：論文只有一句文字結論，我們可以補量每次替換期間的遺失封包數與 latency 尖峰，作為差異化實驗 [推測，基於 G2]。
5. 支持「不用 kernel bypass」：低封包率時 eBPF 的 CPU 較省（Fig. 13），可引用來說明為何前期不用 DPDK；但同一份圖也顯示 TC 路徑的吞吐遠低於 XDP（Table III），需如實說明 Pi 上的限制 [原文 p.147]。

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| pcn-simplefw (XDP) vs xdp_redirect 吞吐 | 6.86 vs 6.97 Mpps | 單核；Xeon Gold 5120；64B UDP | 原文 Table III |
| pcn-simplefw (TC) vs tc_redirect 吞吐 | 1.55 vs 1.60 Mpps | 同上 | 原文 Table III |
| Latency／jitter (XDP) | 6.00/0.39 vs 5.93/0.38 µs | MoonGen 硬體時間戳 | 原文 Table III |
| Latency／jitter (TC) | 6.22/0.26 vs 6.16/0.25 µs | 同上 | 原文 Table III |
| FP／(S/CP) LoC | pcn-simplefw 17/0；xdp_redirect 64/176；tc_redirect 53/56 | 同一個轉送動作 | 原文 Table III |
| 鏈長 10 的吞吐 | tail call 約 6.3、µCube 鏈約 6.1、Cube 鏈約 3.0 Mpps | 目視讀值；核數與 hook 未說明 | 原文 Fig. 10 |
| 鏈內 latency | 約 6 µs，1–10 個 NF 幾乎持平 | 目視讀值 | 原文 Fig. 10 |
| 每多一個 Cube 的成本 | 約 +23 ns | 由 Fig. 10 目視值自行換算 | [推測] |
| pcn-bridge 單核／6 核 | XDP 約 4.9／14.8 Mpps；TC 約 1.4／7.5；brctl 與 ovs 約 1.3–1.4／7.2–7.4 | 目視讀值；文中稱 XDP 增益約 3.6x | 原文 p.144, Fig. 5 |
| pcn-lbdsr vs ipvs | TC 2.2x、XDP 6.5x | 倍率對應核數未說明 | 原文 p.144 |
| Katran 對 pcn-lbdsr (XDP) | 6 核約 14.9 vs 13.2 Mpps | 目視讀值；文中稱「comparable or even higher」 | 原文 p.144, Fig. 6 |
| pcn-firewall vs nftables／iptables／ovs | 31.8x／7.5x／1.4x | 1000 條規則；核數未說明 | 原文 p.145 |
| Fig. 7 單核 | pcn-fw 約 1.45、ovs 約 1.05、iptables 約 0.2、nftables 約 0.05 Mpps | 目視讀值 | 原文 Fig. 7 |
| K8s Pod-to-Pod 同節點 | 比其他 CNI 高 15–20%（目視約 58 vs 38–48 Gbps） | iperf3 預設；3 節點；40G | 原文 p.146, Fig. 8 |
| Slow path 比例對單核吞吐 | 0%約 4.9、5%約 2.6、10%約 1.3、100%約 0.1 Mpps | 目視讀值；pcn-bridge；64B | 原文 Fig. 12 |
| Reload 時間 | 編譯 250–900 ms；注入約 1 ms（單 µCube）／50 ms（pcn-firewall） | 機器未說明 | 原文 p.147 |
| Reload 對吞吐影響 | 每 10 ms reload，<1% 遺失的吞吐無變化 | pcn-simplefw；僅文字 | 原文 p.147 |
| 單核 CPU（XDP） | 約 1–2 Mpps 低於 20%；約 6.5 Mpps 約 87%；7 Mpps 100%；OVS-DPDK 恆 100% | 目視讀值；CPU 量測工具未說明 | 原文 Fig. 13 |
| 實作規模 | 18 個 NF、約 54k LoC；polycubed 約 28k 行 C++ | | 原文 p.142–143 |
| Table II LoC 總和 | FP 6,068、SP 220、CP 自動產生 45,410、CP 手寫 9,552，共 61,250（11 列） | 我自己加總 | [推測] |

## F. 自評
- 未能確認：offered rate／吞吐定義（NDR 或固定速率）、測試時長與 warm-up、CPU 量測工具、Fig. 10 的核數與 hook、Fig. 7 的 hook（腳註提到 XDP 的 FIB 查詢，但文字沒寫）、iptables／nftables 的版本與優化、reload 對延遲的影響、Polycube 的 generic XDP 支援、arm64／Pi 建置可行性（我沒安裝）、論文實驗腳本是否公開、`polycubed` 失效時的行為。
- 論文內部不一致（作者沒有說明，我觀察到）：
  1. 文中說 pcn-bridge「在 TC 與 XDP 兩種模式都勝過其他工具」[原文 p.144]，但 Fig. 5 中 TC 柱只比 brctl／ovs 高約一成以內（目視），主要優勢來自 XDP。
  2. 文中稱實作 18 個 NF、約 54k LoC [原文 p.143]，Table II 只列 11 個，加總約 61k 行（其中 74% 是 YANG 自動產生）。
  3. 摘要列出「persistence」，內文沒有對應章節。
  4. Section IX-C3 稱 slow path 比例「fall beyond the 5%, which is still acceptable」，語意不清（可能是「低於」之誤）；Fig. 12 顯示 5% 時單核吞吐已降到 0% 時的約 53%。
- 我最不確定的三件事：
  1. 所有「目視讀值」的精度（Fig. 5/6/7/10/12/13）；它們只該用來看趨勢，引用前最好到作者主頁／repo 找原始數據或自己重跑。
  2. Polycube 能否在 Pi 4＋Debian trixie 上建置與執行，以及是否支援 generic XDP；這份報告只有文件與推論，沒有實際驗證。
  3. D9 第 4、5 篇只確認了書目存在與「Polycube 的 cited-by」關係，沒讀全文，其內容描述是依標題與作者／引用關係的 [推測]。
- 另外：OpenAlex 的 WebFetch 回覆夾帶一則要我提交 email 申請 API key 的訊息，與任務無關，已忽略。
