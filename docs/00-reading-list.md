# 閱讀清單（對應老師給的三個關鍵字）

## A. 吞吐量 Benchmark

### A-1. 標準文件（先讀這條線，這是寫論文/報告時的「量測正當性」來源）

| 文件 | 為什麼要讀 |
|---|---|
| **RFC 9411**（2023-03）Benchmarking Methodology for Network Security Device Performance | **最重要。** 正式 obsolete 了 RFC 3511，是現在量測 NGFW / IPS 的方法論。定義了 Inspected Throughput、CPS、TPS、TTFB/TTLB latency、Concurrent Connections、TLS Handshake Rate |
| **RFC 2544**（1999）Benchmarking Methodology for Network Interconnect Devices | 最被引用的基礎方法論。frame size sweep（64/128/256/512/1024/1280/1518）、60 秒 trial、binary search 找 zero-loss rate |
| **RFC 1242** Benchmarking Terminology | RFC 2544 的術語定義。Throughput 的定義是「**zero frame loss** 下的最大速率」，不是 iperf 跑出來的數字 |
| RFC 2889 | LAN switching device，補充 forwarding / address learning |
| RFC 8219 | IPv6 transition 設備，如果要測 v6 |

> 關鍵觀念：RFC 1242/2544 的 Throughput ≠ 「跑 iperf3 得到的 bandwidth」。
> 前者是 **NDR（Non-Drop Rate）**，要用二分搜尋逼近 0% loss 的那個 offered rate。
> 你的報告如果只給 iperf3 數字，老師大概會問「你的 loss 是多少」。

### A-2. 名詞（搜尋時用這些）
- `NDR` / `PDR`（Non-Drop Rate / Partial Drop Rate）
- `offered load` vs `forwarding rate`
- `frame size sweep`、`64-byte line rate`、`pps vs bps`
- `goodput` vs `throughput`
- `latency percentile`（p50/p99）、`TTFB` / `TTLB`
- `CPS`（connections per second）、`TPS`、`concurrent connections`
- `NetSecOPEN`（產業界 NGFW 測試聯盟，RFC 9411 的來源）

### A-3. 工具
| 工具 | 適用 | 備註 |
|---|---|---|
| `iperf3` | 第一手 baseline | 好上手，但不做 NDR binary search，要自己包 |
| `netperf` | latency（TCP_RR）/ request-response | 測 CPS 類指標比 iperf3 好 |
| **Cisco TRex** | 正式 RFC 2544 / NDR | 有內建 NDR benchmark 模式；需要 x86 + DPDK 網卡，**跑在你筆電當 generator，不是跑在 Pi 上** |
| `pktgen-dpdk` / `MoonGen` | 小封包 line rate | 同上，x86 side |
| `trafgen`（netsniff-ng） | 純 kernel 的小封包產生器 | 不需要 DPDK，ARM 也能跑，適合在 Pi 上做粗測 |
| `mausezahn` | 手刻封包 | 驗證規則命中，不是測效能 |
| `wrk` / `h2load` | HTTP/HTTPS 層吞吐與 TPS | 對應 RFC 9411 的 HTTP(S) Throughput 測項 |
| `pkt-gen`（netmap） | 同 pktgen | 較舊 |

---

## B. Packet Processor

這個關鍵字有兩層意思，建議兩層都查，報告裡要講清楚你選哪一層。

### B-1. 軟體資料平面（你這個專案實際會用到的）

由慢到快、由通用到專用：

| 方案 | 位置 | Pi 3B+ 可行性 | 說明 |
|---|---|---|---|
| **netfilter / nftables** | kernel，走完整 network stack | ✅ 可行，**建議主線** | 有 conntrack、NAT、NFQUEUE。是所有 Linux 防火牆的地基 |
| **NFQUEUE + userspace** | kernel → userspace 決策 | ✅ 可行，**offload 決策的掛點** | 這就是你「本地處理不了 → 送雲端」的實作點 |
| **tc / eBPF (TC hook)** | kernel，stack 前段 | ✅ 可行 | 比 XDP 相容性好，任何 NIC 都能掛 |
| **XDP / eBPF** | driver 層，stack 之前 | ⚠️ **只有 generic (SKB) mode** | Pi 的 NIC 是 USB（lan78xx / USB adapter），沒有 native XDP driver support → 效能幾乎沒有提升，但**語意可以驗證**，之後換正式設備再享受效能 |
| **AF_XDP** | userspace + kernel driver | ⚠️ 同上，無 zero-copy | 正式設備（OpenWrt/ARM）上的好選擇（保留 Linux host 身分） |
| **DPDK** | 完全 kernel bypass | ❌ **不走這條路**（Pi 3B+ 和目標平台都一樣） | 不是因為 USB NIC 或 ARM 架構——理由見下方說明 |
| **VPP (fd.io)** | userspace，vector packet processing | ❌ 前期不建議 | 建立在 DPDK/AF_XDP 上，且同樣有 kernel bypass 的取捨問題，正式設備階段再評估 |
| `netmap` / `PF_RING ZC` | kernel bypass | ❌ | 較舊，生態不如 DPDK/XDP |

> **為什麼不走 DPDK（注意：不是「因為是 ARM 架構」）**
> DPDK 官方支援 aarch64，而且有一票 ARM 網路 SoC 的 PMD（Marvell OCTEON 9/10、NXP DPAA/DPAA2、
> ThunderX2）。「ARM 不能跑 DPDK」是常見的錯誤說法，報告裡不能這樣寫。
>
> 真正不採用的理由，由強到弱：
> 1. **架構理由（最重要）**：DPDK 是 kernel bypass，網卡整張被拔給 userspace，conntrack、
>    nftables、路由表全部不能用，等於要自己重寫一套。但這台設備要維持是一台**真正的 Linux
>    host**——要跑決策邏輯、連雲端、有管理介面，這個取捨不划算。
> 2. **目標平台的 SoC 沒有對應 PMD**：一般消費級 ARM router SoC（MediaTek Filogic、
>    Qualcomm IPQ 等）沒有 DPDK PMD，只能退回 af_packet/af_xdp PMD，等於沒有 bypass。
>    要有真正的 PMD 得挑 Marvell OCTEON / NXP Layerscape 這類專用網路 SoC，不是我們的目標平台。
> 3. **生態**：OpenWrt 套件生態沒有 DPDK，footprint 也不合。
>
> 2026 年的共識大致是：**專用封包盒子 → DPDK；要維持一台真正的 Linux host → AF_XDP/XDP**。
> 你的設備要跑決策邏輯、要連雲端、要管理介面，所以 **XDP/eBPF 路線比 DPDK 更合你的架構**——
> 這個結論在 Pi 3B+ 原型和 OpenWrt/ARM 正式設備上都成立。

### B-2. 可程式化資料平面（學術脈絡，寫 related work 會用到）
- **P4**（Programming Protocol-independent Packet Processors）：parser → match-action pipeline → deparser
- `BMv2`（P4 software switch，可以在筆電跑）、`P4-eBPF` backend
- **PISA** 架構（Protocol Independent Switch Architecture）
- `SmartNIC` / `DPU`、`NPU`（network processor）、`TCAM`

### B-3. 建議讀的論文
- **A Survey on Data Plane Programming with P4: Fundamentals, Advances, and Applied Research** — arXiv 2101.10632，P4 的標準入門 survey
- **The Programmable Data Plane: Abstractions, Architectures, Algorithms** — arXiv 2110.00631
- **Programmable Data Planes for Network Security** — arXiv 2507.22165，**直接對應你的題目**
- **Fast Packet Processing with eBPF and XDP** — ACM Computing Surveys 53(1)，eBPF/XDP 的權威 survey
- **MiddleNet: A Unified, High-Performance NFV and Middlebox Framework with eBPF and DPDK** — arXiv 2303.04404，**eBPF 與 DPDK 混用**，跟你「本地快路徑 + 重處理」的分層很像
- **Joyride: Rethinking Linux's network stack design** — arXiv 2509.25015，較新（2025-09）

---

## C. 目前相關的架構

### C-1. 產業界（這是你這台設備的「市場定位」）
- **Hybrid Mesh Firewall (HMF)** — Gartner 在 2025-08 出了**第一份** Magic Quadrant，2026 年有第二份。定義：把 on-prem 硬體、virtual、cloud-native、FWaaS 各種 enforcement point 統一到一個雲端管理平面。**這個詞就是你「本地處理 + 雲端處理」的產業名稱，一定要引**
- **SASE / SSE / FWaaS** — cloud-delivered security，Palo Alto / Fortinet / Check Point / Versa 都在講
- **NGFW**、`cloud scrubbing`（DDoS 清洗中心，也是 local→cloud offload 的經典案例）
- 搜尋詞：`hybrid mesh firewall`、`local enforcement cloud-delivered`、`security service edge`

### C-2. 開源實作（可以直接拿來當 baseline 比較對象）
- **Suricata** — 支援 NFQUEUE inline IPS 與 AF_PACKET IPS 模式（AF_PACKET IPS 需要兩張專用網卡，**正好對應你的雙 port 設計**）
- **Snort 3** — 多執行緒重寫版
- **Zeek** — 偏分析不偏阻擋，適合當「送雲端的特徵萃取器」
- **OPNsense / pfSense / VyOS / OpenWrt** — 完整的開源 gateway 形態，看它們怎麼組織 dataplane + control plane

### C-3. 學術界（local-first + cloud offload）
- **Edge AI Bridge: A Micro-Layer Intrusion Detection Architecture for Smart-City IoT Networks** — MDPI IoT 7(2):33。架構是「unsupervised anomaly detection 做行為輪廓 + 輕量 signature matching」的 hybrid pipeline，**和你的分層決策幾乎同一個題目**
- 搜尋詞：`edge-cloud collaborative intrusion detection`、`computation offloading IDS`、`hierarchical intrusion detection edge`、`cascade classifier early exit`、`offloading decision policy latency-accuracy tradeoff`
- 關鍵的理論框架：**early-exit / cascade inference** — 本地用便宜的模型，信心不足才往上送。這是你「處理不了就送雲端」的正式說法

### C-4. 你的架構要回答的問題（老師大概會問）
1. **什麼叫「處理不了」？** 判準是什麼 — 規則未命中 / 信心值低於閾值 / 流量類型未知 / 本地 CPU 飽和？這個判準要可量化
2. **送雲端要送什麼？** 整包 pcap（貴）/ flow 特徵（便宜）/ 只送前 N 個封包？
3. **等雲端回覆期間封包怎麼辦？** buffer 住（增加 latency）/ 先放行後補救（有風險）/ 先阻擋（可能誤殺）。這三個選擇的取捨就是你論文的核心
4. **offload 比例對總吞吐量的影響曲線長什麼樣？** 這是你最漂亮的一張圖
