# slide_implement.md — Security Gateway 開發規劃

> 定義每一頁投影片要有什麼內容。**本文件與 `src/main.typ` 同步**，是重做或交接時的依據。
> 對應草稿：`user_draft.md`　對應講稿：`逐字稿.md`

---

## 0. 全域規範

### 0.1 報告定位
- **這是「實驗才剛開始」的開發規劃報告。**說明「打算做什麼、大概怎麼做」，不是成果。
- 全部用規劃語氣。很多事情**還沒研究出來**，語氣要反映這件事。
- ❌ **不得出現「目前已經做到哪裡」的實作進度陳述。**
- ❌ **不得推估或宣稱任何效能數字**（吞吐量、延遲、pps…）—— 還沒量過。
- ❌ **不放實機截圖、終端機輸出、程式碼片段。**所有視覺元素都是自繪的圖表。
- ❌ **不解釋「為什麼選這個硬體」，也不談硬體的效能限制。**硬體是既定前提。
- ❌ **寫給製作者看的註記（`>` 引言、⚠️ 標記）不得印到投影片上。**

### 0.2 敘述深度原則 ★這份報告最重要的編輯原則
**投影片只放「是什麼」，「為什麼」「細節」「舉例」一律進逐字稿用講的。**

具體表現：
- 表格只留關鍵欄位（規則只寫來源＋授權、引擎只寫名字）
- 不寫推論與結論（介紹方法時只描述，比較與選擇留到「目前選擇」那頁）
- 不寫舉例（例如「黑名單 IP、畸形封包、洪水」放講稿）
- 留白是可接受的，**不要為了填滿版面加東西**

### 0.3 已定案的前提
| 項目 | 定案 |
|---|---|
| 實體原型 | Raspberry Pi 3 Model B+ / Raspberry Pi OS Lite 64-bit |
| 最終目標平台 | **OpenWrt + ARM Based 設備**（型號未定） |
| 模擬環境 | **Docker** 三節點（gw 容器規劃以 OpenWrt 為基底，**此事只在講稿提，不上投影片**） |
| 封包處理路線 | **方法 1：留在 kernel 內（XDP + netfilter/nftables）** |
| DPDK | 不採用 |

### 0.4 不能寫錯的事實 ★每一條都查證過，寫錯會被當場問倒
1. **DPDK 支援 aarch64。**官方有 Marvell OCTEON、NXP DPAA 的 PMD，`rte_acl` 還有 NEON 最佳化。
   **絕不可寫「因為 ARM 所以不能用 DPDK」。**不採用的理由見 P9。
2. **ET Open 的授權是 BSD + GPLv2 混合，不是 MIT。**
   依據是規則集 tarball 自帶的 `LICENSE`（sid 2000000–2799999 為 BSD，沿襲 Snort 舊 sid 為 GPLv2）。
   ⚠️ 「MIT」不是網路訛傳 —— 它寫在 **OISF 官方的 `suricata-intel-index/index.yaml`**
   （`license: MIT`），跑 `suricata-update list-sources` 就會看到。但那與規則集自帶的授權檔不符，
   **以 tarball 內的 `LICENSE` 為準**。被問到時要能講出這個出處，不要說「網路上寫錯」。
3. **OpenWrt 25.12 起套件格式是 `.apk`（apk），24.10 以前才是 `.ipk`（opkg）。**
   官方套件庫可直接驗證。（此事只在講稿出現。）
4. **XDP 沒有「內建」conntrack，但不是「不能」。**
   kernel **5.18** 起有 `bpf_xdp_ct_lookup()` kfunc，可以查、只是要自己寫 BPF。
   所以表格欄位寫「**內建 conntrack**」，答 ✗ 才正確。
5. **Docker 測得到真實網卡與 native XDP**（`--network host` 或把實體卡搬進 netns）。
   **樹莓派反而測不到 native XDP** —— Pi 3B+ 是 USB 網卡（`lan78xx`），USB 網路 driver 沒有 `ndo_bpf`。
   所以第 5 頁**不可寫「樹莓派能驗證真實網卡 driver 行為／XDP 模式」**。
6. **OpenWrt 22.03 起預設防火牆是 firewall4，底層是 nftables。**
7. **OpenWrt 的 software / hardware flow offload 由 kernel 的 netfilter flowtable 驅動。**
   這是 P10 理由 2 的根據：DPDK 拿走網卡 → flowtable 沒了 → 硬體加速路徑一併消失。

### 0.5 技術規格
- 工具：**Typst v0.15.1**；框架 `@preview/slydekit:0.4.1`（metropolis 主題、topbar 導覽）
- 繪圖：`@preview/fletcher:0.5.8`，必要時 `@preview/cetz:0.4.2`
- 中文字型 **Noto Sans CJK TC**，等寬 **Noto Sans Mono CJK TC**；16:9
- 共用樣式在 `slides/template.typ`；編譯用 `slides/build.sh`（會自動處理 `--root` 與檔名）
- **實體 17 頁** = 封面 1 + 章節分隔頁 4 + 內容 12

### 0.6 視覺一致性
- **架構圖的節點與邊標籤一律用英文**；內文說明用中文
- 內網／LAN 一律畫**左**，外網／WAN 一律畫**右**，雲端一律畫**上**
- 語意色：LAN `c-lan`、WAN `c-wan`、雲端 `c-cloud`、強調 `c-stage3`、警告 `c-bad`
- ⚠️ `#callout(title: ...)` 的 title 在 metropolis 主題下**不會渲染**，標題要寫進內文第一行

---

## P1 — 封面
- 標題：**Security Gateway 開發規劃**（此字串同時決定 PDF 檔名，空格會換成底線）
- 日期：2026-09-21
- **不要副標。**

## P2 — 大綱
四項，**必須與四張章節分隔頁一字不差**：
1. 實體與模擬環境建立
2. Packet Processor 介紹
3. Benchmark
4. 可用的規則與引擎

---

# 1. 實體與模擬環境建立（P3–P6）
> **本節只講環境建置：我們在什麼東西上面做實驗。**
> 🔒 **不要放處理程式的內部架構**（三階段管線那些）—— 那屬於第 2 節。

## P3 — 設備的目標形態
**圖（fletcher，節點標籤英文）**
```
                    Cloud Analysis
                          ↑ uncertain
                          │
 LAN Client ──LAN port──→ Security Gateway ──WAN port──→ Internet
```
- 雲端在**上方**；`uncertain` 標籤放虛線**左側**，避免跟 `WAN port` 黏在一起
- 要點兩條：
  - **兩個網路 port**：內外網分離，安全閘道器在流量的必經路徑上。
  - **閘道器判斷不出來**：送雲端分析

> **製作者注意**：**不要寫「非同步」，也不要寫「不在轉發的主路徑上」。**
> 那預設了「不扣住封包等雲端回覆」這個策略，而等待期間怎麼處理**還沒決定**。

## P4 — 實體環境
**圖：laptop 迴路**
- 一個虛線方塊標 `Same Laptop`，**裡面**兩個小方塊：`LAN (netns)`（左）、`WAN`（右）
- 下方 `Raspberry Pi`，兩條弧線：laptop → Pi 標 `LAN port`（左）、Pi → laptop 標 `WAN port`（右）
- ⚠️ 用「一個方塊裝兩個介面」，**不要用外框去圈兩個分離的方塊** —— fletcher 的框線會被格線欄寬牽動、圈不準

**表格**

| | 前期原型 | 最終目標 |
|---|---|---|
| 硬體 | Raspberry Pi 3 Model B+ | ARM Based 設備 |
| OS | Raspberry Pi OS Lite 64-bit | **OpenWrt** |

**要點一條**：閘道器是 Raspberry Pi 3 Model B+，內建網口 + 一張 USB 網卡湊出兩個 port

> **製作者注意**：netns 的坑（不隔開的話封包會走 loopback、不經過閘道器）**放講稿，不上投影片**。

## P5 — 模擬環境
**圖：Docker 三節點（橫向，標籤英文）**
```
cli / LAN client ──lan network──→ gw / gateway container ──wan network──→ srv / WAN server
```
**要點兩條**
- 用 **Docker** 搭三個容器節點模擬「內網 → 閘道器 → 外網」，**閘道器容器掛在兩個網段上**，對應實機的雙 port
- 用途：在動實機之前，先在模擬環境驗證網路拓撲與 nftables 規則

> **製作者注意**：**不要寫「容器基底用 OpenWrt」**，那放講稿。

## P6 — 為什麼兩個環境都要
**開頭兩句（雙向）**
- 每改一次規則就要搬上樹莓派重測，迭代太慢，所以**邏輯的部分先在 Docker 驗**。
- 但 **Docker 容器共用 host 的 kernel**，有些東西它驗不到。

**兩條要點**
- **Docker 能夠驗證**：nftables 規則語意、conntrack、NFQUEUE 的決策流程
- **樹莓派能夠驗證**：aarch64 指令集、資源受限環境下的行為、實體雙 port 接線與部署流程

> 🔒 **製作者注意（重要）**：樹莓派那條**不可以寫「真實網卡 driver 的行為」或「XDP native/generic」**。
> 見 0.4 第 5 條 —— Docker 其實測得到，而樹莓派因為是 USB 網卡反而測不到 native XDP。

---

# 2. Packet Processor 介紹（P7–P10）
> 敘事順序：先講**兩種方法**、各自結構長怎樣 → 再切入我們的選擇。
> **介紹階段只描述，不比較、不下結論**；比較與理由集中在 P10。

## P7 — 封包分析的兩種方法
**圖：左右並排兩個縮圖**
- 方法 1：`NIC → kernel: XDP + netfilter →(if needed)→ user space`
- 方法 2：`NIC → PMD driver →(✗ bypass)→ user space app`
- ⚠️ 兩個縮圖的 `spacing` x 要夠大（目前 4.2em），否則邊標籤會壓到方塊

**對照表**

| | 方法 1：留在 kernel 內 | 方法 2：kernel bypass |
|---|---|---|
| 代表技術 | **XDP + netfilter / nftables** | **DPDK** |
| 封包走向 | 走 kernel 的網路路徑 | **繞過 kernel**，直接進 user space |
| 網卡歸屬 | 仍屬於作業系統 | **整張交給 user space 程式** |

## P8 — 方法 1：留在 kernel 內（XDP + netfilter）
**圖：kernel 內的路徑**
```
NIC → XDP → Network Stack → netfilter / nftables → Routing
                                    ↓
                            NFQUEUE / user space decision
```
**能力對照表**

| | XDP | netfilter / nftables |
|---|---|---|
| 位置 | stack 前 | stack 內 |
| 適合做 | 無狀態即可判定 | 需要連線狀態才能判的 |
| **內建 conntrack** | ✗ | ✓ |
| 能處理 IP 分片 | ✗ | ✓ |
| 能交給 user space | ✗ | ✓ 透過 NFQUEUE |

**兩行說明**
- **現成可參考的實作**：`xdp-filter` —— 比對 IP／port／MAC，**刻意不做複雜比對**以換取極高的丟包速率。
- **可用的函式庫**：`libbpf`／`aya`（XDP）、`libnftnl`／`rustables`（nftables）、`libnetfilter_queue`／`nfq`（NFQUEUE）。

> **製作者注意**：
> - 這頁是全份最擠的，表格字級 0.73em 是放得下的上限，**不要再加內容**。
> - 「內建 conntrack」不可改成「能 conntrack」（見 0.4 第 4 條）。
> - 「能交給 user space：XDP ✗」是**對的，不要「修正」它**。
>   AF_XDP 確實能把封包送進 user space，但那等於離開 kernel 的網路路徑（跟 DPDK 同類），
>   而本頁的框架是「留在 kernel 內」。這一格問的是
>   「送 user space 判斷完能不能**取回 verdict 繼續走 kernel 路徑**」—— NFQUEUE 可以，XDP 不行。
>   被問到時的完整答法在逐字稿。
> - IP 分片的規避手法、無狀態判定的例子**放講稿**。

## P9 — 方法 2：kernel bypass（DPDK）
**圖**：`NIC → PMD driver →(✗ bypasses kernel stack)→ user space app (own polling loop)`

**表格**

| | 得到 | 失去 |
|---|---|---|
| DPDK | 極高的封包處理效能 | **conntrack、nftables、路由表全部不能用** |

**一行說明**：**現成可參考的實作**：`rte_acl` —— 分類函式庫，支援優先序與多重比對，搭配官方 `l3fwd` 範例的 ACL 模式。

> **製作者注意**：**不要在這頁比較兩種方法、也不要下結論**（例如「所以不選 DPDK 是架構取捨」）——
> 那些屬於 P10。這頁跟 P8 要同型：圖 → 表格 → 純敘述。

## P10 — 目前選擇：方法 1
**兩個理由（只有兩個，不要加第三個）**

1. **OpenWrt 上的主流做法就是這套**：官方 feed 裡的 `snort3`、`kmod-nft-queue`、`libnetfilter-queue` 都是使用這個方法。
2. **用 DPDK 會讓 OpenWrt 的 offload 全部失效**：OpenWrt 的 software flow offload 與 hardware flow offload（MediaTek PPE 等）都是由 kernel 的 netfilter flowtable 驅動的。網卡一旦交給 DPDK，**這些加速路徑就不存在**，等於退回純軟體轉發。

> **製作者注意（為什麼只有兩個理由）**：
> - 曾經有第三個理由「已有的 nftables 規則要重寫」，**已刪除** ——
>   那是**路徑依賴**：只在「我們已經選了 nftables」的前提下成立，
>   一開始就走 DPDK 的話模擬與開發都在 DPDK 生態裡，不存在換生態的問題。會被當成循環論證。
> - 也不要寫「這台設備要維持是一台完整的作業系統」——
>   那可以被「多接一張管理網卡」反駁，不夠硬。
> - Cloudflare 的案例、DPDK 對 ARM 的澄清**都放講稿**。

---

# 3. Benchmark（P11）
> 草稿要的是「有哪些 benchmark 可以測試」，所以**直接列指標**，不先講方法論。

## P11 — 可以量的指標
**兩欄、純英文列點、不分先後期、不加任何說明文字**

| | |
|---|---|
| Throughput | NDR / PDR |
| Latency | Frame size sweep |
| Packet loss rate | pps / bps limits |
| CPU utilization | Latency percentile (p50 / p99) |
| Concurrent connections | TTFB / TTLB |
| CPS / TPS | TLS handshake rate |

> **製作者注意**：
> - 每個指標的中文解釋**全部放講稿**，投影片只有名稱。
> - RFC 2544 / 9411 / 1242 的方法論**曾經有獨立一頁，已刪除** ——
>   現階段只是介紹，講 RFC 會失焦。改放講稿，被問「怎麼量才算數」時再拿出來。
> - 括號用半形，避免全形括號撐寬導致換行。

---

# 4. 可用的規則與引擎（P12）
> 只說**有哪些來源**，不展開怎麼挑、怎麼裁、怎麼部署。

## P12 — 規則來源與開源引擎
**左右兩欄**

**左：規則**

| 來源 | 授權 |
|---|---|
| **ET Open** | **BSD + GPLv2** |
| **Snort 3 Community** | **GPLv2** |
| Snort Registered | 免費，需註冊 |
| Snort Subscriber | 付費 |

**右：開源引擎**（只寫名字）
- **Suricata**
- **Snort 3**
- **Zeek**

> **製作者注意**：維護者、說明、各引擎的特性、威脅情報 blocklist **全部放講稿**。

---

## P13 — Q & A
用 slydekit 的 `#focus-slide[Q & A]` —— **整頁深色、沒有標題列**，只有 Q & A。
**不要用 `== 結尾` 開一頁再放內容。**

---

## 附錄：曾經有、後來刪掉的內容（避免重做時又加回來）

| 內容 | 為什麼刪 |
|---|---|
| 「問題陳述」「產業/學術定位」兩頁 | 是計畫的架構，不需要在報告裡論證 |
| Pi 3B+ 的硬體限制、吞吐量預算 | 硬體是既定前提；而且還沒量過，不得出現數字 |
| 三階段管線架構圖（第 1 節） | 第 1 節只講環境建置，架構屬於第 2 節 |
| 「各階段的分工」整頁 | 處理程式的內部分層講太細，且與第 2 節重複 |
| 實體/模擬七個面向的對照卡片 | 太細，讀起來像已經測過一輪 |
| 「把第 1 節架構填上技術名稱」對照表 | 依附於已刪除的架構圖 |
| RFC 方法論整頁 | 現階段只是介紹，講 RFC 失焦 |
| 第 5 節「OpenWrt 整合」整節 | userspace 差異在模擬環境就處理掉了，剩下的 kernel 層問題放講稿 |
| 「不是二選一」「IP 分片提醒」 | 架構分層本來就是這樣，不需強調；舉例放講稿 |
| 各頁的 `#punch` 結語 | 結論用講的 |

**這些都不是寫錯，是刻意拿掉的。重做時不要「補回來」。**
