# 架構與 OS 選擇

## 1. OS 選擇

**前期原型（Pi 3B+）用 Raspberry Pi OS Lite (64-bit)；最終目標平台是 OpenWrt + ARM。**
這兩個決定不衝突——前者是把邏輯跑通的開發環境，後者是產品形態，理由與取捨如下。

| OS | 優點 | 缺點 | 判斷 |
|---|---|---|---|
| **Raspberry Pi OS Lite 64-bit** (Debian base) | 驅動最完整、USB 網卡開箱可用、Debian 套件庫有 suricata/nftables/netsniff-ng、1 GB RAM 跑得動 | **預設 kernel 沒有 `CONFIG_DEBUG_INFO_BTF`** → CO-RE eBPF / bpftrace 不能直接用 | ✅ **前期原型主線**。BTF 問題有解（見下） |
| Ubuntu Server LTS arm64 | kernel 有開 BTF、BPF 工具鏈新、與筆電環境一致 | 1 GB RAM 上偏重；Pi 3 支援不如 Pi 4/5 順；跟最終的 OpenWrt 目標也沒有直接關係 | 🔶 僅前期備選。若 eBPF 是研究核心可考慮，但先確認 Pi 3B+ 能跑順 |
| **OpenWrt** | **最終目標平台**。footprint 小；22.03 起預設是 firewall4、底層就是 nftables——代表在 Debian/Pi 上寫的 nftables 規則**語意可以直接搬過去**，這是選 nftables 當主線最重要的可遷移性理由；有完整 router 套件，也有 `suricata` / `snort3`（含對應的 `luci-app-*` 管理介面） | 跟 Debian 環境差很多：套件要 cross-compile 成 `.ipk`、libc 是 **musl** 不是 glibc、init 是 **procd** 不是 systemd、rootfs 是 overlayfs 且空間小（log 要外接）；`CONFIG_DEBUG_INFO_BTF` 預設也**沒開**，CO-RE eBPF 一樣會壞（跟 Pi 同一個坑，見下）；Suricata 全規則集常見建議 RAM ≥ 4 GB，一般 ARM router 的 RAM 遠低於此，規則集要裁 | ✅ **目標平台**。前期先在 Pi OS Lite 上把邏輯跑通，最後才移植過來 |
| Alpine / DietPi | 極省資源 | musl libc 會讓某些工具編譯踩雷（跟 OpenWrt 是同一種 libc，但生態更小） | ❌ 前期不要增加變數 |

### BTF 問題怎麼處理
`64-bit` 的 Raspberry Pi OS 有兩種 kernel 來源：
- `linux-image-*-arm64`（Debian 官方 kernel）→ **有開 BTF**
- Raspberry Pi 基金會自家 kernel（`/boot/firmware/kernel8.img`）→ **沒有 BTF**

`preflight.sh` 會檢查 `/sys/kernel/btf/vmlinux` 是否存在。若沒有，三個選項：
1. **先不用 CO-RE**：改寫成傳統 BCC（執行時編譯）或直接用 `tc`/`nftables`，**前期建議走這條**
2. 換裝 Debian 官方 arm64 kernel
3. 自己編 kernel 開 `CONFIG_DEBUG_INFO_BTF=y`（在 Pi 3B+ 上編譯很慢，用筆電 cross-compile）

> 決策建議：**前期不要為了 eBPF 去編 kernel。** 先用 nftables + NFQUEUE 把整條
> 「本地判斷 → 不確定 → 送雲端 → 回 verdict」的迴路跑通，這才是你的研究貢獻所在。
> eBPF 是之後的最佳化手段，不是先決條件。

**這個坑會延續到正式設備，不是 Pi 專屬的問題。** OpenWrt 的 `CONFIG_DEBUG_INFO_BTF`
預設也**沒有開**，所以就算之後換到 OpenWrt/ARM，CO-RE eBPF 一樣會壞掉，一樣要自己
build kernel 開這個 config。也就是說「前期不要為了 eBPF 去編 kernel」不只是省事的
權宜之計——BTF 問題在目標平台上也不會自動消失，所以更沒有理由現在就為了它引入額外
複雜度。等真正要做 eBPF 最佳化時，Pi 和 OpenWrt 面對的是同一個坑，屆時一次處理。

---

## 2. 資料平面架構

```
                        ┌─────────────── 雲端分析服務 ───────────────┐
                        │  重量級 DPI / ML 模型 / 威脅情報比對        │
                        └───────────▲──────────────────┬─────────────┘
                                    │ flow 特徵 / 前 N 封包  │ verdict + 快取規則
                                    │  (mTLS, 非同步)        ▼
┌──────────────────────────────────────────────────────────────────────┐
│  安全閘道器 (Pi 3B+ → 正式設備)                                       │
│                                                                      │
│   ┌── Control Plane (userspace) ──────────────────────────────┐      │
│   │  offload 決策器：讀 NFQUEUE → 判斷 → 下 verdict            │      │
│   │  本地快取（已知結論的 flow，避免重複問雲端）                 │      │
│   │  雲端 client（非同步、有 timeout、有 fail-open/close 策略）  │      │
│   └────────▲──────────────────────────────┬───────────────────┘      │
│            │ NFQUEUE (libnetfilter_queue)  │ verdict: ACCEPT/DROP     │
│   ┌────────┴──────────────────────────────▼───────────────────┐      │
│   │  Data Plane (kernel)                                       │      │
│   │  [Tier 0] nftables 快路徑：已知 allow/deny、conntrack 已建立 │      │
│   │  [Tier 1] 本地輕量檢測：Suricata inline / 規則比對          │      │
│   │  [Tier 2] 不確定 → NFQUEUE 交給 Control Plane              │      │
│   └────────▲──────────────────────────────────────┬───────────┘      │
│         eth0 (LAN / 內網 / trusted)         eth1 (WAN / 外網)         │
└────────────┼──────────────────────────────────────┼──────────────────┘
             │                                      │
        內網用戶端                              網際網路
```

### 三層分流（Tier）的設計意義
- **Tier 0（nftables + conntrack）**：絕大多數封包應該在這裡結束。
  一條 flow 一旦有結論就寫進 conntrack / nft set，後續封包不再進 userspace。
  **這一層的命中率決定了整台設備的吞吐量。**
- **Tier 1（本地檢測）**：規則能判的在本地判掉。
- **Tier 2（NFQUEUE → 雲端）**：只有真正不確定的才上雲。

> 論文裡最關鍵的一張圖：**Tier 2 比例 vs 總吞吐量 / 端到端 latency**。
> 你要證明的是「用很小的 offload 比例換到接近雲端的偵測率」。

---

## 3. 必須先決定的四個設計問題

### Q1. 「處理不了」的判準是什麼？（可量化）
候選判準，建議先實作前兩個：
- 規則未命中 且 flow 是新的 / 目的地不在白名單
- 本地模型信心值 < 閾值 τ（**early-exit / cascade inference** 的標準做法）
- 協定是加密的（TLS）→ 本地看不到內容，只能送 metadata 上雲
- 本地 CPU / queue 已飽和 → **反過來，這時候應該減少上雲**（因為上雲也要花 CPU）

### Q2. 送什麼上雲？
| 方式 | 頻寬 | 偵測力 | 建議 |
|---|---|---|---|
| flow 五元組 + 統計特徵（封包數/大小分布/時間間隔） | 極省 | 適合 ML 異常檢測 | ✅ **先做這個** |
| 前 N 個封包的 payload（N=5~10） | 中 | 可做 protocol / signature 判斷 | ✅ 第二階段 |
| 完整 pcap | 很貴 | 最強 | 只在特定觸發時做 |

### Q3. 等雲端回覆的期間，封包怎麼辦？（**這是核心取捨**）
| 策略 | 安全性 | Latency | 備註 |
|---|---|---|---|
| **Buffer 住等 verdict** | 高 | 差（+RTT），且 NFQUEUE 有佇列長度上限，會爆 | 適合低流量高價值 |
| **先放行、後補救**（放行 + 事後阻斷該 flow） | 中（首包已放過） | 好 | 業界常見；要搭配「雲端回報惡意就立刻 kill conntrack」 |
| **先阻擋、等放行** | 最高 | 很差，誤殺體感差 | 只適合高安全等級模式 |

建議做成**可切換的 policy**，然後三種都量一次 — 這三條曲線就是你的實驗結果。

### Q4. 雲端掛掉 / 超時怎麼辦？
`fail-open`（放行，保可用性）vs `fail-close`（阻擋，保安全性）。
要有明確 timeout，且要量「雲端不可用時的降級吞吐量」。這題老師很可能會問。

---

## 4. 開發路線（建議順序）

| 階段 | 在哪做 | 目標 | 產出 |
|---|---|---|---|
| **P0** | 筆電 netns | 把三層分流 + NFQUEUE 迴路跑通，完全不碰 Pi | 可重現的 testbed |
| **P1** | 筆電 netns | 加上假的「雲端」服務，量三種 buffer 策略的 latency | 第一組數據 |
| **P2** | Pi 3B+ | `preflight.sh` 確認硬體能力，量 `T_max` 天花板 | 硬體能力報告 |
| **P3** | Pi 3B+ | 把 P1 的東西原封不動搬上去，量相對留存率 | 真實設備數據 |
| **P4** | Pi 3B+ | 接真的雲端（或筆電當雲端），端到端驗證 | 系統 demo |
| **P5** | 正式設備（OpenWrt/ARM） | 把 P3/P4 的邏輯移植過去：nftables 規則語意可以直接搬（OpenWrt firewall4 底層就是 nftables），但要處理 musl/procd/overlayfs 這些工程差異；重跑全套、比對相對留存率；**這裡才評估要不要導入 AF_XDP/XDP**（不是 DPDK——理由見 `00-reading-list.md` B-1） | 最終數據 |

**重點：P0/P1 在筆電上做。** 你筆電是 8 核 x86、有 BTF、有 docker，
開發迴圈比 Pi 快一個數量級，而且 netns 拓撲跟實機是同一組 nftables 規則。
不要一開始就卡在 microSD 和 USB 網卡上。

> 附帶一提：`security_gateway/` 的 Rust 程式已經在 build `x86_64-unknown-linux-musl`
> target（見 `docker/compose.yml` 裡的掛載路徑）。OpenWrt 也是 musl，所以 P5 移植時
> musl 這一關其實已經先鋪路了，不用從頭處理。procd / overlayfs / `.ipk` 打包這些
> 仍然是 P5 才會遇到的新工程問題。
