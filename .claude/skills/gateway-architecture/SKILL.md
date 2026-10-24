---
name: gateway-architecture
description: 這個專案（Rust 實作的 security gateway：Suricata 8 + nftables/NFQUEUE + tc/XDP eBPF + 雲端卸載）的框架架構、插件點與安全底線。只要在這個 repo 裡寫或改 gateway 程式、設計或審查任何插件（eBPF 外掛、送雲端的欄位腳本、nft 黑名單、Suricata 規則、雲端 API、Debian/OpenWrt 後端、fast path 或 offloading），或處理權限、RCE、注入等安全問題，都要先讀這份 skill，即使使用者沒有提到「架構」。
---

# Security Gateway 框架架構

## 使用前先知道

- 這份文件描述**目標架構**和**安全底線**，不是實作清單。專案規則（`.claude/CLAUDE.md`）優先：
  - 動手前先跟開發者討論，取得同意才寫程式或建檔。
  - 一次只做一步。
  - 開發者問「為什麼」時只解釋，不改程式。

  不要因為這裡列了完整框架，就一次把它全部做出來。
- 每項設計都標了狀態：
  - **[已決定]**：開發者同意過，附日期。
  - **[建議]**：調查後的提案，開發者**還沒同意**。不能當成已決定，要實作前先跟開發者確認。
  - **[待查證]**：事實還沒在實機或原始碼上確認。
- 事實是 2026-10-20 查的。kernel、套件、CVE 都會變，某個事實如果會左右決定，引用前要重查。
- 待決事項的選項分析在 `references/decisions.md`。開發者做了新決定，要同時更新那份檔案和 `research/literature/trust-bypass/SYNTHESIS.md` §10。

## 1. 已決定的前提

| 項目 | 內容 | 狀態 |
|---|---|---|
| 保護範圍 | 公司 LAN↔Internet 邊界，不只 IoT | [已決定] 10-17 |
| IDS | 以 Suricata 為 base，之後可能自製 engine | [已決定] 10-18 |
| Suricata 版本 | 8.0.7（trixie-backports） | [已決定] 10-20 |
| 語言 | Rust | [已決定] 10-20 |
| 平台 | Raspberry Pi 4（CLAUDE.md 已同步），之後會換正式設備 | [已決定] 10-20 |
| NAT | 不做 | [已決定] 10-20 |
| 雲端 | 不看 payload；一部分用 Jev 類決策模型，一部分用 ML；特徵格式未定 | [已決定] 10-20 |
| Fast path | tc eBPF，不用 XDP 當 fast path | [已決定] 10-20 |
| 框架定位 | 框架只定描述語法（型別、合併規則、CEL 計算式）；eBPF 程式、它輸出的欄位、送雲端的欄位和計算方式都由使用者設定 | [已決定] 10-22 |
| Suricata 擷取方式 | 走 NFQUEUE，不用 AF_PACKET＋XDP；行為由使用者設定，預設不做 inline drop（verdict 一律 accept，擋人由 nft 執行） | [已決定] 10-22 |
| eBPF 外掛 | 支援完整功能（掛點不限，可以 drop、redirect），由管理者負責；框架負責揭露（doctor 列出每個 port 上的程式） | [已決定] 10-22 |
| XDP | 可以設定要不要用。預設只有 port 有 native XDP 才掛，否則核心程式掛 TC，不會自動選 generic。使用者的 XDP 外掛遇到沒有 native 的網卡就不載入，請使用者改成 TC 程式，除非明確指定 generic。doctor 顯示每個 port 用 native 或 generic（`references/ebpf-plugins.md` §7） | [已決定] 10-24 |
| L2 bridge 或 L3 routing | 兩種都支援，用設定 `mode` 選，預設 bridge。bridge 預設由 OS 建立、wnc-gw 只檢查（之後可以設定成由 wnc-gw 建立）。bridge 模式走 `br_netfilter`，nft 規則和 L3 共用 `inet`；方向用 netdev ingress 打的 mark 判斷，不用 `iifname`。依模式而不同的功能寫成 trait（SYNTHESIS §11 D3 有實測結果） | [已決定] 10-24 |
| 分三階段做 | 1 nftables + NFQUEUE + ct mark → 2 tc eBPF 算特徵 → 3 tc eBPF 轉送信任 flow | [建議]（SYNTHESIS §4.4） |
| 和 Suricata 的整合方式 | 方案 A：原版套件 + EVE + unix socket + ct mark | [建議]（`suricata-integration.md` §9） |

## 2. 封包怎麼走

```
某個 port 收到封包
  │
  ├─ XDP：port 有 native XDP 才掛核心程式，否則改掛 TC；Pi 4 兩個 port 都不支援
  │       核心程式在這裡做 ban（DROP）和算特徵（PASS）[建議]
  ▼
tc ingress（TCX：核心 eBPF 程式排第一 [建議]，使用者外掛排在後面）
  │  解析 header → 更新 flow 特徵 map → 查信任 map
  │  階段 3：信任 flow 直接 redirect 到另一個 port，下面全部跳過
  ▼
netfilter（我們自己的 table）
  │  ban set → drop
  │  ct mark = trusted → accept（L3 模式可改交給 flowtable）
  │  其他 → queue
  ▼
NFQUEUE → Suricata 8 → verdict（預設一律 accept，不做 inline drop）
  ▼
從另一個 port 送出

控制迴路（非同步，不擋封包）：
  Suricata EVE + flow 特徵 → agent（狀態機）→ 雲端 → 判定
    → privd 改 ct mark / nft set / BPF map
```

- 被轉送的封包一定會經過某個 port 的 ingress，加上不做 NAT，所以觀察和丟包只掛 ingress 就夠。
- 雲端不在封包路徑上。它的成本是判定延遲、上傳 bytes 和雲端運算費用，不是每個封包多花的處理時間。
- tc ingress 比 netfilter ingress 早執行（`net/core/dev.c`）。所以即使 flowtable 讓信任 flow 跳過 netfilter，tc 的特徵計算仍然看得到這些封包。

## 3. Process 與權限 [建議]

**為什麼要分**：被 RCE 時，損害只到那個 process 的權限為止。最容易被打的是解析不可信輸入的部分，例如 EVE 字串、雲端回應、使用者腳本、規則檔。所以這些部分放在沒有特權的 process，需要 `CAP_NET_ADMIN` 或 `CAP_BPF` 的部分縮到最小，而且只接受有型別的指令。

| Process | 權限 | 做什麼 | 不做什麼 |
|---|---|---|---|
| `gw-privd` | 非 root 帳號 + ambient `CAP_NET_ADMIN` `CAP_BPF`；不給 `CAP_PERFMON` 和 `CAP_SYS_ADMIN` | 載入、掛載核心 eBPF 和已驗證的外掛；擁有 BPF map；增刪自己 nft table 裡的 set 元素；透過 ctnetlink 改 ct mark 或刪 entry；操作 Suricata unix socket | 不連外網、不解析 EVE 字串、不跑使用者腳本。每個請求都重新檢查一次 §5 的底線 |
| `gw-agent` | 無特權 | 讀 EVE、收 flow 記錄、跑狀態機、雲端 connector | 不直接碰 nft、BPF、conntrack，只能向 privd 送有型別的請求 |
| `gw-transform` | 無特權，加 seccomp 或 landlock、rlimit；無網路、無檔案 | 批次執行使用者的欄位腳本 | 任何 I/O |
| `rule-check` | 無特權，只用暫存目錄，有逾時 | 用 `suricata -T -S` 驗證候選規則 | 碰 active 規則目錄 |
| Suricata | 非 root、開 landlock、關閉 Lua 規則 | IDS | — |

privd 的 IPC 走 unix socket，用 `SO_PEERCRED` 檢查呼叫者的 uid，只開放這些動作：
- `ban(ip|cidr, ttl, reason)`、`unban(ip)`
- `trust(flow_key, ttl)`、`revoke(flow_key)`、`audit(flow_key, window)`
- `load_plugin(bundle_id)`、`unload_plugin(id)`：只接受本機 plugin store 裡已驗過簽章的 bundle id，不接受路徑或 bytes。
- `apply_ruleset(bundle_id)`：限制同上。
- `stats()`

導入順序：階段 1 可以先寫成單一 process，但 module 照上面的邊界切，privd 的介面先寫成 Rust trait。等雲端 connector 或任何插件要上線時，再把 agent 拆成獨立 process。

## 4. 插件點總表

| # | 插件點 | 形式 | 誰能裝 | 最重要的限制 | 細節 |
|---|---|---|---|---|---|
| 1 | eBPF 外掛 | BPF ELF；掛點由設定決定（TCX、XDP、socket filter、freplace） | 本機管理者；bundle 要有簽章 [建議] | 不限制能力，改成揭露：載入前掃描 ELF 產生能力報告；doctor 列出每個 port 上的程式，不是框架載入的顯示 warning [建議] | `references/ebpf-plugins.md` |
| 2 | 欄位腳本 | CEL 運算式（之後可再加 Rhai） | 本機管理者 | 在 `gw-transform` 執行；輸出要通過 schema 驗證；不輸出來自封包的字串 | `references/field-scripts.md` |
| 3 | 雲端 connector | 設定（endpoint、憑證、schema 版本）加 transport 實作 | 本機管理者 | mTLS；回應只能是白名單動作；雲端不能下發程式碼 | `references/cloud-api.md` |
| 4 | 防火牆操作 | 增刪自己 table 裡 named set 的元素 | 管理者，以及受限制的雲端 | 不開放 `nft -f`；永不封鎖清單 | `references/rules-nft-suricata.md` |
| 5 | IDS 規則 | Suricata 規則 bundle | 管理者、規則來源（要驗 hash 或簽章） | 靜態檢查 → 沙盒裡跑 `-T` → reload 後確認 → 失敗回退 | `references/rules-nft-suricata.md` |
| 6 | 平台後端 | Rust trait 的不同實作：FirewallBackend、FastPathBackend、ServiceManager、ConfigSource、XdpProbe | 編譯時選 | OpenWrt 上不能開 fw4 的全域 flow offloading | `references/platform-backends.md` |
| 7 | IDS engine adapter | 輸入事件 schema、輸出寫入操作 | 編譯時選 | Suricata 以外的選項：OpenWrt 官方套件只有 Snort 3；之後的自製 engine | `references/platform-backends.md` |
| 8 | 特徵來源 | conntrack acct、tc map、EVE flow | 設定 | tc 看到的是 GRO 合併後的 skb | `references/ebpf-plugins.md` §8 |
| 9 | 狀態機參數 | 設定值：觀察期 N/B、TTL、稽核率、K-of-M 等 | 設定 | 是資料，不是程式碼 | SYNTHESIS §4.7 |
| 10 | 量測 hook | 時間戳事件，例如判定延遲、撤銷延遲 | 編譯時 feature | 只輸出到本機，給實驗用 | — |

## 5. 安全底線

每一條後面都寫了理由，遇到沒列到的情況，照理由判斷。

1. **雲端和網路上的任何來源都不能下發可執行的東西**，包括 eBPF、腳本、nft 片段、規則。雲端只能回白名單動作。
   理由：只要有一條路能把程式碼送進 gateway，雲端或連線被攻破就等於 gateway 被 RCE。
2. **插件只能由本機管理者安裝。** 以 bundle 形式放在 root 擁有的 plugin store，privd 只用 bundle id 載入，載入前先驗簽章（例如 minisign / Ed25519）。
   理由：Pi OS 的 kernel 沒有 BPF LSM，kernel 端沒辦法強制檢查簽章，所以 user space 的驗證是唯一防線。
3. **不組 shell 指令。** 呼叫外部程式用 `Command::new().arg()`；nft 用 JSON，而且先在 Rust 端 parse 成自己的型別再重新序列化；Suricata 走 unix socket。
   理由：EVE 裡的 SNI、UA、DNS 名稱都是攻擊者可控制的字串；libnftables 的 JSON 模式解析失敗時會退回原生語法。
4. **只動自己的命名空間**：自己的 nft table、自己的 bpffs 目錄、自己的 Suricata 規則檔。不執行 `flush ruleset`。
   理由：會碰到管理連線和 OS 本身的防火牆規則。
5. **永不封鎖清單由 privd 在本機持有並強制**，包含管理 IP 與網段、gateway 自己、DNS、雲端 endpoint，不依賴雲端。
   理由：雲端出錯或被攻破時，gateway 不能把自己鎖死。
6. **trust 是最危險的動作。** 有本地 Suricata 告警的 flow 不接受 trust；trust 的 TTL 要比 ban 短，而且有上限；被撤銷過的 flow 或設備，下次門檻要提高。
   理由：信任會讓流量繞過 IDS，這正是攻擊者最想要的。
7. **每樣東西都要有上限**：nft set 的 size 和 timeout、BPF map 大小、每分鐘動作數、腳本的 operations 和記憶體、規則檔大小和條數。
8. **以下輸入一律不可信，都要 parse 和驗證**：封包（eBPF 內要做 bounds check）、EVE JSON、雲端回應、使用者腳本、插件 bundle、規則檔、設定檔。
9. **送雲端的欄位只能是數值、bool 或事先宣告的 enum。** 來自封包的字串（SNI、UA、DNS 名稱、URL）不送原文，真的要送就送雜湊或分桶結果。
   理由：雲端有 LLM 類決策模型，原文字串就是 prompt injection 的載體。
10. **所有特權動作都寫進 audit log**，記錄誰、做了什麼、為什麼、結果如何。log 裡的外部字串要跳脫。
11. **雲端異常時進入 fail-safe**：簽章錯誤、動作速率異常或連不上時，停止接受新的 trust，維持本地規則。斷線時該 fail-open 還是 fail-closed 還沒決定（`references/decisions.md` O9）。

## 6. 平台現況速查（2026-10-20）

標「核對」的是主 agent 讀過原始碼或官方清單；其他來自 subagent 調查，出處寫在各 reference。

| 項目 | Pi 4 + Raspberry Pi OS（trixie） | OpenWrt |
|---|---|---|
| kernel | 官方映像是 6.12；archive 裡的 linux-image-rpi-v8 已經到 6.18.50 | 24.10.8 是 6.6.144（opkg）；25.12.6 是 6.12.112（apk） |
| native XDP | 沒有。bcmgenet 在 mainline 和 rpi-6.12.y 都沒有 XDP（核對）；patch 到 2026-05 還在 v9 review。USB 網卡的 r8152、lan78xx、smsc95xx 也沒有 | 看 SoC 的 driver |
| BTF | 沒有，所以不能用 CO-RE 和 kfunc（例如 `bpf_skb_ct_lookup`） | 預設沒有 |
| BPF LSM | 沒有；`CONFIG_LSM=""`（核對） | 預設沒有 |
| flowtable | 有模組，`NF_FLOW_TABLE` 和 `NFT_FLOW_OFFLOAD` 都是 m（核對） | 預設帶 kmod-nft-offload |
| 硬體 offload | 沒有 | MediaTek Filogic 等，約 64 條 entry |
| Suricata | trixie-backports 有 8.0.7 | 官方 feed 沒有；25.12.6 的 aarch64_cortex-a72 只有 snort3 3.10.0.0（核對） |
| libc | glibc | musl（Rust target 是 `aarch64-unknown-linux-musl`） |
| 服務管理 | systemd | procd + ujail |

由此得出的設計規則：
- **核心 eBPF 程式不依賴 BTF、CO-RE 或 kfunc**，只用 `__sk_buff` / `xdp_md`，header 自己解析。這樣在 Pi OS 和 OpenWrt 的預設 kernel 上都能跑。
- **Pi 4 上偵測 XDP 會失敗，一律走 tc。** 不要自動退回 generic XDP。

## 7. 實作順序 [建議]

每一步開始前都先跟開發者討論，做完就停下來讓開發者確認。

1. 階段 1：nftables（自己的 table）+ NFQUEUE + ct mark；agent 讀 EVE、改 ct mark。privd 介面先定成 trait。
2. 階段 2：tc 核心 eBPF 算特徵，要處理 GRO（見 `references/ebpf-plugins.md` §8）。
3. 欄位腳本（CEL）和雲端 connector，這時把 process 拆開。
4. 規則管線，以及 nft set 的操作 API。
5. 階段 3：fast path 後端（tc redirect；L3 模式可以加 flowtable 後端）。
6. eBPF 外掛的載入與揭露、XDP probe、OpenWrt 後端。

## 8. 什麼時候讀哪份文件

| 要做的事 | 讀這份 |
|---|---|
| 寫或審查 eBPF（核心程式或外掛）、XDP 偵測、GRO 問題 | `references/ebpf-plugins.md` |
| 欄位腳本、送雲端的資料格式 | `references/field-scripts.md` |
| nft 黑名單、Suricata 規則載入和 reload、EVE 裡哪些欄位不可信 | `references/rules-nft-suricata.md` |
| 雲端 API、認證、回應處理、更新包簽章 | `references/cloud-api.md` |
| Debian 和 OpenWrt 的差異、fast path 後端、flowtable、offloading、systemd 和 procd | `references/platform-backends.md` |
| 還沒決定的事和選項分析 | `references/decisions.md` |
| 研究背景：信任式 fast path、狀態機、文獻 | `research/literature/trust-bypass/SYNTHESIS.md` |
| Suricata 對外整合介面（EVE、unix socket、datasets、plugin、library mode） | `research/literature/trust-bypass/suricata-integration.md` |
