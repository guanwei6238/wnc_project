# slide_implement.md — Security Gateway 專案進度（2026-11-23）

> 投影片的規格：每一頁放什麼、數據從哪個檔案來、講稿要講什麼。
> 與 `src/main.typ` 同步；兩者不一致時以 `main.typ` 為準。講稿：`逐字稿.md`；草稿：`user_draft.md`。
> 頁碼一律是投影片右下角顯示的頁碼（封面、章節頁、Q&A 不編號）。
> 「當場講」「補充」的內容不印到投影片上。

---

## 0. 這次報告的定位

- 日期 2026-11-23。對象：計畫方（公司）和老師。
- 草稿：「這段時間新增的功能（ct mark、tc）與實驗數據，目前的 eBPF 算特徵的程式也可以稍微說明」。
- 上一次的專案報告是 11/09（專案介紹 & Demo）。11/13 是 group meeting 的論文報告（NetBeacon），和這次無關。
- 11/09 已經講過、這次不重講的：整體架構與 wnc-gw 的 subcommand、packet 怎麼走（SYN／FIN／RST 一律進 Suricata）、auto trust 的狀態機與 `[trust]` 參數、`when_unavailable`、`mode`／`protection`、`doctor`。需要時一句帶過。
- 11/09 講過、這次**要接上**的三件事（不接會被問）：
  1. 11/09 第 5 頁說「trust 用 ct mark，不用 5-tuple，因為 5-tuple 會被 port 重用或偽造的 packet 繞過」。這次 TC 的 trust map 就是 5-tuple，要說清楚 port 重用怎麼處理、偽造還沒處理（第 6 頁）。
  2. 11/09 第 2 頁說「eBPF 程式還沒寫，之後用來做 fast path」，現在已經做了（第 1–5 頁）。
  3. 11/09「下一步」說先接最小的 cloud 迴路、排在 eBPF 之前；11/14 改了順序（第 1 頁講稿要講原因）。
- 11/09 說「`mode` 的預設還沒決定」：11/15 開發者決定維持 `bridge`，第 2 頁講稿一句帶過。

## 1. 查證結果（製作前）

對照的來源：`security_gateway/DECISIONS.md`（§1、§5、§17、§20、§22、§23）、`.claude/skills/gateway-architecture/references/decisions.md`（O13、O17）、`tests/ebpf/README.md`、`tests/cpu_alloc/README.md`（實驗 9–14）、`tests/trust_sim/README.md`、`tests/features/README.md`、`security_gateway/gw-ebpf/src/main.rs`、`gw-common/src/lib.rs`、`src/agent/idle.rs`、`src/features/derive.rs`、git log（11/05 之後）。

| 草稿的說法／要講的點 | 查證 | 結果與處理 |
|---|---|---|
| 「新增的功能（ct mark、tc）」 | ct mark 是 10/28 的做法，11/09 已經報告過；11/14 trust 搬到 TC（commit 1faa17d、11acc35），11/17 把 ct mark 拿回來當選項（9d1826a，`[trust] backend`） | **ct mark 不是新功能**。這次的新功能是「trust 搬到 TC 的 fast path」和「`[trust] backend = tc／ctmark` 二選一」。投影片照這個講法，ct mark 當成「上次的做法、現在是備用選項」 |
| 「目前的 eBPF 算特徵的程式」 | DECISIONS §23（11/18 開發者決定）：**wnc-gw 不預先提供特徵程式，也不預先定義特徵**；使用者自己寫 eBPF＋JSON definition，wnc-gw 檢查格式、載入、解碼、計算 derived。`tests/features/prog/` 是我們寫的**測試用**程式 | 投影片講「特徵框架」，不講成「我們算了哪些特徵」。範例用測試程式的 `flows.json`，並說明它是測試用的 |
| 特徵的成本 | DECISIONS §23「待決」：Pi 上每個 packet 多幾 µs、讀 map／解碼每筆幾 µs **都還沒量**；Pi 只做了功能確認（11/19） | 投影片和講稿都要明說「成本還沒量」 |
| TC 的 trust 單位 | `gw-ebpf/src/main.rs`：key 是 5-tuple（`FlowKey` 40 bytes），每個方向一筆；`TRUST_ENTRIES = 32768`（`gw-common/src/lib.rs`），所以最多 16,384 條 connection（單元測試第 16,385 條 `map "TRUST" is full`） | 和 11/09 的說法衝突，第 6 頁處理 |
| 交回 kernel 的 packet | `main.rs`：SYN／FIN／RST 交回、純 SYN（SYN 且沒有 ACK）刪掉兩個方向；routed 時 TTL ≤ 1 交回、減 TTL 修 checksum；bridge `bpf_redirect`，routed `bpf_redirect_neigh`；DECISIONS §17：廣播／多播、IPv4 分片也交回 | 和 DECISIONS 一致 |
| idle sweep | `src/agent/idle.rs`：TCP 600 s、UDP 120 s；DECISIONS §17：每 10 秒列一次 trust map | 一致 |
| 特徵的運算 | `src/features/derive.rs`：add、sub、mul、div、mean、var、std、delta、rate、scale、bucket、percentile、enum，13 種 | DECISIONS 草案寫的 `ratio` 沒有實作；投影片用程式裡的 13 種 |
| 實驗 13 的 U（不 trust、全部 inspection） | `tests/cpu_alloc/README.md`：U 被 Suricata 的 drop-flow 拉低（大幀、兩張網卡順序錯亂），**不能當成 inspection 的成本** | 投影片不放 U；不算「省了百分之幾」 |
| 套到 dataset 的「平均每個 packet 省多少」 | trust_sim 的 fast path 比例 × 實驗 13 bridge ips 50 kpps 的差：CIC-IDS2017 43.1% × −4.5 ≈ −1.9 µs、CICIoT2023 Benign 55.5% × −3.9 ≈ −2.2 µs | 算式核對過。這是推算，講稿要說「推算」 |
| 11/09 下一步的順序 | decisions.md O13：10/25 決定先接 cloud 迴路；**11/14 改成 eBPF 骨架 → trust 搬到 TC → 特徵（和 edge AI、cloud 一起）**。開發者：「算特徵給 user space 最後跟 edge ai, cloud ai 一起做」。代價：卸載成本（上傳 bytes、判定延遲）比較晚才量得到；先量 trust 省下的地端成本，對應論文主軸 | 第 1 頁講稿講 |
| 為什麼 TC 不能直接用 ct mark | decisions.md O17：TC 讀不到 ct mark（`__sk_buff` 沒有欄位；kfunc `bpf_skb_ct_lookup` 要 vmlinux BTF，Pi OS 沒有，而且是 GPL-only；conntrack 在 TC 之後才查） | 第 2 頁補充 |

沒放進這份報告的新東西（草稿沒提，被問到再講，寫在講稿的補充最後）：doctor／run 的每個訊息都有代碼、`wnc-gw explain`（3e61bd0）；設定只保留相關欄位（§21）；`wnc-gw trust` 改經 unix socket 請 `run` 寫 map。

## 2. 共通規則（照前幾次的回饋）

- 只放重點；說明句寫在講稿，不印在投影片上。圖裡只放節點名稱、箭頭上的短標籤、圖例。
- 先定義再放數據：表格的每個欄位、縮寫，在表格之前或同一頁講稿裡先定義，講稿也要寫。
- 只給比率不夠：直接標 µs／packet、kpps、多少個 packet。
- 技術名詞一律英文，全份統一（投影片、講稿都一樣）。沿用 11/09 的：

  | 用這個 | 不要寫成 |
  |---|---|
  | packet | 封包 |
  | connection（conntrack 的一條連線） | 連線、flow（Suricata 自己的名稱如 `flow-timeouts` 除外） |
  | trust、trusted、auto trust、revoke | 信任、自動信任、撤銷 |
  | TTL、alert、rule、verdict、inspection | 有效期、告警、規則、判決、檢查 |
  | ct mark、conntrack、netfilter、forward chain、`ids` chain、table | — |
  | edge AI、cloud | 邊緣 AI、雲端 |
  | scenario | 場景 |

  這次新增的：

  | 用這個 | 意思 | 不要寫成 |
  |---|---|---|
  | core eBPF program | wnc-gw 自己的 eBPF 程式，掛在兩個 port 的 TCX ingress 第一位 | 核心程式、主程式 |
  | TCX | TC 的新掛載方式（kernel 6.6+），可以排順序 | tc hook |
  | trust map | core eBPF program 查的 BPF hash map，key 是 5-tuple | 信任表 |
  | fast path | trusted packet 在 TC 直接 redirect 到另一個 port，不進 bridge、netfilter、conntrack | 快速路徑 |
  | redirect | `bpf_redirect`／`bpf_redirect_neigh` | 轉向 |
  | backend | `[trust] backend` 的值：`tc`、`ctmark` | 後端 |
  | next hop | routed 時下一跳的位址 | 下一跳 |
  | idle sweep | `tc` backend 每 10 秒刪掉閒置的 trust | 閒置清除 |
  | feature program | 使用者提供的 eBPF 程式（`[[features]]`） | 特徵程式 |
  | definition | 使用者提供的 JSON 定義檔 | 定義檔 |
  | derived | definition 裡用運算算出來的欄位 | 衍生欄位 |
  | hook | feature program 掛在哪：`xdp`、`tc-ingress`、`tc-egress` | 掛點 |

- 「tc」：指 backend 的值寫 `tc`（code 格式），指 kernel 的 Traffic Control 寫 TC。「ctmark」指 backend 的值（`ctmark`），講機制時寫 ct mark。
- setting 的值、子命令、檔名、helper 名稱用 code 格式。
- dataset 的切片一律帶 dataset 或 malware／設備名稱，例如 60-1 (Gafgyt)、Honeypot-5-1 (Amazon Echo)。
- 配色沿用 `template.typ` 的語意色：TC／XDP／eBPF = `c-stage1`、netfilter = `c-stage2`、Suricata 等 user space = `c-stage3`、cloud = `c-cloud`、LAN = `c-lan`、WAN = `c-wan`。**實作狀態用框線表示**：實線＝已實作、虛線＝還沒實作。
- 講稿標「**推算**」「**推論**」「**沒有量**」「**沒有查**」「**沒有找到**」「**還沒決定**」「**還沒找到**」「**還沒查**」「**還沒量**」的地方，講的時候要把這幾個字講出來。

## 3. 頁序

| 頁 | 標題 | 章節 |
|---|---|---|
| 封面 | Security Gateway 專案進度 | |
| 1 | 11/09 之後做了什麼 | |
| — | 章節頁：trust 搬到 TC | ① |
| 2 | fast path：packet 怎麼走 | ① |
| 3 | 每個 trusted packet 省多少（Pi） | ① |
| 4 | 套到 dataset | ① |
| 5 | idle sweep 與長 connection | ① |
| — | 章節頁：`[trust] backend` | ② |
| 6 | `tc` 與 `ctmark` | ② |
| — | 章節頁：特徵 | ③ |
| 7 | 特徵框架 | ③ |
| 8 | definition | ③ |
| 9 | hook：看得到哪些 packet | ③ |
| 10 | 待決與下一步 | |
| Q&A | | |

## 4. 每頁規格

### 封面

- title：`Security Gateway 專案進度`；date：`2026-11-23`。
- 當場講：今天報告 11/09 之後的進度：trust 從 netfilter 搬到 TC、trust 的兩種 backend，和 eBPF 的特徵框架。

### 第 1 頁　11/09 之後做了什麼

**投影片**
- 整頁：架構圖，改自 11/09 第 2 頁（`../20261109_security_gateway_專案介紹_Demo/src/main.typ` 的架構圖），只改這幾處：
  - 兩個 port 的 TCX ingress 上的「core eBPF program」變成實線（已實作），框裡有「trust map」；箭頭標 `fast path`，直接連到另一個 port。
  - 「feature program」實線，標「使用者提供」；它到 wnc-gw 的箭頭實線（wnc-gw 讀 map）。
  - netfilter 的框裡標「ct mark（`ctmark` 時）」。
  - wnc-gw 到 trust map、ct mark 的箭頭：`trust`。
  - edge AI、cloud 照舊虛線；wnc-gw 送特徵給它們的箭頭虛線。core eBPF program 到 netfilter 的箭頭、wnc-gw 與 cloud 之間的箭頭不標字。

**當場講**
11/09 的時候 eBPF 還沒寫。這兩週做的是圖上綠色實線的部分：wnc-gw 在兩個 port 的 TC 掛一支自己的 eBPF 程式，我們叫 core eBPF program；trusted connection 的 packet 在這裡就直接送到另一個 port，這就是 fast path。原本用 ct mark 在 netfilter 放行的做法，11/14 改成 TC 時拿掉，11/17 拿回來，變成 `[trust] backend` 的另一個選項。最後是特徵：使用者自己寫 eBPF 程式算特徵，wnc-gw 負責載入、讀資料、算 derived 的欄位。送到 edge AI 和 cloud 還沒做，所以還是虛線。
順序和 11/09 講的不一樣：11/09 說先接 cloud 迴路，11/14 改成先做 eBPF。原因是研究主軸是用 trust 節省資源，trust 搬到 TC 之後才量得到真正省下的地端成本；算特徵最後和 edge AI、cloud 一起做。代價是送 cloud 的成本要比較晚才量得到。

**補充**
- 這兩週的日期：11/14 core eBPF program、trust 搬到 TC；11/14 idle sweep、`routed` 的 next hop；11/17 `[trust] backend = tc／ctmark`；11/18–19 特徵框架（`[[features]]`）。
- wnc-gw 和 cloud 之間的虛線雙向箭頭（還沒做，圖上沒有標）：往 cloud 送特徵；cloud 回 trust、block、observe 三種動作之一（11/09 講過）。
- core eBPF program 到 netfilter 的箭頭（圖上沒有標）：交回 kernel 的 packet，回傳值是 `TCX_NEXT`。
- 順序的決定：decisions.md O13（10/25 決定先接 cloud 迴路；11/14 改順序）。
- core eBPF program 用 Rust（aya-ebpf），授權 `Dual MIT/GPL`，嵌在 wnc-gw 裡，不 pin：wnc-gw 結束或被 `kill -9` 時 kernel 自動卸下（Pi 驗過）。排在 TCX 第一位；run 每 10 秒確認還在第一位，被別的程式插隊就 warning（D002、D003），doctor 會列出 port 上別人的 TCX 程式（D006）。
- 為什麼 fast path 在 TC 不在 XDP：XDP 只有 ingress、有些硬體不支援；Pi 4 的 `bcmgenet` 和常見的 USB 網卡都沒有 native XDP。XDP 只留給 feature program（看得到 GRO 合併前的原始 frame）（DECISIONS §17）。
- 掛 core eBPF program 本身的成本（Pi、veth、10 kpps，步驟 A3）：進 TCX 約 0.52 µs／packet；加上解析 header、查一次 trust map，約 1.0 µs／packet，每個 packet 都要付（沒有 trust 的 packet 約多 2%）。

### 章節頁　trust 搬到 TC

### 第 2 頁　fast path：packet 怎麼走

**投影片**
- 一張 packet 路徑圖（左到右）：port A 的 TCX ingress → core eBPF program →
  - 查到 trust map（而且不是 SYN／FIN／RST）→ `redirect` → port B（綠色，標 `fast path`）
  - 其他 → `TCX_NEXT` → bridge／routing → netfilter → Suricata（11/09 的路徑，灰色或淡色）
  - core eBPF program 和 trust map 之間一條雙向箭頭（查詢、刪除，不標字）
- 下面一張小表：`mode` 對應的 packet 改動

  | `mode` | packet 的改動 |
  |---|---|
  | `bridge` | 不改 |
  | `routed` | TTL −1、修 checksum |

**當場講**
packet 從一個 port 進來，在 TC 先經過 core eBPF program。它用 5-tuple 查 trust map，查到就直接 redirect 到另一個 port，不經過 bridge、netfilter 和 conntrack，也不進 Suricata。SYN、FIN、RST、分片和廣播、多播 packet 照樣交回 kernel，走 11/09 講的那條路：SYN／FIN／RST 一律進 Suricata；看到純 SYN，也就是同一個 5-tuple 有新的 connection，就把兩個方向的 trust 刪掉。
`bridge` 直接 redirect；`routed` 要自己把 TTL 減 1、修 IPv4 checksum。wnc-gw 在 trust 的時候先查好每個方向的 next hop 寫進 map，kernel 就不用每個 packet 查路由；路由一有變動就先不用 next hop，改回每個 packet 查。

**補充**
- 圖上沒有標的：分片、廣播／多播也交回 kernel；netfilter 裡是 forward chain → `ids` chain；純 SYN 會刪掉兩個方向的 trust（trust map 的雙向箭頭）。redirect 用的 helper：`bridge` 用 `bpf_redirect`；`routed` 用 `bpf_redirect_neigh`＋next hop，TTL ≤ 1 交回 kernel。
- 為什麼不能在 TC 直接看 ct mark：TC 執行的時候 conntrack 還沒查表；`__sk_buff` 沒有 ct mark 的欄位；kfunc `bpf_skb_ct_lookup` 要 vmlinux BTF（Pi OS 沒有），而且只給 GPL 程式（我們之後可能閉源）。所以 fast path 一定要自己的 map（decisions.md O17）。
- trust map：BPF hash map，32,768 筆，每個方向一筆，所以最多 16,384 條 connection；滿的時候 `trust add` 回錯誤、不會留半筆。value 是 packet 數、bytes、最後時間、方向、next hop，另外預留 TCP 序號的欄位（第 6 頁）。
- 誰寫 trust map：auto trust（每 5 秒讀 conntrack，條件和 11/09 一樣）和 `wnc-gw trust add／del`（經 `/run/wnc-gw/control.sock` 請 `run` 寫，只收 root 或 run 的帳號）。寫一筆 2.8 µs，ctnetlink 設 ct mark 一筆 14.5 µs（E2）。
- next hop 的安全：訂閱 kernel 的路由變更，任何變更都讓所有 next hop 失效（kernel 端改回每個 packet 查路由），路由安靜 10 秒後才重新填；持續變動 60 秒記 WARN D007。Docker：每 0.5 秒改一次路由持續 70 秒，999／999 個都在 TC 送出。沒有排除的：路由改變到 wnc-gw 收到通知的幾 ms 內仍用舊的 next hop。
- next hop 省多少（Pi 實體網卡、120 kpps，實驗 10、12）：`routed` 的 trusted packet 9.16 → 8.28 µs；`bridge` 7.79 µs。
- `mode` 的預設：11/15 開發者決定維持 `bridge`（部署透明）。有 fast path 之後 trusted packet `bridge` 比 `routed` 少約 0.5 µs，沒 trust 的 packet `routed` 少 3.1–3.9 µs（實驗 10、12，Pi）。
- 驗證：Docker（`routed`，只測 IPv4 TCP、UDP）、Pi（`bridge`、`routed`，含 IPv6 TCP）上，trust 期間 forward chain 的 counter 停住、`trust del` 後恢復，160／160 個都收到；Pi `bridge` 的 TCP 多 2 個 IPv6 多播 packet，交回 kernel；port 重用時 trust 被刪（`tests/ebpf/README.md`）。

### 第 3 頁　每個 trusted packet 省多少（Pi）

**投影片**
- 一行條件（小字）：Pi 4、1000 MHz、實體網卡、`ips`、50 kpps；整台 Pi 的 CPU 時間 ÷ packet 數（µs／packet）；2 輪平均。
- 表（實驗 13，C → T）：

  | 切片 | `bridge` ct mark → TC | `routed` ct mark → TC |
  |---|---|---|
  | IoT-23 60-1 (Gafgyt) | 14.2 → 8.8（−5.4） | 11.1 → 9.2（−1.9） |
  | IoT-23 Honeypot-5-1 (Amazon Echo) | 30.5 → 24.7（−5.7） | 29.4 → 25.2（−4.2） |
  | CIC-IDS2017 Benign | 30.8 → 26.4（−4.5） | 28.6 → 26.9（−1.7） |
  | CIC-IDS2017 FTP-Patator | 30.1 → 22.6（−7.5） | 27.2 → 23.2（−4.0） |
  | CIC-DDoS2019 Benign | 29.5 → 26.6（−2.9） | 27.3 → 25.3（−1.9） |
  | CICIoT2023 Benign | 29.6 → 25.7（−3.9） | 27.3 → 29.5（**+2.3**） |
  | CICIoT2023 DNS Spoofing | 28.3 → 25.7（−2.6） | 26.4 → 25.8（−0.6） |

- 表下一行：容量（`bridge`，kpps）：ct mark 50–80 → TC 50–197。

**當場講**
這張表是每個 trusted packet，整台 Pi 用掉多少 CPU 時間，單位 µs，不是延遲。實驗在 Pi 的實體網卡上做，筆電從兩張網卡以每秒 5 萬個 packet 重播；兩欄是兩種 `mode`，每格是 ct mark 的做法到 TC 的做法。
送進去的只有經過 gateway、會走 fast path 的 packet：我們從四個 dataset 挑了 7 段、每段 20 萬個 packet 的切片，拿掉 SYN、FIN、RST、多播、分片這些不走 fast path 的 packet，每段實際送 10 到 20 萬個，所以兩邊的差就是每個 trusted packet 的差。
結果：`bridge` 下 7 個切片 TC 都比較省，每個 packet 少 2.6 到 7.5 µs。`routed` 少得比較少，0.6 到 4.2 µs，因為 ct mark 在 `routed` 本來就比較便宜，沒有 bridge 和 `br_netfilter`。只有一個例外：`routed` 的 CICIoT2023 Benign，TC 反而貴 2.3 µs，原因**還沒找到**。
最下面是容量，也就是丟掉的 packet 不超過 0.1% 的最高速率：ct mark 大多是每秒 8 萬個，TC 掃到 19.7 萬個都還沒丟，那是我們掃描的上限。

**補充**
- 切片：每個 20 萬個 packet（`../tests/ids_throughput/` 實驗 5 的切片）。60-1 (Gafgyt) 是一條 UDP connection 佔大部分、小 packet；Honeypot-5-1 (Amazon Echo) 是 TLS 下載；CIC-IDS2017 Benign 是辦公室背景流量，443 為主；FTP-Patator 是大 packet（平均 1,289 bytes）；CIC-DDoS2019、CICIoT2023 Benign 是背景流量；DNS Spoofing 是 Spoofing 類的檔，大部分是背景流量。挑這 7 個是因為 trust_sim 模擬時 trust 的比例高；攻擊為主的切片幾乎不 trust，兩種做法沒有差別。connection 數 31–8,362 條。
- 兩種做法：C 是 eBPF 之前的 wnc-gw（commit `16137e0`），暖身之後用 `conntrack -U` 一次把所有 connection 設 mark；T 是現在的 wnc-gw，暖身之後 `wnc-gw trust add` 逐條 trust，`routed` 等每條都有 next hop 才開始量。
- 為什麼各切片的絕對值差很多（60-1 只有 8.8，其他 22–27）：packet 大小、connection 數不同，wnc-gw 本身也可能有固定成本（下一點，只在一個切片量過），**沒有拆開量**。
- wnc-gw 的固定成本：只在 CICIoT2023 Benign（8,360 條 connection）量過：trust 之後 wnc-gw 程序一直用約 130 ms／s（一顆 core 的 13%），沒有流量時也一樣；50 kpps 時**推算**約每個 packet 2.6 µs（130 ms／s ÷ 5 萬）。其他切片 connection 比較少，固定成本和 connection 數的關係**沒有量**。是哪一段程式**沒有查**（idle sweep 每 10 秒讀整個 trust map、next hop、control socket 都有可能）。
- 例外（`routed` 的 CICIoT2023 Benign）：查過的：99.96% 的 packet 都有 redirect、Suricata 的 CPU 是 0、沒有 IPv6、wnc-gw 本身的 CPU 兩種 `mode` 一樣；多出來的在 CPU1（網卡中斷）。它是 connection 最多（8,360）、平均 packet 最小（301 bytes）的切片。Pi 的 `perf_event_paranoid=4`，沒有用 perf；原因**沒有找到**。
- `ids` 的結果和 `ips` 幾乎一樣（trusted packet 兩種做法都不送 Suricata），所以只放 `ips`。完整的表在 `tests/cpu_alloc/README.md` 實驗 13。
- 容量（`bridge` ips，兩輪）：60-1 80 → 180、Honeypot-5-1 50–80 → 127 以上、CIC-IDS2017 Benign 80 → 80、FTP-Patator 80 → 193 以上、CIC-DDoS2019 Benign 80 → 50–80、CICIoT2023 Benign 80 → 100、DNS Spoofing 50 → 50–80。CIC-IDS2017 Benign 兩種做法都是 80，CIC-DDoS2019 Benign 的 TC 只有 50–80；TC 在 100 kpps 丟 0.1% 以上，原因**沒有查**。
- 先前只用 60-1 一個切片的 bench（E1，11/14）：TC 比 ct mark 少 5–6 µs、IRQ 搬到 CPU1 時容量 80 → 150 kpps，和這張表的 60-1 一致。
- 被問「不 trust、全部 inspection 的時候是多少」：這次量到的數字被 Suricata 的 drop-flow 拉低（重播的切片有超過 MTU 的幀、兩張網卡到 Pi 的順序和 pcap 不同），**不能當成 inspection 的成本**，要另外重量。11/09 第 5 頁的數字：全部進 Suricata 79.6–106.2 µs、trusted 40.0–97.1 µs（SYN／FIN／RST 照樣進 Suricata）；當時是 Pi 的 veth、10 kpps、Suricata 直接跑 NFQ（不是經過 wnc-gw）、含 tcpreplay，量法不同，不能和這頁直接比。

### 第 4 頁　套到 dataset

**投影片**
- 一行條件（小字）：照 wnc-gw 的 auto trust 條件離線重演 4 個 dataset 的全部 pcap。
- 表：

  | dataset | fast path 的 packet | 平均每個 packet（推算） | trust 之後才出現的 alert |
  |---|---|---|---|
  | IoT-23 | 0.14% | < 0.03 µs | 3／14,770,158 |
  | CIC-IDS2017 | 43.1% | −1.9 µs | 5／41,861 |
  | CIC-DDoS2019 | 0.07% | < 0.03 µs | 12／39,962 |
  | CICIoT2023 | 0.39% | < 0.03 µs | 43／596,012 |
  | 　其中 Benign | 55.5% | −2.2 µs | — |

**當場講**
上一頁是每個 trusted packet 省多少，整體省多少要看真實流量裡有多少 packet 會被 trust。我們寫了一個模擬器，照 wnc-gw 的 auto trust 條件，用 pcap 的時間戳重演四個 dataset 的全部 pcap，算出有多少 packet 會走 fast path。
正常流量多的 dataset 大約一半：CIC-IDS2017 43%、CICIoT2023 的 Benign 約 55%。攻擊為主的都不到 1%，因為 flood、scan 大多是單向、很短，夠不到兩個方向各 10 個 packet。
把比例乘上一頁的差，**推算**平均每個 packet 省 1.9 到 2.2 µs；攻擊為主的 dataset 幾乎沒有差別。
最右邊一欄是 trust 的風險：connection 被 trust 之後才出現的 alert，Suricata 看不到。數量很少，但 CIC-IDS2017 裡有 reverse shell、cmd.exe 這類 alert。這和用 TC 還是 ct mark 無關，兩種完全一樣，是 trust 的條件本身的問題。

**補充**
- 模擬器叫 trust_sim。各 dataset 的全部 packet 數（M 是百萬）：IoT-23 770 M、CIC-IDS2017 56 M、CIC-DDoS2019 312 M、CICIoT2023 4,482 M（其中 Benign 11 M）。
- 模擬了什麼（`tests/trust_sim/README.md`）：每 5 秒看一次 connection、≥ 5 秒且兩個方向各多 ≥ 10 個 packet、TCP 要 ESTABLISHED 才 trust；TTL 900 秒；trust 前有 alert 就不 trust、trust 後有 alert 就 revoke；SYN／FIN／RST、分片、多播交回 kernel、純 SYN 刪 trust；idle sweep；conntrack 的逾時照 kernel 預設。alert 用 10/30–11/01 離線跑 full rule set（11/02 報告）的結果，以 `pcap_cnt` 對到 packet。單元測試 37 個；alert 對錯的計數全部是 0。
- 近似：假設 pcap 裡每個 packet 都經過 gateway（pcap 是在某台主機或交換器上錄的，實際不一定）；alert 一出來就生效（沒有讀 EVE 的延遲；`ids` 的 alert 會晚到）；不模擬 conntrack 表滿（Pi 上 65,536 條；CICIoT2023 107 個檔的峰值超過）。
- 推算的算式：CIC-IDS2017 43.1% × −4.5（CIC-IDS2017 Benign 的 `bridge`）≈ −1.9；CICIoT2023 Benign 55.5% × −3.9 ≈ −2.2。只用 `bridge` 的差；`routed` 的差比較小。和全部 inspection 的成本比是百分之幾，要等 inspection 的成本重量（第 3 頁補充），**沒有算**。
- ct mark 和 TC 的 fast path 比例幾乎一樣（差最多 0.48 個百分點，CICIoT2023 BruteForce）。
- 漏掉的 alert 舉例：CIC-IDS2017 Thursday 的 `ET MALWARE Win32/Suspected Reverse Shell Connection`（2034945）、`GPL EXPLOIT Microsoft cmd.exe banner`（2102123）；Friday 的 HTTP 下載 EXE（2014519、2018959）；CICIoT2023 BrowserHijacking 的 BeEF（2018090、2038614–2038616）。其他是 P2P、DNS、爬蟲 User-Agent。做法**還沒決定**（第 10 頁）。
- IoT-23 另外有 487,051 條 connection 在 trust 之前就有 alert，被拒絕 trust。

### 第 5 頁　idle sweep 與長 connection

**投影片**
- 左：idle sweep（`tc` backend）
  - 一行：每 10 秒看一次，packet 數沒變超過 UDP 120 s、TCP 600 s → 刪掉 trust
  - 小表（trust_sim）：

    | dataset | idle sweep | 之後又有流量 | 多送 inspection 的 packet |
    |---|---|---|---|
    | IoT-23 | 1,950 | 27 | 0.000% |
    | CIC-IDS2017 | 100,703 | 146 | 0.019% |
    | CIC-DDoS2019 | 5,351 | 23 | 0.006% |
    | CICIoT2023 | 76,844 | 7,541 | 0.020% |

- 右：TLS 長 connection 回到 Suricata 會不會斷（Docker、Pi；`tc`、`ctmark` 結果相同）

  | | `ids` | `ips`＋`accept` | `ips`＋`drop` |
  |---|---|---|---|
  | idle：閒置 640 s 後恢復 | 不斷 | 不斷 | 不斷 |
  | gap：`trust del` 後繼續傳 | 不斷 | 不斷 | **斷** |

**當場講**
`tc` backend 多了一件事：trusted packet 不經過 conntrack，conntrack 的 entry 會自己逾時，但 trust map 不會。所以 wnc-gw 每 10 秒看一次 trust map，UDP 120 秒、TCP 600 秒沒有 packet 就刪掉，這兩個數字對齊 conntrack 的 UDP 和 Suricata 的 TCP 逾時。
開發者擔心的是：HTTPS 這種長 connection 會不會一直被刪掉、又回到 Suricata。左邊是模擬的結果：被刪掉的 connection 之後又有流量的很少，CIC-IDS2017 十萬條裡只有 146 條，多送 inspection 的 packet 都在 0.02% 以下。
右邊是實測：一條 TLS 1.3 的長 connection，兩種情況回到 Suricata。idle 是閒置超過 600 秒再恢復，這時 Suricata 已經忘了這條 connection，從中途接手；gap 是 trust 中途被拿掉，Suricata 還記得，中間少了一段資料。結果只有一種會斷：gap、`ips`、`when_unavailable` 設 `drop`，因為 Suricata 看到資料缺一段，把整條 connection 丟掉。預設的 `accept` 不會斷。

**補充**
- idle sweep 用 packet 數有沒有變來判斷，精度 10 秒；不讀 kernel 的時間（`bpf_ktime_get_ns` 是 CLOCK_MONOTONIC，Rust std 拿不到）。`ctmark` 沒有 idle sweep，conntrack 的 entry 逾時 mark 就跟著消失。
- 被刪掉的 trust 有一個行為：wnc-gw 的 auto trust 裡那條 connection 還是 trusted，要等 TTL（900 秒）到期才會重新觀察，這段時間的 packet 全部送 inspection。這是 trust_sim 照程式重演看到的，做法**還沒決定**。
- 之後又有流量的 connection 大多是 NTP、NetBIOS、LDAP 和 CICIoT2023 裝置的長 connection（port 55444、10001），443 很少（CIC-IDS2017 19 條、107 個 packet）。
- 實測的做法（`tests/ebpf/README.md`）：用戶端每送一行等伺服器回音，5 秒沒回就算斷；auto trust 用預設值。idle：忙 20 秒 → 閒置 640 秒 → 每秒一行 330 秒。gap：忙 20 秒 → `trust del` → 忙 30 秒。
- 斷的原因（抓包＋Suricata 計數）：`trust del` 之後第一個資料段觸發 `tcp.reassembly_gap`、`app_layer.error.tls.gap`；`ips`＋`drop` 時 wnc-gw 把 `app-layer.error-policy` 設成 `drop-flow`（11/09 的 `when_unavailable` 跟著 exception policy），之後兩個方向的資料都被丟。`accept` 時只記數。
- `ips` 從中途接手之後，關 connection 的 FIN 可能被丟（`stream.fin_invalid_ack`）：Docker 兩種 backend、Pi 的 `ctmark` 都有，資料一個都沒丟，但伺服器那端要等逾時才關。為什麼 ACK 對不上**沒有查**。
- 什麼時候會發生 gap：之後 cloud 或 alert revoke 一條還在傳的 connection 時。

### 章節頁　`[trust] backend`

### 第 6 頁　`tc` 與 `ctmark`

**投影片**
- 一行設定：`[trust] backend = "tc"`（default）／`"ctmark"`，二選一，不自動切換。
- 比較表：

  | | `tc`（default） | `ctmark` |
  |---|---|---|
  | trust 存在 | trust map（5-tuple，每個方向一筆） | conntrack entry 的 ct mark |
  | port 重用 | 純 SYN 刪 trust | 純 SYN 清 mark |
  | 偽造同 5-tuple 的 packet | 沒有 TCP 序號檢查 | conntrack 的序號檢查 |
  | TCX 不能用 | 沒有 trust（全部 inspection） | 不影響 |

**當場講**
11/17 把 ct mark 拿回來當選項：`[trust] backend` 預設 `tc`，設成 `ctmark` 就是 11/09 的做法，兩個只能用一個。為什麼要留 ct mark：TC 的做法要 kernel 有 TCX（6.6 以上）、wnc-gw 要有 `CAP_BPF` 和 `CAP_NET_ADMIN`；掛不上的時候（kernel 太舊、缺權限、port 不存在，D001），`tc` 就沒有 trust，所有 packet 都進 Suricata。port 上有別人的 TCX 程式不會讓 trust 消失，只是 warning（D002、D006），trust 照常。我們不自動切換，doctor（D005）和 log（D001、T014）會提示，建議改成 `ctmark`，讓使用者知道現在是哪一種。
表上幾個差別：
11/09 說 trust 不用 5-tuple，因為會被 port 重用或偽造的 packet 繞過。`tc` 的 trust map 就是 5-tuple：port 重用時會先看到純 SYN，TC 就把兩個方向的 trust 刪掉，效果和 ct mark 一樣；但偽造一個 5-tuple 相同的 packet，`tc` 沒有 conntrack 的序號檢查，這是還沒處理的風險，之後在 TC 自己檢查序號，map 已經留了欄位。
成本：用現在的程式在 Pi 上同樣 7 個切片重量，`ips` 時 `ctmark` 每個 trusted packet 比 `tc` 貴，`bridge` 3.7 到 8.5 µs，`routed` 0.8 到 4.4 µs。所以 `tc` 維持 default。

**補充**
- 表上的「TCX 不能用」：啟動時 `tc` 掛不上 core eBPF program（D001）：kernel 沒有 TCX（6.6 以前）、wnc-gw 缺 `CAP_BPF`／`CAP_NET_ADMIN`，或 port 不存在。port 上有別人的 TCX 程式不算，只是 warning（D002、D006），trust 照常；執行中 core eBPF program 被別人 detach、或網卡被拔掉（D003）時，那個 port 的 trust 也會失效。
- 表上沒有的兩個差別：trusted packet 怎麼放行，`tc` 是 TC redirect（第 2 頁），`ctmark` 是 netfilter forward chain accept（11/09 的做法）；idle sweep 和 next hop，`tc` 都有，`ctmark` 沒有 idle sweep（跟著 conntrack 逾時），next hop 是 kernel 自己查。
- 每個 trusted packet 的成本（Pi，`ips`，50 kpps，`ctmark` 比 `tc` 貴）：`bridge` +3.7–8.5 µs、`routed` +0.8–4.4 µs；`ids` 時 `bridge` +4.2–8.5 µs、`routed` +1.8–4.5 µs（不含 `routed` 的 CICIoT2023 Benign 這個例外）。這是實驗 14 的 K（現在程式的 `ctmark` backend）對 T（`tc`）。
- 和第 3 頁的差別：第 3 頁是 eBPF 之前的舊 ct mark（實驗 13 的 C，commit `16137e0`，沒有 core eBPF program）對 TC；上一條是現在程式的 `ctmark` backend（實驗 14 的 K）對 `tc`，所以數字不同；K 比 C 多一支掛著的 core eBPF program（見下面「`ctmark` 時 core eBPF program 照樣掛」那一條：`bridge` 約 +1 µs、`routed` 約 +0.3 µs），所以這裡的差比第 3 頁大。
- 為什麼放在 `[trust]` 裡：最上層寫 `trust = "tc"` 會和既有的 `[trust]` 區塊在 TOML 裡衝突（DECISIONS §22）。
- 偽造的風險是**推論**（設計上沒有序號檢查），還沒有實驗；是論文 RQ3 第 4 項的實驗條件。`ctmark` 這一欄也是**推論**：序號不在窗內的 packet conntrack 不會接到原本的 entry，沒有 mark，送 Suricata；序號在窗內的偽造 packet 兩種都擋不住。
- `ctmark` 時 core eBPF program 照樣掛（feature program 和之後的特徵要用），trust map 是空的，每個 packet 多一次查不到的 lookup：和沒有 core eBPF program 的舊 ct mark 比，`bridge` 約 +1 µs、`routed` 約 +0.3 µs。`bridge` 比 `routed` 多的原因**沒有查**。
- `ctmark` 啟動時先清掉上一次留下的 mark（`kill -9` 之後 mark 留在 conntrack；Docker 驗過）。
- 加了 backend 這個選項之後 `tc` 有沒有變慢（實驗 14，Pi，7 切片 × 2 種 `mode` × `ips`／`ids`，2 輪）：28 格裡 21 格差在 ±0.2 µs 內，沒有兩輪都變慢的格子。設定只在啟動時選一次，每個 packet 的路徑都在 kernel。
- 容量：`ctmark` 在 `bridge` 50–80 kpps、`routed` 50–120 kpps；`tc` 50–197 kpps。例外同第 3 頁：`routed` 的 CICIoT2023 Benign `ctmark` 便宜 1.5 µs。
- 驗證：Docker 的 fast path 測試全部用 `BACKEND=ctmark` 重跑一次，trust 期間 `ids` chain 的 counter 停住、`del` 後恢復、port 重用清 mark（`tests/ebpf/README.md`）。

### 章節頁　特徵

### 第 7 頁　特徵框架

**投影片**
- 一張流程圖（左到右）：
  - 使用者提供（左邊一欄）：`flows.o`（feature program）、`flows.json`（definition）
  - wnc-gw：檢查格式 → 掛到 hook → 每 `interval` 秒讀 map → 解碼 → derived → `features/<name>.jsonl`
  - 虛線：→ edge AI、cloud
- 下面一行兩個原則（短句）：
  - 不提供 feature program
  - 不預先定義特徵，只提供運算

**當場講**
特徵的部分，草稿寫的是「eBPF 算特徵的程式」，但我們決定 wnc-gw 不提供 feature program，也不預先定義特徵：要算什麼由使用者自己寫 eBPF 決定，例如之後的 edge AI 或 cloud 的模型要什麼特徵。wnc-gw 只做框架：使用者給一支 eBPF 程式和一個 JSON 的 definition，說明 map 裡每個欄位的格式；wnc-gw 先檢查格式對不對，掛到指定的位置，定期讀 map、解碼，再用我們提供的運算算出 derived 的欄位，例如速率、平均、標準差，最後寫成 JSON lines。送到 edge AI 和 cloud 還沒做。
definition 不用 JSON Schema，因為 JSON Schema 沒有整數寬度、byte order、欄位順序這些我們需要的東西，它其他的功能也用不到。

**補充**
- 圖上沒有標的：檢查格式是 `doctor`、`run` 都會做；ring buffer 是有資料就讀、不看 `interval`。第三個原則是 definition 用自己的簡單 JSON，不用 JSON Schema（當場講最後一段）。
- 設定（`[[features]]`，最多 16 個）：`name`、`program`、`entry`、`definition`、`hook`（必填、沒有預設）、`xdp_mode`（只能配 `hook = "xdp"`）、`interval`（1–3600 秒，預設 1）。
- 輸出：`<log 目錄>/features/<name>.jsonl`，每筆一行，64 MiB 時改名成 `.jsonl.1`（只留一份舊的）。
- 支援的 map：hash、per-CPU hash、array、per-CPU array、LRU hash、LRU per-CPU hash、ring buffer；per-CPU 的 map 依 `merge`（sum、min、max、or、first）合併每個 CPU 的值。
- 運算寫成 JSON 物件，不用運算式語言：不需要 parser，避開 parser 那一類的 DoS 漏洞。跨 connection 的彙總（依主機、時間窗）第一版不做。
- 安全：檔案路徑必須是絕對路徑，doctor 檢查非 root 改不改得了 ELF 和 definition；簽章**還沒做**。
- 成本（Pi 上 feature program 每個 packet 多幾 µs、讀 map 和解碼每筆幾 µs、connection 多時一次讀多久）**沒有量**。
- 測試用的 feature program（`tests/features/prog/`）是我們為了驗證框架寫的，不是要交付的特徵。

### 第 8 頁　definition

**投影片**
- 左：`flows.json` 的節錄（code block，從 `tests/features/flows.json` 縮短：key 的五個欄位全部列出、順序和檔案一樣；value、derived 各留前三個，`…` 是省略的欄位）：

  ```json
  {
    "map": "FLOWS",
    "key":   [{"name": "saddr", "type": "ipv4"},
              {"name": "daddr", "type": "ipv4"},
              {"name": "sport", "type": "u16", "endian": "big"},
              {"name": "dport", "type": "u16", "endian": "big"},
              {"name": "proto", "type": "u8"}],
    "value": [{"name": "packets",   "type": "u64"},
              {"name": "bytes",     "type": "u64"},
              {"name": "len_sumsq", "type": "u64"}, …],
    "derived": [
      {"name": "pps",      "op": "rate", "of": "packets"},
      {"name": "len_mean", "op": "mean", "sum": "bytes", "count": "packets"},
      {"name": "len_std",  "op": "std",  "sum": "bytes",
                           "sumsq": "len_sumsq", "count": "packets"}]
  }
  ```

- 右上：一行標題「運算：13 種」，不列名稱。
- 右下：載入前的檢查（表）：

  | 檢查 | 抓得到 |
  |---|---|
  | ELF 有這個 map、種類支援 | 名稱打錯 |
  | key／value 的長度 | 漏欄位、型別寫錯 |
  | BTF 逐欄比對 offset | 長度一樣但順序寫反 |
  | derived 的引用 | 欄位不存在、循環 |

**當場講**
這是測試用的 definition 縮短的版本，value 和 derived 只留前幾個。key 和 value 照 eBPF 程式裡 struct 的順序列出每個欄位的型別；padding 照 C 的對齊規則自動算，不用使用者寫。derived 用運算組出特徵：`pps` 是 packet 數和上一次讀的差除以時間，`len_mean`、`len_std` 是 packet 長度的平均和標準差，eBPF 只要累加總和和平方和。
右邊是目前的 13 種運算，和載入前的檢查。長度不合一定抓得到；程式帶 BTF 的話，連兩個欄位順序寫反也抓得到，例如把 `packets` 和 `bytes` 對調，doctor 會指出 offset 不一樣。抓不到的是欄位的意思對不對，所以另外有 `wnc-gw features test`：把 pcap 的 packet 一個一個餵給使用者的程式，印出解碼和運算之後的結果，讓使用者自己對。

**補充**
- 13 種運算，分四行：add、sub、mul、div、scale；mean、var、std；delta、rate；bucket、percentile、enum。
- 型別：u8–u64、i8–i64、`ipv4`、`ipv6`、固定長度陣列（`"len": N`）；`endian` 預設 little。`"packed": true` 時不補 padding。doctor 印出每個欄位算出來的 offset 和總長。
- 運算的細節：整數的加減乘保持整數；溢位和除以 0 輸出 null；var／std 是母體變異數；delta、rate 第一次讀沒有值（null）；percentile 用直方圖，回傳桶的上界；enum 把整數對應成字串（送 cloud 只能是數值、bool、事先宣告的 enum）。
- BTF：libbpf 的 `.maps`（`__type(key/value)`）或 aya-ebpf `#[btf_map]` 宣告的 map 才有；舊式 `#[map]` 只比長度（warning G007）。ring buffer 的記錄型別如果沒宣告，執行時逐筆查長度，不合就丟掉、計數（G013）。
- `features test`：用 `BPF_PROG_TEST_RUN`，程式只載入不掛；pcap 最多 100 萬個 packet。Docker 驗證：20 個 UDP＋5 個 TCP 的 pcap，hash、per-CPU hash、XDP 的 hash 都得到 20／5 兩條，ring buffer 25 筆。
- 驗證（Docker，`tests/features/`）：hash／per-CPU hash 通過、舊式 map G007、`packets`／`bytes` 對調 error G006。run 時 bytes、長度平方和、直方圖、mean、std、enum、percentile、pps 都和手算一致。

### 第 9 頁　hook：看得到哪些 packet

**投影片**
- 表：

  | `hook` | trusted packet（`tc`） | 被丟掉的 packet |
  |---|---|---|
  | `xdp` | 看得到 | 看得到 |
  | `tc-ingress` | **看不到** | 看得到 |
  | `tc-egress` | 看得到 | **看不到** |

**當場講**
feature program 掛在哪裡，使用者一定要自己選，沒有預設，因為三個位置看到的 packet 不一樣，沒有一個全部看得到。
`xdp` 在最前面，什麼都看得到，而且看到的是 GRO 合併之前的原始 frame，大小和間隔比較準；但 Pi 的網卡沒有 native XDP。
`tc-ingress` 排在我們的 core eBPF program 後面，`tc` backend 的 trusted packet 已經被 redirect 走了，所以看不到。
`tc-egress` 是另一個 port 的出口，trusted packet 看得到，但被 Suricata 丟掉的 packet 不會到這裡。
驗證過這個結果：先送 20 個沒 trust 的、再送 20 個 trusted 的，數每個 hook 數到的 packet 數；`tc` backend 時 `tc-ingress` 只數到 20，其他兩個是 40；`ctmark` 時 trusted packet 不在 TC redirect，三個都是 40。Docker 和 Pi 的結果一樣。

**補充**
- GRO：看到的 packet 是 GRO 合併前還是合併後；`xdp` 是合併前（native XDP 時），`tc-ingress`、`tc-egress` 是合併後。
- 驗證的設定：20 個不 trust ＋ 20 個 trusted 的 UDP，數字是每個 hook 數到的 packet 數；Docker、Pi 相同（結果在當場講最後一段）。
- 為什麼 `tc-ingress` 看不到：core eBPF program 對沒 trust 的 packet 回傳 `TCX_NEXT`、trusted 的回傳 redirect，TCX 的鏈就結束（`gw-ebpf/src/main.rs`）。
- 沒有做的另一種做法：freplace（core eBPF program 在 redirect 前呼叫使用者的函式）：每個 packet 都多一次呼叫，沒用特徵的人也要付。
- 一張網卡只能掛一個 XDP 程式（Pi 上驗證：第二個回 `EEXIST`），所以兩個以上 `hook = "xdp"`，或 port 上已經有別的 XDP 程式，doctor 是 error（G015）。`xdp_mode` 預設 native，port 沒有 native XDP 是 error（G009）；generic 要明寫，給 warning（G010），generic 會讓整張網卡不做 GRO。
- Pi 的功能確認（11/19，veth、`bridge`）：`bridge` 的 `bpf_redirect` 出去的 packet 也經過另一個 port 的 egress；BTF 宣告的 map 在沒有 vmlinux BTF 的 Pi kernel 上照樣載入；`features test` 和 Docker 一樣。
- 寫 feature program 的限制：wnc-gw 之後以沒有 `CAP_PERFMON` 的權限載入，verifier 會拒絕某些寫法（小陣列清零、map value 用變數索引、XDP 用 `data_end - data`），`tests/features/README.md` 有改法。

### 第 10 頁　待決與下一步

**投影片**
- 待決（四點，短句）：
  - trust 之後的 alert Suricata 看不到
  - `tc` 沒有 TCP 序號檢查
  - `ips` 從中途接手後 FIN 可能被丟
  - 特徵的成本（Pi）
- 下一步（兩點）：
  - 特徵送 edge AI、cloud（先做模擬的 cloud）
  - timer 對齊：Suricata 的 `flow-timeouts`、TTL、idle sweep、conntrack

**當場講**
還沒決定的有四件：第一，trust 之後才出現的 alert Suricata 看不到，要不要對 trusted connection 做部分 inspection，或調整 trust 的條件；第二，`tc` 沒有 TCP 序號檢查，偽造的 packet 可能不經 inspection，之後在 TC 自己檢查；第三，`ips` 從中途接手 connection 之後關 connection 的 FIN 可能被丟，原因**還沒查**；第四，特徵在 Pi 上的成本**還沒量**。
下一步是把特徵送到 edge AI 和 cloud，先用我們自己做的模擬 cloud；另外是幾個 timer 的對齊：Suricata 忘掉 connection 的時間、TTL、idle sweep 和 conntrack 的逾時，誰先到期決定 connection 回到 Suricata 時是 gap 還是從中途接手，也就是第 5 頁那兩種情況。

**補充**
- 部分 inspection 的先前實驗（DECISIONS §20 O20，Docker）：只 inspection 每段開頭可以抓到後段的攻擊，約送 5–8% 的 packet；固定長度會被「先塞資料再攻擊」繞過，隨機長度 83–90% 抓得到。tc eBPF 的實作成本、Pi 上的量測**沒有做**。
- `ids` 的 alert 比 `min_age` 晚到（11/09 補充講過）：還沒處理。
- 不 trust 的 inspection 成本要重量：用沒有大幀、低速率或單一網卡的流量（第 3 頁補充）。
- 沒解釋的量測：CICIoT2023 Benign 的 8,360 條 trust 之後 wnc-gw 固定約 130 ms／s（只在這個切片量過）；`routed` 的 CICIoT2023 Benign TC 比 ct mark 貴；wnc-gw 比同樣送法的 bench 貴 0.3–0.6 µs。
- 每次讀 conntrack 會停住事件迴圈（約 7 ms＋每條 9.4 µs）；改法**還沒決定**：讀表放到另一個執行緒，或改用 conntrack 的 NEW／DESTROY 事件（DECISIONS §19）。
- timer 對齊：全部設成一樣會變成競賽（誰先到期不確定），要實驗決定順序；**還沒跑**。

### Q&A

- 投影片：`Q&A`。
- 當場講：以上是這次的報告，謝謝，歡迎提問。

### 講稿補充最後：沒有投影片的新東西（被問到再講）

- doctor 和 run 的每個訊息都有代碼（例如 D001、T014、G006），`wnc-gw explain <代碼>` 印出原因和修法。
- 設定只保留相關的欄位：例如 `protection = "ids"` 卻寫了 `suricata.queue`、`trust.auto = false` 卻寫了 `min_packets`，直接報錯（C004），避免使用者以為設定生效了。
- `wnc-gw trust add／del／list` 改經 `/run/wnc-gw/control.sock` 請 `run` 寫 trust map（權限 0600，只收 root 或 run 的帳號）；`add` 先確認 connection 存在、而且是經過 gateway 轉送的。

## 5. 給製作的 subagent

- 原始碼：`src/main.typ`，`#import "../../template.typ": *`。版面、小工具（`m()`、`sn()`、`frame()`、`small-tbl()`、`note()`）和架構圖直接參考 `../20261109_security_gateway_專案介紹_Demo/src/main.typ`；第 1 頁的架構圖從那份的第 2 頁改。
- 編譯：在報告資料夾跑 `../build.sh -p`，逐頁 PNG 在 `/tmp/<資料夾名>/`，每一頁都要看過：沒有超出頁面、沒有被截斷、表格沒有換行換得很難看、圖的箭頭標籤沒有和節點重疊。
- 輸出：`Security_Gateway_專案進度.pdf`（build.sh 依 title 產生，資料夾裡只能有這一個 PDF）。
- 講稿：`逐字稿.md`，格式照 `../20261109_security_gateway_專案介紹_Demo/逐字稿.md`：檔頭（日期、對應投影片、頁碼說明）、使用方式（含用詞與單位的定義）、**一、當場講**（封面到 Q&A 連著讀，只放要講的話）、**二、補充**（每頁的怎麼讀、實驗怎麼做、被問到時，頁碼對應，不用 `>`）。內容照本文件每頁的「當場講」「補充」，可以順句子，但數字、名詞、推算／推論／沒有量的標記不能改。不要寫改動紀錄。
- 本文件沒寫到的數字不要自己加；需要的話先查 `../../security_gateway/DECISIONS.md`、`../../tests/ebpf/README.md`、`../../tests/cpu_alloc/README.md`、`../../tests/trust_sim/README.md`、`../../tests/features/README.md`，並在回報裡列出加了什麼、出處在哪。

## 6. 查證後的修正（2026-11-19）

依 `驗證報告.md`「需要修改」的 24 項，改了 `src/main.typ`、`逐字稿.md` 和本文件（本文件裡規格本身錯的地方，本文直接改成正確的）。

**有誤**
1. 第 3 頁補充的 11/09 數字：「71–106、33–40」改成 11/09 第 5 頁實際的數字：全部進 Suricata 79.6–106.2 µs、trusted 40.0–97.1 µs（SYN／FIN／RST 照樣進 Suricata），並註明當時是 Pi 的 veth、10 kpps、Suricata 直接跑 NFQ、含 tcpreplay，條件不同、不能和這頁直接比。
2. 第 6 頁「port 上有別人的 TC 程式 → `tc` 沒有 trust」：當場講和補充改成：沒有 trust 的原因是 D001（kernel 沒有 TCX〔6.6 以前〕、缺 `CAP_BPF`／`CAP_NET_ADMIN`、port 不存在）；別人的 TCX 程式只是 warning（D002、D006），trust 照常；執行中被 detach 或網卡被拔掉是 D003。
3. 逐字稿「trust 搬到 TC」章節頁移到第 1 頁之後；使用方式裡的順序說明一併改。

**誤導**
4. 第 10 頁補充：「11/04 建議移到別的執行緒，還沒做」改成「改法**還沒決定**：讀表放到另一個執行緒，或改用 conntrack 的 NEW／DESTROY 事件（DECISIONS §19）」。
5. 第 8 頁 code block：key 寫出全部五個欄位（`saddr`、`daddr`、`sport`、`dport`、`proto`，順序同 `flows.json`）；value、derived 仍各留前三個，用 `…` 標省略。字級 13pt 改 12pt 才放得進一頁。
6. 第 3 頁補充：2.6 µs／packet 標成**推算**（130 ms／s ÷ 5 萬），註明 130 ms／s 只在 CICIoT2023 Benign（8,360 條 connection）量過，固定成本和 connection 數的關係**沒有量**；第 10 頁補充的 130 ms／s 同樣註明；「各切片絕對值差很多」那段改成「可能也有固定成本」。
7. 第 6 頁表最後一列加 `ips`；當場講「`ips` 時」；`ids` 的範圍（`bridge` +4.2–8.5、`routed` +1.8–4.5，不含 `routed` 的 CICIoT2023 Benign 例外）放補充。
8. 第 1 頁當場講：「ct mark 的做法沒有拿掉」改成 11/14 改成 TC 時拿掉、11/17 拿回來。

**輕微**
9. 第 2 頁補充：next hop 省多少的實驗編號 11、12 改 10、12。
10. 第 2 頁補充的驗證：Docker 只測 IPv4（testbed 的 gw 不轉送 IPv6）；Pi 含 IPv6 TCP；Pi `bridge` 的 TCP 多 2 個 IPv6 多播 packet 交回 kernel。
11. 第 3 頁補充容量：「CIC-IDS2017、CIC-DDoS2019 Benign 兩者都是 80」改成 CIC-IDS2017 Benign 兩種做法都是 80、CIC-DDoS2019 Benign 的 TC 只有 50–80。
12. 第 3 頁補充：「Pi 上不能用 perf」改成 `perf_event_paranoid=4`、沒有用 perf。
13. 第 4 頁當場講：Benign「56%」改「約 55%」（表上 55.5%）。
14. 第 4 頁補充：alert 的日期「11/02 離線跑」改成 10/30–11/01 離線跑、11/02 報告。
15. 第 3 頁當場講：改成只留經過 gateway、會走 fast path 的 packet（拿掉 SYN、FIN、RST、多播、分片），每段實際送 10 到 20 萬個。
16. 第 3 頁當場講：「TC 最高到 19.7 萬個」改成掃到 19.7 萬個都還沒丟（掃描的上限）。
17. 第 6 頁當場講：「doctor 和 log 會給 warning」改成 doctor（D005）和 log（D001、T014）會提示。
18. 第 7 頁圖與補充：「每 `interval` 秒讀 map（或 ring buffer）」改成 ring buffer 有資料就讀、不看 `interval`。
19. 第 7 頁補充：支援的 map 補 per-CPU array、LRU hash、LRU per-CPU hash。
20. 第 8 頁補充：「四種 map 都得到 20／5 兩條」改成 hash、per-CPU hash、XDP 的 hash 得到 20／5 兩條，ring buffer 25 筆。
21. 第 10 頁當場講：「FIN 會被丟」改「FIN 可能被丟」；投影片上的短句同步改成「FIN 可能被丟」。
22. 逐字稿檔頭：next hop 的定義改成「路由有 gateway 時是那個 router 的位址，直接相連時是目的地本身」。
23. 名詞：「auto trust 規則」「trust 規則本身」改成「auto trust 條件」「trust 的條件」（投影片第 4 頁、逐字稿、本文件）；逐字稿檔頭「check 只用在 doctor 的檢查項目」改成 Suricata 的檢查一律寫 inspection、不寫成「檢查」。
24. 標記：逐字稿「還沒找到」「還沒查」「還沒量」加粗，並加進使用方式列的標記清單（第 10 頁補充的「還沒做」已隨第 4 項改成「還沒決定」）。

## 7. 審稿後的刪減（2026-11-19）

審稿後從投影片拿掉下列內容。投影片拿掉之後，講稿（`逐字稿.md`）裡還沒有的內容補進對應頁的「二、補充」，講稿裡已經有的不重複；第 4 節各頁的規格、「當場講」「補充」同步改成拿掉之後的樣子。本節以下的頁碼，除了標「原」的以外都是新頁碼。

**頁碼對應**（整頁刪掉大綱，之後每頁往前移一號；本文件第 0–6 節和 `逐字稿.md` 的頁碼已全部改成新頁碼，指向 11/09 那份簡報的頁碼不動）

| 原頁碼 | 標題 | 新頁碼 |
|---|---|---|
| 1 | 大綱 | 刪除 |
| 2 | 11/09 之後做了什麼 | 1 |
| 3 | fast path：packet 怎麼走 | 2 |
| 4 | 每個 trusted packet 省多少（Pi） | 3 |
| 5 | 套到 dataset | 4 |
| 6 | idle sweep 與長 connection | 5 |
| 7 | `tc` 與 `ctmark` | 6 |
| 8 | 特徵框架 | 7 |
| 9 | definition | 8 |
| 10 | hook：看得到哪些 packet | 9 |
| 11 | 待決與下一步 | 10 |

投影片共 15 頁（封面、章節頁、Q&A 不編號），編號第 1–10 頁。

**1. 原第 1 頁「大綱」整頁刪除**
- 逐字稿「一、當場講」的「第 1 頁　大綱」整節刪掉（內容是三個部分加待決與下一步的順序，封面和各章節頁已經講出）；檔頭的頁數、頁碼說明、使用方式裡的順序同步改。

**2. 原第 2 頁（新第 1 頁）**
- 刪：core eBPF program → netfilter 箭頭的 `TCX_NEXT` 標籤；wnc-gw → cloud 箭頭的「特徵／trust／block／observe」標籤；下方的時間軸（四個日期點）。
- 版面：時間軸拿掉後，架構圖的節點、字級、上下間距放大，圖和圖例在頁面上置中。
- 講稿：`TCX_NEXT`（交回 kernel 的 packet）本來就在補充的怎麼讀，改成「圖上沒有標」；補充「被問到時」新增兩條：四個日期（11/14 core eBPF program、trust 搬到 TC；11/14 idle sweep、`routed` 的 next hop；11/17 `[trust] backend`；11/18–19 特徵框架）、wnc-gw 和 cloud 之間的箭頭內容（往 cloud 送特徵；cloud 回 trust、block、observe）。當場講沒有提到時間軸，不動（已經口頭講 11/14、11/17 兩個日期）。

**3. 原第 3 頁（新第 2 頁）**
- 刪：netfilter 框內的「forward chain → `ids` chain」；fast path 條件小字裡的「分片、廣播／多播」（保留 SYN／FIN／RST）；「純 SYN：刪兩個方向的 trust」標籤（trust map 的雙向箭頭保留）；表格的「redirect」欄；「（TTL ≤ 1 交回 kernel）」。
- 講稿：這幾項本來都在補充的怎麼讀和當場講；怎麼讀的文字改成「圖上只標 SYN／FIN／RST」「netfilter 裡是 forward chain → `ids` chain」「trust map 的雙向箭頭是查詢和刪除」，並把 redirect 的 helper（`bridge` 用 `bpf_redirect`、`routed` 用 `bpf_redirect_neigh`＋next hop）和 TTL ≤ 1 交回 kernel 寫成「不在投影片上」。

**4. 原第 5 頁（新第 4 頁）**
- 刪：副標的「（trust_sim）」；表格的「packet」欄。
- 講稿：補充的怎麼讀新增一條各 dataset 的全部 packet 數（IoT-23 770 M、CIC-IDS2017 56 M、CIC-DDoS2019 312 M、CICIoT2023 4,482 M、其中 Benign 11 M），並寫明模擬器叫 trust_sim；欄位說明拿掉「packet」欄。

**5. 原第 7 頁（新第 6 頁）**
- 刪：比較表的「trusted packet」列、「idle sweep／next hop」列、最後一列「每個 trusted packet（Pi，`ips`，50 kpps）」。
- 講稿（補充「被問到時」）：
  - 「trusted packet」「idle sweep／next hop」兩列：`tc` 是 TC redirect、`ctmark` 是 netfilter forward chain accept；idle sweep 和 next hop，`tc` 都有，`ctmark` 沒有 idle sweep（跟著 conntrack 逾時），next hop 是 kernel 自己查。
  - 成本那列：`ctmark` 比 `tc` 貴，`bridge` +3.7–8.5 µs、`routed` +0.8–4.4 µs（`ids` 時的範圍沿用原有的一條）。補充一條和第 3 頁的差別：第 3 頁是 eBPF 之前的舊 ct mark（實驗 13 的 C，commit `16137e0`）對 TC；這列是現在程式的 `ctmark` backend（實驗 14 的 K）對 `tc`，所以數字不同；K 比 C 多一支掛著的 core eBPF program，差距多約 1 µs（`bridge`）、0.3 µs（`routed`）。
  - 當場講關於成本的那句（「所以 `tc` 維持 default」）保留口頭講，不動。
  - 補充原有的「表上 `tc` 那格的『—』」一句因為該列已刪，一併拿掉。

**6. 原第 8 頁（新第 7 頁）**
- 刪：「檢查格式」框內的 `doctor／run`；「（ring buffer：有資料就讀）」；第三個原則「definition 用自己的簡單 JSON」（投影片剩兩個原則）。
- 講稿：`doctor`／`run`、ring buffer 有資料就讀本來就在補充的怎麼讀；第三個原則改寫成「投影片上沒有的第三個原則是 definition 用自己的簡單 JSON，不用 JSON Schema（當場講最後一段）」，當場講本來就有。

**7. 原第 9 頁（新第 8 頁）**
- 刪：右上「運算」只留標題一行「運算：13 種」，逐一列出的運算名稱拿掉。
- 講稿：13 種運算的四行名稱本來就在補充的怎麼讀，改成「右上只標『運算：13 種』，沒有列名稱」。

**8. 原第 10 頁（新第 9 頁）**
- 刪：上表的「GRO」欄；下方驗證的小字與 20／40／40 小表。
- 講稿：補充「被問到時」新增 GRO（`xdp` 合併前〔native XDP 時〕、`tc-ingress`／`tc-egress` 合併後）和驗證的設定（20 個不 trust ＋ 20 個 trusted 的 UDP、數字是每個 hook 數到的 packet 數、Docker 和 Pi 相同）；驗證的數字（`tc` 是 20／40／40、`ctmark` 是 40／40／40）本來就在當場講，只把「下面是驗證」「表上的數字」改成不指向投影片的說法。

**版面**
- 拿掉內容後，第 1、2、4、6、7、8、9 頁的圖、表、字級各放大一點，內容在頁面上置中，沒有留下大片空白。
