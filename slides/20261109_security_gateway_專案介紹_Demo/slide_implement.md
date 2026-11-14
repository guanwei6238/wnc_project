# slide_implement.md — Security Gateway 專案介紹 & Demo

> 投影片的規格：每一頁放什麼、數據從哪個檔案來、講稿要講什麼。
> 與 `src/main.typ` 同步；兩者不一致時以 `main.typ` 為準。講稿：`逐字稿.md`；草稿：`user_draft.md`。
> 頁碼一律是投影片右下角顯示的頁碼（封面、章節頁、Q&A 不編號）。
> 「當場講」「補充」的內容不印到投影片上。

---

## 0. 這次報告的定位

- 日期 2026-11-09。對象：計畫方（公司）和老師。10/19 老師要求「下次要有一個能跑的 gateway，不用 UI」，這次就是交出 wnc-gw 並 demo。
- 草稿要求：依 `../security_gateway/README.md`、`DECISIONS.md` 介紹整體架構、doctor、支援的 setting；demo 的細節在 `../tests/demo/`，**demo 要提的東西投影片都要講到**。
- 前幾次已經講過的不重講：09/21 的 XDP → netfilter → NFQUEUE 管線與「為什麼不用 DPDK」、10/05 的 RFC 9411 與 dataset、10/19 選 Suricata、11/02 的偵測結果。這次只在講稿裡一句帶過。
- 11/09 的 demo 用 **Docker、手動操作**，流程是 `../tests/demo/DOCKER.md`（不是 `README.md` 裡的 `demo.sh` 實機版）。實機版 11/04–05 在 Pi 上演練過，投影片只提一句「Pi 上同樣跑過」。

## 1. 查證結果（製作前）

對照的來源：`security_gateway/README.md`、`DECISIONS.md`、`setting.example.toml`、`src/config.rs`、`src/cli/mod.rs`、`tests/demo/DOCKER.md`、`tests/demo/README.md`、`tests/cpu_alloc/README.md`、`.claude/skills/gateway-architecture/SKILL.md`、`.claude/skills/gateway-development/references/doctor-checks.md`。

| 項目 | 查證 | 結果 |
|---|---|---|
| 子命令 | `src/cli/mod.rs` 的 `Command` | doctor、run、show、trust 四個，和 README 一致 |
| setting 欄位與預設 | `src/config.rs`、`setting.example.toml` | 和 README 一致（下面 p8 的表就是從這兩個檔案抄的） |
| doctor 的實際輸出 | 2026-11-06 在 Docker testbed 跑 `wnc-gw -c /etc/wnc-gw/demo.toml doctor`（只讀，不改東西），存在 `assets/doctor_docker_20261106.txt` | exit 0、沒有 error；10 個 warning、1 個 note（見下一列） |
| DOCKER.md 第 2 步「warning 都是刻意的」 | 對照上面的輸出 | **DOCKER.md 沒列到三個 warning**：`net.ipv6.conf.all.forwarding is 0`（Docker 的 routed 拓樸只用 IPv4）、`could not check whether suricata.service starts at boot: /usr/bin/systemctl not found`（容器裡沒有 systemd）、`forwarded traffic passes without inspection while suricata starts or restarts (when_unavailable = "accept")`。前兩個是 Docker 環境造成的，Pi 的 bridge 模式不會出現 IPv6 forwarding 這一項。講稿第 11 頁與 demo 第 2 步要準備說法。另外 `default route via WAN` 要先跑 `prep_docker.sh` 才會是 ok（第一次跑時是 not met，跑完 prep 後是 ok） |
| demo 的 log 訊息 | 在 `src/` grep `connection trusted`、`it will not be trusted`、`forwarded traffic is inspected`、`table installed`、`suricata missed packet copies`、`uninspected_ms`、`trust revoked`、`trust expired` 等 | 全部存在 |
| demo 的 pcap 內容 | `tcpdump -nn -r tests/demo/pcaps/*.pcap` | 都是 500 個 packet。somfy：`192.168.1.158:10366 ↔ 18.195.134.106:443` 兩方向 212／244 個。muhstik：IRC C&C `51.38.81.99:2407`、`111.230.241.23:2407` 兩條，NTP 4 條（4 個 server；第 4 條 `78.108.102.237` 每個方向只有 10 個 packet，wnc-gw 從第一次看到才開始算，到不了 10，所以只有 3 條會被 trust，`src/agent/trust.rs`）；另外有 62 條連到 `200.168.87.203:59353` 只有 SYN、沒有回應的 connection（共 246 個 SYN，單向，不會被 trust），DOCKER.md 沒提。mirai：`185.244.25.235:80` 兩條下載、`192.168.1.1:40831 → 192.168.1.195:22` 一條 SSH；超過 1,515 bytes 的 packet 3 個（對應 tcpreplay 的 `Failed packets: 3`） |
| ET Open 規則數 | `grep -c '^alert' docker/suricata-rules/et_all.rules` | 52,798 條 `alert`、0 條 `drop`（DOCKER.md「ips 也不擋」的依據） |
| scenario 的 malware 名稱 | 前幾次逐字稿與 `tests/*/README.md` | 3-1 Muhstik、34-1 Mirai、39-1 IRCBot、1-1 Hide and Seek、44-1 Mirai、17-1 Kenjiro、Honeypot-5-1 Amazon Echo、Honeypot-7-1 Somfy door lock |
| 「分三階段做」 | gateway-architecture SKILL.md | 標的是**[建議]**，不是已決定；README 用「階段 1」。投影片寫「規劃」，講稿說順序可能調整。「階段 1 做完先接最小的 cloud 迴路、排在階段 2 前面」是 10/25 已決定（O13） |
| edge AI | SKILL.md、DECISIONS.md §20 | 11/02 和老師討論後決定：地端有 rule 和 edge AI，再加 cloud；edge AI 跑在同一台機器。介面、CPU 分配是 [建議]（O19），輸入、任務、模型都還沒定 |

**草稿可以補強的地方（已放進下面的規格）**
- demo 在 Docker 上跑，`mode` 是 `routed`；Pi 和預設是 `bridge`。要說清楚 Docker 和 Pi 哪些等價、哪些不等價（CLAUDE.md 第 4 條），demo 環境頁專門處理。
- demo 看到的速度（iperf3 Gbit/s）、Suricata 啟動時間是筆電的；效能一律引用 Pi 的數字（trust 每個 packet 省多少、auto trust 每秒省多少 CPU）。
- demo 會看到 ct mark `0xc0000000`、`ids` chain 和 `accept` 兩個 counter、`uninspected_ms`、missed copies 的 WARN、`Failed packets: 3`；這些在 demo 前的頁面都要先定義（先定義再看結果）。
- `ips` 不現場示範（DOCKER.md 寫「口頭說明」），做成一頁簡短的投影片，demo 結束後講。

## 2. 共通規則（照前幾次的回饋）

- 只放重點；說明句寫在講稿，不印在投影片上。圖裡只放節點名稱、箭頭上的短標籤、圖例。
- 技術名詞一律英文，全份統一（投影片、講稿都一樣）：

  | 用這個 | 不要寫成 |
  |---|---|
  | packet | 封包 |
  | connection（conntrack 的一條連線；trust 的單位） | 連線、flow（`flow_id` 這種欄位名稱除外） |
  | trust、trusted（狀態）、auto trust、revoke | 信任、自動信任、撤銷 |
  | TTL | 有效期 |
  | alert、rule | 告警、規則 |
  | copy（`ids` 送給 Suricata 的 packet copy） | 複本 |
  | inspection（Suricata 的檢查）；「進 Suricata」 | 檢查（「檢查」只留給 doctor 的 check） |
  | check（doctor 的檢查項目） | — |
  | verdict | 判決 |
  | forward chain、`ids` chain、table | 鏈、表 |
  | ct mark、conntrack、NFLOG、NFQUEUE、`br_netfilter` | — |
  | edge AI、cloud | 邊緣 AI、雲端 |
  | scenario | 場景 |
- setting 的值、子命令、檔名用 code 格式：`mode`、`bridge`、`routed`、`protection`、`ids`、`ips`、`doctor`、`run`、`trust list`。
- scenario 一律帶 malware／設備名稱，例如 3-1 (Muhstik)、Honeypot-7-1 (Somfy door lock)。
- 數字直接標單位和條件（µs／packet、ms／s、kpps），不要只給比率。
- 配色沿用 `template.typ` 的語意色：tc eBPF／XDP = `c-stage1`、netfilter = `c-stage2`、Suricata 等 user space = `c-stage3`、cloud = `c-cloud`、LAN = `c-lan`、WAN = `c-wan`。**實作狀態用框線表示**：實線＝已實作、虛線＝還沒實作（不要用綠色表示已實作，綠色已經是 tc eBPF 的顏色）。
- 標題、表頭用中文沒關係，但名詞照上表。

## 3. 頁序

| 頁 | 章節 | 標題 |
|---|---|---|
| — | 封面 | Security Gateway 專案介紹 & Demo |
| 1 | — | 大綱 |
| — | 章節 | 架構 |
| 2 | 架構 | 整體架構 |
| 3 | 架構 | wnc-gw 做什麼 |
| 4 | 架構 | packet 怎麼走 |
| — | 章節 | Trust |
| 5 | Trust | trust 以 connection 為單位 |
| 6 | Trust | auto trust |
| 7 | Trust | Suricata 沒在 inspection 時 |
| — | 章節 | 設定與 doctor |
| 8 | 設定與 doctor | `setting.toml` |
| 9 | 設定與 doctor | `mode`：`bridge`／`routed` |
| 10 | 設定與 doctor | `protection`：`ids`／`ips` |
| 11 | 設定與 doctor | `doctor` |
| — | 章節 | Demo |
| 12 | Demo | Demo 環境 |
| 13 | Demo | 重播的 scenario |
| 14 | Demo | Demo 流程 |
| 15 | Demo | `ips`（不現場示範） |
| — | 章節 | 下一步 |
| 16 | 下一步 | 待決事項 |
| 17 | 下一步 | 下一步 |
| 18 | — | References |
| — | — | Q&A（`focus-slide`） |

---

## 4. 每頁規格

### 封面

- `title: "Security Gateway 專案介紹 & Demo"`、`date: "2026-11-09"`。

**當場講**
各位好，今天報告的是 security gateway 目前的實作，程式叫 wnc-gw。前半段介紹架構、trust 的做法、可以設定什麼、doctor 會檢查什麼；後半段直接 demo：重播 dataset 裡真實的惡意流量，看哪些 connection 被 trust、哪些因為 Suricata 的 alert 不被 trust。

**補充**
- 之前的報告：09/21 開發規劃（XDP → netfilter → NFQUEUE 的管線）、10/05 RFC 9411 與 dataset、10/19 本地 IDS 效能（決定以 Suricata 為 base）、11/02 偵測測試。這次是把這些決定做成能跑的 gateway。

### 第 1 頁　大綱

- 五項：架構、Trust、設定與 doctor、Demo、下一步。版面照 11/02 的大綱頁。

**當場講**
分五個部分：架構、trust、設定與 doctor、demo，最後是下一步。

### 第 2 頁　整體架構

**投影片**
- 一張 fletcher 圖，左到右：
  - `LAN`（`c-lan`）→ gateway 方框（`groupnode`）→ `WAN`（`c-wan`）。
  - gateway 方框裡上排三個節點，左到右：`tc eBPF`（`c-stage1`，**虛線**）→ `netfilter` 下一行小字 `table inet wnc_gw`（`c-stage2`，實線）→ `Suricata 8`（`c-stage3`，實線）。netfilter → Suricata 的箭頭標 `copy／queue`。
  - gateway 方框裡下排：`wnc-gw`（`c-stage3`，實線）、`edge AI`（`c-stage3`，**虛線**）。
  - gateway 方框外右上：`cloud`（`c-cloud`，**虛線**）。
  - 箭頭：Suricata → wnc-gw 標 `alert`；wnc-gw → netfilter 標 `ct mark`；wnc-gw ↔ edge AI（虛線）；wnc-gw ↔ cloud（虛線）標 `trust／block／observe`。
- 圖下方一行圖例（小字、`c-muted`）：`實線：已實作　虛線：規劃中`。
- 圖下方一句重點（`punch`）：`判斷完的 connection 設成 trusted，之後不進 Suricata`。

**當場講**
wnc-gw 用 Rust 寫，架在內網 LAN 和外網 WAN 之間，轉送的流量都會經過它。偵測分三層：本地的 Suricata rule、同一台機器上的 edge AI，再加上 cloud；edge AI 和 cloud 是和其他教授合作的部分，還沒接上。
實線是已經做好的：nftables 把轉送的 packet 交給 Suricata，wnc-gw 讀 Suricata 的 alert，判斷哪些 connection 可以 trust，然後在 connection 上設 ct mark。trusted 的 connection 之後不再進 Suricata，省下來的 CPU 就是之後 edge AI 可以用的預算。
虛線是規劃中的：tc eBPF 算特徵和 fast path、edge AI、cloud。

**補充**
- 規劃的順序（`.claude/skills/gateway-architecture/SKILL.md` §7）：階段 1 nftables + Suricata + ct mark（**已完成**，包含 auto trust）→ 最小的 cloud 迴路（10/25 決定排在階段 2 前面，O13）→ 階段 2 tc eBPF 算特徵 → 階段 3 tc eBPF 轉送 trusted connection（fast path）。「分三階段」是建議的切法，不是定案，順序可能調整。
- cloud 不看 payload，只能回三種動作：trust、block、observe（O12，10/25 決定）；edge AI 一樣只能回這三種，這是**建議**（O19），edge AI 的輸入、任務、模型都還沒定。
- 保護範圍是公司 LAN 到 Internet 的邊界，不只 IoT。不做 NAT。
- 平台：Raspberry Pi 4（之後換正式設備）、Raspberry Pi OS（Debian trixie）、Suricata 8.0.7（trixie-backports）。
- 被問「為什麼省 CPU 那麼重要」：Pi 上全部進 Suricata 時每個 packet 71–106 µs，trusted 只要 33–40 µs（第 5 頁）。

### 第 3 頁　wnc-gw 做什麼

**投影片**
- 左半：子命令表（2 欄：子命令、做什麼）：

  | 子命令 | 做什麼 |
  |---|---|
  | `doctor` | 檢查設定與環境，不改任何東西 |
  | `run` | gateway 本體，Ctrl-C／SIGTERM 停止 |
  | `trust add／del／list` | 手動 trust、取消、列出 |
  | `show interfaces` | 列出網卡 |

- 右半：`run` 的圖（fletcher，小）：
  - 中間 `wnc-gw run`（`c-stage3`）。
  - 上：`Suricata 8`（`c-stage3`）。wnc-gw → Suricata 標 `spawn`；Suricata → wnc-gw 兩條：`READY=1`、`alert（eve.json）`。
  - 下：`kernel`（`c-stage2`），裡面兩個小節點 `nft table`、`conntrack`。wnc-gw → nft table 標 `nft JSON`；wnc-gw ↔ conntrack 標 `ctnetlink`。

**當場講**
wnc-gw 有四個子命令。`doctor` 只檢查、不改東西；`trust` 可以手動 trust 一條 connection；`show interfaces` 列出網卡，方便在設定檔裡指定 port。
gateway 本體是 `run`：它先跑一次 doctor，有 error 就不啟動；接著裝我們自己的 nft table、啟動 Suricata，等 Suricata 送出 `READY=1` 才把流量交給它；之後讀 Suricata 寫在 eve.json 的 alert，用 ctnetlink 讀 conntrack 的計數、寫 ct mark。停止時把 table 移除，流量就直接通過。

**補充**
- nftables 用 nft JSON，spawn `/usr/sbin/nft`，不連結 GPL 的 libnftnl（專案可能閉源）；每次約 7.7 ms（Pi），所以要批次（O4）。
- ct mark 用手寫的 ctnetlink：Pi 上設一筆 13 µs，用 crate 是 20–51 µs（O17）。
- 停止時的順序：換回「沒有 inspection」的規則 → 停 Suricata → 移除 table。SIGHUP（例如 SSH 斷線）也一樣正常停止。同一台機器只能跑一個 `run`（flock）。
- log 只印到 stderr（tracing），`--log-format json` 給程式讀；每一筆 alert 是 DEBUG，有 alert 時每 60 秒一行 INFO 摘要。
- `run` 還會每 10 秒讀 conntrack 表的筆數（到 90% 記 WARN），`ids` 時讀 Suricata 漏掉多少 copy。

### 第 4 頁　packet 怎麼走

**投影片**
- 一張 fletcher 圖，左半是 forward chain、右半是 `ids` chain（兩個 `groupnode`，標題 `forward chain`、`ids chain`）。
- forward chain，由上而下四個規則節點（`c-stage2`），左邊帶 ①–④：
  1. `① 純 SYN、已 trusted → 清掉 trust`
  2. `② 第一次經過 → 設 forwarded 位元`
  3. `③ SYN／FIN／RST？` → 是：往右到 `ids` chain
  4. `④ trusted？` → 是：往下到 `accept`（實線框，`c-good` 字色可，不進 Suricata）；否：往右到 `ids` chain
- `ids` chain：`Suricata 就緒？` → 否：`when_unavailable`（`accept`／`drop`）；是：分兩個節點 `ids：NFLOG copy，packet 立刻轉送`、`ips：NFQUEUE，等 verdict`（`c-stage3`）。
- 圖之外不放文字。

**當場講**
不管 `bridge` 還是 `routed`，轉送的 packet 都會經過 netfilter 的 forward hook，進到我們自己的 table。forward chain 有四條規則，順序是刻意的：
第一條，純 SYN 碰到已經 trusted 的 connection，先把 trust 清掉，因為 port 重用時 conntrack 會把舊 connection 的 mark 沿用給新的 connection；第二條，connection 第一次經過 gateway 時設一個 forwarded 位元，auto trust 只看有這個位元的 connection；第三條，SYN、FIN、RST 一律進 Suricata，所以就算 trusted，Suricata 還是看得到 connection 的開始和結束；第四條，trusted 的直接放行。其他的都進 `ids` chain。
`ids` chain 先看 Suricata 就緒了沒，還沒就緒就照 `when_unavailable` 放行或丟掉。就緒之後，`ids` 模式用 NFLOG 送一份 copy 給 Suricata、packet 立刻轉送；`ips` 模式用 NFQUEUE，packet 要等 Suricata 的 verdict。
等一下 demo 會看兩個 counter：`ids` chain 的是送進 Suricata 的 packet，第四條 `accept` 的是 trusted、跳過 Suricata 的 packet。

**補充**
- 實際裝進 kernel 的 table（`nft list table inet wnc_gw`，README §1）：

  ```
  chain forward {
      type filter hook forward priority filter; policy accept;
      tcp flags & (syn | ack) == syn ct mark & 0x80000000 == 0x80000000 counter ct mark set ct mark & 0x7fffffff   # ①
      ct mark & 0x40000000 == 0x00000000 ct mark set ct mark | 0x40000000                                           # ②
      tcp flags fin,syn,rst jump ids                                                                                # ③
      ct mark & 0x80000000 == 0x80000000 counter accept                                                             # ④
      jump ids
  }
  ```
- table 的骨架寫死在程式裡，使用者只能改參數（O11）；Suricata 就緒或停止時只換 `ids` chain 的規則，不重裝整張 table。
- SYN／FIN／RST 一律進 Suricata 的成本：長 connection 每個 packet 約 +1 µs（控制 packet 只佔 0.01–0.04%）。
- 純 SYN 清 trust：conntrack 在舊 connection 沒有 FIN／RST 就消失時（例如設備重開機），會把同一組 5-tuple 的新 SYN 接回舊 entry，id 不變、mark 沿用；Docker 和 Pi 都重現過。偽造純 SYN 只能讓 trusted connection 回到 Suricata，不能讓沒 trusted 的被放行。
- 多個 queue／group 時用 symhash 分到不同的 Suricata worker（含 port、兩個方向同一個值）。

### 第 5 頁　trust 以 connection 為單位

**投影片**
- 上：ct mark 位元表（3 欄）：

  | ct mark 位元 | 意思 | 誰設 |
  |---|---|---|
  | `0x80000000` | trusted | wnc-gw（`trust add` 或 auto trust） |
  | `0x40000000` | forwarded（經過 gateway） | forward chain ② |

  表下一行：`trust list` 看到 `0xc0000000` = 兩個位元都有。
- 下：Pi 的量測表（整台機器 µs／packet）：

  | scenario | 全部進 Suricata | 全部 trusted | 只轉送 |
  |---|---|---|---|
  | 39-1 (IRCBot) | 106.2 | 38.0 | 37.3 |
  | 1-1 (Hide and Seek) | 79.6 | 37.6 | 36.7 |
  | 44-1 (Mirai) | 94.5 | 32.8 | 37.6 |
  | Honeypot-5-1 (Amazon Echo) | 71.1 | 33.1 | 37.5 |
  | Honeypot-7-1 (Somfy door lock) | 106.0 | 40.4 | 39.6 |

- 表的上方或下方一行條件（小字）：`Pi 4（1000 MHz）、10,000 packet／s、ET Open full rules、Suricata 8.0.7`。

**當場講**
trust 的單位是 conntrack 的一條 connection。wnc-gw 在 connection 上設 ct mark 的最高位元 `0x80000000`，forward chain 看到就直接放行。另一個位元 `0x40000000` 是 forward chain 在 connection 第一次經過 gateway 時設的；auto trust 只看有這個位元的 connection，所以 gateway 自己的 connection，例如 SSH，不會被算進來。等一下 demo 用 `trust list` 會看到 `0xc0000000`，就是兩個位元都有。
為什麼不用 nft set 存 5-tuple：5-tuple 會被 port 重用或偽造的 packet 繞過；conntrack 的新 connection 一定沒有 mark。
下面是 Pi 上量的：五個 IoT-23 scenario，每秒 10,000 個 packet。全部進 Suricata 時，整台機器每個 packet 71 到 106 µs；全部 trusted 時是 33 到 40 µs，和只轉送差不多。也就是 trust 每個 packet 省 38 到 68 µs。

**補充**
- 量法（DECISIONS.md §5）：Pi 4 Model B 4 GB 鎖 1000 MHz、governor performance；Pi 內的 veth netns，tcpreplay 綁 CPU 1；整台機器的 CPU 用 `/proc/schedstat`（不是 `/proc/stat`），÷ packet 數；含 tcpreplay，所以只能看差距；2 輪。表中三欄是 Suricata 8.0.7（`tests/ids_inline/results/trust2.kvl`）。
- 「全部 trusted − 只轉送」在 −4.8 到 +3.5 µs，是量測雜訊；也就是 conntrack 加 ct mark 規則本身幾乎不花成本。44-1 trusted 比只轉送還低就是雜訊。
- 實體網卡（方案 B，2026-11-02）：trusted 的 packet 整台約 14 µs、進 Suricata 的約 55 µs。
- 只用最高位元、寫入帶 mask：其他程式（例如 mwan3）用的是低位元。
- 限制：scan 幾乎都是純 SYN，一定進 Suricata，trust 對它沒有幫助。
- conntrack 表被塞滿時，early drop 只清沒有 assured 的 entry，trusted 的 TCP connection 不受影響。

### 第 6 頁　auto trust

**投影片**
- 上：狀態圖（fletcher，左到右）：
  - `觀察`（`c-stage3`）→ `trusted`（`c-stage3`）：箭頭標 `兩個方向各 ≥ min_packets、≥ min_age、沒有 alert`。
  - `trusted` → `觀察`（回頭的箭頭）：標 `ttl 到期`。
  - `alert` 節點（`c-bad`）：從 `觀察` 往下到 `永遠不 trust`；從 `trusted` 往下到 `revoke`。
- 下左：設定表（3 欄）：

  | `[trust]` | 預設 | demo |
  |---|---|---|
  | `auto` | `false` | `true` |
  | `min_packets` | 10 | 10 |
  | `min_age` | 5 s | 5 s |
  | `ttl` | 900 s | 60 s |
  | `check_interval` | 5 s | 2 s |

- 下右：Pi 的成本（小表）：

  | 8 條 TCP connection、4,000 packet／s、`ids` | 不 trust | auto trust |
  |---|---|---|
  | Suricata | 100.5 ms／s | 13.6 ms／s |
  | wnc-gw | 0.5 ms／s | 1.9 ms／s |

  表下一行：`每秒省 85 ms CPU = 每個 packet 21 µs`。

**當場講**
auto trust 是讓 wnc-gw 自己決定要 trust 哪些 connection。wnc-gw 每 `check_interval` 秒讀一次 conntrack 的 packet 計數；在 Suricata 有在 inspection 的期間，一條 connection 兩個方向都至少有 `min_packets` 個 packet、觀察滿 `min_age` 秒、而且沒有任何 alert，就設成 trusted，維持 `ttl` 秒，到期後回到 Suricata、要重新觀察一次。只有 TCP（已建立）和 UDP 會被 trust。
有 alert 的話：還在觀察的 connection 之後永遠不 trust；已經 trusted 的立刻 revoke。
預設是關的，trust 是 gateway 最危險的動作：trusted 之後才送的攻擊，到 TTL 結束前都看不到，所以要使用者明確打開，doctor 也一律給 warning。demo 把 `ttl` 設成 60 秒，是為了看得到到期。
右邊是 Pi 上的成本：8 條 TCP connection、每秒 4,000 個 packet，Suricata 從每秒 100.5 ms 降到 13.6 ms，wnc-gw 自己從 0.5 多到 1.9 ms，合計每秒省 85 ms，等於每個 packet 省 21 µs。

**補充**
- 量法（DECISIONS.md §19，`tests/ids_inline/autotrust_cost_pi.sh saving`）：Pi 4 鎖 1000 MHz，`ids`、預設的 trust 數值；CPU 是 Suricata、wnc-gw 所有執行緒的 schedstat。13.6 ms／s 是 Suricata 閒置時本來就有的成本。
- 每次讀 conntrack 的成本：固定約 7 ms（kernel 要掃整個 hash table 的 65,536 個 bucket），加上每條經過 gateway 的 connection 約 9.4 µs。預設每 5 秒一次：connection 很少時 1.4 ms／s，1 萬條約 20 ms／s（一顆核心的 2%）。
- 讀 alert：每 `eve_interval`（預設 0.5 秒）讀一次 eve.json 新增的部分（poll）。Pi：沒有 alert 時 0.37 ms／s，每筆 alert 16 µs；延遲 0 到一個間隔。inotify 量過，alert 多時貴 3 倍，已經刪掉。
- 觀察用 conntrack 計數、不用 EVE 的 flow 事件：flow 事件要等 connection 結束或逾時才有，長 connection 等不到。`nf_conntrack_acct` 要開（每個 packet 多 0.1–1.3 µs），沒開時 doctor 報 error。
- `ttl` 900 秒比 Suricata 的 `flow-timeouts.tcp.established`（600 秒）長：trust 結束時 Suricata 已經忘了這條 connection，會從中間接手，不會因為序號過時丟 packet（`ips` 下 `ttl` 不夠長時 doctor 會警告）。
- `min_packets` 10、`min_age` 5 秒是**建議值**，沒有實驗依據，待確認（第 16 頁）。
- Suricata 停止時，觀察到一半的 connection 全部重來；已經 trusted 的照常到期。alert 比第一次觀察早到也算（記 10 分鐘）。
- 驗證：Docker 和 Pi 都跑過 `protection_docker.sh autotrust`／`protection_pi.sh autotrust`（`ids`、`ips`、`routed` 都測過）。

### 第 7 頁　Suricata 沒在 inspection 時

**投影片**
- 上一行：`收到 READY=1 才把 packet 交給 Suricata`。
- 中：`when_unavailable` 表（3 欄）：

  | 情況 | `accept`（預設） | `drop` |
  |---|---|---|
  | Suricata 啟動中、重啟中 | 放行 | 丟掉 |
  | `ips`：Suricata 跟不上 | 放行 | 丟掉 |
  | `ids`：Suricata 跟不上 | packet 照樣轉送，copy 被丟掉 | 同左 |

- 下：兩個重點（條列）：
  - 一定記 log：何時沒有 inspection、持續多久（`uninspected_ms`）、漏掉多少 copy
  - Suricata 結束 → 1 秒後重啟，失敗就加倍，最長 60 秒

**當場講**
wnc-gw 自己啟動 Suricata，等它送出 `READY=1` 才把 `ids` chain 換成送 packet 的規則。原因是 Suricata 7.0.10 和 8.0.7 都有一個問題：初始化時收到 packet 會 segfault；Docker 上 8.0.7 先有 packet 進 queue 時，50 次有 42 次當掉，等 `READY=1` 再送就 30 次全部正常。
Suricata 還沒就緒、重啟中、跟不上的時候，照 `when_unavailable` 處理：預設 `accept` 放行，不讓 Suricata 的問題把整個公司網路斷掉；設成 `drop` 就丟掉。`ids` 模式比較特別，packet 本來就不等 Suricata，所以跟不上時 packet 照樣轉送，只是 copy 被丟掉。
不管哪一種，一定記 log：什麼時候開始沒有 inspection、沒有 inspection 了多久，`ids` 漏掉多少 copy 每 10 秒記一次。Suricata 掛掉時 1 秒後重啟，連續失敗就加倍，最長 60 秒。

**補充**
- segfault 的原因用 gdb 確認過：NFQ 執行緒等 kernel 回覆時，就把 queue 裡的 packet 交給還沒初始化完的統計計數器。Pi 上經過 wnc-gw（等 READY=1）在 `ping -f` 下啟動 20／20 正常（DECISIONS.md §10）。
- `ips` 跟不上時放行靠 queue 的 `bypass` 加 `nfq.fail-open=yes`。Suricata 當掉那一刻還在 queue 裡等 verdict 的 packet 會被 kernel 丟掉，`bypass` 只管之後的 packet。
- exception policy（Suricata 檢查不了某條 flow，例如記憶體用完）跟著 `when_unavailable`：`accept` → ignore，`drop` → drop-flow。Debian 預設的 `auto` 在 `ips` 等於 drop-flow，會丟正常流量。
- wnc-gw 強制 `stream.midstream=true`：Suricata 重啟後、trust 到期回到 Suricata 的 connection 都是「從中間開始」，Debian 預設會整條丟掉（Pi 上 39-1 (IRCBot) 丟 26%）。
- 漏掉的 copy：Suricata 自己的統計不算 NFLOG socket 丟掉的 copy，wnc-gw 讀 kernel 的 Drops；驗證時兩者完全相同（Docker 53,425、Pi 28,016）。
- wnc-gw 停止、table 移除後流量直接通過（開發者：「沒 run 當然就是通過」）。

### 第 8 頁　`setting.toml`

**投影片**
- 兩欄的表（左右各一張），每張 3 欄：設定、預設、其他選項。字小一點，但一頁放完。
- 左：

  | 設定 | 預設 | 其他選項 |
  |---|---|---|
  | `mode` | `bridge` | `routed` |
  | `protection` | `ids` | `ips` |
  | `xdp` | `auto` | `off`、`generic` |
  | `[ports] lan`、`wan` | （必填） | 網卡名稱或 MAC |
  | `[nftables] path` | `/usr/sbin/nft` | |
  | `[trust] auto` | `false` | `true` |
  | `[trust] min_packets` | 10 | 1–1,000,000 |
  | `[trust] min_age` | 5 s | 1–3,600 |
  | `[trust] ttl` | 900 s | 10–86,400 |
  | `[trust] check_interval` | 5 s | 1–60 |

- 右（`[suricata]`）：

  | `[suricata]` | 預設 | 其他選項 |
  |---|---|---|
  | `path` | `/usr/bin/suricata` | |
  | `config` | `/etc/suricata/suricata.yaml` | |
  | `queue`（`ips`） | `0` | 範圍，例如 `"0-2"` |
  | `group`（`ids`） | `10` | 範圍，例如 `"10-12"` |
  | `ready_timeout` | 300 s | |
  | `stop_timeout` | 90 s | |
  | `when_unavailable` | `accept` | `drop` |
  | `eve_interval` | 0.5 s | 0.05–10 |

- 表下一行（小字）：`設定檔預設 /etc/wnc-gw/setting.toml；--lan／--wan 可以蓋過`。

**當場講**
設定檔是 TOML。會改變 packet 怎麼走的有 `mode`、`protection`、`when_unavailable` 和 `[trust]`，接下來兩頁講 `mode` 和 `protection`。
`[ports]` 是唯一一定要填的：gateway 不猜哪張網卡是 LAN、哪張是 WAN，用網卡名稱或 MAC 指定，等一下 demo 用的是 MAC。
`xdp` 是之後 eBPF 程式掛在哪的原則：網卡有 native XDP 才掛 XDP，否則掛 TC；Pi 4 兩個 port 都沒有 native XDP，所以是 TC。eBPF 程式還沒寫，現在只有 doctor 會判斷。
`queue`、`group` 設成範圍就會開多個 Suricata worker，用 symhash 分流，同一條 connection 一定在同一個 worker。其他是路徑和逾時。

**補充**
- 來源：`security_gateway/setting.example.toml`（每個欄位的英文說明）、`src/config.rs`。
- MAC 先比對網卡的 permanent MAC，找不到才用目前的 MAC；對到多張網卡時要改用名稱。
- `ready_timeout` 300 秒：rule 多時慢的硬體要載入很久，逾時就停掉重啟。`stop_timeout` 90 秒：Suricata 結束前要把每條開著的 flow 寫進 eve.json，Pi 上 full rules 處理過 18 萬條 flow 要 11–13 秒，原本的 10 秒會被 SIGKILL。
- `group` 不能是 0。`queue`／`group` 被別的程式佔用時 Suricata 啟動失敗，wnc-gw 記 log、退避重啟。
- 預設開幾個 queue／group 還沒決定（第 16 頁）：queue／group 越多每個 packet 越貴（Pi，`ids`、RPS、50 kpps：worker 從 1 個 group 的 15.6 µs 到 4 個的 29.2 µs）。
- `xdp = "generic"` 只給測試用：比 TC 慢，而且整張網卡跳過 GRO。
- 被問「為什麼 table 不讓使用者寫」：程式依賴 table 的結構（mark 的值、chain 名稱），開放 `nft -f` 可能把 trust 的模型改壞（O11）。之後的黑名單放在 nft set，使用者只能管 set 的內容（還沒做）。

### 第 9 頁　`mode`：`bridge`／`routed`

**投影片**
- 一張表（3 欄）：

  | | `bridge`（預設） | `routed` |
  |---|---|---|
  | 部署 | 插在中間，LAN、WAN 同一個網段 | LAN、WAN 不同網段；不做 NAT，上游 router 要加 route |
  | 怎麼進 nftables | 經過 `br_netfilter` | 一般的 IP forwarding |
  | doctor 的 check | 同一個 bridge、`br_netfilter`、`bridge-nf-call-iptables` | 不在 bridge、`ip_forward`、IPv4 位址、網段重疊、default route |
  | 只轉送（Pi、實體網卡、100 kpps） | 9.97 µs／packet | 8.02 µs／packet |
  | ARP 等非 IP 的 packet | 照常轉送 | 不轉送 |

- 表下一行：`nft table 兩種模式完全相同`。

**當場講**
`mode` 是 L2 還是 L3。預設 `bridge`，理由是部署：插進既有的公司網路中間，內網的設定不用改。`routed` 的 LAN 和 WAN 是不同網段，我們不做 NAT，所以上游 router 要加一條到內網的 route。
兩種模式的 nft table 完全一樣，差別只在 doctor 檢查的環境：`bridge` 要確認 LAN、WAN 在同一個 bridge，而且 `br_netfilter` 有載入，沒載入的話 packet 會完全繞過我們的規則；`routed` 要確認 IP forwarding、位址、網段沒有重疊、default route 走 WAN。
效能上，Pi 的實體網卡只轉送時，`routed` 每個 packet 少約 2 µs；有 Suricata 時兩者只差 2 到 9%。等一下的 demo 在 Docker 上用的是 `routed`。

**補充**
- 量法（DECISIONS.md §1、`tests/cpu_alloc/README.md` 實驗 4，2026-11-04）：方案 B（筆電的 tcpreplay 從兩張實體網卡送進 Pi），2 輪。只轉送、中斷都在 CPU0 時（A0）@100 kpps：`bridge` 9.97 µs、容量 100 kpps；`routed` 8.02 µs（−20%）、容量 150 kpps。開 RPS 時兩者容量都是 300 kpps。有 inspection 時（`ips` 2 queue、`ids` 3 group）只差 2–9%，容量一樣。容量的定義：處理不過來而丟的 packet ≤ 0.1% 的最高速率。
- `bridge` 時 forward chain 看到的 `iifname` 都是 `br0`，之後要靠 netdev ingress 打 mark 判斷方向（已決定、還沒實作）。
- Pi 的 kernel 沒有 `nf_conntrack_bridge`，所以只能走 `br_netfilter`。
- `routed` 的位址和路由由 OS 設定，wnc-gw 只檢查：沒有位址是 warning（DHCP 可能還沒拿到）、網段重疊是 error、default route 不走 WAN 是 warning；note 會寫出內網 gateway 和上游要加的 route。
- `routed`、沒開 RPS 時，同一條新 TCP connection 兩個一模一樣的 packet 同一批收進來，第二個會在 conntrack confirm 時被丟（`insert_failed`），丟的是重複的副本。
- 預設要不要改成 `routed` 還沒決定（第 16 頁）。

### 第 10 頁　`protection`：`ids`／`ips`

**投影片**
- 一張表（3 欄）：

  | | `ids`（預設） | `ips` |
  |---|---|---|
  | packet 等不等 Suricata | 不等：NFLOG 送 copy，立刻轉送 | 等：NFQUEUE 等 verdict |
  | 能不能擋 | 不能，只有 alert | rule 的 action 是 `drop` 就擋 |
  | checksum 檢查 | 關掉 | 照常 |
  | Suricata 每個 packet（Pi、veth） | 19–24 µs | 35–48 µs |
  | 容量（Pi、實體網卡、full rules、17-1 (Kenjiro)） | 80 kpps | 60 kpps |

**當場講**
`protection` 決定 packet 要不要等 Suricata。預設 `ids`：kernel 立刻轉送，另外用 NFLOG 送一份 copy 給 Suricata，所以 Suricata 再慢都不會拖慢或擋住流量，但也就不能擋，只有 alert。`ips` 用 NFQUEUE，packet 要等 Suricata 的 verdict，rule 的 action 是 `drop` 就擋。
`ids` 的代價還有一個：checksum 檢查一定要關，因為 GRO 合併過的 copy checksum 不完整，開著的話 74% 會被當成 checksum 錯誤；關掉的風險是攻擊者可以送接收端會丟掉的 packet 來混淆 Suricata，doctor 會警告。
效能上，Pi 上 Suricata 每個 packet `ids` 是 19 到 24 µs，`ips` 是 35 到 48 µs，`ids` 約省一半。實體網卡上重播 17-1 (Kenjiro) 的 scan，`ids` 可以 inspection 到每秒 8 萬個 packet，`ips` 最好是 6 萬；但 `ids` 要開 RPS，不開的話轉送只有 3 到 4 萬。

**補充**
- Suricata 每個 packet 的量法（DECISIONS.md §2，`tests/ids_inline/results/nflog2.kvl`）：Pi、veth、10,000 pps、1 個 queue／group、2 輪、Suricata 8.0.7、workers；三個 scenario 60-1 (Gafgyt)、1-1 (Hide and Seek)、17-1 (Kenjiro)，empty 和 full rules。整台機器 `ids` 省 4–25 µs／packet。`ips` 貴在 verdict 之後 kernel 的轉送是在 Suricata 的 syscall 裡做。
- 容量（`tests/cpu_alloc/README.md`，方案 B、PAUSE 關、full rules，2026-11-03）：`ids` 要開 RPS（CPU1–3）＋3 個 group，17-1 (Kenjiro) 轉送 120、inspection 80 kpps；**`ids` 不開 RPS 時轉送只有 30–40 kpps**（轉送和 copy 都在收 packet 那顆 CPU 的 softirq 裡做）。`ips` 用「網卡中斷搬到 CPU1＋3 個 queue」兩個 pcap 都到 60；`ips` 只開 1 個 queue 只有 20–30 kpps。容量的定義同第 9 頁。`ids` 有兩個容量：轉送容量（丟 ≤ 0.1%）和 inspection 容量（Suricata 漏掉的 copy ≤ 0.1%），投影片的 80 是 inspection 容量。
- 投影片只放 17-1 (Kenjiro)：另一個 pcap 1-1 (Hide and Seek) 有 18.4% 的 packet 從 Pi 的 USB 網卡（eth1）進來，eth1 的中斷在 CPU0、沒設 RPS，`ids` 的轉送只到 50 kpps（inspection ≥ 70），比 `ips` 的 60 低；eth1 也設 RPS 會不會改善**沒有量**。被問到「`ids` 是不是一定比 `ips` 快」時要講這個例外。
- checksum 的實驗：方案 B 用 iperf3 的大量 TCP 送進 Pi，GRO 平均把 6.7 個 packet 合併成一份 copy，開著檢查時 74% 被判成 checksum 錯誤、payload rule 比對不到。
- `ids` 跟不上時 packet 照樣轉送、copy 被丟掉，`when_unavailable` 管不到（第 7 頁）。
- Suricata 一律用 workers runmode（wnc-gw 強制）：autofp 在 Pi 上整台每個 packet 多 15–35 µs（O18）。
- 被問「和直接跑 Suricata 比，wnc-gw 多花多少」：8.0.7 下每個 packet 的成本比值 0.81–1.21（60-1 wnc-gw 便宜 18%、Honeypot-7-1 full 貴 21%），**原因沒查**，每格只量 1 次（`tests/ids_inline/results/compare2.kvl`，DECISIONS.md §20「還沒解釋的量測」）。不要說成結論。
- 預設 `ids` 是開發者的要求：前期只標記、不擋。

### 第 11 頁　`doctor`

**投影片**
- 左：check 項目（條列，小字，兩欄也可以）：
  - 設定檔
  - port 對到哪張網卡、link 狀態
  - `mode` 的環境（`bridge`／`routed`）
  - eBPF 掛點（XDP 或 TC）
  - kernel 模組
  - `nft`
  - Suricata：NFQUEUE／NFLOG、`READY=1`
  - Suricata 的設定、rule 檔、eve-log
  - auto trust：`nf_conntrack_acct`
  - 其他在跑的 Suricata
  - 哪些檔案非 root 可以改
- 右：嚴重程度表（3 欄）：

  | 等級 | 意思 | `run` |
  |---|---|---|
  | error | gateway 無法正確運作 | 不啟動 |
  | warning | 暫時的狀態、已知的風險 | 照常啟動 |
  | note | 資訊 | 照常啟動 |

- 下：`punch`：`doctor 不改任何東西；run 啟動前先跑同一套 check`。

**當場講**
doctor 是部署時第一個要跑的。它檢查設定檔、每個 port 對到哪張網卡、`mode` 需要的環境、kernel 模組、`nft`、Suricata 有沒有編進 NFQUEUE 或 NFLOG 和就緒通知、Suricata 的設定和 rule 檔、eve-log 有沒有寫 alert，auto trust 打開時看 `nf_conntrack_acct`，還有有沒有其他 Suricata 在跑、哪些檔案非 root 可以改。
結果分三級：error 是 gateway 沒辦法正確運作，例如設定錯、port 找不到、缺模組，`run` 就不啟動；warning 是暫時的狀態或已知的風險，例如 link down、`ids` 不擋流量，`run` 照常啟動；note 只是資訊。每一則訊息都寫怎麼修。
doctor 不改任何東西，`run` 啟動前也會先跑同一套 check。

**補充**
- 為什麼 link down 只是 warning：gateway 串在網路中間，開機時線沒插好就拒絕啟動的話，線插上之後網路會不通，或流量完全沒有 inspection（doctor-checks.md §1）。同理，`routed` 沒有位址是 warning。
- doctor 看的是「能力」不是版本號：例如 Suricata 看 `--build-info` 有沒有 NFQueue／NFLOG 支援、`Systemd support`。Suricata 的設定是用 `suricata --dump-config` 加上 wnc-gw 強制的 `--set`，看到的就是實際執行時的設定（約 12 ms、不載入 rule）。rule 檔只檢查有沒有 rule，不檢查語法（要 `-T` 載入全部 rule，太慢）。
- Suricata 最低版本 8.0 的 check 已決定、還沒寫。
- 輸出全部在 stdout（`wnc-gw doctor > report.txt` 可以存下完整報告），finding 集中印在最後。
- demo 的 doctor 輸出（2026-11-06 實際跑的，`assets/doctor_docker_20261106.txt`）：沒有 error，10 個 warning、1 個 note。warning：`net.ipv6.conf.all.forwarding` 是 0（Docker 的拓樸只用 IPv4）、`when_unavailable = "accept"` 放行、`ids` 不擋、`ids` 不檢查 checksum、`ids` 流量太快會漏 copy、Suricata 和 wnc-gw 共用帳號、auto trust 的風險、Docker 裡沒有 `systemctl` 查不到 `suricata.service`、兩個設定檔非 root 可以改（從筆電掛進容器，擁有者是筆電的帳號；Pi 上放在 root 的 `/etc/wnc-gw` 就不會出現）。note：`routed` 要內網用 10.0.1.1 當 gateway、上游加 route。

### 第 12 頁　Demo 環境

**投影片**
- 上：拓樸圖（fletcher，左到右）：
  - `wnc-cli` 下一行 `10.0.1.2`（`c-lan`）— 線標 `lan 10.0.1.0/24` — `wnc-gw` 下一行 `routed、Suricata 8.0.7`（`c-stage2` 或 `c-stage3`）— 線標 `wan 10.0.2.0/24` — `wnc-srv` 下一行 `10.0.2.2`（`c-wan`）。
  - `wnc-rep`（`c-muted`）在 wnc-gw 上方，兩條線分別接到 lan 和 wan 兩側，標 `重播 pcap`。
- 下：對應表（3 欄）：

  | Docker | 實際部署（Pi） | 等不等價 |
  |---|---|---|
  | `wnc-gw` 容器，`routed` | Pi，`bridge`（預設） | nft table、conntrack、Suricata 8.0.7 相同；環境 check 不同 |
  | `wnc-rep` 重播 pcap 到 LAN、WAN 兩邊 | 內網設備、外網 server | 同樣經過 forward chain |
  | 共用筆電的 kernel、CPU | Pi 4 的 kernel、CPU | 速度、Suricata 啟動時間不等價 |

- 最下一行：`同樣的流程 11/04–05 在 Pi 上跑過（bridge、實體網卡）`。

**當場講**
demo 在筆電的 Docker 上做。中間的 `wnc-gw` 容器跑 wnc-gw 和 Suricata，`mode` 是 `routed`；兩邊的 `wnc-cli`、`wnc-srv` 是 iperf3 的兩端，用來量速度；`wnc-rep` 有兩張網卡，把 dataset 的 pcap 重播進 gateway：設備送出的 packet 從 LAN 進，外面送回來的從 WAN 進。
和 Pi 比，等價的是 nft table、conntrack 的行為、Suricata 的版本和 rule，所以 trust、alert 的結果一樣；不等價的是速度和 Suricata 的啟動時間，因為容器共用筆電的 kernel 和 CPU，等一下看到的 Gbit/s 不代表 Pi。Pi 上的數字是前面幾頁的表。同樣的流程 11/04 和 11/05 在 Pi 上用 `bridge` 和實體網卡跑過，結果一樣。

**補充**
- 設定檔 `docker/wnc-gw/demo.toml`：`mode = "routed"`、`xdp = "off"`、`protection = "ids"`、`[ports]` 用 MAC（`02:00:00:00:01:01`、`02:00:00:00:02:01`）、`[suricata] config = "/etc/wnc-gw/demo-suricata.yaml"`、`[trust] auto = true, min_packets = 10, min_age = 5, ttl = 60, check_interval = 2`。
- Suricata 的設定 `demo-suricata.yaml` include 系統的 `suricata.yaml`，只把 rule 換成 `et_all.rules`（ET Open 52,798 條，和 11/02 偵測測試同一份）。
- gw 另外加了兩條 route（`192.168.0.0/16` 往 LAN、其他往 WAN），下一跳是不存在的 MAC：packet 經過 forward（nft、Suricata 在這裡）之後送出去，沒有人收。所以重播的 packet 只走一趟 gateway。
- 容器的 `nf_conntrack_acct` 由 `docker/compose.yml` 設成 1。Docker 裡沒有 XDP 的差異可看（`xdp = "off"`）。
- Pi 上的演練（`tests/demo/README.md`）：11/04 `TARGET=pi`（veth）、11/05 `TARGET=phys`（筆電 USB 網卡 ↔ Pi eth0、筆電 eno2 ↔ Pi eth1 上的 VLAN 20，`bridge`）；trust、alert 不 trust、TTL 到期、kill Suricata 都和 Docker 一樣。實機重播 Muhstik 時 3 筆 alert 和 Docker 一樣。Pi 上 SIGKILL 後 1.3 秒重新就緒（只有 2 條 demo rule 時）；Pi 載入完整 rule 就緒約 41 秒（`startup_ms=41052`）。

### 第 13 頁　重播的 scenario

**投影片**
- 一張表（4 欄）：

  | pcap | IoT-23 scenario | 內容 | 預期 |
  |---|---|---|---|
  | `somfy` | Honeypot-7-1 (Somfy door lock) | 1 條 HTTPS connection | 沒有 alert → trusted |
  | `muhstik` | 3-1 (Muhstik) | 2 條 IRC C&C、3 條 NTP | C&C：alert → 不 trust；NTP：trusted |
  | `mirai` | 34-1 (Mirai) | 2 次 HTTP 下載 ELF、1 條 SSH | 下載：alert → 不 trust；SSH：trusted |

- 表下一行：`每個 scenario 開頭 500 個 packet、每秒 50 個；IP、port 沒改`。

**當場講**
重播的是 IoT-23 三個 scenario 的開頭 500 個 packet，每秒 50 個，大約 10 秒。IP 和 port 都沒改，所以 log 裡的位址就是 dataset 原本的。
第一個是 Honeypot-7-1，Somfy 的門鎖，良性的；一條 HTTPS connection，沒有 alert，應該會被 trust。
第二個是 3-1，Muhstik 殭屍網路：同一台被感染的設備連兩台 IRC C&C，另外有 NTP 校時。C&C 有 alert，不會被 trust；NTP 沒有 alert，會被 trust。
第三個是 34-1，Mirai：設備用 HTTP 下載兩次 ELF 執行檔，另外有一條 SSH。下載有 alert、不 trust；SSH 會被 trust。
這三個 pcap 都先用 Suricata 離線跑過全部 rule，alert 和送進 gateway 的結果一樣。

**補充**
- 預期的 alert（DOCKER.md）：
  - Muhstik 3 筆：`ET MALWARE ELF/Muhstik - IRC CnC Checkin` ×2（兩條 C&C 各一筆）、`ET INFO IRC Channel JOIN on non-standard port`。C&C 是 `51.38.81.99:2407`、`111.230.241.23:2407`；設備是 `192.168.2.5`。
  - Mirai 4 筆：`ET INFO Executable and linking format (ELF) file download Over HTTP`、`ET HUNTING Possible ELF executable sent when remote host claims to send a Text File`，兩條下載各兩筆；下載來源 `185.244.25.235:80`，設備 `192.168.1.195`。SSH 是 `192.168.1.1:40831 → 192.168.1.195:22`。
  - Somfy：`192.168.1.158:10366 → 18.195.134.106:443`，兩個方向 212／244 個 packet。
- muhstik 裡另外有 64 條連到 `200.168.87.203:59353` 只有 SYN、沒有回應的 connection：單向，不會被 trust，也沒有 alert。
- pcap 的處理（`prep_docker.sh`）：修正 checksum（IoT-23 從 router 那側來的 packet IP checksum 是 0，kernel 會丟）、依 router 的 MAC 分成兩邊、目的 MAC 改成 gw 的兩張網卡。
- 「判斷以 connection 為單位，不是以設備為單位」是 Muhstik 這一段要講的重點（demo 第 5 步）。
- 和 11/02 的關係：11/02 的偵測測試說 payload 有特徵的攻擊（C&C checkin、ELF 下載）偵測得到，這次挑的就是這一類，所以才看得到「有 alert 就不 trust」。scan、flood 這類本地 rule 抓不到的，auto trust 也就擋不到，要靠之後的 edge AI 和 cloud。

### 第 14 頁　Demo 流程

**投影片**
- 一張表（3 欄）：

  | # | 做什麼 | 看什麼 |
  |---|---|---|
  | 1 | 設定 `demo.toml` | `mode`、`protection`、`[ports]`、`[trust]` |
  | 2 | `doctor` | 沒有 error |
  | 3 | `run` | Suricata 就緒前沒有 inspection 的時段（`uninspected_ms`） |
  | 4 | 重播 `somfy` | `connection trusted`、`trust list`、counter |
  | 5 | 重播 `muhstik` | C&C `will not be trusted`、NTP trusted |
  | 6 | 重播 `mirai` | 下載 `will not be trusted`、SSH trusted |
  | 7 | iperf3 | trust 前後的速度 |
  | 8 | kill Suricata | 沒有 inspection 的時段、自動重啟 |

**當場講**
demo 有八個步驟：先看設定檔、跑 doctor、啟動 gateway，接著依序重播三個 scenario，看哪些 connection 被 trust、哪些不被 trust，再用 iperf3 看 trust 前後的速度，最後把 Suricata 砍掉，看 gateway 怎麼處理。接下來切到終端機。

**補充**
- 指令全部在 `tests/demo/DOCKER.md`，準備是 `prep_docker.sh`。開三個終端機：T1 wnc-gw 的 log、T2 送流量、T3 看狀態。
- **每次 `run` 之前 `docker exec wnc-gw conntrack -F`**：`min_age` 從 wnc-gw 第一次看到 connection 開始算，上一輪留下的 connection 會讓 trust 看起來太快。同一個 pcap 要重播第二次也要先停掉 wnc-gw 再 `run`（Suricata 記得上一輪的 connection）。

### Demo（切到終端機，不是投影片）

逐字稿要有一節「Demo」，放在第 14 頁和第 15 頁之間，**一、當場講**照下面每一步寫要講的話；**二、補充**寫每一步預期看到的輸出和出狀況時怎麼辦。來源：`tests/demo/DOCKER.md`（流程、演練紀錄）。

1. **設定**（`cat docker/wnc-gw/demo.toml`）
   講：`mode` 是 `routed`、`protection` 是 `ids`、`[ports]` 用 MAC 指定、`[suricata] config` 指到 Suricata 的設定、`[trust]` 的四個值；`ttl` 只設 60 秒是為了看得到到期，預設是 900 秒。
2. **doctor**
   講：上面幾張表是 LAN、WAN 對到哪張網卡、`routed` 的 check、kernel 模組、Suricata 8.0.7 有 NFLOG、rule 檔、eve-log；沒有 error。warning 都是預期的：`ids` 不擋、不檢查 checksum、流量太快會漏 copy、auto trust 的風險、Suricata 由 wnc-gw 啟動；另外兩個是 Docker 環境造成的（IPv6 forwarding、沒有 systemctl），設定檔非 root 可以改是因為從筆電掛進容器。
   補充：預期輸出就是 `assets/doctor_docker_20261106.txt`（10 個 warning、1 個 note）。如果出現 `default route via WAN … not met`，是還沒跑 `prep_docker.sh`。
3. **run**（`--log-level debug`）
   看：`table installed`、`automatic trust is on`、`suricata started`，約 15 秒後（載入 52,798 條 rule）`suricata is ready`、`forwarded traffic is inspected … uninspected_ms=…`。
   講：table 先裝好，Suricata 就緒前的流量照樣轉送但沒有 inspection，這段時間記在 log。
   補充：演練時就緒 15.5–16.0 秒。
4. **Somfy**
   看：約 5–6 秒後 `INFO connection trusted … connection="tcp 192.168.1.158:10366 -> 18.195.134.106:443" packets_original=128 packets_reply=148 ttl_s=60`；`trust list` 是這條 connection，MARK `0xc0000000`；`nft list table inet wnc_gw` 的 `ids` chain 約 292、`ct mark & 0x80000000 … accept` 約 164。
   講：兩個方向都有 10 個 packet、觀察滿 5 秒、沒有 alert，就設 ct mark；之後除了 SYN／FIN／RST 都不進 Suricata。`ids` 的 counter 是送進 Suricata 的，`accept` 的 counter 是跳過的。
   補充：292 + 164 = 456，就是這條 connection 的 TCP packet 總數（212 + 244）。
5. **Muhstik**
   看：約 2 秒內 3 筆 `DEBUG suricata alert`，兩條 C&C 各一行 `it will not be trusted`；第 7–10 秒 3 條 NTP `connection trusted`。
   講：同一台被感染的設備，有 alert 的 C&C connection 永遠不 trust，正常的 NTP 照樣 trust；判斷以 connection 為單位，不是以設備為單位。
6. **Mirai**
   看：每條下載兩筆 alert 加一行 `it will not be trusted`，兩條下載相隔約 5 秒；SSH `connection trusted`。`trust list` 共 5 條：Somfy、3 條 NTP、SSH。
   補充：tcpreplay 會說 `Failed packets: 3`：pcap 裡有 3 個 2,962 bytes 的 packet（錄的時候被 GRO 合併過），超過 MTU 1500 送不出去，不影響 alert（送出 497／500）。
7. **iperf3**（`docker exec wnc-cli iperf3 -c 10.0.2.2 -t 15 -i 1`）
   看：前 7 秒約 30 Gbit/s，trusted 之後約 50 Gbit/s（沒有 wnc-gw 時 48.0–53.8）；T1 每 10 秒 `WARN suricata missed packet copies … missed=…`。
   講：`ids` 下 packet 本來就不等 Suricata，但 kernel 還是要把每個 packet 複製一份給 Suricata，複製本身就有成本；trusted 之後不複製，速度回到沒有 gateway 的水準。流量比 Suricata 收 copy 還快時會漏，wnc-gw 會記下漏了多少。這是筆電的速度，不代表 Pi。
   補充：演練 27.8–31.2 → 49.1–52.5 Gbit/s（第 7 秒 trusted），漏掉的 copy 371,678、533,159（每 10 秒）。為什麼不用重播看速度：tcpreplay 照固定速率送，gateway 快或慢都一樣。
8. **kill Suricata**（`docker exec wnc-gw pkill -9 -x Suricata-Main`）
   看：`WARN suricata exited … exit="SIGKILL"`、`WARN forwarded traffic passes without inspection`、`restarting suricata delay_s=1`，約 7.5 秒後 `forwarded traffic is inspected … uninspected_ms=…`；`trust list` 的 connection 還在。
   講：沒有 inspection 的時段一定記在 log；`when_unavailable = "drop"` 時這段期間改成丟掉。
   補充：演練重新就緒 6.6 秒、`uninspected_ms=7572`；60 秒後 3 條 NTP 的 trust 到期（`trust expired` 是 DEBUG）。
   停止：Ctrl-C，看到 `table removed`。

### 第 15 頁　`ips`（不現場示範）

**投影片**
- 上兩點（條列）：
  - ET Open 52,798 條 rule 全部是 `alert`（0 條 `drop`）→ 現在 `ips` 也不擋
  - 要擋：把 rule 的 action 改成 `drop`；哪些要改還沒決定
- 下：實測表（Docker、2026-11-05，3 條 rule 改成 `drop`；3 欄）：

  | | `ids` | `ips` |
  |---|---|---|
  | server 回 `uid=0(root)` | alert，client 照樣收到 | client 6 秒收到 0 bytes |
  | 重播 3-1 (Muhstik) | alert | 比對到的 `NICK` packet 不轉送，其他照常 |
  | iperf3：trust 前 → 後（筆電） | 約 30 → 50 Gbit/s | 約 1.1 → 50 Gbit/s |

**當場講**
`ips` 已經實作，但今天不現場示範，因為現在沒有任何 `drop` 的 rule：ET Open 的 52,798 條全部是 `alert`，跑 `ips` 看起來會和 `ids` 一樣。哪些 rule 要改成 `drop` 還沒決定。
我們把 3 條 rule 改成 `drop` 測過：server 回 `uid=0(root)` 的 connection，`ids` 只有 alert、client 照樣收到；`ips` 下 client 6 秒收到 0 bytes。重播 Muhstik 時，觸發 rule 的那個 `NICK` packet 沒有轉送出去，同一條 connection 的其他 packet 照常；也就是 `drop` 丟的是比對到的 packet，不是整條 connection。
最後一列是筆電上的 iperf3：`ips` 下每個 packet 都要等 Suricata，trust 之前只有約 1.1 Gbit/s，trust 之後約 50；所以 trust 在 `ips` 下省得更多。

**補充**
- 來源：`tests/demo/DOCKER.md`「ips」一節。
- 真的 TCP connection 收不到東西，是因為重送的內容一樣又被丟。log 是 `action="blocked"`。
- 演練：iperf3 `ips` 1.02–1.15 → 50.6–52.2 Gbit/s（第 7 秒 trusted）；`ids` 27.8–31.2 → 49.1–52.5。
- wnc-gw 自己的擋（nft 黑名單 set）還沒做；之後 cloud 回 block 時是用 nft set 擋，不是 Suricata（O11）：trusted 的 connection 和之後的 fast path 都不經過 Suricata，黑名單放在 Suricata 就擋不到。
- Pi 上 `ips` 的容量見第 10 頁（約 60 kpps）。

### 第 16 頁　待決事項

**投影片**
- 一張表（2 欄：事項、現況）：

  | 事項 | 現況 |
  |---|---|
  | auto trust 的預設值 | 建議值：10 個 packet、5 s、TTL 900 s，沒有實驗依據 |
  | `ids` 下 alert 比 `min_age` 晚到 | 低流量的 connection 先 trusted、結束時才 revoke（`ips` 沒有這問題） |
  | 讀 conntrack 會停住 wnc-gw | 每次 7 ms＋每條 connection 9.4 µs；1 萬條約 0.1 s |
  | 預設開幾個 queue／group | Pi：`ids` 3 group＋RPS、`ips` 3 queue＋中斷搬到 CPU1 最好 |
  | `mode` 的預設 | `routed` 只轉送每個 packet 少約 2 µs，但要改網段 |

**當場講**
目前還沒決定的有五件。第一，auto trust 的數值現在是建議值，沒有實驗依據。第二，`ids` 模式下，低流量 connection 的 payload alert 可能比 `min_age` 晚到，connection 會先被 trust、結束時才因為 alert 被 revoke；`ips` 下同樣的 connection 一開始就不會被 trust。第三，wnc-gw 每次讀 conntrack 固定約 7 ms，加上每條 connection 9.4 µs，讀的期間 wnc-gw 的事件迴圈會停住，1 萬條約 0.1 秒，打算移到另一個執行緒。第四，預設開幾個 queue 或 group。第五，`mode` 的預設要不要改成 `routed`。

**補充**
- ids alert 晚到（DECISIONS.md §19）：Docker、Pi 都重現。**推測**原因是 `ids` 模式的 Suricata 依 TCP 重組處理 copy，raw stream 的比對要累積到 `stream.reassembly.toserver-chunk-size`（Debian 預設 2560 bytes）或 connection 結束才做；測試的 connection 之後每秒只送 50 bytes。可能的做法：`ids` 時要求送往 server 的資料超過 chunk 大小才 trust、調小 chunk（Suricata 多花 CPU）、加大 `min_age`。demo 用的 Muhstik、Mirai 在 2 秒內就有 alert，不受影響。
- 讀 conntrack 停住事件迴圈：6 萬條**推算**約 0.57 秒。另一個做法是改用 conntrack 的 NEW／DESTROY 事件維護觀察表。階段 3 的 eBPF fast path 時會改成讀 BPF map。
- queue／group 的數據：`tests/cpu_alloc/README.md`。有 18% 流量從 USB 網卡進來時 `ids` 只到 50 kpps（推測是 eth1 的中斷在 CPU0、沒開 RPS），沒量。
- 其他待決（DECISIONS.md §20）：log 保存多少（Suricata 的 eve.json 等目前沒有上限）、Suricata 要不要輸出 EVE flow 事件、edge AI 的介面和 CPU 分配、拆成多個 process（privd／agent）。
- 老師 11/04 擔心 `ids` 要複製 2–3 份（Suricata、edge AI、cloud 特徵）的成本：Pi 上 kernel 每多一份 copy，小 packet +3–5 µs、大 packet +7–8 µs，多 2 份轉送容量少約 2 成；只複製前 128 bytes 時大 packet 幾乎不加成本（`tests/cpu_alloc/README.md` 實驗 5）。每個用途要整個 packet 還是只要 header 還沒定。

### 第 17 頁　下一步

**投影片**
- 三點（條列，大字）：
  - 最小的 cloud 迴路：自己做的模擬 cloud，回 trust／block／observe
  - 階段 2：tc eBPF 算特徵
  - 階段 3：tc eBPF fast path，trusted connection 不經過 netfilter
- 下一行（小字）：`edge AI：介面與 CPU 分配和合作方確認`

**當場講**
下一步是先接最小的 cloud 迴路：我們自己做一個模擬的 cloud，wnc-gw 把資料送上去，cloud 回 trust、block 或 observe，wnc-gw 照著改 ct mark 或 nft set。這是 10/25 決定的，排在 eBPF 之前。之後是階段 2，用 tc eBPF 算特徵，給 cloud 和 edge AI 用；階段 3 是 fast path，trusted 的 connection 在 tc 就直接轉送，不經過 netfilter。edge AI 的介面和 CPU 分配要和合作方確認。

**補充**
- O13（10/25）：階段 1 的地端執行點做完後，先接最小的 cloud 迴路；request 照設定組、回應照設定對應（O12），特徵先用 EVE 和 conntrack 計數。
- 階段 2、3 的切法是建議，順序可能調整。fast path 用 tc eBPF、不用 XDP（10/20 決定）：XDP 只有 ingress、有些硬體不支援；tc 比 netfilter 早執行，trusted 的 connection 繞過 netfilter 時 tc 的特徵計算仍看得到。
- edge AI 的 CPU 實驗（O19，DECISIONS.md §20）：純運算的替身綁在 Suricata 以外的核心時 0 干擾；共用核心時即使 `SCHED_IDLE` 也丟 28–47%；吃記憶體的負載綁在別的核心仍讓 Suricata 每個 packet 貴 2 倍。
- 還沒做的小項目：Suricata 最低版本 8.0 的 doctor check、systemd 的 `LogNamespace`、nft 黑名單 set、方向判斷（netdev ingress mark）。

### 第 18 頁　References

- 照 11/02 的 `webref` 寫法（名稱一行、網址一行）：
  - IoT-23 — https://www.stratosphereips.org/datasets-iot23
  - ET Open rules — https://rules.emergingthreats.net/open/
  - Suricata 8.0 User Guide — https://docs.suricata.io/en/suricata-8.0.7/
  - nftables wiki — https://wiki.nftables.org/wiki-nftables/index.php/Main_Page

**當場講**
參考資料在這一頁：IoT-23、ET Open、Suricata 和 nftables 的文件。

### Q&A

- `#focus-slide[Q&A]`。

**當場講**
以上是這次的報告，謝謝，歡迎提問。

---

## 5. 給製作的 subagent

- 原始碼：`src/main.typ`，`#import "../../template.typ": *`，版面和小工具參考 `../20261102_security_gateway_本地_IDS_偵測測試/src/main.typ`。
- 編譯：在報告資料夾跑 `../build.sh -p`，逐頁 PNG 在 `/tmp/<資料夾名>/`，每一頁都要看過：沒有超出頁面、沒有被截斷、表格沒有換行換得很難看、圖的箭頭標籤沒有和節點重疊。
- 輸出：`Security_Gateway_專案介紹_&_Demo.pdf`（build.sh 依 title 產生，資料夾裡只能有這一個 PDF）。
- 講稿：`逐字稿.md`，格式照 `../20261102_security_gateway_本地_IDS_偵測測試/逐字稿.md`：檔頭（日期、對應投影片、頁碼說明）、使用方式、**一、當場講**（封面到 Q&A 連著讀，只放要講的話；第 14 頁和第 15 頁之間有「Demo」一節）、**二、補充**（每頁的怎麼讀、實驗怎麼做、被問到時，頁碼對應，不用 `>`）。內容照本文件每頁的「當場講」「補充」，可以順句子，但數字、名詞、推論與沒量的標記不能改。不要寫改動紀錄。
- 本文件沒寫到的數字不要自己加；需要的話先查 `../../security_gateway/DECISIONS.md`、`README.md`、`../../tests/demo/DOCKER.md`，並在回報裡列出加了什麼、出處在哪。

---

## 6. 第二版（查證與審稿後，2026-11-06）— 以本節為準

### 6.1 改動紀錄（只記在這裡，不寫進講稿）

- 依 `驗證報告.md`（Opus 查證：181 項、27 項有問題）修正事實與條件；依兩份審稿（公司工程主管角度、指導教授角度，都建議刪減：章節頁、`setting.toml` 細表、ct mark 位元表、doctor 清單、①② 規則、iperf3 的 Gbit/s、待決的實作細節）精簡。
- 草稿要求「介紹 doctor、支援哪些 setting」，所以 `setting.toml` 和 doctor 兩頁**不整頁刪**，改成精簡版（審稿都建議刪整頁）。
- 刪掉：5 張章節頁、第 13 頁（重播的 scenario，併進 Demo 流程）、第 15 頁（`ips` 不現場示範，併進 `protection` 頁）、第 17 頁（併進待決）。References 移到 Q&A 之後。
- 第 5 頁的數字換成 wnc-gw 實際的規則（trusted 時 SYN／FIN／RST 照樣進 Suricata，`trust2.kvl` 的 C3），並標出「Suricata 直接跑 NFQUEUE」；原本的「trust 省 38–68 µs」是不含 SYN／FIN／RST 規則的 C2，移到補充並標條件。
- 曾加一行 auto trust 的風險（兩份審稿列為「缺少的」）；2026-11-06 使用者同意拿掉（審稿只判斷聽眾需不需要看）。

### 6.2 頁序

| 頁 | 標題 |
|---|---|
| — | 封面 |
| 1 | 大綱 |
| 2 | 整體架構 |
| 3 | wnc-gw 的子命令 |
| 4 | packet 怎麼走 |
| 5 | trust 以 connection 為單位 |
| 6 | auto trust |
| 7 | Suricata 沒在 inspection 時 |
| 8 | `setting.toml` |
| 9 | `mode`：`bridge`／`routed` |
| 10 | `protection`：`ids`／`ips` |
| 11 | `doctor` |
| 12 | Demo 環境 |
| 13 | Demo 流程 |
| 14 | 待決與下一步 |
| — | Q&A（`focus-slide`） |
| 15 | References |

不要章節頁（不寫 `= 章節`，或寫了也不產生章節頁）。大綱五項：架構、Trust、設定與 doctor、Demo、待決與下一步。

### 6.3 名詞補充（覆蓋 §2）

- nft 的規則也寫 rule（「forward chain 的 rule」），不寫「規則」。
- checksum 的那個寫 **checksum validation**（doctor 訊息是 `validate checksums`），不寫「checksum 檢查」。
- 「Suricata 檢查不了某條 flow」→「Suricata 處理不了某條 connection」；「副本」→「重複的 packet」。
- Suricata 自己的名稱保留 flow：EVE 的 flow 事件、`flow_id`、`flow-timeouts`。其他指連線的地方一律 connection。

### 6.4 每頁（只寫和第一版不同的地方；沒寫的照 §4）

**封面**　當場講：「各位好，今天報告的是 security gateway 目前的實作，程式叫 wnc-gw，最後會現場 demo。」（刪掉預告結構的那句）

**第 1 頁 大綱**　五項見 6.2。當場講：「分五個部分：架構、trust、設定與 doctor、demo，最後是待決事項和下一步。」

**第 2 頁 整體架構**
- 投影片：netfilter 節點拿掉小字 `table inet wnc_gw`；`tc eBPF → netfilter` 的箭頭改**虛線**；`ct mark` 標籤要明確貼在 `wnc-gw → netfilter` 的箭頭上，不能靠近 edge AI 的虛線。
- 補充：「被問為什麼省 CPU 重要」改成「見第 5、6 頁」，刪掉 71–106／33–40 那句。

**第 3 頁 wnc-gw 的子命令**
- 投影片：上方子命令表只留三列：`doctor`（檢查設定與環境，不改任何東西）、`run`（gateway 本體）、`trust add／del／list`（手動 trust、取消、列出）。下方改成 `run` 的流程圖（fletcher，左到右五個小框，`c-stage3`）：`doctor` → `裝 nft table` → `啟動 Suricata` → `READY=1 後送 packet` → `讀 alert、auto trust`；最右或下方另一個框 `停止：移除 table`。拿掉原本右邊的介面圖（spawn、nft JSON、ctnetlink）。
- 當場講：「wnc-gw 主要有三個子命令。`doctor` 只檢查、不改東西；`trust` 可以手動 trust 一條 connection；gateway 本體是 `run`。`run` 先跑一次 doctor，有 error 就不啟動；接著裝我們自己的 nft table、啟動 Suricata，等 Suricata 送出 `READY=1` 才把 packet 交給它；之後讀 Suricata 的 alert、做 auto trust。停止時把 table 移除，流量就直接通過。」
- 補充：原本的補充保留；加「`show interfaces` 列出網卡，方便在設定檔裡指定 port」「wnc-gw 用 nft JSON（spawn `/usr/sbin/nft`）裝 table、用 ctnetlink 讀 conntrack 的計數和寫 ct mark、從 eve.json 讀 alert」。

**第 4 頁 packet 怎麼走**
- 投影片（圖重畫，避免三條「是」從同一點射出交叉）：
  - forward chain：`SYN／FIN／RST？` —是→ `ids` chain；—否→ `trusted？` —是→ `accept`；—否→ `ids` chain。
  - `ids` chain：`Suricata 就緒？` —否→ `when_unavailable`（`accept`／`drop`）；—是→ `protection？` —`ids`→ `NFLOG copy，立刻轉送`；—`ips`→ `NFQUEUE，等 verdict`。
  - 拿掉 ①② 兩個框；不加編號。
- 當場講：「不管 `bridge` 還是 `routed`，轉送的 packet 都會經過 netfilter 的 forward hook，進到我們自己的 table。forward chain 先看 SYN、FIN、RST：這三種一律進 Suricata，所以就算 connection 已經 trusted，Suricata 還是看得到它的開始和結束。其他 packet 如果屬於 trusted 的 connection 就直接放行，不是的才進 `ids` chain。`ids` chain 先看 Suricata 就緒了沒，還沒就緒就照 `when_unavailable` 放行或丟掉；就緒之後，`ids` 模式用 NFLOG 送一份 copy、packet 立刻轉送，`ips` 模式用 NFQUEUE，packet 要等 Suricata 的 verdict。」（刪掉「四條規則」的逐條說明和 counter 那句；counter 移到 Demo 第 4 步）
- 補充：code block 補上開頭單獨的 `counter`（README §1、`src/firewall.rs`）；加一段「圖上只畫了兩個判斷，實際 forward chain 還有兩條 rule：一、純 SYN 碰到已 trusted 的 connection 先清掉 trust（port 重用時 conntrack 會把新 SYN 接回舊 entry、沿用 mark）；二、connection 第一次經過時設 forwarded 位元 `0x40000000`（auto trust 只看有這個位元的，gateway 自己的 SSH 不會被算進來）」。其他原本的補充保留。

**第 5 頁 trust 以 connection 為單位**
- 投影片：
  - 上：兩行重點（不要 ct mark 位元表）：`在 conntrack 的 connection 上設 ct mark`、`不用 5-tuple：會被 port 重用、偽造的 packet 繞過`。
  - 中：表（整台機器 µs／packet）：

    | scenario | 全部進 Suricata | trusted | 只轉送 |
    |---|---|---|---|
    | Honeypot-7-1 (Somfy door lock) | 106.0 | 40.0 | 39.6 |
    | 1-1 (Hide and Seek) | 79.6 | 59.7 | 36.7 |
    | 39-1 (IRCBot) | 106.2 | 97.1 | 37.3 |

  - 下：條件（小字，可兩行）：`Pi 4（1000 MHz）、veth、10,000 packet／s、Suricata 8.0.7 直接跑 NFQUEUE、ET Open full rules`；`整台機器含 Pi 上的 tcpreplay；trusted 時 SYN／FIN／RST 照樣進 Suricata`。
- 當場講：「trust 的單位是 conntrack 的一條 connection：wnc-gw 在 connection 上設 ct mark 的最高位元，forward chain 看到就直接放行。為什麼不用 nft set 存 5-tuple：5-tuple 會被 port 重用或偽造的 packet 繞過；ct mark 跟著 conntrack 的 entry，新建的 entry 沒有 mark，port 重用時接回舊 entry 的情況，forward chain 會在純 SYN 時先把 trust 清掉。
  下面是 Pi 上量的，Suricata 用 NFQUEUE，也就是 `ips` 的路徑。長 connection 為主的 Somfy 門鎖，全部進 Suricata 時整台機器每個 packet 106 µs，trusted 之後 40 µs，和只轉送差不多；一半是 SYN 的 1-1 只降到 60；幾乎都是 scan 的 39-1 降不下來，因為 SYN 一定進 Suricata。所以 trust 對長 connection 有用，對 scan 沒有用。」
- 補充（取代原本的第一、二點，其餘保留）：
  - 量法：`tests/ids_inline/trust_cost.sh`，Pi 4 鎖 1000 MHz、Pi 內的 veth netns、tcpreplay 綁 CPU 1；Suricata **直接跑 NFQ**（full、和 wnc-gw 一樣的強制設定，不是經過 wnc-gw）；整台機器 CPU 用 `/proc/schedstat`，÷ 經過 forward 的 packet；含 tcpreplay，只能看差距；2 輪平均（`results/trust2.kvl`）。
  - 「trusted」是 C3（全部 trust＋SYN／FIN／RST 進 Suricata，和 wnc-gw 相同）。不含 SYN／FIN／RST 規則的 C2 是 33–40 µs，五個 scenario 省 38–68 µs（DECISIONS §5 的表）；C3 下 39-1 (IRCBot)、1-1 (Hide and Seek) 的控制 packet 佔 91%、53%，所以省得少（DECISIONS §6）。另外兩個 scenario 的 C3：44-1 (Mirai) 94.5 → 32.8、Honeypot-5-1 (Amazon Echo) 71.1 → 40.3。
  - `ids`（NFLOG）路徑時全部進 Suricata 的整台成本約 56–64 µs（`nflog2.kvl`），trust 省的會比這頁少；`ids` 下 auto trust 的實測是第 6 頁。
  - 「trusted − 只轉送」在 8.0.7 是 −4.8 到 +0.9 µs（7.0.10 時到 +3.5）；44-1、Honeypot-5-1 比只轉送低約 4–5 µs，兩輪、兩個版本都一樣，原因**沒有查**。
  - ct mark 的兩個位元（demo 第 4 步會看到 `0xc0000000`）：`0x80000000` trusted、`0x40000000` forwarded。
- 刪掉原本「44-1 trusted 比只轉送還低就是雜訊」「−4.8 到 +3.5 是量測雜訊」的說法。

**第 6 頁 auto trust**
- 投影片：成本表的表頭（或表上一行）寫明 `Pi 4（1000 MHz）、veth、ids：8 條 TCP connection、4,000 packet／s`；表下一行改成 `每秒省 85 ms CPU`（拿掉「= 每個 packet 21 µs」）。（第二版曾在最下方加一行風險，2026-11-06 使用者同意拿掉：審稿只判斷需不需要看，不依「缺少的」加內容；風險只在當場講說。）
- 當場講：刪掉「只有 TCP（已建立）和 UDP 會被 trust」「demo 把 ttl 設成 60 秒…」兩句（前者移到補充，後者在 Demo 第 1 步講）。成本那句改成：「右邊是 Pi 上 `ids` 的成本：8 條 TCP connection、每秒 4,000 個 packet，Suricata 從每秒 100.5 ms 降到 13.6 ms，wnc-gw 自己從 0.5 多到 1.9 ms，合計每秒省 85 ms；換算成每個 packet 是 21 µs，算的是 Suricata 加 wnc-gw 的 CPU。」
- 補充：加「只有 TCP（已建立）和 UDP 會被 trust」。「讀 conntrack 的成本」那點保留，並加「讀表是同步的，讀的期間 wnc-gw 的事件迴圈停住：1 萬條約 0.1 秒；做法待決：放到另一個執行緒，或改用 conntrack 的 NEW／DESTROY 事件」。

**第 7 頁 Suricata 沒在 inspection 時**
- 投影片：表合併成兩列：

  | 情況 | `accept`（預設） | `drop` |
  |---|---|---|
  | Suricata 啟動中、重啟中；`ips` 跟不上 | 放行 | 丟掉 |
  | `ids`：Suricata 跟不上 | packet 照樣轉送，copy 被丟掉 | 同左 |

  重點只留一點：`一定記 log：何時沒有 inspection、持續多久（uninspected_ms）、漏掉多少 copy`。拿掉退避重啟那點。
- 當場講：「wnc-gw 自己啟動 Suricata，等它送出 `READY=1` 才把 packet 交給它，因為 Suricata 7.0.10 和 8.0.7 初始化時收到 packet 會 segfault。Suricata 還沒就緒、重啟中，或 `ips` 跟不上的時候，照 `when_unavailable` 處理：預設 `accept` 放行，不讓 Suricata 的問題把整個公司網路斷掉；設成 `drop` 就丟掉。`ids` 比較特別，packet 本來就不等 Suricata，所以跟不上時 packet 照樣轉送，只是 copy 被丟掉。不管哪一種，一定記 log：什麼時候開始沒有 inspection、沒有了多久、漏掉多少 copy。Suricata 掛掉時 wnc-gw 會自動重啟它。」
- 補充：加「重現：Docker 上 8.0.7、啟動前就有 packet 進 queue 時 50 次有 42 次 segfault；改成收到 `READY=1` 才加 queue 規則後跑 30 次全部正常（DECISIONS §10）」「重啟的退避：1 秒，連續失敗就加倍，最長 60 秒」「漏掉的 copy 每 10 秒記一次」。exception policy 那點改成：「`ips` 時 exception policy（Suricata 處理不了某條 connection，例如記憶體用完）跟著 `when_unavailable`：`accept` → ignore，`drop` → drop-flow（flow、defrag 用 drop-packet）；`ids` 一律 ignore（拿到的是 copy，丟了也擋不到）」。

**第 8 頁 `setting.toml`**（精簡，字要夠大）
- 投影片：一張表（4 欄）：

  | 設定 | 預設 | 其他選項 | 頁 |
  |---|---|---|---|
  | `[ports] lan`、`wan` | （必填） | 網卡名稱或 MAC | |
  | `mode` | `bridge` | `routed` | 9 |
  | `protection` | `ids` | `ips` | 10 |
  | `when_unavailable` | `accept` | `drop` | 7 |
  | `[trust] auto` | `false` | `true` | 6 |
  | `queue`／`group` | 一個 | 範圍：多個 Suricata worker | |

  表下一行（小字）：`其他：nft、Suricata 的路徑與設定檔、逾時、eve_interval、xdp`。
- 當場講：「設定檔是 TOML。唯一一定要填的是 `[ports]`：gateway 不猜哪張網卡是 LAN、哪張是 WAN，用網卡名稱或 MAC 指定，demo 用的是 MAC。會改變 packet 怎麼走的是 `mode`、`protection`、`when_unavailable` 和 `[trust]`；`when_unavailable` 和 `[trust]` 前面講過，接下來兩頁講 `mode` 和 `protection`。`queue`、`group` 設成範圍就會開多個 Suricata worker 分攤流量。其他是路徑和逾時。」
- 補充：第一版第 8 頁的兩張完整表（所有欄位、預設、範圍）整份放進補充，供被問時查；`xdp` 的說明（Pi 4 沒有 native XDP，所以是 TC；eBPF 程式還沒寫，現在只有 doctor 會判斷）和 symhash 的說明移到這裡。其他原本的補充保留。

**第 9 頁 `mode`**
- 投影片：表只留三列（拿掉「怎麼進 nftables」「doctor 的 check」兩列和表下那行）：

  | | `bridge`（預設） | `routed` |
  |---|---|---|
  | 部署 | 插在中間，LAN、WAN 同一個網段 | LAN、WAN 不同網段；不做 NAT，上游 router 要加 route |
  | ARP 等非 IP 的 packet | 照常轉送 | 不轉送 |
  | 只轉送，整台機器（Pi、實體網卡、100 kpps） | 9.97 µs／packet | 8.02 µs／packet |

- 當場講：「`mode` 是 L2 還是 L3。預設 `bridge`，理由是部署：插進既有的公司網路中間，內網的設定不用改。`routed` 的 LAN 和 WAN 是不同網段，我們不做 NAT，所以上游 router 要加一條到內網的 route；另外 `routed` 不轉送 ARP 這類非 IP 的 packet。兩種模式的 nft table 完全一樣，差別只在 doctor 檢查的環境；例如 `bridge` 要確認 `br_netfilter` 有載入，沒載入的話 packet 會完全繞過我們的 rule。效能上，Pi 的實體網卡只轉送時，`routed` 每個 packet 少約 2 µs；有 Suricata 時兩者只差 2 到 9%。等一下的 demo 在 Docker 上用的是 `routed`。」
- 補充：加「兩種模式 doctor 的 check：`bridge` 看 LAN、WAN 在同一個 bridge、`br_netfilter`、`bridge-nf-call-iptables`／`ip6tables`；`routed` 看不在 bridge、`ip_forward`、IPv4 位址、網段重疊、default route 走 WAN」「這頁的 9.97／8.02 是 Pi 整台機器、封包從筆電送進來（Pi 上沒有 tcpreplay），和第 5 頁（veth、Pi 上跑 tcpreplay）的『只轉送』基準不同，不能互相比」。其他保留。

**第 10 頁 `protection`**（併入原第 15 頁的 `ips` 說明）
- 投影片：表四列（拿掉 checksum 那列）：

  | | `ids`（預設） | `ips` |
  |---|---|---|
  | packet 等不等 Suricata | 不等：NFLOG 送 copy，立刻轉送 | 等：NFQUEUE 等 verdict |
  | 能不能擋 | 不能，只有 alert | rule 的 action 是 `drop` 就擋 |
  | Suricata 執行緒 µs／packet（Pi、veth） | 19–24 | 35–48 |
  | 容量（Pi、實體網卡、2 個 pcap） | 50–80 kpps（要開 RPS） | 60 kpps |

  表下一行：`ET Open 52,798 條 rule 全部是 alert → 現在 ips 也不擋（今天不現場示範）`。
- 當場講：「`protection` 決定 packet 要不要等 Suricata。預設 `ids`：kernel 立刻轉送，另外用 NFLOG 送一份 copy 給 Suricata，所以 Suricata 再慢都不會拖慢或擋住流量，但也就不能擋，只有 alert；`ids` 還要關掉 checksum validation，doctor 會警告。`ips` 用 NFQUEUE，packet 要等 Suricata 的 verdict，rule 的 action 是 `drop` 就擋。
  Pi 上只算 Suricata 自己的執行緒，每個 packet `ids` 是 19 到 24 µs，`ips` 是 35 到 48 µs。實體網卡上的容量，`ids` 是每秒 5 萬到 8 萬個 packet，看流量從哪張網卡進來，而且要開 RPS；`ips` 是 6 萬。
  `ips` 今天不現場示範：ET Open 的 52,798 條 rule 全部是 `alert`，沒有 `drop`，跑 `ips` 看起來會和 `ids` 一樣。我們把 3 條 rule 改成 `drop` 測過：server 回 `uid=0(root)` 的 connection，`ips` 下 client 6 秒收到 0 bytes，`ids` 下照樣收到。哪些 rule 要改成 `drop` 還沒決定。」
- 補充：原第 10 頁補充保留（「checksum 檢查」都改成 checksum validation；eth1 的原因標「**推測**」）；加 checksum 的完整說明（GRO 平均 6.7 個 packet 合成一份 copy、開著時 74% 被判成 checksum 錯誤；關掉的風險是 insertion：攻擊者送接收端會丟掉的 packet 來混淆 Suricata；`ips` 沒有這個問題，kernel 會標出 checksum 還沒算的 packet）；容量的兩個 pcap：17-1 (Kenjiro) `ids` 80（inspection 容量）、1-1 (Hide and Seek) `ids` 50（轉送容量）、`ips` 兩個都是 60；原第 15 頁的補充整份移來（`drop` 實測：Docker、8.0.7、3 條 rule 改成 `drop`；Muhstik 的 `NICK` packet 不轉送、同一條 connection 其他 packet 照常，`drop` 丟的是比對到的 packet；iperf3 `ips` 1.02–1.15 → 50.6–52.2 Gbit/s 是 DOCKER.md 演練紀錄 Suricata 8.0.8 那一次、筆電的數字；nft 黑名單還沒做）。

**第 11 頁 `doctor`**
- 投影片：左邊 check 清單縮成四行：
  - 設定、port 對到哪張網卡
  - kernel：模組、sysctl、`mode` 需要的環境
  - Suricata：NFQUEUE／NFLOG、`READY=1`、設定、rule 檔、eve-log
  - 權限：非 root 可以改的檔案
  右邊嚴重程度表、下方 punch 保留。
- 當場講：「doctor 是部署時第一個要跑的。它檢查四類：設定和 port、kernel 的模組和 sysctl、Suricata 的能力和設定，還有哪些檔案非 root 可以改。結果分三級：error 是 gateway 沒辦法正確運作，例如設定錯、port 找不到、缺模組，`run` 就不啟動；warning 是暫時的狀態或已知的風險，例如 link down、`ids` 不擋流量，`run` 照常啟動；note 只是資訊。能修的訊息都附上修法的指令。doctor 不改任何東西，`run` 啟動前也會先跑同一套 check。」
- 補充：加完整的 check 項目（第一版投影片左邊的 11 項，包含 eBPF 掛點、其他在跑的 Suricata、auto trust 的 `nf_conntrack_acct`）；demo 輸出那點的「DOCKER.md 沒列」改成三則（IPv6 forwarding、systemctl、`when_unavailable = "accept"`）。

**第 12 頁 Demo 環境**
- 投影片：拓樸圖拿掉 IP 和網段標籤；節點寫名稱加角色：`wnc-cli`（iperf3 client）、`wnc-gw`（`routed`、Suricata 8.0.7）、`wnc-srv`（iperf3 server）、`wnc-rep`（重播 pcap）；兩段線標 `LAN`、`WAN`。對應表只留兩列：

  | Docker | Pi | 等不等價 |
  |---|---|---|
  | `wnc-gw` 容器，`routed` | Pi，`bridge`（預設） | nft table、Suricata 8.0.7、rule 相同；kernel 版本不同 |
  | 共用筆電的 kernel、CPU | Pi 4 的 kernel、CPU | 速度、Suricata 啟動時間不等價 |

  最下一行改成：`Pi 上用 demo.sh 跑過：trust、alert 不 trust、TTL 到期、kill Suricata、重播 3-1 (Muhstik)`。
- 當場講：「demo 在筆電的 Docker 上做。中間的 `wnc-gw` 容器跑 wnc-gw 和 Suricata，`mode` 是 `routed`；兩邊的 `wnc-cli`、`wnc-srv` 是 iperf3 的兩端，用來量速度；`wnc-rep` 有兩張網卡，把 dataset 的 pcap 重播進 gateway：設備送出的 packet 從 LAN 進，外面送回來的從 WAN 進。和 Pi 比，nft table、Suricata 的版本和 rule 都一樣，所以 trust、alert 的行為一樣；不一樣的是 kernel 版本，還有速度和 Suricata 的啟動時間，因為容器共用筆電的 kernel 和 CPU，等一下看到的速度不代表 Pi。Pi 上我們用另一支腳本 `demo.sh` 跑過同樣的功能：11/04 在 Pi 內部的 veth、11/05 接實體網卡，trust、有 alert 不 trust、TTL 到期、kill Suricata 都和 Docker 一樣，11/05 也重播過 Muhstik。」
- 補充：「實機重播 Muhstik 時 3 筆 alert 和 Docker 一樣」改成「前 3 筆和 Docker 一樣；另外 2 筆 `ET MALWARE ELF/Muhstik Botnet CnC Activity` 要等 connection 結束才出來，停止時才記（共 5 筆，和離線 `suricata -r` 相同）」；加「conntrack 的行為相同是**推論**：筆電 kernel 7.0、Pi 6.18；port 重用清 trust、auto trust 兩邊都驗證過」「somfy、mirai、iperf3 沒有在 Pi 上跑過」。

**第 13 頁 Demo 流程**（併入原第 13 頁「重播的 scenario」）
- 投影片：一張表（3 欄）：

  | # | 做什麼 | 預期 |
  |---|---|---|
  | 1 | 設定 `demo.toml` | `ttl` 60 s（為了看到到期） |
  | 2 | `doctor` | 沒有 error |
  | 3 | `run` | Suricata 就緒前的時段記在 log |
  | 4 | 重播 Honeypot-7-1 (Somfy door lock)：1 條 HTTPS | trusted |
  | 5 | 重播 3-1 (Muhstik)：2 條 IRC C&C、4 條 NTP | C&C 不 trust；3 條 NTP trusted |
  | 6 | 重播 34-1 (Mirai)：2 次 HTTP 下載 ELF、1 條 SSH | 下載不 trust；SSH trusted |
  | 7 | iperf3 | trust 後速度回到沒有 gateway 的水準 |
  | 8 | kill Suricata | 記下沒有 inspection 的時段、自動重啟 |

  表下一行：`IoT-23 各 scenario 開頭 500 個 packet，每秒 50 個`。
- 當場講：「demo 照這張表做。重播的是 IoT-23 三個 scenario 的開頭 500 個 packet，每秒 50 個，大約 10 秒。Somfy 門鎖是良性的，應該會被 trust；Muhstik 是同一台被感染的設備，連 C&C 的 connection 有 alert，不會被 trust，NTP 會；Mirai 下載 ELF 的 connection 有 alert，不會被 trust，SSH 會。這三個 pcap 都先用 Suricata 離線跑過全部 rule，alert 和送進 gateway 的一樣。接下來切到終端機。」
- 補充：原第 13 頁（重播的 scenario）、第 14 頁的補充合併到這裡；改正：62 條只有 SYN 的 connection（不是 64）；NTP 4 條、第 4 條（`78.108.102.237`）每個方向只有 10 個 packet，wnc-gw 從第一次看到才開始算、到不了 10，所以只有 3 條會被 trust；「scan、flood 本地 rule 抓不到」改成「大部分 scan、flood 本地 rule 抓不到（SSH scan 例外；這是 11/02 的推論）」。

**Demo（切到終端機）**　照 §4「Demo」，改：
- 第 1 步當場講：只講 `mode` 是 `routed`、`protection` 是 `ids`、`[ports]` 用 MAC、`ttl` 只設 60 秒是為了看得到到期（預設 900）；不逐一念 `[trust]` 的欄位。
- 第 2 步當場講：「沒有 error。warning 都是預期的：`ids` 不擋、不做 checksum validation、流量太快會漏 copy、Suricata 啟動和重啟時放行、auto trust 的風險、Suricata 由 wnc-gw 啟動；另外幾個是 Docker 環境造成的。」補充：列出全部 10 個 warning 和 1 個 note；DOCKER.md 沒列的是三個（IPv6 forwarding、systemctl、`when_unavailable = "accept"`）。
- 第 4 步當場講：不念 IP、port、`packets_original` 等數字；改講：「log 說這條 connection 被 trust 了。`trust list` 的 MARK 是 `0xc0000000`：`0x80000000` 是 trusted，`0x40000000` 是經過 gateway。nft 的 counter：`ids` chain 的是送進 Suricata 的 packet，`accept` 那條是 trusted、跳過 Suricata 的。」數字（`packets_original=128`、292／164）放補充。
- 第 5 步：「約 2 秒內」改成「重播開始後約 3 秒內」（IRC 的 connection 約第 2.4–2.6 秒才開始）；「3 條 NTP」改成「NTP 4 條裡 3 條 trusted」；補充 62 條。
- 第 7 步當場講：不報 Gbit/s，只講「trusted 之前比較慢，trusted 之後回到沒有 gateway 的水準；這是筆電的速度，不代表 Pi」，copy 的成本和漏 copy 的說明保留。補充：演練數字改成「8.0.7 重做時 28.7–31.7 → 47.1–52.4 Gbit/s；表格那一次（8.0.8）27.8–31.2 → 49.1–52.5，漏掉的 copy 371,678、533,159」。
- 第 8 步補充：「重新就緒 6.6 秒、`uninspected_ms=7572`」標明是 8.0.8 那一次的演練，8.0.7 沒有這一步的紀錄。
- Demo 結束：當場講加一句「回到投影片，最後是待決事項和下一步」。

**第 14 頁 待決與下一步**（併入原第 16、17 頁）
- 投影片：左右兩塊。
  - 左「待決」（表 2 欄）：

    | 待決 | 現況 |
    |---|---|
    | auto trust 的預設值 | 建議值；packet 數和秒數沒有實驗依據 |
    | `ids` 下 alert 比 `min_age` 晚到 | 低流量的 connection 先 trusted、結束時才 revoke |
    | `mode` 的預設 | `bridge` 不用改網段；`routed` 轉送較省 |

  - 右「下一步（規劃）」（條列）：
    - 最小的 cloud 迴路：模擬 cloud，回 trust／block／observe
    - tc eBPF 算特徵
    - tc eBPF fast path
- 當場講：「還沒決定的有三件。第一，auto trust 的數值現在是建議值：預設關、10 個 packet、5 秒、TTL 900 秒；TTL 有理由，要比 Suricata 忘記一條 connection 的 600 秒長，但 packet 數和秒數沒有實驗依據。第二，`ids` 模式下，低流量 connection 的 payload alert 可能比 `min_age` 晚到，connection 會先被 trust、結束時才因為 alert 被 revoke；`ips` 下同樣的 connection 一開始就不會被 trust。第三，`mode` 的預設：`bridge` 部署不用改網段，`routed` 轉送比較省。
  下一步是先接最小的 cloud 迴路：我們自己做一個模擬的 cloud，wnc-gw 把資料送上去，cloud 回 trust、block 或 observe。這是 10/25 決定的，排在 eBPF 之前。之後是用 tc eBPF 算特徵，給 cloud 和 edge AI 用，再來是 fast path，trusted 的 connection 在 tc 就直接轉送、不經過 netfilter；這兩步的切法是規劃，順序可能調整。」
- 補充：原第 16、17 頁的補充合併；刪掉「demo 用的 Muhstik、Mirai 在 2 秒內就有 alert」和「階段 3 時會改成讀 BPF map」；讀 conntrack 停住事件迴圈、預設開幾個 queue／group 兩項從投影片移到這裡（做法待決：另一個執行緒或 conntrack 事件）；加「auto trust 待確認的還有預設關、`check_interval` 5 秒（README）」「edge AI 的介面與 CPU 分配要和合作方確認」。

**第 15 頁 References**（放在 Q&A 之後）　內容不變；當場講刪掉（不念）。

### 6.5 逐字稿的其他修正

- 檔頭的頁數改成實際頁數（應是 17 頁：封面、編號 1–14、Q&A、References 15）。
- 章節頁拿掉了，章節頁的過場句一起刪。
- 全份照 6.3 改名詞。

### 6.6 第二次審稿後的改動（2026-11-06，使用者同意；覆蓋 6.4 對應的地方）

依 `審稿_預期問題.md`。審稿只判斷聽眾需不需要看；兩個角度（公司工程主管、指導教授）都認為不需要的才移除，和草稿要求衝突的保留。

- 移除（`審稿_預期問題.md` 一、第 1、2、3、5、6 項）：
  - 第 6 頁：`[trust]` 表的 `demo` 欄（表只剩「`[trust]`｜預設」兩欄；demo 的 `ttl` 60 s 只在第 13 頁和 Demo 第 1 步講）。
  - 第 8 頁：「頁」欄、表下那行灰字（其他設定的列舉）。當場講不變。
  - 第 11 頁：下方的 punch（`doctor` 不改任何東西；`run` 啟動前先跑同一套 check），以及當場講最後一句；第 3 頁已講。
  - 第 15 頁 References：Suricata 8.0 User Guide、nftables wiki 兩筆；剩 IoT-23、ET Open rules，改成單欄。
- 保留（老師角度建議刪，但草稿要求介紹 setting 和 doctor）：第 8 頁的設定列、第 11 頁的 check 清單。
- 沒動（只有一方提出，等使用者決定）：`審稿_預期問題.md` 一、第 4、7–17 項。
- 逐字稿「二、補充」依頁碼加入預期問題的回答（「被問「…」：…」的寫法），24 題中加了 23 題；第 23 題（時程、上正式設備的驗收標準）要使用者決定，沒有加：
  - 第 3 頁：權限（第 20 題）、授權（第 22 題）。
  - 第 5 頁：in-window 偽造 packet（第 4 題）。
  - 第 6 頁：UDP 的 trust（第 3 題）、TTL 到期後從中間接手（第 14 題）、本地抓不到的攻擊（第 1 題）、先裝正常再攻擊（第 2 題）、HTTPS（第 9 題）、偵測有沒有變差（第 10 題）、省 85 ms 夠不夠（第 12 題）。
  - 第 7 頁：wnc-gw 當掉（第 8 題）、故意弄倒 Suricata（第 6 題）、`ids` 下大量送 packet（第 7 題）、rule 更新（第 18 題）。
  - 第 9 頁：和現有 firewall、NAT、QoS、mwan3、PPPoE、VLAN 共存（第 16 題）。
  - 第 10 頁：容量換成 Mbps（第 5 題）、哪些 rule 改成 `drop`（第 15 題）。
  - 第 12 頁：Pi 實機的 throughput（第 24 題）。
  - 第 14 頁：alert 晚到漏掉多少（第 11 題）、`min_packets`／`min_age` 怎麼定（第 13 題）、log 與 eve.json（第 19 題）、cloud 通道（第 21 題）、SoC 硬體加速（第 17 題）。
- 寫進逐字稿前再查證，和 `審稿_預期問題.md` 不同的兩處（已一併更正該文件）：
  - 第 2 題：不是「沒有量」。`tests/partial_inspect/README.md` 實驗 5（合成 connection、offline Suricata）：只看前 20 個 packet、之後不看時，後段的攻擊 0% 抓到。
  - 第 14 題：原本引的實驗 3 是 offline（`--simulate-ips`），不是 Docker。改引實驗 3b：Docker 上真的 TCP connection 經過 wnc-gw，Suricata 已經忘了這條 connection 時 `ids` 全部抓到、`ips` 第一個 request 的 `flow:established` rule 漏；Suricata 還記得時就取消 trust，HTTP 的 rule 會漏、`ips` 丟 4 個 packet。
  - 第 20 題：「Suricata 用非 root 加 landlock」出處是 gateway-architecture SKILL.md §3 的表（Suricata 那一列）；O1 是「什麼時候拆 process」，做 cloud 迴路之前要再決定一次。

### 6.7 Demo 改一頁、單位標清楚、第 2 頁與 XDP（2026-11-06，使用者同意；覆蓋 6.4、6.6 對應的地方）

使用者：「12-14改成Demo」「單位要標記清楚不然我也不知道怎麼讀」「（第 2 頁）你說的對照你說的改」「（XDP）好」。

- 頁序：原本第 12 頁 Demo 環境、第 13 頁 Demo 流程、第 14 頁待決與下一步，換成一頁 `#focus-slide[Demo]`（不編號）。大綱剩 4 項（架構、Trust、設定與 doctor、Demo）。共 15 頁、編號 1–12，References 是第 12 頁。
  - 理由：demo 的每一步在前面的頁都講到了（doctor 第 11 頁、run 與 `READY=1` 第 3、7 頁、以 connection 為單位第 5 頁、auto trust 與 TTL 第 6 頁、iperf3 與漏 copy 第 6、7 頁、kill Suricata 第 7 頁、設定第 8 頁），拿掉 demo 頁不違反草稿「demo 要提的東西 slides 都要講到」。
  - Demo 環境（Docker 對 Pi）改成切到終端機前用講的；待決與下一步搬到逐字稿補充最後一節，被問到再講。
- 第 2 頁：LAN、WAN 改成雙向箭頭；框的標籤改成「gateway（Pi 4）」，框代表 gateway 這台機器、不是 wnc-gw（netfilter、eBPF 在 kernel，Suricata 是 spawn 的獨立程式，edge AI 是合作方的程式；README 定義 wnc-gw 是「主程式」）。`tc eBPF` 改成 `eBPF（XDP／TC）`（DECISIONS.md §17：`xdp = auto`，fast path 固定 TC）。
- 第 8 頁：表加一列 `xdp`｜`auto`｜`off`、`generic`。
- 單位：
  - 第 5 頁：表上方加「每轉送一個 packet，整台機器用掉的 CPU 時間（µs）」，表頭第一格只留 scenario。
  - 第 6 頁：表上方加「每秒用掉的 CPU 時間（ms）」，格子只放數字；底下改成「每秒省 85 ms（一顆 CPU core 的 8.5%）」。條件加「1 條測試 rule」：查 `autotrust_cost_pi.sh saving`，Suricata 只載入 1 條 UDP 的 content rule，不是 ET Open（原本沒寫，容易被當成 full rules）。
  - 第 9 頁：列名改「只轉送：每個 packet 整台機器的 CPU 時間」，格子 `9.97 µs`、`8.02 µs`；條件移到表下：Pi 4（1000 MHz）、實體網卡、100,000 packet／s。
  - 第 10 頁：列名改「每個 packet Suricata 的 CPU 時間」「容量：丟掉的 packet ≤ 0.1% 的最高速率」；容量寫成 50,000–80,000 packet／s、60,000 packet／s；條件移到表下。
- 第 10 頁數字更正：原本 19–24／35–48 混了 empty rules。只看 full rules：`ids` 21.1–24.4、`ips` 37.6–47.8（DECISIONS.md §2 的 nflog2 表）→ 21–24／38–48。
- 逐字稿：使用方式加單位定義和「量測的流量都是小規模的」；第 2、5、6、8、9、10 頁的當場講跟著改；第 2 頁補充加框的意義、XDP、fast path；第 5、6、9、10 頁補充加流量的規模（IoT-23 開頭 200,000 個 packet／Python 產生的 8 條 TCP connection）。

### 6.8 doctor 第二頁：Pi 4 與 Docker 的截圖（2026-11-06）

使用者要用截圖（「這樣比較真實」），自己在 Pi 和 Docker 上跑 doctor，放了 `assets/pi_xdp.png`、`assets/docker_xdp.png`。

- 第 12 頁「`doctor` 的輸出：Pi 4 與 Docker」，放在第 11 頁之後、Demo 之前；References 變第 13 頁，共 16 頁。
- 截圖用 PIL 裁掉上面的設定摘要和 port 表，只留 MODE CHECK 和 XDP 兩張表（`assets/pi_xdp_crop.png`、`assets/docker_xdp_crop.png`；原圖保留）。兩張用同一個比例，字一樣大；左邊標「Pi 4／`bridge`／`xdp = auto`」「Docker（veth）／`routed`／`xdp = auto`」。
  - 用 Typst 的 clip 裁切，在 slydekit 裡顯示錯（圖幾乎不見），所以改成先裁好檔案。
- 查證：
  - Pi：`eth0` bcmgenet、`eth1.20` 的 NATIVE XDP 都是 `no` → CORE HOOK `tc`，和 DECISIONS.md §17 從 driver 原始碼推的一致。Docker 的 veth `basic,redirect,rx-sg` → `xdp (native)`。`hook.rs` 的 `core_hook`：`auto` 時有 basic 才選 native XDP，否則 TC。
  - DRIVER 欄讀 `/sys/class/net/<網卡>/device/driver`（`netif.rs` 的 `read_driver`），VLAN、veth 沒有，所以是 `-`。
  - Pi 的 wnc-gw 是 11/06 用工作目錄（含 11/05 還沒 commit 的 `routed` check）編的 aarch64 版，sha256 `a5b39188…`；舊版留在 Pi 的 `~/demo/wnc-gw.20261104`。
  - Docker 截圖的 `xdp: auto (config file)` 是 `demo.toml` 暫時改的；現在的 `demo.toml` 是 `xdp = "off"`（和 HEAD 相同），demo 現場 doctor 的 CORE HOOK 是 `tc`。逐字稿「Demo：環境」照這個寫。
- 逐字稿：加第 12 頁的當場講（兩張表各在檢查什麼、XDP 怎麼選、doctor 的原則）和補充（截圖條件、欄位意思、怎麼讀、沒量 XDP 對 TC）。

### 6.9 第 3 頁：流程圖標成 `run` 的生命週期（2026-11-06）

使用者：圖中的流程沒說是做什麼的；寫「run 生命週期」，而且是目前的；「READY=1 後送 packet」看不出是誰送。

- 流程圖包進容器框，左上灰字「`run` 的生命週期（目前）」，和第 2、4 頁的框同一種畫法。
- 「`READY=1` 後 送 packet」改成「收到 `READY=1` 開始 inspection」。查 `src/cli/run.rs`：table 一裝好就照 `when_unavailable` 轉送（預設 `accept`、沒有 inspection）；收到 `READY=1` 後只換 `ids` chain 的 rule，packet 才交給 Suricata（`start_inspection`）。所以不寫「開始收、送封包」（會被讀成 Suricata 就緒前 gateway 不通）。
- 圖的順序和 `run.rs` 相同：`doctor::passes` → 清掉上次留下的 trust → `firewall::install` → 啟動 Suricata → 就緒後 `start_inspection` → 讀 alert、auto trust → `firewall::remove`。
- 排版：加框後圖被擠到下一頁，間距改 (0.7cm, 1.1cm)、方塊 3.3cm、字 0.78em，READY 那格 5cm。
- 逐字稿第 3 頁：「下面是 `run` 目前的生命週期」，「等 `READY=1` 才開始 inspection，也就是把 packet 交給它」。

### 6.10 單位縮短、實驗設定只留逐字稿、英文用詞（2026-11-06，使用者同意）

使用者：第 6 頁表格沒對齊；實驗設定都放逐字稿（第 5、6、9、10 頁都拿掉）；拿掉「一顆 CPU core 的 8.5%」；有些地方用英文（「不 trust」、圖中的「觀察」）。

- 灰字實驗設定：第 5 頁（使用者先拿掉了）、第 6、9、10 頁全部拿掉，條件只在逐字稿。
- 單位：第 5 頁表上方「整台機器 CPU µs／packet」；第 6 頁右表表頭左上角「CPU ms／s」；第 9 頁列名「只轉送：整台機器 CPU µs／packet」，格子只放數字；第 10 頁列名「Suricata CPU µs／packet」，格子只放數字。保留「CPU」：只寫 µs／packet 容易被讀成延遲。保留「整台機器」／「Suricata」：兩者範圍不同。
- 第 6 頁：
  - 圖改成程式的三個狀態（`src/agent/trust.rs` 的 `State`：`Watching`、`Trusted`、`Refused`）：watching → trusted（條件）、trusted → watching（`ttl` 到期）、watching → refused（alert）、trusted → refused（alert（revoke））。查程式：兩種 alert 都把狀態設成 `Refused`，原本的「永遠不 trust」「revoke」兩個終點合成一個。
  - 右表表頭「不 trust／auto trust」改成 `auto = false`／`auto = true`；兩張表各自置中、頂端對齊；「每秒省 85 ms」拿掉括號。
- 英文用詞：第 3 頁標題和表頭「子命令」→ subcommand；第 4 頁「Suricata 就緒？」→「Suricata ready？」；第 10 頁「容量」→ capacity；第 11 頁「等級」→ severity。
- 逐字稿這次不動（使用者：改完最後一起更新）。要一起更新的：
  - 第 3 頁：「gateway 本體是 `run`」→ 執行 gateway 的是 `run`（表已改「執行 gateway」）；subcommand。
  - 第 4 頁：ready；可加「`accept` 會結束比對，所以 SYN／FIN／RST 排在 trusted 前面」。
  - 第 5、6、9、10 頁：投影片上拿掉的條件改用講的（第 6 頁一定要講「1 條測試 rule」）；單位用「CPU µs／packet」「CPU ms／s」；第 6 頁「約一顆 core 的 8.5%」改講法或拿掉。
  - 第 6 頁：watching／trusted／refused、`auto = false`／`auto = true`。
  - 第 10 頁 capacity、第 11 頁 severity；使用方式的單位定義跟著改。

### 6.11 「預設」改成 default（2026-11-06，使用者：「改」）

- 第 6 頁 `[trust]` 表頭、第 7 頁 `accept`（default）、第 8 頁表頭（只改 default，「設定」「其他選項」留中文）、第 9 頁 `bridge`（default）、第 10 頁 `ids`（default）。理由：和 doctor 輸出的 `(default)` 一致（第 12 頁截圖、demo 現場）；設定的技術名詞用英文。
- 逐字稿最後一起更新：指設定值的地方寫 default，口語句子留「預設」。

### 6.12 第 8 頁設定表（2026-11-06，使用者：「P8 照你說的改」）

- 表頭改英文：setting／default／options；「（必填）」→「（required）」。
- 段落名稱補齊（`setting.example.toml`）：`when_unavailable`、`queue`、`group` 都在 `[suricata]` 底下。
- `queue`／`group` 那列：default 寫實際值 `0`／`10`（原本「一個」不是設定值）；options 寫「範圍，例如 `"0-2"`／`"10-12"`」（原本「多個 Suricata worker」是用途，改用講的）。
- 只列會改變 packet 怎麼走的 7 項；沒列的 12 項（路徑、逾時、`eve_interval`、`[trust]` 的四個數值在第 6 頁）留在逐字稿補充的完整表。
- 逐字稿最後一起更新：`queue` 是 `ips` 的 NFQUEUE 編號、`group` 是 `ids` 的 NFLOG group，設成範圍就開多個 Suricata worker。

### 6.13 第 7 頁：拿掉 READY 那行、情況分三種（2026-11-06，使用者：「改」）

- 拿掉「收到 `READY=1` 才把 packet 交給 Suricata」：這頁講沒在 inspection 時，這行講開始 inspection，方向相反；第 3 頁的生命週期已有「收到 `READY=1` 開始 inspection」。等 `READY=1` 的理由（Suricata 初始化時收到 packet 會 segfault）用講的。
- 表頭「情況」→ case；原本第一列拆開，共三列：Suricata 啟動中、重啟中／`ips`：NFQUEUE 滿了／`ids`：NFLOG socket 滿了。
  - 查證：`firewall.rs` 在 `accept` 時給 queue 設 bypass，`ids/spawned.rs` 設 `nfq.fail-open=yes`；`drop` 時 queue 滿了由 kernel 丟。`ids` 漏 copy 是 Suricata 的 NFLOG netlink socket 滿了，wnc-gw 讀 `/proc/net/netlink` 的 Drops 欄（`kernel/nflog.rs`）。
  - 「Suricata 跟不上」改寫成實際發生的事（使用者覺得有更好的說法）。
- 底下那行 log 的文字是使用者改的，沒動。
- 逐字稿最後一起更新：第 7 頁的三種情況、READY 的理由。

### 6.14 第 9、10 頁只留重點（2026-11-06，使用者：「改」）

使用者：大家都知道 bridge／routed、ids／ips 是做什麼的，只寫重點。

- 第 9 頁：拿掉「ARP 等非 IP 的 packet」（L2／L3 的基本差別）；「部署」改成我們的取捨：`bridge` 不用改網段（選它當 default 的理由）／`routed` 不做 NAT，上游 router 要加 route。留「只轉送：整台機器 CPU µs／packet」。兩種模式需要的環境在第 12 頁的截圖。欄寬改成依內容。
- 第 10 頁：拿掉「packet 等不等 Suricata」「能不能擋」（定義；NFLOG／NFQUEUE 的實作在第 4 頁的圖）；留 Suricata CPU µs／packet 和 capacity。
- 使用者自己先拿掉了：第 10 頁的「（要開 RPS）」和 ET Open 全部是 `alert` 那行灰字、References 頁。沒有加回去。
- 逐字稿最後一起更新：拿掉的內容（ARP、ids／ips 的機制、要開 RPS、ET Open 全是 alert 所以不示範 ips、checksum validation）改成用講的或放補充；References 那節。

### 6.15 第 9、10 頁合併；doctor 頁寫檢查方式（2026-11-06，使用者：「改 a」）

- 第 9 頁「`mode` 與 `protection`」：原本第 9、10 頁的兩張表上下排（內容同 §6.14）。共 14 頁。
- 第 10 頁 `doctor`：
  - 左邊「check／怎麼查」10 列，對照程式確認：port（rtnetlink、先比 permanent MAC，`ports.rs`）、`mode` 環境（sysctl、rtnetlink）、XDP（netdev netlink `xdp-features`）、kernel 模組（`/lib/modules`、`/proc/modules`，`kernel/modules.rs`）、`nft`（版本、JSON，`kernel/nft.rs`）、Suricata 能力（`--build-info` 的 NFQueue、NFLOG、Systemd support，`ids/suricata.rs`）、Suricata 設定（`--dump-config` ＋ 強制的 `--set`；rule 檔、eve-log）、其他 Suricata（RUNNING SURICATA、`suricata.service` AT BOOT）、auto trust（`nf_conntrack_acct`）、權限（檔案和上層目錄，`access.rs`）。
  - 右邊 severity 表（使用者選 a：同頁並排）；「意思」縮成「無法正確運作」「暫時狀態、已知風險」「資訊」，避免左表折行。
  - 下面 punch：「看能力、不看版本號；看正在跑的狀態；判斷不了就給 warning」（`doctor-checks.md` §6）。
- 逐字稿最後一起更新：第 9 頁合併後的講法；第 10 頁 doctor 的檢查方式與原則（原則從第 11 頁的講稿搬過來）；Systemd support 就是 `READY=1`。

### 6.16 doctor 頁改成 4 類「沒過會怎樣」（2026-11-06，使用者：「改」）

使用者：「怎麼查」不重要，寫檢查什麼、為什麼；再統整，沒人想知道所有細節。

- 第 10 頁改成「check／沒過會怎樣」4 列（依 `cli/doctor.rs`、`forwarding/bridge.rs` 的訊息與嚴重程度統整）：
  - port、`mode` 的環境：找不到網卡，或 packet 繞過 nft table（`bridge-nf-call-iptables` 沒開時 "bridged IPv4 traffic bypasses nftables"）。
  - kernel、`nft`、Suricata 的能力：table 裝不上（模組、nft JSON），或 Suricata 收不到 packet（NFQueue／NFLOG）。
  - Suricata 設定、rule、alert：Suricata 起不來（設定載入失敗、queue／group 被別的 Suricata 佔住）、沒有 rule；EVE 沒輸出 alert 時 "connections that raise alerts would be trusted too"。
  - 權限：非 root 能改的檔案 "could make the gateway run code with its privileges"。
- 拿掉「怎麼查」表和原則 punch（改用講的）；XDP 不列（第 11 頁截圖有）。
- severity 表保留；左右並排會折行，改成上下排。
- 逐字稿最後一起更新：細項（線沒插好只給 warning、`READY=1`、`nf_conntrack_acct`、其他 Suricata、原則）用講的或放補充。

### 6.17 doctor 表改成「類別／檢查什麼／沒過會怎樣」（2026-11-06，使用者：「改」）

使用者：check 寫太簡略，看不出檢查什麼（例如權限應該寫設定／執行檔）。

- 第 10 頁改成 5 列三欄：網路／kernel、`nft`／Suricata／auto trust／權限。依 `cli/doctor.rs`、`forwarding/*.rs`、`access.rs`：
  - 網路：port 對到哪張網卡；`mode` 需要的 bridge、sysctl、位址和 route。
  - kernel、`nft`：需要的模組；`nft` 的 JSON 支援。
  - Suricata：NFQUEUE／NFLOG、`READY=1`（Systemd support）；設定載入得了（`--dump-config`）；有 rule；queue／group 沒被別的 Suricata 佔住。
  - auto trust：Suricata 有輸出 alert（EVE）；`nf_conntrack_acct`。
  - 權限：wnc-gw 設定檔、`nft`、`suricata` 執行檔、Suricata 設定檔，含上層目錄（跟 symlink；sticky 目錄只看擁有者），非 root 能不能改；warning。
- 排版：一開始 severity 表最後一列被擠到下一頁，字級改 0.72em、間距縮小，回到 14 頁。

### 6.18 Demo 前一頁補上 Demo 架構（2026-11-10，使用者被要求補上）

- 新增第 12 頁「Demo 架構」，放在「Demo」大字頁之前；共 15 頁。
- 圖：框標「筆電的 Docker」；`wnc-cli`（iperf3 client）── LAN 10.0.1.0/24 ── `wnc-gw`（wnc-gw ＋ Suricata 8.0.7，`routed`、`ids`）── WAN 10.0.2.0/24 ── `wnc-srv`（iperf3 server）；`wnc-rep`（重播 IoT-23 pcap）兩條箭頭分別指向 LAN、WAN。
- 查證（`docker/compose.yml`、`docker/entrypoint.sh`、`docker/wnc-gw/demo.toml`、`tests/demo/prep_docker.sh`）：
  - 網段 lan 10.0.1.0/24、wan 10.0.2.0/24；gw 10.0.1.1／10.0.2.1，cli 10.0.1.2，srv 10.0.2.2，rep 10.0.1.3／10.0.2.3（兩邊都有網卡）。
  - cli 的 default route 指向 gw；srv 加了 `10.0.1.0/24 via` gw，也就是 `routed` 時「上游要加的 route」。
  - `demo.toml`：`mode = "routed"`、`xdp = "off"`、`protection = "ids"`。
  - 重播時 gw 另加 `192.168.0.0/16` 往 LAN、default 往 WAN，下一跳是不存在的 MAC，packet 只經過 gateway 一次。
- 逐字稿最後一起更新：Demo 開場那段環境說明移到這頁的當場講；可帶一句 srv 的 route 就是 `routed` 要上游加的那條。
