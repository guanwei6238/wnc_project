# wnc-gw（security_gateway）

Security gateway 的主程式，Rust 實作，執行檔是 `wnc-gw`。架在內網（LAN）和外網（WAN）之間，轉送的流量先在本機用 Suricata 檢查，之後再把本機判斷不了的交給 edge AI 和雲端。

目前做到階段 1 加上 TC fast path：nftables 把轉送的流量交給 Suricata；「已信任」的連線記在核心 eBPF 程式的 map 裡，它的封包在兩個 port 的 TCX ingress 就直接轉送到另一個 port，不進 bridge／routing、netfilter 和 Suricata。信任可以由管理者手動設，也可以讓 wnc-gw 觀察一段時間、沒有 alert 就自動信任（`[trust] auto`）。

核心 eBPF 程式（步驟 A、C，2026-11-14）：`run` 把它掛在兩個 port 的 TCX ingress 第一位；查到信任的五元組就 redirect（bridge 用 `bpf_redirect`，routed 先減 TTL 再 `bpf_redirect_neigh`），其他封包照常進 kernel。Pi 上信任的封包每個比原本的 ct mark 做法少 5–6 µs（`tests/ebpf/README.md`）。

## 用法

```sh
cargo build --release
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  cargo build --release --target aarch64-unknown-linux-musl
```

編譯時 `build.rs` 會先用 nightly 編 `gw-ebpf/`（在 kernel 裡跑的 eBPF 程式），把 ELF 嵌進 wnc-gw；wnc-gw 本身用 stable。所以編譯的機器要多裝兩樣（Pi 上不用）：

```sh
rustup toolchain install nightly-2026-11-13 --profile minimal --component rust-src
# bpf-linker：從 https://github.com/aya-rs/bpf-linker/releases 下載 0.13.0 的 x86_64-unknown-linux-musl 版，放進 PATH
# （不要 cargo install：要綁特定版本的 LLVM）
```

eBPF 程式同一個 ELF 在 x86 和 arm64 都能用（只分 endian），授權是 `Dual MIT/GPL`（`gw-ebpf/Cargo.toml`）。nightly 的日期寫在 `build.rs` 的 `EBPF_TOOLCHAIN`，換日期要重新驗證。

| 子命令 | 做什麼 |
|---|---|
| `wnc-gw doctor` | 檢查設定、port、每個 port 的 TCX 程式、kernel 模組、nft、Suricata 和權限，不改任何東西 |
| `wnc-gw run` | 先跑 doctor，再裝 nft table、啟動並監督 Suricata，直到收到 SIGINT／SIGTERM／SIGHUP；結束時移除 table |
| `wnc-gw trust add／del／list` | 手動信任或取消信任一條連線，或列出信任中的連線和每個方向的封包數、bytes：透過 `/run/wnc-gw/control.sock` 請 `run` 寫 trust map，所以 `run` 要在跑、要用 root；只能信任 gateway 轉送的 TCP、UDP 連線 |
| `wnc-gw show interfaces` | 列出網卡，方便在設定檔裡指定 port |
| `wnc-gw explain [代碼]`、`explain --all` | doctor 的每個 error／warning／note 都有代碼（例如 `warning[R006]`），`run` 的每個 WARN／ERROR log 也有（`code=S015`，json 是 `"code":"S015"`）；不帶參數列出全部代碼，帶代碼印出說明（cause：什麼情況會出現；action：怎麼處理），`--all` 印出全部的詳細說明 |

全域選項：`--log-format text|json`、`--log-level error|warn|info|debug|trace`（預設 info；每一筆 alert 的細節要 `debug` 才印）。

設定檔預設在 `/etc/wnc-gw/setting.toml`，每個欄位的說明見 `setting.example.toml`。只在某些選項下才有作用的欄位，在其他情況下設了會直接報錯（C004）：`[suricata] queue` 只能配 `protection = "ips"`、`group` 只能配 `"ids"`，`[trust]` 的其他欄位只能配 `auto = true`。

**看核心 eBPF 程式**：`run` 啟動時記 `core ebpf program attached first on tcx ingress prog_id=… interfaces="…"`，結束時記 `core ebpf program detached packets=…`（兩個 port 收到的封包數合計，GRO 合併後的 skb 算一個）。執行中用 root 看（Pi 的 bpftool 在 `/usr/sbin`）：

```sh
bpftool net show                     # 每個 port 的 tcx/ingress 上有 wnc_gw_ingress，排在第一個
bpftool prog show name wnc_gw_ingress   # map_ids 是計數 map 的 id
bpftool map dump id <map_id>         # 每個 CPU 各一個計數（little-endian u64）
```

程式不 pin：wnc-gw 結束（包括被 `kill -9`）時 kernel 會自動卸下，封包回到原本的路徑。掛不上（沒有 `CAP_BPF`、kernel 沒有 TCX 等）時記 ERROR D001，`run` 照常執行，檢查和信任不受影響。

**別的 eBPF 程式（揭露，不阻擋）**：kernel 沒辦法鎖住「排第一」，之後有人用 `BPF_F_BEFORE` 掛的程式就會排到前面，所以 wnc-gw 只負責讓管理者看得到：

| 情況 | doctor | run（每 10 秒查一次，只在狀態改變時記） |
|---|---|---|
| port 上有不是 wnc-gw 的 TCX 程式 | 表格列出 id（root 執行時加上名稱），warning D006 | — |
| 有程式排在 wnc-gw 的程式前面 | warning D002 | WARN D002（`before="…"`），恢復時 INFO |
| wnc-gw 的程式不見了（USB 網卡拔掉、被 `bpftool link detach`） | — | WARN D003；不會自動重新掛上 |
| 沒有 `CAP_NET_ADMIN`（一般帳號跑 doctor） | `not checked`，warning D004 | — |
| kernel 沒有 TCX（6.6 以前） | warning D005 | 掛不上，D001 |

查詢用 `bpf(BPF_PROG_QUERY)`，只要 `CAP_NET_ADMIN`；名稱要 `CAP_SYS_ADMIN`，沒有時只顯示 id，也分不出哪個是 wnc-gw 的。都是 warning：核心程式現在還不影響轉送，等 fast path 上線再改一部分成 error。

## 架構圖

圖和表裡的標記：

| 標記 | 意思 |
|---|---|
| 〔已實作〕（綠色） | 已決定，程式裡已經有了 |
| 〔已決定，未實作〕（黃色虛線框） | 已決定，還沒寫程式 |
| 〔待決〕（灰色虛線框） | 還沒決定；有的是建議或實驗結果 |
| 〔預設〕 | 有多種選擇時，沒設定就用這個 |

決策的完整紀錄和量測在 `.claude/skills/gateway-architecture/references/decisions.md`（表裡的 O4、O14 等編號就是那份文件的章節）。

### 1. 封包怎麼走

```mermaid
flowchart TD
    IN["封包從 LAN 或 WAN 的 port 進來"]
    HOOK["TCX ingress：核心 eBPF 程式排第一（不受 xdp 設定影響，一律 TC）<br/>解析 header，用五元組查 trust map"]:::done
    FP{"已信任？<br/>（unicast、不是分片、TCP 沒有 SYN／FIN／RST）<br/>純 SYN：先刪掉這組五元組的信任"}
    REDIR["fast path：直接送到另一個 port<br/>bridge：bpf_redirect<br/>routed：減 TTL → bpf_redirect_neigh<br/>不進 bridge／routing、netfilter、Suricata"]:::done
    MODE{"mode"}
    BR["bridge 〔預設〕<br/>bridge 由 OS 建立，wnc-gw 只檢查<br/>經過 br_netfilter 進 netfilter"]:::done
    RT["routed"]:::done
    FWD["netfilter forward hook<br/>table inet wnc_gw → chain forward"]:::done
    RF["連線第一次經過時設 forwarded 位元（0x40000000）<br/>自動信任只看有這個位元的連線"]:::done
    IDSC["chain ids"]:::done
    READY{"Suricata 已就緒？<br/>（收到 READY=1）"}
    UNAV{"when_unavailable"}
    ACC["不檢查，直接放行"]:::done
    DROP["丟掉"]:::done
    PROT{"protection"}
    IDS["ids：NFLOG 送一份複本，封包立刻轉送<br/>1 個 group：log group 10<br/>多個 group：symhash vmap 分到 ids_g10、ids_g11…"]:::done
    IPS["ips：NFQUEUE，封包等 Suricata 判決<br/>1 個 queue：queue to 0<br/>多個 queue：queue to symhash mod N<br/>when_unavailable = accept 時加 bypass"]:::done
    SUR["Suricata 8（由 wnc-gw 啟動）<br/>runmode=workers：每個 queue／group 一個 worker 執行緒"]:::done
    OUT["從另一個 port 送出"]
    VDROP["丟掉"]

    IN --> HOOK --> FP
    FP -->|是| REDIR --> OUT
    FP -->|"否（包括 TCP 的控制封包：一律檢查）"| MODE
    MODE -->|"bridge〔預設〕"| BR --> FWD
    MODE -->|routed| RT --> FWD
    FWD --> RF --> IDSC
    IDSC --> READY
    READY -->|否| UNAV
    UNAV -->|"accept〔預設〕"| ACC --> OUT
    UNAV -->|drop| DROP
    READY -->|是| PROT
    PROT -->|"ids〔預設〕"| IDS
    PROT -->|ips| IPS
    IDS --> OUT
    IDS -.->|複本| SUR
    IPS --> SUR
    SUR -->|"判決 accept"| OUT
    SUR -->|"判決 drop（規則的 action 是 drop）"| VDROP

    classDef done fill:#d4edda,stroke:#2e7d32,color:#000
    classDef later fill:#fff3cd,stroke:#b8860b,color:#000,stroke-dasharray: 5 5
```

裝到 kernel 裡的 table（`sudo nft list table inet wnc_gw` 的格式，counter 的數字省略）：

```
table inet wnc_gw {
	chain forward {
		type filter hook forward priority filter; policy accept;
		counter
		ct mark & 0x40000000 == 0x00000000 ct mark set ct mark | 0x40000000
		jump ids
	}
	chain ids {
		# Suricata 沒就緒：      counter accept           （when_unavailable = "accept"）
		#                        counter drop             （when_unavailable = "drop"）
		# 就緒、ids、1 個 group： counter log group 10 accept
		# 就緒、ids、多個 group： counter symhash mod 2 vmap { 0 : jump ids_g10, 1 : jump ids_g11 }
		# 就緒、ips、1 個 queue： counter queue flags bypass to 0
		# 就緒、ips、多個 queue： counter queue flags bypass to symhash mod 3
	}
	chain ids_g10 { counter log group 10 accept }   # 只有多個 group 時才有，每個 group 一條 chain
	chain ids_g11 { counter log group 11 accept }
}
```

Suricata 就緒或停止時，wnc-gw 只換掉 `ids` chain 的規則，不重裝整張 table。

### 2. 各個設定分支的差別

圖裡會分岔的設定都在 `setting.toml`。每個分支的實驗、數字和限制見 `DECISIONS.md`（括號裡是章節）。下面的「Pi」數字都是 Pi 4 鎖 1000 MHz 量的。

**`mode`：bridge〔預設〕／routed**（DECISIONS.md §1）

| | bridge〔預設〕 | routed |
|---|---|---|
| 部署 | 插在中間即可，LAN 和 WAN 同一個網段 | LAN 和 WAN 不同網段；不做 NAT，所以上游路由器要加到內網的路由 |
| 怎麼進 nftables | 經過 `br_netfilter`（沒載入時規則完全被繞過） | 一般的 IP 轉送 |
| doctor 檢查 | LAN、WAN 在同一個 bridge；`br_netfilter`、`bridge-nf-call-iptables`／`ip6tables` | LAN、WAN 不在 bridge 裡；`ip_forward`；兩個 port 都有 IPv4 位址（沒有是 warning）、網段不和彼此或其他介面重疊（error）、預設路由走 WAN（warning）；note 寫出內網 gateway 和上游要加的路由 |
| 封包從哪個 port 進來 | `iifname` 都是 `br0`，要靠 ingress 打的 mark〔已決定，未實作〕 | 同樣用 ingress 的 mark，兩種模式共用規則 |
| fast path（tc eBPF） | `bpf_redirect` 到另一個 port | 減 TTL（IPv4 修 checksum）＋`bpf_redirect_neigh`（kernel 自己查限定在出口網卡的路由；不是 GPL-only） |
| 轉送成本（Pi、veth） | 10.7 µs／封包 | 7.9 µs／封包 |
| 轉送成本（Pi、實體網卡，2026-11-04） | 只轉送 @100k：9.97 µs，A0 容量 100 kpps | 8.02 µs，A0 容量 150 kpps；有檢查時只少 2–9%、容量一樣 |
| 非 IP 的封包（ARP 等） | 照常轉送 | 不轉送 |

nft table 兩種模式完全相同，差別只在 `forwarding/` 的環境檢查。

**`protection`：ids〔預設〕／ips**（DECISIONS.md §2）

| | ids〔預設〕 | ips |
|---|---|---|
| 封包要不要等 Suricata | 不用：kernel 立刻轉送，另外用 NFLOG 送一份複本 | 要：封包在 NFQUEUE 等 Suricata 判決 |
| 能不能擋流量 | 不能，只產生 alert | 能，規則的 action 是 drop 就擋 |
| checksum 檢查 | 一定要關（GRO 合併過的複本 checksum 不完整），有 insertion 的風險 | 照常，kernel 會標出 checksum 還沒算的封包 |
| Suricata 跟不上時 | 封包照樣轉送，複本被丟掉；wnc-gw 每 10 秒記一次漏掉幾份 | 看 `when_unavailable` |
| 需要的 kernel 模組 | `nft_log`、`nfnetlink_log` | `nft_queue`、`nfnetlink_queue` |
| Suricata 要支援 | NFLOG | NFQueue |
| Suricata 每個封包的成本（Pi、veth） | 19–24 µs | 35–48 µs |
| 容量（Pi、實體網卡、full 規則） | 一定要開 RPS：不開時轉送只有 30–40 kpps；RPS 到 CPU1–3、3 個 group 時轉送 120、檢查 80 kpps | 1 個 queue 20–30 kpps；最好約 60 kpps（網卡中斷搬到 CPU1＋3 個 queue） |

兩種模式的信任、SYN／FIN／RST 規則都一樣，也都等 Suricata 送出 READY=1 才開始送封包。

**`when_unavailable`：accept〔預設〕／drop**（DECISIONS.md §11）

| 情況 | accept〔預設〕 | drop |
|---|---|---|
| Suricata 啟動中、還沒就緒 | 不檢查，直接放行 | 丟掉 |
| Suricata 結束、重啟中 | 不檢查，直接放行（Suricata 結束那一刻還在 queue 裡的封包會被 kernel 丟掉） | 丟掉 |
| ips：Suricata 跟不上（queue 滿） | 放行（queue 加 `bypass`、`nfq.fail-open=yes`） | 丟掉 |
| ips：Suricata 檢查不了某條 flow（記憶體用完、解析錯誤） | exception policy ignore，照常放行 | drop-flow／drop-packet |
| ids：Suricata 跟不上 | 照樣轉送，只是複本被丟掉 | 一樣照樣轉送（ids 的轉送不經過 Suricata） |
| wnc-gw 停止、table 已移除 | 直接通過 | 直接通過 |

不管哪一種，都會記 log：何時開始沒檢查、沒檢查了多久（`uninspected_ms`）。

**`queue`／`group`：一個〔預設〕或多個**（DECISIONS.md §3、§4）

| | 一個〔預設：queue 0、group 10〕 | 多個（例如 `"0-2"`、`"10-12"`） |
|---|---|---|
| nft 規則 | `queue to 0`／`log group 10` | `queue to symhash mod N`／`symhash mod N vmap` 分到每個 group 一條 chain |
| Suricata 執行緒 | 1 個 worker，只用一顆核心 | 每個 queue／group 一個 worker |
| 怎麼分 | — | symhash：含 port、兩個方向算出同一個值，同一條連線一定在同一個 worker |
| 一條連線佔大部分流量時 | 上限是一個 worker（約 30 kpps） | 一樣只有一個 worker 在忙，要靠信任 |
| 每個封包的成本 | 最低 | 越多越貴（Pi，ids、RPS、50 kpps：worker 從 1 個 group 的 15.6 µs 到 4 個的 29.2 µs） |

預設開幾個還沒決定（DECISIONS.md §20）。

**`xdp`：auto〔預設〕／off／generic**（DECISIONS.md §17）

| | auto〔預設〕 | off | generic |
|---|---|---|---|
| 之後算特徵的 eBPF 程式掛在哪 | 網卡有 native XDP 就掛 XDP，否則掛 TC | 一律 TC | 即使網卡不支援也掛 generic XDP |
| Pi 4 上 | 兩個 port 都是 TC | TC | generic XDP |
| 代價 | — | 特徵在 GRO 合併後才算（大小、到達間隔不準） | 比 TC 慢（省不到建 skb、可能要複製封包），而且整張網卡跳過 GRO；只給測試用 |

2026-11-14 起 XDP 只負責算特徵（看得到 GRO 合併前的原始 frame），轉送和信任一律在 TCX，所以核心 eBPF 程式不受這個設定影響。算特徵的程式還沒實作，目前只有 doctor 會判斷每個 port 會掛在哪（doctor 的 CORE HOOK 欄位到時候改名）。

**讀 alert：每 `eve_interval` 秒讀一次**（DECISIONS.md §19；不是分支，只有間隔可以設）

wnc-gw 從 suricata.yaml 設定的 eve-log 檔讀 alert，每 `eve_interval` 秒（預設 0.5，0.05–10，可以有小數）看一次檔案長度，只讀上次之後新增的部分；檔案被換掉或截斷時，先讀完舊檔再從頭讀新檔。Pi 上：沒有 alert 時 0.37 ms／秒，每筆 alert 16 µs，延遲 0 到一個間隔。原本另有 inotify（有寫入才醒），Pi 量測每筆 alert 51 µs、只在 alert 稀疏時延遲較低，2026-11-04 刪掉。

**`[trust] auto`：false〔預設，只能手動信任〕／true**（DECISIONS.md §19）

| | false〔預設〕 | true |
|---|---|---|
| 誰信任連線 | 只有管理者用 `wnc-gw trust add` | wnc-gw 自己判斷，`wnc-gw trust add` 也照樣能用 |
| 什麼時候信任 | — | Suricata 在檢查的期間，這條連線兩個方向都已經有 `min_packets`（預設 10）個封包、觀察滿 `min_age`（預設 5）秒、沒有任何 alert；只限 TCP（已建立）和 UDP |
| 信任多久 | 到 `trust del`、同一組五元組的新 TCP 連線（純 SYN）或 run 停止；連線結束不會自己清掉（閒置清除還沒做） | `ttl`（預設 900）秒，之後回到檢查，再觀察一次才會再信任 |
| 有 alert 時 | — | 還在觀察的：之後都不信任；已經信任的：立刻撤銷，記 WARN |
| 需要 | 核心 eBPF 程式有掛上（D001） | 同左（掛不上時自動信任關閉、全部檢查，T014）；`net.netfilter.nf_conntrack_acct = 1`、Suricata 把 alert 寫進 eve 檔；doctor 確定沒有就報 error（T002），讀不到 Suricata 設定而無法確認時是 warning，run 照常啟動但關掉自動信任、全部送檢查（T012）；執行中 EVE 讀不到或落後時暫停新增信任（T013） |
| 風險 | — | 信任之後才送的攻擊，到 TTL 結束前都看不到；doctor 一律給 warning |
| log | `trust add／del` 各一行 | 每次信任一行 INFO、撤銷一行 WARN、到期是 DEBUG；有變動時每 60 秒一行摘要 |
| 成本（Pi） | — | 每次讀 conntrack 固定約 7 ms＋每條經過 gateway 的連線 9.4 µs，讀的期間事件迴圈停住；4,000 封包／秒的 8 條長連線時，Suricata 加 wnc-gw 每秒省 85 ms（每個封包 21 µs） |

- `ttl` 的預設 900 秒比 Suricata 的 `flow-timeouts.tcp.established`（600 秒）長：信任結束時 Suricata 已經忘了這條連線，會當成從中間開始的連線接手，不會因為序號過時把封包丟掉（O21）。ips 模式下 `ttl` 不夠長時 doctor 會警告。
- ids 模式下，低流量連線的 payload alert 可能比 `min_age` 晚到（Docker 實測：帶攻擊標記的連線先被信任，連線結束時才因 alert 撤銷；ips 模式下同樣的連線一開始就不被信任）。DECISIONS.md §19 有細節，怎麼處理還沒決定。

### 3. 誰控制什麼

```mermaid
flowchart LR
    ADMIN["管理者"]
    subgraph RUN["wnc-gw run（同一台機器只能跑一個）"]
        SUP["Suricata 監督<br/>NOTIFY_SOCKET 收 READY=1<br/>結束時退避 1→60 秒後重啟"]
        FW["firewall<br/>table 骨架寫死在程式裡"]
        CTL["control.sock（0600，SO_PEERCRED 只收 root 或 run 的帳號）<br/>trust add 先確認連線存在、而且是轉送的"]
        CORE["核心 eBPF 程式（TCX 第一位）<br/>trust map、port 對應<br/>每 10 秒確認還在第一位（D002、D003）"]
        MON["監控<br/>conntrack 表快滿、因表滿丟包<br/>ids：NFLOG 漏掉的複本（每 10 秒）"]
        ALR["讀 alert<br/>eve.json 每 0.5 秒讀新增的部分<br/>每筆 DEBUG、每 60 秒一行 INFO 摘要"]
    end
    CLI["wnc-gw doctor／show／trust"]
    NFT["/usr/sbin/nft<br/>（nft JSON）"]
    CT["ctnetlink<br/>（手寫，kernel/conntrack.rs）"]
    K["kernel<br/>table inet wnc_gw、conntrack"]
    SUR["Suricata 8<br/>--set 強制 runmode=workers、midstream 等"]
    LOG["stderr（tracing，可選 --log-format json）<br/>Suricata 的輸出也收進來"]
    AGT["自動信任（[trust] auto，3d）<br/>每 check_interval 讀有 forwarded 位元的連線和計數<br/>封包夠多、夠久、沒 alert → 信任；TTL 到期 → 回到檢查；alert → 撤銷"]
    PRIVD["Privd（trait）<br/>現在是同一個 process 的 LocalPrivd"]
    LOOP["之後：edge AI／雲端 → trust／block／observe"]:::later

    ADMIN --> CLI
    ADMIN --> RUN
    CLI -->|"trust add／del／list"| CTL --> PRIVD
    SUP -->|spawn| SUR
    SUR -->|"READY=1"| SUP
    SUP -->|"就緒後才換上 queue／log 規則"| FW
    FW --> NFT --> K
    MON -->|讀計數| K
    RUN --> LOG
    SUR -->|"eve.json"| ALR
    ALR -->|alert| AGT
    AGT -->|"讀連線、寫信任"| PRIVD
    PRIVD -->|"讀連線（ctnetlink）"| CT --> K
    PRIVD -->|"寫、刪 trust map"| CORE
    LOOP -.-> AGT

    classDef later fill:#fff3cd,stroke:#b8860b,color:#000,stroke-dasharray: 5 5
```

### 4. 決策一覽

每一項的實驗、數字和限制見 `DECISIONS.md`。

**封包路徑**

| 項目 | 用什麼 | 其他選項 | 狀態 | 為什麼（出處） |
|---|---|---|---|---|
| 轉送模式 `mode` | bridge〔預設〕，bridge 由 OS 建立，經過 `br_netfilter` | routed | 〔已實作〕 | 透明部署；Pi 的 kernel 沒有 `nf_conntrack_bridge`（D3，2026-10-24） |
| 檢查模式 `protection` | ids〔預設〕用 **NFLOG** 送複本 | ips 用 **NFQUEUE**，封包等判決 | 〔已實作〕 | NFLOG 不讓轉送等 Suricata，Pi 上整台每個封包省 4–25 µs；ids 要關 checksum 檢查（GRO），doctor 會警告（O18，2026-10-29） |
| 多核分流 | kernel 的 **symhash**（ips：`queue to symhash mod N`；ids：`symhash vmap`） | `queue num 0-N`（只看位址）、Suricata 的 autofp | 〔已實作〕 | 位址 hash 讓同一對 IP 的連線擠在同一個 queue（42-1：12.9 對 26.4 kpps）；symhash 含 port、雙向一致，每個封包只多 0.7–1.8 µs（O14，2026-10-27） |
| Suricata runmode | 強制 **workers**（`--set runmode=workers`） | autofp | 〔已實作〕 | autofp 要在執行緒之間交接，Pi 上整台每個封包多 15–35 µs（O18，2026-10-30） |
| 信任 | **核心 eBPF 程式的 trust map**（五元組，每個方向一筆，32,768 筆），信任的封包在 TC 直接轉送 | ct mark（10-28～11-14 的做法）、map＋ct mark | 〔已實作〕（`wnc-gw trust` 手動，或 `[trust] auto`） | TC 讀不到 ct mark；Pi 實體網卡上信任的封包比 ct mark 少 5–6 µs、容量 80 → 150 kpps，寫一筆 2.8 對 14.5 µs。程式掛不上時沒有信任（全部檢查）；沒有 conntrack 的 TCP 序號窗檢查，是 RQ3 第 4 項的實驗條件（O17，2026-11-14） |
| 控制封包（L2） | TCP 的 SYN／FIN／RST 在 TC 一律交回 kernel，所以一定進 Suricata；純 SYN 先刪掉同一組五元組的信任 | 不送 | 〔已實作〕 | 長連線只多約 1 µs（O17，2026-10-28）；port 重用時新連線不沿用舊的信任 |
| 讀 conntrack | **手寫 ctnetlink**（`kernel/conntrack.rs`）：自動信任讀連線和計數、`trust add` 確認連線 | `netlink-packet-netfilter` crate、spawn `conntrack` | 〔已實作〕 | Pi 上讀一筆：手寫 20 µs、crate 74 µs（O17，2026-10-28） |
| 操作 nftables | **nft JSON**，spawn `/usr/sbin/nft` | libnftnl、rustables | 〔已實作〕 | 不連結 GPL 的函式庫；每次約 7.7 ms，所以要批次（O4，2026-10-25） |
| 我們的 table | 骨架寫死在程式，使用者只能管 set 的內容 | 使用者寫 nft 規則 | 〔已實作〕（set 還沒有） | 流程由程式決定，避免設定錯讓程式出錯（O11，2026-10-25） |
| 自動信任（3d） | 讀 conntrack 計數（有 forwarded 位元 `0x40000000` 的連線）和 Suricata 的 alert，判斷後經 `Privd` 寫 trust map；預設關 | EVE 的 flow 事件、雲端判定 | 〔已實作〕（門檻和 TTL 的預設值是建議值，待確認） | EVE flow 要等連線結束才有；forwarded 位元讓 gateway 自己的連線不被算進來（O22，2026-11-04） |
| 方向判斷 | netdev ingress 打 mark，不用 `iifname` | `iifname` | 〔已決定，未實作〕 | bridge 模式下 forward chain 看到的 `iifname` 是 `br0`，分不出從哪個 port 進來；ingress 打的 mark 帶得到 forward chain（D3，2026-10-24） |
| 核心 eBPF 掛點 `xdp` | auto〔預設〕：native XDP 才掛 XDP，否則 TC | off、generic | 〔已決定，未實作〕（doctor 已會判斷） | generic XDP 比 TC 慢，不自動選（2026-10-24） |
| Fast path | tc eBPF 轉送已信任的 flow | XDP、flowtable | 〔已決定，未實作〕 | 2026-10-20；flowtable 當後端（O5）待決 |

**Suricata 怎麼管**

| 項目 | 用什麼 | 其他選項 | 狀態 | 為什麼（出處） |
|---|---|---|---|---|
| 誰啟動 Suricata | **wnc-gw 自己 spawn** | systemd 管理（之後也要支援） | 〔已實作〕 | 兩種實作同一個生命週期介面（O14，2026-10-26） |
| 什麼時候開始送封包 | 收到 **READY=1** 才換上 queue／log 規則 | 先裝規則 | 〔已實作〕 | Suricata 7.0.10、8.0.7 在初始化時收到封包會 segfault |
| Suricata 沒在檢查時 `when_unavailable` | accept〔預設〕（ips 時加 bypass、`nfq.fail-open=yes`） | drop | 〔已實作〕 | 預設不斷網，但一定記 log：何時沒檢查、沒檢查多久（O14，2026-10-26） |
| exception policy | ips 跟著 `when_unavailable`（accept → ignore，drop → drop-flow／drop-packet）；ids 一律 ignore（拿到的是複本，丟了也擋不到） | 照 suricata.yaml | 〔已實作〕 | Debian 預設的 `auto` 在 IPS 模式等於 drop-flow（O16，2026-10-28） |
| 從中間開始的連線 | `stream.midstream=true`、midstream policy ignore | 丟掉 | 〔已實作〕 | Suricata 重啟、信任後稽核時不能把連線丟掉（O16，2026-10-27） |
| 規則載入失敗 | `engine.init-failure-fatal=no`，失敗的條數記 WARN | 整個 Suricata 不啟動 | 〔已實作〕 | 一條壞規則不該讓整個網路失去檢查（O16，2026-10-28） |
| 停止時 | 換回沒檢查的狀態 → 停 Suricata → 移除 table；SIGHUP 也一樣 | 留著 table | 〔已實作〕 | wnc-gw 沒在跑時流量直接通過（O14，2026-10-28、10-29） |
| Suricata 版本 | 8.0.7；最低 8.0，低於時 doctor 報 error | — | 〔已決定，未實作〕（版本檢查） | 7.0 已 EOL（2026-10-30） |
| alert 怎麼到 wnc-gw | 讀 suricata.yaml 設定的 **eve-log 檔**，只讀新增的部分；每 `eve_interval` 秒（預設 0.5）讀一次 | unix_stream、wnc-gw 強制 Suricata 另外輸出、inotify | 〔已實作〕 | unix_stream 在 live 模式讀取端跟不上時默默丟事件、沒有計數；inotify 在 Pi 上每筆 alert 51 µs（poll 16 µs）（O22，2026-11-04） |
| log | stderr，用 tracing；`--log-format json`、`--log-level`。只放重要資訊和出事時能定位的資訊：alert 細節是 DEBUG、每 60 秒一行摘要，講到連線的都帶五元組和 `flow_id` | 自己寫檔 | 〔已實作〕；Debian 的 systemd `LogNamespace` 〔已決定，未實作〕 | O15，2026-10-26；O22，2026-11-04 |

**還沒決定的**

| 項目 | 現況 |
|---|---|
| 自動信任的預設值 | 〔待決〕目前是建議值：預設關、10 個封包、5 秒、TTL 900 秒、每 5 秒檢查一次（O22） |
| ids 模式下 alert 比 `min_age` 晚到 | 〔待決〕Docker 實測發現；可能的做法：ids 時要求送往 server 的資料超過 Suricata 的重組 chunk、調小 chunk、或加大 `min_age`（DECISIONS.md §19） |
| log 保存多少 | 〔待決〕wnc-gw 自己的 log 要等 systemd unit（journald 的大小上限）；Suricata 的 eve.json、fast.log、stats.log 目前沒有上限（O22） |
| 預設開幾個 queue／group、網卡中斷和 RPS 怎麼放 | 〔待決〕2026-11-03 Pi 實驗：ids 用 RPS（CPU1–3）＋3 個 group，轉送 120、檢查 80 kpps；ips 用 IRQ 搬到 CPU1＋3 個 queue，60 kpps；ips 只開 1 個 queue 只有 20–30 kpps（`tests/cpu_alloc/README.md`） |
| Suricata 要不要輸出 EVE flow 事件 | 〔待決〕3d 的觀察已改用 conntrack 計數（O22），但 Debian 預設的 eve.json 仍輸出 flow；Pi 上離線時每個 flow 事件約 100 µs，live 模式還沒量（`tests/eve_output/README.md`） |
| edge AI 的介面與 CPU 分配 | 〔待決〕O19：跑在同一台機器、無特權、只能回 trust／block／observe 是建議 |
| 已信任 flow 的部分檢查、稽核前要不要讓 Suricata 忘掉 flow | 〔待決〕O20、O21 |
| 拆成 privd／agent 等多個 process | 〔待決〕O1；目前是單一 process，模組照之後的邊界切 |

## 程式結構

| 目錄／檔案 | 內容 |
|---|---|
| `src/cli/` | 子命令（doctor、run、trust、show、explain）和 log 初始化 |
| `src/issue.rs` | doctor 結果和 `run` 的 WARN／ERROR log 的代碼（`Issue`），以及 `explain` 印的說明 |
| `src/config.rs` | 讀設定檔，CLI 參數可以蓋過 |
| `src/ports.rs` | 依名稱或 MAC 找出 LAN、WAN 是哪張網卡 |
| `src/forwarding/` | bridge、routed 兩種模式各自的環境檢查（trait） |
| `gw-ebpf/`、`build.rs` | 在 kernel 裡跑的 eBPF 程式（`no_std`，用 nightly 編）；`build.rs` 編好後由 `src/datapath/ingress.rs` 嵌進 wnc-gw |
| `src/datapath/` | 核心 eBPF 程式：掛在哪（`hook.rs`：xdp 設定的判斷）、載入並掛到兩個 port 的 TCX ingress 第一位（`ingress.rs`） |
| `src/firewall.rs` | 我們的 nft table、信任與取消信任 |
| `src/agent/` | 3d：自動信任的狀態機（`trust.rs`）和 `Privd` trait（之後拆出有權限的 process 時，換成跨 process 的實作） |
| `src/protection.rs`、`src/ids/` | ids／ips、啟動和監督 Suricata、讀 Suricata 的資訊和 EVE 檔裡的 alert |
| `src/kernel/` | 和 kernel 溝通：nft、ctnetlink、NFLOG／NFQUEUE、eBPF（`bpf.rs`，包住 aya）、模組、sysctl、netlink |
| `gw-common/` | kernel 和 user space 共用的 trust map key、value（`#[repr(C)]`） |
| `src/control.rs` | `wnc-gw trust` 和 `run` 之間的 unix socket：一行 JSON 的請求和回應 |
| `src/monitor/` | 執行中的監控（conntrack 表、NFLOG 漏掉的複本、Suricata 的 alert 摘要） |
| `src/platform/` | 依 OS 而不同的部分（目前只有 Debian） |
| `tests/unit/` | 單元測試，路徑對應 `src/` |
