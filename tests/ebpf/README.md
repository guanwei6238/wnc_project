# 核心 eBPF 程式的驗證

`core_pi.sh`：在 Pi 上用三個 netns 驗證核心 eBPF 程式（步驟 A1），不碰 eth0、eth1。

```
ecli(c0 10.8.0.1) --veth-- lan0 [egw: br0] wan0 --veth-- s0(esrv 10.8.0.2)
```

wnc-gw 的 port 是 `lan0`、`wan0`，ping 一定經過這兩個 port 的 TC ingress。

```sh
scp target/aarch64-unknown-linux-musl/debug/wnc-gw wnc@10.254.254.2:/tmp/wncgw/wnc-gw
scp tests/ebpf/core_pi.sh tests/ebpf/foreign_tcx.py wnc@10.254.254.2:/tmp/wncgw/
sudo bash core_pi.sh up      # 建 netns
sudo bash core_pi.sh run     # run → ping 5 次 → SIGINT，印出 attach／detach 的 log
sudo bash core_pi.sh show    # run 中印 bpftool net show 和每個 CPU 的計數
sudo bash core_pi.sh tcx     # 別的 TCX 程式：doctor（root、wnc）、run 中被插隊、被拆掉
sudo bash core_pi.sh fastpath  # 步驟 C：IPv4 TCP、UDP、IPv6 TCP 手動信任，看 forward chain、TTL、trust list
sudo bash core_pi.sh auto      # 步驟 C：自動信任
# ROUTED=1（up、down 和其他子命令都要帶）：routed 的拓樸，ecli 10.9.1.2／fd09:1::2、esrv 10.9.2.2／fd09:2::2
sudo bash core_pi.sh kill9   # kill -9 之後程式是否自動卸下
sudo bash core_pi.sh down
```

## 結果（2026-11-14，Pi 4、6.18.50+rpt-rpi-v8、沒有 /sys/kernel/btf）

| 案例 | 結果 |
|---|---|
| run | `core ebpf program attached first on tcx ingress interfaces="lan0,wan0"`，結束時 `detached packets=10`（5 個請求從 lan0、5 個回應從 wan0），exit 0 |
| show | 兩個 port 的 `tcx/ingress` 都是 `wnc_gw_ingress`、同一個 prog_id；ping 3 次後 CPU 0 的計數是 6，其他 CPU 是 0 |
| kill9 | `kill -9` 前 lan0 有 1 個 TCX 程式，之後 0 個；nft table 留下（和之前一樣，腳本會刪掉） |
| BTF | Pi 沒有 vmlinux BTF，ELF 自己帶的 BTF 照常載入（`bpftool prog show` 有 `btf_id`） |
| tcx（A2） | run 之前掛的 `before_run`：root 的 doctor 是 `55 (before_run)`、D006；wnc 帳號 `not checked`、D004。run 掛上後順序是 `wnc_gw_ingress`、`before_run`。run 中掛 `first` 的 `jumper`：WARN D002 `before="58"` → 拿掉後 INFO「first again」→ `bpftool link detach` 我們的 link 後 WARN D003 |

`foreign_tcx.py <介面> first|last [名稱]`：用 bpf syscall 載入一支只回傳 TCX_NEXT 的程式、掛在 TCX ingress 的最前或最後，收到 SIGINT／SIGTERM 才拿掉；用來模擬別人的程式（需要 CAP_BPF、CAP_NET_ADMIN）。

# 步驟 A3：掛一支 TCX 程式要多少 CPU

`bench/`（獨立的小 workspace，不是 wnc-gw）：`bench-ebpf` 有三支程式，`ebpf-bench <v1|v2|v3> [--flow …] <介面>…` 把其中一支掛到每個介面的 TCX ingress 第一位，收到 SIGINT 後印 `packets=… hits=…`。

| 版本 | 內容 |
|---|---|
| V0 | 沒有程式 |
| V1 | 空程式，回傳 TCX_NEXT |
| V2 | V1＋per-CPU 計數（= wnc-gw 現在的程式） |
| V3 | V2＋解析 Ethernet／IPv4／IPv6／TCP／UDP，用五元組（40 bytes）查一次 65,536 筆的 hash map（是空的，一定查不到） |

`cost_pi.sh cpu|stats`：`tests/ids_inline/env.sh` 的 veth 拓樸（wtest 的 tcpreplay 從兩端送進 wgw 的 br0，port 是 g-lan、g-wan），沒有 nft、沒有 Suricata。`cpu` 量整台 Pi 的 CPU（`/proc/schedstat` rq_cpu_time ÷ 送出的封包，`tcpreplay -T nano` 綁 CPU 1），`stats` 開 `kernel.bpf_stats_enabled` 讀每支程式的 run_time_ns ÷ run_cnt。每輪版本順序打亂。`summarize.py cost.kvl` 彙整。

```sh
cd bench && CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld cargo build --release --target aarch64-unknown-linux-musl
scp target/aarch64-unknown-linux-musl/release/ebpf-bench ../cost_pi.sh wnc@10.254.254.2:/home/wnc/ebpf/
# Pi：pi_lab_mode.sh up 1000、systemctl stop suricata 之後
sudo bash cost_pi.sh cpu; sudo bash cost_pi.sh stats
```

功能檢查（筆電的臨時容器，只有 CAP_NET_ADMIN、CAP_BPF）：V3 預先放一組 UDP 五元組，IPv4 送 100＋30 個（其他 port）＋20 個 IPv6 → `hits=100`；IPv6 的五元組 → `hits=40`；帶 IP option 的 IPv4（走 `bpf_skb_load_bytes`）→ `hits=15`。

## 結果（2026-11-14，Pi 4 Model B 4 GB、鎖 1000 MHz、6.18.50+rpt-rpi-v8；C17_Benign 20 萬個封包、平均 475 bytes、10 kpps；全部 throttled 0x0）

整台 Pi（cpu，5 輪；同一輪裡和 V0 相減）：

| | V0 | V1 − V0 | V2 − V0 | V3 − V0 |
|---|---|---|---|---|
| µs／封包 | 32.7–34.8 | **+0.52（標準差 0.07）** | +1.25（1.31） | +1.05（0.69） |

程式本身（stats，3 輪）：

| | V1 | V2 | V3 |
|---|---|---|---|
| ns／次 | 104（2.4） | 151（12.6） | 600（33） |
| 和前一個版本的差 | — | +47 | +449 |

怎麼讀：
- **進 TCX 本身約 0.5 µs／封包**（V1 − V0，5 輪都在 0.44–0.63），是這次唯一能用整台 CPU 量準的差。
- V2、V3 多出來的部分小於整台 CPU 的誤差（輪與輪之間差 1 µs 以上），要看 bpf_stats：計數 +47 ns、解析＋查表 +449 ns。V1 的 104 ns 大多是 bpf_stats 自己的成本（每次執行前後各讀一次時間），所以只看版本之間的差。
- 加起來 V3 ≈ 0.52 + 0.05 + 0.45 ≈ **1.0 µs／封包**，和整台 CPU 的 V3 − V0（+1.05）一致。現在 wnc-gw 的程式（V2）≈ 0.57 µs。
- 這個 1 µs 是每個封包都要付的。對照：信任的封包約 14 µs、全部檢查 55–61 µs（`tests/cpu_alloc/README.md`，實體網卡、ips），信任每個封包省 39–67 µs（DECISIONS.md §5）。fast path 要讓信任的封包省下的比 1 µs 多很多才划算；沒被信任的封包多 1 µs（約 2%）。
- 查表的 449 ns 是空 map、40 bytes 的 key；map 有資料時 cache 的行為會不同，C 要再量。
- **沒有解釋的**：V0 從第一輪的 32.7 慢慢升到第五輪的 34.8 µs（約 8 分鐘內 +2 µs），時脈、throttled 都沒變；用同一輪相減抵掉。33 µs 也包含 tcpreplay 自己送封包的 CPU，不是 gateway 單獨的轉送成本。

原始資料：筆電 `~/datasets/throughput/ebpf/cost.kvl`、`run.log`（和 Pi 上的 sha256 核對過）。

## 寫 eBPF 時發現的 verifier 限制（沒有 CAP_PERFMON 時）

筆電容器只給 CAP_NET_ADMIN、CAP_BPF，和之後的 privd 一樣沒有 CAP_PERFMON（架構 §3）。這時 verifier 不允許某些指標運算，Rust 寫起來很自然的兩種寫法會被拒絕（Pi 用 root 有全部權限，不會發現）：
- **先把 struct 清成 0 再填欄位**：被編成逐 byte 的 memset 迴圈（`R5 tried to add from different maps, paths or scalars`）。改成每個欄位先讀出來，最後一次組成 struct；連 `[u8; 3]` 的 pad 也會變 memset，key 裡不要放 byte 陣列。
- **變數 offset 讀封包**（IPv4 的 header 長度）：編譯器產生 `scalar += pkt`（`pointer arithmetic with it prohibited for !root`）。常見的位置（沒有 option 的 IPv4 在 34、IPv6 在 54）用固定 offset 直接讀，其他用 `bpf_skb_load_bytes`（`ctx.load()`）。

# 步驟 C 之前的實驗：TC fast path 對 ct mark 信任（E1、E2）

問題：信任的封包在 TC 就 redirect 到另一個 port（跳過 bridge、netfilter、conntrack），比現在用 ct mark 在 netfilter 放行省多少？trust 只放在 TC 的 map（不用 ct mark）和 map＋ct mark，寫入的成本差多少？

`bench` 的 V4（`v4_redirect`）：V3 的解析之外，目的 MAC 不是 unicast、IPv4 分片、TCP 的 SYN／FIN／RST 交回 netfilter（純 SYN 先刪掉兩個方向的信任）；用五元組查 `TRUST`（每個方向一筆，值是封包數、bytes、最後時間），查到就更新計數並 `bpf_redirect` 到 `PEER` 裡的另一個 port。`ebpf-bench v4 --flows <檔> <port A> <port B>` 把檔裡的五元組兩個方向都放進去；`flows.py <pcap>` 從 pcap 產生這個檔。

功能檢查（筆電臨時容器，只有 CAP_NET_ADMIN、CAP_BPF）：va→vb 的 100 個信任 UDP 全部從 vd 送出（vc 收到 100），其他 port 的 30 個 0；`connect()` 送出的純 SYN 讓 map 從 4 筆變 2 筆。

## E1：每個信任封包（2026-11-14，方案 B 的實體網卡，`tests/cpu_alloc/alloc_run.sh exp9`，2 輪）

Pi 4、鎖 1000 MHz、eth0 PAUSE 關、bridge；S_m60（102 條 flow，最大的一條 UDP 佔 98%），每個速率點至少 5 秒。

| 工作負載 | 內容 |
|---|---|
| B0 | 只有 bridge（沒有 wnc-gw） |
| B2 | wnc-gw ips、full、1 queue，prerouting 把每條連線設成信任（ct mark）＝現在的信任 |
| F2 | B2 再加 TC fast path（V4，信任 S_m60 的全部五元組；98.6–98.9% 的封包在 TC 就 redirect，其餘是 TCP 控制封包等） |

容量（cap_loss ≤ 0.1% 的最高速率，kpps；兩輪相同）：

| 放置 | B0 只有 bridge | B2 ct mark 信任 | F2 TC fast path |
|---|---|---|---|
| A0（中斷都在 CPU0） | 80 | 50 | 50 |
| I1（IRQ 29 → CPU1） | 120 | 80 | **150** |

同一個速率的每封包 CPU（µs，整台 Pi＝經過時間 − idle；A0 另列 CPU0；兩輪平均）：

| 速率 | B0 | B2 | F2 | F2 − B2 |
|---|---|---|---|---|
| A0 50k（CPU0） | 9.78 | 12.68 | **6.82** | −5.9（−46%） |
| I1 80k（整台） | 10.12 | 13.96 | **8.53** | −5.4（−39%） |
| I1 120k（整台） | 9.26 | 丟 20% | 7.53 | — |

怎麼讀：
- 信任的封包走 TC fast path 比走 netfilter＋ct mark 每個少 5–6 µs，也比完全不裝 wnc-gw 的 bridge 便宜 1.6–3 µs（跳過了 bridge 和 br_netfilter）。I1 的容量從 80 到 150 kpps（+87%）。
- 低速率時「整台」的數字比較高（50k 時 B0 是 14 µs、80k 是 10 µs），是每秒固定的背景（ssh 讀計數等）攤到比較少的封包，所以只比同一個速率。
- **A0 沒有解釋的**：三種在 80 kpps 都只有少量網卡丟包（B0 0.09%、F2 0.36–0.38%、B2 0.54%），CPU0 平均只用了 33–60%，不是 CPU 不夠；推測是 CPU0 被其他工作（USB 的中斷、softirq 的批次）短暫佔住時 RX ring 滿了。速率點 50 → 80 太粗，A0 的容量比不出差別；F2 在 80k 的丟包比 B0 多，原因沒查。
- 只有一條大的 flow：RPS 依 flow 分，所以這個情境只看中斷放在哪裡；很多條信任 flow 時要另外量。

原始資料：筆電 `~/datasets/throughput/cpu_alloc/e1.kvl`、`e1.log`（`python3 tests/cpu_alloc/alloc.py cap e1.kvl`）。

## E2：寫入一筆信任的成本（Pi、鎖 1000 MHz、root、單執行緒）

`ebpf-bench mapbench <n>`：對 `TRUST`（65,536 筆的 hash map）逐筆 insert、lookup、delete，每筆一次 bpf syscall。

| 操作 | 1 萬筆（3 次） | 3 萬筆 |
|---|---|---|
| insert | 2.79–2.81 µs | 2.88 |
| lookup | 2.12–2.17 µs | 2.16 |
| delete | 2.57–2.60 µs | 2.67 |

對照 ctnetlink 設 ct mark（DECISIONS.md §7）：一筆 14.5 µs、一次 100 筆時每筆 2.4 µs。一條連線信任兩個方向要寫兩筆 map（約 5.6 µs）。map＋ct mark 的做法兩邊都要寫（約 20 µs），還要定期從 conntrack 對帳（每次讀表固定約 7 ms＋每條 9.4 µs，DECISIONS.md §19）。這次 map 沒有用批次操作（`BPF_MAP_UPDATE_BATCH`）。


# 步驟 C：trust 在 TC（wnc-gw 本身）

- `fastpath_docker.sh <tcp|udp|reuse|errors|all>`：Docker 的 routed testbed（cli 10.0.1.2 — gw — srv 10.0.2.2）。
- `core_pi.sh fastpath|auto`：Pi 上的 bridge（上面的 netns 拓樸，ecli、esrv 另外有 fd08::1、fd08::2）。

結果（2026-11-14）：

| | Docker（routed） | Pi（bridge） |
|---|---|---|
| 手動信任 TCP | forward chain 65 → 65（信任期間），`del` 後 65 → 107；TTL 63；160／160 行 | 72 → 74（多的 2 個是 IPv6 的多播，交回 kernel），`del` 後 74 → 115；TTL 64；160／160 |
| 手動信任 UDP | 32 → 32，`del` 後 33 → 53；TTL 63；160／160 | 228 → 228，`del` 後 228 → 250；160／160 |
| IPv6 TCP | testbed 的 gw 不轉送 IPv6，沒測 | 365 → 367，`del` 後 367 → 409；hop limit 64；160／160 |
| port 重用 | 同一個來源 port 重連，信任 1 → 0 筆 | — |
| 自動信任 | `protection_docker.sh autotrust`：ids chain 停住（ids 67 → 67、ips 71 → 72）、到期再信任、FIN alert 撤銷，和 11/04 相同 | ids chain 47 → 47、到期再信任、FIN alert 撤銷；250／250 行 |
| 失敗路徑 | run 沒在跑、找不到連線、送給 gw 自己的連線（`is not forwarded by the gateway`）、沒被信任、nobody（`permission denied`）、沒有 CAP_BPF（D001＋T014） | — |

補測（C3）：`fastpath_docker.sh options|ttl1|control|kill9|l007|idle`、map 滿的 `--ignored` 單元測試、`ROUTED=1 core_pi.sh fastpath|auto`（Pi routed：IPv4 TCP 63 → 63、UDP 215 → 215、IPv6 TCP 348 → 348，TTL／hop limit 63，160／160），結果見 `security_gateway/DECISIONS.md` §17。

`make_flows_pcap.py`：照樣本 pcap 裡某條 UDP flow 的 MAC，產生 N 條 UDP flow 輪流送的 pcap（來源 port 10000＋編號）和對應的 flows 檔，給 exp10 的 T1k 用（`X_udp1000`：1,000 條、20 萬個 60 bytes 的封包）。

## C3：wnc-gw 本身在 Pi 實體網卡上，bridge 對 routed（exp10）

詳細的表在 `tests/cpu_alloc/README.md` 實驗 10。結論：信任的封包 bridge 比 routed 每個少約 1.4 µs（7.80 對 9.16 µs @120k），沒被信任的 routed 比 bridge 少 3.1–3.9 µs；信任比例約 70% 以上 bridge 才整體便宜。1,000 條信任 flow 時查表沒有變貴。

## routed 的送法（exp11）

`bench` 的 v5（`v5_routed`）：v4 的 routed 版，只處理沒有 option 的 IPv4。`--via neigh|nexthop|fib`：`bpf_redirect_neigh` 不帶參數、帶下一跳（`--nexthop <出口> <IPv4>`，key 是出口的 ifindex）、`bpf_fib_lookup`＋改 MAC＋`bpf_redirect`（出口不是另一個 port、或 neighbor 還沒解析時交回 kernel）。三種都要在沒有 CAP_PERFMON 時通過 verifier：`FibParams` 的 MAC 拆成純量欄位，一個欄位一個欄位用 `write_volatile` 寫、不複製整個 struct（連續的 0 會被合成 memset）。Docker（routed testbed）三種都是 50／50 送達、TTL 63。

結果在 `tests/cpu_alloc/README.md` 實驗 11：帶下一跳最快（7.91 µs @120k，容量 180 kpps），和 bridge 的 fast path 差不多；`bpf_fib_lookup` 沒有比不帶參數快多少。

## routed 帶下一跳（wnc-gw 本身）

`fastpath_docker.sh nexthop`（Docker routed）：信任後 `trust list` 兩個方向都有下一跳（`10.0.1.2 / 10.0.2.2`）、forward chain 停住、TTL 63；`ip route add` 之後 0.3 秒變成 `- / -`、12 秒後填回；每 0.5 秒改一次路由持續 70 秒：WARN D007 一次、999／999 行都在 TC 送出（forward chain 43 → 43）、停止後 INFO「stable again」。Pi（`ROUTED=1 core_pi.sh fastpath`、方案 B 的 routed）：IPv4／IPv6 照常；1,000 條信任後幾秒內全部有下一跳（`alloc_pi.sh trust_flows … hops`）。
Pi 實體網卡（exp12）：routed 的信任封包 8.28 µs @120k（不帶下一跳時 9.16），bridge 7.79。
