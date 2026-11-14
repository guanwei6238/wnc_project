# wnc-gw 的決策與依據

這份文件回答「為什麼用這個」：每個決定比較過哪些選項、做了什麼實驗、量到什麼、還有哪些限制。決策的完整討論過程在 `.claude/skills/gateway-architecture/references/decisions.md`（下面的 D3、O4、O14 等編號就是那份文件的章節）。

每一節的格式：
- **決定**：用什麼、狀態、日期。狀態的標記和 README 相同：〔已實作〕〔已決定，未實作〕〔待決〕。
- **選項**：比較過哪些。
- **依據**：實驗（平台、量法、數字），或不是靠實驗的理由（安全、部署、設計）。
- **限制**：哪些情況沒量過。
- **腳本與結果**：可以重跑的寫 repo 裡的路徑；不在 repo 的另外註明。

## 共同的量測條件

| 名稱 | 內容 |
|---|---|
| Pi | Raspberry Pi 4 Model B 4 GB，**鎖 1000 MHz**（`pi_lab_mode.sh`，持續滿載不降頻的時脈）、governor performance，kernel 6.18.50+rpt-rpi-v8。Suricata 10/29 以前是 7.0.10，10/30 起是 8.0.7 |
| veth 拓樸 | Pi 內的 netns（`tests/ids_inline/env.sh`：wtest 送、wgw 轉送），tcpreplay 綁 CPU 1。沒有實體網卡、沒有 GRO |
| 方案 B | 筆電的 tcpreplay 從兩張實體網卡送進 Pi 的 eth0 和 eth1.20（`tests/ids_inline/planb_*.sh`）。10/30 起量容量時關掉 Pi eth0 的 Ethernet PAUSE |
| Docker testbed | 筆電上的 wnc-gw、cli、srv 容器，共用筆電的 kernel；用來驗證功能，不拿來比效能 |
| µs／封包 | Suricata 執行緒的 CPU（`/proc/<pid>/task/*/schedstat`）或整台機器的 CPU（`/proc/schedstat` 或「經過時間 − idle」）÷ 封包數；10/30 以前用 `/proc/stat` 的整台機器數字是錯的（見 §2） |
| 容量 | 處理不過來而丟的封包 ≤ 0.1% 的最高速率（kpps） |
| pcap | IoT-23 的切片：17-1 掃描（99.8% 純 SYN）、1-1 約一半純 SYN、60-1 一條 UDP 連線佔大部分、42-1 同一對 IP 有很多連線、39-1 IRCBot、Honeypot-7-1 一條 TLS 連線佔大部分 |

## 總覽

| § | 決策 | 主要依據 | 狀態 |
|---|---|---|---|
| 1 | 轉送模式預設 bridge | 部署（透明）；Pi 實體網卡上 routed 每個封包少約 2 µs（只轉送 −15～−20%，有檢查 −2～−9%） | 〔已實作〕預設待開發者決定 |
| 2 | ids 用 NFLOG、ips 用 NFQUEUE | Pi 量測 | 〔已實作〕 |
| 3 | 多個 queue／group 用 symhash 分流 | Pi 量測 | 〔已實作〕 |
| 4 | Suricata 強制 runmode=workers | Pi 量測 | 〔已實作〕 |
| 5 | 信任：10-28 用 ct mark，11-14 改成 TC 的 trust map（fast path） | 安全理由＋Pi 量測 | 〔已實作〕（11-14 的做法） |
| 6 | SYN／FIN／RST 一律檢查、純 SYN 清信任（11-14 起在 TC 做） | Pi 量測＋kernel 行為 | 〔已實作〕 |
| 7 | 手寫 ctnetlink（11-14 起只用來讀連線） | Pi 量測 | 〔已實作〕 |
| 8 | nftables 用 nft JSON | 授權＋Pi 量測 | 〔已實作〕 |
| 9 | table 骨架寫死、黑名單放 nft set | 設計 | 〔已實作〕（set 未做） |
| 10 | wnc-gw 啟動 Suricata，READY=1 後才送封包 | 當機重現 | 〔已實作〕 |
| 11 | `when_unavailable` 預設 accept、exception policy 跟著它 | 設計＋功能驗證 | 〔已實作〕 |
| 12 | 強制接手從中間開始的連線 | 功能驗證 | 〔已實作〕 |
| 13 | 其他強制給 Suricata 的設定 | 功能驗證 | 〔已實作〕 |
| 14 | 停止時移除 table、SIGHUP 正常停止 | 功能驗證 | 〔已實作〕 |
| 15 | 監控 conntrack 表和漏掉的複本 | 功能驗證＋成本 | 〔已實作〕 |
| 16 | Suricata 8.0.7、最低 8.0 | EOL＋重量 | 〔已實作〕（版本檢查未做） |
| 17 | XDP 預設原則、fast path 用 tc eBPF | 設計 | 〔已決定，未實作〕 |
| 18 | log 只印 stderr | 平台限制 | 〔已實作〕（systemd 部分未做） |
| 19 | 3d：讀 Suricata 的 alert（EVE 檔、poll）、自動信任、log 只放重要資訊 | 實驗（EVE 行為與成本、poll 對 inotify）＋Docker、Pi 功能驗證 | 〔已實作〕（自動信任的預設值待確認） |
| 20 | 還沒決定、但已有實驗的事項 | — | 〔待決〕 |

---

## 1. 轉送模式 `mode`：bridge〔預設〕／routed

**決定**：兩種都支援，預設 bridge，bridge 由 OS 建立、wnc-gw 只檢查。〔已實作〕D3，2026-10-24。2026-11-04 在實體網卡上量過；預設要不要改還沒決定（§20）。

**兩種模式的架構差異**

| | bridge（L2） | routed（L3） |
|---|---|---|
| 部署 | 插在中間即可，LAN 和 WAN 同一個網段，內網設定不用改 | LAN 和 WAN 是不同網段。我們不做 NAT，所以上游路由器要加一條到內網的路由，內網的 gateway 也要指向它 |
| 封包怎麼進 nftables | 經過 `br_netfilter`：被橋接的 IP 封包也走 `inet` 的 forward hook | 一般的 IP 轉送，直接走 `inet` 的 forward hook |
| doctor 檢查 | LAN、WAN 在同一個 bridge；`br_netfilter` 已載入；`net.bridge.bridge-nf-call-iptables`、`-ip6tables` = 1（必要） | LAN、WAN 都不在 bridge 裡；`net.ipv4.ip_forward` = 1（必要）、`net.ipv6.conf.all.forwarding` = 1（建議）；IPv4 的位址和路由（見下面「routed 的網路設定」） |
| 判斷封包從哪個 port 進來 | forward chain 看到的 `iifname` 都是 `br0`，要在 netdev ingress 打 mark〔已決定，未實作〕 | `iifname` 就是實體 port；但決定兩種模式都用 ingress 的 mark，規則才能共用 |
| fast path（tc eBPF） | `bpf_redirect` 直接送到另一個 port | 要 `bpf_fib_lookup` 查路由再 `bpf_redirect_neigh`；`bpf_fib_lookup` 是 GPL-only helper，BPF 程式要宣告 GPL 相容授權 |
| nft flowtable | 不能用（只接受 ip、ip6、inet family，純橋接流量不經過） | 可以用（O5，待決） |
| 每個封包的轉送成本（veth，見下面） | 10.7 µs | 7.9 µs |

在程式裡，兩種模式是 `forwarding/` 裡同一個 trait（`Forwarding`）的兩個實作：各自宣告需要的 kernel 模組和環境檢查，nft table 完全相同。

**依據**
- 預設 bridge 的理由是**部署**，不是效能：gateway 插進既有的公司網路時不用改任何設定。
- 功能（2026-10-24，筆電 kernel 7.0 和 Pi，都在 netns 裡）：
  - 沒載入 `br_netfilter`，或 `bridge-nf-call-iptables=0` 時，`inet` 的 forward chain 看到 **0 個**被橋接的封包，等於完全繞過規則。所以 doctor 把它列為必要條件。
  - 載入後 forward chain 看得到全部封包，`iifname` 是 `br0`；netdev ingress 打的 mark 帶得到 forward chain；ct mark 可以用；queue 給 Suricata 照常轉送和 alert。
  - Pi 的 kernel 沒有 `nf_conntrack_bridge`，所以不能用 `bridge` family 加 conntrack，只能走 `br_netfilter`。
- 成本（2026-10-24，Pi、veth、單一 UDP flow、60-byte frame、發送和轉送在同一顆 CPU、3 輪差異 < 2%）：

  | 設定 | 每個封包的轉送成本 |
  |---|---|
  | bridge（沒有 br_netfilter） | 3.1 µs |
  | routed | 4.0 µs |
  | bridge + br_netfilter（沒有規則） | 6.9 µs |
  | routed + nft + conntrack | 7.9 µs |
  | bridge + br_netfilter + nft + conntrack | 10.7 µs（比 routed 多約 35%） |

- 成本（2026-11-04，Pi、方案 B 的實體網卡、2 輪；`tests/cpu_alloc/README.md` 實驗 4）：

  | 工作負載 | bridge | routed |
  |---|---|---|
  | 只轉送，A0 @100k | 9.97 µs，容量 100 kpps | 8.02 µs（−20%），容量 150 kpps |
  | 只轉送，RPS @100k | 11.79 µs，容量 300 kpps | 9.99 µs（−15%），容量 300 kpps |
  | ips、全部信任，A0 @50k | 13.98 µs | 11.13 µs（−20%） |
  | ips 2 queue @30–40k | 56.5–63.1 µs | 51.8–60.7 µs（−2～−9%），容量一樣 |
  | ids 3 group，RPS @30–80k | 45.1–45.8 µs | 44.0–44.4 µs（−2～−3%），容量一樣 |

  routed 的轉送每個封包少約 2 µs，省的主要是收封包那顆 CPU。veth 上的 35% 在實體網卡上是 15–20%（只轉送）；有檢查時只差 2–9%。
- 行為差異（2026-11-04 同一組實驗）：
  - routed 不轉送非 IP 的封包（ARP 等），bridge 照轉。
  - routed、沒開 RPS 時，同一條新 TCP 連線的兩個一模一樣的封包如果同一批收進來，第二個會在 conntrack confirm 時被丟（`insert_failed`）；丟的是重複的副本。S_m17 有一半的封包是重複的，所以 ids A0 少送了 21–42%。開 RPS、或 bridge 都沒有。

**限制**：只量了方案 B 的兩個 pcap（S_m17 掃描、S_m60 單一 UDP flow）；routed 的下一跳是假的 MAC，沒有真的路由器和 ARP。

**routed 的網路設定**（2026-11-05 決定）：和 bridge 一樣由 OS 設定，wnc-gw 不設位址和路由，只在 doctor 檢查。wnc-gw 自己設的話會和 OS 的網路管理（NetworkManager、之後的 OpenWrt UCI）搶同一份設定，而且上游路由器那條路由它一樣設不到。

| 檢查 | 結果 | 理由 |
|---|---|---|
| LAN、WAN 都有 IPv4 位址（169.254.0.0/16 不算） | 沒有：warning | 和 link down 一樣：WAN 用 DHCP 時開機那一刻可能還沒拿到。報 error 的話 `run` 不啟動，之後位址拿到了 kernel 照樣轉送，流量卻完全沒經過檢查 |
| LAN、WAN 的網段不和彼此、也不和其他介面重疊 | 重疊：error | 設定本身矛盾，不會自己好 |
| 預設路由走 WAN | 沒有、走別的介面、是 blackhole 等：warning；有 kernel 預設之外的 `ip rule`：無法確認（warning） | 公司內部網段可能本來就只用特定路由；只看 main table，policy routing 時不下結論 |
| 內網 gateway、上游路由 | note，用實際的位址寫出來 | Pi 上查不到，只能提醒 |

rp_filter 不另外檢查：路由設對時 strict 模式不會擋正常流量，還能擋偽造來源；會誤擋的情況（從 WAN 進來、回程卻走別的介面）就是「預設路由走 WAN」抓的，訊息裡順便提。IPv6 的位址和路由等真的要支援 IPv6 再加。

成本：doctor 多三次 rtnetlink dump（位址、路由、rule），`run` 啟動前也會跑。筆電 Docker 裡第一次 149 µs、之後每次約 37 µs（同一個 doctor 列介面每次約 240 µs）；Pi 還沒量。

**腳本與結果**：10/24 的量測腳本（`perf-fwd.sh`、`udpblast.rs`）放在當時的暫存目錄，**沒有進 repo**；功能驗證的紀錄在 `research/literature/trust-bypass/SYNTHESIS.md` §11 D3。

---

## 2. 檢查模式 `protection`：ids〔預設〕用 NFLOG、ips 用 NFQUEUE

**決定**：ids 用 NFLOG 送複本給 Suricata，封包立刻轉送；ips 用 NFQUEUE，封包等 Suricata 判決。〔已實作〕O18，2026-10-29。預設 ids 是開發者的要求（前期只標記、不擋）。

**選項**：ids 可以是 (A) NFQ 但一律放行、(B) NFLOG 送複本、(C) af-packet。(C) 先排除：af-packet 看不到 ct mark，信任就沒有用（af-packet IPS 是 Suricata 自己在兩張網卡之間搬封包，不經過 bridge 和 nft）。

**依據**
- 功能（Docker，Suricata 8.0.7，`nflog_docker.sh`）：複本完整，TCP 第 1300 bytes 之後的 payload 照樣 alert；信任後 log 規則的計數停住；Suricata 被 SIGKILL 時 ping 100/100，轉送不受影響；多個 group 用 symhash vmap，8 條連線 8/8 alert。
- 成本（Pi、veth、10,000 pps、1 個 queue／group、2 輪、Suricata 8.0.7、workers，`nflog2.kvl`）：

  | scenario | rules | Suricata NFQ | Suricata NFLOG | 整台 NFQ | 整台 NFLOG |
  |---|---|---|---|---|---|
  | 60-1 | empty | 40.8／41.2 | 19.2／19.3 | 80.7／80.0 | 55.8／56.6 |
  | 60-1 | full | 43.3／42.3 | 21.1／21.2 | 87.1／81.2 | 58.2／59.5 |
  | 1-1 | empty | 43.9／43.0 | 22.1／22.2 | 83.7／81.6 | 60.0／61.6 |
  | 1-1 | full | 47.8／47.0 | 24.4／24.4 | 86.0／85.4 | 62.2／63.5 |
  | 17-1 | empty | 35.3／35.5 | 21.3／21.3 | 66.2／66.9 | 59.7／60.3 |
  | 17-1 | full | 37.6／37.8 | 23.4／23.3 | 68.2／68.7 | 64.4／63.2 |

  （µs／封包；整台含 tcpreplay，只能看差距。）NFLOG 讓 Suricata 執行緒的工作約減半，整台機器省 4–25 µs。NFQ 貴在判決之後 kernel 的轉送是在 Suricata 的 syscall 裡做。
- 容量（方案 B、PAUSE 關、full，2026-11-03，`tests/cpu_alloc/README.md`）：ids 開 RPS（CPU1–3）、3 個 group 時，17-1 轉送 120 kpps、Suricata 不漏複本到 80 kpps；ips 最好約 60 kpps。但 **ids 不開 RPS 時轉送只有 30–40 kpps**：ids 的轉送和複本都在收封包那顆 CPU 的 softirq 裡做完，ips 的轉送則分散到 Suricata 的執行緒。
- 7.0.10 時的舊量測（`nflog1.kvl`）只有 Suricata 那兩欄正確；整台機器那兩欄用 `/proc/stat`（tick 取樣，10,000 pps 和 tick 對齊）量錯了，曾經得出「NFLOG 不省總 CPU」的錯誤結論，10/30 用上面的方法重量後推翻。

**代價（doctor 和啟動時會警告）**
- ids 的偵測不會擋任何流量。
- **checksum 檢查一定要關**（`capture.checksum-validation=none`）：方案 B 用 iperf3 的大量 TCP 送進 Pi，GRO 平均把 6.7 個封包合併成一份複本，開著檢查時 74% 被判成 checksum 錯誤、payload 規則比對不到。關掉的代價是 insertion：攻擊者送出接收端會因 checksum 錯而丟掉的封包，Suricata 照樣檢查，可以用來混淆。NFQ 沒有這個問題（kernel 會標出 checksum 還沒算的封包）。
- Suricata 跟不上時，不管 `when_unavailable` 怎麼設，封包照樣轉送，只是複本被丟掉；所以 wnc-gw 要監控漏掉的複本（§15）。

**腳本與結果**：`tests/ids_inline/nflog_docker.sh`、`run_nflog.sh`、`nflog.py`、`results/nflog1.kvl`、`results/nflog2.kvl`；GRO 與 checksum、10/29 的方案 B 容量在筆電 `~/datasets/throughput/planb/`（`nflog.kvl`、`checksum.kvl`、`bufcheck.kvl`）；容量在 `tests/cpu_alloc/`。

---

## 3. 多個 queue／group 的分流：kernel 的 symhash

**決定**：ips 用 `queue to symhash mod N`，ids 用 `symhash mod N vmap { … }` 分到每個 group 一條 chain。〔已實作〕O14，2026-10-27 決定、10-28 實作。

**選項**：nft 的 `queue num 0-(N-1)`（kernel 只用兩端位址和協定算 hash）；symhash（含 port、兩個方向算出同一個值）；Suricata 的 autofp（見 §4）。

**依據**
- 位址 hash 的問題（Pi、veth、full、全速、Suricata 直接跑 NFQ、3 個 queue；`addr*.kvl`、`sym*.kvl`）：

  | 42-1（同一對 IP 很多連線） | queue 分配 | 處理 kpps | 丟失 |
  |---|---|---|---|
  | 位址 hash，7.0.10（10/27） | 5／7／88% | 12.9 | 46.8% |
  | symhash，7.0.10（10/27） | 37／33／30% | 26.4 | 0% |
  | 位址 hash，8.0.7（11/03） | 94／3／4% | 9.2 | 62.6% |
  | symhash，8.0.7（11/03） | 30／36／34% | 24.9 | 0% |

  其他 scenario 兩種 hash 結果相同。symhash 讓 kernel 每個封包多 0.7–1.8 µs。
- 分片：symhash 對分片只能用位址算（後面的分片沒有 port）。沒有 conntrack 時，同一條連線的分片會落到不同 queue（Pi bridge，24 條連線有 18 條被拆開）；table 用到 conntrack 時 kernel 會在進 queue 前組回分片（0/24，IPv4、IPv6 都是）。我們的 table 一定有 ct mark 規則，conntrack 一定啟用，所以不另外處理。
- ids 的 group 一樣用 symhash：Docker 和 Pi 都是 8 條連線兩個方向進同一個 group，8/8 alert。

**限制**：一條連線佔大部分流量時（60-1、Honeypot-7-1），不管幾個 queue 都只有一個 worker 在忙，上限就是一個 worker（約 30 kpps）；這要靠信任（§5）。非 0 的 offset（queue 不是從 0 開始）實際怎麼分流沒有測。

**腳本與結果**：`tests/ids_inline/run_mq.sh`、`mq.py`、`frag_pi.sh`、`results/mq1.kvl`、`sym1.kvl`、`addr1.kvl`（7.0.10）、`mq2.kvl`、`sym2.kvl`、`addr2.kvl`（8.0.7）。

---

## 4. Suricata runmode：強制 workers

**決定**：wnc-gw 一律加 `--set runmode=workers`，蓋過 suricata.yaml。每個 queue／group 一個 worker 執行緒，多核靠多個 queue／group。〔已實作〕O18，2026-10-30。

**選項**：workers（一條執行緒從收封包做到判決）；autofp（RX 執行緒收封包，再交給幾條 worker；NFQ 另有 TX 執行緒送判決）。Debian 預設的 yaml 沒寫 runmode，NFQ 和 NFLOG 都會變成 autofp。

**依據**（Pi、veth、10,000 pps、1 個 queue／group、2 輪、8.0.7，`nflog2.kvl`；µs／封包，兩輪平均、四捨五入；每一輪的數字在 `nflog2.kvl` 和 decisions.md O18）：

| scenario | rules | Suricata workers（NFQ／NFLOG） | Suricata autofp（NFQ／NFLOG） | 整台 workers（NFQ／NFLOG） | 整台 autofp（NFQ／NFLOG） |
|---|---|---|---|---|---|
| 60-1 | full | 43／21 | 59／36 | 84／59 | 96／74 |
| 1-1 | full | 47／24 | 69／41 | 86／63 | 106／81 |
| 17-1 | full | 38／23 | 64／38 | 68／64 | 103／79 |

- autofp 每個封包都比較貴：Suricata 多 15–30 µs、整台多 15–35 µs，貴在執行緒之間交接（RX、TX 合計 NFQ 43–54、NFLOG 約 19 µs）。
- 分流放在 kernel（symhash，+0.7–1.8 µs）比在 Suricata 裡交接便宜很多；兩者都把同一條連線交給同一條執行緒，分得一樣平均。
- 只剩一顆核心時，autofp 的幾條執行緒擠在同一顆核心上更差。
- 驗證（`protection_docker.sh runmode`、`protection_pi.sh runmode`）：yaml 明寫 autofp 時，wnc-gw 起的 Suricata 也只有 W 執行緒，沒有 RX、TX。

**代價**：只開 1 個 queue／group 時只用一顆核心檢查。2026-11-03 方案 B：ips 1 個 queue 只有 20–30 kpps。預設開幾個還沒決定（§20）。autofp 單一 queue 的容量沒量。

**腳本與結果**：`tests/ids_inline/run_nflog.sh`（`RUNMODES`）、`nflog.py`、`results/nflog2.kvl`、`protection_docker.sh`、`protection_pi.sh`。

---

## 5. 信任：ct mark，以一條連線為單位

> **2026-11-14 改掉，已實作**（步驟 C；Docker routed、Pi bridge 驗過，見 §17）：trust 只放在 TC 的 BPF map（五元組、每個方向一筆），不再用 ct mark：信任的封包在 TC 直接 redirect，不進 bridge、netfilter、conntrack。核心程式掛不上時就沒有信任（全部檢查，D001／D005 維持 warning、log 寫明信任停用）。沒有 conntrack 的 TCP 序號窗檢查：偽造五元組相同的封包可以不經檢查送進內網，這是 RQ3 第 4 項（SYNTHESIS §6.1）的實驗條件，緩解（TC 自己檢查序號窗）在那個實驗做，map 的 value 先預留欄位。依據：E1（Pi 實體網卡、bridge）：信任的封包 TC redirect 比 ct mark 少 5–6 µs（−39～−46%），IRQ 在 CPU1 時容量 80 → 150 kpps；E2：map 寫一筆 2.8 µs、ctnetlink 14.5 µs；兩種做法查到時每封包成本相同，map＋ct mark 還要每 5 秒對帳（`tests/ebpf/README.md`）；選項與差別見架構 skill 的 `decisions.md` O17。下面是 10-28 的 ct mark 做法和它的量測，留著當 RQ3 第 4 項的對照（程式在 git 歷史，`1faa17d` 之前）。

**決定**：已信任的連線在 conntrack entry 上設 mark 的最高位元（`0x80000000`），forward chain 看到就直接 accept、不進 Suricata。〔已實作〕O17，2026-10-28。目前用 `wnc-gw trust add／del／list` 手動設定；自動判定（控制迴路）還沒做。

**選項**：(a) ct mark；(b) nft set 放五元組，元素帶 TTL。

**依據**
- **安全（主要理由）**：(b) 以五元組為單位，port 重用或偽造封包就會被當成已信任；(a) 是 conntrack 的一條連線，新連線沒有 mark。conntrack 本來就要用（分片重組、之後的計數），所以 (a) 沒有多出 conntrack 的代價。
- 只用最高位元、寫入時帶 mask：其他程式（例如 mwan3）用的是低位元。
- 信任省多少（Pi、veth、10,000 pps、full、2 輪；整台機器 µs／封包，含 tcpreplay）：

  | scenario | 只轉送 | 全部進 Suricata | 全部信任 | 信任省下（7.0.10 → 8.0.7） |
  |---|---|---|---|---|
  | 39-1 | 37.3 | 106.2 | 38.0 | 66.6 → 68.2 |
  | 1-1 | 36.7 | 79.6 | 37.6 | 40.8 → 42.1 |
  | 44-1 | 37.6 | 94.5 | 32.8 | 60.8 → 61.8 |
  | Honeypot-5-1 | 37.5 | 71.1 | 33.1 | 38.6 → 38.0 |
  | Honeypot-7-1 | 39.6 | 106.0 | 40.4 | 64.3 → 65.6 |

  （表中前三欄是 8.0.7。）信任的封包和不檢查一樣便宜；conntrack + ct mark 規則本身（全部信任 − 只轉送）在 −4.8～+3.5 µs，量測雜訊內。
- 實體網卡（方案 B、PAUSE 關，2026-11-02）：信任的封包整台約 14 µs、檢查的約 55 µs；一條連線佔大部分的 60-1，檢查時上限 30 kpps，全部信任時 50 kpps（網卡中斷搬到 CPU1 時 80）。
- conntrack 表被掃描塞滿時（Pi、`ctfull_pi.sh`）：early drop 只清沒有 assured 的 entry，被信任的 TCP 連線不受影響；只有單向的 UDP 不會變 assured，可能被清掉，清掉後回到 Suricata（多檢查，不會少檢查）。

**限制**：掃描流量幾乎都是純 SYN，一定進 Suricata（§6），信任對它沒有用。

**腳本與結果**：`tests/ids_inline/ctmark_docker.sh`、`ctmark_pi.sh`、`trust_cost.sh`、`trust.py`、`ctfull_pi.sh`、`results/trust1.kvl`（7.0.10）、`results/trust2.kvl`（8.0.7）。

---

## 6. 控制封包一律檢查（L2）、純 SYN 清掉信任

> **2026-11-14 起在 TC 做**：核心 eBPF 程式看到 TCP 的 SYN／FIN／RST 一律交回 kernel（所以一定進 netfilter 和 Suricata，nft 裡不再需要 L2 規則）；純 SYN 先刪掉這組五元組兩個方向的信任。nft 的 forward chain 只剩 counter、設 forwarded 位元、jump ids。Docker 驗證（`tests/ebpf/fastpath_docker.sh reuse`）：同一個來源 port 重新連線，信任從 1 筆變 0 筆。下面是 10-28 在 netfilter 的做法。

**決定**：forward chain 依序是：純 SYN 碰到已信任的 entry 先清掉信任位元 → SYN／FIN／RST 一律進 Suricata → 已信任的 accept → 其他進 Suricata。〔已實作〕2026-10-28。

**依據：L2**
- 放行之後的可見性：信任之後 Suricata 仍看得到每條連線的建立和結束。Shunting（CCS'07）等四個前例都這樣做（`research/literature/trust-bypass/SYNTHESIS.md` §4.3）。
- 成本（同 §5 的量測，「信任 + L2」減「全部信任」）：長連線約 +1 µs（控制封包只佔 0.01–0.04%）；39-1 +59 µs、1-1 +22 µs，因為控制封包佔 91%、53%。掃描類流量本來就不會被信任，所以不影響信任能省的部分。
- Honeypot-5-1 的「信任 + L2」2 輪差 13.5 µs：重播時後面的封包搶先經過 conntrack，被判成 INVALID 而進 queue；降到 500 pps 時是 0 個，是重播造成的假象。

**依據：純 SYN 清掉信任**
- kernel 的行為（kernel 6.18 `nf_conntrack_proto_tcp.c`）：舊連線沒有 FIN／RST 經過就消失（例如裝置重開機），entry 會停在 ESTABLISHED；同一組五元組的新 SYN 會被 conntrack 重新同步到舊 entry，**id 不變、mark 被沿用**，新連線就直接被信任。
- 重現（Docker `synreuse_docker.sh`、Pi `synreuse_pi.sh`）：沒有這條規則時新連線只有 4 個控制封包進 Suricata；有這條規則時新連線全部進 Suricata。
- 成本（Pi、10,000 pps、empty；同一條規則複製 500 條再除回去）：每條規則每個封包 52–159 ns，1 條在量測雜訊內。
- 判斷錯的方向只會多檢查：偽造純 SYN 只能讓一條被信任的連線回到 Suricata，不能讓沒被信任的連線被放行。UDP 沒有這種訊號，只能靠 TTL。

**腳本與結果**：`tests/ids_inline/trust_cost.sh`、`synreuse_docker.sh`、`synreuse_pi.sh`、`results/synclear.kvl`。

---

## 7. 寫 ct mark：手寫 ctnetlink

> **2026-11-14 起只用來讀**：自動信任讀轉送的連線和計數、`wnc-gw trust add` 確認連線存在而且是轉送的；信任不再寫 ct mark。

**決定**：wnc-gw 自己組 ctnetlink 訊息（`kernel/conntrack.rs`），不用 crate、也不 spawn `conntrack`。〔已實作〕O17，2026-10-28。這是「netlink 用 rust-netlink」原則的例外，只限 ctnetlink。

**依據**（Pi、單核、表 1,000 筆；µs／筆；`tests/ctnetlink/bench/`）：

| 做法 | 設一筆 | 一次 100 筆 | 讀一筆 |
|---|---|---|---|
| netlink-packet-netfilter + netlink-proto | 51–52 | 13.5–13.9 | — |
| netlink-packet-netfilter + netlink-sys `Socket` | 19.9–20.8 | 5.4 | 74 |
| 手寫 + netlink-sys `Socket` | 13.0–13.7 | 2.4 | 19.6 |

- netlink-proto 每個請求要經過兩個 channel 和 task 切換；crate 每筆配置好幾層 `Vec`，musl 的記憶體配置慢。兩種編碼出來的位元組完全相同（單元測試比對）。
- `conntrack -U`（conntrack-tools 1.4.8）每改一筆就讀一次整張表：表 1 千、1 萬、5 萬筆時每筆 16、78、354 ms（2026-10-25），不能當寫入路徑。
- 實作後（表 6 萬筆）：設一筆 14.5 µs、讀一筆 23.4 µs；啟動時清掉 6 萬筆信任要 636 ms。整表 dump 每筆 7.10 µs，開 `nf_conntrack_acct` 時 7.25 µs（2026-11-03）。

**腳本與結果**：`tests/ctnetlink/bench/`；10/25 的 `conntrack -U` 量測在 Pi 的 `~/ctbench/`，沒有進 repo。

---

## 8. 操作 nftables：nft JSON，spawn `/usr/sbin/nft`

**決定**：`nftables` crate 產生 JSON，交給 `nft` 執行。〔已實作〕O4，2026-10-25。

**選項**：`rustables`（netlink，GPL-3.0+）、`nftnl`（連結 GPL-2+ 的 libnftnl）、自己寫 netlink。

**依據**
- **授權**：專案可能閉源。連結 GPL 的函式庫會讓 wnc-gw 也受 GPL 約束；spawn 獨立的 `nft` 程式不受影響。
- 成本（Pi，2026-10-25）：只影響寫入，不影響每個封包的轉送。plain set 加元素：nft 每次約 7.7 ms、自己寫 netlink 約 53 µs；一次寫 1000 個時 nft 17.2 ms、netlink 1.66 ms；set 裡已有 10 萬個元素時一樣。interval set 隨 set 變大線性變慢（10 萬個元素時 nft 每次約 1.9 s）。
- 所以：寫入 set 元素要設計成一次一批；常變動的黑名單用 plain set。之後如果 nft 寫入太吃 CPU，只把「寫入元素」換成自己寫 netlink。

**腳本與結果**：量測在 Pi 的 `~/nftbench/`，沒有進 repo。

---

## 9. table 骨架寫死在程式裡、黑名單放 nft set

**決定**：chain、hook、priority、規則都寫在 `src/datapath/firewall.rs`，設定檔只能改參數；使用者只能管理 set 的內容。黑名單放在 nft set，不交給 Suricata。〔已實作〕（set 還沒做）O11，2026-10-25。

**依據（設計，不是量測）**
- 程式依賴 table 的結構（ct mark 的值、queue 編號、chain 名稱）；讓使用者改整張 table 等於開放 `nft -f`，可能把信任模型改壞。
- 黑名單放 nft：已信任的連線和之後的 fast path 都不經過 Suricata，黑名單放在 Suricata 就擋不到；放在 nft，被擋的封包在 kernel 查一次 hash 就丟掉。
- Suricata 就緒或停止時只換 `ids` chain 的規則，不重裝整張 table，避免清掉之後 set 裡的動態內容。

---

## 10. Suricata 由 wnc-gw 啟動，收到 READY=1 才送封包

**決定**：wnc-gw spawn Suricata（設 `NOTIFY_SOCKET`），收到 `READY=1` 之後才把 `ids` chain 換成 queue 或 log 規則；Suricata 結束時先換回「沒在檢查」的規則，換好才重啟。重啟的退避從 1 秒加倍到 60 秒。〔已實作〕O14，2026-10-26。之後也要支援由 systemd 管理，兩者實作同一個生命週期介面。

**依據**
- Suricata 在初始化時收到封包會 segfault（7.0.10 和 8.0.7 都有）。原因用 gdb 確認過：NFQ 執行緒等 kernel 回覆時就把 queue 裡的封包交給還沒初始化完的統計計數器。

  | 情況 | 結果 |
  |---|---|
  | Docker，7.0.10，啟動前就有封包進 queue | 20 次 11 次 segfault |
  | Docker，8.0.7，同上 | 50 次 42 次 |
  | Docker，8.0.7，收到 `READY=1` 才加 queue 規則 | 30 次全部正常 |
  | Pi，7.0.10，啟動後 0.1 秒內有封包 | 9／9 segfault；0.2 秒之後 0／6 |
  | NFLOG 直接跑、有流量時啟動 | Docker 8.0.7 5／20、Pi 7.0.10 4／20、Pi 8.0.7 2／20 |
  | Pi，經過 wnc-gw（等 READY=1），`ping -f` 下啟動 | 20／20 正常 |

- 自己 spawn 而不是一開始就用 systemd：順序最好推理，能在 Docker（沒有 systemd）驗證，OpenWrt 也能用。代價是 Suricata 和 wnc-gw 共用帳號，doctor 會警告。
- `PR_SET_PDEATHSIG`：wnc-gw 被強制結束時 Suricata 也結束，不會留下佔著 queue 的孤兒。
- 同一台機器只能跑一個 `wnc-gw run`（flock `/run/wnc-gw/wnc-gw.lock`）：兩個同時跑時，一個收尾會刪掉另一個的 table。

**腳本與結果**：NFQ 的 Docker 重現（10/25）和 gdb 分析沒有留下腳本；NFLOG 是 `tests/ids_inline/nflog_docker.sh`、`nflog_startup_pi.sh`；經過 wnc-gw 的驗證是 `protection_pi.sh startup`。

---

## 11. Suricata 沒在檢查時 `when_unavailable`：accept〔預設〕／drop；exception policy 跟著它

**決定**
- Suricata 還沒就緒、重啟中、跟不上時：accept〔預設〕直接放行（ips 時 queue 加 `bypass`、強制 `nfq.fail-open=yes`），或 drop 丟掉。不管哪一種都一定記 log：何時開始沒檢查、沒檢查了多久（`uninspected_ms`）。〔已實作〕O14，2026-10-26。
- Suricata 檢查不了某一條 flow 時（memcap 用完、app-layer 解析錯誤）的 exception policy 也跟著它：ips 時 accept → ignore、drop → drop-flow（flow、defrag 用 drop-packet）。ids 一律 ignore（拿到的是複本，丟了也擋不到）。〔已實作〕O16，2026-10-28。

**依據**
- 預設 accept 是設計選擇：Suricata 出問題不該讓整個公司網路斷掉；但沒檢查的時段一定要能從 log 查到。
- Debian 預設的 `exception-policy: auto` 在 NFQ 模式等於 drop-flow：Suricata 記憶體不夠時會丟掉正常流量，和 `when_unavailable` 是同一個問題，只是範圍是一條 flow。
- 功能驗證（`exception_policy_pi.sh`：flow memcap 調到 512 KiB，對 5000 個 port 各送 1 個 UDP）：

  | | Docker（8.0.7） | Pi（7.0.10） |
  |---|---|---|
  | accept | 5000／5000 送達 | 5000／5000 送達 |
  | drop | 送達 2203，丟 2797 | 送達 2101，丟 2899 |

- SIGKILL Suricata（重啟約 1.1–1.3 秒）：accept 120／120 送達，drop 96–98／120。Suricata 當掉時還在 queue 裡等判決的封包會被 kernel 丟掉，`bypass` 只管之後的封包（Docker：每秒 20 個 ping 掉 2 個）。

**腳本與結果**：`tests/ids_inline/exception_policy_pi.sh`、`protection_docker.sh kill`、`protection_pi.sh kill`。

---

## 12. 強制接手從中間開始的連線

**決定**：強制 `--set stream.midstream=true` 和 `--set stream.midstream-policy=ignore`。〔已實作〕O16，2026-10-27。

**依據**
- 我們的設計會常常產生「從中間開始」的連線：Suricata 重啟後所有既有連線、信任之後回到 Suricata 稽核的連線。
- Pi 上用 Debian 預設設定時，連 empty 規則都丟掉 39-1 26% 的封包：29 條從中間開始的 flow 之後全部被丟。
- Docker（8.0.7）：TCP 連線送 100 行，中途讓 Suricata segfault 重啟：

  | 設定 | 連線 | 重啟後的 alert | Suricata 丟的封包 |
  |---|---|---|---|
  | 預設 | 斷（只收到 27 行） | 沒有 | 整條連線 |
  | 只開 `stream.midstream` | 100 行 | 有 | 0 |
  | 只改 `exception-policy: ignore` | 100 行 | 有 | 5（靠 TCP 重傳才沒斷） |
  | 兩個都改 | 100 行 | 有 | 0 |

- 另外強制 midstream-policy=ignore：yaml 若設成 `pass-flow`，接手後不再檢查；設成 `drop-flow`，Suricata 說不合法但實際仍然丟。強制之後每一種 yaml 都是「連線不斷、照常 alert」。

---

## 13. 其他強制給 Suricata 的設定

| 設定 | 為什麼（都在 Docker 或 Pi 上重現過） |
|---|---|
| `detect.delayed-detect=no` | 設成 yes 時 Suricata 先送 `READY=1` 才載入規則，wnc-gw 會把沒有規則的那段記成「已檢查」 |
| `coredump.max-dump=0` | Suricata 預設把 core 上限放寬成 unlimited；Pi 上每次當機寫 154 MB（載入完整規則時 1 GB 以上），寫檔時卡在 D 狀態幾十秒，反覆當機可能寫滿 SD 卡 |
| `engine.init-failure-fatal=no` | 一條壞規則不該讓整個網路失去檢查；改成 Suricata 照常啟動、wnc-gw 記 WARN（`suricata could not load some rules`） |
| `stop_timeout` 預設 90 秒（原本 10 秒） | Suricata 結束前要把每條開著的 flow 寫進 eve.json，Pi 上 full 處理過 18 萬條 flow 要 11–13 秒，10 秒會被 SIGKILL |

---

## 14. 停止時移除 table；SIGHUP 也正常停止

**決定**：停止時先換回沒檢查的規則，再停 Suricata，最後移除 table；wnc-gw 沒在跑時流量直接通過。SIGHUP 和 SIGINT、SIGTERM 一樣正常停止。〔已實作〕O14，2026-10-28、10-29。

**依據**
- 開發者：「沒 run 當然就是通過」。
- SIGHUP 原本沒處理，收到就直接結束：table 留著、Suricata 跟著結束，drop 模式下所有轉送流量被丟到 wnc-gw 重啟為止，而且沒有 log。SSH 斷線就會送 SIGHUP。
- Docker 驗證：`kill -HUP`、強制關掉執行 `run` 的終端機、輸出經過管線，三種都正常收尾。測的時候發現終端機斷掉後 `eprintln!` 會 panic，改成寫不出去的 log 就丟掉。Pi：經過 `ssh -tt … sudo` 斷線也正常停止。

---

## 15. 執行中監控：conntrack 表、漏掉的複本

**決定**：`run` 每 10 秒用 ctnetlink 讀 conntrack 的筆數、上限和丟包計數；ids 時每 10 秒讀 Suricata 的 netfilter socket 的 Drops，增加就記 WARN。〔已實作〕2026-10-29。

**依據**
- conntrack：10,000 pps 的掃描 8 秒就把表塞滿（上限 65,536），所以 10 秒讀一次；到 90% 記 WARN、丟包或 early drop 增加記 WARN。
- 漏掉的複本：Suricata 自己的統計不算 NFLOG socket 丟掉的複本。驗證時 kernel 的 Drops 和 wnc-gw 記的 `missed` 完全相同（Docker 53,425；Pi 28,016）。
- 成本：讀一次約 340 µs（Pi），每 10 秒一次可以忽略。

---

## 16. Suricata 8.0.7，最低要求 8.0

**決定**：用 trixie-backports 的 8.0.7。最低要求 8.0，低於時 doctor 報 error、`run` 不啟動〔已決定，未實作〕。2026-10-20、10-30。

**依據**
- 7.0 已在 2026-07-07 EOL。
- 2026-11-03 在 8.0.7 重量（`tests/ids_inline/results/inline2.kvl` 等，和 7.0.10 對照）：1 個 queue、full 時多數 scenario 每個封包變便宜（最多約 −15%），Honeypot-7-1 貴 16%、42-1 貴 7%；載入完整規則的記憶體多約 170 MB（1,358–1,396 MB），就緒從 34 秒變 38 秒。信任省下的量和 7.0.10 相同。

---

## 17. XDP 預設原則、fast path 用 tc eBPF

**決定**
- `xdp = auto`〔預設〕：網卡有 native XDP 才掛 XDP，否則掛 TC；不會自動選 generic XDP。doctor 已會判斷每個 port 用哪一種，核心 eBPF 程式本身〔已決定，未實作〕。2026-10-24。
- fast path（已信任的 flow 直接轉送）用 tc eBPF，不用 XDP。〔已決定，未實作〕2026-10-20。
- XDP 只負責算特徵（GRO 合併前的原始 frame，大小和 IAT 準），之後可能加 ban；轉送和 trust 一律在 TCX，有 native XDP 的硬體上也一樣。`xdp` 設定改指特徵程式掛在哪。〔已決定，未實作〕2026-11-14。
- 接下來的順序：eBPF 骨架 → trust 從 netfilter 搬到 TC（fast path）→ 算特徵送 user space，和 edge AI、雲端一起做。〔已決定〕2026-11-14。
- 核心 eBPF 程式用 Rust（aya-ebpf），排在 TCX 第一；授權先用 GPL 相容的開源授權（字串待定，建議 `Dual MIT/GPL`），之後要閉源再改。〔已決定〕2026-11-14。
- 骨架（步驟 A1）〔已實作〕2026-11-14：`run` 裝好 table 後把核心程式掛到兩個 port 的 TCX ingress 第一位，只計數、回傳 NEXT；不 pin（wnc-gw 結束或被 `kill -9` 時 kernel 自動卸下）。ELF 用 `Dual MIT/GPL` 嵌進 wnc-gw。**掛不上時記 ERROR D001、照常執行**（我替開發者選的：程式現在不改變轉送；之後 fast path 掛不上時，信任仍由 netfilter 的 ct mark 處理，只是比較慢）。Docker、Pi 6.18（沒有 vmlinux BTF）都驗過。
- 揭露別的 TCX 程式（步驟 A2）〔已實作〕2026-11-14：doctor 列出每個 port 的 TCX ingress（D002 排在前面、D006 不是 wnc-gw 的、D004 查不了、D005 沒有 TCX），run 每 10 秒確認核心程式還在第一位（D002、D003，只在改變時記，不自動重掛），全部是 warning。查詢自己呼叫 `bpf(BPF_PROG_QUERY)`（新增一處 `unsafe`，開發者同意），只要 `CAP_NET_ADMIN`，之後的 privd 也能用；aya 的 `query_tcx` 要 `CAP_SYS_ADMIN`，沒有用。
- **trust 搬到 TC（步驟 C）〔已實作〕2026-11-14**：核心程式查 trust map（`gw-common` 的 `FlowKey`：五元組 40 bytes；每個方向一筆，HASH 32,768 筆；value 是封包數、bytes、最後時間、方向，另外預留 RQ3 第 4 項的欄位），查到就 redirect：bridge 用 `bpf_redirect`；routed 減 TTL（IPv4 用 `l3_csum_replace` 修 checksum，TTL ≤ 1 交回 kernel）再 `bpf_redirect_neigh`。廣播／多播、IPv4 分片、TCP 的 SYN／FIN／RST 交回 kernel。寫入由 `LocalPrivd` 負責（它持有核心程式）；`wnc-gw trust` 經 `/run/wnc-gw/control.sock`（0600、`SO_PEERCRED` 只收 root 或 run 的帳號）請 run 寫，`add` 先用 ctnetlink 確認連線存在而且有 forwarded 位元（送給 gateway 自己的連線 redirect 出去會錯）。自動信任的狀態機：已信任的連線不在 conntrack 表裡（UDP 逾時）或換了 entry（控制封包建了新的）也留到 TTL 再刪 map。核心程式掛不上時沒有信任，自動信任關閉（T014）。
  - Docker（routed testbed，`tests/ebpf/fastpath_docker.sh all`）：TCP、UDP 信任期間 forward chain 的 counter 停住（65 → 65、32 → 32），`trust del` 後恢復；srv 收到的 TTL 是 63；160 行／160 個全部收到；port 重用時信任被刪；送給 gw 自己的連線 `is not forwarded by the gateway`；nobody `permission denied`；run 沒在跑 `wnc-gw run is not running`。自動信任（`protection_docker.sh autotrust`，ids、ips）和 11/04 的結果相同。沒有 CAP_BPF 時 D001＋T014。
  - Pi（bridge，`tests/ebpf/core_pi.sh fastpath|auto`）：IPv4 TCP、UDP、IPv6 TCP 都在信任期間停住、`del` 後恢復，TTL／hop limit 64（bridge 不減）；自動信任的 ids chain 停在 47，TTL 到期再信任，FIN 的 alert 撤銷。
  - 還沒做：手動信任的閒置清除（連線結束後 entry 留到 `del`、新 SYN 或 run 停止）；用 wnc-gw 本身在 Pi 實體網卡重量（E1 是 bench 的 V4）、很多條信任 flow、routed 的 Pi 量測。
- 成本（步驟 A3）〔已量〕2026-11-14（`tests/ebpf/README.md`，Pi 4、1000 MHz、veth、10 kpps）：進 TCX 本身約 0.52 µs／封包（整台 CPU，同一輪相減，標準差 0.07）；程式本身（bpf_stats）計數 +47 ns、解析 header＋五元組查一次空的 hash map +449 ns。現在的核心程式約 0.57 µs、加上 fast path 每個封包一定要做的查表約 1.0 µs，每個封包都要付；信任的封包約 14 µs、全部檢查 55–61 µs。

**依據（設計，沒有在 Pi 上量過）**
- generic XDP 比 TC 差：省不到建 skb 的成本，可能要重新配置並複製封包，而且整張網卡會跳過 GRO。
- Pi 4 的 bcmgenet 和常見的 USB 網卡驅動（r8152、lan78xx、smsc95xx）都沒有 native XDP（原始碼確認），所以 Pi 上一律是 TC。
- tc 而不是 XDP：XDP 只有 ingress、有些硬體不支援；tc ingress 比 netfilter 早執行，信任的 flow 繞過 netfilter 時 tc 的特徵計算仍看得到這些封包。

**限制**：照 CLAUDE.md 第 6 條要量，但要等核心 eBPF 程式寫出來；有 native XDP 的硬體上 XDP 對 TC 的差距也還沒量。

---

## 18. log：只印到 stderr

**決定**：wnc-gw 用 tracing 印到 stderr（`--log-format json` 可以給程式讀），不自己寫檔；Debian 上用 systemd 的 `LogNamespace=wnc-gw` 讓 log 持久保存〔已決定，未實作〕。O15，2026-10-26。

**依據**：Raspberry Pi OS 的 journald 設成 `Storage=volatile`，重開機後 log 就消失，查不到 Suricata 什麼時候掛掉；把整個系統改成 persistent 會讓所有服務都寫 SD 卡，自己的 namespace 只影響 wnc-gw。

---

## 19. 3d：讀 Suricata 的 alert、自動信任

**決定**（O22，2026-11-04，3d 的步驟 1）〔已實作〕：
- alert 從 suricata.yaml 設定的 eve-log 檔讀（enabled、filetype regular、types 有 alert），只讀上次之後新增的部分。
- 每 `eve_interval` 秒（預設 0.5，0.05–10，可以有小數）讀一次（poll）。設定原本是 `eve_interval_ms`，同日改成秒，和其他時間設定一致（開發者：「統一改秒好了，這樣比較直觀」）。原本另有 `eve_watch = "inotify"`，Pi 量測後刪掉（2026-11-04，開發者：「poll 是最佳解，沒理由用 inotify」）。
- 觀察期間的封包數和 bytes 之後用 conntrack 計數，EVE 只讀 alert。
- wnc-gw 的 log 只放重要資訊和出事時能定位的資訊：每筆 alert 是 DEBUG（`--log-level debug`），每 60 秒有 alert 時一行 INFO 摘要；講到連線的都帶五元組和 `flow_id`。

**選項**：alert 從 unix_stream 讀；wnc-gw 強制 Suricata 另外輸出一個只有 alert 的檔；讀的時機用 inotify（量過，刪掉）。

**依據**
- unix_stream 的行為（Docker、Suricata 8.0.7，`tests/eve_output/README.md`）：
  - 離線（`-r`）時 socket 是 blocking：讀取端停多久，Suricata 就停多久。
  - live（NFQ、NFLOG）時是 non-blocking：讀取端停 15 秒，封包照常轉送（ips 的 ping 0 丟），但丟掉 4,833 個事件，只在 Suricata 結束時記一行 WARN，執行中沒有計數。
  - alert 被默默丟掉，就等於有問題的連線可能被信任，所以不用 unix_stream。寫檔不會丟，成本也只差約 7%（Pi 離線：每個 flow 事件寫檔 103 µs、unix_stream 95 µs）。
- 不強制另外輸出：Suricata 的 `--include` 會整個蓋掉 `outputs` 清單（測試用的 af-packet 設定、wnc-gw 的 nflog 設定都是靠這個行為整段換掉），使用者原本的輸出會不見；用 `--set` 指定清單位置又依賴清單順序。所以改由 doctor 檢查 yaml，沒有寫 alert 的輸出就給 warning。
- 觀察用 conntrack 計數而不是 EVE flow：EVE 的 flow 事件要等連線結束或逾時才輸出，長連線等不到；`nf_conntrack_acct` 每個封包多 0.1–1.3 µs（`tests/cpu_alloc` 實驗 3）。
- 原本 poll 和 inotify 都做成設定（開發者的要求），Pi 量測（下面「成本與延遲」）後只留 poll：alert 多時 poll 便宜 3 倍；inotify 只省閒置的 0.17 ms／秒和 alert 稀疏時的延遲，而自動信任要觀察 5 秒、信任後只剩 SYN/FIN/RST 會產生 alert、ips 的擋由 Suricata 自己做，都不需要毫秒級的延遲。要更快就調小 `eve_interval`（成本沒量）。刪掉也拿掉了唯一的 `unsafe`（`kernel/inotify.rs`）。

**功能驗證**（Docker，`tests/ids_inline/protection_docker.sh alerts`；刪掉 inotify 前 poll 和 inotify 各一次，刪掉後再跑一次）：
- fast.log 的 5 筆 alert（ICMP 2、TCP payload 3）和 wnc-gw 的 DEBUG 筆數相同。
- `mv eve.json eve.json.1` 再對 Suricata 送 SIGHUP（輪替）：wnc-gw 先讀完舊檔、再從頭讀新檔，記一行「was replaced」。Suricata 重開檔案之前會繼續寫在舊檔，所以路徑暫時不見時 wnc-gw 繼續讀手上的舊檔。
- `: > eve.json`（截斷）：記一行「was truncated」，之後的 alert 照樣讀到。
- 停止時一行 INFO `suricata raised alerts alerts=5 connections=4`（同一條 flow 的兩個方向用 `flow_id` 算成一條）。
- 啟動時沒有「讀不到檔案」的 WARN：Suricata 第一次就緒才開始讀，那之前不會有封包，也就不會有 alert。
- 只輸出 dns 的 eve-log 時，doctor 印 `no alerts` 並給 warning。

**Pi 驗證**（2026-11-04，Pi 4 鎖 1000 MHz，`tests/ids_inline/protection_pi.sh alerts`；刪掉 inotify 前後都跑過）：和 Docker 相同，5 筆都讀到，換檔、截斷後照樣讀。

**成本與延遲**（Pi，`tests/ids_inline/autotrust_cost_pi.sh eve|latency`；UDP 每個封包帶一筆 alert；CPU 是 wnc-gw 所有執行緒的 schedstat；延遲是 wnc-gw 的 log 時間減 eve 的 timestamp；結果 `tests/ids_inline/results/autotrust_cost.kvl`；inotify 是刪掉前的版本，程式留在 `~/datasets/throughput/func_20261104/worktree_with_inotify.diff`）：

| | poll（每 500 ms） | inotify（最短間隔 500 ms） |
|---|---|---|
| 沒有 alert 時 wnc-gw 的 CPU | 0.37 ms／秒 | 0.20 ms／秒 |
| 每秒 100 筆 | 2.2 ms／秒 | 6.5 ms／秒 |
| 每秒 1000 筆 | 16.3 ms／秒（每筆 16 µs） | 50.8 ms／秒（每筆 51 µs） |
| 延遲，每秒 1 筆 | 241 ms（送的節奏剛好和 poll 對齊；隨機時是 0–500 ms） | 中位數 2.5 ms |
| 延遲，每秒 10 筆 | 中位數 250、最大 450 ms | 中位數 231、最大 461 ms |

- inotify 有 alert 時比 poll 貴 3 倍。監看的是整個 log 目錄，Suricata 每筆 alert 會交替寫 eve.json 和 fast.log；kernel 只合併「和上一個相同」的事件，所以每次寫入都會叫醒 wnc-gw。每秒 1000 筆時 wnc-gw 每秒被叫醒 1966 次（poll 是 4 次），每次約 18 µs。最短間隔只限制多久讀一次檔案，沒有限制被叫醒幾次。
- 改成只監看 eve.json 本身的寫入（連續的寫入會合併）可以把叫醒次數降下來，但最多追平 poll。
- inotify 只在 alert 稀疏時延遲比較低；alert 頻繁時兩種都受 500 ms 的間隔限制。所以刪掉 inotify。

**限制**：log 保存多少還沒做：wnc-gw 自己的 log 要等 systemd unit，Suricata 的 eve.json、fast.log、stats.log 目前沒有上限。

**腳本與結果**：`src/ids/eve.rs`、`src/monitor/alerts.rs` 和對應的單元測試；`tests/ids_inline/protection_docker.sh alerts`、`protection_pi.sh alerts`、`autotrust_cost_pi.sh eve|latency`；`tests/eve_output/`。

### 自動信任（步驟 2、3）

**決定**（O22，2026-11-04）〔已實作〕；數值是建議值，待開發者確認：
- `[trust] auto`，預設 false（只能手動 `wnc-gw trust`）。打開後，Suricata 在檢查的期間，一條連線兩個方向都有 `min_packets`（預設 10）個封包、觀察滿 `min_age`（預設 5）秒、而且沒有 alert，就信任 `ttl`（預設 900）秒；`check_interval`（預設 5）秒讀一次 conntrack。只信任 TCP（已建立）和 UDP。
- 有 alert：還在觀察的連線之後都不信任；已信任的立刻撤銷（記 WARN）。alert 比第一次觀察早到也算（記住 10 分鐘）。
- TTL 到期：取消信任，回到檢查，要再觀察一次才會再信任。
- Suricata 停止時，觀察到一半的連線全部重來（那段時間沒有 alert 可以參考）；已信任的照常到期。
- **沒有即時的 alert 就不新增信任**（2026-11-14，開發者：「要否則會出現被繞過的問題，我們要重視資安」）。原則是「alert 是唯一的『有問題』訊號，看不到它時不能用『沒有 alert』當理由信任」：
  - doctor 確定 Suricata 沒有寫 alert 的 eve-log：error（T002），run 不啟動。
  - 讀不到 Suricata 的設定而無法確認（S002、S010；run 時是 S024）：warning（T012），run 照常啟動、**關掉自動信任**，全部送檢查。不選「不啟動」：run 沒啟動時 table 不存在，routed 下 kernel 照轉，等於全部不檢查，比少了信任更糟。
  - 執行中 EVE 讀不到（E002）或落後（E003）：暫停新增信任（T013），觀察中的連線重新觀察；已信任的照常到期，之後讀到的 alert 照樣撤銷。恢復時記 INFO。
  - 修正前的漏洞：doctor 在 `--build-info` 或 `--dump-config` 失敗時整段跳過信任檢查，run 照常開自動信任，卻讀不到 alert（subagent 在 Docker 上用假 Suricata 重現）。
  - 成本：都是啟動時或每次讀 EVE 時的布林判斷，不在封包路徑上，沒有另外量。
- 只看經過 gateway 的連線：forward chain 在連線第一次經過時把 ct mark 的 `0x40000000` 設上（只寫一次），wnc-gw 用 ctnetlink 依這個位元列連線（kernel 端過濾），gateway 自己的連線（例如 SSH）不會被算進來。
- 寫入走 `agent::Privd` trait（架構 §3：privd 的介面先定成 trait、方法隨功能才加），現在的實作 `LocalPrivd` 在同一個 process 裡直接用 ctnetlink。
- 預設值的理由：
  - 預設關：信任是 gateway 最危險的動作（架構 §5 第 6 條），要使用者明確打開；doctor 開著時一律 warning。
  - `ttl` 900 秒：比 Suricata 預設的 `flow-timeouts.tcp.established`（600）長。信任結束時 Suricata 已經忘了這條連線，會當成從中間開始接手；如果還記得，序號過時，ips 會自己丟封包（O21 的實驗 3b）。ips 模式下 `ttl` 不夠長時 doctor 給 warning。
  - `min_packets` 10、`min_age` 5 秒：要比讀 alert 的延遲（`eve_interval`，0.5 秒）長很多，又不能長到短連線都等不到。沒有實驗依據。

**功能驗證**（Docker，`tests/ids_inline/protection_docker.sh autotrust`，設定改成 5 個封包、2 秒、TTL 10 秒、每秒檢查）：

| | ids | ips |
|---|---|---|
| 乾淨的長連線（每 0.1 秒一行，25 秒） | 約 3 秒後信任；ids chain 的計數 65 → 65 停住；TTL 到期後再信任一次 | 同左（45 → 45） |
| 帶攻擊標記的連線（第一段資料就有標記） | **先被信任，連線結束時才因 alert 撤銷** | 被觀察之前就有 alert，一直不信任 |
| 已信任的連線結束（FIN 觸發的測試規則） | alert → 撤銷，記 WARN | 同左 |

- doctor：`nf_conntrack_acct` 是 0 時報 error；ips、`ttl` 600 時警告（Suricata 的 established 逾時也是 600）。
- **ids 模式下 alert 晚到**：同一條連線在 ips 立刻有 alert，在 ids 要到連線結束才有。[推測] ids 模式的 Suricata 依 TCP 重組處理複本，raw stream 的比對要累積到 `stream.reassembly.toserver-chunk-size`（Debian 預設 2560 bytes）或連線結束才做；這條連線之後每秒只送 50 bytes，所以要等到 FIN。可能的做法（待決）：ids 時要求送往 server 的資料超過 chunk 大小才信任、調小 chunk（Suricata 多花 CPU）、或加大 `min_age`。

**Pi 驗證**（2026-11-04，Pi 4 鎖 1000 MHz，`tests/ids_inline/protection_pi.sh autotrust`，同樣的設定）：ids、ips 的結果和上表相同；ids 下帶標記的連線一樣先被信任、之後才撤銷。doctor 的 `nf_conntrack_acct` 檢查相同。routed 模式（veth）的 ids、ips 也測過：信任、有 alert 不信任都正常。demo 全流程見 `tests/demo/README.md`。

**成本**（Pi，`tests/ids_inline/autotrust_cost_pi.sh saving|check`）：
- 省多少：8 條 TCP 連線，共 4,000 封包／秒，ids，信任用預設值。Suricata 從 100.5 降到 13.6 ms／秒（剩下的是 Suricata 閒置時本來就有的成本），wnc-gw 從 0.5 升到 1.9 ms／秒。合計每秒省 85 ms，等於每個封包省 21 µs。
- 每次讀 conntrack：
  - 固定約 7 ms。kernel 要掃過整個 hash table：65,536 個 bucket，全機共用，跟 netns 裡有幾筆無關。用 conntrack 指令對照，空表時 dump 比只數筆數多 6.6 ms。
  - 每條經過 gateway 的連線再加約 9.4 µs。`check_interval` 1 秒時，1,000 條是 17 ms／秒，10,000 條是 101 ms／秒。
  - 換算到預設每 5 秒一次：連線很少時 1.4 ms／秒，1 萬條時約 20 ms／秒（一顆核心的 2%）。
- 讀表是同步的，讀的期間 wnc-gw 的事件迴圈會停住：1 萬條約 0.1 秒，6 萬條〔推算〕約 0.57 秒（§7：整表 dump 每筆 7.25 µs，其餘是 wnc-gw 解析和觀察表的成本）。可能的改法（待決）：讀表放到另一個執行緒；或改用 conntrack 的 NEW／DESTROY 事件維護觀察表，只查觀察中連線的計數。
- forward chain 多的那條 forwarded 規則沒有單獨量；同類的 ct mark 規則以前量過，每條每個封包 52–159 ns（§6）。

**腳本與結果**：`src/agent/`（`trust.rs`、`mod.rs`）、`src/datapath/firewall.rs`（`FORWARDED_MARK`、`forwarded()`）、`src/kernel/conntrack.rs`（`Counters`）和對應的單元測試；`tests/ids_inline/protection_docker.sh autotrust`、`protection_pi.sh autotrust`、`autotrust_cost_pi.sh saving|check`。

---

## 20. 還沒決定、但已經有實驗的事項

| 事項 | 目前的數據 | 還缺什麼 |
|---|---|---|
| 預設開幾個 queue／group、網卡中斷和 RPS 怎麼放 | 方案 B、PAUSE 關（`tests/cpu_alloc/README.md`）：ids 用 RPS（CPU1–3）＋3 個 group 最好（17-1 轉送 120、檢查 80 kpps），不開 RPS 時轉送只有 30–40；ips 用「IRQ 搬到 CPU1＋3 個 queue」兩個 pcap 都到 60，1 個 queue 只有 20–30；queue／group 越多每個封包越貴（ids worker 15.6 → 29.2 µs） | 有 18% 流量從 USB 網卡進來時 ids 只到 50（推測是 eth1 的中斷在 CPU0、沒開 RPS），eth1 開 RPS 沒量 |
| mode 的預設（§1） | Pi 實體網卡（2026-11-04）：routed 的轉送每個封包少約 2 µs，只轉送少 15–20%（A0 容量 100 → 150 kpps），有檢查時少 2–9%、容量一樣；routed 不轉送非 IP 的封包 | 開發者決定：效能差異主要在只轉送、信任的流量；routed 要改網段和上游路由（部署面） |
| ids 一個封包複製多份（Suricata、edge AI、雲端特徵） | Pi（2026-11-04，`tests/cpu_alloc/README.md` 實驗 5）：kernel 每多一份，小封包 +3–5 µs、大封包 +7–8 µs；多 2 份轉送容量少約 2 成。只複製前 128 bytes 時大封包幾乎不加成本。user space 分發在小封包時比 kernel 複製省（A0 +5.8 對 +10.6 µs），大封包時比較貴 | 讀取端真的處理資料時的成本；要哪種做法看各用途要整個封包還是只要 header |
| Suricata 要不要輸出 EVE flow 事件 | 3d 的觀察已決定用 conntrack 計數（§19），但 Debian 預設的 eve.json 仍輸出 flow、dns、http 等事件。Pi 離線時每個 EVE flow 事件約 100 µs（筆電 7 µs），主要是 Suricata 自己的 CPU；開 `nf_conntrack_acct` 每個封包多 0.1–1.3 µs（≤ 2%），dump 每筆 7.25 µs（`tests/eve_output/README.md`、`tests/cpu_alloc` 實驗 3） | live 模式下每個 EVE 事件的成本 |
| 自動信任的預設值（§19） | Docker、Pi 功能驗證；Pi 上 4,000 封包／秒時每秒省 85 ms（每個封包 21 µs）；數值是建議值 | 開發者確認；真實流量下會不會信任到不該信任的連線 |
| ids 模式下 alert 比 `min_age` 晚到（§19） | Docker、Pi：帶攻擊標記的連線在 ids 先被信任、結束時才撤銷，ips 一開始就不信任 | 確認原因（重組的 chunk 大小）；選做法：要求送往 server 的資料超過 chunk、調小 chunk、加大 `min_age` |
| 每次讀 conntrack 會停住事件迴圈（§19） | Pi：固定約 7 ms（掃 65,536 個 bucket）＋每條連線 9.4 µs；1 萬條約 0.1 秒 | 選做法：放到另一個執行緒、改用 conntrack 事件；連線很多時的實測 |
| log 保存多少 | 沒有實驗 | wnc-gw 的 log 要等 systemd unit；Suricata 的 eve.json 等要選做法：限制事件種類、Suricata 輪替加上刪舊檔、logrotate |
| edge AI 的 CPU 分配（O19） | 純運算的替身綁在 Suricata 以外的核心時 0 干擾；共用核心時即使 `SCHED_IDLE` 也丟 28–47%；吃記憶體的負載綁在別的核心仍讓 Suricata 每個封包貴 2 倍；6 MiB 的 MLP 貴 15–17%；IRQ 搬到 CPU1 後 CPU0 可以放 AI | 合作方的真實模型；傳輸方式、權限 |
| 已信任 flow 的部分檢查（O20）、稽核前要不要讓 Suricata 忘掉 flow（O21） | Docker 實驗（`tests/partial_inspect/README.md`）：只檢查每段開頭可以抓到後段攻擊，約送 5–8% 的封包；固定長度會被「先塞資料再攻擊」繞過，隨機長度 83–90% 抓得到 | tc eBPF 的實作成本、Pi 上的量測 |
| 拆成多個 process（O1） | 沒有實驗 | 做控制迴路之前要決定 |
| 步驟 C：trust 只放在 TC 的 map，還是 map＋ct mark（2026-11-14 已決定：只放 TC，§5） | E1（`tests/ebpf/README.md`，Pi 實體網卡、bridge、單一大 flow）：信任的封包 TC redirect 比 ct mark 少 5–6 µs（−39～−46%），IRQ 搬到 CPU1 時容量 80 → 150 kpps；兩種做法查到時的每封包成本相同。E2：map 寫一筆 2.8 µs、刪一筆 2.6 µs，ctnetlink 14.5 µs（批次 2.4） | 開發者決定；很多條信任 flow、routed 模式還沒量 |

**還沒解釋的量測**
- 8.0.7 下 wnc-gw 和直接跑 Suricata NFQ 的每個封包成本比值是 0.81–1.21（7.0.10 時 0.97–1.01）：60-1 wnc-gw 便宜 18%，Honeypot-7-1 full 貴 21%。wnc-gw 多傳了 midstream、exception policy、delayed-detect、fail-open 等設定，原因沒查；這組每格只量 1 次（`tests/ids_inline/results/compare2.kvl`）。
- af-packet IPS 比 NFQ 便宜 0–20%（8.0.7），但看不到 ct mark，所以沒有選（§2）。

## 21. 設定：只保留相關的值，不相關的欄位直接報錯

**決定**（2026-11-14，開發者：「不同的 mode、protection 應該只能存在他相關的設定，不然會出現 bug」）〔已實作〕：
- 讀設定時，設了用不到的欄位就報錯（C004），doctor 和 run 都不往下走：`suricata.queue` 只能配 `protection = "ips"`、`suricata.group` 只能配 `"ids"`、`trust.min_packets`／`min_age`／`ttl`／`check_interval` 只能配 `trust.auto = true`。和 `deny_unknown_fields`（打錯欄位名稱就報錯）同一個理由：設了沒作用，使用者會以為生效了。
- 程式內部的型別也只放相關的值：`SuricataSettings.delivery` 是 `Delivery::Queue(QueueRange)` 或 `Delivery::Copy(GroupRange)`，沒有另一個；`TrustSettings` 是 `Manual { source }` 或 `Auto(AutoTrust)`，手動時程式拿不到 `min_packets`，信任的計時器也不會建立。
- `mode` 目前沒有只屬於 bridge 或 routed 的欄位；之後加的時候照同樣方式（型別分開、另一個模式設了就報錯）。
- 考慮過的其他做法：doctor 只給 warning（切換 ids／ips 做實驗比較方便，但容易沒注意到）；改成 `[protection.ips]` 這種格式（格式本身就排除，但現有設定檔、腳本、文件都要改）。
- 成本：只在讀設定時判斷，沒有執行期成本。省下的記憶體只有幾個欄位，主要的好處是不會讀到沒作用的值。
- 現有的設定檔和腳本（`docker/wnc-gw/`、`tests/demo/demo.sh`、`tests/ids_inline/*.sh`、`tests/cpu_alloc/`）都只寫相關的欄位，不受影響。

