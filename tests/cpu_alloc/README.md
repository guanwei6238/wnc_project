# tests/cpu_alloc — 同一台 Pi 上，網卡中斷、轉送、Suricata、edge AI 怎麼分 CPU

問題（2026-11-02）：地端會有 rule（Suricata）和 edge AI，edge AI 跑在 gateway 同一台機器上（`.claude/skills/gateway-architecture/references/decisions.md` O19）。Pi 4 的 4 顆核心要分給網卡中斷、轉送、Suricata 和 edge AI。
- 實驗 1：CPU 0 是所有網卡中斷所在、也是 10/30 量到的轉送瓶頸。RPS、搬 IRQ、threaded NAPI 能把天花板推多高？
- 實驗 2：edge AI 和 Suricata 搶 CPU 時，三種分配做法下各損失多少？

實驗計畫先給一個 subagent 審查過（審查意見：CPU 改用 `/proc/stat` 的「經過時間 − idle」、要算 qdisc 丟包、eth0 只有 IRQ 29 有流量、xhci 的 IRQ 搬不動、實驗 2 改成比較三種分配做法）。

## 量法

- 平台：Pi 4 Model B 4 GB、**鎖 1000 MHz**、governor performance、kernel 6.18.50+rpt-rpi-v8、Suricata 8.0.7；系統的 suricata.service 停掉。
- 拓樸：方案 B（`tests/ids_inline/planb_pi.sh`）。筆電 USB 網卡 ── Pi eth0 [netns wgw: br0] Pi eth1.20 ── 筆電 eno2.20；筆電的 tcpreplay 在 `wnc-gen` 容器、依 MAC 從兩張網卡送。
- **eth0 的 Ethernet PAUSE 關掉**（`alloc_pi.sh pause off`）：開著的話 Pi 會讓筆電暫停，看不到丟包（10/30 的發現）。實驗結束後改回 on。
- 工作負載：
  - B0 只有 bridge（沒有 wnc-gw、沒有 nft 規則）
  - B1 wnc-gw `protection = "ips"`、full rules（ET Open 2026-10-30 快照）、2 個 queue，S_m17（掃描，99.8% 純 SYN、很多 flow）
  - B2 wnc-gw ips、1 queue、全部信任（ct mark），S_m60（一條 UDP 連線為主）
  - 每個 pcap 約 20 萬個封包、平均 60–71 bytes；B0、B2 用 `--loop` 讓每個速率點至少 5 秒
- 放置（`alloc_pi.sh place`）：
  - A0 預設：IRQ 29（eth0 的 RX 和 5 個 TX ring）、xhci 的 IRQ 30 都在 CPU 0，RPS 關
  - R1：eth0 rx-0 的 RPS 到 CPU 1
  - R123：RPS 到 CPU 1–3
  - I1：IRQ 29 搬到 CPU 1
  - T1：eth0 threaded NAPI，NAPI kthread 綁 CPU 1
  - xhci（USB 網卡 eth1）的 IRQ 是 brcmstb MSI，不能搬；S_m17 99.8%、S_m60 99% 的封包從 eth0 進來，所以 eth1 不設 RPS。
- 每個速率點前後各讀一次 `alloc_pi.sh snap`：
  - 各 CPU 的忙碌時間 = 經過時間 − idle − iowait（`/proc/stat`；NO_HZ 下 idle 是精確的，而且 idle 時處理的中斷不算 idle）
  - softnet（backlog 丟包、squeeze、RPS 次數）、IRQ 29/30 與 NET_RX/NET_TX 的每 CPU 次數
  - qdisc 丟包（eth0、eth1.20、eth1）、方案 B 的計數（rx/tx、網卡 miss/drop、nfq 丟包）
  - Suricata worker 執行緒與 burner 的 schedstat
  - 溫度、throttled、時脈、swap
- 處理不過來而丟（cap_loss）= nfq queue 滿 + qdisc 丟 + max(沒收到 + softnet backlog 丟, 網卡 miss + rx_dropped)。網卡的 rx_dropped 已含 backlog 丟的，所以兩邊取大的。**容量 = cap_loss ≤ 0.1% 的最高實際速率**；連續兩個速率 > 1% 就停。
- loss_pct 是端到端（送出 − 轉送出去），包含 Suricata 自己的判決丟包（S_m17 是重播，約 26–28% 被 Suricata 以 stream 錯誤丟掉，和容量無關，10/29 已知）。ips 下 wnc-gw 啟動後的**第一個速率點**判決丟包比較多（S_m17 約 48%、S_m1 約 30–37%，之後的點 26–28%、4–13%）；容量只看 cap_loss，不受影響。
- µs/封包（全機）= 4 顆 CPU 忙碌時間總和 ÷ Pi 收到的封包；這個數字也包含窗口裡 ssh 讀計數的背景（每點約幾十 ms），在低速時會偏高一點。

## 檔案

| 檔案 | 用途 |
|---|---|
| `alloc_pi.sh` | Pi 端：snap、place、pin_suricata、pause、burner_start／stop |
| `alloc_run.sh` | 筆電端：sweep（實驗 1）、ai（實驗 2）、exp1、exp2、exp1b、exp2b、exp1c、exp1d、exp3（acctpt）、exp4（routed 對 bridge）、exp5–exp8（多份複本） |
| `alloc.py` | 兩次 snap 相減、彙整成表（`cap`、`ai`、`modes`、`copies`）；ids 另算複本丟失（copy_loss）和檢查容量，多份複本另算讀取端的丟失（xcopy_loss） |
| `burner.c` | edge AI 替身：cpu（L1 內運算）、mem（STREAM triad，每執行緒 3×8 MiB）、mlp（float32 MLP 256-1024-1024-256，權重約 6 MiB） |
| `fanout/` | 實驗 5 的 user space 分發程式（Rust）：從一個 NFLOG group 收複本，分給 N 個讀取執行緒（各一個 8 MiB 環狀緩衝，每 1 ms 讀一次），統計寫在 `/dev/shm/fanout.stats` |

原始資料：筆電 `~/datasets/throughput/cpu_alloc/alloc.kvl`（每點一行，含 exp1b、exp2b、exp1c、exp1d、exp3）、`main.log`、`ext.log`、`exp1c.log`、`exp1d.log`、`night_laptop.log`（exp3）；實驗 4、5 在 `night1104.kvl`、`night1104.log`、`night1104b.log`、`night1104d.log`，routed 丟包的診斷在 `routed_diag.log`、`routed_ct_diag.txt`、`diag.kvl`；複本在 `results/`。

## 實驗 1 結果（2 輪，數字是「輪 1／輪 2」）

### 容量（cap_loss ≤ 0.1% 的最高速率，kpps；速率間隔 B0 50k、B1 5k、B2 20–30k）

| 放置 | B0 只有 bridge | B1 檢查（ips、2 queue） | B2 全部信任（單一 flow） |
|---|---|---|---|
| A0 預設（中斷都在 CPU0） | 100／100 | 60／60 | 50／50 |
| I1（IRQ 29 → CPU1） | 100／100 | 60／55 | 80／80 |
| T1（threaded NAPI → CPU1） | 100／100 | 55／60 | 80／80 |
| R1（RPS → CPU1） | 150／150 | 50／60 | 80／50 |
| R123（RPS → CPU1–3） | **300／300** | 45／45 | 80／80 |

第一個丟包點的原因：B0、B2 都是網卡收不完（`nic_drop`，CPU0 或接手的那顆滿了）；B1 在 A0、I1、T1 是網卡、在 R1、R123 是 Suricata 的 queue 滿（`nfq_drop`）。

### 每個封包的 CPU（µs，全機與各 CPU；在大家都不丟包的速率）

| 工作負載 | 放置 | 全機 | CPU0 | CPU1 | CPU2 | CPU3 |
|---|---|---|---|---|---|---|
| B0 @100k | A0 | 9.5 | 8.6 | 0.4 | 0.3 | 0.2 |
| | I1 | 9.2–9.4 | 0.6 | 8.0 | 0.3 | 0.2 |
| | R1 | 9.9 | 3.5 | 6.0 | 0.3 | 0.2 |
| | R123 | 11.0 | 3.5 | 2.6 | 2.6 | 2.4 |
| B1 @40k | A0 | 54–55 | 17 | 10–16 | 13 | 8–14 |
| | R123 | 60 | 17 | 13 | 13 | 17 |
| B2 @50k | A0 | 14.1 | 12.2 | 0.6 | 0.7 | 0.7 |
| | I1 | 13.9–14.6 | 1.2 | 11.6 | 0.7 | 0.7 |
| | R123 | 14.6–14.9 | 4.1 | 0.7 | 9.5 | 0.6 |

### 延伸：3、4 個 queue（`exp1b`，B4 = 3 queue、B5 = 4 queue，S_m17，2 輪）

| 放置 | 3 queue | 4 queue | 全機 µs/封包 @50k |
|---|---|---|---|
| A0 | 60／60 | 55／55 | 57.9（3q）、60.4（4q） |
| I1 | 60／60 | 60／60 | 58.2、59.8 |
| T1 | 60／60 | 60／55 | 59.9、61.7 |

加 queue、搬中斷都推不過 60 kpps：每個檢查過的封包 57–61 µs，60 kpps 就要約 3.5 顆核心，**整台機器已經滿了**。queue 越多，每個封包還多花 1–4 µs。

### 解讀
- **CPU0 只是「轉送」的天花板，不是「檢查」的天花板。** 只轉送時，RPS 分到 3 顆核心可以到 300 kpps（3 倍）；RPS 本身每個封包多花約 0.5–1.5 µs（跨核心）。
- **檢查（ips、full rules）每個封包約 55–57 µs**，4 顆核心加起來的理論上限約 70 kpps；2 個 queue 實測 55–60 kpps。RPS 分到 Suricata 所在的核心反而變差（R123：45 kpps、60 µs/封包）。
- **信任的封包每個約 14 µs**（bridge + conntrack + 我們的 nft table；只有 bridge 是 9.5 µs）。和 10/28 量的「信任每封包省 39–67 µs」一致：這次是 55 → 14，省 41 µs。
- 單一 flow 的信任流量：把收封包移出 CPU0（I1、T1、R123）從 50 提高到 80 kpps；RPS 對單一 flow 只會整條送到同一顆核心。
- **對 edge AI 的意涵**：檢查流量時 Suricata 幾乎吃滿整台機器；edge AI 能用的 CPU 幾乎全部來自信任（每個信任封包省約 41 µs）。例如 40 kpps、全部檢查時約用掉 2.2 顆核心，80% 信任時只用約 0.9 顆。

### 延伸：ids（NFLOG）、1 個 queue、第二個 pcap（`exp1c`、`exp1d`，2 輪，2026-11-03）

- 工作負載：B9 = ips 1 queue；B1／B4／B5 = ips 2／3／4 queue；B6／B3／B7／B8 = `protection = "ids"`、1／2／3／4 group。都是 full rules。
- pcap：S_m17（掃描，99.8% 純 SYN，200,000 個封包只有 188 個從路由器那側來）；S_m1（49% 純 SYN，**18.4% 從路由器那側來**，這些封包從 Pi 的 eth1（USB 網卡）進來，eth1 的中斷在 CPU0、搬不動，也沒設 RPS）。
- ids 有兩個容量：**轉送容量**（cap_loss ≤ 0.1%，和 ips 同一個定義）和**檢查容量**（Suricata 漏掉的複本 ≤ 0.1%）。「≥」表示到掃描停止時（轉送已經連續兩點丟 > 1%）複本都還沒漏，檢查容量至少這麼多。

**容量（kpps；ips 是一個數字，ids 是「轉送（檢查）」；兩輪不同時寫「輪 1／輪 2」）**

| 工作負載 | S_m17 A0 | S_m17 I1 | S_m17 R123 | S_m1 A0 | S_m1 I1 | S_m1 R123 |
|---|---|---|---|---|---|---|
| ips 1 queue | 30 | 30／20 | 20 | 30／20 | 30／20 | 20 |
| ips 2 queue | 60 | 60／55 | 45 | 40 | 50 | 40 |
| ips 3 queue | 60 | 60 | 60 | 40 | **60** | 60／50 |
| ips 4 queue | 55 | 60 | 60 | 40 | **60** | 60／50 |
| ids 1 group | 30（≥60／≥50） | 40（≥60） | 120（50） | 30（≥50） | 40（60／≥60） | 50（60） |
| ids 2 group | 30（≥50） | 30（≥50） | 100／120（70） | 30（≥50） | 40（≥60） | 50（≥70） |
| ids 3 group | 30（≥50） | 30（≥50） | **120（80）** | 30（≥50） | 40（≥60） | **50（≥70／≥80）** |
| ids 4 group | 30（≥50） | 30（≥50） | 120（80） | 30（≥50） | 40（≥60） | 50（≥70） |

第一個丟包點的原因：ips 1 queue 都是 Suricata 的 queue 滿（`nfq_drop`）；ids 都是網卡收不完（`nic_drop`）。

**每個封包的 CPU（µs，@30 kpps，括號是 Suricata worker 的部分；兩輪平均）**

| 工作負載 | S_m17 A0 | S_m17 R123 | S_m1 A0 | S_m1 R123 |
|---|---|---|---|---|
| ips 1 queue | 53.3（33.6） | —（< 30k） | 56.5（32.9） | —（< 30k） |
| ips 2 queue | 54.8（34.2） | 61.0（36.9） | 58.5（34.9） | 66.9（40.0） |
| ips 3 queue | —（@50k 57.8） | 63.9（37.4） | 64.2（38.5） | 69.0（42.5） |
| ips 4 queue | —（@50k 61.0） | 65.5（41.2） | 66.7（47.4） | 70.8（47.2） |
| ids 1 group | 49.0（17.8） | 41.6（16.1） | 52.1（17.5） | 48.3（16.4） |
| ids 2 group | 52.6（19.8） | 44.2（22.8） | 56.9（19.3） | 52.0（22.2） |
| ids 3 group | 52.8（19.2） | 45.7（27.1） | 58.0（20.1） | 53.2（26.9） |
| ids 4 group | 53.2（19.0） | 47.7（29.1） | 58.8（20.5） | 55.2（31.2） |

CPU0 每個封包：ids A0 約 26–30 µs、ids R123 5–11（S_m17）／15–19（S_m1）；ips A0 約 17–28。

解讀：
1. **ids 的轉送要靠 RPS。** ids 下轉送和 NFLOG 複本都在收封包那顆 CPU 的 softirq 裡做完，A0、I1 只有 30–40 kpps；ips 的轉送在 Suricata 判決後由 worker 執行緒做，所以 ips 的 A0 可以到 60。開 RPS 到 CPU1–3 後，ids 在 S_m17 轉送 100–120 kpps。
2. **ids 的檢查容量比 ips 高**：R123 下 S_m17 1 group 50、2 group 70、3–4 group 80 kpps；ips 最好是 60。worker 的成本約是 ips 的 6 成（@30k A0：19.8 對 34.2 µs）。
3. **S_m1 下 ids 的轉送只到 50 kpps**（S_m17 是 100–120）。60 kpps 時網卡丟包、softnet backlog 沒有丟、CPU0 的 NAPI 用完額度（squeeze）330 次。[推測] 原因是那 18.4% 從 eth1 進來的封包：它們的轉送和複本全部在 CPU0 做。給 eth1 也設 RPS 可能有幫助，沒有量。
4. **ips 只有 1 個 queue 時 20–30 kpps**（一個 worker 的上限）；RPS 讓 1–2 個 queue 的 ips 變差（RPS 的處理和 worker 搶同一批核心）。S_m1 下 2 個 queue 在 A0 只有 40；兩個 pcap 都到 60 的是 **I1 + 3 或 4 個 queue**。
5. **queue／group 越多，每個封包越貴。** ids R123 @50k、S_m17 的 worker 成本：1 group 15.6、2 group 21.8、3 group 26.1、4 group 29.2 µs（每個封包只有一份複本，複本數 ≈ 收到的封包數，不是重複送）。ips 也一樣（2 → 4 queue：34 → 41–50 µs）。[推測] 每個 worker 每次讀到的封包變少、批次變小；沒有量。
6. 對預設值的意涵（還沒決定）：這兩個 pcap 下，ids 最好的組合是 RPS（CPU1–3）+ 3 group，ips 是 I1 + 3 queue；ids 有流量從 USB 網卡進來時，要另外處理 eth1 的中斷。

## 實驗 2 結果（B1 固定 40 kpps，A0 下這個速率不丟包；2 輪）

三種分配做法：
- α：中斷在 CPU0，Suricata 2 個 worker 綁 CPU1、2，AI 1 個執行緒綁 CPU3
- β：RPS → CPU1，Suricata 綁 CPU2、3，AI 2 個執行緒也在 CPU2、3 但用 `SCHED_IDLE`（只在空閒時跑）
- γ：都不綁，AI 3 個執行緒

| 做法 | AI 負載 | Suricata 丟包 % | Suricata worker µs/封包 | AI 吞吐被拖慢 |
|---|---|---|---|---|
| α | 無 | 0／0 | 37 | — |
| α | cpu（L1 內運算） | **0／0** | 37 | **0%** |
| α | mem（吃記憶體頻寬） | **31.7／31.9** | **71（變 2 倍）** | 13% |
| β | 無 | 0／0 | 37 | — |
| β | cpu，SCHED_IDLE | **29.3／28.4** | 26（被搶走時間） | 34% |
| β | mem，SCHED_IDLE | 47.4／41.7 | 27 | 23% |
| γ | 無 | 0／0 | 39 | — |
| γ | cpu ×3 | 22.2／16.6 | 42 | 20% |
| γ | mem ×3 | 54.8／57.7 | 49 | 8% |
| γ | mem ×1 | 31.3 | 72 | 13% |

### 解讀
1. **純運算的 AI 只要綁在別的核心，完全不干擾**（α-cpu：0 丟包、Suricata 每封包成本不變、AI 也沒變慢）。
2. **吃記憶體頻寬的 AI，綁在別的核心也擋不住**：Suricata 每封包成本從 37 變 71 µs（2 倍），40 kpps 就丟 32%。Pi 4 的 4 顆核心共用 L2 和記憶體頻寬（STREAM 1 個執行緒就吃到約 3.5 GB/s 的上限）。這和文獻（RT-Gang：Pi 3 上 DNN 和吃記憶體的鄰居一起跑慢 10.33×）同一個現象。
3. **調低優先權（SCHED_IDLE）也擋不住**：和 Suricata 共用核心時仍丟 28–47%，AI 還拿到 1.3–1.4 顆核心的時間。[推測] worker 處理封包之間有空檔，AI 就在空檔跑；封包來時喚醒和切換有延遲，快取也被洗掉，queue 就滿了。沒有量喚醒延遲。
4. 都不綁（γ）介於中間，而且不可預測。
5. **真正的 edge AI 模型多半是吃記憶體的那一種**（權重大於 1 MiB 的 L2，batch 1）。所以「綁核心」不夠，要限制 AI 的記憶體頻寬或工作比例，見延伸實驗。

## 延伸實驗：真實大小的模型、限制 AI 的工作比例、δ 分配（`exp2b`，40 kpps，2 輪）

- δ：IRQ 29（eth0）搬到 CPU1，Suricata 綁 CPU2、3，AI 1 個執行緒綁 CPU0（CPU0 只剩 USB 網卡的中斷）。
- mlp：float32 MLP 256-1024-1024-256，權重約 6 MiB（大於 1 MiB 的 L2），batch 1，單核每秒約 184 次推論。
- duty：每 100 ms 只做 25 或 50 ms。

| 做法 | AI 負載 | Suricata 丟包 % | Suricata worker µs/封包 | AI 被拖慢 |
|---|---|---|---|---|
| α | mlp | 0／0 | 43（無 AI 時 37，+17%） | 0% |
| α | mem，duty 25% | 0.96／1.63 | 42–44（+16%） | 13% |
| α | mem，duty 50% | 5.2／5.8 | 48–50（+32%） | 15% |
| α | mem，duty 100%（實驗 2） | 31.7／31.9 | 71（+92%） | 13% |
| δ | 無 | 0／0 | 37 | — |
| δ | cpu | 0／0 | 37 | 1% |
| δ | mlp | 0／0 | 42.5（+15%） | 2% |
| δ | mem | 28.9／29.6 | 60（+63%） | 13% |

解讀：
1. **接近真實的小模型（MLP、權重 6 MiB）綁在別的核心時，40 kpps 不丟包，但 Suricata 每個封包貴約 15–17%**。這是記憶體干擾的代價；離容量越近，這 15% 越可能變成丟包（40 kpps × 43 µs ≈ 1.7 顆核心給 2 個 worker）。
2. **吃記憶體頻寬的負載，干擾大致和它的工作比例成正比**（25% → +16%、50% → +32%、100% → +92%）。所以「依負載調整 edge AI 的推論量」是有效的控制旋鈕，而且要以記憶體頻寬、不是以 CPU 時間來看。
3. **δ：把 eth0 的中斷搬走後，CPU0 可以放 edge AI**（cpu、mlp 都不丟包），四顆核心可以分成「CPU1 收封包、CPU2–3 Suricata、CPU0 AI」。記憶體干擾一樣存在。
4. Linux 限制記憶體頻寬要靠 resctrl，背後需要 x86 的 MBA 或 ARM 的 MPAM（ARMv8.4 之後）；Pi 4 的 Cortex-A72 是 ARMv8.0，沒有。所以只能靠 AI 自己限制工作比例或 batch 大小（[推測] 正式設備若有 MPAM 可以改用硬體限制，要查規格）。

## 實驗 3：conntrack 計數（`nf_conntrack_acct`）的轉送成本（`exp3`，A0，3 輪，2026-11-03）

3d 要讀每條連線的封包數和 bytes，要開 `net.netfilter.nf_conntrack_acct=1`（Pi OS 預設 0）。每個點都重新啟動 wnc-gw，acct 0／1 的順序每輪打亂。

| 工作負載 | acct=0（範圍，平均） | acct=1（範圍，平均） | 差 |
|---|---|---|---|
| B2 信任、1 queue、S_m60 @40k | 16.35–16.55，16.47 | 16.55–16.70，16.60 | +0.13 µs（+0.8%） |
| B1 ips 2 queue、S_m17 @40k | 60.00–60.35，60.15 | 61.10–61.60，61.40 | +1.25 µs（+2.1%） |
| B3 ids 2 group、S_m17 @30k | 55.60，55.60 | 56.10–56.20，56.17 | +0.57 µs（+1.0%） |

（µs 是全機每個封包；18 個點都沒有 cap_loss；B1 的 loss 48.7% 是判決丟包，acct 0／1 一樣，見「量法」。）

解讀：開 conntrack 計數每個封包多 0.1–1.3 µs（≤ 2%），轉送成本上可以開。讀出來的成本（ctnetlink 整表 dump）在 `tests/ctnetlink/bench`。

## 實驗 4：routed 對 bridge（`exp4`，2 輪，2026-11-04）

問題（開發者 11/04）：10/24 在 veth 上量到 routed 比 bridge 便宜 35%，預設是不是該用 routed？這次用實體網卡量。

- routed 的拓樸（`planb_pi.sh up` 加 `MODE=routed`）：eth0（10.99.1.1/24）、eth1.20（10.99.2.1/24）不接 bridge，Pi 做 IP 轉送。下一跳是假的 MAC，筆電的網卡不收，轉送出去的封包不會被筆電再轉送。pcap 裡的 LAN 網段經 eth0，其餘走 eth1.20。送進來的封包目的 MAC 先改成 Pi 的（`planb_run.sh routed_pcap`）。wnc-gw 設 `mode = "routed"`。
- 工作負載、放置同實驗 1：B0（只轉送）、B1（ips 2 queue）、B2（ips、全部信任、S_m60）、B7（ids 3 group）× A0、R123。兩種模式的先後每輪對調。

**容量（kpps；ids 是「轉送（檢查）」；兩輪不同時寫「輪 1／輪 2」）**

| 工作負載 | A0 bridge | A0 routed | R123 bridge | R123 routed |
|---|---|---|---|---|
| B0 只轉送 | 100 | **150** | 300 | 300 |
| B2 ips 信任、S_m60 | 50 | 50 | 80／50 | 80 |
| B1 ips 2 queue | 60／55 | 60 | 45 | 45 |
| B7 ids 3 group | 30（≥50） | 50（≥70）＊ | 120／100（80） | 120（80） |

**每個封包的 CPU（µs，全機，兩輪平均；兩種模式都不丟包的速率）**

| 工作負載 | bridge | routed | 差 |
|---|---|---|---|
| B0 A0 @100k | 9.97（CPU0 8.99） | 8.02（CPU0 7.08） | −20% |
| B0 R123 @100k／@300k | 11.79／10.18 | 9.99／8.54 | −15%／−16% |
| B2 A0 @50k | 13.98（CPU0 12.07） | 11.13（CPU0 9.17） | −20% |
| B2 R123 @50k | 14.60 | 13.51 | −7% |
| B1 A0 @30k／@40k | 56.58／56.52 | 51.75／55.20 | −9%／−2% |
| B1 R123 @30k／@40k | 63.12／63.00 | 60.70／59.52 | −4%／−6% |
| B7 R123 @30k／@80k | 45.77／45.08 | 44.42／43.97 | −3%／−2% |
| B7 A0 @30k | 52.65 | 43.23＊ | 不能比 |

解讀：
1. **routed 的轉送每個封包少約 2 µs。** 只轉送（B0）時是 15–20%，省的主要是收封包那顆 CPU：A0 下 CPU0 每個封包從 9.0 降到 7.1 µs，所以 A0 的只轉送容量從 100 提高到 150 kpps。R123 兩種模式都到 300（350 時都丟）。veth 上量到的 35%，在實體網卡上是 15–20%。
2. **有 Suricata 時差距變小、容量一樣。** ips 少 2–9%、ids R123 少 2–3%，因為大部分 CPU 花在 Suricata 上。
3. **routed 不轉送非 IP 的封包。** S_m60 有 0.38% 是 ARP 等非 IP 封包，所以 routed 的端到端 loss 比 bridge 多約 0.4%；bridge 照常轉送。
4. **＊ B7 A0 routed 少送了 21–42%，但沒有一個丟包計數器有記到。**
   - 丟在哪：kfree_skb 顯示是 POSTROUTING 的 `NETFILTER_DROP`。`IpForwDatagrams` 399,886 但 `IpOutTransmits` 只有 269,617。conntrack 的 `insert_failed` 和丟掉的數量一樣（@20k：83,732 對 83,790）。
   - 為什麼：S_m17 有 **50% 的封包和前一個一模一樣**（IoT-23 擷取時重複記錄，相隔約 12 µs）。[推測] 沒開 RPS 時，網卡收進來的封包是整批（list）送進 IP 層。同一批裡同一條新連線的兩個副本都先過 PREROUTING、各自建了 conntrack；第二個在 confirm 時撞上第一個，TCP 沒有 clash resolution，就被丟掉。
   - 為什麼只有這個組合：R123 時 RPS 逐個處理，bridge 的路徑也是逐個，所以都沒有（實測 0）。ips（B1）的重複副本在 bridge 下也會被 Suricata 丟掉，所以 B1 兩種模式的 loss 一樣（26–48%）。
   - 影響：丟的都是重複的那一份，每條連線的第一個封包都有轉送，對真實流量沒有影響。但 B7 A0 routed 少送、少做了 2–4 成，它的容量和 µs/封包不能拿來和 bridge 比。
5. 對預設的意涵（還沒決定）：
   - routed 省的是轉送的那約 2 µs，在只轉送、信任的流量上最明顯；有檢查時只差 2–9%。
   - 代價在部署面：兩個 port 要有各自的 IP 網段和路由，不轉送非 IP 的封包，和既有網路的接法不同。

## 實驗 5：ids 一個封包複製多份（`exp5`–`exp8`，bridge，2 輪，2026-11-04）

問題（老師 11/04）：Suricata、edge AI、雲端特徵各要一份複本時，Pi 撐得住嗎？三種做法都量：
- (a) **kernel 多送幾份 NFLOG**：wnc-gw 照常送 Suricata 一份（group 10..）。另一個 table `inet wnc_copy`（forward priority 10，在 wnc-gw 之後）對每個封包再 `log group 20..`。
- (b) 同 (a)，每份**只複製前 128 bytes**（規則的 `snaplen 128`）。
- (c) kernel 只多送一份給 **user space 的分發程式**（`fanout/`），它再分給 2 個讀取端。

讀取端只收、不處理：(a)(b) 是 `tcpdump -i nflog:N -s 0 -w /dev/null`（buffer 1 MiB，和 Suricata 一樣），(c) 是 fanout 的讀取執行緒。

| 代號 | 內容 |
|---|---|
| K0 | 只有 Suricata（ids、1 group） |
| K1／K2 | ＋ kernel 1／2 份 |
| K2h | ＋ kernel 2 份，每份前 128 bytes |
| U2 | ＋ kernel 1 份，fanout 分成 2 份 |
| K0g3、K2g3、U2g3 | 同上，Suricata 3 group（實驗 1 裡 ids 最好的組合，只量 R123） |

- pcap：
  - S_m17：掃描，小封包、很多 flow。
  - bulk_fixed：一條 iperf3 TCP 連線，1454-byte 的封包。網卡的 GRO 會把同一條 TCP 平均約 6.8 個封包合成一個再交給 nft，所以每份複本的數量約是封包數的 15%。
- 讀取端容量：讀取端漏掉的複本 ≤ 0.1% 的最高速率。漏掉的算法：netlink socket 滿了被 kernel 丟的，加上 fanout 的環狀緩衝滿了丟的。
- **K2h、K0g3、K2g3 是重跑的數字**，第一次的數據不算：
  - 第一次 K2h 的讀取端用 `tcpdump -s 128`。libpcap 的接收緩衝只有 snaplen + 128 bytes，kernel 一批送來的複本會被截掉：小封包只收到約 1 成，大封包時 tcpdump 直接結束（Docker 重現過）。重跑時改成 tcpdump `-s 0`、截短交給規則的 snaplen（exp7）。
  - 第一次 K0g3、K2g3 時 fanout 沒結束，一直佔著 group 20：背景啟動的程式會忽略 SIGINT，fanout 自己又沒處理。結果 K2g3 的第一份複本進了 fanout，K0g3 多了 fanout 空轉的 CPU。重跑時改用 SIGTERM，啟動前也會檢查有沒有殘留的讀取端（exp8）。
  - 順帶量到：fanout 空轉時（2 個讀取執行緒每 1 ms 醒來一次）每秒用掉約 70 ms CPU。

**容量（kpps，轉送（讀取端）；兩輪不同時寫「輪 1／輪 2」；「≥」表示掃到最高速率都沒丟）**

| 工作負載 | S_m17 A0 | S_m17 R123 | bulk A0 | bulk R123 |
|---|---|---|---|---|
| K0 | 40 | 120 | 60 | ≥88 |
| K1 | 30（≥50） | 120（100） | 50（40） | ≥88（80／70） |
| K2 | 30（≥50） | 100（100） | 40（30） | 80／70（70／60） |
| K2h | 30（≥50） | 100（100） | 50／60（≥70） | ≥88（≥88） |
| U2 | 30（≥50） | 120／100（100） | 40（30） | 70（60） |
| K0g3 | | 120／100 | | ≥88 |
| K2g3 | | 100（80） | | 70（60） |
| U2g3 | | 100（100／120） | | 70（50／60） |

Suricata 自己的檢查容量（Suricata 漏掉的複本 ≤ 0.1%）：
- S_m17 R123：1 group 40–50 kpps，3 group 70–80 kpps，和實驗 1 一致。
- bulk_fixed：所有組合都 < 10 kpps。這是單一 TCP 連線，3 group 也只有一個 worker 在做；10 kpps（約 116 Mbps）時那個 worker 已經 100% 忙，漏掉 15%。

**每個封包多花的 CPU（µs，全機，兩輪平均；括號是讀取端自己的部分）**

| 比較基準 | K1 | K2 | K2h | U2 |
|---|---|---|---|---|
| S_m17 A0 @30k，K0 = 48.6 | +5.1（1.8） | +10.6（3.8） | +11.2（3.6） | **+5.8**（3.1） |
| S_m17 R123 @30k，K0 = 41.8 | +3.4（5.2） | +6.5（9.6） | +7.0（8.9） | +6.0（8.0） |
| S_m17 R123 @30k，K0g3 = 46.7 | | +9.5（6.6）（K2g3） | | +7.4（4.8）（U2g3） |
| bulk A0 @20k，K0 = 81.4 | +7.8（6.6） | +12.8（10.7） | **+3.6**（1.6） | +16.2（11.5） |
| bulk R123 @20k，K0 = 81.2 | +8.7（6.9） | +14.8（14.5） | **+3.4**（2.0） | +17.8（14.7） |
| bulk R123 @20k，K0g3 = 82.3 | | +15.1（14.4）（K2g3） | | +18.1（13.4）（U2g3） |

（bulk 的 µs 是每個線上的封包。R123 下讀取端的時間比 A0 多，[推測] 是因為 R123 時 CPU1–3 也在跑 RPS 的 softirq，被算進當時正在跑的讀取端。所以讀取端那欄只當參考，比較時看全機。）

解讀：
1. **每多一份 kernel 複本：小封包約 +3–5 µs，大封包約 +7–8 µs**，大致和份數成正比。加 2 份讓整機每個封包貴 13–22%。轉送容量少約 2 成：S_m17 R123 120 → 100、bulk R123 ≥88 → 70–80、A0 40 → 30。
2. **只要 header 就用 snaplen。** S_m17 的封包本來就小於 128 bytes，K2h 和 K2 一樣。bulk 就差很多：2 份只多 +3.4–3.6 µs（整份是 +12.8–14.8），轉送容量和沒有複本時一樣。注意 GRO 合併過的封包只有一份複本，128 bytes 只看得到第一段的 header。
3. **user space 分發（c）在小封包時比較省，大封包時比較貴。**
   - 小封包：A0 +5.8 對 kernel 2 份的 +10.6；R123 差不多（+6.0 對 +6.5；3 group +7.4 對 +9.5）。
   - 大封包：+16–18 對 +13–15，因為 fanout 在 user space 又把資料複製了兩次（每個環狀緩衝一次）。改成共用一份緩衝可能更省，沒有做。
4. 讀取端只收不處理時，跟得上 100 kpps（S_m17 R123）、60–70 kpps（bulk）。真正的 edge AI 或特徵程式還要加上自己的處理時間，而且會和 Suricata 搶 CPU（實驗 2）。

## 整體結論（給設計用）

| 問題 | 答案 |
|---|---|
| CPU0 是瓶頸嗎？ | 只對轉送和信任流量是。RPS 分到 CPU1–3 讓只轉送的容量從 100 到 300 kpps；信任的單一 flow 從 50 到 80 kpps（I1、T1、R123）。 |
| 檢查的容量上限？ | 全部檢查（ips、full）時每個封包約 55–61 µs，4 核心約 60 kpps 就滿；加 queue、搬中斷都推不過 60。ids（NFLOG）配 RPS、3 group 可以檢查到 80（S_m17），但 ids 的轉送在 A0 只有 30，一定要開 RPS。 |
| queue／group 開幾個？ | ips 1 queue 只有 20–30；ips 用 I1 + 3 queue、ids 用 RPS + 3 group 在兩個 pcap 都最好。多開會讓每個封包更貴。 |
| 開 conntrack 計數？ | 每個封包多 0.1–1.3 µs（≤ 2%）。 |
| edge AI 的 CPU 從哪來？ | 幾乎全部來自信任：信任的封包約 14 µs、檢查的約 55 µs。 |
| 怎麼放 edge AI？ | 綁在 Suricata 以外的核心（α 或 δ）；不要和 Suricata 共用核心，SCHED_IDLE 也不行。 |
| 綁核心就夠了嗎？ | 不夠。記憶體頻寬是共用的：真實大小的模型讓 Suricata 貴 15–17%，吃記憶體的負載讓它貴到 2 倍。要依 Suricata 的負載調整 AI 的工作比例。 |
| routed 還是 bridge？ | routed 的轉送每個封包少約 2 µs：只轉送少 15–20%（A0 容量 100 → 150 kpps），有檢查時只少 2–9%、容量一樣。預設用哪個還沒決定（部署面的取捨）。 |
| 一個封包複製 2–3 份撐得住嗎？ | 撐得住：kernel 多 2 份讓每個封包貴 13–22%、轉送容量少約 2 成。只要 header 時用 snaplen（大封包幾乎不加成本）；小封包多時 user space 分發比較省，大封包時 kernel 複製比較省。 |

品質檢查：312 個量測點全部 `throttled=0x0`（量測前後）、時脈 1000 MHz、swap 0、最高溫 63.3°C；沒有 ssh 讀取失敗的點。exp1c、exp1d 的 392 個點和 exp3 的 18 個點也都是 `throttled=0x0`、1000 MHz、swap 0、PAUSE 0 個，最高溫 67.6°C。實驗 3b（Docker）在實驗 1 第二輪的 B1 期間跑過約 6 分鐘，B1 兩輪的容量在 5 kpps 的速率間隔內一致。實驗 4、5 的 776 個點（含重跑）也都是 `throttled=0x0`、1000 MHz、swap 0、PAUSE 0 個、沒有 ssh 讀取失敗，最高溫 68.1°C。

限制：Pi 4 鎖 1000 MHz；流量是 IoT-23 切片重播（S_m17 掃描、S_m60 單一 UDP flow）；edge AI 是替身，不是合作方的模型；實驗 2 只量 40 kpps 一個速率；`µs/封包（全機）` 在有 AI 時包含 AI 的 CPU，那一欄只在沒有 AI 時有意義。

## 實驗 9（exp9，2026-11-14）：TC fast path 對 ct mark 信任

B0、B2 和 F2（B2 加上 TC fast path：`alloc_pi.sh fastpath_start` 掛 `tests/ebpf/bench` 的 ebpf-bench v4）× A0、I1，都用 S_m60，2 輪。結果和解讀在 `tests/ebpf/README.md`「E1」；原始資料 `~/datasets/throughput/cpu_alloc/e1.kvl`。

## 實驗 10（exp10，2026-11-14）：wnc-gw 本身的 TC fast path，bridge 對 routed（步驟 C3）

Pi 4、鎖 1000 MHz、方案 B、eth0 PAUSE 關、I1（IRQ 29 → CPU1）；2 輪，每輪兩種模式的順序對調、工作負載的順序隨機。T1、T1k 啟動後先以 20 kpps 送一次整個 pcap（讓 conntrack 有這些連線），再 `alloc_pi.sh trust_flows` 逐條 `wnc-gw trust add`。原始資料：筆電 `~/datasets/throughput/cpu_alloc/e3.kvl`（`e3_try.kvl` 是一個試跑的點）。

| 工作負載 | 內容 |
|---|---|
| B0 | 只有 bridge／routing（沒有 wnc-gw） |
| U1 | wnc-gw ips、full、1 queue，沒有信任（全部檢查），S_m60 |
| T1 | U1 再用 `wnc-gw trust add` 信任 S_m60 的 101 條 flow（1 條 TCP 在暖身時已經結束），信任的封包走 TC fast path |
| T1k | 同 T1，1,000 條合成的 UDP flow（`X_udp1000`，60 bytes） |

每封包 CPU（µs，整台 Pi＝經過時間 − idle，兩輪平均，只算沒丟包的點）：

| 速率 | B0 bridge | B0 routed | T1 bridge | T1 routed | T1k bridge | T1k routed | U1 bridge | U1 routed |
|---|---|---|---|---|---|---|---|---|
| 10k | — | — | — | — | — | — | 57.55 | 53.65 |
| 30k | — | — | — | — | — | — | 48.33 | 45.22 |
| 50k | 13.71 | 11.71 | 9.01 | 10.40 | 8.82 | 10.34 | — | — |
| 80k | 10.13 | 8.09 | 8.72 | 10.02 | 8.51 | 10.05 | — | — |
| 120k | 9.21 | 7.37 | 7.80 | 9.16 | 7.61 | 8.96 | — | — |
| 150k | 丟 | 6.92 | 7.32 | 8.31 | 7.11 | 8.09 | — | — |

容量（cap_loss ≤ 0.1%，kpps，兩輪相同）：

| | B0 | U1 | T1 | T1k |
|---|---|---|---|---|
| bridge | 120 | 30 | 150（180 時丟 0.33%） | 180 |
| routed | 180 | 30 | 150 | 150 |

怎麼讀：
- **信任的封包：bridge 比 routed 每個少約 1.4 µs**（T1、T1k 各速率都是），T1k 的容量 180 對 150 kpps。routed 的 fast path 要多做減 TTL、修 checksum（兩次 helper 寫入）和 `bpf_redirect_neigh` 裡的路由查詢、neighbor 輸出。
- **沒被信任（檢查）的封包：routed 比 bridge 每個少 3.1–3.9 µs**（約 7%），容量一樣（Suricata 是瓶頸）；只轉送的 B0 也是 routed 少約 2 µs、容量 180 對 120，和 11/04 相同。
- 所以整體哪個便宜看信任的比例 f：bridge − routed ≈ −1.4 f + 3.5 (1 − f) µs，**f 大於約 70% 時 bridge 才比較便宜**（只用這組 pcap 和 I1 估的）。
- bridge 的 fast path 比只有 bridge 的 B0 還便宜（7.80 對 9.21 µs @120k），routed 的 fast path 反而比只有 routing 的 B0 貴（9.16 對 7.37）：kernel 的 routing 本身很便宜，`bpf_redirect_neigh` 每個封包重新查路由和 neighbor。可能的改善（沒試）：在 map 裡記下一跳的 MAC，自己改寫 MAC 後用 `bpf_redirect`（不用 GPL-only 的 `bpf_fib_lookup`）。
- 1,000 條信任 flow 的 T1k 和單一大 flow 的 T1 一樣或更便宜（60 bytes 的 UDP，沒有 TCP 控制封包），map 有 2,000 筆時看不出查表變貴。
- 和 E1 的 bench V4（F2，bridge）一致：T1 bridge 50k 9.01、80k 8.72 µs 對 F2 9.02、8.53 µs；E1 的 ct mark 信任（B2）80k 是 13.96 µs。
- 限制：只用 I1（IRQ 搬到 CPU1）、S_m60 和一個合成 pcap、2 輪；U1 的差主要在 bridge＋br_netfilter 對 routing，與 fast path 無關。

## 實驗 11（exp11，2026-11-14）：routed 的三種送法

routed、I1、S_m60、2 輪；F5n／F5h／F5f 是 U1（wnc-gw ips、沒有信任）再在 TCX 最前面掛 `tests/ebpf/bench` 的 v5（信任 S_m60 的 102 條 flow；98.9–99.3% 在 TC 送出），T1 是 wnc-gw 本身（`bpf_redirect_neigh` 不帶參數）。原始資料 `~/datasets/throughput/cpu_alloc/e4.kvl`（`e4_try.kvl` 是一個試跑的點）。

| 送法 | 50k | 80k | 120k | 150k | 容量（kpps） |
|---|---|---|---|---|---|
| F5n `bpf_redirect_neigh` 不帶參數（kernel 查路由＋neighbor） | 9.96 | 9.55 | 8.57 | 7.84 | 150／150 |
| **F5h `bpf_redirect_neigh` 帶下一跳**（kernel 只查 neighbor） | **9.15** | **8.76** | **7.91** | **7.38** | **180／180** |
| F5f `bpf_fib_lookup`＋自己改 MAC＋`bpf_redirect` | 9.84 | 9.41 | 8.48 | 7.78 | 150／150 |
| T1 wnc-gw 本身（同 F5n 的送法） | 10.46 | 10.06 | 9.20 | 8.27 | 150／150 |

（µs／封包，整台 Pi，兩輪平均，只算沒丟包的點。）

怎麼讀：
- 貴的是**查路由**，不是 neighbor：帶下一跳（不查路由）每個少約 0.7 µs、容量 150 → 180；`bpf_fib_lookup` 也要查路由，只比不帶參數少 0.1 µs，還是 GPL-only，沒有好處。
- 帶下一跳的 routed（7.91 µs @120k）和 bridge 的 fast path（exp10 T1 bridge 7.80）差不多。
- wnc-gw 本身（T1）比同樣送法的 bench（F5n）貴約 0.6 µs，原因沒查（bridge 時 exp10 的 T1 對 E1 的 F2 也貴約 0.3 µs）。
- 沒量的：(a) 把下一跳的 MAC 記在 map 裡，因為 MAC 會過期（IP 換到別台機器時，最多 10 秒送錯）而排除。

## 實驗 12（exp12，2026-11-14）：routed 改成帶下一跳之後重量

exp10 的 T1、T1k（wnc-gw 本身），兩種模式、I1、2 輪；routed 的 wnc-gw 帶下一跳（`agent/nexthop.rs`），`trust_flows … hops` 確認每條都有下一跳之後才開始量（`with_next_hops=101`、`102`、`1000`）。原始資料 `~/datasets/throughput/cpu_alloc/e5.kvl`（`e5_try.kvl` 是一個試跑的點）。

| 速率 | T1 bridge | T1 routed | T1k bridge | T1k routed |
|---|---|---|---|---|
| 50k | 9.00 | 9.53 | 8.76 | 9.30 |
| 80k | 8.75 | 9.23 | 8.55 | 9.23 |
| 120k | 7.79 | 8.28 | 7.60 | 8.29 |
| 150k | 7.38 | 7.74 | 7.06 | 7.53 |
| 容量（kpps） | 150／150 | 150／150（180k 丟 0.13–0.18%） | 180／180 | 180／150 |

（µs／封包，整台 Pi，兩輪平均。）

怎麼讀：
- routed 的信任封包比 exp10（不帶下一跳）每個少 0.7–0.9 µs（T1 9.16 → 8.28、T1k 8.96 → 8.29 @120k），bridge 不變（7.80 → 7.79）。
- bridge 和 routed 的差從 1.4 µs 縮到約 0.5 µs。沒被信任的封包 routed 少 3.1–3.9 µs（exp10 的 U1），所以只有信任的封包佔約 87% 以上時 bridge 才整體便宜（−0.5 f + 3.5 (1 − f)）。
- wnc-gw 本身仍比 exp11 的 bench F5h（7.91）貴約 0.4 µs，原因沒查。
