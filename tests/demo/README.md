# tests/demo — 11/09 demo 操作手冊

**11/09 用 Docker、手動操作：流程在 `DOCKER.md`**（準備用 `prep_docker.sh`）。下面是之前用 `demo.sh` 的實機／Pi 版本，留著參考。

要展示的是階段 1 做完的樣子：wnc-gw 把轉送的流量交給 Suricata（ids，NFLOG 複本），讀 Suricata 的 alert，並且自己決定信任哪些連線（3d）。被信任的連線不再送給 Suricata；有 alert 的連線不會被信任；Suricata 掛掉時會記下沒檢查的時段並自動重啟。

接線、ssh 進 Pi、wnc-gw 的設定和檢查指令（nft、trust、Suricata 的 log 等）在 `OPERATIONS.md`。

腳本是 `demo.sh`，有三種跑法，步驟完全一樣：
- **`TARGET=phys`（11/09 用這個）**：實機。wnc-gw 跑在 Pi 上，流量從筆電經網路線真的送進 Pi、再從 Pi 送回筆電；所有指令都在筆電上下，Pi 那一半由腳本 ssh 過去做。
- `TARGET=pi`：全部在 Pi 裡用 veth 接，不需要筆電的網卡。
- `TARGET=docker`：筆電的 Docker testbed，可以先用來練習。

## 拓樸

| | 實機（`TARGET=phys`） | Pi（`TARGET=pi`） | Docker（`TARGET=docker`） |
|---|---|---|---|
| client | 筆電上的容器 `dcli`，10.9.0.1，macvlan 掛在 USB 網卡 | netns `fcli`，10.9.0.1 | 容器 `wnc-cli`，10.0.1.2 |
| gateway | Pi：netns `wgw` 裡的 bridge `br0`，接 **eth0**（LAN）和 **eth1.20**（WAN，eth1 上的 VLAN 20），`mode = "bridge"` | netns `wgw` 裡的 bridge `br0`（g-lan、g-wan、x-lan、x-wan；wnc-gw 的 port 是 x-lan、x-wan），`mode = "bridge"` | 容器 `wnc-gw`，`mode = "routed"` |
| server | 筆電上的容器 `dsrv`，10.9.0.130，macvlan 掛在 eno2.20 | netns `fsrv`，10.9.0.2 | 容器 `wnc-srv`，10.0.2.2 |
| 和真實部署的差別 | 兩個 port 是真的網卡，但 WAN 借用管理線（eth1）上的 VLAN 20，SSH 照常走 eth1；Suricata 的 log 目錄是 tmpfs | 全部在 Pi 裡用 veth 接，不經過實體網卡；Suricata 的 log 目錄是 tmpfs | 共用筆電的 kernel；容器的 `nf_conntrack_acct` 由 `docker/compose.yml` 設 |

實機的接線：筆電的 USB 網卡（`enx9c69d3241bd9`）↔ Pi eth0；筆電 eno2 ↔ Pi eth1（原本的管理線，不用改）。client 和 server 在不同的 /25，各自加了到對方的 on-link 路由，所以 ARP 和封包都要經過 Pi 的 bridge。

server 上有兩個服務：5001 收資料（正常流量），8080 收到任何東西就回 `uid=0(root) gid=0(root)`，觸發真實的 GPL 規則「ATTACK_RESPONSE id check returned root」（sid 2100498），之後持續送資料，讓這條連線夠長、本來會被信任。

demo 用的設定（`up` 寫到 `run/setting.toml`）：`protection = "ids"`，`[trust] auto = true`、`min_packets = 10`、`min_age = 5`、`ttl = 60`、`check_interval = 2`。TTL 只設 60 秒是為了在 demo 裡看得到到期；正式的預設是 900 秒。規則只有兩條（上面那條 GPL 和一條 ICMP），Suricata 啟動不到一秒。`RULES=full bash demo.sh up` 會再載入 ET Open 的完整規則（Pi 上 `~/ids_throughput/data/rules/suricata_full.rules`），用來展示重播真實惡意流量（第 5b 步）；Suricata 啟動和被 kill 後的重啟都會變慢。

## 事前準備

**筆電**（Docker 練習）：`cd docker && ./up.sh`，`cd security_gateway && cargo build --target x86_64-unknown-linux-musl`。

**實機**：Pi 上要有 `~/demo/wnc-gw`（下面「Pi」的前兩行）；`up` 會自己把 `demo.sh` 複製到 Pi。筆電要能免密碼 `ssh wnc@10.254.254.2`，有 Docker 映像 `wnc-lab`、`wnc-lab-gen`（重播用），重播的 pcap 在 `~/datasets/throughput/pcaps`（`PCAPS=` 可以改）。量測用的 `wnc-gen` 容器（`tests/ids_inline/planb_run.sh setup`）要先 `teardown`，它也會用到 eno2.20。

**Pi**：
```bash
# 筆電：編 Pi 版，連同腳本放到 Pi 的 ~/demo
cd security_gateway
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld cargo build --release --target aarch64-unknown-linux-musl
ssh wnc@10.254.254.2 mkdir -p demo
scp target/aarch64-unknown-linux-musl/release/wnc-gw ../tests/demo/demo.sh wnc@10.254.254.2:demo/
# Pi 上要有 ~/ids_inline/env.sh（實驗用的那份；不在的話用 ENV_SH=… 指定）
```
- 筆電重開機後 eno2 沒有位址：`sudo ip addr add 10.254.254.1/24 dev eno2`。
- Pi 的時鐘沒有網路校時，log 的時間會不對：`ssh wnc@10.254.254.2 sudo date -u -s @$(date +%s)`。
- `up` 會停掉 Pi 的 `suricata.service`（它開機就以 af-packet 跑）。

## 步驟

開三個終端機。下面的指令是 `TARGET=pi` 的寫法（在 Pi 上 `sudo bash ~/demo/demo.sh …`）；**實機在筆電上把前面換成 `TARGET=phys bash tests/demo/demo.sh …`**（不用 sudo，T1 的 `run` 會 ssh 到 Pi、Ctrl-C 一樣能停）；Docker 換成 `TARGET=docker bash tests/demo/demo.sh …`：

| 終端機 | 用途 |
|---|---|
| T1 | `run`：wnc-gw 的 log 一直印在這裡 |
| T2 | 送流量 |
| T3 | 看狀態（`status`） |

1. **建立環境、檢查**（T2）
   ```bash
   sudo bash ~/demo/demo.sh up
   sudo bash ~/demo/demo.sh doctor
   ```
   講：doctor 檢查 bridge、`br_netfilter`、kernel 模組、nft、Suricata 8.0.7 有 NFLOG 支援、eve-log 有 alert、自動信任的設定。看到的 warning 都是刻意的：ids 不擋流量、checksum 不檢查、自動信任的風險、Suricata 由 wnc-gw 啟動。沒有 error 才能 `run`。

2. **啟動**（T1）：`sudo bash ~/demo/demo.sh run`
   看到：`automatic trust is on`、`suricata started`、`suricata is ready`、`reading suricata's alerts from its EVE file`、`forwarded traffic is inspected`。
   講：table 先裝好（沒檢查的狀態），Suricata 送出 READY=1 才開始把流量交給它；就緒前的那段 log 會寫明「沒經過檢查」。

3. **正常流量被信任**（T2）：`sudo bash ~/demo/demo.sh normal 120`
   約 5–8 秒後（`min_age` 5 秒，再加上最多一次 `check_interval` 2 秒）T1 出現：
   `INFO connection trusted; its packets other than syn/fin/rst skip inspection connection="tcp 10.9.0.1:… -> 10.9.0.2:5001" packets_original=… ttl_s=60`
   T3 `sudo bash ~/demo/demo.sh status`：ids chain 的計數停住不再增加；`trusted connections` 列出這條連線，MARK 是 `0xc0000000`（`0x80000000` 信任、`0x40000000` 經過 gateway）。
   講：wnc-gw 讀 conntrack 的計數，Suricata 在檢查的期間兩個方向都有 10 個封包、觀察滿 5 秒、沒有 alert，就設 ct mark；之後這條連線只有 SYN／FIN／RST 會送給 Suricata。Pi 上量過，信任的封包每個省 38–68 µs。

4. **有 alert 的連線不被信任**（T2）：`sudo bash ~/demo/demo.sh attack 60`
   T1 出現：`DEBUG suricata alert … sid=2100498 signature="GPL ATTACK_RESPONSE id check returned root"`，接著 `DEBUG suricata alerted on a watched connection; it will not be trusted`。
   這條連線之後一直在送資料，但不會出現 `connection trusted`。
   講：alert 是 Suricata 寫在 eve.json 的，wnc-gw 每 0.5 秒讀新增的部分；有 alert 的連線永遠不信任，已經信任的會立刻撤銷（log 是 WARN `trust revoked`）。

5. **ICMP**（T2）：`sudo bash ~/demo/demo.sh ping`，T1 有三筆 `demo ICMP echo request`。ICMP 沒有 port，不會被信任。

5b. **重播真實的惡意流量**（只有實機，而且 `up` 時要 `RULES=full`）（T2）：`TARGET=phys bash tests/demo/demo.sh replay`。
   - 重播什麼：從筆電的兩張網卡重播 IoT-23 3-1（Muhstik 殭屍網路）的 500 個封包（SSH 掃描、IRC），每秒 50 個、約 10 秒。從「路由器」那側來的封包走 eno2.20 進 Pi 的 WAN，其餘走 USB 網卡進 LAN。
   - 約 3 秒內 T1 出現 3 筆 alert：`ET MALWARE ELF/Muhstik - IRC CnC Checkin`（sid 2029319）兩條連線各一筆、`ET INFO IRC Channel JOIN on non-standard port`（sid 2000348），每條都接著 `it will not be trusted`。
   - 另外兩筆 `ET MALWARE ELF/Muhstik Botnet CnC Activity`（sid 2034743）要等連線結束才出來；切片裡的連線沒有結束，所以是第 8 步停止時才記。5 筆和離線用 `suricata -r` 跑同一個 pcap 的結果一樣。
   - 同一個 pcap 重播第二次之前要重新 `run`：Suricata 會記得上一次的連線狀態，結果不一樣。
   - 講：這是 dataset 裡真實的惡意流量，不是我們自己寫的規則；和第 4 步一樣，有 alert 的連線不會被信任。

6. **信任到期**：第 3 步之後約 60 秒，T1 出現 `DEBUG trust expired; connection is inspected again`，再過 5–6 秒又出現 `connection trusted`。
   講：TTL 到期就回到檢查，要重新觀察一次才會再信任；正式的 TTL 是 900 秒，比 Suricata 忘記一條連線的時間（600 秒）長，ips 模式下 Suricata 才不會因為序號過時丟封包。

7. **Suricata 掛掉**（T2）：`sudo bash ~/demo/demo.sh kill-suricata`
   T1：`WARN suricata exited … exit="SIGKILL"`、`WARN forwarded traffic passes without inspection`，約 1 秒後 `suricata started`、`forwarded traffic is inspected … uninspected_ms=…`。
   講：Suricata 掛掉的時段一定記在 log（`when_unavailable = "accept"` 時放行、`"drop"` 時丟掉）；已經信任的連線不受影響。注意 ids chain 的計數會從 0 重新算（規則被換掉）。

8. **停止**（T1）：Ctrl-C。T1 出現 `table removed`；如果上一行摘要之後還有新的 alert，停止前會先記一行 `suricata raised alerts alerts=… top=…`。
   講：每 60 秒、這段時間有 alert 才記一行摘要（啟動後第 60 秒那行就是第 4、5 步的 alert）；每一筆 alert 的細節是 DEBUG（demo 用 `LEVEL=debug`），完整紀錄在 Suricata 的 eve.json，wnc-gw 的 log 都帶 `flow_id` 可以對回去。

9. **收拾**（T2）：`sudo bash ~/demo/demo.sh down`

## 被問到時

- **為什麼 alert 只是 DEBUG？** wnc-gw 的 log 只放重要資訊和出事時能定位的資訊；alert 本身在 eve.json。改成 `LEVEL=info` 跑就只剩每 60 秒一行摘要。
- **ids 模式下 alert 會不會太晚？** 會。Docker 測過：低流量連線的 payload alert，在 ids 模式下可能到連線結束才出來，比 `min_age` 晚，連線會先被信任、結束時才撤銷；ips 模式一開始就不會信任。原因和做法還在決定（`security_gateway/DECISIONS.md` §19）。demo 的 8080 用的是逐封包比對的規則，所以不受影響。
- **自動信任省多少？** Pi（鎖 1000 MHz）上 8 條長連線、每秒 4,000 個封包：Suricata 從每秒 100 ms 降到 14 ms，wnc-gw 多 1.4 ms，合計每個封包省 21 µs。代價是 wnc-gw 每次讀 conntrack 固定約 7 ms，加上每條連線約 9.4 µs（`security_gateway/DECISIONS.md` §19）。
- **還沒做的**：雲端和 edge AI 的判定（現在沒有 alert 就當成良性）、eBPF fast path、log 保存的上限。

## Docker 演練紀錄（2026-11-04）

`TARGET=docker`，依序 `up`、`doctor`、`run-bg`、`normal 40`、9 秒後 `status`、`attack 15`、`ping`、`kill-suricata`、`status`、`stop`：
- 正常的連線約 6 秒後信任（`packets_original=60 packets_reply=60`），`trust list` 的 MARK 是 `0xc0000000`。
- 攻擊連線：`alerted on a watched connection; it will not be trusted`（sid 2100498）。
- ping：3 筆 alert。
- SIGKILL 後 1.1 秒重新就緒（`uninspected_ms=1092`），信任的連線還在。
- 停止時摘要 `alerts=4 connections=2`。

## Pi 演練紀錄（2026-11-04）

Pi 4（鎖 1000 MHz），`TARGET=pi`，依序 `up`、`doctor`、`run-bg`、`normal 90`（背景）、第 10 秒 `status`、`attack 15`、`ping`、第 66 秒 `status`、第 82 秒 `kill-suricata`、`status`、`stop`、`down`：
- doctor 沒有 error；`trust:` 那行是 `automatic after 10 packets each way and 5 s, for 60 s; checked every 2 s`。
- 正常的連線約 7 秒後信任（`packets_original=60 packets_reply=60`），`status` 的 MARK 是 `0xc0000000`。
- 攻擊連線：`suricata alerted on a watched connection; it will not be trusted`（sid 2100498）；ping 3 筆 alert。
- 第 60 秒兩行摘要：`suricata raised alerts alerts=4 connections=2`、`automatic trust trusted=1 … refused=1 trusted_now=1`。
- 信任 60 秒後到期，6 秒後再次信任。
- SIGKILL 後 1.3 秒重新就緒（`uninspected_ms=1284`），信任的連線還在；ids chain 的計數從 0 重新算。
- 停止時沒有摘要：最後的 alert 已經記在第 60 秒那行。

## 實機演練紀錄（2026-11-05）

Pi 4（鎖 1000 MHz），`TARGET=phys`。依序做了這些：
- 演練：`wiring`、`up`、`doctor`、`run-bg`、`normal 90`（背景）、第 10 秒 `status`、`attack 15`、`ping`、第 66 秒 `status`、第 90 秒 `kill-suricata`、`status`、`stop`；
- 拆掉重來：`down`、`RULES=full up`、`run-bg`、`replay`、`stop`。

結果：
- `wiring` 正確分出兩張網卡：eno2 → Pi eth1，USB 網卡 → Pi eth0。doctor 沒有 error。
- 正常的連線約 6 秒後被信任（`packets_original=59 packets_reply=59`），`status` 的 MARK 是 `0xc0000000`。
- 攻擊連線：`suricata alerted on a watched connection; it will not be trusted`（sid 2100498）；ping 3 筆 alert。
- 第 60 秒兩行摘要：`alerts=4 connections=2`、`trusted=1 … refused=1 trusted_now=1`。信任 60 秒後到期，6 秒後再次信任。
- SIGKILL 後 1.3 秒重新就緒（`uninspected_ms=1295`），信任的連線還在。
- `RULES=full` 時 Suricata 啟動 41 秒（`startup_ms=41052`），`run-bg` 要等這麼久。重播的結果見第 5b 步；停止時記了 Botnet CnC Activity 的那一行摘要。

演練時發現、已經修好的問題：
- **pcap 的 checksum**：pcap 裡從路由器來的 IP 封包，IPv4 header checksum 都是 0。Pi 的 br_netfilter 會把它們丟掉（kfree_skb 的原因 `IP_INHDR`），Suricata 只看到單向的流量，所以一筆 alert 都沒有。離線的 `suricata -r -k none` 不檢查 checksum，所以之前沒發現。`replay` 現在先用 `tcprewrite --fixcsum` 修正。
- **剛拆掉拓樸時的網卡判斷**：`down` 之後馬上 `up`，Pi 的 eth0 還沒重新 link up，抓不到 LAN 那張網卡。現在最多等 10 秒。
- **太早做連通檢查**：eth0 移進 netns 後要 2–3 秒才通，`up` 最後的 ping 檢查也改成最多重試 5 次。
