# Demo 操作：接線、連進 Pi、wnc-gw 設定、檢查指令

`README.md` 是 demo 的流程（每一步做什麼、會看到什麼、要講什麼）；這份是**流程以外會用到的每個操作**：網路線怎麼接、怎麼確認、怎麼 ssh 進 Pi、wnc-gw 怎麼設定、出問題時用哪些指令查。以實機（`TARGET=phys`）為主。

指令前的提示符號：`筆電$` 在筆電上下，`Pi$` 在 Pi 上下（先 ssh 進去）。

## 1. 硬體與接線

| | 介面名稱 | 實體位置 | MAC（目前） | demo 裡的角色 |
|---|---|---|---|---|
| Pi | `eth0` | Pi 本身的 RJ45 網口 | e4:5f:01:2d:03:bf | **LAN**（client 那一側） |
| Pi | `eth1` | 插在 Pi USB 上的網路卡 | 9c:69:d3:2a:11:54（換一張就變） | **管理線**（SSH，10.254.254.2）＋ **WAN**（同一條線上的 VLAN 20，`eth1.20`） |
| 筆電 | `eno2` | 筆電的 RJ45 網口 | 04:42:1a:85:7f:e7 | 看接到 Pi 的哪個口 |
| 筆電 | `enx9c69d3241bd9` | 插在筆電 USB 上的網路卡（名稱就是 `enx` 加它的 MAC，換一張名稱就變） | 9c:69:d3:24:1b:d9 | 看接到 Pi 的哪個口 |

**規則只有一條：Pi 那邊的角色是固定的，筆電那邊怎麼插都可以。**
- 兩條網路線，一條接 **Pi 的 USB 網卡（eth1）**，一條接 **Pi 本身的網口（eth0）**。
- 筆電的兩張網卡哪一張接哪一條都沒關係；`demo.sh` 會自己判斷（下一節）。接到 Pi eth1 的那張要有管理位址 10.254.254.1。

為什麼 Pi 的介面名稱不會因為 MAC 變：
- Pi OS 關掉了「依 MAC 命名」（`/etc/systemd/network/73-usb-net-by-mac.link` 指到 `/dev/null`），USB 網卡一律叫 `eth1`，換一張也一樣。
- Pi 的管理位址是 NetworkManager 的「Wired connection 2」，綁的是**介面名稱 `eth1`**（不是 MAC），手動設 10.254.254.2/24。
- 所以 wnc-gw 的設定也用名稱（`eth0`、`eth1.20`），不用 MAC。

Pi 的 eth0 另外有一個 NetworkManager 設定「Wired connection 1」：固定 172.24.8.131/24（接學校網路用），**沒有 IPv6**。demo 時 eth0 會被移進 netns `wgw`，這個設定暫時失效；`down` 之後 eth0 回到主 namespace，NetworkManager 會自己套回去。

## 2. 筆電端：確認接線、設管理位址

### 自動判斷（建議）

```bash
筆電$ TARGET=phys bash tests/demo/demo.sh wiring
NIC              CABLE  SEES PI eth1 (IPv6)          IPv4
eno2             yes    fe80::1f9d:9dcc:3f01:5e15    10.254.254.1/24
enx9c69d3241bd9  yes    none                         -

Pi eth1 (management + WAN) is on eno2; Pi eth0 (LAN) is on enx9c69d3241bd9
use: LAN_NIC=enx9c69d3241bd9 WAN_NIC=eno2 TARGET=phys bash tests/demo/demo.sh up   (up picks the same ones by itself)
```

原理：對每張有線網卡 `ping -6 ff02::1%<網卡>`（同一條線上所有 IPv6 節點都會回）。Pi 只有 eth1 開 IPv6（eth0 是關的），所以**有收到 Pi 回應的那張就是接到 Pi eth1 的**。這個方法不需要任何 IPv4 位址，也不用 sudo。

- `CABLE no`：那張網卡沒接線或對方沒開機。
- 兩張都 `none`：Pi 還沒開好（開機約 1 分鐘），或兩條線都沒插到 Pi 的 USB 網卡。
- 如果接到 Pi eth1 的那張沒有 10.254.254.1，`wiring` 會印出要下的指令。

### 手動設管理位址

```bash
筆電$ sudo ip addr add 10.254.254.1/24 dev eno2     # eno2 換成 wiring 說的那張
筆電$ ping -c 2 10.254.254.2
```

- 這個位址**筆電重開機就沒了**，要再下一次（筆電目前沒有替 eno2 存 NetworkManager 設定）。
- 想永久保存可以建一個 NetworkManager 設定（綁介面名稱，所以之後要固定用同一張網卡接 Pi eth1）：
  `sudo nmcli con add type ethernet ifname eno2 con-name pi-mgmt ipv4.method manual ipv4.addresses 10.254.254.1/24 ipv6.method link-local`
- 如果換線之後管理位址要換到另一張網卡：先 `sudo ip addr del 10.254.254.1/24 dev <舊的>`，再加到新的。

### 手動確認接線的指令

| 指令 | 看什麼 |
|---|---|
| `ip -br link` | 每張網卡的狀態；有接線的是 `UP` 而且有 `LOWER_UP` |
| `cat /sys/class/net/<網卡>/carrier` | 1 = 有接線、對方有開 |
| `ethtool <網卡> \| grep -E 'Speed\|Link detected'` | 速度（應該是 1000Mb/s）和連線 |
| `ip -br addr` | 每張網卡的位址 |
| `ping -6 -c 2 ff02::1%<網卡>` | 這條線上有誰（自己的位址也會回） |
| 筆電 `sudo dmesg -w` 然後拔插網路線 | 看是哪張網卡 link up／down |

## 3. ssh 進 Pi

```bash
筆電$ ssh wnc@10.254.254.2
```

- 帳號 `wnc`，用金鑰登入（這台筆電已經設好，不用密碼）；Pi 上 `sudo` 不用密碼。
- 換一台筆電：`ssh-keygen`（如果還沒有金鑰），再 `ssh-copy-id wnc@10.254.254.2`（要輸入一次 wnc 的密碼）。

**10.254.254.x 不通時的備援**（都只要網路線接到 Pi eth1）：

| 方法 | 指令 | 說明 |
|---|---|---|
| mDNS（Pi 的主機名稱 `wnc-project`） | `ssh wnc@wnc-project.local` | Pi 有跑 avahi。第一次用這個名字會問要不要信任主機金鑰，回 yes；或加 `-o HostKeyAlias=10.254.254.2` 沿用原本的 |
| IPv6 link-local | `ssh wnc@fe80::1f9d:9dcc:3f01:5e15%eno2` | 筆電不用設任何 IPv4。`%eno2` 換成接到 Pi eth1 的網卡；Pi 的位址可以用 `ping -6 -c 2 ff02::1%eno2` 找（不是筆電自己的那個就是 Pi） |
| 線插到 Pi eth0 了 | 把線改插 Pi 的 USB 網卡 | eth0 沒有 IPv6、位址是學校網段的 172.24.8.131，不要用它當管理線：demo 一開始就會把 eth0 移走，ssh 會斷 |

Pi 開機後先做的事：

```bash
筆電$ ssh wnc@10.254.254.2 sudo date -u -s @$(date +%s)   # Pi 沒有網路校時，不校的話 log 的時間是錯的
筆電$ ssh wnc@10.254.254.2 systemctl is-active suricata     # 開機會自動跑系統的 Suricata；demo 的 up 會把它停掉
```

關機：`ssh wnc@10.254.254.2 sudo poweroff`，等 Pi 的綠燈不再閃再拔電源。**Pi 關機後不能遠端開機**，要拔插電源。

## 4. 把 wnc-gw 放到 Pi

```bash
筆電$ cd security_gateway
筆電$ CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld cargo build --release --target aarch64-unknown-linux-musl
筆電$ ssh wnc@10.254.254.2 mkdir -p demo
筆電$ scp target/aarch64-unknown-linux-musl/release/wnc-gw wnc@10.254.254.2:demo/
筆電$ ssh wnc@10.254.254.2 demo/wnc-gw --version
```

`demo.sh` 不用自己複製：`TARGET=phys … up` 每次都會把筆電上的版本複製到 Pi 的 `~/demo/demo.sh`。

## 5. Pi 上的 demo 網路（`up` 做了什麼）

`TARGET=phys bash tests/demo/demo.sh up` 會 ssh 到 Pi 執行下面這些（Pi 上的 `TARGET=pigw … up`），想自己做或要理解時可以照著打：

```bash
Pi$ sudo systemctl stop suricata                          # 系統的 Suricata 會搶 NFLOG／網卡
Pi$ sudo modprobe br_netfilter                            # 讓 bridge 上的封包經過 nftables（沒載入時 wnc-gw 的規則完全被繞過）
Pi$ sudo ip netns add wgw                                 # gateway 的網路放在獨立的 netns，eth1（ssh）留在外面
Pi$ sudo ip link add link eth1 name eth1.20 type vlan id 20   # 管理線上的 VLAN 20 當 WAN
Pi$ sudo ip link set eth1.20 netns wgw
Pi$ sudo ip link set eth0 netns wgw                       # eth0 從主 namespace 消失是正常的
Pi$ sudo ip -n wgw link add br0 type bridge
Pi$ sudo ip -n wgw link set eth0 master br0; sudo ip -n wgw link set eth1.20 master br0
Pi$ sudo ip -n wgw link set eth0 up; sudo ip -n wgw link set eth1.20 up; sudo ip -n wgw link set br0 up
Pi$ sudo mount -t tmpfs -o size=1g,mode=0750 wncgw-suricata-log /var/log/wnc-gw/suricata   # Suricata 的 log 寫記憶體，不寫 SD 卡
Pi$ sudo ip netns exec wgw sysctl -w net.netfilter.nf_conntrack_acct=1   # 自動信任要每條連線的封包數（每個 netns 各一份）
```

再寫三個設定檔到 `~/demo/run/`（第 6 節）。筆電那一半：建兩個 Docker macvlan 網路（`demo-lan` 掛在 LAN_NIC、`demo-wan` 掛在 WAN_NIC 的 VLAN 20），各放一個容器（`dcli` 10.9.0.1、`dsrv` 10.9.0.130），在 server 上啟動 5001、8080 兩個服務，最後從 client ping server 確認封包有經過 Pi。

看 Pi 上的網路：

| 指令 | 看什麼 |
|---|---|
| `Pi$ ip netns list` | 應該有 `wgw` |
| `Pi$ sudo ip -n wgw -br link` | `eth0`、`eth1.20`、`br0` 都是 UP |
| `Pi$ sudo bridge -n wgw link` | `eth0`、`eth1.20` 都是 `master br0`、`state forwarding` |
| `Pi$ sudo bridge -n wgw fdb show br br0 \| grep -v permanent` | bridge 學到的 MAC（有流量時會看到兩個容器的 MAC） |
| `Pi$ ip -br addr show eth1` | 管理線還是 10.254.254.2（`up` 不會動它） |

拆掉：`TARGET=phys bash tests/demo/demo.sh down`。手動拆：`Pi$ sudo ip netns del wgw`（eth0 自己回到主 namespace，eth1.20 一起消失），`Pi$ sudo umount /var/log/wnc-gw/suricata`。

## 6. wnc-gw 的設定

### 設定檔

demo 的設定檔是 Pi 上的 `~/demo/run/setting.toml`（`up` 寫的，每次 `up` 都會覆蓋）；沒有 `-c` 時 wnc-gw 讀 `/etc/wnc-gw/setting.toml`。每個欄位的完整說明在 `security_gateway/setting.example.toml`。

```toml
mode = "bridge"          # LAN、WAN 是同一個 bridge 的兩個 port（透明部署）；"routed" 是兩個網段之間做路由
xdp = "off"              # 核心 eBPF 程式掛哪裡（還沒實作，只有 doctor 會判斷）
protection = "ids"       # ids：kernel 立刻轉送、另外送一份複本給 Suricata（不擋）；ips：封包等 Suricata 判決（會擋）

[ports]
lan = "eth0"             # 內網那一側；可以寫介面名稱或 MAC
wan = "eth1.20"          # 外網那一側；eth1.20 和 eth1 同一個 MAC，所以這裡一定要寫名稱

[suricata]
config = "/home/wnc/demo/run/s.yaml"   # Suricata 的設定：include 系統的 suricata.yaml，只換規則
# eve_interval = 0.5     # 幾秒讀一次 Suricata 的 alert（預設 0.5）
# when_unavailable = "accept"   # Suricata 還沒好或掛掉時：accept 放行、drop 丟掉

[trust]
auto = true              # 自動信任（預設 false）
min_packets = 10         # 兩個方向各要多少封包
min_age = 5              # 至少觀察幾秒
ttl = 60                 # 信任幾秒（demo 為了看得到到期才設 60；預設 900）
check_interval = 2       # 幾秒讀一次 conntrack（預設 5）
```

- 想改數值（例如 `ttl`）：在 Pi 上改 `~/demo/run/setting.toml`，停掉 `run` 再啟動；不要再 `up`（會覆蓋回去）。
- 規則：`~/demo/run/demo.rules`（兩條）；`RULES=full` 時 `s.yaml` 另外載入 `~/ids_throughput/data/rules/suricata_full.rules`（ET Open 快照）。

### 選 port：`show interfaces`

ports 在 netns `wgw` 裡，所以要在裡面看：

```bash
Pi$ sudo ip netns exec wgw ~/demo/wnc-gw show interfaces
```

印出每張網卡的名稱、目前 MAC、出廠 MAC（PERM）、狀態、driver。`[ports]` 寫 MAC 時先比對出廠 MAC。臨時換 port 不用改檔案：`--lan <名稱或 MAC> --wan <名稱或 MAC>` 會蓋過設定檔。

### 檢查：`doctor`

```bash
Pi$ sudo ip netns exec wgw ~/demo/wnc-gw -c ~/demo/run/setting.toml doctor
筆電$ TARGET=phys bash tests/demo/demo.sh doctor            # 一樣的東西
```

由上往下看：
1. 開頭幾行：設定檔、`mode`、`protection`、`trust`，括號是值的來源（config file／default）。
2. `ROLE …` 表：LAN、WAN 對到哪張網卡、怎麼對到的（name／MAC）、是不是 UP。
3. `BRIDGE MODE CHECK`：LAN、WAN 在同一個 bridge、`br_netfilter` 的兩個 sysctl 是 1。
4. kernel 模組、nft、Suricata 版本（要有 NFLOG、READY NOTIFY）、Suricata 設定和規則檔、eve-log（`alerts, read every 0.5 s`）。
5. 最後的 `warning:` 是提醒（ids 不擋流量、自動信任的風險等，demo 裡都是刻意的）；**有 `error:` 時 `run` 不會啟動**，exit code 不是 0。

常見的 error：`nf_conntrack_acct` 是 0（沒在 `wgw` 裡設）、LAN／WAN 不在同一個 bridge、找不到 port。

### 執行：`run`

```bash
筆電$ TARGET=phys bash tests/demo/demo.sh run                 # 前景，Ctrl-C 停止（會先移除 nft table、停 Suricata）
Pi$ sudo ip netns exec wgw ~/demo/wnc-gw --log-level debug -c ~/demo/run/setting.toml run   # 直接在 Pi 上
```

- `--log-level`：`info`（預設，只有重要事件和每 60 秒的 alert 摘要）、`debug`（每筆 alert、信任到期、拒絕信任）。
- `--log-format json`：每行一個 JSON，方便之後用程式處理。
- 背景跑：`run-bg`／`stop`，log 在 Pi 的 `~/demo/run/run.log`（`筆電$ ssh wnc@10.254.254.2 tail -f demo/run/run.log`）。
- 同時只能有一個 wnc-gw 在跑。

## 7. 檢查指令

Pi 上的指令幾乎都要 `sudo`，而且 gateway 的東西都在 netns `wgw` 裡：下面寫 `W` 的地方代表 `sudo ip netns exec wgw`（可以先 `Pi$ W="sudo ip netns exec wgw"`）。

### nftables

```bash
Pi$ $W nft list tables                       # 跑起來時有 table inet wnc_gw
Pi$ $W nft list table inet wnc_gw            # 整個 table 和每條規則的計數
Pi$ $W nft list chain inet wnc_gw ids        # 只看送給 Suricata 的計數
Pi$ watch -n 1 "sudo ip netns exec wgw nft list chain inet wnc_gw ids"   # 每秒更新
Pi$ $W nft -a list table inet wnc_gw         # 多印每條規則的 handle
Pi$ $W nft list ruleset                      # 這個 netns 裡所有 table
```

跑起來、有一條被信任的連線時大概長這樣：

```
table inet wnc_gw {
	chain ids {
		counter packets 157 bytes 9335 log group 10 accept
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		counter packets 163 bytes 9692
		tcp flags & (syn | ack) == syn ct mark & 0x80000000 == 0x80000000 counter packets 0 bytes 0 ct mark set ct mark & 0x7fffffff
		ct mark & 0x40000000 == 0x00000000 ct mark set ct mark | 0x40000000
		tcp flags fin,syn,rst jump ids
		ct mark & 0x80000000 == 0x80000000 counter packets 6 bytes 357 accept
		jump ids
	}
}
```

| forward 的規則（由上往下比對） | 意思 |
|---|---|
| `counter` | 所有經過 gateway 的封包 |
| `tcp flags & (syn \| ack) == syn ct mark & 0x80000000 …` | 只有 SYN、但連線帶著信任位元：同一組 port 被新連線重用，清掉信任 |
| `ct mark & 0x40000000 == 0 … set … \| 0x40000000` | 連線第一次經過就設 forwarded 位元（自動信任只看有這個位元的連線） |
| `tcp flags fin,syn,rst jump ids` | 連線的開始和結束一律送給 Suricata，信任了也一樣 |
| `ct mark & 0x80000000 == 0x80000000 counter … accept` | 被信任的連線：直接放行，**這個計數是跳過檢查的封包數** |
| `jump ids` | 其他都送給 Suricata |

`ids` chain 的內容看狀態：ids 模式下是 `log group 10 accept`（送一份複本、照樣轉送）；ips 模式是 `queue … to 0`；Suricata 還沒就緒或掛掉時是 `counter accept`（`when_unavailable = "drop"` 時是 `counter drop`）。**ids chain 的計數停住不動 = 流量被信任、沒有送給 Suricata。**

想把每條規則的計數歸零重新觀察：`Pi$ $W nft reset rules table inet wnc_gw`（`reset counters` 只清具名的 counter 物件，對這裡沒用）。wnc-gw 被 `kill -9` 時 table 會留下來，下次 `run` 會整個換掉；不再跑的話手動刪：`Pi$ $W nft delete table inet wnc_gw`。

### 信任與 conntrack

```bash
Pi$ $W ~/demo/wnc-gw trust list                                        # 被信任的連線
Pi$ $W ~/demo/wnc-gw trust add tcp 10.9.0.1 <client port> 10.9.0.130 5001   # 手動信任一條連線（反方向的五元組也可以）
Pi$ $W ~/demo/wnc-gw trust del tcp 10.9.0.1 <client port> 10.9.0.130 5001
Pi$ $W cat /proc/sys/net/netfilter/nf_conntrack_count                  # 目前有幾條連線
Pi$ $W sysctl net.netfilter.nf_conntrack_acct                          # 要是 1
Pi$ $W ~/ctbench/root/usr/sbin/conntrack -L                            # 所有連線（含計數、mark）；Pi 沒裝系統的 conntrack，這是實驗時編的
```

`trust list` 的 MARK 欄：`0x80000000` 信任、`0x40000000` 經過 gateway，兩個都有就是 `0xc0000000`。TIMEOUT 是 conntrack 的逾時（秒），不是信任的 TTL；信任的 TTL 由 wnc-gw 自己計時，到期時 log 有 `trust expired`。

### Suricata

```bash
Pi$ pgrep -a Suricata-Main                    # 程序；系統的 Suricata 也叫這個名字，看命令列有沒有 --nflog 和 /run/wnc-gw
Pi$ ps -o pid,pcpu,rss,etime -C Suricata-Main # CPU、記憶體、跑了多久
Pi$ sudo tail -f /var/log/wnc-gw/suricata/fast.log                       # 每筆 alert 一行
Pi$ sudo grep '"event_type":"alert"' /var/log/wnc-gw/suricata/eve.json | tail -3
Pi$ sudo grep -E '^(capture|detect\.alert|decoder\.pkts)' /var/log/wnc-gw/suricata/stats.log | tail -6   # 每 8 秒的統計
筆電$ ssh wnc@10.254.254.2 sudo cat /var/log/wnc-gw/suricata/eve.json | jq -c 'select(.event_type=="alert") | {src_ip, src_port, dest_ip, dest_port, sig: .alert.signature}' | tail
```

- Pi 沒有 `jq`，要整理 eve.json 時拿回筆電看（上面最後一行）。
- Suricata 自己的 log 也會出現在 wnc-gw 的 log 裡（帶 `source="suricata"`）。
- wnc-gw 的 log 裡每筆 alert 都有 `flow_id`，可以拿去 eve.json 找同一條連線的完整紀錄：`sudo grep '"flow_id":<數字>' eve.json`。
- `/var/log/wnc-gw/suricata` 是 tmpfs，`down` 或重開機後就沒了；要留的話先複製出來。

### 看封包

```bash
Pi$ $W tcpdump -ni eth0 -c 20                 # LAN 那一側
Pi$ $W tcpdump -ni eth1.20 -c 20              # WAN 那一側
Pi$ $W tcpdump -ni br0 -c 20 host 10.9.0.1    # 只看 client 的
Pi$ $W ip -s link show eth0                   # 收送封包數、丟包
Pi$ $W ethtool -S eth0 | grep -E 'rx_packets|tx_packets|drop|pause'
```

**不要 `tcpdump -i nflog:10`**：Suricata 正在用 NFLOG group 10，另一個程式綁同一個 group 會搶走或讓 Suricata 起不來。

封包進了 Pi 卻沒轉送出去、丟包計數器又都是 0 時，看 kernel 記的丟包原因（kfree_skb tracepoint；`location` 是丟在哪個函式，`reason` 是原因）：

```bash
Pi$ T=/sys/kernel/tracing; sudo sh -c "echo > $T/trace; echo 1 > $T/events/skb/kfree_skb/enable"
#   …送一次流量…
Pi$ sudo sh -c "echo 0 > $T/events/skb/kfree_skb/enable"
Pi$ sudo grep -o 'location=.*reason: [A-Z_0-9]*' $T/trace | sed 's/+0x[0-9a-f/x]*//' | sort | uniq -c | sort -rn | head
```

`dev_kfree_skb_any_reason … NOT_SPECIFIED` 是網卡送完後的正常釋放，不用管。11/05 演練時看到的是 `br_nf_pre_routing … IP_INHDR`：IPv4 header 有錯，例如 checksum，被 br_netfilter 丟掉。

### 筆電端（client／server 容器）

```bash
筆電$ docker ps --filter name=dcli --filter name=dsrv
筆電$ docker exec dcli ip -br addr            # 10.9.0.1
筆電$ docker exec dcli ping -c 2 10.9.0.130   # 經過 Pi 到 server
筆電$ docker network inspect demo-lan -f '{{index .Options "parent"}}'   # 這個網路掛在哪張網卡
```

## 8. 出問題時

| 狀況 | 先查 | 處理 |
|---|---|---|
| ssh 不到 Pi | `TARGET=phys … wiring`；筆電那張有沒有 10.254.254.1 | 第 2、3 節；用 mDNS 或 IPv6 備援 |
| `up` 最後說 `NOT reachable` | `wiring`；`Pi$ sudo ip -n wgw -br link`、`sudo bridge -n wgw link` | LAN 那條線是不是插在 Pi 本身的網口（eth0）；`down` 再 `up` |
| doctor 有 error | 照 error 的說明 | 最常見：`nf_conntrack_acct` 是 0 → `Pi$ $W sysctl -w net.netfilter.nf_conntrack_acct=1` |
| Suricata 起不來、log 有 `cannot bind the nflog group` | `Pi$ pgrep -a Suricata-Main`、`systemctl is-active suricata` | `Pi$ sudo systemctl stop suricata`；或另一個 wnc-gw 還在跑（`pgrep -a wnc-gw`） |
| log 的時間不對 | `Pi$ date -u` | 第 3 節的校時 |
| 流量都沒有被信任 | `trust list`、log 有沒有 `conntrack keeps no packet counters` | `nf_conntrack_acct` 要在連線**建立之前**就是 1；重新開一條連線 |
| wnc-gw 被強制結束 | `Pi$ $W nft list tables` | 再 `run` 一次（會換掉舊的 table），或手動刪 table |
| `replay` 之後沒有 alert | 第 7 節「看封包」的 kfree_skb；`Pi$ sudo grep -c '"alert"' /var/log/wnc-gw/suricata/eve.json` | `replay` 會先用 `tcprewrite --fixcsum` 修正 checksum（IoT-23 從路由器來的封包 checksum 是 0，br_netfilter 會丟掉）；規則要 `RULES=full`；同一個 pcap 再播一次前要重新 `run` |
| 想全部重來 | | `TARGET=phys … down`，再 `up` |

手動收拾（`down` 失敗時）：

```bash
筆電$ docker rm -f dcli dsrv; docker network rm demo-lan demo-wan
Pi$ sudo pkill -INT -x wnc-gw; sudo ip netns del wgw; sudo umount /var/log/wnc-gw/suricata
```
