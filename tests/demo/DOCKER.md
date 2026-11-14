# Docker demo（手動操作）

先介紹 wnc-gw 的開發與功能，再用指令重播 dataset 裡的 flow，看 wnc-gw 的 log 和信任的狀態：哪些連線被信任、哪些被 Suricata 偵測到而不信任、信任到期；中間用 iperf3 看信任前後的速度。全部在筆電的 Docker testbed 上做，指令都是手打（或從這份文件複製），沒有包裝腳本；只有不需要展示的準備工作放在 `prep_docker.sh`。

## 環境

```
                         wnc-rep 10.0.1.3 / 10.0.2.3（重播 pcap，兩邊各一張網卡：lan、wan）
                           │                      │
wnc-cli 10.0.1.2 ──[lan 10.0.1.0/24]── 10.0.1.1 [wnc-gw] 10.0.2.1 ──[wan 10.0.2.0/24]── wnc-srv 10.0.2.2（iperf3 server）
```

| 容器 | 做什麼 | 對應到實機 |
|---|---|---|
| `wnc-gw` | 跑 wnc-gw 和 Suricata，`mode = "routed"` | Pi |
| `wnc-cli`、`wnc-srv` | iperf3 的兩端（量速度） | 內網的設備、外網的伺服器 |
| `wnc-rep` | 重播 dataset 的 pcap：設備送出的封包從 `lan` 送進 gw 的 LAN，路由器那側的封包從 `wan` 送進 gw 的 WAN | 實機 demo 裡筆電的兩張網卡 |

用到的檔案（`docker/wnc-gw/` 整個目錄唯讀掛到 gw 的 `/etc/wnc-gw/`，改了不用重建容器）：

| repo 裡 | gw 容器裡 | 內容 |
|---|---|---|
| `docker/wnc-gw/demo.toml` | `/etc/wnc-gw/demo.toml` | demo 的設定：ids、自動信任（10 個封包、5 秒、ttl 60 秒、每 2 秒檢查） |
| `docker/wnc-gw/demo-suricata.yaml` | `/etc/wnc-gw/demo-suricata.yaml` | include 系統的 `suricata.yaml`，只把規則換成 `et_all.rules` |
| `docker/suricata-rules/et_all.rules` | `/var/lib/suricata/rules/et_all.rules` | ET Open 完整規則 52,798 條，和偵測評估（`tests/detection/README.md`）同一份；不進 git |
| `tests/demo/pcaps/*.pcap` | `wnc-rep` 的 `/pcaps/` | 改寫好的 pcap 和 `.cache`（哪個封包走哪一邊）；不進 git |

## 要重播的 flow

都是 IoT-23 的 scenario 開頭 500 個封包，用全部規則離線（`suricata -r`）跑過，結果和送進 gw 的一樣。

| 檔案 | 來源 | 內容 | 結果 |
|---|---|---|---|
| `somfy.pcap` | Honeypot-7-1（Somfy 門鎖，良性） | 一條 HTTPS 長連線 `192.168.1.158:10366 → 18.195.134.106:443`，兩個方向各兩百多個封包 | 沒有 alert，重播開始後 6–8 秒被信任 |
| `muhstik.pcap` | 3-1（Muhstik 殭屍網路） | 被感染的設備 `192.168.2.5` 連兩台 IRC CnC（port 2407），另外有 NTP 校時 | 3 筆 alert（`ET MALWARE ELF/Muhstik - IRC CnC Checkin` ×2、`ET INFO IRC Channel JOIN on non-standard port`），兩條 CnC 都不信任；同一台設備的 3 條 NTP 被信任；停止時可能再多 2 筆（第 8 步） |

`prep_docker.sh` 另外會準備 `mirai.pcap`（34-1，ELF 下載不信任、SSH 信任），在 wnc-gw 的 log 裡和 Muhstik 是同樣的幾種訊息，所以 demo 沒有用。

`prep_docker.sh` 對 pcap 做的事：修正 checksum（IoT-23 從路由器來的封包 IP checksum 是 0，kernel 會丟掉）、依路由器的 MAC 分成兩邊、目的 MAC 改成 gw 的兩張網卡。**IP 和 port 沒有改**，所以 log 和 eve.json 裡的位址就是 dataset 原本的。gw 另外加了兩條路由（`192.168.0.0/16` 往 LAN、其他往 WAN），下一跳是不存在的 MAC：封包經過 gw 的 forward（nft、Suricata 在這裡）之後送出去，沒有人收。

## 事前準備（demo 前做好）

```bash
cd security_gateway && cargo build --target x86_64-unknown-linux-musl && cd ..
cd docker && ./up.sh && cd ..
bash tests/demo/prep_docker.sh         # gw 容器重建（./down.sh、./up.sh）後要再跑一次
docker exec wnc-gw conntrack -F        # 每次 run 之前都清一次，原因見「注意」
```

開三個終端機：

| 終端機 | 用途 |
|---|---|
| T1 | wnc-gw 的 log |
| T2 | 送流量 |
| T3 | 看狀態 |

## 流程

1. **設定**（T3）：`cat docker/wnc-gw/demo.toml`
   講：`mode`、`protection`、`[ports]` 用 MAC 指定、`[suricata]` 指到 Suricata 的設定、`[trust]` 的四個值。ttl 只設 60 秒是為了看得到到期，預設是 900 秒。

2. **檢查**（T3）：`docker exec wnc-gw /opt/sg/wnc-gw -c /etc/wnc-gw/demo.toml doctor`
   看：ROLE 表（LAN、WAN 對到哪張網卡）、ROUTED MODE CHECK、kernel 模組、Suricata 版本與 NFLOG、規則檔、eve-log。沒有 error。
   warning 都是刻意的：ids 不擋流量、checksum 不檢查、流量太快時會漏檢、自動信任的風險、Suricata 由 wnc-gw 啟動。「can be modified without root」是因為設定檔從筆電掛進去，擁有者是筆電的帳號，Pi 上放在 root 的 `/etc/wnc-gw` 就不會出現。

3. **啟動**（T1）：`docker exec -it wnc-gw /opt/sg/wnc-gw --log-level debug -c /etc/wnc-gw/demo.toml run`
   看：`table installed`、`automatic trust is on`、`suricata started`，約 15 秒後（載入 52,798 條規則）`suricata is ready`、`forwarded traffic is inspected … uninspected_ms=…`。
   講：table 先裝好，Suricata 就緒前的流量照樣轉送但沒有檢查，這段時間會記在 log。

4. **良性的 flow 被信任**（T2）：`docker exec wnc-rep tcpreplay -i wan -I lan -c /pcaps/somfy.cache --pps=50 /pcaps/somfy.pcap`
   每秒 50 個封包、10 秒。約 6–8 秒後 T1 只有這一行，沒有任何 alert：`INFO connection trusted; … connection="tcp 192.168.1.158:10366 -> 18.195.134.106:443" packets_original=… packets_reply=… ttl_s=60`（`packets_*` 是 wnc-gw 第一次看到這條連線之後的封包數，每次不一樣）
   T3：
   ```bash
   docker exec wnc-gw /opt/sg/wnc-gw trust list        # 這條連線，MARK 0xc0000000（0x80000000 信任＋0x40000000 經過 gw 轉送）
   docker exec wnc-gw nft list table inet wnc_gw       # ids chain 約 270–365；「ct mark & 0x80000000 … accept」約 90–185；加起來一定是 456
   ```
   講：wnc-gw 每 2 秒讀 conntrack 的封包數，兩個方向都有 10 個、觀察滿 5 秒、Suricata 沒有 alert，就在連線上設 ct mark；之後這條連線除了 SYN／FIN／RST 都不再送給 Suricata。`ids` 的計數是送去檢查的，`0x80000000 … accept` 的計數是跳過檢查的，加起來 456 就是這條連線全部的 TCP 封包（212 + 244）。
   為什麼每次分法不一樣：第一個封包建出 conntrack 之後，wnc-gw 要等下一次讀（0–2 秒後）才看到這條連線，從那時開始算 `min_age`；之後每 2 秒檢查一次，經過 4 秒時還不到 5 秒，6 秒時才信任（`min_age` 實際上會進位到 `check_interval` 的倍數）。所以信任在第一個封包之後 6–8 秒，照每秒 50 個封包算，送去檢查的是 272（6 秒）到 364（8 秒）個。11/05 是 292／164（約 6.5 秒），11/06 是 359／97（約 7.9 秒）。
   60 秒後這條的信任到期，T1 出現 `DEBUG trust expired; connection is inspected again`，這時大概在做第 5、6 步（見第 7 步）。

5. **速度：信任前後**（T2）：`docker exec wnc-cli iperf3 -c 10.0.2.2 -t 15 -i 1`
   每秒印一次速度：信任前約 30 Gbit/s，第 6–8 秒 T1 出現 `connection trusted … connection="tcp 10.0.1.2:… -> 10.0.2.2:5201"`（6–8 秒的原因同第 4 步），之後約 50 Gbit/s（沒有 wnc-gw 時是 48–54）。
   T1 在信任前會有這些 WARN：
   - 一開始，Suricata 自己印的（wnc-gw 轉印，`source="suricata"`）：`WARN nflog: Maximum buffer size (2097152) in NFLOG has been reached. Please, consider raising buffer-size and max-size in nflog configuration`。Suricata 收複本的接收緩衝區滿了，kernel 再送來的複本放不進去就丟掉。2097152 是 2 MiB：wnc-gw 給 Suricata 的 `buffer-size` 是 1 MiB（`max-size` 4 MiB，`src/ids/spawned.rs`），Linux 會把 socket 接收緩衝區的設定值乘 2。
   - 每 10 秒，wnc-gw 自己數的：`WARN suricata missed packet copies; that traffic was forwarded without inspection missed=… interval_s=10`。數字是 kernel 記的 Suricata NFLOG socket 的 Drops，就是上一行丟掉的那些。11/06 是 578,191，下一次 254,727（那 10 秒裡只有信任前的 2 秒多還在複製），之後信任的封包不再複製，就不再出現。
   兩行是同一件事：Suricata 說緩衝區滿了，wnc-gw 說漏了多少。緩衝區調大也沒用：iperf3 一直送得比 Suricata 處理得快，再大也很快滿，緩衝區只能吸收短暫的突發，調大還要多用 kernel 記憶體。
   講：和第 4 步是同一件事，換成一條量得到速度的真的 TCP 連線。ids 模式下封包本來就不等 Suricata，但 kernel 還是要把每個封包複製一份給 Suricata，這個複製本身就有成本；信任之後不複製，速度回到沒有 gateway 的水準。流量比 Suricata 收複本還快時會漏檢，wnc-gw 會記下漏了多少。這是筆電的數字；Pi 上是固定速率下量 CPU（簡報第 5、6 頁）。

6. **Muhstik：偵測到的連線不信任**（T2）：`docker exec wnc-rep tcpreplay -i wan -I lan -c /pcaps/muhstik.cache --pps=50 /pcaps/muhstik.pcap`
   pcap 裡是被感染的設備 `192.168.2.5`：2 條 IRC CnC（送 `NICK A5|1|5358668|black-pe`、`USER muhstik …`，加入頻道 `#a925d765`）、4 條 NTP、62 條連 `200.168.87.203:59353` 只有 SYN 沒有回應的連線、1 條從路由器 SSH 進來的連線（9 個封包）。
   約 3 秒內 T1：
   ```
   DEBUG suricata alert connection="tcp 192.168.2.5:45623 -> 111.230.241.23:2407" sid=2029319 signature="ET MALWARE ELF/Muhstik - IRC CnC Checkin"
   DEBUG suricata alert connection="tcp 192.168.2.5:48654 -> 51.38.81.99:2407" sid=2029319 signature="ET MALWARE ELF/Muhstik - IRC CnC Checkin"
   DEBUG suricata alert connection="tcp 192.168.2.5:48654 -> 51.38.81.99:2407" sid=2000348 signature="ET INFO IRC Channel JOIN on non-standard port"
   DEBUG suricata alerted on a watched connection; it will not be trusted connection="tcp 192.168.2.5:45623 -> 111.230.241.23:2407" …
   DEBUG suricata alerted on this connection before it was watched; it will not be trusted connection="tcp 192.168.2.5:48654 -> 51.38.81.99:2407"
   ```
   兩種「不信任」的寫法結果一樣：第二條的 alert 比 wnc-gw 第一次讀到這條連線（每 2 秒讀一次）還早，wnc-gw 先把 alert 記 10 分鐘，看到連線時直接不信任。
   第 7–10 秒 3 條 NTP `connection trusted`（`37.157.198.150`、`31.31.74.35`、`5.1.56.123`）。
   沒有 log 的：第 4 條 NTP（`78.108.102.237` 兩個方向各只有 10 個，wnc-gw 從第一次看到才開始算，最多算到 9 個）、62 條 SYN、SSH。這些一直在觀察，封包一直送給 Suricata。
   講：同一台被感染的設備，有 alert 的 CnC 連線永遠不信任，正常的 NTP 照樣信任；判斷是以連線為單位，不是以設備為單位。沒出現在 log 的連線都一直被檢查：預設是檢查，信任是例外。

7. **信任到期**（T1、T3）：Muhstik 重播完後再等約 60 秒（可以邊講邊等）。
   T1：每條被信任的連線在信任 60 秒後各一行 `DEBUG trust expired; connection is inspected again connection=…`：Somfy、iperf3、3 條 NTP。Somfy、iperf3 的大概在第 5、6 步時就會出現。iperf3 的連線已經結束，conntrack 還會留著它（TIME_WAIT 約 2 分鐘），所以預期一樣會看到到期，還沒在演練確認。
   T3：`docker exec wnc-gw /opt/sg/wnc-gw trust list` 一條條變少，最後是空的。
   講：信任到期後連線回到 Suricata、重新觀察；重播已經結束、沒有新的封包，所以不會再被信任。`ttl` 預設 900 秒。Suricata 對已信任的連線發出 alert 時會立刻撤銷（`WARN … trust revoked`），這次的 flow 不會觸發，用口頭說明。

8. **停止**（T1）：按 Ctrl-C，看到 `stopping`、`WARN table removed; forwarded traffic passes without inspection`。
   可能多出 Muhstik 的 `ET MALWARE ELF/Muhstik Botnet CnC Activity`（sid 2034743）：這條規則要等連線結束才判斷，Suricata 停止時才把還開著的連線結束掉。Pi 上演練看過（停止時記在 alert 的統計裡），Docker 上還沒確認。這兩條 CnC 本來就不信任，結果不變。

T1 每 60 秒還會各出現一行統計（`automatic trust trusted=… expired=… refused=… trusted_now=…`、`suricata raised alerts …`），和操作到哪一步無關。

## ips（報告時口頭說明，不現場示範）

目前沒有任何 `drop` 規則，現場跑 ips 看起來和 ids 一樣，所以只說明。可以講的：

- **已經實作**：`protection = "ips"` 用 NFQUEUE，封包等 Suricata 的判決才轉送；Suricata 還沒就緒或掛掉時照 `when_unavailable` 放行或丟掉，一樣記 log（`security_gateway/DECISIONS.md` §11）。
- **擋流量要靠規則的 action 是 `drop`**：ET Open 的 52,798 條全部是 `alert`，哪些要改成 `drop` 還沒決定，所以現在 ips 也不擋任何東西。wnc-gw 自己的擋（nft 黑名單）還沒做。
- **實測過擋得住**（2026-11-05，Docker、Suricata 8.0.7，把 3 條規則改成 `drop`）：
  - 真的 TCP 連線，server 回 `uid=0(root)`：ips 下 client 6 秒收到 0 bytes，log 是 `action="blocked"`；ids 下同一條規則只有 alert，client 照樣收到。
  - 重播 Muhstik：觸發規則的那個 `NICK` 封包沒有轉送出去，同一條連線的其他封包照樣轉送（66／67、18／20）。`drop` 丟的是比對到的封包，不是整條連線；真的 TCP 連線收不到，是因為重送的內容一樣又被丟。
- **信任在 ips 下省得更多**：iperf3 信任前約 1.1 Gbit/s（每個封包都要等 Suricata），信任後約 50 Gbit/s（筆電的數字）。

## 注意

- **每次 `run` 之前 `conntrack -F`**：`min_age` 是從 wnc-gw 第一次看到這條連線開始算。上一輪重播留在 conntrack 的連線，新的 `run` 一啟動就開始計時，再重播時 2 秒就被信任，看起來像 `min_age` 沒作用。同一個 pcap 要重播第二次，也要先停掉 wnc-gw 再重新 `run`：Suricata 會記得上一輪的連線狀態。
- **重播看不出速度**：tcpreplay 是照固定速率送，不管 gateway 快或慢都一樣；速度要用 iperf3 這種真的 TCP 連線（gateway 慢，它就送得慢）。
- **數字是筆電的**：Docker 共用筆電的 kernel 和 CPU，速度、Suricata 啟動時間都不代表 Pi。Pi 上量的見 `security_gateway/DECISIONS.md` §19（例如信任的封包每個省 38–68 µs）。Docker 是 `routed`，Pi 和預設是 `bridge`。
- **Suricata 版本**：Docker 和 Pi 一樣是 8.0.7。trixie-backports 11/03 換成 8.0.8，所以 `docker/Dockerfile` 從 snapshot.debian.org 取 11/02 的 backports，指定 `1:8.0.7-1~bpo13+1`。

## 演練紀錄（2026-11-05）

筆電 Docker、`et_all.rules`，照當時的流程依序做：啟動、Somfy、Muhstik、Mirai、iperf3、kill Suricata，下表的步驟編號是當時的。表格是 Suricata 8.0.8 那一次；換成 8.0.7 後重做第 2–7 步，alert、信任的連線都一樣，就緒 16.0 秒，iperf3 ids 28.7–31.7 → 47.1–52.4 Gbit/s。

| 步驟 | 結果 |
|---|---|
| 3 啟動 | 就緒 15.5 秒（`startup_ms=15540`） |
| 4 Somfy | 信任（`packets_original=128 packets_reply=148`）；ids chain 292、跳過檢查 164 |
| 5 Muhstik | 3 筆 alert、2 條不信任；3 條 NTP 信任 |
| 6 Mirai | 4 筆 alert、2 條不信任；SSH 信任（`packets_original=32 packets_reply=34`）；送出 497／500 |
| 7 iperf3 ids | 27.8–31.2 → 49.1–52.5 Gbit/s（第 7 秒信任）；漏掉的複本 371,678、533,159（每 10 秒） |
| 8 SIGKILL | 重新就緒 6.6 秒，`uninspected_ms=7572`；60 秒後 3 條 NTP 的信任到期 |
| iperf3 ips（口頭說明用） | 1.02–1.15 → 50.6–52.2 Gbit/s（第 7 秒信任） |
| 基準 | 沒跑 wnc-gw：48.0–53.8 Gbit/s |
