# Docker testbed 與 Pi

## 目錄
1. 建置與掛載
2. testbed 的拓樸
3. 常用指令
4. 模擬情境
5. Docker 會掩蓋的問題
6. 搬到 Pi

## 1. 建置與掛載

```bash
cd security_gateway
cargo build --target x86_64-unknown-linux-musl     # 靜態連結，容器裡不需要任何函式庫
cargo test  --target x86_64-unknown-linux-musl
```

gw 容器的掛載（`docker/compose.yml`）：

| 主機 | 容器 | 用途 |
|---|---|---|
| `security_gateway/target/x86_64-unknown-linux-musl/debug` | `/opt/sg`（唯讀） | 編好的 `wnc-gw` 在筆電重新編譯後，容器裡馬上看得到 |
| `docker/wnc-gw/` | `/etc/wnc-gw`（唯讀） | `setting.toml`，路徑和 Pi 上的預設路徑相同。掛的是目錄而不是單一檔案，因為編輯器存檔時常會換掉整個檔案，單檔掛載會因此失效 |
| `/lib/modules` | `/lib/modules`（唯讀） | 讓 doctor 看到和主機 `modprobe` 相同的模組清單。容器裡的模組自動載入，實際上是主機 kernel 呼叫主機的 modprobe |
| `docker/` | `/etc/wnc`（唯讀） | 舊的實驗檔案 |
| `docker/suricata-rules/` | `/var/lib/suricata/rules`（唯讀） | 只有一條 ICMP 規則的 `suricata.rules`，讓 Suricata 有規則可以載入（剛裝好的 Debian 沒有規則，doctor 會報 error）。改規則不用重建 image |

改了 `compose.yml` 之後要重建：`./down.sh && ./up.sh`。只改程式碼的話不用重建，重新編譯就好。

## 2. testbed 的拓樸

目前是 L3 routing，對應設定 `mode = "routed"`。D3 已決定兩種都支援、預設 bridge，但 bridge 的 testbed 還沒做：

```
cli 10.0.1.2 ── lan 10.0.1.0/24 ── eth0 [gw] eth1 ── wan 10.0.2.0/24 ── srv 10.0.2.2（iperf3 server）
                                   10.0.1.1  10.0.2.1
                                   MAC 02:00:00:00:01:01 / 02:00:00:00:02:01（固定）
```

- gw 有 `NET_ADMIN`、`NET_RAW`，並開了 `ip_forward=1`。
- MAC 在 compose 裡固定，否則每次重建容器都會變，設定檔就對不上。
- `docker/wnc-gw/setting.toml` 用 MAC 指定 LAN、WAN。veth 沒有出廠 MAC，所以實際上走的是「目前 MAC」這條路。
- image 是 Debian trixie，和 Pi OS 同一代。`docker/Dockerfile` 分成兩個 stage：`base`（`wnc-lab:latest`，cli、srv 用）內含 iproute2、nftables、conntrack、tcpdump、iperf3、ethtool；`gw`（`wnc-lab-gw:latest`）在 `base` 上加裝 trixie-backports 的 Suricata 8.0.7。容器裡沒有 systemd，Suricata 不會自己啟動。改了 Dockerfile 要重建：`./down.sh && ./up.sh`。

## 3. 常用指令

```bash
cd docker && ./up.sh                                        # 建 image、啟動、ping 驗證
docker exec -u nobody wnc-gw /opt/sg/wnc-gw doctor          # 用沒有權限的帳號執行
docker exec -u nobody wnc-gw /opt/sg/wnc-gw show interfaces
docker exec wnc-gw ip -d link                               # 拿來和程式輸出對照
docker exec wnc-cli ping -c1 -W2 10.0.2.2                   # 確認轉送沒有被弄壞
./down.sh
```

功能不需要權限時，一律用 `-u nobody` 執行，證明它真的不需要權限。需要權限的功能要說明需要哪個 capability。

## 4. 模擬情境

都在容器裡執行，不會動到主機。用完一定要清掉，再 ping 一次確認轉送正常。

| 要模擬 | 指令 | 預期 |
|---|---|---|
| 管理者關閉介面 | `docker exec wnc-gw ip link set eth1 down`（之後 `up`） | `AdminDown` |
| 沒有 carrier | `ip link add va type veth peer name vb && ip link set va up`，再用 `--lan va` | OPER 是 `LOWERLAYERDOWN`，判定為 `NoCarrier` |
| driver 不回報 link 狀態 | `ip link add d0 type dummy && ip link set d0 up`，再用 `--lan d0` | OPER 是 `UNKNOWN` |
| MAC 歧義 | `ip link add br-test type bridge && ip link set br-test address 02:00:00:00:01:01` | LAN 的 MAC 對到 `eth0`、`br-test` 兩個介面，報錯；改用 `--lan eth0` 就能解決 |
| 設定檔錯誤 | 在容器的 `/tmp` 寫一個錯誤的 toml（欄位打錯、MAC 格式錯、缺欄位），用 `-c /tmp/x.toml` 指定 | 報錯並指出行號和欄位 |
| 讀不到模組目錄 | 拿掉 `/lib/modules` 的掛載（或在其他沒掛載的容器裡跑） | 沒載入的模組變成 `unknown` |
| bridge 模式 | 在 gw 裡建臨時的 veth 和 bridge：`ip link add va type veth peer name vb; ip link add vc type veth peer name vd; ip link add br-test type bridge; ip link set va master br-test; ip link set vc master br-test`，全部 `up`，再用 `-c` 指定 `mode = "bridge"`、`lan = "va"`、`wan = "vc"` 的設定 | 一切正常時 4 項 ok；`ip link set vc nomaster` 報 error；換到另一個 bridge 報 error；`br-test` down 是 warning |
| 介面上已經掛了 XDP 程式 | 臨時容器（`--cap-add SYS_ADMIN --cap-add NET_ADMIN --security-opt apparmor=unconfined`）裡掛 bpffs：`mount -t bpf bpf /tmp/bpffs`，用 Python 呼叫 bpf syscall 載入一個只回傳 `XDP_PASS` 的程式並 pin 起來，再 `ip link set dev va xdpgeneric pinned …`（native 用 `xdpdrv`）。筆電沒有 clang，所以不用 `.o` 檔 | generic 的顯示 `generic (id N)` 並提出 warning；native 的顯示 `native (id N)` |
| `wnc-gw run` 的安裝與移除 | gw 裡先放一張假的系統 table（`table inet fake_os`，forward chain、policy accept），在背景跑 `sh -c '/opt/sg/wnc-gw run > /tmp/run.log 2>&1 & p=$!; echo $p > /tmp/run.pid; wait $p; echo exit=$? >> /tmp/run.log' &`，ping 之後看 counter，再 `kill -INT`（或 `-TERM`）。上次留下舊 table 的情況：先手動建一張內容不同的 `inet wnc_gw` 再跑 | 執行中 `nft list tables` 多一張 `inet wnc_gw`；結束後和開始前的清單相同、`exit=0`；舊 table 被整張換掉。容器的 PID 1 是 `sleep infinity`，不會回收子程序，所以用 `kill -0` 判斷會誤以為還在跑（zombie），結束碼要靠外層的 `sh` 記錄 |
| SSH 斷線（SIGHUP） | gw 裡 `sleep 1000 \| script -qfc "/opt/sg/wnc-gw run" /tmp/x.typescript &`，等 typescript 出現 `traffic is inspected`，再 `kill -KILL $(pgrep -x script)`：終端機消失，kernel 對前景的 process group 送 SIGHUP。另外測 `2> 檔案`（看 log）和 `2>&1 \| cat`（管線） | `nft list tables` 沒有 `inet wnc_gw`；wnc-gw 變成 zombie（PID 1 不回收），結束碼從 `/proc/<pid>/stat` 第 52 欄讀，0 是正常（25856 = 101 << 8 是 panic）；log 有 `stopping signal="SIGHUP"` |
| ids／ips 模式 | `bash tests/ids_inline/protection_docker.sh <ids1\|trust\|kill\|groups\|ips\|startup\|missed\|runmode>`，最後 `clean`。用 `/tmp/wt` 的設定和規則（ICMP 加一條 TCP payload 規則）跑真的 `wnc-gw run`；`kill` 用 `WHEN=drop` 測丟掉模式 | ids：ids chain 是 `log group 10 accept`、Suricata 帶 `--nflog --include`、ICMP 和 payload 都 alert（Docker 的 veth checksum 不完整，靠強制的 checksum-validation=none）；信任時 ids chain 計數停住；多個 group 時是 symhash vmap 和 ids_g<group>；ips 和原本一樣；`ping -f` 下啟動 10 次都不當；`missed`（UDP 時 SIGSTOP Suricata 3 秒）轉送不掉、wnc-gw 記的 `missed` 等於 kernel 的 Drops；`runmode`（ids、ips 各一個和多個 queue／group，`AUTOFP=1` 時 yaml 明寫 autofp）Suricata 只有 W 執行緒 |
| NFLOG group 被佔用 | gw 裡先手動跑一個 `suricata --nflog --include <yaml>`（yaml 的 nflog 清單要有 group 10 和帶 `max-size` 的 default，少了 `max-size` 會 `Invalid max-size value`），再 `doctor`、`run` | doctor：對方的 capture 是 `nflog`，warning 說它可能佔了 group 10；run：每次 `nflog_bind_group() failed` 後記 ERROR「suricata cannot bind the nflog group」並退避重試，對方停掉後就緒 |
| `run` 拒絕啟動 | `docker exec wnc-gw /opt/sg/wnc-gw --lan eth9 run` | 先印 doctor 報告，最後 `error: not starting because the checks above found errors`，結束碼 1，沒有 `inet wnc_gw` |
| doctor 通過、但 nft 失敗 | `run` 會先跑 doctor，所以要先讓 doctor 通過：臨時容器加 `--cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1`，建兩張 dummy 網卡，用 `mode = "routed"` 的設定加 `--lan d1 --wan d2`。再分別把 `/usr/sbin/nft` 換成 `exec sleep 30` 的腳本，或先 `sleep 2` 再執行真的 nft 的腳本（啟動 2.5 秒後送 SIGINT，這時正在安裝）。沒有權限：`docker exec --user 65534 wnc-gw /opt/sg/wnc-gw run` | 卡住：doctor 是 warning，安裝逾時，`error: failed to install table inet wnc_gw: …`，結束碼 1。安裝中收到 Ctrl-C：會等安裝完再移除，結束碼 0、不留 table。沒有權限：建 `/run/wnc-gw/wnc-gw.lock` 時就 `Permission denied`（`not starting`），結束碼 1。刪掉 nft 時 doctor 就會報 error，不會啟動 |
| `run` 帶起 Suricata、Ctrl-C | 在 gw 裡背景跑 `run`，stderr 導到檔案，3 秒後 `kill -INT` | 事件依序是 suricata started → suricata is ready（startup_ms）→ stopping → suricata stopped → table removed；Suricata 自己的輸出帶 `source="suricata"`；`/run/wnc-gw` 有 `notify.sock` 和 `suricata.sock`，`/var/log/wnc-gw/suricata` 有 eve.json 等四個檔案；結束後沒有 `Suricata-Main` |
| Suricata 當掉 | `kill -SEGV $(pgrep -n -x Suricata-Main)`（`-n`：避開之前留下的 zombie） | WARN `exit="SIGSEGV"`，1 秒後重啟並再次 ready |
| 封包真的送進 Suricata | `run` 起來後 cli `ping -c 4 10.0.2.2` | `nft list table inet wnc_gw` 的 `ids` chain 是 `counter … queue flags bypass to 0`、counter 有增加；`/var/log/wnc-gw/suricata/fast.log` 有 sid 1000001 的雙向 alert；停止時 Suricata 印 `Treated: Pkts N` |
| 當掉時放行或丟掉 | cli `ping -i 0.05 -c 120` 的同時 `kill -SEGV`；丟掉模式用 `-c` 指定加了 `[suricata] when_unavailable = "drop"` 的設定 | `accept`：只掉當時還在 queue 裡的 1～2 個，log 有 WARN「passes without inspection」到 INFO「is inspected」`uninspected_ms≈1100`。`drop`：`ids` 沒有 `bypass`，重啟期間的 ping 全掉（約 1.1 秒），doctor 沒有 `when_unavailable` 的 warning |
| 有流量時啟動和重啟 | cli `ping -f -q 10.0.2.2` 持續送，反覆「啟動 → 1.5 秒後 `kill -SEGV` → 2.5 秒後 SIGINT」 | 除了刻意送的 SIGSEGV 沒有其他當機（2026-10-26：20 次啟動 0 次），重啟後的 Suricata 也有處理到封包。這驗證「READY 之後才裝 queue、拆掉之後才重啟」 |
| 換 queue 規則失敗 | `[nftables] path` 指向包裝腳本：讀 stdin，有旗標檔時對含 `"queue"` 的批次（或所有 `-j`）`exit 1`，否則轉給真的 nft | 裝不上：ERROR「failed to send forwarded traffic to suricata」，停 Suricata、移除 table、`exit=1`。拆不掉：ERROR「…not restarting suricata」，**沒有重啟**，`exit=1`，table 留下要手動刪 |
| 同時執行兩個 wnc-gw | 一個 `run` 在背景跑，再執行一次 `run`；另外 `kill -9` 第一個之後再啟動 | 第二個 ERROR `not starting error=another wnc-gw is running (pid N)`，結束碼 1，第一個不受影響。`kill -9` 之後 kernel 會釋放 flock，下一個照常啟動並換掉留下的 table |
| yaml 開了 `delayed-detect`、Suricata 當掉不留 core | 用 `-c` 指定 `include` 系統 yaml 再加 `detect: delayed-detect: yes` 的 yaml；`kill -SEGV` | `/var/log/wnc-gw/suricata/suricata.log` 裡 `signatures processed` 在 `Engine started` 之前（`--set detect.delayed-detect=no` 蓋過 yaml）；`/proc/<pid>/limits` 的 core 是 0，`/proc/<pid>/cwd` 是 log 目錄，找不到新的 core 檔 |
| 停止 Suricata 要很久 | 假的 `/tmp/fake/suricata`：`--build-info`、`--dump-config` 交給真的 suricata；其他情況用 python 送 `READY=1`，收到 SIGTERM 後等 `$FAKE_STOP_S` 秒才結束。設定 `[suricata] path`，用 `docker exec -e FAKE_STOP_S=…` 啟動 `run`，再 SIGINT | 預設 90 秒、要 15 秒：第 10 秒 INFO `suricata is still stopping waited_s=10`，第 15 秒 `exit="exit code 0"`。`stop_timeout = 3`、要 30 秒：第 3 秒 WARN `did not stop in time; killing it`，`exit="SIGKILL"`。真的 Suricata 平常約 2 秒停好，不會有 still stopping。Pi 上 `full` 處理過 S_m39（18 萬條 flow）要 12.8 秒，eve.json 的 flow 紀錄完整（2026-10-27） |
| Suricata 重啟後既有連線不斷 | srv 用 python 開 TCP 5001，cli 用 bash `exec 3<>/dev/tcp/10.0.2.2/5001` 每 0.2 秒送一行含 `WNC-MARK` 的字串（共 100 行）；`[suricata] config` 指向加了 `content:"WNC-MARK"` 規則的 yaml；第 4 秒 `kill -SEGV` | 100 行都收到；重啟後 fast.log 仍有這條規則的 alert；stats 有 `tcp.midstream_pickups 1`、沒有 `drop_reason`。拿掉 `stream.midstream=true` 時連線會斷（`exception_policy.tcp.midstream.drop_flow`） |
| 其他 Suricata | gw 裡另外跑 `suricata -c /etc/suricata/suricata.yaml <模式> -l /tmp/os --set unix-command.enabled=no -D --pidfile /tmp/os/pid`，模式分別是 `--af-packet=lo`、`-q 0`、`-q 3`；`run` 跑著的時候再執行 doctor | `RUNNING SURICATA` 表格列出 pid、抓封包方式、RSS、誰啟動的。af-packet：warning（`kill <pid>`）；`-q 0`：warning，`run` 照常啟動，它的 Suricata 綁不上就退避重試；`-q 3`：warning，`run` 照常啟動；wnc-gw 自己的顯示 `STARTED BY wnc-gw`、不算 finding；之前留下的 zombie 不算；用 nobody 執行結果相同。容器沒有 systemctl，所以 `SURICATA SERVICE` 是 unknown，一直有一條 warning（正確）。Pi：系統服務顯示 `af-packet 71 MB suricata.service`、AT BOOT enabled，一條 warning，修法 `systemctl disable --now suricata.service`；`sudo ip netns exec <ns> suricata -q 0` 用一般帳號跑 doctor 是「could not tell」，用 root 跑是 `NETNS other`、只報資源；`systemd-run --unit=<名稱>` 啟動的顯示 `under <名稱>.service`、修法 `kill <pid>`（2026-10-27） |
| 前一個 wnc-gw 留下的 Suricata | 背景跑 `run`，`kill -STOP` 它的 Suricata 再 `kill -9` wnc-gw（PDEATHSIG 的 SIGTERM 會先擱著）；執行 doctor、再啟動新的 `run`；之後 `kill -CONT` 舊的 | doctor：`STARTED BY previous wnc-gw`，warning 說它佔著 NFQUEUE 0、應該很快會自己結束。新的 `run` 照常裝 table，Suricata 綁不上就退避（1、2、4、8 秒）；舊的結束後新的就緒，log 的 `uninspected_ms` 涵蓋整段（2026-10-27：15397） |
| `suricata -T` | Docker 只有一條規則，`-T` 一下就跑完，改用名稱叫 `suricata` 的腳本帶 `-T` 參數停 30 秒（comm 取自腳本檔名） | CAPTURE `test`，note、不建議 kill |
| yaml 設了 midstream-policy | 「Suricata 重啟後既有連線不斷」那個情境，yaml 用 sed 把 `#midstream-policy: ignore` 改成 `drop-flow`、`pass-flow` 等；另外在檔尾加 `engine:` / `init-failure-fatal: yes`（Debian 的 yaml 沒有這一段） | wnc-gw 強制 `stream.midstream-policy=ignore`，所以每一種都是 100 行收到、重啟後照常 alert、Suricata 沒有「not a valid」的 warning；加了 `init-failure-fatal` 也照常就緒。拿掉這個強制時：`drop-flow` 連線會斷，`pass-flow` 重啟後不再 alert，加上 `init-failure-fatal` 時 Suricata 結束碼 1 起不來（2026-10-27） |
| Suricata 檢查不了的時候 | yaml 的 flow 段改成 `memcap: 512 KiB`、`hash-size: 256`、`prealloc: 10`，cli 對 srv 的 5000 個 port 各送 1 個 UDP，`when_unavailable` 分別設 accept、drop；另外用一條正常、一條壞掉的規則加 `engine: init-failure-fatal: yes` | accept：log 有 `master exception-policy set to: ignore`，5000 個全部送達；drop：`drop-flow`，約 2800 個被丟（`ips.drop_reason.flow_memcap`）。壞規則：直接跑 Suricata exit 1，經過 wnc-gw 照常就緒、WARN `could not load some rules failed=1`（2026-10-28；Pi 用 `tests/ids_inline/exception_policy_pi.sh`） |
| 多個 queue | `[suricata] queue = "0-2"`，cli 對 srv 開 6 條 TCP 連線 | Suricata 參數 `-q 0:2`，`ids` 是 `queue … to symhash mod 3`（offset 0 不印出來），`/proc/net/netfilter/nfnetlink_queue` 有三列。同一對主機的連線也會分到不同 queue（2026-10-28：92／46／137 個封包）；改回位址 hash 會全部擠在同一個 queue |
| 信任（ct mark） | 「Suricata 重啟後既有連線不斷」那個情境，不 `kill`；第 4 秒在 gw 裡 `conntrack -U -p tcp --orig-port-dst 5001 --mark 0x80000000/0x80000000`，第 10 秒 `--mark 0/0x80000000` | forward chain 有 `tcp flags fin,syn,rst jump ids`、`ct mark & 0x80000000 == 0x80000000 counter accept`。設上之後這條規則的 counter 增加，`ids` 的 counter 和 fast.log 的 alert 停住；清掉後 counter 和 alert 都恢復；信任中結束連線時 `ids` 只多 2 個 FIN；100 行都收到（2026-10-28） |
| `wnc-gw trust` | 同上，`run` 跑著；第 4 秒 `trust add tcp 10.0.1.2 <sport> 10.0.2.2 5001`（sport 從 `conntrack -L -p tcp --orig-port-dst 5001` 找），第 7 秒用反方向的五元組再 add，第 10 秒用反方向 `trust del`。失敗路徑：不存在的連線、協定不符、IPv4 和 IPv6 混用、`setpriv --reuid=65534 --regid=65534 --clear-groups` 以非 root 執行。IPv6 用 `conntrack -I -p tcp -s 2001:db8::1 …` 建一筆假的 entry | 效果和上一列相同，`trust list` 列得出、del 後變空；反方向 add 不會出錯；失敗時英文錯誤、結束碼 1，非 root 是「ctnetlink needs CAP_NET_ADMIN」；先用 `conntrack -U` 設 0x1234 時，add／del 後仍保留（2026-10-28） |
| 新連線沿用被信任的舊 entry | `tests/ids_inline/synreuse_docker.sh clear` 和 `noclear`：Suricata 的 tcp established 逾時改成 5 秒；cli 從固定 port 連線、`trust add`，再讓兩端 `SO_LINGER 0` 中斷、FIN/RST 在 conntrack 之前被另一張 table 丟掉；15 秒後從同一個 port 重連 | 兩種都是同一個 entry（id 不變）。`noclear`：mark 被沿用，新連線只有控制封包進 `ids`；`clear`：清 bit 的規則 counter 是 1、mark 變 0，新連線全部進 `ids`；10 行都收到。Suricata 的 flow 還沒逾時就重連的話，Suricata 會丟掉新的 SYN（`ips.drop_reason.stream_error`），連不上（2026-10-28） |
| 上一次留下的信任 | `run` 跑著、一條每 0.2 秒送一行的連線 `trust add`；另外 `conntrack -I -p icmp … --mark 0x80000000` 建一筆 ICMP；`pkill -9 -x wnc-gw` 後再 `run` | `kill -9` 後 table 留著、連線仍被信任；第二次 `run` 的 log 在 `table installed` 前有 `cleared trust left by an earlier run cleared=1`，ICMP 那筆是 ERROR（`Invalid argument`，五元組編碼沒有 ICMP 欄位）；連線的封包回到 `ids`，150 行都收到（2026-10-28） |
| queue 被佔用、退避 | 先在 gw 裡自己跑一個 `suricata -q 0 -l /tmp/other --set unix-command.enabled=no`，再跑 `run` | 每次都 ERROR「suricata cannot bind the queue」，重啟間隔 1、2、4、8、16 秒（看時間戳記）；退避等待中送 SIGINT 會馬上結束 |
| 等不到就緒 | 假的 `/tmp/fake/suricata`：遇到 `--build-info`、`--dump-config` 就交給真的 suricata（doctor 才會過），其他情況 `exec sleep 30`；設定 `[suricata] path` 和 `ready_timeout = 2` | 每 2 秒 WARN「did not become ready in time」，接著 `exit="SIGTERM"` 並重啟 |
| wnc-gw 被強制結束 | `kill -9` wnc-gw | Suricata 收到 PDEATHSIG 而結束。容器的 PID 1 是 `sleep infinity`，不會回收，所以狀態顯示 `Z`；table 會留下來，要手動 `nft delete table inet wnc_gw` |
| 改 sysctl（例如 `bridge-nf-call-iptables=0`） | testbed 容器改不了（見 §5），改用臨時容器：`docker run --rm --network none --cap-add NET_ADMIN --security-opt apparmor=unconfined --security-opt systempaths=unconfined …` | 對應的 error |
| 沒有規則、規則只有註解 | 用 `wnc-lab-gw:latest` 開臨時容器（沒有掛載規則目錄），跑 `--lan lo --wan lo doctor`；再寫一個只有 `#` 開頭的 `suricata.rules` | `missing` 或 `no rules`，error「suricata has no rules to load」 |
| 規則用萬用字元、規則檔不存在 | 把 suricata.yaml 複製到 `/tmp`，用 `sed` 把 `rule-files` 改成 `"*.rules"` 加一個不存在的絕對路徑，再用 `-c` 指定 `[suricata] config` | `not checked` 和 `missing`，兩個 warning，沒有 error |
| Suricata 設定檔不存在 | `[suricata] config = "/nonexistent.yaml"` | error，訊息附上 Suricata 自己的錯誤（`conf-yaml-loader: failed to open file`） |
| 路徑不是絕對路徑 | `[suricata] path = "suricata"` | 讀設定檔就報錯，指出行號，結束碼 1 |
| 另一份 Suricata、可被非 root 修改 | 臨時容器裡 `cp /usr/bin/suricata /opt/s8/bin/`，`chown -R nobody /opt/s8/bin`，`chmod 777 /opt/s8`，設定 `[suricata] path` | SOURCE 是 `config file`；warning 依帳號列出 nobody 擁有的檔案和目錄、可以寫 `/opt/s8` 的群組和所有人 |
| 規則檔讀不到 | `chmod 600` 規則檔，用 `nobody` 跑 doctor | `unreadable`，warning（不是 error：以其他帳號執行的 Suricata 可能讀得到） |
| 用設定的 nft 路徑安裝 table | gw 裡 `ln -s /usr/sbin/nft /opt/nftalt/nft`，複製 setting.toml 加上 `[nftables] path`，用 `-c` 跑 `run`；再改成不存在的路徑 | 照常裝上、移除 table；不存在時 doctor 報 error，`run` 拒絕啟動 |
| 找不到 Suricata | testbed 的 gw 裡暫時改名：`mv /usr/bin/suricata /usr/bin/suricata.off`（用完改回來）；或用沒有 Suricata 的 `wnc-lab:latest` 開臨時容器 | doctor 報 error，`run` 拒絕啟動 |
| Suricata 7.0 | 用 `wnc-lab:latest` 開臨時容器，裝 trixie 的 `suricata`（7.0.10），掛上 `/opt/sg`，跑 `--lan lo --wan lo doctor` | READY NOTIFY 是 `unknown`，給 warning |
| Suricata 的能力是 no、逾時、執行失敗 | 用 `wnc-lab-gw:latest` 開臨時容器，把 `/usr/bin/suricata` 換成假腳本：用 `sed` 把真的 `--build-info` 輸出改成 `no` 或刪掉那一行、`exec sleep 30`、`exit 1`、拿掉執行權限 | no 是 error；沒有那一行是 warning；逾時（5 秒，子程序會被砍掉）和執行失敗都是 warning |

## 5. Docker 會掩蓋的問題

| 問題 | 原因 | 怎麼處理 |
|---|---|---|
| 把自己鎖在外面 | `docker exec` 不經過網路，規則把流量全擋掉也進得去。Pi 上是 SSH 經過資料 port（eth1）連進去，會直接斷線 | 會改流量的步驟要另外設計「從網路連 gw」的驗證，例如加一個 admin 容器 |
| 動到別人的設定 | 容器的 netns 一開始是空的，`flush ruleset` 只會清掉容器自己的規則 | 只動自己的 nft table。驗證時先放一張假的「系統 table」，確認跑完之後它還在 |
| XDP 看起來可以用 | veth 支援 native XDP（回報 basic、redirect、rx-sg），Pi 的網卡不支援 | 只把 Docker 的結果當成「邏輯對」。`xdp = "auto"` 在 Docker 會選 native XDP，在 Pi 會選 TC；要模擬 Pi 就用 `xdp = "off"` |
| kernel 不一樣 | 容器用的是筆電的 kernel（Ubuntu 7.0），不是 Pi 的 6.18.50+rpt-rpi-v8 | 模組、kernel 設定要在 Pi 上用 doctor 確認。例如筆電有 `nf_conntrack_bridge`，Pi 沒有 |
| 連線一直有被追蹤 | kernel 只在有規則用到 conntrack 的 netns 追蹤連線。testbed 的 gw 容器有 Docker 內建 DNS 的 `table ip nat`，所以沒有 `run` 時也有 conntrack entry；Pi 上沒有 `run` 就沒有 entry | 依賴「連線有被追蹤」的步驟（例如 `trust add`）在 Pi 上要先 `run` |
| 容器裡改不了 sysctl | Docker 把 `/proc/sys` 掛成唯讀，預設的 AppArmor profile 也禁止寫入 | 需要改 sysctl 的情境用臨時容器加 `--security-opt apparmor=unconfined --security-opt systempaths=unconfined`；netns 還要加 `--cap-add SYS_ADMIN` |
| 主機的模組會影響 testbed | 模組是整台筆電共用的。筆電載入 `br_netfilter` 時，主機 bridge 上的封包也會經過 Docker 的防火牆規則，`internal` 網路的隔離規則會丟掉跨網段的封包，cli→srv 就不通了（2026-10-24 確認） | 不要在筆電上載入 `br_netfilter`；需要它的測試放到 Pi 上做。卸載模組一律用 `rmmod <模組>`，**不要用 `modprobe -r`**：它會連帶卸載 `bridge`，刪掉筆電上所有的 bridge（包括其他專案的 Docker 網路），只能重啟 dockerd 恢復 |
| suricata.service 會不會開機啟動 | 容器裡沒有 systemd，`/usr/bin/systemctl` 不存在 | testbed 的 doctor 會一直有「could not check whether suricata.service starts at boot」的 warning，這是正確的；開機啟動的判斷要在 Pi 上確認 |
| 設定檔看起來可以被非 root 修改 | `/etc/wnc-gw` 是從筆電掛載進去的，擁有者是筆電上的 uid 1000，目錄和檔案也是 group 可寫 | testbed 的 doctor 會一直有這條 warning，這是正確的（筆電上的帳號確實能改它）。Pi 上照正式部署的方式放在 root 擁有的 `/etc/wnc-gw` 就不會出現 |
| 腳本傳不進容器 | `docker exec` 沒有 `-i` 時不會把 stdin 傳進去，`docker exec wnc-gw sh -c 'cat > /tmp/x.sh' < x.sh` 會得到空檔案 | 用 `docker exec -i` |
| 輸出順序亂掉 | `docker exec` 把 stdout 和 stderr 分開傳回 | doctor 的報告全部印在 stdout |
| core dump | 筆電的 `core_pattern` 交給 apport，容器裡看不到 core 檔。Pi 的是 `core`，Suricata 的預設設定又會把 core 上限放寬成 unlimited：2026-10-26 在 Pi 上每次 SIGSEGV 都在工作目錄寫 154 MB，Suricata 寫檔期間卡在 D 狀態幾十秒（SIGKILL 也要等） | wnc-gw 已用 `--set coredump.max-dump=0` 關掉；在 Pi 上測當機時還是要確認沒有 core 檔 |
| 實體網卡的行為 | veth 沒有 driver、沒有出廠 MAC、不會被拔插 | driver、出廠 MAC 在筆電主機上用唯讀的方式驗證；USB 網卡拔插要到 Pi 上測 |

## 6. 搬到 Pi

- **前提**：同一個功能已經通過 Docker 驗證。
- **編譯**：Pi 要用 aarch64 版本（筆電已經裝好 target）：`CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld cargo build --target aarch64-unknown-linux-musl`。不指定 linker 的話，會用筆電的 x86 `cc`，連結會失敗。
- **連線**：`ssh wnc@10.254.254.2`，走的是 Pi 的 `eth1`（ASIX USB 網卡），**它同時是之後的資料 port**。任何會改網路設定的步驟都要先想好怎麼避免把自己鎖在外面（獨立的管理通道、自動回復、永不封鎖清單）。
- **Pi 的網卡**：

  | 介面 | 是什麼 | MAC |
  |---|---|---|
  | `eth0` | 板載 bcmgenet | `e4:5f:01:2d:03:bf` |
  | `eth1` | ASIX USB，driver 是 `cdc_ncm` | `9c:69:d3:24:1b:d9` |

  名稱在 Pi 3B+ 和 Pi 4 上是相反的，所以一律用 MAC 或確認過的名稱指定。2026-10-16 筆電和 Pi 的兩張 USB 網卡對調過，eth1 原本的 `9c:69:d3:2a:11:54` 現在在筆電上；MAC 以 Pi 上 `ip -br link` 讀到的為準。
- **到 Pi 上要確認的事**：
  - USB 網卡重插後 ifindex 會變。
  - 已確認（2026-10-24，doctor 在 Pi 上跑過）：兩張網卡都用出廠 MAC 對應成功；eth1 的 driver 是 `cdc_ncm`；階段 1 和 bridge 模式需要的模組都是 loadable，`nf_conntrack_bridge` 沒有。
  - Pi 上的 Suricata 2026-10-30 從 7.0.10 升級到 8.0.7（trixie-backports，和 Docker 的 gw 相同）。Pi 沒有網路：在筆電的 `debian:trixie-slim` 容器裡用 Pi 的 `/var/lib/dpkg/status` 加 `-o APT::Architecture=arm64` 模擬安裝、`--download-only` 下載，再傳到 Pi 用 `apt-get install ./…deb`。回退用 `apt-get install --allow-downgrades` 裝 7.0.10 和 `libhtp2`。套件的安裝腳本會啟動 suricata.service，裝完要再停掉。之前 Pi 上的量測數字都是 7.0.10 量的。
  - 信任與 symhash（2026-10-28，`wgw` 再接兩個 netns 到 `br0`，放一條被信任的 TCP 連線）：分片 0/24 被拆到不同 queue；重播 39-1 的掃描把連線表塞滿（65,536）時靠 early drop，沒有因表滿丟封包，被信任的連線 mark 不掉、連線不斷。數字見架構 skill 的 `decisions.md` O14、O17。
  - `wnc-gw trust`（2026-10-28，獨立 netns，量測模式）：`tests/ctnetlink/bench/` 0 個檢查失敗；用 Pi 的 `conntrack -I` 建 IPv4、IPv6 各一筆，add、list、del 都正常，反方向的五元組也可以；非 root 被拒絕；doctor 的 `nf_conntrack_netlink` 是 loaded。
  - 3c 收尾測試（2026-10-28）：`nf_conntrack_netlink` `rmmod` 後會被 `wnc-gw trust list` 自動載入回來；`FAMILY=6 frag_pi.sh` 0/24；`PROTO=udp ctfull_pi.sh 10000 30` 單向 UDP 的信任在表滿約 4 秒後被 early drop 清掉、回到 Suricata；`synreuse_pi.sh early|clear|noclear` 和 Docker 結果相同。IPv6 的 Docker 驗證要用臨時容器（testbed 的 gw 不能開 IPv6 轉送），在容器裡建 c、s 兩個 netns 走 routed，s 要把 UDP 5000 丟掉，否則回來的 ICMP 會混進 queue 的計數。
  - 從外面送流量（方案 B，2026-10-29）：筆電 USB 網卡（`enx9c69d3241bd9`，沒設 IP）直接接 Pi eth0；管理線 eno2 ↔ Pi eth1 再加 VLAN 20（筆電 `eno2.20`、Pi `eth1.20`）當第二個資料 port，eth1 本身照常是 SSH。`planb_pi.sh up` 把 eth0、eth1.20 移進 `wgw` 接成 `br0`，`down` 刪掉 netns 後 eth0 自己回到主 namespace、NetworkManager 會重新接上。筆電端是容器 `wnc-gen`（image `wnc-lab-gen`，host 網路、`NET_ADMIN`、`NET_RAW`），`planb_run.sh setup|teardown`。tcpreplay 最多送到約 60 kpps（1-1、17-1），60-1 約 84 kpps。
  - **方案 B 的 PAUSE（2026-10-30）**：Pi eth0 的 Ethernet PAUSE 預設開著，CPU 0（所有網卡中斷都在這裡）收不完時 Pi 讓筆電暫停，結果是「Pi 不丟、筆電送不快」，看起來像筆電的上限。筆電實際可以送 ≥ 200 kpps（不限速 856 kpps）。量容量時要關 PAUSE（`ip netns exec wgw ethtool -A eth0 rx off tx off`，改完 eth0 會重新協商幾秒；量完 `rx on tx on`），或看 `planb_pi.sh counters` 的 `pause_tx0`。`planb_pi.sh start` 用 `PROTECTION=ips|ids` 選 wnc-gw 的模式（預設 ips；第 1 步之後沒寫 protection 會變成 ids）。
  - ids／ips（2026-10-30）：`sudo bash tests/ids_inline/protection_pi.sh net up` 在 env.sh 的 wgw 上接 fcli（10.9.0.1）、fsrv（10.9.0.2），再跑 `doctor|ids1|trust|kill|groups|ips|startup|missed|bind|runmode`，最後 `clean`、`net down`。結果和 Docker 相同（見架構 skill decisions.md O18「Pi 驗證」）；7.0.10 接受 `--include`；Debian 預設 yaml 下 NFLOG 和 NFQ 都是 autofp。腳本在背景啟動的程式（python server、run）都要把輸出導走，否則 `ssh` 會等它們結束；`wait` 要指定 pid，不然會等到背景的 `run`。`pkill -f <字串>` 會連 ssh 帶進來的 `bash -c` 一起殺掉（命令列含同樣的字串）。
  - 8.0.7 重跑功能測試（2026-10-30）：`exception_policy_pi.sh accept|drop|badrule`、`synreuse_pi.sh early|clear|noclear`、`FAMILY=4|6 frag_pi.sh`、`[PROTO=udp] ctfull_pi.sh 10000 30`、`ctmark_pi.sh nol2|l2` 結果和 7.0.10 相同；`nflog_startup_pi.sh` 是 2/20 segfault。第 1 步之後 `protection` 預設是 ids，設定檔沒寫的話 wnc-gw 走 NFLOG：`make_configs.sh` 已改成寫 `protection = "ips"`；`synreuse_docker.sh`（複製 Docker 的 setting.toml）和 `planb_pi.sh` 自己產生設定，還沒寫。`/tmp/wncgw/m` 在 Pi 重開機後會消失，要重跑 `make_configs.sh`，再用 `trial.sh empty <pcap> cache <目錄>` 建 tcpreplay 的 cache。
  - Pi 的 journald 是 `Storage=volatile`（Raspberry Pi OS 的 `40-rpi-volatile-storage.conf`），log 只在記憶體，重開機就消失；Pi 的時鐘也不準（2026-10-26 時慢了 6 天）。要事後查 log 的實驗，先把 stderr 導到檔案。
  - Pi 的 `/var/lib/suricata/rules/` 是空的，系統的 Suricata 目前載入 0 條規則；doctor 會報「suricata has no rules to load」（2026-10-26 確認）。
- **在 Pi 上跑 `run` 而不碰 eth0、eth1**：建三個 netns，`wcli`、`wsrv` 各一端 veth，`wgw` 放另外兩端和 `br0`（`mode = "bridge"`、`lan = "g-lan"`、`wan = "g-wan"`、`xdp = "off"`），用 `sudo ip netns exec wgw wnc-gw -c … run`。`br_netfilter` 要在主機 `modprobe`（模組是全機共用），兩個 sysctl 在每個 netns 都預設是 1。Suricata 用 `include: /etc/suricata/suricata.yaml` 的測試 yaml 改 `default-rule-path`、`rule-files`。2026-10-26 確認：doctor 全部 ok，ICMP 雙向 alert，`ping -f` 下啟動和重啟 20 次沒有當機。注意系統的 Suricata 也叫 `Suricata-Main`，要從 log 的 `suricata started pid=` 取 pid
- **Pi 的固定設定**（時脈、校時、Suricata 服務）、關機順序：見專案記憶 `pi-experiment-delegation`，以及 `scripts/README.md`。系統的 Suricata 服務目前是 enabled（開機就以 af-packet 模式跑），做量測前要先停掉，量完再啟動。
