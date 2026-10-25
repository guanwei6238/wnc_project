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
- image 是 Debian trixie，和 Pi OS 同一代，內含 iproute2、nftables、conntrack、tcpdump、iperf3、ethtool。**還沒有安裝 Suricata**，等整合方式決定後再加。

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
| `run` 拒絕啟動 | `docker exec wnc-gw /opt/sg/wnc-gw --lan eth9 run` | 先印 doctor 報告，最後 `error: not starting because the checks above found errors`，結束碼 1，沒有 `inet wnc_gw` |
| doctor 通過、但 nft 失敗 | `run` 會先跑 doctor，所以要先讓 doctor 通過：臨時容器加 `--cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1`，建兩張 dummy 網卡，用 `mode = "routed"` 的設定加 `--lan d1 --wan d2`。再分別把 `/usr/sbin/nft` 換成 `exec sleep 30` 的腳本，或先 `sleep 2` 再執行真的 nft 的腳本（啟動 2.5 秒後送 SIGINT，這時正在安裝）。沒有權限：`docker exec --user 65534 wnc-gw /opt/sg/wnc-gw run` | 卡住：doctor 是 warning，安裝逾時，`error: failed to install table inet wnc_gw: …`，結束碼 1。安裝中收到 Ctrl-C：會等安裝完再移除，結束碼 0、不留 table。沒有權限：`Operation not permitted`，結束碼 1。刪掉 nft 時 doctor 就會報 error，不會啟動 |
| 改 sysctl（例如 `bridge-nf-call-iptables=0`） | testbed 容器改不了（見 §5），改用臨時容器：`docker run --rm --network none --cap-add NET_ADMIN --security-opt apparmor=unconfined --security-opt systempaths=unconfined …` | 對應的 error |

## 5. Docker 會掩蓋的問題

| 問題 | 原因 | 怎麼處理 |
|---|---|---|
| 把自己鎖在外面 | `docker exec` 不經過網路，規則把流量全擋掉也進得去。Pi 上是 SSH 經過資料 port（eth1）連進去，會直接斷線 | 會改流量的步驟要另外設計「從網路連 gw」的驗證，例如加一個 admin 容器 |
| 動到別人的設定 | 容器的 netns 一開始是空的，`flush ruleset` 只會清掉容器自己的規則 | 只動自己的 nft table。驗證時先放一張假的「系統 table」，確認跑完之後它還在 |
| XDP 看起來可以用 | veth 支援 native XDP（回報 basic、redirect、rx-sg），Pi 的網卡不支援 | 只把 Docker 的結果當成「邏輯對」。`xdp = "auto"` 在 Docker 會選 native XDP，在 Pi 會選 TC；要模擬 Pi 就用 `xdp = "off"` |
| kernel 不一樣 | 容器用的是筆電的 kernel（Ubuntu 7.0），不是 Pi 的 6.18.50+rpt-rpi-v8 | 模組、kernel 設定要在 Pi 上用 doctor 確認。例如筆電有 `nf_conntrack_bridge`，Pi 沒有 |
| 容器裡改不了 sysctl | Docker 把 `/proc/sys` 掛成唯讀，預設的 AppArmor profile 也禁止寫入 | 需要改 sysctl 的情境用臨時容器加 `--security-opt apparmor=unconfined --security-opt systempaths=unconfined`；netns 還要加 `--cap-add SYS_ADMIN` |
| 主機的模組會影響 testbed | 模組是整台筆電共用的。筆電載入 `br_netfilter` 時，主機 bridge 上的封包也會經過 Docker 的防火牆規則，`internal` 網路的隔離規則會丟掉跨網段的封包，cli→srv 就不通了（2026-10-24 確認） | 不要在筆電上載入 `br_netfilter`；需要它的測試放到 Pi 上做。卸載模組一律用 `rmmod <模組>`，**不要用 `modprobe -r`**：它會連帶卸載 `bridge`，刪掉筆電上所有的 bridge（包括其他專案的 Docker 網路），只能重啟 dockerd 恢復 |
| 輸出順序亂掉 | `docker exec` 把 stdout 和 stderr 分開傳回 | doctor 的報告全部印在 stdout |
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
- **Pi 的固定設定**（時脈、校時、Suricata 服務）、關機順序：見專案記憶 `pi-experiment-delegation`，以及 `scripts/README.md`。系統的 Suricata 服務目前是 enabled（開機就以 af-packet 模式跑），做量測前要先停掉，量完再啟動。
