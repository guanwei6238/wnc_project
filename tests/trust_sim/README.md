# tests/trust_sim — 各 dataset 有多少封包會走 fast path

問題：自動信任（`[trust] auto`）讓已信任連線的封包不送 Suricata。把這件事從 ct mark 搬到 TC（DECISIONS.md §5、§17）之後，每個信任封包省 5–6 µs（`tests/ebpf/README.md` E1）。整體能省多少，要看真實流量裡有多少封包會被信任，這個比例只跟流量和信任規則有關，不需要 Pi。

做法：用 pcap 的原始時間戳，照 wnc-gw 的程式重演信任（離線模擬），一次讀檔同時算 ct mark 版和 TC 版。Pi 上的每封包成本另外量（計畫中的 B），兩者相乘就是各 dataset 預估省下的 CPU。

## 模擬了什麼

| wnc-gw 的行為 | 程式位置 | 模擬 |
|---|---|---|
| 每 5 秒讀一次 conntrack；第一次看到連線時記下時間和封包數，之後過 ≥ 5 秒、兩個方向各多 ≥ 10 個封包、TCP 是 ESTABLISHED 才信任；TTL 900 秒到期回到觀察 | `src/agent/trust.rs` | `src/agent.rs` 的 `Agent` 逐段照搬（含 `tracked` 的 id 變了但信任中就不重設、alert 記 600 秒、最多 10,000 筆） |
| alert 早於信任：不信任；信任後的 alert：撤銷，之後不再信任 | 同上 | eve.json 的 alert 用 `pcap_cnt` 對到封包。那個封包如果會送 Suricata 才算收到；如果它走 fast path，Suricata 看不到，記成 `alerts_missed` |
| SYN／FIN／RST、分片、多播／廣播、非 TCP／UDP、IPv6 extension header 交回 kernel；純 SYN 刪掉兩個方向的信任 | `gw-ebpf/src/main.rs`（舊版 nft 規則相同） | `src/pcap.rs`、`src/sim.rs` |
| TC 版：信任的封包不經過 conntrack；閒置 UDP 120、TCP 600 秒清掉信任（每 10 秒看封包數有沒有變） | `src/agent/idle.rs` | `src/agent.rs` 的 `IdleSweep` |
| ct mark 版：每個封包都經過 conntrack，信任是 entry 上的 mark，entry 逾時就消失；純 SYN 清 mark | `16137e0` 的 `firewall.rs` | `src/sim.rs` |
| conntrack 的逾時（kernel 預設）：UDP 只有單向 30 秒、有回覆且超過建立後 2 秒 120 秒；TCP 開始 120、ESTABLISHED 5 天、FIN 後 120、RST 後 10 秒；FIN／RST 之後的純 SYN 建新的 entry；中途接上的 TCP 直接當 ESTABLISHED | kernel `nf_conntrack_proto_{tcp,udp}.c` | `src/conntrack.rs` |

## 近似（解讀數字時要記得）

- 假設 pcap 裡每個封包都經過 gateway。實際上 pcap 是在某台主機或交換器上錄的，同一個網段裡的流量不一定經過 gateway。
- 不模擬 EVE 的讀取延遲：alert 一出來就生效。ids 模式下 alert 會晚到，要在 Pi 上看。
- TCP 只看「兩個方向都有封包、還沒 FIN／RST」，不檢查序號；kernel 判成 INVALID、不計數的封包，這裡仍然計數。
- 不模擬 conntrack 表滿（Pi 上 65,536 條）和 trust map 滿（32,768 條），只記峰值（`peak_conntrack`、`peak_trusted`）。
- VLAN tag 先拿掉再判斷（`vlan_packets` 是數量）；`gw-ebpf` 只看 offset 12 的 EtherType，真的收到帶 tag 的封包時不會走 fast path。
- ct mark 版的分片：kernel 會先把分片組回，組回的封包仍然可能被 mark 放行；這裡兩版都算成交回 kernel。
- alert 用 offline 跑 `full` rule set 的結果（`../detection/`）。沒有 `pcap_cnt` 的 alert（flow 逾時才送出的）記在 `alerts_unplaced`，不參與判斷。

照程式重演看到的一個行為：信任被閒置清除或純 SYN 刪掉之後，`trust.rs` 裡那條連線還是 `Trusted`，要等 TTL 到期才回到觀察。這段時間流量恢復也不會再被信任（全部送檢查），TC 版的 `idle_ended` 就是被清掉的次數。

## 用法

```
cargo build --release
target/release/trust_sim --header --name 3-1 --eve <eve.json> <pcap>   # pcap 也可以用 - 從 stdin 讀
systemd-run --user --unit trust-sim -p MemoryMax=8G -p MemorySwapMax=0 -E IOT23_SKIP=43-1 \
    bash -c 'bash run_all.sh [iot23 cicids2017 cicddos2019 ciciot2023] > log 2>&1'
python3 -I summarize.py ~/datasets/trust_sim results
```

- `run_all.sh`：每個檔案的結果寫到 `~/datasets/trust_sim/<dataset>/<name>.tsv`，已經有的跳過。本機的檔案、IoT-23 的 tar、CICIoT2023 三組同時跑（`LOCAL_JOBS`、`NAS_JOBS` 是每組的平行數）。`MemorySwapMax=0`：記憶體不夠時直接失敗（`failed:` 記在 log），不會換到 swap 卡住。`IOT23_SKIP` 跳過的 scenario 之後另外給記憶體跑：43-1 是掃描，2,484 秒裡 6,732 萬條 flow，同時活著的連線約 300 萬條，4 GB 不夠。IoT-23 本機沒有的 scenario，從 NAS 的 tar.gz 用 `tar --to-command` 一次讀完；CIC-DDoS2019 01-12 用 `../detection/zip_pcap_concat.py` 從 zip 串流，和偵測評估的順序相同，`pcap_cnt` 才對得上。
- 每列欄位：`fast_packet_pct`／`fast_byte_pct` 是走 fast path 的封包數、bytes 比例；`trusted`、`expired`、`revoked`、`refused`、`idle_ended` 是次數；`other_packets` 是一律交回 kernel 的封包；`alerts_mismatched` 是 alert 的五元組和那個封包不同的數量，`alerts_beyond_end` 是 `pcap_cnt` 超過檔尾的，`alerts_out_of_order` 是 `pcap_cnt` 倒退的，三個都應該是 0（不是 0 代表 pcap 和 eve 對錯）。

## 驗證

- 單元測試 37 個（`src/<模組>/tests.rs`）：每條規則一個封包時間軸。
- IoT-23 3-1：50,525 筆有 `pcap_cnt` 的 alert 全部對到同一組五元組的封包；`summarize.py` 也拿 IoT-23 的封包數和對齊結果（`../iot23/results/*.json` 的 `pcap_packets`）比對。
- tar 串流和直接讀檔的結果相同（3-1）。
- 跳過安靜期間的檢查（見「速度」）：單元測試用一條有 3 天、5 天等空檔、時間倒退、alert 的隨機時間軸，比對跳過和不跳過的全部統計相同（把安靜門檻改成 10 秒時這個測試會失敗）；3-1、49-1、CIC-IDS2017 monday、CIC-DDoS2019 03-11、CICIoT2023 DDoS-PSHACK_Flood6／11 用改前和改後跑，輸出逐位元組相同。

## 速度

筆電（8 核心）單一 process：
- 49-1 前 300 MB（389 萬個封包，pcap 時間 6,313 秒、conntrack 峰值 2.5 萬條）：Rust 預設的 SipHash 21.7 秒；換成 FxHash、每次檢查不重建 HashSet 後 5.4 秒（0.71 M 封包／秒），結果相同。慢的部分是每 5 秒掃一次全部連線，和 wnc-gw 本身一樣。
- eve.json 原本整份載入，39-1 的 10.9 GB 放不進 4 GB；改成和 pcap 一起依 `pcap_cnt` 串流讀（Suricata single runmode 的輸出照封包順序），記憶體 5 MB，結果相同。
- NAS 經 Wi-Fi：CICIoT2023 BenignTraffic1（2 GB）35 秒，約 57 MB/s。
- CICIoT2023 的 PSH-ACK flood：偽造來源、從中途接上的 TCP 都當成 ESTABLISHED（逾時 5 天），一個檔同時有 120–180 萬條連線（記憶體約 1.4 GB）；有些檔的時間戳中間空了好幾天（DDoS-PSHACK_Flood7 跨 253,536 秒），每 5 秒掃一次全部連線，一個檔跑超過一小時。改成：距離最後一個封包超過 1,800 秒（TTL 900、閒置 600、alert 記 600 秒中最大值的兩倍；這段時間後信任、閒置、alert 都不會再變）時，直接跳到最早的 conntrack 逾時或下一個封包之後的第一個檢查時間。DDoS-PSHACK_Flood6 從 19 分鐘以上變 272 秒。

## 結果（2026-11-15，四個 dataset 全部 344 個檔）

`results/files.tsv` 是每個檔、`results/summary.tsv` 是每組的加總（`python3 -I summarize.py ~/datasets/trust_sim results`）。四個 dataset 的封包數都和偵測評估（`../detection/README.md`）讀到的相同；alert 對應檢查的 `alerts_mismatched`、`alerts_beyond_end`、`alerts_out_of_order` 全部是 0。

| dataset | 檔 | 封包 | fast path 封包（ct mark／TC） | fast path bytes（ct mark／TC） | 一律交回 kernel 的封包 | 信任次數（TC） | 被閒置清除（TC） | 落在 fast path 的 alert |
|---|---|---|---|---|---|---|---|---|
| IoT-23 | 28 | 770,313,789 | 0.140%／0.139% | 1.025%／1.024% | 0.059% | 3,145 | 1,950 | 3／14,770,158 |
| CIC-IDS2017 | 5 | 56,370,702 | 43.121%／43.115% | 60.855%／60.854% | 1.046% | 105,777 | 100,703 | 5／41,861 |
| CIC-DDoS2019 | 2 | 312,191,170 | 0.070%／0.070% | 0.026%／0.026% | 20.170% | 5,642 | 5,351 | 12／39,962 |
| CICIoT2023 | 309 | 4,482,456,728 | 0.392%／0.391% | 2.048%／2.048% | 22.077% | 123,502 | 76,844 | 43／596,012 |

CICIoT2023 依類別：

| 類別 | 檔 | 封包 | fast path 封包（ct mark／TC） | fast path bytes（ct mark／TC） | 一律交回 kernel 的封包 |
|---|---|---|---|---|---|
| Benign | 4 | 11,102,705 | 55.591%／55.497% | 64.558%／64.549% | 8.838% |
| Spoofing | 3 | 4,904,322 | 53.694%／53.565% | 65.978%／65.947% | 7.108% |
| BruteForce | 1 | 133,138 | 25.666%／25.187% | 15.444%／15.265% | 15.217% |
| Recon | 5 | 7,020,685 | 22.969%／22.735% | 30.049%／29.973% | 13.874% |
| Web | 6 | 255,560 | 18.774%／18.774% | 10.842%／10.842% | 19.972% |
| DoS | 38 | 808,847,158 | 0.346%／0.346% | 2.387%／2.391% | 0.686% |
| Mirai | 76 | 262,877,918 | 0.294%／0.294% | 0.277%／0.277% | 65.371% |
| DDoS | 176 | 3,387,315,242 | 0.104%／0.104% | 0.476%／0.476% | 23.908% |

讀法：

- **比例由流量決定**：正常流量多的檔，一半左右的封包走 fast path（CIC-IDS2017 43%、CICIoT2023 Benign 56%；Spoofing 檔大部分也是背景的正常流量）。攻擊為主的檔很低：flood、掃描大多是單向、很短，或根本不是 TCP／UDP（CIC-DDoS2019、CICIoT2023 DDoS 約兩成、Mirai 的 GRE flood 65% 一律交回 kernel），夠不到兩個方向各 10 個封包。IoT-23 另外有 487,051 條連線在信任前就有 alert，被拒絕信任。
- **ct mark 和 TC 的 fast path 比例幾乎一樣**：差最多的是 CICIoT2023 BruteForce 的 0.48 個百分點，其他都不到 0.25。TC 大多稍低，是因為被閒置清除的連線之後要等 TTL（900 秒）到期才會再被信任，這段時間的封包全部送檢查（見上面「照程式重演看到的一個行為」）。TC 被閒置清除的次數不少（CIC-IDS2017 105,777 次信任裡有 100,703 次），但被清掉的連線都已經 120 秒（UDP）或 600 秒（TCP）沒有封包，之後還有流量的很少。所以把 fast path 搬到 TC，省下的 CPU ≈ 信任封包數 × 每個封包的成本差（E1：5–6 µs），比例本身不變。
- **信任後才出現的 alert，Suricata 看不到**：兩版漏掉的 alert 完全相同，所以這是信任規則（5 秒、各 10 個封包）的問題，跟轉送方式無關。值得注意的：CIC-IDS2017 Thursday 的 `ET MALWARE Win32/Suspected Reverse Shell Connection`（2034945）、`GPL EXPLOIT Microsoft cmd.exe banner`（2102123）、`ET MALWARE Windows dir Microsoft Windows DOS prompt command exit OUTBOUND`（2023205）；Friday 的 HTTP 下載 EXE（2014519、2018959）；CICIoT2023 BrowserHijacking 的 BeEF 4 個 SID（2018090、2038614–2038616）。其他是 P2P（Edonkey 2003311、BitTorrent DHT）、DNS 查詢、Jabber、爬蟲 User-Agent。這和 ids 模式下「payload alert 比 min_age 晚」（`security_gateway/DECISIONS.md` §19）是同一類問題，差在這裡的連線信任前完全沒有 alert，撤銷也不會發生。
- **conntrack 表會滿**：峰值超過 Pi 上限 65,536 條的有 IoT-23 5 個檔（43-1 的 241.6 萬條最多）、CIC-DDoS2019 2 個、CICIoT2023 107 個（最多 183.6 萬條）；CIC-IDS2017 最多 9,759 條。Pi 上表滿時新連線會被丟掉，這裡沒有模擬，數字是「表夠大」的情況。
- Pi 上量到的每個信任封包的差（B，`../cpu_alloc/README.md` 實驗 13，2026-11-16）：bridge 時 TC 比 ct mark 少 2.6–7.5 µs（−9%～−38%，50 kpps），routed 時少 0.6–4.2 µs（routed 的 I23_Benign_Final 反而貴 2.3 µs，原因沒找到）。乘上這裡的比例：CIC-IDS2017 平均每個封包約 −1.9 µs、CICIoT2023 Benign 約 −2.2 µs，攻擊為主的 dataset 不到 0.03 µs。

## 閒置清除之後又有流量的連線（TC，2026-11-17）

開發者問：閒置清除會不會讓 HTTPS 這種長連線一直「突然又變不信任」？模擬器多記三欄（`idle_resumed`、`idle_resumed_packets`、`idle_resumed_ports`）：被閒置清除之後又送了非控制封包的連線數，以及這些連線從恢復到再次被信任（或連線結束、port 重用）之前送去檢查的封包數，依 service port（兩端 port 較小的一個）分開。只有 TC 有閒置清除，ct mark 這三欄都是 0。重跑之後原本的 25 欄和 11-15 完全相同（`diff` 過），原始輸出在 `~/datasets/trust_sim2/`。

| dataset | 被閒置清除 | 之後又有流量的連線 | 因此多送檢查的封包（占全部封包） | 其中 443 |
|---|---|---|---|---|
| IoT-23 | 1,950 | 27 | 3,433（0.000%） | 0 |
| CIC-IDS2017 | 100,703 | 146 | 10,581（0.019%） | 19 條、107 個封包 |
| CIC-DDoS2019 | 5,351 | 23 | 17,744（0.006%） | 0 |
| CICIoT2023 | 76,844 | 7,541 | 875,981（0.020%） | 1,262 條、39,787 個封包 |
| CICIoT2023 Benign | 1,858 | 58 | 13,322（0.120%） | 26 條、314 個封包 |

- 被閒置清除的連線，99% 以上之後不再有流量（CIC-IDS2017 100,703 條只有 146 條回來）。回來的大多是 NTP（123）、NetBIOS（137）、LDAP（389、3268）和 CICIoT2023 的 55444、10001（裝置的長連線），HTTPS 很少。
- 這也解釋了 ct mark 和 TC 的 fast path 比例為什麼只差不到 0.5 個百分點。CICIoT2023 的 Spoofing、Recon 多送檢查的比例最高（2.2%、2.1%），主要是 55444。
- 連線回到 Suricata 時會不會斷，模擬器看不到，另外在 Docker 和 Pi 實測（`../ebpf/README.md`「HTTPS 長連線回到 Suricata 時會不會斷」）。
