# tests/ids_throughput — Pi 上 IDS engine 的 offline 處理速度與 memory

問題：Suricata 與 Snort 3 掛上 ET Open rule 之後，在 Raspberry Pi 上每秒能處理多少 packets、要多少 memory？
挑過的 rule set（`sel`、`gw_corp`）能換回多少速度？

做法是 **offline**：engine 直接讀 tmpfs 上的 pcap，量 engine 自己的處理能力，**沒有走網卡、NFQUEUE，也沒有 cli → DUT → srv**。
所以這裡的數字是 engine 處理速度的**上限**，不是 inline 轉送的線上速率。

這份 README 是這個資料夾唯一的說明文件。`RULE_CATEGORIES_corp.md` 是 `12_gateway_rule_corp.py` 產生的 `gw_corp` 分類表。

## 檔案放哪

- repo 內：腳本、`manifest.json`（每個 pcap 的 packets、bytes、sha256、來源與切法）、`results/`（CSV、彙總、log）。
- repo 外（工作站）：`$BIG=/home/sixsquare/datasets/throughput/`
  - `pcaps/`：切片（凍結後不再改）；`rules/`：rule 檔 + `SHA256SUMS`；`runs/`：每次量測的原始 log
- Pi 上：`~/ids_throughput/`（`pack.sh` 打包、解壓後的目錄），`data/{pcaps,rules,runs}` 對應上面三個目錄（`BIG=$PWD/data`）。

## 環境

| 項目 | 設定 |
|---|---|
| Hardware | Raspberry Pi 4 Model B Rev 1.4，4 GB（MemTotal 3,796 MB），Cortex-A72 × 4 |
| CPU 時脈 | 鎖 1000 MHz、governor `performance`（`../../scripts/pi_lab_mode.sh up 1000`；只對這次開機有效，重開機要重設）。Pi 4 沒有散熱，1.8 GHz 持續滿載約 30 秒就撞溫度牆降頻；1000 MHz 持續滿載不降頻 |
| OS | Raspberry Pi OS（Debian 13 trixie），kernel 6.18.50+rpt-rpi-v8 aarch64；zram 維持系統預設開啟 |
| Engine | Suricata 7.0.10（Debian 套件，沒有 Hyperscan）；Snort 3.12.2.0（DAQ 3.0.27，設定檔在 `/etc/snort`） |
| Rules | ET Open 2026-10-11 快照（由 `../ids_rules/` 產生 `full`，見下方 rule set） |
| Traffic | IoT-23 的切片（`01_make_slices.sh`、`11_make_scen_slices.sh`） |
| 讀法 | offline：每次量測先把 pcap 複製到 tmpfs（`/dev/shm/ids_tp`），engine 讀記憶體裡的檔；rule 檔在初始化時從 SD 卡讀，不在處理時間內 |
| Thread | single packet thread（Suricata `--runmode single`；Snort 3 `--max-packet-threads 1`），`taskset -c 2,3` |
| 其他 | 系統的 Suricata 服務先停掉（`sudo systemctl disable --now suricata`，約佔 72 MB）；Pi 沒有網路校時，開機後用 `sudo date -u -s @<epoch>` 校正 |

engine 的指令（`measure.sh`）：只改必要的設定，其餘維持各自的預設設定檔（Debian 的 `suricata.yaml`，含 eve.json、stats 輸出與 app-layer 解析；官方 `snort.lua`）。

- Suricata：`suricata -v -c /etc/suricata/suricata.yaml -S <rules> --runmode single --set mpm-algo=ac-ks --set spm-algo=bm --set unix-command.enabled=no -k none -r <pcap>`
- Snort 3：`snort -c snort.lua --include-path /etc/snort -R <rules> --lua "search_engine = { search_method = 'ac_bnfa' } alert_fast = { file = true }" -r <pcap> -A alert_fast -k none -s 65535 --max-packet-threads 1`
  - `snort.lua` 是官方檔只改 `HOME_NET`／`EXTERNAL_NET`（設成和 Suricata 預設相同的 RFC1918 三段，否則 ET 的 `!$HOME_NET` 會被拒絕）
  - `-s 65535`：Snort 3 預設只看每個 packet 前 1518 bytes，加大才保證兩個 engine 看到同樣的資料
- 兩者都 `-k none`（忽略 checksum；IoT-23 有些 packet 的 checksum 是錯的，不忽略會被丟掉），matcher 選 Pi 的 Suricata 也有的 `ac-ks`／`bm` 與 Snort 3 的 `ac_bnfa`。

工作站（x86）只用來準備資料：切 pcap、產生 manifest 用 Docker image `wnc-ids-lab`（`../ids_rules/Dockerfile`，`--network none`）；產生 rule set 的 Python 腳本直接在主機上跑。

## Rule set

| 名稱 | 內容 | Suricata 版 | Snort 版 | 產生 |
|---|---|---|---|---|
| `empty` | 不載 rule（`/dev/null`），engine 本身的基線 | 0 | 0 | — |
| `full` | 完整 ET Open | 52,606 | 52,445 | `../ids_rules/` |
| `sel` | `full` 扣掉 header 逗號 ≥ 8（帶長清單，主要是 TOR、CINS、DROP 等 IP 清單）的 rule；依成本挑，不是依偵測價值挑 | 51,384 | 50,886 | `04_make_sel_rules.py` |
| `gw_corp` | 依 category 挑：公司內外網之間的 gateway 本地需要的 rule | 38,511 | 38,086 | `12_gateway_rule_corp.py` |
| `common` | 兩個 engine 規則包 sid 的交集；只有 `run_pi_main.sh` 會跑，簡報沒有用到 | 52,090 | 52,090 | 檔案已在 `$BIG/rules/`，這個資料夾沒有重新產生它的腳本 |

`sel` 與 `gw_corp` 都是先決定 sid，兩個 engine 各用自己那版的規則文字；Snort 版比較少，是因為有些 sid 在 Snort 規則包裡沒有。
每個 rule 檔的 sha256 記在 `$BIG/rules/SHA256SUMS`，量測時也寫進每批的 `env.json`。

## 量測定義

**一次量測**（`measure.sh`）：把 pcap 複製進 tmpfs → 跑一次 engine → 留下 `engine.log`、`time.txt`（`/usr/bin/time -v`）、`timing.kv`（牆鐘 µs、exit code、完整指令）、`stats.log`（Suricata）、`sids.txt`（alert 的 sid 次數）。原始 log 在 `runs/<tag>/<run_id>/`，CSV 只放解析後的數字（`run_matrix.py`，每次量測一行）。

| 名稱 | CSV 欄位 | 定義 |
|---|---|---|
| engine 自報處理時間 | `self_s` | engine 讀完整個 pcap 後自己回報的秒數：Suricata `-v` log 的 `time elapsed`、Snort 3 summary 的 `timing: seconds`。不含啟動與載入 rule |
| kpps | `pps_self` ÷ 1000 | engine 回報的 packets（Suricata `decoder.pkts`、Snort 3 `daq analyzed`）÷ `self_s`。這是「pcap 的 packets 除以 engine 處理時間」，不是線上速率 |
| Mbps | `mbps_self` | engine 回報的 bytes × 8 ÷ `self_s` ÷ 10^6（bytes 含 Ethernet header） |
| 牆鐘時間 | `wall_s` | `measure.sh` 用 `$EPOCHREALTIME` 包住 engine 指令（含啟動、載入 rule、結束；不含複製 pcap） |
| load time | `wall_s − self_s` | 啟動、載入 rule 的時間（沒有獨立欄位，由這兩欄相減） |
| 差分法 | `pps_diff`（summary） | 同一輪、同一組態：`wall_s`（大 pcap）− `wall_s`（同切片的前 500 packets，`.small.pcap`），扣掉固定的啟動與載入時間；kpps = packets ÷ 差分。**只用在 Suricata 的 `empty`**：它的自報時間不含讀完 pcap 後的 flow 清理 |
| RSS | `maxrss_mb` | `/usr/bin/time -v` 的 Maximum resident set size（整個行程的峰值實體 memory，含 rule 與 flow table）。被換進 zram 的 page 不算在內 |
| CPU 時間 | `cpu_s` | user + sys，含載入 rule；Suricata 有管理 thread，所以可能大於牆鐘 |
| alerts | `alerts`、`suppressed`、`top_sids` | Suricata `detect.alert`（`suppressed` = 被 rule 內 threshold 壓掉的）、Snort 3 `detection: alerts`。Snort 3 只用 `-R` 載 rule 時 `threshold` 不生效，所以兩個 engine 的 alert 數不能直接比 |
| 核對 | `pkts_match`、`bytes_match` | engine 回報的 packets／bytes 必須等於 `manifest.json` 的數字 |
| 作廢 | `void`、`void_reason` | exit code ≠ 0、解析不到自報時間、逾時，或 throttled 閘門不過。作廢列留在 CSV，彙總時排除 |

- **throttled 閘門**（`run_matrix.py` 的 `throttle_void()`）：只看「這次量測期間」。量測前或後 `vcgencmd get_throttled` 的目前位元 bit0–3（欠壓、時脈上限、降頻、溫度上限）不是 0，或「開機後曾發生」位元 bit16–19 在量測前後有改變，就作廢。開機前就存在、沒有改變的 bit16–19（要重開機才會清）不算。
- **重複與順序**：一輪（round）= 所有組態各跑一次，每輪用固定 seed（20261011 + round）打亂順序；前幾輪是 warm-up（丟棄），之後是正式量測。這樣負載、溫度的漂移會平均分散到各組態，不會變成「某個組態比較慢」的假差異。每次量測都是新的 engine 行程。
- **彙總**（`summarize.py`）：只用 warm-up = 0 且 void = 0 的列，每組 (pcap, engine, rule set) 一行：`self_med`、`pps_med`（各次 pps 的中位數）、CV、差分欄、`maxrss_mb_max`（各次 RSS 的最大值）、alert 數集合等。並檢查 alert 數與 packets 每次相同（決定性）、自報時間和差分差距 > 10% 的組。簡報的 RSS 用的是 CSV 裡 3 次 `maxrss_mb` 的中位數。

## 實驗 1：主矩陣與 `sel`（2026-10-11）

目的：Snort 3 掛 `full` 為什麼這麼慢，只拿掉帶長清單的 rule 能換回多少；Suricata 會不會也受影響。

**切片**（`01_make_slices.sh`；「取前 N 個 packets」只代表檔案開頭，不代表整個 scenario）

| 名稱 | 來源與切法 | 流量型態 |
|---|---|---|
| `A_scan17` | IoT-23 Malware-17-1 (Kenjiro)，前 600,000 packets | 幾乎全是 60 B 的 TCP SYN（scan） |
| `B1_pay5` | Honeypot-5-1 (Amazon Echo)，前 140,000 packets | 幾乎是單一條 TLS(443) 大量下載 |
| `B2_mix3` | Malware-3-1 (Muhstik)，整檔 496,959 packets | SYN scan + SSH／IRC |
| `C_somfy02` | Honeypot-7-1 (door lock)，整檔 119,638 packets | benign IoT 日常流量 |

**批次**（`run_pi_main.sh`，tag 前綴 `pi_`）

| tag | 內容 | 次數 |
|---|---|---|
| `pi_E` | `empty` × 兩個 engine × 4 切片（含 `.small`，差分法用） | 1 warm-up + 3 |
| `pi_R1` | Suricata × `common`／`full`／`sel` × 4 切片 | 1 warm-up + 3 |
| `pi_R2a1` | Snort 3 × `sel` × 4 切片 | 1 warm-up + 3 |
| `pi_R2a2` | Snort 3 × `common`／`full` × B1、C | 1 warm-up + 3 |
| `pi_R2b` | Snort 3 × `common`／`full` × A、B2（單次 12–27 分鐘） | 0 warm-up + 2 |

**重跑**

```bash
# 工作站（在這個資料夾）：source lib.sh 會設好 $BIG、$PCAPS、$RULES、$IOT23 與 dk()
source lib.sh
# 切片（寫進 $BIG/slice_spec.tsv；manifest 等實驗 2 的切片做完再一起產生，指令見實驗 2）
./01_make_slices.sh
# 工作站：產生 sel（輸入是 $BIG/rules/{suricata,snort}_full.rules；可用 sha256 確認結果和量測時相同）
python3 -I 04_make_sel_rules.py $BIG/rules --check-snort-sha256 52537d4daeecae050cbe763456f5018d58060b10f5c267ad4dcb6f53b0352902
# Pi（見下方「在 Pi 上執行」的前置步驟）
nohup bash run_pi_main.sh > ~/pi_main_driver.log 2>&1 < /dev/null &
```

**結果檔**：`results/pi/pi_{E,R1,R2a1,R2a2,R2b}.{csv,env.json,summary.csv}`、`results/pi/logs/pi_main_driver.log`

**主要結果**：`A_scan17` 上 Snort 3 `full` 只有 0.37 kpps（366 pps），`sel` 回到 64.3 kpps（`empty` 104 kpps）；`B2_mix3` 也從 0.56 回到 21.2 kpps。
Suricata 的 `sel` 和 `full` 在 4 個切片相差 −1.5% 到 +1.0%，幾乎不受這批 rule 影響。

## 實驗 2：14 個 scenario × `empty`／`full`／`gw_corp`（2026-10-17）

目的：在不同流量型態下比較兩個 engine 掛 `full` 與 `gw_corp` 的處理速度、RSS、load time。

**挑 scenario**：`10_scenario_features.py` 讀每個 IoT-23 scenario 主 pcap 的前 20 萬 packets，算平均大小、payload 比例、TCP／UDP／ICMP 比例、SYN 比例、目的 port 與目的 IP 的分散程度（`results/scenario_features.tsv`，28 個 scenario），挑流量型態不同的 14 個，特徵幾乎相同的只取一個。

**切片**（`11_make_scen_slices.sh`）：每個 scenario 取前 200,000 packets，不足的用整檔（4 個）；另做 `.small`（前 500 packets）給差分法用。

| 切片 | scenario | 流量型態 | packets |
|---|---|---|---|
| `S_m17` | 17-1 (Kenjiro) | SYN scan 8081/80 | 200,000 |
| `S_m36` | 36-1 (Okiru) | SYN probe 37215 | 200,000 |
| `S_m48` | 48-1 (Mirai) | SYN scan 23 | 200,000 |
| `S_m39` | 39-1 (IRCBot) | SYN scan 22 | 200,000 |
| `S_m3` | 3-1 (Muhstik) | SSH scan + IRC | 200,000 |
| `S_m1` | 1-1 (Hide and Seek) | multi-port + UDP | 200,000 |
| `S_m34` | 34-1 (Mirai) | TCP/UDP mixed | 200,000 |
| `S_m60` | 60-1 (Gafgyt) | UDP flood, small | 200,000 |
| `S_m44` | 44-1 (Mirai) | UDP flood, large | 200,000 |
| `S_h5` | Honeypot-5-1 (Amazon Echo) | TLS download | 200,000 |
| `S_somfy02` | Honeypot-7-1 (door lock) | benign | 119,638 |
| `S_m20` | 20-1 (Torii) | C2 443 | 50,156 |
| `S_m42` | 42-1 (Trojan) | file download | 24,484 |
| `S_h4` | Honeypot-4-1 (Philips HUE) | benign | 21,664 |

**批次**（`run_pi_scen2.sh`，tag 前綴 `pi_scen2_`；全部在同一次開機內，每格 1 warm-up + 3，逾時 3600 秒）

| tag | 內容 |
|---|---|
| `anchor0` | 錨點：`C_somfy02` × `full` × 兩個 engine |
| `E` | `empty` × 14 切片（含 `.small`）× 兩個 engine |
| `S` | Suricata × `full`／`gw_corp` × 14 切片（同一批交錯） |
| `N` | Snort 3 × `full`／`gw_corp` × 14 切片（同一批交錯；`full` 的 9 個 scan／flood 切片每次 4–9 分鐘，這批約 5 小時） |
| `anchor1` | 錨點：同 `anchor0`，放在最後，看整段期間有沒有漂移 |

**重跑**

```bash
# 工作站：特徵 -> 切片 -> manifest（01_make_slices.sh 會清空 slice_spec.tsv，所以要先跑實驗 1 的 01 再跑 11；manifest 涵蓋兩個實驗的切片）
source lib.sh
python3 -I 10_scenario_features.py $IOT23 ../iot23/results results/scenario_features.tsv 200000
bash 11_make_scen_slices.sh
dk -v $HERE:/s:ro -v $PCAPS:/p:ro -v $BIG:/b -- python3 -I /s/make_manifest.py /p /b/slice_spec.tsv /b/manifest.json && cp $BIG/manifest.json .
# Pi
nohup bash run_pi_scen2.sh > ~/pi_scen2_driver.log 2>&1 < /dev/null &
```

**結果檔**：`results/pi/pi_scen2_{anchor0,E,S,N,anchor1}.{csv,env.json,summary.csv}`、`results/pi/logs/pi_scen2_driver.log`。
這次在 2026-10-17 12:50–18:56 UTC 跑完，正式量測 348 次、作廢 0。Suricata `empty` 的 kpps 用 summary 的 `pps_diff`，其他用 `pps_med`。

**主要結果**：Snort 3 `full` 在 9 個 scan／flood scenario 只有 0.37–0.92 kpps，`gw_corp` 在 14 個 scenario 都 ≥ 11.4 kpps；
Suricata `full` 15.5–176 kpps，`gw_corp` 只快 1–26%。load time 中位數：Suricata 34.9 → 24.7 s，Snort 3 26.3 → 19.3 s。

## 實驗 3：`gw_corp` rule set

目的：依 category 挑出「公司內網與外網之間的 security gateway」本地 IDS 需要的 rule。判斷表是分析判斷，**沒有經過偵測率驗證**。

1. `05_rule_features.py` 把 Suricata 版 `full` 每條 rule 的 category、classtype、metadata、協定、header 逗號數、flowbits 抽成 `results/rule_features.tsv`（52,606 條）。
2. `12_gateway_rule_corp.py` 依 category 判斷（GPL 舊規則依子類別、Threatview 單獨一類，共 73 個 category），每個 category 的判斷與理由寫在 `results/rule_category_decisions_corp.tsv` 與 `RULE_CATEGORIES_corp.md`：

| 判斷 | category | rules（全部 → 放進 `gw_corp`） |
|---|---|---|
| 全部保留 | 50 個，和入侵直接相關（MALWARE、WEB_SPECIFIC_APPS、PHISHING、EXPLOIT_KIT、EXPLOIT、SCAN、DOS、TELNET…） | 38,399 → 38,378 |
| 只留 IRC | INFO、CHAT（IRC 常被當 C2，其餘只是資訊） | 4,585 → 12 |
| 不保留 | DYN_DNS、HUNTING、TA_ABUSED_SERVICES（ET 的說明：觸發不代表攻擊） | 7,567 → 0 |
| 不保留 | RETIRED、P2P、REMOTE_ACCESS 等 12 個（辨識服務使用、過時技術） | 839 → 0 |
| 不保留 | TOR、CINS、DROP、THREATVIEW、COMPROMISED、CNC（IP blocklist，建議改用 nftables 的 IP set，尚未實作） | 1,216 → 0 |

再補上 flowbits 依賴的 121 條，總數 38,511（Snort 版 38,086）。

**已知限制**：「全部保留」的 category 也用 header 逗號 ≥ 8 排除長清單，這個條件誤篩了 21 條正常的偵測 rule（MALWARE 14、EXPLOIT 5、SCADA 1、ADWARE_PUP 1；
其中 20 條的長清單是 port，1 條是 IP 清單加 content 比對），所以上表是 38,399 → 38,378。照判斷原則它們應該保留，之後要加回。

**重跑**（工作站）

```bash
source lib.sh
python3 -I 05_rule_features.py $BIG/rules/suricata_full.rules results/rule_features.tsv
python3 -I 12_gateway_rule_corp.py $BIG/rules results/rule_features.tsv
# -> $BIG/rules/{suricata,snort}_gw_corp.rules、gw_corp_sids.txt（sha256 附加到 SHA256SUMS）
#    results/rule_category_decisions_corp.tsv、RULE_CATEGORIES_corp.md
```

量測時用的 `gw_corp` rule 檔 sha256：Suricata `d0d76bde…`、Snort `88894917…`（完整值在 `$BIG/rules/SHA256SUMS`）。

## 實驗 4：39-1 的 memory（2026-10-18）

目的：memory 只有 2 GB／1 GB 時，engine 載不載得進去、會不會變慢。

做法：用韌體選項 `total_mem` 把 4 GB 的 Pi 限制成 2 GB、1 GB（`pi_set_total_mem.sh`，改 `/boot/firmware/config.txt`，重開機後生效；只限制可用 RAM，CPU 與 memory 頻寬不變）。
每個等級重開機後跑一次 `run_pi_mem_scen.sh`：39-1（`S_m39`）× `full`／`gw_corp` × 兩個 engine，每格 1 warm-up + 3。

- 選 39-1：Suricata 掛 `full`／`gw_corp` 時，它在 14 個 scenario 裡都最慢、RSS 最大；Snort 3 也排在最慢的前幾個；而且在 11 個 usable scenario 裡。
- 4 GB 不另外量，用實驗 2 的 `pi_scen2_S`／`pi_scen2_N` 裡 `S_m39` 的數據。
- zram 維持系統預設開啟（MemTotal：2 GB 時 1,847 MB、1 GB 時 905 MB；zram 大小約等於 MemTotal）。
- 開跑前先等 `vcgencmd` 回報的 ARM 時脈真的降到 1000 MHz：剛開機的一兩分鐘內，`scaling_max_freq` 已經是 1000 MHz，但 CPU 實際還跑 1800 MHz。正式量測全部是 1000 MHz。
- 矩陣跑完後，Suricata 每個 rule set 再單獨跑一次，取樣行程的 VmSwap（被換進 zram 的量）峰值，結果只在 log 裡；和 RSS 不是同一次量的，不要相加。
- OOM 紀錄（dmesg）存到 `results/<tag>.dmesg.txt`，兩個等級都沒有 OOM。

**重跑**（Pi）

```bash
bash pi_set_total_mem.sh 2048 && sudo reboot
# 重開機後：pi_lab_mode.sh up 1000、校時，然後
cd ~/ids_throughput && PCAP=S_m39.pcap nohup bash run_pi_mem_scen.sh 2gb > ~/pi_mem39_2gb.log 2>&1 < /dev/null &
bash pi_set_total_mem.sh 1024 && sudo reboot
cd ~/ids_throughput && PCAP=S_m39.pcap nohup bash run_pi_mem_scen.sh 1gb > ~/pi_mem39_1gb.log 2>&1 < /dev/null &
bash pi_set_total_mem.sh off && sudo reboot                    # 還原成 4 GB
# run_pi_mem_scen.sh 不會自己彙總：
python3 -I summarize.py results/pi_mem39_2gb.csv --out results/pi_mem39_2gb.summary.csv
python3 -I summarize.py results/pi_mem39_1gb.csv --out results/pi_mem39_1gb.summary.csv
```

**結果檔**：`results/pi/pi_mem39_{2gb,1gb}.{csv,env.json,summary.csv,dmesg.txt}`、`results/pi/logs/pi_mem39_{2gb,1gb}.log`（含 VmSwap 取樣）

**主要結果**：1 GB 時 Suricata `full` 15.5 → 13.4 kpps（慢約 13%），RSS 719 MB 是因為一部分被換進 zram（VmSwap 峰值約 794 MB），不是用得比較少；
`gw_corp` 15.8 → 14.2 kpps（慢約 10%，VmSwap 約 466 MB）。Snort 3 三個等級都不受影響（`full` 0.38–0.39 kpps、376 MB；`gw_corp` 19.9–20.0 kpps、302 MB）。

## 在 Pi 上執行

Pi 需要：bash、coreutils、python3（標準函式庫）、`/usr/bin/time`（Debian 套件 `time`）、`taskset`（util-linux）、`vcgencmd`、Suricata 7.0.10、Snort 3.12.2.0。不需要網路。

```bash
# 工作站：打包（不會連線）-> $BIG/ids_throughput_pi.tar.gz 與 .sha256（壓縮前約 1.3 GB）
source lib.sh; ./pack.sh
scp $BIG/ids_throughput_pi.tar.gz{,.sha256} ../../scripts/pi_lab_mode.sh wnc@10.254.254.2:~/

# Pi：檢查、解壓、進入量測模式
sha256sum -c ids_throughput_pi.tar.gz.sha256 && tar xzf ids_throughput_pi.tar.gz && cd ids_throughput
(cd data/pcaps && sha256sum -c ../pcaps.SHA256SUMS) && (cd data/rules && sha256sum -c --ignore-missing SHA256SUMS)
bash ~/pi_lab_mode.sh up 1000             # 每次開機都要重設
sudo date -u -s @<工作站的 date +%s>         # Pi 沒有網路校時
sudo systemctl disable --now suricata      # 系統的 Suricata 服務；實驗結束要還原就 enable --now
# 然後跑上面各實驗的 run_pi_*.sh；Snort 3 的設定目錄不是 /etc/snort 時設 SNORT_ETC=...
```

結果寫在 Pi 的 `~/ids_throughput/results/<tag>.*`，driver log 在 `~/`；抓回工作站放到 `results/pi/` 與 `results/pi/logs/`。
每批的 `env.json` 記錄 CPU、核心數、governor、MemTotal、kernel、機型、開始時的溫度／時脈／throttled、engine 版本、rule 檔 sha256 與參數；
每次量測的完整指令在 `data/runs/<tag>/<run_id>/timing.kv` 的 `cmd=`。

## 腳本一覽

| 檔案 | 做什麼 |
|---|---|
| `measure.sh` | 一次量測：複製 pcap 進 tmpfs → 跑一個 engine → 留下原始 log。`run_matrix.py` 呼叫它 |
| `run_matrix.py` | 量測矩陣的調度：(pcap) × (engine) × (rule set)，warm-up、每輪打亂順序、讀溫度／時脈／throttled、解析 log、每次一行寫 CSV、逾時就殺掉整個行程群組。`--mode native`（Pi）或 `docker`（工作站容器） |
| `summarize.py` | 把 CSV 彙總成每組態一行（中位數、CV、差分法），並做決定性等檢查 |
| `lib.sh` | 工作站共用路徑（`$BIG`、`$PCAPS`、`$RULES`、`$RUNS`、`$IOT23`）與 `dk()`（`docker run --network none --user …`） |
| `pcap_stats.py` | 只用標準函式庫讀 pcap：packets、bytes、持續時間、平均大小、payload 比例（定義在檔頭）。Pi 上也能跑 |
| `make_manifest.py` | 把 `pcap_stats.py` 的數字、sha256、來源與切法寫成 `manifest.json` |
| `manifest.json` | 每個 pcap 的事實資料；`run_matrix.py` 用它核對 packets／bytes |
| `pcap_concat.py` | 把 pcap 串接 N 次並平移時間戳（`01_make_slices.sh` 用它產生 `.x2.pcap`，給 `summarize.py` 的線性檢查用；上面的實驗沒有用到） |
| `01_make_slices.sh` | 在容器內用 tcpdump 切出實驗 1 的 4 個切片與 `.small`、`.x2` |
| `04_make_sel_rules.py` | 產生 `sel`：用 Snort 版 `full` 找出 header 逗號 ≥ 8 的 sid，兩個 engine 移除同一批 sid（另存 `sel_removed_sids.txt`） |
| `05_rule_features.py` | 抽出每條 rule 的分類特徵 → `results/rule_features.tsv` |
| `10_scenario_features.py` | 算每個 IoT-23 scenario 開頭 N 個 packets 的流量特徵 → `results/scenario_features.tsv` |
| `11_make_scen_slices.sh` | 在容器內切出實驗 2 的 14 個 scenario 切片（前 200,000 packets）與 `.small` |
| `12_gateway_rule_corp.py` | 產生 `gw_corp` rule 檔、`results/rule_category_decisions_corp.tsv`、`RULE_CATEGORIES_corp.md` |
| `RULE_CATEGORIES_corp.md` | `12` 產生的分類表：每個 category 的判斷、規則數、理由 |
| `run_pi_main.sh` | 實驗 1 的 Pi 批次 |
| `run_pi_scen2.sh` | 實驗 2 的 Pi 批次 |
| `run_pi_mem_scen.sh` | 實驗 4 的 Pi 批次（每個 memory 等級跑一次） |
| `pi_set_total_mem.sh` | 在 Pi 上設定或移除 `total_mem`（需要 sudo，重開機生效；第一次會備份 `config.txt`） |
| `pack.sh` | 把 Pi 要用的腳本、pcap、rule 檔打成 tar.gz + sha256 |
| `../../scripts/pi_lab_mode.sh` | 在 Pi 上鎖時脈（`up 1000`）、還原（`down`）、查看（`status`） |

`results/` 底下：

| 檔案 | 內容 |
|---|---|
| `rule_features.tsv` | `05` 的輸出：ET Open（Suricata 版）52,606 條 rule 的分類特徵 |
| `scenario_features.tsv` | `10` 的輸出：28 個 scenario 的流量特徵 |
| `rule_category_decisions_corp.tsv` | `12` 的輸出：73 個 category 的判斷 |
| `pi/pi_{E,R1,R2a1,R2a2,R2b}.*` | 實驗 1 |
| `pi/pi_scen2_*` | 實驗 2 |
| `pi/pi_mem39_*` | 實驗 4 |
| `pi/logs/` | 三個 Pi 批次的 driver log |

每個 tag 有 `<tag>.csv`（每次量測一行）、`<tag>.env.json`（環境與參數）、`<tag>.summary.csv`（`summarize.py` 的彙總）。

## 限制

- **offline 上限**：沒有網卡、NFQUEUE、真實的封包到達時間；inline 轉送的速度要另外量。
- **Pi 4 不是 Pi 3B+**：Pi 4 是 Cortex-A72、4 GB，鎖在 1000 MHz；Pi 3B+ 是 Cortex-A53 1.4 GHz、1 GB，這裡的數字不能直接外推到 3B+。
  `total_mem` 只限制可用 RAM，不會讓 Pi 4 變成 3B+。
- **切片只代表檔案開頭**：「取前 N 個 packets」有偏差，結論只適用這些切片的流量型態。
- **預設設定**：engine 用各自的預設設定檔（含 eve.json、app-layer 解析等），量到的是「預設設定掛 ET rule」的成本，不是調校過的設定。
- **single packet thread**：多 thread 的擴充性沒有量。
- **`gw_corp` 的判斷沒有驗證偵測率**；另有上面提到的 21 條誤篩 rule 要加回。
