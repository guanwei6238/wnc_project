# tests/detection — 流量送進去，本地 IDS 偵測得到嗎？

問題（老師 10/19）：把各 dataset 的流量送進本地 IDS，偵測得出來嗎？同時要有一張「每個 dataset 目前做到哪」的狀態表，之後每次更新。

做法是 **offline**：Suricata 直接讀 pcap，把 eve.json 的 alert 對回 dataset 的 label。偵測結果取決於 engine 版本、設定、rule 與 pcap（設定和 Pi 相同），所以在工作站（x86 Docker）跑；和 Pi 上同版本的 Suricata 結果相同是推論，沒有在 Pi 上跑過偵測。同一台工作站跑兩次（03-11 從 pipe 讀和讀檔案），657 筆 alert 的時間、SID、五元組、`pcap_cnt` 相同，但 Syn 時段（flow emergency mode）有 15 筆 alert 附帶的 flow 欄位（`flow.start`、packet 數）不同。

這份 README 是這個資料夾唯一的說明文件。

## 檔案放哪

- repo 內：腳本、`results/`（每個 scenario／day 的比對結果 JSON、彙總 TSV、對齊結果）。
- repo 外（工作站）：
  - `~/datasets/detection/rules/`：ET Open 8.0.7 快照合併後的 `et_all.rules`、`gw_corp_sids.txt`、`iplist_sids.txt`、`detect.yaml`
  - `~/datasets/detection/{iot23,cicids2017,cicddos2019,ciciot2023}/`：每次跑 Suricata 的 `eve.json`、`run.log`
  - `~/datasets/{cicids2017,cicddos2019}/`：轉好的 pcap、`conn/`（label 轉成 conn.log 格式）、`align/`；`~/datasets/cicddos2019/zips/`：01-12 的 4 個 pcap zip（從 NAS 複製，20.9 GB）；`~/datasets/cicddos2019/conn/0311.dedup.conn.log.labeled`：03-11 去重後的 label（`.dropped` 是刪掉的列號）
- NAS（`/mnt/nas/dataset/`）：原始檔存檔。`cicids2017/pcaps/`（官方 pcapng，md5 核對過）、`cicddos2019/{pcaps,csvs}/`（官方 zip）、`ciciot2023/pcap_sample/`（最初抽樣的 36 個 pcap）、`ciciot2023/pcap/<資料夾>/`（其餘 273 個，每個檔旁邊的 `.ok` 是 sha256；寫進 NAS 後用 direct read 讀回核對過）；IoT-23 原始壓縮檔在 `/mnt/nas/wnc_data/`。

## 環境

| 項目 | 設定 |
|---|---|
| Engine | Suricata 8.0.7，Debian trixie-backports 套件（和 Pi 上同一個版本，`Dockerfile` → image `wnc-suricata8`） |
| Rules | ET Open `suricata-8.0.7` 2026-10-30 快照（`~/datasets/rulesets/snapshot_2026-10-30_suricata-8.0.7`），啟用的 52,798 條全部載入成功（CICIoT2023 因為 HOME_NET 是 `any`，有 3 條載入失敗，見「待決與限制」） |
| 設定 | Debian 預設 `suricata.yaml`，只改輸出（只留 eve 的 alert，`make_yaml.py`）；`--runmode single`、`mpm-algo=ac-ks`／`spm-algo=bm`（和 Pi 相同）、`-k none` |
| HOME_NET | IoT-23：預設（RFC1918 三段，被感染設備在 192.168.x）；CIC-IDS2017：`192.168.10.0/24`；CIC-DDoS2019：`192.168.50.0/24`；CICIoT2023：`HOME_NET` 與 `EXTERNAL_NET` 都是 `any` |

HOME_NET 為什麼不同：CIC-IDS2017／CIC-DDoS2019 的攻擊者經防火牆 NAT 後是 `172.16.0.1`／`172.16.0.5`，Suricata 預設的 HOME_NET 含 `172.16.0.0/12`，會把攻擊者當成內部主機，外部打內部的 rule 就不會觸發；所以 HOME_NET 只放受害端網段，模擬 gateway 放在攻擊者與受害者之間。CICIoT2023 的攻擊者也在實驗區網內、官方受害清單只有設備名稱，所以不分內外（rule 偵測的上限）。

## Rule set

| 名稱 | 內容 | 條數 |
|---|---|---|
| `full` | ET Open 8.0.7 全部啟用的 rule | 52,798 |
| `gw_corp` | 10/19 報告挑的本地 rule（`../ids_throughput/12_gateway_rule_corp.py` 的 2026-10-11 SID 清單，取 8.0.7 快照裡還存在的） | 38,506 |
| `gw_corp` + IP 清單 | 再加上長 IP 清單的 rule（`tor`、`ciarmy`、`drop`、`threatview_CS_c2`、`compromised`、`botcc`、`dshield`）；gateway 設計上這些改用 nftables 的 IP 集合比對，偵測面一樣 | 39,729 |

只跑一次 `full`，`gw_corp` 的結果是從 `full` 的 alert 依 SID 篩出來的。已知誤差：`gw_corp` 裡若有 rule 靠被排除的 rule 先設 flowbits，篩出來的會偏高。8.0.7 快照比 10/11 多 203 個 SID（10/11 之後新增），沒有分類，不在 `gw_corp`。

## 偵測的定義

- **alert 對 flow**（`match_iot23.py`）：五元組雙向都算（ICMP 不看 port），alert 的 packet 時間落在 flow 的 [ts, ts+duration]（兩端各放寬 1 µs）就對上；落不進任何 flow 時，再看 alert 所屬 Suricata flow 的起始時間和 flow 的 ts 是否相差 ≤ 1 ms（flow timeout 時才送出的 alert）。CIC-DDoS2019 加 `--cic`：非 TCP／UDP 的 alert（例如 ICMP）對到同一對 IP 的 Protocol 0 flow（見下）。
- 每個（dataset, label）報兩個數字：
  - **有 alert 的 flow 比例**：至少對上一筆 alert 的 flow ÷ 該 label 的 flow 數
  - **有沒有 alert**：該 label 有沒有任何一條 flow 對上 alert
- 以實際輸出的 alert 為準。很多 rule 設了 threshold（例如 SSH scan 同一來源每 5 條 flow 才報 1 次、Heartbleed 120 秒內只報 1 次），所以 scan／DoS 的「flow 比例」天生偏低，要和「有沒有 alert」一起看。
- Benign 上的 alert 只列數字：dataset 的 Benign label 本身有疑點（例如 IoT-23 33-1 有 208 條、17-1 有 3 條 Benign 觸發 Mirai User-Agent rule），不直接算成 false positive rate。
- CICIoT2023 的 label 只到 pcap 檔，沒有 flow 層級的 label：每個檔報 flow 總數（Suricata `flow.total`）、有 alert 的 flow 數（eve 的 distinct `flow_id`）、alert 的 SID。

## 各 dataset 的處理

| Dataset | label 來源 | 對齊 | 偵測 |
|---|---|---|---|
| IoT-23 | Zeek `conn.log.labeled` | 10/19 已做（`../iot23/`），11 個 usable | 全部 23 個有 label 的 scenario 的完整 pcap：11 個 usable（`run_iot23.sh`、`match_iot23_all.sh`）＋其餘 12 個（`run_iot23_rest.sh`，2026-11-01；另 Somfy-02～06 沒有 label，只跑 Suricata，都是 0 筆 alert） |
| CIC-IDS2017 | CNS 2022 修正版 CSV（`CICIDS2017_improved.zip`，時間是 UTC），`cic_to_conn.py` 轉成 conn 格式 | 5 天全部 flow（`run_cicids2017.sh`） | 5 天 |
| CIC-DDoS2019 | 官方 CSV（當地時間：03-11 加 3 小時、01-12 加 4 小時，用 pcap 第一個 packet 與 CSV 第一筆比對確認） | 兩天全部 flow（`align_cicddos2019_full.sh`）：03-11 讀串好的 pcap；01-12 從 zip 解壓用 pipe 送進 `align_stream.py`，flow 分 3 份（`align_cicddos2019_full.sh 3`）、每份各讀一次串流，`merge_align.py` 相加；對齊和比對都加 `--cic`（納入 Protocol 0，見下）；03-11 先去掉重複列（`dedup_conn.sh`） | 兩天全天：03-11 `run_cicddos2019.sh`；01-12 從 zip 解壓用 pipe 送進 Suricata（`run_cicddos2019_0112_full.sh`） |
| CICIoT2023 | pcap 檔名（每個檔一種攻擊） | 檔案層級（沒有 flow label） | 全部 309 個檔（2026-10-31：先抽 36 個，其餘 273 個用 `fetch_ciciot2023_all.sh` 下載、跑 Suricata、存到 NAS 的 `pcap/<資料夾>/`；清單與大小：`results/ciciot2023_files.tsv`，由 Hugging Face 鏡像 `bencorn/CIC-IoT-2023` 的檔案清單產生，`sampled` 欄是最初抽的 36 個） |

CIC-DDoS2019 01-12 解開約 164 GB，所以不先存成 pcap：`zip_pcap_concat.py` 依段落編號把 zip 裡的 819 段串成一個 pcap 串流寫到 stdout，直接接給 Suricata（`-r /dev/stdin`）或 `align_stream.py`（pcap 給 `/dev/stdin`）。用 03-11 驗證過：Suricata 從 pipe 讀和讀檔案的 657 筆 alert 完全相同（時間、SID、五元組、`pcap_cnt`），讀到的 packet 數也相同；`align_stream.py` 從 pipe 讀、`--part` 分份再用 `merge_align.py` 相加，和讀檔案不分份的結果相同（0112s 抽樣資料）。pipe 只能讀一次，所以每次載入的 flow 都要一批放得下（`--max-flows` 設大）：記憶體實測每條 flow 約 235 bytes（03-11 的 2,036 萬條一次載入，峰值 4.8 GB）；01-12 的 5,006 萬條用 `--part i/3` 分 3 份，每份各讀一次 pcap 串流（約 65 分鐘；峰值約 4.3 GB 是只收 TCP／UDP／ICMP 那次量的，flow 數只差 2,546 條；用 `systemd-run --user --scope -p MemoryMax=8G` 限制記憶體，一次載入全部時曾在約 10 GB 被 OOM killer 砍掉）。

CIC-DDoS2019 的 Protocol 0（`align_stream.py`、`match_iot23.py` 的 `--cic`）：官方 CSV 沒有 Protocol = 1（ICMP）的列，但有 Protocol 0、port 0／0 的列（03-11 1,452 條、01-12 2,546 條）。原版 CICFlowMeter 只解 TCP／UDP header，解不出的 packet（ICMP、非第一個的 IP fragment 等）都依 IP 對記成 Protocol 0 的 flow。`--cic` 照同樣的規則：IPv4 不是 TCP／UDP、或 fragment offset > 0 的 packet 算成 Protocol 0、port 0。只用在 CIC-DDoS2019；CIC-IDS2017 修正版的 CSV 有 603 條 ICMP flow，加 `--cic` 會把 ICMP packet 也算成 Protocol 0、這些 flow 就對不上，整體反而變差（aligned 2,097,247 → 2,096,968），所以 CIC-IDS2017 只算 TCP／UDP／ICMP。它的 1,510 條 Protocol 0：1,184 條是 `8.6.0.1 → 8.0.6.4`（ARP frame 被當成 IP 解析：`08 06 00 01` 是 EtherType 與 hardware type、`08 00 06 04` 是 protocol type 與位址長度），對不回 IP packet；另外 326 條是真的 IP 流量（大多是 192.168.10.x → 192.168.10.3、送往 224.0.0.22 的 multicast；label Benign 324、Malicious 2），沒有納入。

### 原始數據

| Dataset | 檔案 | 大小 | packets | labeled flows |
|---|---|---|---|---|
| IoT-23 | 28 個 pcap（23 個有 label；Somfy-02～06 沒有） | 62.9 GB | 770,313,789 | 325,309,946 |
| IoT-23（11 個 usable） | 11 個 pcap | 32.1 GB | 413,410,334 | 296,338,640 |
| CIC-IDS2017 | 5 個 pcapng（Monday–Friday，2017-07-03～07） | 52.4 GB | 56,370,702 | 2,098,466（TCP／UDP／ICMP；CSV 2,099,976 列） |
| CIC-DDoS2019 03-11 | 146 段（2018-11-03，testing） | 29.1 GB（zip 2.0 GB） | 61,407,883 | 19,881,726（去重後；CSV 20,364,525 列，含 Protocol 0 1,452 條） |
| CIC-DDoS2019 01-12 | 819 段（2018-12-01，training） | 163.6 GB（zip 20.9 GB） | 250,783,287 | 50,063,112（含 Protocol 0 2,546 條） |
| CICIoT2023 | 309 個 pcap（34 個資料夾：33 種攻擊 + Benign） | 587.3 GB | — | 沒有 flow label |
| CICIoT2023（全部跑完） | 309 個 pcap | 587.3 GB | 4,482,456,728 | Suricata 算出 931,869,557 條 |

CIC-DDoS2019 01-12 的大小是 Suricata 讀到的 packet 資料（159,591,649,284 bytes）加上每個 packet 16 bytes 的 pcap 記錄檔頭，等同串成一個 pcap 的大小。CICIoT2023 的大小依類別：DDoS 346.9 GB（176 個檔）、Mirai 153.1 GB（76）、DoS 74.8 GB（38）、Benign 7.0 GB（4）、Spoofing 3.7 GB（3）、Recon 1.8 GB（5）、Web-based 0.1 GB（6）、Brute Force 0.04 GB（1）。

## 資料來源與核對

CIC 官方伺服器（cicresearch.ca，要填表拿 token）實測約 65 KB/s，改從 Hugging Face 的鏡像 `bencorn/{CICIDS2017,CICDDoS2019,CIC-IoT-2023}` 下載（`hf_download.sh`，用鏡像記的 sha256 核對下載完整；`cic_list.py` 用 token 列出官方的檔案清單），再和官方比對：

- CIC-IDS2017：5 個 pcap 都和官方 `.md5` 一致（`~/datasets/cicids2017/official_md5/`；NAS 上的複本也核對過，標記檔 `*.md5ok`）。
- CICIoT2023：從官方抓 5 個小檔（Uploading_Attack、XSS、SqlInjection、Recon-PingSweep、Backdoor_Malware），sha256 和鏡像相同。
- CIC-DDoS2019：官方沒有 md5；從官方抓 `PCAP-03-11.zip`、`CSV-03-11.zip` 的前 5 MB，和鏡像相同。

## 結果

彙總表在 `results/*_by_label.tsv`（依 label 合計）、`results/*_by_scenario.tsv`（每個 scenario／day）、`results/*_sids.tsv`（每個 SID 打中哪些 label 的幾條 flow）；原始比對結果在 `results/*_match/*.json`，對齊在 `results/align/`。重產彙總表：`python3 -I summarize.py <名稱> results results/<名稱>_match/*.json`。

### 對齊

| Dataset | 範圍 | labeled flows | flow alignment | packet coverage |
|---|---|---|---|---|
| IoT-23 | 23 個 scenario（10/19） | 325,309,946 | 98.87% | 逐 scenario 見 `../iot23/` |
| CIC-IDS2017 | 5 天 | 2,098,466 | 99.94% | 99.26%（56,370,702 packets） |
| CIC-DDoS2019 | 03-11 | 19,881,726 | 99.89% | 99.94%（61,407,883 packets） |
| CIC-DDoS2019 | 01-12 | 50,063,112 | 99.95% | 99.99%（250,783,287 packets） |

CIC-IDS2017 逐日：Monday 100%／99.28%、Tuesday 100%／99.28%、Wednesday 100%／99.39%、Thursday 99.66%／99.11%（對不上的 1,219 條都是 pcap 的 packet 比 label 多）、Friday 100%／99.16%，5 天都 usable（flow alignment ≥ 99% 且 packet coverage ≥ 90%）。

CIC-DDoS2019：03-11 aligned 19,860,617、covered 61,372,112（去重後；去重前 20,364,525 條、aligned 20,341,001，99.88%，covered 相同）；01-12 aligned 50,035,937、covered 250,748,053，兩天都 usable。各攻擊 label 的 flow alignment 都 ≥ 99.7%，低的是 03-11 Benign 75.50%、UDPLag 65.19%（1,873 條），01-12 Benign 80.31%、WebDDoS 91.12%（439 條）。只收 TCP／UDP／ICMP 時（舊結果）packet coverage 只有 03-11 91.28%、01-12 87.24%：沒被涵蓋的 packet（5,354,677、32,001,558 個）有 97.6%（5,225,955）、99.4%（31,817,880）是非第一個的 IP fragment（tcpdump `ip[6:2] & 0x1fff != 0`），原版 CICFlowMeter 把它們記在 Protocol 0 的 flow 裡；加 `--cic` 之後 coverage 是上表的數字。packet 增加最多的是反射攻擊的 label，例如 01-12 DrDoS_DNS 從 12,341,421 變 30,492,461、DrDoS_SNMP 從 10,337,460 變 18,043,573。03-11 的官方 CSV 有 482,799 組重複列（每組 2 列，除了 uid 以外每個欄位都相同、label 也相同：Syn 478,395 組、Benign 4,404 組；其中 117 組是 Protocol 0），對齊與比對都用去重後的 label（`dedup_conn.sh`：5-tuple、ts、duration、兩個方向的 packet 數相同的列只留第一次出現的，保留原本順序）；去重前有 95 筆 alert 同時對到一組重複的兩條 flow。01-12 沒有重複列（含 Protocol 0）。

### IoT-23（全部 23 個有 label 的 scenario，完整 pcap，770,313,789 packets）

malicious flow 294,449,255 條，有 alert 的 14,762,773 條（5.01%；`gw_corp` 14,762,716），其中 14,711,802 條是 39-1 (IRCBot) 的 SSH scan（`ET SCAN Potential SSH Scan OUTBOUND`，threshold 每 5 條報 1 次，所以剛好 20%）；扣掉 39-1 是 49,694／220,887,611（0.02%）。只算 11 個 usable 是 265,503,156 條、14,713,172 條（5.54%；`results/iot23_usable11_*.tsv`）。彙總：`python3 -I summarize.py iot23 results results/iot23_match/*.json`。

| label | flows | 有 alert 的 flow（`full`） | 有 alert 的 scenario |
|---|---|---|---|
| PartOfAHorizontalPortScan | 213,852,924 | 14,757,108（6.90%） | 4／11（39-1、3-1 (Muhstik) SSH scan；1-1、52-1 只有 IP 清單） |
| Okiru | 60,990,708 | 34（全部是 IP 清單） | 2／5 |
| DDoS | 19,538,713 | 0 | 0／7 |
| C&C-HeartBeat | 33,673 | 0 | 0／5 |
| C&C | 21,995 | 4,165（18.9%；34-1 IRC 1,767、49-1 `ET MALWARE Mirai Variant Checkin Response` 1,232、39-1 IRC 1,156、3-1 `ET MALWARE ELF/Muhstik` 6、43-1、52-1 各 2） | 6／10 |
| Attack | 9,398 | 1,389（14.8%；3-1 SSH scan 1,264、39-1 121） | 4／5 |
| C&C-FileDownload、C&C-HeartBeat-FileDownload、FileDownload | 53、11、18 | 50、11、16（ELF 下載） | 7／7 |
| 其他 6 種（C&C-PartOfAHorizontalPortScan、C&C-HeartBeat-Attack、C&C-Torii、PartOfAHorizontalPortScan-Attack、Okiru-Attack、C&C-Mirai） | 1,762 | 0 | 0／6 |

Telnet（23／2323）、52869、80、8081 等 port 的 SYN scan、Okiru（37215 的 SYN）、DDoS 沒有 alert（只有少數 IP 清單）：2026-10-30 快照的 SCAN category 沒有這些 port 的 scan rule，也沒有 CVE-2017-17215 的 rule。60-1 (Gafgyt) 的 22 GB DDoS（2.7 億個 packet）一筆 alert 都沒有（Pi 速度測試的同一個 scenario 切片也是 0）。SSH scan 的 rule 只看 header（送往 22 的 SYN，同一來源 120 秒內每 5 條報 1 次）。Benign 30,860,691 條（含小寫 `benign` 1,956 條），有 alert 的 2,837 條（`gw_corp` 2,474），主要是 SSH scan OUTBOUND、IRC、BitTorrent。

不 usable 的 scenario 也能比對 alert：比對只看 5-tuple 與時間、不看 packet 數，所以 34-1、60-1（packet 數對不上）照樣對得到；52-1、49-1 的 label 只涵蓋 pcap 前 61%、90% 的時間，之後的 alert 沒有 flow 可對（unmatched：52-1 3 筆、49-1 135 筆），其他 21 個 scenario 都是 0。

### CIC-IDS2017（5 天，56,370,702 packets）

malicious（不含 Attempted）505,429 條，有 alert 的 1,947 條（0.39%）。

| 攻擊 | flows | 有 alert 的 flow | rule |
|---|---|---|---|
| Web Attack – XSS | 18 | 18 | WEB_SERVER（URI 的 script tag） |
| Web Attack – SQL Injection | 13 | 9 | WEB_SERVER（SQLi、SQL 錯誤回應） |
| Infiltration | 36 | 15 | MALWARE／EXPLOIT（cmd.exe、reverse shell） |
| FTP-Patator | 3,972 | 1,553（39.1%） | SCAN FTP brute force |
| Heartbleed | 11 | 1（threshold 120 秒 1 次） | EXPLOIT |
| SSH-Patator | 2,961 | 31 | SCAN SSH |
| Infiltration – Portscan | 71,767 | 111 | SCAN Nmap User-Agent |
| Portscan | 159,064 | 185 | SCAN（資料庫、VNC 等 port） |
| DoS Slowhttptest | 1,740 | 4 | WEB_SERVER DoS tool |
| DDoS（LOIC） | 95,144 | 20 | DOS AnonMafiaIC DDoS tool |
| DoS Hulk／GoldenEye／Slowloris | 158,468／7,567／3,859 | 0 | — |
| Web Attack – Brute Force | 73 | 0 | — |
| Botnet（Ares） | 736 | 0 | — |

Attempted 11,979 條全部沒有 alert。Benign 1,581,058 條，有 alert 的 10,293 條（`gw_corp` 7,420），Monday 以 `ET JA3 Hash – [Abuse.ch] Possible Adware` 為主。

### CIC-DDoS2019（兩天全天：03-11 61,407,883 packets；01-12 250,783,287 packets）

攻擊 flow 69,835,414 條（03-11 去重後 19,829,165、01-12 50,006,249），有 alert 的 1,578 條（275、1,303），`gw_corp` 746 條（274、472）；03-11 去重前是 311（`gw_corp` 310），差的 36 條都是 Syn 的重複列。01-12 的 39,472 筆 alert 全部對得到 flow：其中 38,510 筆是攻擊者 172.16.0.5 → 192.168.50.1 的 `GPL ICMP PING`（SID 2100366 等，不在 `gw_corp`），落在同一對 IP、已經標成攻擊的 Protocol 0 flow 裡，所以 01-12 有 alert 的 flow 比只收 TCP／UDP／ICMP 時多 811 條，全部是這些 ping。ping 從 14:36 持續到 20:59（UTC，每小時約 5,700 筆，flood 結束後還在），18:00 之後的落在 TFTP 的 Protocol 0 flow（`TFTP.csv` 的 Protocol 0 flow 到 21:15）；這 811 條合計 26,760,200 個 packet，幾乎都是 flood 的 IP fragment（整份 pcap 的 ICMP packet 只有 129,659 個）：524 條以 IP fragment 為主、ping 因為同一對 IP 被歸進同一條 flow；287 條只有 ping 的 packet（TFTP 144、DrDoS_NTP 119 等，共 11,416 個 packet）。SSH scan（SID 2001219，`threshold: type both, count 5, seconds 120`）是攻擊主機整天的背景連線：01-12 每小時 20–28 筆，全部是 172.16.0.5 → 192.168.50.1；03-11 是 → 192.168.50.4。資料庫 port 的 scan rule（SID 2010935／2010936／2010937／2010939，1433／1521／3306／5432，`flags:S; threshold: type limit, count 5, seconds 60`：每個 SYN 都報、同一來源每分鐘最多 5 筆）：03-11 共 219 筆，154 筆在 Syn 時段（14:29–14:37，SYN flood 亂打 port 打到），65 筆在其他時段（例如 12:48:06 同一個來源 port 63407 在約 6 ms 內打 3306、1433、5432）；01-12 共 181 筆，75 筆在 Syn 時段（17:30–17:34），106 筆在其他時段；攻擊主機為什麼在其他時段連資料庫 port 沒有查。這些都不是 flood 本身，只是時間落在攻擊時段、被標成那個攻擊。比對到攻擊所用 protocol 內容的只有三個（共 113 條）：MSSQL 反射的 `ET DOS MC-SQLR Response Inbound Possible DDoS Target`（03-11，7 條）、SNMP 的 `GPL SNMP public access udp`（01-12 DrDoS_SNMP，103 條）、NTP 反射的 `ET DOS Likely NTP DDoS In Progress MON_LIST Response to Non-Ephemeral Port IMPL 0x03`（01-12 DrDoS_NTP，3 條；同一來源 120 秒只報 1 次、只看送往 0–1023 port 的回應）。MC-SQLR 那條 rule 只比對從 udp/1434 送出的回應（threshold 同一目的地 60 秒 30 次），01-12 的 DrDoS_MSSQL 4,522,492 條只有 57 條是從 udp/1434 送出的，所以 01-12 沒有觸發。01-12 的 Syn（`full` 47 條、`gw_corp` 44 條）、UDP-lag（42、29 條）是 SCAN rule 和 ICMP ping；WebDDoS（439 條，在 `UDPLag.csv` 裡）2 條是 `ET INFO Go-http-client User-Agent`（不在 `gw_corp`）。Benign 109,424 條（03-11 去重後 52,561、01-12 56,863），有 alert 的 333 條（`gw_corp` 315；311 條是 SSH scan OUTBOUND）。舊結果（只收 TCP／UDP／ICMP）留在 `~/datasets/cicddos2019/align/old_tcpudp/`、`~/datasets/detection/match_cicddos2019/old_tcpudp/`。

### CICIoT2023（全部 309 個檔，587.3 GB）

label 只到 pcap 檔。每個檔都有實驗網路的背景流量（Benign 檔也觸發 `GPL ICMP PING`、`GPL MISC UPnP malformed advertisement`），所以以 Benign 檔為基準：只看 4 個 Benign 檔（7.0 GB）都沒出現過的 SID，再依 rule 的內容判斷和攻擊有沒有關係（每個檔：`summarize_ciciot2023.py` → `results/ciciot2023.tsv`；每種攻擊合計：`ciciot2023_by_attack.py` → `results/ciciot2023_by_attack.tsv`；逐一判斷寫在 `results/ciciot2023_judgement.tsv`）。多檔的 flood 類，其他檔多出的 SID 都是背景類（403 Forbidden、Go HTTP client User-Agent、.cc TLD、External IP Lookup、TLS Handshake Failure、STUN、Jabber 等），在 ICMP、UDP、TCP 等不相干的 flood 檔都出現；Mirai 的 GRE flood 多了 `GPL SNMP trap Format String`（2100227，`gw_corp`）、`ET TFTP Outbound TFTP ACK`（2008118），alert 落在 GRE 封裝、內層 IP 隨機的 packet 上（亂數內容碰巧對上打到 162、69 port 的 rule），仍判 △。判斷結果和只做 36 個檔時相同（36 個檔的版本留在 `~/datasets/detection/ciciot2023_judgement_36files.tsv`）。

| 類別 | 攻擊數 | ✓ | △ | ✗ |
|---|---|---|---|---|
| Web-based | 6 | 6 | 0 | 0 |
| Brute Force | 1 | 1 | 0 | 0 |
| Recon | 5 | 4 | 0 | 1（PingSweep） |
| DDoS | 12 | 0 | 2（HTTP_Flood、SlowLoris） | 10 |
| DoS | 4 | 0 | 1（HTTP_Flood） | 3 |
| Mirai | 3 | 0 | 3（greeth、greip、udpplain） | 0 |
| Spoofing | 2 | 0 | 0 | 2 |

判斷先只看 Benign 檔沒出現過的 rule，再看 alert 有沒有落在攻擊流量上：✓ = 攻擊流量上有 alert，而且 rule 內容對得上攻擊（都在 `gw_corp`）；△ = 攻擊流量上有 alert，但 rule 是 HUNTING（不在 `gw_corp`）或和攻擊無關；✗ = 攻擊流量上沒有 alert（只有背景）。33 種：✓ 11、△ 6、✗ 16。Benign 4 個檔 345,984 條 flow（Suricata 算的），有 alert 的 5,157 條（`gw_corp` 3,676）。

### 四個 dataset 統一的標準（2026-11-01）

`related_flows.py` → `results/unified_by_label.tsv`：每個 label 一列，flows、有 alert 的 flow（`full`、`gw_corp`）、rule 對得上的 flow、判斷。

- **rule 對得上的 flow**：flow 上至少有一筆 alert 的 SID 在 `results/related_rules.tsv` 該 label 的清單裡（`ET SCAN*` = msg 以 ET SCAN 開頭）。清單依 rule 名稱與內容判斷，每條有理由欄。原則是 rule 要描述攻擊本身：只數 SYN 的 SSH scan（2003068、2001219）不算對得上暴力破解或連線嘗試（CIC-IDS2017 SSH-Patator、IoT-23 Attack 是 △），認的是協定使用的 rule 不算（IRC 指令不算 C&C，IoT-23 C&C 只算 Mirai checkin、Muhstik，1,238 條；SNMP `public` 不算 DrDoS_SNMP，所以是 △），`ET SCAN*` 扣掉 IMAP／POP3「Possible Brute Force」四條（描述的不是 scan）。回應裡出現 /etc/passwd 的 rule 算 CommandInjection、Backdoor_Malware、Uploading_Attack 三種（代表透過 web 漏洞執行命令成功）。
- **判斷**：✓ = rule 對得上的 flow > 0；△ = 有 alert 但都對不上；✗ = 沒有 alert。四個 dataset 同一個定義。
- IoT-23、CIC-IDS2017、CIC-DDoS2019 的比對結果只有「每個 label 各 SID 落在幾條 flow」，所以逐個 scenario／天算（清單外的 SID 都沒出現、清單內只有一個 SID、或清單內的 SID 剛好是出現的 `gw_corp` SID 時是精確值）；這次全部是精確值，不用重跑比對。CICIoT2023 用 eve.json 的 `flow_id`，照官方 label 整個檔的 flow 都算該檔的攻擊（含背景流量）。

| Dataset | malicious flow | 有 alert | rule 對得上 | ✓／△／✗ | Benign 有 alert |
|---|---|---|---|---|---|
| IoT-23 | 294,449,255 | 14,762,773（5.01%） | 14,758,406（5.01%） | 5／2／8 | 2,837／30,860,691（0.009%） |
| CIC-IDS2017 | 505,429 | 1,947（0.39%） | 1,900（0.38%） | 9／1／5 | 10,293／1,581,058（0.65%） |
| CIC-DDoS2019 | 69,835,414 | 1,578（0.002%） | 10（0.00001%） | 2／17／0 | 333／109,424（0.30%） |
| CICIoT2023 | 931,523,573 | 38,600（0.004%） | 1,967（0.0002%） | 11／22／0 | 5,157／345,984（1.49%） |

CICIoT2023 用上面 Benign 基準判斷時的 ✗ 16 種，在統一定義下都是 △：照官方 label，背景的 alert（UPnP、ping）也算落在攻擊流量上。✓ 的 11 種兩種判法相同。

## 待決與限制

- CIC-DDoS2019 加 `--cic` 之後還沒被涵蓋的 packet（03-11 35,771、01-12 35,234）是哪些沒有逐一查。
- CICIoT2023 判斷 ✓／△／✗ 是依 rule 名稱與內容的人工判斷。
- Suricata flow emergency mode：Debian 預設 `flow.memcap` 128 MiB，flood 時 flow table 會滿（run.log 的 "Flow emergency mode entered"：IoT-23 43-1 98 次、CIC-DDoS2019 03-11 10 次、01-12 2 次、CICIoT2023 DDoS-PSHACK_Flood 27、RSTFINFlood 26、TCP_Flood 24 次）；CICIoT2023 全部 309 個檔有 56 個進入過（DDoS-TCP_Flood 16、PSHACK_Flood 15、RSTFINFlood 14、SYN_Flood 11 個檔，4 GiB 重跑只做了最初那 3 個）。`memcap_check.sh` 把 `flow.memcap` 調到 4 GiB 重跑這幾個 pcap（03-11 另外跑），都沒有再進入 emergency mode：03-11 的 657 筆 alert 有 2 筆計數型 rule（SID 2001972）觸發在不同 packet，每個 label 有 alert 的 flow 數不變；PSHACK、TCP_Flood 的 alert 完全相同；RSTFINFlood、43-1 的 alert 是同樣的五元組與 SID，只差觸發時間；01-12 的 DrDoS_SNMP 有 alert 的 flow 從 210 變 207（`gw_corp` 118 → 115；SID 2101411 的 alert 12 筆換成 7 筆，總數 214 → 209），其他 label 不變，原因沒有查。表上的數字都用預設設定（和 Pi 上一樣）。
- CICIoT2023 的 HOME_NET、EXTERNAL_NET 都是 `any`，有 3 條 rule 的位址取反後變成空集合、載入失敗（52,795／52,798）：SID 2011802 `ET DNS DNS Lookup for localhost.DOMAIN.TLD`、2000328 `ET INFO Outbound Multiple Non-SMTP Server Emails`、2002087 `ET INFO Inbound Frequent Emails - Possible Spambot Inbound`。其他 dataset 52,798 條全部載入。
- Pi 速度（2026-10-31）：CIC 三個 dataset 依流量特徵挑 27 個切片、IoT-23 的 14 個用 Suricata 8.0.7 與同一份 2026-10-30 rule 重量，見 `../ids_throughput/README.md` 實驗 5（`full` 最慢：CIC-IDS2017 DoS Hulk 6.2 kpps、CICIoT2023 DDoS-HTTP_Flood 8.5、CIC-DDoS2019 16.0、IoT-23 14.9）。
- HOME_NET 的影響只在 CIC-IDS2017 Wednesday 比較過（第一次用預設 HOME_NET 的輸出沒有保留）。
- 工作站上轉好的 CIC-IDS2017 pcap（`~/datasets/cicids2017/pcap/`，52 GB）、CIC-DDoS2019 03-11 串好的 pcap（29 GB）、01-12 的 zip（20.9 GB）還留著，方便重跑；01-12 舊的抽樣 pcap `0112s.pcap`（20.6 GB）已刪除（2026-10-31，`run_cicddos2019_0112.sh` 可重產）。原始檔都在 NAS。IoT-23 解壓後的資料已刪除（原始壓縮檔在 NAS，md5 2026-10-31 核對過）。
