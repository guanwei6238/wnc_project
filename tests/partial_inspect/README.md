# tests/partial_inspect — 只給 Suricata 一部分封包時，還偵測得到嗎？

問題（2026-11-02）：fast path 想對已信任的 flow 做「抽樣」或「部分檢查」（只送一部分封包給 Suricata）。Suricata 是有狀態的引擎，給它不完整的 stream 時會怎樣？哪些送法可行、哪些不行？
文獻與原始碼的推導在 `research/literature/fastpath-methods/C-partial-inspection.md`（§2 C7 的 E1–E9）；這裡是實測。

- 實驗 3：合成的 HTTP／MQTT 連線，切出各種子集，Suricata 8.0.7 offline 跑 ids 與 ips（`--simulate-ips`）兩種語意。
- 實驗 4：CIC-IDS2017 的真實攻擊流量，比較各種抽樣／部分檢查策略的「送出比例」和「攻擊 flow 的 alert 保留率」。

## 檔案

| 檔案 | 用途 |
|---|---|
| `tcpgen.py` | 不用 scapy 產生 TCP 封包（checksum 正確），每個封包帶標記（方向、交易、訊息、段），可以只推進序號不產生封包（模擬被跳過的資料） |
| `cases.py` | 實驗 3 的所有 case（pcap + `manifest.tsv` + `rules.txt`） |
| `run_cases.sh` | 每個 case 用 Suricata 8.0.7（image `wnc-lab-gw`）跑 ids、ips 兩次；`RES`、`EXTRA_SET` 換設定 |
| `report.py` | 彙整成表：alert（sid×次數@第一個 pcap_cnt）、app_proto、關鍵 stats |
| `results/exp3_*.md` | 實驗 3 的結果表（`res` 預設、`res_noinv` 加 `stream.drop-invalid=no`、`res_async` 加 `stream.async-oneside=true`、`res_inline` 加 `stream.inline=yes`） |
| `policy_filter.py` | 實驗 4：讀一次 pcap 同時寫出所有策略的子集 |
| `run_policies.sh`、`summarize_policies.py` | 實驗 4：切片 → 子集 → Suricata full ET → alert 對 label → 彙整 |
| `live_docker.sh`、`results/exp3b_live.kvl` | 實驗 3b：Docker testbed 上真的 TCP 連線，`wnc-gw trust add/del` 之後再送攻擊 request |
| `extract_attacks.py`、`late_mix.py`、`run_late.sh`、`eval_late.py` | 實驗 5：真實攻擊 request 插進合成長連線的後段 |

資料在 repo 外：`~/datasets/partial_inspect/{cases,policies,late}/`。實驗 4 過濾後的 pcap（約 33 GB）2026-11-03 已刪除，只留 `policies/<切片>/run/`（eve、match）和 `kept.tsv`；要重跑時刪掉該切片的 `kept.tsv` 再跑 `run_policies.sh`，會從 `~/datasets/cicids2017/pcap/` 重新過濾。

## 實驗 3：合成連線

### 設定
- Suricata 8.0.7，設定照 wnc-gw 強制的（`security_gateway/src/ids/spawned.rs`）：`stream.midstream=true`、`midstream-policy=ignore`、exception policy 全部 ignore、`-k none`；另外 `--runmode single`、`flow-timeouts.tcp.established=30`（emergency 10），讓「閒置超過逾時」可以在 pcap 時間裡測。
- ids＝一般 offline（等同 NFLOG 送複本：Suricata 看不到的封包照樣轉送）；ips＝`--simulate-ips`（inline 語意，Suricata 自己會丟 invalid 的封包）。
- 規則：R1 `http.uri` 含 `/evil`（`flow:established,to_server`）、R2 同上但沒有 established、R3 stream content `EVIL`（established）、R4 packet content `EVIL`（`depth`）、R5 `http.request_body` `EVIL`、R6 `mqtt.publish.message` `EVIL`、R7 `stream-event:est_invalid_ack`、R8 content `EVIL` 沒有 established、R9 `http.response_body` `BADRESP`、R10 `stream-event:reassembly_seq_gap`。
- 主連線 `h_full`：HTTP/1.1 keep-alive 20 個交易，response 6 KB；tx15 `GET /evil?q=EVIL`、tx16 POST body offset 200 有 `EVIL`、tx17 response 有 `BADRESP`、tx18 `GET /evil2`。沒有 window scale 時視窗是 65,535。
- 表中 `@-` 表示 alert 不是在某個封包當下，而是在 flow 結束（逾時或 pcap 結束）時才出現；實際部署會延遲到 flow 逾時（預設 established 600 秒）。

### 結果（完整表在 `results/exp3_res.md`）

| 送法 | ids（NFLOG 複本） | ips（NFQ inline） | 結論 |
|---|---|---|---|
| 完整連線 | 全部 alert | 全部 alert，0 丟 | 基準 |
| 從 request 開頭接手（E1 i） | 全部 alert | 第一個交易的 R1（established）漏掉，之後的交易都抓到 | 可行；ips 的第一個交易有 established 問題 |
| 從 server 的 ACK 或 response 開頭接手（E1 ii、iii） | 全部 alert | 全部 alert（R1 兩次都抓到） | **ips 要從 server→client 的封包開始接手**，第一個 request 才算 established |
| 從 response 中間接手（E1 iv） | R3/R8（stream content）漏掉，R9 延到 flow 結束 | 同左 | 起點不在訊息邊界會掉規則 |
| 從 POST body 中間接手（E1 v） | **全部沒有**（app_proto failed），之後的 `GET /evil2` 也漏 | 同左 | 確認原始碼推導：中途接手時 to_server 協定偵測失敗，整條 flow 的 app-layer 永久關閉 |
| 只送一個封包（E2，預篩命中） | 會 alert，但**延到 flow 結束** | 只有沒有 established 的 R2、R8 | ET Open 的 TCP 規則 97.2% 帶 `flow:established`，**單一封包在 ips 幾乎沒用、在 ids 要等逾時** |
| 同一個 session 內，跳過一段之後只送一個封包或一個交易（E2b） | 只剩 R3/R4/R8，R1 漏 | 同左，**而且 Suricata 丟了 2 個封包** | 跳過的資料超過視窗 → ACK 無效（R7）→ 封包不進 stream |
| 握手完整，之後只送 client→server（E3） | 全部 alert 但**延到 flow 結束**（IDS 要等對方 ACK） | 全部 alert，0 丟 | ips 單向可行；ids 要 `stream.inline=yes` 才即時（`res_inline`） |
| 沒有握手、只送 client→server（E3 mid） | R1/R5 漏（HTTP 只解析了 1 個交易），R7×46 | 同左，丟 1 個 | 推導的 INVALID_ACK 成立；ids 開 `async-oneside` 可以救回（`res_async` 全部 alert） |
| 稽核窗：tx1–12 完整、跳過、tx150–152 再看，閒置 10 秒（E5b，同一個 session） | R1 漏，R7 | R1 漏，**丟 2 個** | 跳過 > 視窗時，同 session 的稽核窗看不到 app-layer |
| 同上，閒置 60 秒（> 逾時，變成新的 session） | R1 抓到 | R1 漏（新 session 的第一個交易）；若從前一個 response 中間接手（E5c）則抓到 | 新 session 可行，但 ips 要提早一點接手 |
| 同 E5b，跳過期間每 10 個純 ACK 給 1 個（E5d ack10） | **R1 抓到** | **R1 抓到，0 丟** | 讓 Suricata 的 ACK／視窗跟上就好；每 50 個給 1 個不夠（視窗 64 KB） |
| 同 E5b，握手帶 window scale 7（視窗約 8 MiB），一個 ACK 都不給（E5w） | 跳 2 MB：R1 抓到；跳 20 MB：漏 | 同左（20 MB 丟 2 個） | **條件是「跳過的量 < 接收端視窗」** |
| DPA：每個訊息只送前 N bytes（response 6 KB） | 全部 alert（含 R5、R9），即時 | 全部 alert，0 丟 | 間隔小於視窗時，有沒有 ACK 都可以 |
| DPA，response 2 MB，不給 ACK（dpa_big_noacks） | 只剩 R3/R4/R8 | 同左，丟 2 個 | 跳過 > 視窗就壞 |
| DPA，response 2 MB，每 10 個純 ACK 給 1 個（dpa_big_ack10） | R1、R5 抓到；R9（response body）漏 | 同左，0 丟 | **只送 3.5% 的封包（584／16,609），request 方向的規則全部保留**；response body 規則在 body 被截斷時不觸發 |
| MQTT 從第 50 個 PUBLISH 接手 | R6 抓到 | R6 抓到 | port 1883 不需要看到 CONNECT |
| MQTT 中間跳過（同 session） | R6 漏（mqtt_tx 停在 1） | 同左 | MQTT parser 不接受 gap，跳過一次 app-layer 就關了；> 逾時變新 session 才恢復 |

其他設定：
- `stream.drop-invalid=no`（`res_noinv`）：ips 不再丟封包，但偵測結果不變（R1 仍漏）。可以避免傷到流量，救不了偵測。
- `stream.async-oneside=true`（`res_async`）：只對 midstream 接手的 session 有效；沒有握手的單向流量全部救回。
- `stream.inline=yes` 用在 ids（`res_inline`）：握手完整的單向流量變即時；但單一封包、沒有握手的單向流量和 ips 一樣差。

### 對設計的意涵
1. **送給 Suricata 的子集要滿足三個條件**：
   - 從訊息邊界開始。ips 最好從 server→client 的封包開始接手。
   - 兩個方向的 ACK 要跟上：跳過的量不能超過接收端的視窗；超過時要每隔一段放一個純 ACK。合成流量裡，64 KB 視窗配每 10 個放 1 個就夠。
   - MQTT 這類不接受 gap 的協定，不能在同一個 session 裡跳過。
2. **「預篩命中只送那一個封包」不可行**：ips 下 established 規則不觸發；ids 下要等 flow 逾時才 alert。
3. **DPA 式（每個訊息只送開頭）加稀疏的 ACK 同步是可行的部分檢查**：大檔傳輸只送約 3.5% 的封包，request 方向的規則全部保留；代價是 response body 規則（如惡意檔案下載）在 body 被截斷時不觸發。
4. ips 模式下，Suricata 遇到跳號會**自己丟封包**（`stream_error`）。實作稽核窗前，要嘛同步 ACK，要嘛設 `stream.drop-invalid=no`。

限制：合成流量；沒有測 retransmission、亂序、TLS；ips 是 `--simulate-ips`，不是真的 NFQ（丟包之後端點重送的行為沒有測）。

## 實驗 3b：真的 TCP 連線（Docker testbed，wnc-gw run）

`live_docker.sh`：cli 用一條 keep-alive 連線依序 `GET /small` → **`wnc-gw trust add`** → `GET /big`（1 MB 或 64 MB，信任中）→ **`wnc-gw trust del`** → `GET /evil?q=EVIL` → `GET /small`。Linux 的 TCP（window scale、autotuning、veth 的 GSO/GRO）都是真的；ips 是真的 NFQ。結果 `results/exp3b_live.kvl`（每個設定 2 輪，兩輪相同）。

| 設定 | `/evil` 的 alert | Suricata 丟封包 | 連線 |
|---|---|---|---|
| 不信任（對照） | R1、R2、R3 | 0 | 正常 |
| 信任中傳 1 MB 或 64 MB，傳完馬上取消信任（ids 與 ips） | 只有 R3（raw stream）＋ R7 invalid ack 6–7 次；**R1、R2 漏**；HTTP 停在第 1 個交易 | ips 丟 4 個（`stream_error`），ids 0 | 照常完成（丟的是 ACK 或重送補回） |
| 同上，信任中的純 ACK 每 10 個送 1 個（`ACKSYNC=1`，nft `numgen`） | 同上，沒有改善 | 同上 | 正常 |
| Suricata 的 established 逾時設 10 秒，信任後連線閒置 20 秒才取消信任（`TIMEOUT=10 HOLD=20`） | ids：**R1、R2、R3 都抓到**；ips：R2、R3 抓到，R1 漏（新 session 的第一個交易） | 0 | 正常；`tcp.midstream_pickups`=2 |
| 同上但不閒置（`HOLD=0`，Suricata 還記得這條 flow） | 只有 R3 | ips 丟 4 個 | 正常 |

解讀：
- 合成實驗的「每 10 個 ACK 給 1 個」在真實 TCP 不夠：veth 的 GSO 讓每個 ACK 確認約 64 KB，每 10 個才給 1 個時，每次跳約 640 KB，遠超過 Suricata 上次看到的視窗（連線剛開始時很小，之後的 autotuning 它看不到）。ACK 同步要「每個 ACK 都給」或「每次跳的量小於 Suricata 記得的視窗」，實務上不可靠。
- **可靠的做法是讓稽核窗變成 Suricata 的新 session**：信任期間 Suricata 什麼都看不到，等它的 established 逾時（預設 600 秒，可調）把 flow 忘掉，再取消信任。ids 模式完整偵測；ips 模式第一個交易的 established 規則會漏（實驗 3 的 E1：從 server→client 的封包開始接手才能避免）。
- 代價：Suricata 的逾時是全域的。調短會讓所有閒置連線在下一次有流量時變成 midstream 接手，ips 模式下那一刻的第一個交易同樣會漏 established 規則。

## 實驗 4：CIC-IDS2017 上比較策略（ids 語意）

### 做法
- 三個時間切片（攻擊時段前後各放寬 60 秒）：`tue_ftp`（FTP-Patator）、`tue_ssh`（SSH-Patator）、`thu_web`（Web Attack：Brute Force、XSS、SQL Injection）。
- `policy_filter.py` 讀一次切片，同時寫出各策略的子集（策略說明在檔頭）。控制封包（SYN／FIN／RST）和非 TCP/UDP 一律留，對應 L2。
- Suricata 8.0.7、ET Open 2026-10-30 full（52,798 條），設定同 `tests/detection`（HOME_NET 192.168.10.0/24），另加 midstream=true；alert 對 label 用 `tests/detection/match_iot23.py`。
- **保留率 = 這個策略下有 alert 的攻擊 flow ÷ full（同一個切片）下有 alert 的攻擊 flow**；括號是 Wilson 95% 區間。隨機策略 3 個種子。
- 過濾後的 pcap 交給 offline Suricata，等同 ids 模式（Suricata 只拿到複本、轉送不受影響）；沒有模擬過載丟包、GRO。

### 結果（`results/exp4_summary.md`）

| 策略 | 送出封包 ftp／ssh／web | FTP-Patator（1,527 條） | SSH-Patator（31） | XSS（18） | SQLi（9） |
|---|---|---|---|---|---|
| first20（只看前 20 個封包） | 9.6／47.1／18.2% | 94.0% | 100% | 94.4% | 100% |
| cut4k（每方向前 4 KB） | 10.8／57.2／20.5% | 100% | 100% | 100% | 100% |
| dpa_ack10 | 12.8／47.6／20.7% | 100%（1,566 條，比 full 多 39） | 100% | 100% | 100% |
| hpa_ack10（HTTP 訊息邊界） | 12.4／46.0／20.1% | 100%（1,566） | 100% | 100% | 100% |
| dpa_rn（隨機 N，3 種子平均） | 13.5／51.1／22.2% | 100%（1,566） | 100% | 100% | 100% |
| dpa_win（DPA + 10% 稽核窗，3 種子平均） | 20.2／53.0／29.9% | 100% | 100% | 100% | 100% |
| obs20_win（前 20 + 10% 稽核窗，3 種子平均） | 20.9／54.8／30.8% | 97.2% | 100% | 98.1% | 100% |
| pkt（隨機 10% 封包） | 11.7／18.3／13.1% | **5.9%** | 100% | **9.3%** | **7.4%** |
| obs20_flow（前 20 + 10% flow 全看） | 12.0／52.5／20.5% | 97.9% | 100% | 94.4% | 100% |
| flow（隨機 10% flow，不含觀察期） | 5.0／18.4／7.2% | 14.6% | 100% | 9.3% | 18.5% |

解讀：
- 這三種攻擊都出現在**連線開頭**（暴力破解每次都開新連線、web 攻擊的 request 在短連線前段），所以截斷類（first20、cut4k、DPA）幾乎全保留，只送 10–21% 的封包（bytes 只有 2–6%）。和文獻一致（Kučera、HPA/DPA）。
- **隨機抽封包對 Suricata 幾乎沒用**（6–9%）：送進去的封包沒有前後文。XNET 報告的 1.2% 是同一個現象。
- SSH-Patator 在所有策略都是 100%：抓到它的是看 SYN 次數的 scan 規則，控制封包一律留。
- DPA 比 full 多 39 條 FTP-Patator flow 有 alert：送進去的是不完整的 stream，部分規則（threshold、stream 事件）觸發的方式不同，不全是「多抓到」。
- 實驗 5 加的三個策略（HPA、隨機 N、DPA + 稽核窗）在真實流量上也是 100%；HPA 的 HTTP 切段在真實流量（有重送、亂序）上沒有出問題，送出比例和 DPA 差不多。
- **限制**：這些資料集裡沒有「攻擊藏在長連線後段」的例子，所以截斷類看起來完美。實驗 5 專門補這一塊。

## 實驗 5：攻擊在長連線後段（真實攻擊 payload + 合成連線）

### 做法
- `extract_attacks.py`：從 `thu_web` 抽出真實的攻擊 request（40 個 XSS、3 個 SQLi，都是 DVWA 的 `GET`）。
- `late_mix.py`：330 條 HTTP keep-alive 連線（window scale 7、每條 12–40 個交易、response 大小 lognormal 中位數 30 KB、交易間平均閒置 2 秒、中位數長度約 52 秒），類型：
  - early（30）：攻擊在第 1 個交易
  - late（120）：攻擊在後半段的某個交易
  - pipe（60）：後半段先送 4 KB body 的 POST、緊接著送攻擊 request（不等 response），**專門打「方向改變後前 N bytes」**
  - benign（120）
- 同樣的策略（多三個抗規避的策略，`EXTRA=1`）→ Suricata full ET（HOME_NET 10.0.2.0/24）→ `eval_late.py`：一條連線只要有 web 攻擊規則（2009714、2010963、2017808）的 alert 就算抓到。

### 結果（`results/exp5_late.md`，隨機策略列 3 個種子的範圍）

| 策略 | 送出封包 | early | late | pipe | benign 誤報 |
|---|---|---|---|---|---|
| full | 100% | 100% | 100% | 100% | 0 |
| first20 | 1.3% | 100% | **0%** | **0%** | 0 |
| cut4k | 3.0% | 100% | 88% | 8% | 0 |
| dpa_ack10 | 8.1% | 100% | **100%** | **0%** | 0 |
| obs20_win（10% 稽核窗） | 13–15% | 100% | 7–11% | 7–17% | 0 |
| obs20_flow（10% flow） | 8–12% | 100% | 5–10% | 8–15% | 0 |
| pkt（10% 封包） | 10% | 3–20% | 0% | 0% | 0 |
| **hpa_ack10**（HTTP 訊息邊界，每個訊息前 2000 bytes） | 8.2% | 100% | **100%** | **100%** | 0 |
| dpa_rn（DPA，每條 flow 的 N 隨機 1–16 KB） | 14% | 100% | 100% | 83–90% | 0 |
| dpa_win（DPA + 10% 稽核窗） | 17–19% | 100% | 100% | 7–17% | 0 |

解讀：
1. **信任後完全不看（first20）漏掉所有後段攻擊**；這就是 D 類盲點，現在有數字了。
2. **隨機稽核（稽核窗、flow 抽樣）抓到的比例 ≈ 抽樣比例 a**（10% 左右），單發攻擊的密度上限實測成立；而且它不受規避影響（pipe 一樣約 10%）。
3. **確定性的「每段開頭」檢查**很便宜（5–8% 的封包）就抓到全部後段攻擊，但**固定 N 會被「先塞資料」繞過**（DPA 對 pipe 0%）。cut4k 的 88% 只是因為 request 很小、4 KB 涵蓋了很多個 request，同樣被塞資料繞過（8%）。
4. **抗規避**：
   - 依應用層訊息邊界切（HPA）最好：成本和 DPA 差不多，pipe 也 100%。但它要解析 HTTP（Content-Length），放進 kernel 比 DPA 難。
   - 隨機化 N（dpa_rn）是不解析協定的折衷：攻擊者得塞到超過 N 的上限才能確定繞過，實測 83–90%。
   - 確定性加隨機窗（dpa_win）對規避的幫助只有 a。
5. 限制：合成連線（時間、大小分布是假設的）；只有 URI 型的 web 攻擊（攻擊在 request line，最前面）；沒有測「把攻擊放在單一訊息的 body 深處」這種規避（HPA 也擋不住，要靠隨機 N 或 body 規則的深度）；ids 語意。
