# tests/eve_output — 3d 讀 EVE：寫檔案還是 unix_stream

問題（2026-10-29 開發者：「先測試再定」）：3d 的 agent 要讀 Suricata 的 EVE。用 unix_stream 時，讀取端跟不上會讓 Suricata 卡住，還是丟事件？兩種方式各花 Suricata 多少 CPU？

## 檔案

| 檔案 | 用途 |
|---|---|
| `reader.py` | unix_stream 的讀取端（listen；fast／stall:N 秒不讀／slow:每秒 R 行），結束時寫行數、bytes |
| `eve_sock_docker.sh` | Docker testbed（Suricata 8.0.7）：`offline <pcap>`（`suricata -r`）與 `live <ids|ips>`（`wnc-gw run`） |
| `eve_cost_pi.sh` | Pi：offline 跑 S_m17，none／regular／unix 各 5 次，量 Suricata 的 user+sys 與整台機器的忙碌時間 |
| `results/eve_cost_pi.kvl` | Pi 的結果（每次一行） |

## 結果 1：行為（Docker，2026-11-03）

**offline（`suricata -r S_m17.pcap`，沒有規則，只輸出 flow 事件，99,729 個）**

| 輸出 | 讀取端 | Suricata 執行時間 | 讀到的事件 |
|---|---|---|---|
| regular（檔案） | — | 0.7 s | 99,729 |
| unix_stream | fast | 1.1 s | 99,729 |
| unix_stream | 停 10 秒才讀 | 11.0 s | 99,729 |
| unix_stream | 每秒 2,000 行 | 50.9 s | 99,729 |

offline 模式的 socket 是 blocking：讀取端停多久，Suricata 就停多久，不丟事件。

**live（`wnc-gw run`、routed、`when_unavailable = "drop"`，cli 10 秒送 5,000 個 UDP，每個一條新連線、各觸發一個 alert；同時 ping 每 10 ms；讀取端前 15 秒不讀）**

| protection | ping | 讀到的事件 | Suricata 結束時的訊息 |
|---|---|---|---|
| ids | 1000/1000，max 0.19 ms | 4,750 | `4833 events were dropped due to slow or disconnected socket` |
| ips | 1000/1000，max 1.35 ms | 4,750 | 同上，4,833 |

- Suricata 啟動時印 `Setting logging socket of non-blocking in live mode`：**live 模式下讀取端跟不上時丟事件，不會卡住封包**（ips 的 ping 照常、延遲沒有變長）。
- 丟掉的數量只在 Suricata 結束時記一行 WARN（wnc-gw 會把它轉成自己的 log）；stats.log 裡沒找到對應的計數。所以執行中看不出丟了多少。
- 讀到的 4,750 加上丟掉的 4,833 是 9,583 個事件（5,000 個 alert，其餘是 flow）；讀取端沒記事件種類，所以分不出丟的是哪一種。

## 結果 2：CPU（Pi，2026-11-03）

Pi 4 鎖 1000 MHz、Suricata 8.0.7，offline `-r S_m17.pcap`（沒有規則，99,729 個 flow 事件），Suricata 綁 CPU 2、讀取端（reader.py fast）綁 CPU 3，每種 5 次、順序每輪打亂（`results/eve_cost_pi.kvl`）。

| 輸出 | Suricata CPU（user+sys，s） | 整台機器忙碌（s） | 比 none 多的 Suricata CPU ÷ 事件數 |
|---|---|---|---|
| none（不開 eve-log） | 2.88（2.84–2.91） | 2.88 | — |
| regular（檔案，SD 卡） | 13.21（13.17–13.22） | 13.23 | 103 µs |
| unix_stream | 12.33（12.26–12.39） | 18.27（17.88–18.74） | 95 µs |

- unix_stream 讓 Suricata 少花約 7%；整台機器多出來的約 5.9 s 是 Python 的讀取端（每行約 59 µs，換成 Rust 會便宜很多，沒量）。
- 補量（各 2 次，分開記 user 和 sys）：regular 寫 SD 卡 user 11.26、sys 1.89–2.00 s；寫 /dev/shm 時 user 10.39–10.80、sys 1.78–1.95 s。**成本主要在 user（Suricata 產生事件），寫到哪裡只差約 5%。**
- 筆電（Docker、同一版 Suricata、同一個 pcap、綁 1 顆 CPU，2 次）：none 0.32 s、regular 1.02–1.07 s，每個事件約 7 µs。Pi 處理同一個 pcap 本來就慢約 9 倍（none 2.88 對 0.32 s），所以 Pi 上每個 flow 事件約 100 µs 是這個量級。
- 限制：offline 模式的 flow 在逾時或讀完 pcap 時才輸出，**live 模式下每個事件花多少沒有量**。之前的 live 實驗（tests/ids_inline、tests/cpu_alloc）用的是系統 yaml，eve-log 和 flow 都是開的（輸出到 tmpfs），flow 事件由 worker 以外的執行緒在逾時後輸出；那些實驗的整機 µs／封包裡有沒有包含這部分，從現有資料判斷不了。

## 對 3d 的意涵（CPU）

- [推算] 如果 live 模式下每個 flow 事件也要約 100 µs，連線多的流量（S_m17 每 2 個封包就是一條新連線）光是輸出 flow 事件，每個封包就要多約 50 µs，和檢查本身一樣貴。要先量 live 模式下 flow 事件的成本，再決定 3d 要用 EVE flow 還是用 conntrack 計數（`nf_conntrack_acct`，每個封包 ≤ 1.3 µs，見 `tests/cpu_alloc` 實驗 3；整表 dump 每筆約 7 µs，見下面）。
- conntrack 整表 dump（`tests/ctnetlink/bench`，6 萬筆，Pi 1000 MHz，2 輪）：acct=0 每筆 7.10 µs、acct=1 每筆 7.25 µs（+2%）；只取有信任 mark 的 entry（kernel 端過濾）時每掃一筆約 0.63 µs。10/25 用另一個量測程式、UDP entry 量到約 3.2 µs／筆，兩者的差異沒有查。

## 對 3d 的意涵（行為）

- unix_stream 不會拖慢封包處理，但讀取端（wnc-gw）慢的時候事件會默默不見，而且執行中沒有計數可以監控；alert 事件不見，就等於那條連線的告警沒有傳到 agent，「有 alert 的連線不信任」會失效。
- 檔案不會丟也不會卡，但要處理寫入 SD 卡、檔案輪替、讀取端的位置。
- 如果用 unix_stream，wnc-gw 讀 socket 的執行緒要獨立、不能被其他工作卡住，並且要有辦法知道丟了（例如定期用 unix socket 查，或在 Suricata 結束時讀那行 WARN）；這部分還沒查。
