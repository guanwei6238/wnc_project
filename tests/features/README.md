# tests/features — 使用者特徵程式（`[[features]]`）的黑箱測試

`security_gateway/DECISIONS.md` §23 的驗證。單元測試在 `security_gateway/src/features/*/tests.rs`。

## 檔案

| 檔案 | 內容 |
|---|---|
| `prog/` | 測試用的特徵程式（aya-ebpf，獨立 crate）：`flows_tc`（TC）、`flows_xdp`（XDP）都把 IPv4 TCP／UDP 的封包記進四個 map：BTF 宣告的 hash `FLOWS`、BTF 的 per-CPU hash `PFLOWS`、BTF 的 ringbuf `EVENTS`（每個封包一筆：來源位址、長度）、舊式 `#[map]` 的 hash `LEGACY`。key 是五元組加 3 bytes 的 `pad`，value 是封包數、bytes、長度平方和、第一個和最後一個封包的時間、4 格的長度直方圖 |
| `flows.json`、`pflows.json`、`legacy.json`、`events.json` | 對應四個 map 的定義檔；`flows`、`pflows` 另外有 7 個 `derived`（rate、mean、std、sub、scale、enum、percentile） |
| `swapped.json` | `flows.json` 把 `packets` 和 `bytes` 對調：長度一樣，只有 BTF 比對抓得到 |
| `doctor_docker.sh` | 編 `prog/`、複製到 testbed 的 wnc-gw 容器、寫五個 `[[features]]`、跑 doctor |
| `run_docker.sh` | 四個 feature（tc-egress、tc-ingress per-CPU、ringbuf、xdp）跑 `wnc-gw run`，送 20 個不信任、20 個信任的 UDP，讀 `/var/log/wnc-gw/features/*.jsonl`；`BACKEND=ctmark` 用 ctmark |
| `test_docker.sh` | 產生 20 個 UDP＋5 個 TCP 的 pcap，對四個 feature 跑 `wnc-gw features test` |
| `bench/` | 讀 map 每個環節每筆的成本（獨立 crate，見下面「讀取的 bench」） |
| `features_pi.sh` | Pi（bridge，veth：`env.sh up`＋`protection_pi.sh net up`）上的 doctor、run、試跑；`XDP_MODE=generic`、`BACKEND=ctmark` |

`prog/` 的編法和 `security_gateway/build.rs` 相同（`nightly-2026-11-13`、`bpfel-unknown-none`、`-Z build-std=core`、bpf-linker `--btf`）。

## doctor 的結果（2026-11-18，Docker routed testbed）

| feature | map | hook | doctor |
|---|---|---|---|
| flows | `FLOWS`（hash，BTF） | tc-egress | note G008：key 的 `pad8`、`pad16` 沒列在定義檔（在 padding 的位置，不讀） |
| pflows | `PFLOWS`（percpu_hash，BTF） | tc-ingress | note G008（同上） |
| legacy | `LEGACY`（hash，舊式） | tc-egress | warning G007：沒有 BTF，只比長度 |
| events | `EVENTS`（ringbuf，BTF 宣告了記錄型別） | tc-egress | 沒有問題（記錄 8 bytes，載入前就比） |
| swapped | `FLOWS` | xdp（native；veth 有 native XDP） | error G006：`bytes is at offset 8 in the struct, 0 in the definition; packets is at offset 0 …` |

## run 的結果（2026-11-19，`run_docker.sh`）

| feature | hook | backend tc | backend ctmark |
|---|---|---|---|
| egress（FLOWS） | tc-egress | packets 40、bytes 13,680、len_sumsq 4,678,560、hist [0,0,40,0]、len_mean 342、len_std 0 | 40 |
| ingress（PFLOWS，per-CPU） | tc-ingress | **20**（信任之後的在核心程式就被 redirect） | 40 |
| xdp（FLOWS） | xdp native（veth） | 40 | 40 |
| events（EVENTS ringbuf） | tc-egress | 40 筆，len 342 | 40 筆 |

每秒讀一次，`pps`：第一次讀 null（沒有前一次）、之後 0、多了 20 個封包的那一次 19.98。`proto_name` = udp、`len_p50` = 1024（桶的上界）、`span_s` ≈ 3.4 秒。

## 試跑的結果（2026-11-19，`test_docker.sh`）

20 個 UDP（10.0.1.2:43000 → 10.0.2.2:5001，342 bytes）＋5 個 TCP（10.0.1.9:1234 → :80，74 bytes）：egress、ingress、xdp 都是兩筆（packets 20、bytes 6,840、hist [0,0,20,0]；packets 5、bytes 370、hist [0,5,0,0]），events 25 筆；TC 回傳 `TCX_NEXT` ×25，XDP `XDP_PASS` ×25。

## 測試程式為了通過 verifier 改過的地方

gw 容器只有 `CAP_BPF`、`CAP_NET_ADMIN`，沒有 `CAP_PERFMON`，verifier 不允許可能洩漏位址或受 Spectre 影響的指標運算。`prog/` 一開始有四種寫法被拒（`EACCES`，log 的 verifier 輸出有原因）：

| 寫法 | verifier | 改成 |
|---|---|---|
| `[0u8; 20]`、`pad: [0; 3]` 這種小陣列清零（編成 memset 迴圈，堆疊指標加變數） | `R5 tried to add from different maps, paths or scalars, pointer arithmetic with it prohibited for !root` | 用 `ctx.load::<[u8; N]>()` 直接讀；pad 拆成 `u8`、`u16` |
| map value 裡 `hist[bucket(len)] += 1` | 同上（R0 是 map value） | `match` 每個分支寫固定的索引 |
| XDP 用 `data_end - data` 當長度 | `R2 pointer -= pointer prohibited` | `bpf_xdp_get_buff_len()` |
| XDP 三個 `Option` 一起比對 | `R7 !read_ok`（編譯器把判斷排到 bounds check 前面） | 先檢查一次 38 bytes，再讀 |

## Pi 的功能確認（2026-11-19，`features_pi.sh`，Pi 4，kernel 6.18 rpt，沒有 vmlinux BTF）

| feature | backend tc | backend ctmark |
|---|---|---|
| egress（tc-egress） | 40：bridge 的 `bpf_redirect` 出去的封包也經過另一個 port 的 egress | 40 |
| ingress（tc-ingress，per-CPU） | 20 | 40 |
| xdp（veth native、generic 各跑一次） | 40／40 | 40 |
| events（ringbuf） | 40 筆 | 40 筆 |

- BTF 宣告的 map（`#[btf_map]`）在沒有 vmlinux BTF 的 Pi kernel 上照樣載入、讀得到；試跑（`BPF_PROG_TEST_RUN`）四種都和 Docker 一樣。
- 一張網卡只能掛一個 XDP 程式：native 的 `xdp` 和 generic 的 `xdpg` 一起設定時，第二個 `bpf_link_create` 回 `EEXIST`（File exists），run 記 G011、照常執行；單獨掛 generic 正常。所以 doctor 加了 G015（兩個以上 `hook = "xdp"`，或 port 上已經有 XDP 程式）。
- 第一次跑時 run 沒有啟動：Pi 的 `/var/lib/suricata/rules/suricata.rules` 不存在（S011），和特徵無關；腳本改成自己放一條測試規則。

## 讀取的 bench（2026-11-19，`bench/`）

量 run 每次讀 map 的每個環節（讀 map、解碼、衍生、寫 JSON、寫檔、釋放）每筆幾 ns、配置幾次記憶體，結果和決定在 `security_gateway/DECISIONS.md` §23「讀取的成本」，原始數據在 `~/datasets/throughput/features_bench/step{1,2,3}.kvl`。

```
feature-bench <prog.o> <definition.json> <entry> <hook> <entries> <rounds> <gap_ms> <out_file> <mode> <read>
```

- 先用 `BPF_PROG_TEST_RUN` 把 `<entries>` 條 flow（每條 3 個封包，輪流綁在不同 CPU）填進 map，再讀 `<rounds>` 輪（前 2 輪暖身、最後一輪只數配置次數），每輪之間停 `<gap_ms>`。
- `<mode>`：`current`（改之前的 wnc-gw，`src/legacy.rs` 留了一份）、`plan-json`／`plan-bin`／`plan-none`（bench 自己的計畫版，`src/fast.rs`：寫 JSON、二進位、不輸出）、`gw`（wnc-gw 現在的 `Table` 和 `Plan`）。
- `<read>`：`current` 只能配 `table`（舊的讀法）；計畫版可以是 `table`、`walk`（next_key＋lookup 寫進重複使用的 buffer）、`batchN`（`BPF_MAP_LOOKUP_BATCH` 一次 N 筆，`src/read.rs`）；`gw` 配 `gw`，或 `gw-walk`（強制一次一個 key，測 kernel 不支援 batch 時的退路）。
- 除了 `current`，每次執行前都先和 `legacy.rs` 用同一次讀取、同一個時間點比對 3 輪（中間打封包讓 rate 變動），輸出不同就停下來。batch 的順序和舊讀法不同，所以排序後比。
- 最後印 markdown 表和一行 kvl，也量 next_key、lookup、`getppid` 的 syscall 成本。
- 編法：`cargo build --release --target aarch64-unknown-linux-musl`（`CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld`）；`--features mimalloc` 要 `CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc` 和 `CFLAGS_aarch64_unknown_linux_musl="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-stack-protector"`。x86 的 mimalloc 版編不過（缺 musl 的 C 交叉環境）。
- Pi 上用 `prog/` 的 16,384 筆版本，`sudo ./feature-bench prog.o flows.json flows_tc tc-egress 5079 20 0 /tmp/wncgw/bench.jsonl gw gw`。
