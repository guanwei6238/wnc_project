# 核心 eBPF 程式的驗證

`core_pi.sh`：在 Pi 上用三個 netns 驗證核心 eBPF 程式（步驟 A1），不碰 eth0、eth1。

```
ecli(c0 10.8.0.1) --veth-- lan0 [egw: br0] wan0 --veth-- s0(esrv 10.8.0.2)
```

wnc-gw 的 port 是 `lan0`、`wan0`，ping 一定經過這兩個 port 的 TC ingress。

```sh
scp target/aarch64-unknown-linux-musl/debug/wnc-gw wnc@10.254.254.2:/tmp/wncgw/wnc-gw
scp tests/ebpf/core_pi.sh tests/ebpf/foreign_tcx.py wnc@10.254.254.2:/tmp/wncgw/
sudo bash core_pi.sh up      # 建 netns
sudo bash core_pi.sh run     # run → ping 5 次 → SIGINT，印出 attach／detach 的 log
sudo bash core_pi.sh show    # run 中印 bpftool net show 和每個 CPU 的計數
sudo bash core_pi.sh tcx     # 別的 TCX 程式：doctor（root、wnc）、run 中被插隊、被拆掉
sudo bash core_pi.sh kill9   # kill -9 之後程式是否自動卸下
sudo bash core_pi.sh down
```

## 結果（2026-11-14，Pi 4、6.18.50+rpt-rpi-v8、沒有 /sys/kernel/btf）

| 案例 | 結果 |
|---|---|
| run | `core ebpf program attached first on tcx ingress interfaces="lan0,wan0"`，結束時 `detached packets=10`（5 個請求從 lan0、5 個回應從 wan0），exit 0 |
| show | 兩個 port 的 `tcx/ingress` 都是 `wnc_gw_ingress`、同一個 prog_id；ping 3 次後 CPU 0 的計數是 6，其他 CPU 是 0 |
| kill9 | `kill -9` 前 lan0 有 1 個 TCX 程式，之後 0 個；nft table 留下（和之前一樣，腳本會刪掉） |
| BTF | Pi 沒有 vmlinux BTF，ELF 自己帶的 BTF 照常載入（`bpftool prog show` 有 `btf_id`） |
| tcx（A2） | run 之前掛的 `before_run`：root 的 doctor 是 `55 (before_run)`、D006；wnc 帳號 `not checked`、D004。run 掛上後順序是 `wnc_gw_ingress`、`before_run`。run 中掛 `first` 的 `jumper`：WARN D002 `before="58"` → 拿掉後 INFO「first again」→ `bpftool link detach` 我們的 link 後 WARN D003 |

`foreign_tcx.py <介面> first|last [名稱]`：用 bpf syscall 載入一支只回傳 TCX_NEXT 的程式、掛在 TCX ingress 的最前或最後，收到 SIGINT／SIGTERM 才拿掉；用來模擬別人的程式（需要 CAP_BPF、CAP_NET_ADMIN）。

# 步驟 A3：掛一支 TCX 程式要多少 CPU

`bench/`（獨立的小 workspace，不是 wnc-gw）：`bench-ebpf` 有三支程式，`ebpf-bench <v1|v2|v3> [--flow …] <介面>…` 把其中一支掛到每個介面的 TCX ingress 第一位，收到 SIGINT 後印 `packets=… hits=…`。

| 版本 | 內容 |
|---|---|
| V0 | 沒有程式 |
| V1 | 空程式，回傳 TCX_NEXT |
| V2 | V1＋per-CPU 計數（= wnc-gw 現在的程式） |
| V3 | V2＋解析 Ethernet／IPv4／IPv6／TCP／UDP，用五元組（40 bytes）查一次 65,536 筆的 hash map（是空的，一定查不到） |

`cost_pi.sh cpu|stats`：`tests/ids_inline/env.sh` 的 veth 拓樸（wtest 的 tcpreplay 從兩端送進 wgw 的 br0，port 是 g-lan、g-wan），沒有 nft、沒有 Suricata。`cpu` 量整台 Pi 的 CPU（`/proc/schedstat` rq_cpu_time ÷ 送出的封包，`tcpreplay -T nano` 綁 CPU 1），`stats` 開 `kernel.bpf_stats_enabled` 讀每支程式的 run_time_ns ÷ run_cnt。每輪版本順序打亂。`summarize.py cost.kvl` 彙整。

```sh
cd bench && CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld cargo build --release --target aarch64-unknown-linux-musl
scp target/aarch64-unknown-linux-musl/release/ebpf-bench ../cost_pi.sh wnc@10.254.254.2:/home/wnc/ebpf/
# Pi：pi_lab_mode.sh up 1000、systemctl stop suricata 之後
sudo bash cost_pi.sh cpu; sudo bash cost_pi.sh stats
```

功能檢查（筆電的臨時容器，只有 CAP_NET_ADMIN、CAP_BPF）：V3 預先放一組 UDP 五元組，IPv4 送 100＋30 個（其他 port）＋20 個 IPv6 → `hits=100`；IPv6 的五元組 → `hits=40`；帶 IP option 的 IPv4（走 `bpf_skb_load_bytes`）→ `hits=15`。

## 結果（2026-11-14，Pi 4 Model B 4 GB、鎖 1000 MHz、6.18.50+rpt-rpi-v8；C17_Benign 20 萬個封包、平均 475 bytes、10 kpps；全部 throttled 0x0）

整台 Pi（cpu，5 輪；同一輪裡和 V0 相減）：

| | V0 | V1 − V0 | V2 − V0 | V3 − V0 |
|---|---|---|---|---|
| µs／封包 | 32.7–34.8 | **+0.52（標準差 0.07）** | +1.25（1.31） | +1.05（0.69） |

程式本身（stats，3 輪）：

| | V1 | V2 | V3 |
|---|---|---|---|
| ns／次 | 104（2.4） | 151（12.6） | 600（33） |
| 和前一個版本的差 | — | +47 | +449 |

怎麼讀：
- **進 TCX 本身約 0.5 µs／封包**（V1 − V0，5 輪都在 0.44–0.63），是這次唯一能用整台 CPU 量準的差。
- V2、V3 多出來的部分小於整台 CPU 的誤差（輪與輪之間差 1 µs 以上），要看 bpf_stats：計數 +47 ns、解析＋查表 +449 ns。V1 的 104 ns 大多是 bpf_stats 自己的成本（每次執行前後各讀一次時間），所以只看版本之間的差。
- 加起來 V3 ≈ 0.52 + 0.05 + 0.45 ≈ **1.0 µs／封包**，和整台 CPU 的 V3 − V0（+1.05）一致。現在 wnc-gw 的程式（V2）≈ 0.57 µs。
- 這個 1 µs 是每個封包都要付的。對照：信任的封包約 14 µs、全部檢查 55–61 µs（`tests/cpu_alloc/README.md`，實體網卡、ips），信任每個封包省 39–67 µs（DECISIONS.md §5）。fast path 要讓信任的封包省下的比 1 µs 多很多才划算；沒被信任的封包多 1 µs（約 2%）。
- 查表的 449 ns 是空 map、40 bytes 的 key；map 有資料時 cache 的行為會不同，C 要再量。
- **沒有解釋的**：V0 從第一輪的 32.7 慢慢升到第五輪的 34.8 µs（約 8 分鐘內 +2 µs），時脈、throttled 都沒變；用同一輪相減抵掉。33 µs 也包含 tcpreplay 自己送封包的 CPU，不是 gateway 單獨的轉送成本。

原始資料：筆電 `~/datasets/throughput/ebpf/cost.kvl`、`run.log`（和 Pi 上的 sha256 核對過）。

## 寫 eBPF 時發現的 verifier 限制（沒有 CAP_PERFMON 時）

筆電容器只給 CAP_NET_ADMIN、CAP_BPF，和之後的 privd 一樣沒有 CAP_PERFMON（架構 §3）。這時 verifier 不允許某些指標運算，Rust 寫起來很自然的兩種寫法會被拒絕（Pi 用 root 有全部權限，不會發現）：
- **先把 struct 清成 0 再填欄位**：被編成逐 byte 的 memset 迴圈（`R5 tried to add from different maps, paths or scalars`）。改成每個欄位先讀出來，最後一次組成 struct；連 `[u8; 3]` 的 pad 也會變 memset，key 裡不要放 byte 陣列。
- **變數 offset 讀封包**（IPv4 的 header 長度）：編譯器產生 `scalar += pkt`（`pointer arithmetic with it prohibited for !root`）。常見的位置（沒有 option 的 IPv4 在 34、IPv6 在 54）用固定 offset 直接讀，其他用 `bpf_skb_load_bytes`（`ctx.load()`）。
