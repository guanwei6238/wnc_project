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

成本（每個封包多幾 µs）還沒量，是步驟 A3。
