# eBPF：核心程式與外掛

查證日期 2026-10-20。出處縮寫：
- `K`：github.com/torvalds/linux master（約 7.3-rc）
- `RPI`：raspberrypi/linux rpi-6.12.y，以及 archive.raspberrypi.com trixie 的 kernel config
- `AYA`：aya-rs/aya（v0.14.0 / main）
- `LRS`：libbpf-rs
- `LB`：libbpf

標「主 agent 核對」的是主 agent 自己讀過原始碼；其他來自 subagent 調查。

## 目錄
1. 核心程式和外掛怎麼分工
2. 外掛能造成哪些危害
3. 權限
4. 外掛的載入管線
5. kernel 端的強制手段
6. 多個程式怎麼共存、用哪個 Rust 函式庫
7. XDP 能力偵測
8. GRO 和特徵的正確性
9. 沒有 BTF 的影響

## 1. 核心程式和外掛怎麼分工 [建議]

- **核心程式**由我們自己寫、自己發行，擁有所有 hook（TCX ingress/egress、XDP）和最終 verdict。它負責解析 header、維護 flow 特徵 map、查信任 map、redirect、設 mark。
- **外掛只做分析。** 核心程式裡預留 global function（例如 `plugin_hook_0(const struct pkt_view *v, struct plugin_out *out)`），外掛以 freplace（`BPF_PROG_TYPE_EXT`）替換它，回傳特徵值或 flag，再由核心程式寫進固定的 schema。
- 為什麼不讓外掛直接掛 XDP/TCX，也不用 tail call：
  - 直接掛在 hook 上的程式可以 drop、redirect、改 mark；tail call 等於把最終 verdict 交給外掛。
  - EXT 程式沿用目標程式的 verifier ops，可用的 helper 不會因此變少 [K: `kernel/bpf/verifier.c` check_attach_btf_id]。所以「外掛只能做分析」要靠載入前的 ELF 白名單（§4）來擋，kernel 不會替你擋。
  - 核心程式呼叫外掛前後，要保存並還原 ctx 裡可寫的欄位（mark 等）。
- 一個目標函式只有一個 extension slot [K: `kernel/bpf/trampoline.c`]。要同時掛多個外掛，核心程式就要預留多個 hook 函式。
- 如果真的需要能改封包的外掛（drop、redirect），那屬於另一個信任等級：只限內建或管理者明確開啟，而且仍然不能碰 mark 和 ct。

## 2. 外掛能造成哪些危害（verifier 擋不住的）

- verifier 保證記憶體存取有界、沒有無限迴圈、helper 參數合法，但**不保證語意** [docs.kernel.org/bpf/verifier.html]。
- verifier 自己也出過提權漏洞（CVE-2021-3490、CVE-2022-23222）。載入任意程式，等於把 kernel 的攻擊面開放給外掛。
- tc 程式不需要 `CAP_PERFMON` 就能用這些 helper [K: `net/core/filter.c` tc_cls_act_func_proto]：
  - 改封包：`skb_store_bytes`、`l3/l4_csum_replace`、`skb_change_*`、`skb_adjust_room`、vlan push/pop
  - 轉送或複製流量：`clone_redirect`（把流量複製出去）、`redirect`、`redirect_neigh`、`redirect_peer`
  - 把封包送到 user space：`perf_event_output`
  - 可寫的 ctx 欄位有 `mark`、`priority`、`tc_index`、`tc_classid`、`cb`、`tstamp`。
- XDP 有 `xdp_adjust_head/tail`、`xdp_store_bytes`、`redirect_map` [K: 同檔 xdp_func_proto]。
- kfunc（kernel 有 BTF 才能用）有 `bpf_ct_set_status`、`bpf_ct_change_status`、`bpf_ct_insert_entry`、`bpf_skb_ct_lookup`，可以直接改 conntrack [K: `net/netfilter/nf_conntrack_bpf.c`]。
- **每個程式都讀得到完整封包內容。** 惡意外掛可以把 payload 編碼進特徵值送上雲端，破壞「雲端不看 payload」的承諾。這只能靠「誰有權裝外掛」來控制。
- **偽造 mark。** 信任判斷如果看 skb mark 或 ct mark，外掛改掉 mark 就能讓惡意 flow 被當成可信任。

## 3. 權限

- 載入 XDP、SCHED_CLS、EXT 程式需要 `CAP_BPF` + `CAP_NET_ADMIN` [K: `kernel/bpf/syscall.c` is_net_admin_prog_type]。
- `CAP_PERFMON` 會放行指標洩漏、未初始化 stack、略過 Spectre 緩解，以及 `probe_read_kernel`、`trace_printk` [K: `include/linux/bpf.h`、`kernel/bpf/helpers.c`]。privd **不要**有這個權限。
- `CAP_SYS_ADMIN` 隱含上面全部，也不給。
- Pi OS 預設關閉 unprivileged BPF（`BPF_UNPRIV_DEFAULT_OFF=y`）[RPI]。
- systemd 的 `bpf` syscall 屬於 `@privileged`，不在 `@system-service` 裡。所以 `SystemCallFilter` 要寫成 `@system-service bpf` [systemd `src/shared/seccomp-util.c`]。

## 4. 外掛的載入管線 [建議]

1. **驗簽章。** bundle 包含 ELF、manifest 和簽章，放在 root 擁有的 plugin store。privd 先驗簽章（minisign / Ed25519）和 manifest 版本。
2. **解析 ELF。** 把 ELF 讀進記憶體，用 `aya-obj` 解析。`Object::parse` 會列出 programs、functions、instructions、maps [AYA: `aya-obj/src/obj.rs`]。
3. **白名單檢查：**
   - prog type：分析外掛只允許 EXT。
   - helper：掃描所有 call 指令。`src_reg=0` 時 imm 是 helper ID，`1` 是 bpf-to-bpf 呼叫，`2` 是 kfunc [K: `include/uapi/linux/bpf.h` BPF_PSEUDO_CALL / BPF_PSEUDO_KFUNC_CALL]。只放行白名單，例如 map lookup/update、`ktime_get_ns`。禁止 redirect 系列、`skb_store_bytes`、`clone_redirect`、`perf_event_output`、`csum_replace`、`skb_change_*`。
   - 禁止 kfunc。
   - map type 只允許 ARRAY、HASH、PERCPU_*、LRU_*；禁止 map-in-map 和 pin-by-name；設大小上限。
   - 指令數上限。
   - 回傳值沒辦法靜態判斷，所以外掛的輸出由核心程式解讀，不讓它決定 verdict。
4. **檢查和載入用同一份記憶體 bytes**，避免檢查完之後檔案被換掉（TOCTOU）。
5. **共享 map 由核心建立。** 用 `BPF_F_RDONLY_PROG` 開給外掛，pin 在只有 root 能寫的 bpffs 目錄，由 loader 把 fd 注入外掛。

限制：
- libbpf 和 aya 載入時會改寫 map fd 與 CO-RE relocation，所以檢查的是改寫前的指令。
- 不能事後用 xlated dump 檢查，因為 `bpf_insn_prepare_dump` 會把 call 的 imm 清成 0 [K: `kernel/bpf/syscall.c`]。

## 5. kernel 端的強制手段

| 機制 | 版本 | 能做什麼 | 不能做什麼 | Pi OS 現況 | Rust 支援 |
|---|---|---|---|---|---|
| BPF token | 6.9 起 | 限制 cmd、map type、prog type、attach type（bpffs 的 `delegate_*` mount 選項） | 不能限制 helper、kfunc、指令；只能在非 init 的 userns 建立；設定 bpffs 需要 init ns 的 `CAP_SYS_ADMIN` | kernel 夠新，`USER_NS=y` | libbpf（C）有；libbpf-rs 沒有；aya 的 PR 還沒合併 |
| BPF 程式簽章 | 6.18 起 | kernel 驗證簽章並記下 verdict | **本身不強制**，要靠 LSM；簽的是 light skeleton loader，一般 CO-RE 的 `.o` 不能直接簽 | 6.12 沒有；6.18 有，但沒有 BPF LSM 能強制 | 沒有 Rust API，要自己寫 syscall |
| BPF LSM | — | 依 cmd、prog type、map type、簽章 verdict 拒絕 | — | 沒開，`CONFIG_LSM=""`（主 agent 核對 bcm2711_defconfig） | — |
| Hornet LSM | 未合併（2026-04 v6 仍有 Nacked-by） | — | — | — | — |

- 簽章的部分，主 agent 讀過 `Documentation/bpf/signing.rst`：kernel 只記錄 verdict，由 LSM 決定要不要拒絕載入。
- **結論：在 Pi OS 上，user space 的白名單和簽章是唯一防線。** 如果 verifier 或 JIT 有 bug，外掛就等於能在 kernel 裡執行程式碼，而 kernel 沒有任何強制機制擋得住。這是目前最大的未解風險。

## 6. 多個程式怎麼共存、用哪個 Rust 函式庫

- **tc**：用 TCX（6.6 起），每個 hook 最多掛 64 支程式（`BPF_MPROG_MAX`），不需要 clsact。aya v0.14.0 支援 TCX 和排序（`TcAttachOptions::TcxOrder`、`LinkOrder` before/after）。
- **XDP**：要掛多支程式得靠 libxdp dispatcher（freplace + BPF trampoline，需要 5.10 以上）。aya 沒有實作 dispatcher。arm64 的 BPF trampoline 從 6.0 開始有。
- **freplace**：型別檢查用的是目標程式自帶的 BTF [K: verifier.c bpf_check_attach_target]，[推測] 不需要 vmlinux BTF，所以 Pi OS 上應該能用。[待查證] 要在 Pi 4 上實測。
- **tail call**：最多 33 層（`MAX_TAIL_CALL_CNT`）。
- **Rust 函式庫比較**：

| | aya | libbpf-rs |
|---|---|---|
| 有 | TCX、Extension（freplace）、ProgramArray、map pinning | XDP、舊式 TcHook、`Xdp::query`（可讀 XDP feature） |
| 沒有 | BPF token、簽章、xdp-features 查詢、libxdp dispatcher | TCX、freplace、BPF token、light skeleton |

  「核心程式 + 外掛」的架構傾向選 aya [建議]。

## 7. XDP 能力偵測 [建議]

- kernel 6.3 起，netdev genetlink 會回報 xdp-features [K: `Documentation/netlink/specs/netdev.yaml`]。旗標值：basic=1、redirect=2、ndo-xmit=4、xsk-zerocopy=8、hw-offload=16、rx-sg=32、ndo-xmit-sg=64。
- 怎麼讀：
  - libbpf：`bpf_xdp_query` 的 `feature_flags`。
  - libbpf-rs：`Xdp::query` 可以直接讀。
  - aya：沒有 API。要自己寫 genl 查詢，或用 DRV_MODE 嘗試 attach，失敗再退回。
- 依用途分開判斷：
  - DROP、PASS：只要收封包的 port 有 basic。
  - redirect：除了收封包的 port，送出的 port 還要有 ndo-xmit。
- 只接受 native XDP，**不要自動退回 generic XDP**。generic XDP 在 skb 建好、GRO 合併之後才執行，沒有任何好處，還會讓量測結果看起來像用了 XDP。
- 每個 port 實際用了哪種模式，要寫進 log 和實驗紀錄。
- **Pi 4 的現況**：
  - bcmgenet 在 mainline 和 rpi-6.12.y 都沒有 XDP（主 agent 核對：兩份 `bcmgenet.c` 搜尋 `xdp` 都是 0 筆）。
  - 加 XDP 的 patch 系列（2026-03 起）到 2026-05 還在 v9 review。
  - USB 網卡的 r8152、lan78xx、smsc95xx 也沒有 XDP。
- **筆電和 Pi 不一樣**：筆電上用 netns + veth 測試時會偵測到可用，因為 veth 支援 native XDP，連 redirect 都可以。所以筆電上的結果不代表 Pi。

## 8. GRO 和特徵的正確性

- tc ingress（含 TCX）和 generic XDP 看到的是 **GRO 合併後**的 skb；native XDP 看到的是原始 frame。封包的路徑是 `napi_gro_receive` → `netif_receive_skb_list_internal` → `__netif_receive_skb_core`，在這裡先跑 `do_xdp_generic`，再跑 `sch_handle_ingress` [K: `net/core/dev.c`]。
- tc egress 在 GSO 切分之前執行，所以也看到合併後的大封包。
- `__sk_buff.gso_segs` 從 5.1 開始可讀，可以用來修正封包數；`gso_size` 從 5.7 開始可讀。但封包大小的分布和到達間隔（IAT）會失真。
- 三種處理方式（`decisions.md` O7）：
  - (a) 用 `gso_segs` 修正封包數，接受大小會失真。
  - (b) `ethtool -K <if> gro off`，特徵變準確，但要多花 CPU。
  - (c) 在有 native XDP 的硬體上改用 XDP 算特徵。

  雲端模型如果要用封包長度相關的特徵，這個問題就很重要，要實際量。

## 9. 沒有 BTF 的影響

- tc/XDP 程式只要只存取 `__sk_buff` / `xdp_md`、header 自己解析，就不需要 vmlinux BTF。需要 BTF 的只有 CO-RE relocation、typed ksym 和 kfunc [LB: `obj_needs_vmlinux_btf`；AYA: `aya/src/bpf.rs`]。
- kfunc 一定需要 BTF，所以 `bpf_skb_ct_lookup`、`bpf_ct_change_timeout` 在 Pi OS 預設 kernel 上不能用。沒有 BTF 時，verifier 會拒絕並回報 "calling kernel function is not supported without CONFIG_DEBUG_INFO_BTF"。
  - 對階段 3 的影響：conntrack 的逾時和計數不能靠 kfunc，要自己在 map 裡管理。
  - 好處：外掛也用不到 kfunc，攻擊面比較小。
- 可以用 `btf_custom_path` 或 aya 的 `EbpfLoader::btf()` 提供外部 BTF，但要自己產生。
- Pi OS 6.12 和 6.18 的 rpi_v8 config 都是 `CONFIG_DEBUG_INFO_NONE=y` [RPI]。OpenWrt 的 `KERNEL_DEBUG_INFO_BTF` 預設是 n。
