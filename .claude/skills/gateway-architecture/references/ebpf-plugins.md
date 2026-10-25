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

## 1. 核心程式和外掛怎麼分工

- **[已決定] 2026-10-22：外掛支援完整功能。** 外掛掛在哪個 hook、能不能 drop 或 redirect，由管理者在設定裡決定，後果也由管理者負責。框架依設定載入和掛載，並讓管理者看得清楚：§4 的能力報告，以及 doctor 列出的清單。
- **核心程式**由我們自己寫、自己發行。它負責解析 header、維護 flow 特徵 map、查 ban 和信任 map、redirect、設 mark。
- [建議] 核心程式在 TCX 排第一：ban 回傳 DROP，trust 回傳 REDIRECT，永不封鎖清單回傳 PASS，其他回傳 NEXT 交給後面的程式。這不限制外掛能做什麼，只是讓外掛寫錯時，管理連線還連得上。預設開啟，可以在設定裡關掉。
  - TCX 依序執行，只要有一支程式回傳 NEXT 以外的值就停 [K: `net/core/dev.c` tcx_run]。所以核心程式回傳 PASS 或 REDIRECT 的封包，排在後面的外掛看不到。
  - 這個保護只對 TCX 外掛有效。XDP 在 tc 之前執行，socket filter 不影響轉送。

外掛的掛法：

| 掛法 | 能做什麼 | 和核心程式的關係 |
|---|---|---|
| TCX（排在核心程式後面） | drop、redirect、改封包、改 mark | 只看得到核心程式回傳 NEXT 的封包。改 mark 會影響後面 nft 的判斷，包括信任判斷 |
| XDP | drop、redirect、改封包 | 在核心程式之前執行，永不封鎖清單保護不到。網卡沒有 native XDP 時不載入，請使用者改成 TC 程式，除非明確指定 generic（§7）。Pi 4 的兩張網卡都沒有 native XDP |
| socket filter | 只能觀察；可以寫 map、ringbuf | 不影響轉送 |
| freplace（EXT） | 替換核心程式預留的 hook 函式（例如 `plugin_hook_0(const struct pkt_view *v, struct plugin_out *out)`） | 回傳值由核心程式解讀。EXT 沿用目標程式的 verifier ops，可用的 helper 和核心程式一樣 [K: `kernel/bpf/verifier.c` check_attach_btf_id]。核心程式呼叫前後要保存並還原 ctx 裡可寫的欄位（mark 等）。一個目標函式只有一個 extension slot [K: `kernel/bpf/trampoline.c`]，要掛多個就要預留多個 hook 函式 |

## 2. 外掛能造成哪些危害（verifier 擋不住的）

外掛支援完整功能之後，框架不擋這些事，改成在能力報告和 doctor 裡揭露給管理者（§4）。

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
- doctor 要列出 port 上的程式時，各項資料需要的權限（主 agent 核對 `kernel/bpf/syscall.c`、`include/linux/bpf.h`、`net/core/rtnetlink.c`，2026-10-22）：

  | 資料 | 怎麼拿 | 權限 |
  |---|---|---|
  | 某個 port 的 TCX 上掛了哪些程式（id 和順序） | `BPF_PROG_QUERY` | `CAP_NET_ADMIN`（`bpf_net_capable`） |
  | 某個 port 的 XDP 程式 id 和模式 | rtnetlink 的 `IFLA_XDP_*` | 不需要 |
  | 程式的名稱、tag | `BPF_PROG_GET_FD_BY_ID` 再 `OBJ_GET_INFO_BY_FD` | `CAP_SYS_ADMIN` |
  | 系統上全部的程式 | `BPF_PROG_GET_NEXT_ID` | `CAP_SYS_ADMIN` |

  privd 不給 `CAP_SYS_ADMIN`，所以「是不是框架載入的」要用 id 比對：privd 記得自己載入的每支程式的 id，不在名單裡的就是框架以外的程式，只顯示 id。

## 4. 外掛的載入管線 [建議]

1. **驗簽章。** bundle 包含 ELF、manifest 和簽章，放在 root 擁有的 plugin store。privd 先驗簽章（minisign / Ed25519）和 manifest 版本。
2. **解析 ELF。** 把 ELF 讀進記憶體，用 `aya-obj` 解析。`Object::parse` 會列出 programs、functions、instructions、maps [AYA: `aya-obj/src/obj.rs`]。
3. **能力掃描**，結果寫進 log，doctor 也會顯示。只用來揭露，不拒絕載入：
   - 掛點決定能不能丟包：TCX 和 XDP 程式只要回傳值就能 drop，這和用了哪些 helper 無關。回傳值沒辦法靜態判斷，所以掛在這兩個 hook 的程式一律標成「可以丟包」。
   - helper：掃描所有 call 指令。`src_reg=0` 時 imm 是 helper ID，`1` 是 bpf-to-bpf 呼叫，`2` 是 kfunc [K: `include/uapi/linux/bpf.h` BPF_PSEUDO_CALL / BPF_PSEUDO_KFUNC_CALL]。依 helper 標出：
     - 轉送：redirect 系列
     - 複製流量：`clone_redirect`
     - 改封包：`skb_store_bytes`、`csum_replace`、`skb_change_*`、`skb_adjust_room`
     - 送到 user space：`perf_event_output`、ringbuf
   - 有沒有用 kfunc（Pi OS 沒有 BTF，用了也載不進去，見 §9）。
   - map type、map 大小、指令數。大小的上限仍然要有（SKILL.md §5 第 7 點），由設定決定。
4. **掃描和載入用同一份記憶體 bytes**，避免掃描完之後檔案被換掉（TOCTOU）。
5. **共享 map 由核心建立**，pin 在只有 root 能寫的 bpffs 目錄，由 loader 把 fd 注入外掛。預設用 `BPF_F_RDONLY_PROG` 開給外掛。

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
- **結論：在 Pi OS 上，user space 的簽章是唯一防線**，它決定誰能裝外掛；外掛能做什麼不限制（§1）。如果 verifier 或 JIT 有 bug，外掛就等於能在 kernel 裡執行程式碼，而 kernel 沒有任何強制機制擋得住。這是目前最大的未解風險。

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

## 7. XDP 的預設與能力偵測

**[已決定] 2026-10-24：框架預設用已知最快的方式。**
- **核心程式**：port 有 native XDP 就掛 XDP，否則掛 TC，不會自動選 generic。使用者可以關掉 XDP（一律 TC），或明確指定 generic。設定名稱暫定為 `xdp = "auto" | "off" | "generic"`，預設 `auto`。核心程式的解析邏輯只寫一份，編出 XDP 和 TC 兩個入口。
- **使用者的 XDP 外掛**：網卡沒有 native XDP 時不載入，請使用者改成 TC 程式；只有明確指定 generic 才載入。XDP 和 TC 程式的 ctx 不同（`xdp_md`、`__sk_buff`），框架沒辦法替外掛改掛。錯誤訊息的例子：
  `error: plugin "foo" is an XDP program but eth0 has no native XDP support; rebuild it as a TC program, or allow generic XDP explicitly`
- **doctor** 顯示每個 port 實際的 XDP 模式（rtnetlink 的 `IFLA_XDP_ATTACHED`，不需要權限）。generic 的話提出 warning，說明這張網卡的 GRO 被關掉了。
- [待確認] 這條原則和 10-20「fast path 用 tc、不用 XDP」的關係：有 native XDP 時，trust 的 redirect 要不要也放在 XDP。
- [待確認] 核心程式掛在 XDP 時，§1「排在 TCX 第一，用 PASS 保護管理連線」的做法要重新設計，因為 XDP 回傳 PASS 不會跳過後面的 TCX 外掛。

**為什麼不用 generic XDP**（主 agent 核對 `net/core/dev.c`、`include/linux/netdevice.h`，2026-10-24）：
- 它在 skb 建好之後才執行（`do_xdp_generic`），省不到建 skb 的成本。執行位置只比 tc ingress 早一點。
- 它要求 skb 是 linear、沒有被 clone，而且前面留 `XDP_PACKET_HEADROOM`（256 bytes）。不符合就重新配置並複製（`netif_receive_generic_xdp`）。Pi 的兩個 driver 預留的 headroom 夠不夠 [待查證]。
- **掛上 generic XDP，那張網卡會整個跳過 GRO**：`netif_elide_gro` 看到 `dev->xdp_prog` 就跳過，而這個欄位只有 generic 模式會設。
- `XDP_TX`、`XDP_REDIRECT` 每個封包各走一次 `dev_queue_xmit`，沒有批次。
- 它唯一的用處，是讓同一支 XDP 程式在沒有 native 支援的機器上也能跑，方便測試。

**怎麼偵測：**
- kernel 6.3 起，netdev genetlink 會回報 xdp-features [K: `Documentation/netlink/specs/netdev.yaml`]。旗標值：basic=1、redirect=2、ndo-xmit=4、xsk-zerocopy=8、hw-offload=16、rx-sg=32、ndo-xmit-sg=64。
- 怎麼讀：
  - libbpf：`bpf_xdp_query` 的 `feature_flags`。
  - libbpf-rs：`Xdp::query` 可以直接讀。
  - aya：沒有 API。要自己寫 genl 查詢，或用 DRV_MODE 嘗試 attach，失敗再退回。
  - wnc-gw（2026-10-25 已實作）：`kernel/netdev.rs` 用 genetlink 對每個介面各送一次 `NETDEV_CMD_DEV_GET`（帶 ifindex）。不用 dump，因為 kernel 的 dump 回應不帶 `NLM_F_MULTI`，netlink-proto 只會收第一則。doctor 的 XDP 段落顯示 native 功能、已掛的 XDP 程式（`IFLA_XDP_ATTACHED`，native/generic/offload）和 `core_hook()` 選到的 hook。實測：Pi 的 bcmgenet、cdc_ncm 都回報 0；筆電 7.0 的 veth 回報 basic、redirect、rx-sg。
- 依用途分開判斷：
  - DROP、PASS：只要收封包的 port 有 basic。
  - redirect：除了收封包的 port，送出的 port 還要有 ndo-xmit。
- 每個 port 實際用了哪種模式，要寫進 log 和實驗紀錄。
- **Pi 4 的現況**：
  - bcmgenet 在 mainline 和 rpi-6.12.y 都沒有 XDP（主 agent 核對：兩份 `bcmgenet.c` 搜尋 `xdp` 都是 0 筆）。
  - 加 XDP 的 patch 系列（2026-03 起）到 2026-05 還在 v9 review。
  - USB 網卡的 r8152、lan78xx、smsc95xx 也沒有 XDP。
- **筆電和 Pi 不一樣**：筆電上用 netns + veth 測試時會偵測到可用，因為 veth 支援 native XDP，連 redirect 都可以。所以 `auto` 在 Docker 上會選 XDP，在 Pi 上會選 TC。Docker 驗證時兩條都要測：預設跑一次，再用 `xdp = "off"` 模擬 Pi。

## 8. GRO 和特徵的正確性

- tc ingress（含 TCX）看到的是 **GRO 合併後**的 skb；native XDP 看到的是原始 frame。封包的路徑是 `napi_gro_receive` → `netif_receive_skb_list_internal` → `__netif_receive_skb_core`，在這裡先跑 `do_xdp_generic`，再跑 `sch_handle_ingress` [K: `net/core/dev.c`]。
- **例外：網卡掛了 generic XDP 時完全不做 GRO**（`netif_elide_gro`，§7），所以這張網卡上的 generic XDP 和 tc 看到的都是沒合併的封包。（2026-10-24 更正：這份文件原本寫 generic XDP 看到的是合併後的 skb，那是錯的。）
- Pi 上只有 eth0（bcmgenet）有 GRO。eth1 的 USB 網卡（ASIX，`cdc_ncm`）經過 usbnet 走 `netif_rx`，本來就沒有 GRO。
- **XDP 和 TC 看到的封包不同，同一個特徵在不同硬體上會算出不同的值**：有 native XDP 的設備在 XDP 算，Pi 在 TC 算。雲端模型如果用一種硬體的資料訓練、在另一種上推論，就會有偏差。[建議] 上傳的資料要記錄是在哪個 hook 算的；TC 端用 `gso_segs` 修正封包數。
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
