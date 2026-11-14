---
name: gateway-development
description: 在 security_gateway/（執行檔 wnc-gw）加功能或改程式時的實作慣例：程式該放哪一層（cli/、config、ports、forwarding/、datapath/、kernel/、platform/，之後的 ids/）、型別與英文錯誤訊息怎麼寫、設定欄位與 CLI 參數怎麼加、單元測試放 tests/unit/ 並鏡像 src、新功能要在 wnc-gw doctor 補哪些檢查，以及「先在 Docker testbed 驗證、再上 Pi」的流程。只要要在 wnc-gw 新增或修改子命令、setting.toml 欄位、kernel 互動（netlink、sysfs、procfs、nftables、conntrack、eBPF 載入）、doctor 檢查或測試，或要在 Docker／Pi 上驗證 gateway，都先讀這份 skill，即使使用者只說「加一個功能」「檢查一下環境」「接下來做 X」。目標架構與安全底線另見 gateway-architecture。
---

# wnc-gw 開發指南

這份 skill 描述**現在的程式長什麼樣子，以及要怎麼往上加**。目標架構、插件點與安全底線在 `gateway-architecture`；兩份都適用時一起讀。內容反映 2026-10-28（3c-1：`kernel/conntrack.rs`、`wnc-gw trust`）的狀態，程式之後若有變動，以實際程式碼為準，並回頭更新這份 skill。

## 0. 動手之前

- **`.claude/CLAUDE.md` 的工作方式優先。** 先說明要做什麼、為什麼、有哪些選項，取得開發者同意才寫程式；一次只做一步；開發者問「為什麼」「這是什麼」時只解釋，不改程式。開發者說「可以」「好」之前，不要先動手。
- **用全域需求比較方案。** 不要只看「這一步」的成本，要列出這個模組之後所有已知的需求再比較。目標是後面的步驟只新增、不改寫前面的程式。依賴未決事項的部分要明說，並先把對外的型別定住。
- **程式不替使用者做決定。** 例如哪張網卡是 LAN/WAN 一律由使用者指定，有歧義就報錯、把決定交回使用者，不用啟發式規則去猜。相反地，**系統事實**（例如 kernel 從哪裡載入模組）要照實回報，不提供讓使用者覆寫的選項，否則檢查結果會和實際行為脫鉤。
- 待決事項先給選項分析（好處、代價、我的傾向），不要只問「選哪個」。

## 1. 現在的結構

```
security_gateway/
├── Cargo.toml              package = security_gateway（lib 名稱），[[bin]] name = "wnc-gw"；也是 workspace 根（members = gw-ebpf，default-members = "."，所以 cargo build／test 不會用 host target 編 gw-ebpf）
├── build.rs                用 rustup run nightly-2026-11-13 cargo build -Z build-std=core --target bpfel-unknown-none 編 gw-ebpf（另外的 --target-dir 在 OUT_DIR，避免和外層 cargo 互鎖；拿掉 RUSTC 等環境變數，否則會用到 stable 的 rustc），把 ELF 複製到 OUT_DIR/gw-ebpf；成功時不印東西（不用 aya-build：它把每行輸出變成 cargo warning，而且每次 build 都重印）
├── gw-common/              kernel 和 user space 共用的型別（no_std；feature user 時替 aya 實作 Pod）：FlowKey（五元組，位址和 port 照封包的 bytes 存）、FlowStats（封包數、bytes、最後時間、方向，預留 RQ3 的欄位）、map 大小與常數
├── gw-ebpf/                在 kernel 裡跑的 eBPF 程式（no_std、no_main，aya-ebpf 0.3.0，授權 Dual MIT/GPL）：wnc_gw_ingress（TC classifier）：解析 header、多播／分片／TCP 控制封包交回 kernel（純 SYN 先刪信任）、查 TRUST，查到就更新計數並 redirect 到 PEER 的另一個 port（CONFIG 是 routed 時先減 TTL 再 bpf_redirect_neigh）；COUNTERS 記收到和 redirect 的封包數
├── setting.example.toml    設定檔範本：說明用英文，所有值預設註解掉
├── src/
│   ├── main.rs             #[tokio::main(flavor = "current_thread")]，只呼叫 cli::run()
│   ├── cli/                ← bin：只放參數與膠水
│   │   ├── mod.rs          out! macro（取代 println!：stdout 被關掉時不 panic，cli 一律用它）；Cli（全域參數 -c/--config、--lan、--wan、--log-format、--log-level）、Command、run()
│   │   ├── doctor.rs       doctor（TCX 段落：check_tcx 每個 port 查 tcx_ingress，有程式時才試 program_names；tcx_findings 純函式：前面有別人 D002、後面有別人 D006、沒名稱時列 id 並說分不出來 D006、查不了 D004、沒有 TCX D005，都是 warning）：載入設定 → passes()（各項檢查、印報告，沒有 error 才回傳 true）→ 結束碼；每個 Finding 帶 Issue，印成 warning[R006]: …
│   │   ├── explain.rs      explain：列出全部代碼、印一條（explain R006）或全部（--all）的說明（cause、action），100 字元折行
│   │   ├── logging.rs      LogFormat（text、json）、LogLevel（預設 info）、init()：tracing 的輸出設定（stderr、UTC 時間、text 在終端機才上色、寫入失敗不回報，否則 stderr 斷掉時會 panic），run 和 trust add/del 會呼叫
│   │   ├── trust.rs        trust add/del/list：經 control socket 請 run 寫 trust map（run 要在跑、要 root）；list 印每個方向的封包數、bytes；log 由 run 記（帶 uid）
│   │   ├── run.rs          run：開 log → 載入設定 → instance::lock()（已有 wnc-gw 在跑就不啟動）→ doctor::passes()，有 error 就不啟動 → 先註冊 SIGINT/SIGTERM/SIGHUP → 安裝 table（ids chain 是沒就緒狀態）→ 掛核心 eBPF 程式（attach_core：重新解析 port，掛不上記 ERROR D001、照常執行但沒有信任，自動信任關閉 T014；交給 LocalPrivd）→ 開 control socket（開不起來 WARN L006；別的帳號 WARN L007）→ 事件迴圈裡處理 trust 請求（add 先確認連線有 forwarded 位元）→ 結束時關 socket、在移除 table 之前 detach_core，記 packets、redirected → 從 suricata.yaml 找出寫 alert 的 eve-log 檔（dump-config）→ 啟動 Suricata（SpawnedSuricata）→ Ready 時 start_inspection（第一次 Ready 時開始讀 EVE 的 alert：AlertWatch）、Stopped 時 stop_inspection 再 allow_restart；每 10 秒用新的 ctnetlink socket 讀 conntrack 統計交給 ConntrackMonitor；ids 時 Suricata 就緒後每 10 秒讀它的 NFLOG socket 交給 CopyMonitor → 收到訊號：stop_inspection → 停止 Suricata → 讀完 EVE 最後一段並記摘要 → 移除 table；沒檢查的時段都記成 log 事件
│   │   └── show/           show 的巢狀子命令（mod.rs 分派，interfaces.rs 列介面）
│   ├── lib.rs              只宣告功能模組：agent、config、datapath、forwarding、ids、issue、kernel、monitor、platform、system
│   ├── issue.rs            Issue（doctor 結果和 run 的 WARN／ERROR log 的代碼，issues! macro 同時產生 enum 和 ALL）、explanation()（exhaustive match，新增 Issue 不寫說明就編不過）、FromStr 不分大小寫
│   ├── agent/              3d：wnc-gw 自己判斷信任（之後拆成無特權的 agent process）
│   │   ├── mod.rs          trait Privd（forwarded_connections、trust、untrust；之後由有權限的 process 實作）、PrivdError（NoFastPath、NotTrusted、Trust）、LocalPrivd（持有 CoreProgram 和 ctnetlink socket，socket 壞了就下次重連；connection()、trusted() 給 control socket 用）
│   │   ├── control.rs      wnc-gw trust 和 run 之間的 unix socket（<runtime_dir>/control.sock，0600）：一個連線一個請求，各一行 JSON（Request：trust、untrust、list；Response：done、trusted、error）；ControlServer（bind 時刪掉舊檔、Drop 時刪掉，accept 用 SO_PEERCRED，只收 root 和 socket 擁有者的帳號）、Incoming（讀一行，1 秒逾時、64 KiB 上限）、request()（CLI 端，同步）
│   │   └── trust.rs        TrustAgent：TrustPolicy（min_packets、min_age、ttl）；每個連線（五元組不分方向，配 conntrack id）的狀態 Watching（開始時間和當時的計數）→ Trusted（到期時間）→ 或 Refused（有 alert）；observe()（純函式，輸入連線清單和時間，輸出 Decision：Trust、Expire、Revoke）、alert()；check()、on_alert() 經 Privd 寫入並記 log（信任 INFO、撤銷 WARN、到期 DEBUG、有變動時每 60 秒摘要）；Suricata 停止時（set_inspecting）觀察中的連線全部重來；連線沒有計數時記一次 WARN
│   ├── config/             設定和它的值型別（2026-11-14 從頂層搬進來）
│   │   ├── mod.rs          setting.toml + CLI 覆寫 → Config（每個值帶 Source；只放相關的值：delivery、TrustSettings::Manual／Auto，不相關的欄位報 C004）；AbsolutePath（路徑設定必須是絕對路徑）；delivery()：依 protection 選 queue 或 group
│   │   ├── ports.rs        Role、PortSelector（名稱或 MAC）、resolve()
│   │   └── protection.rs   Protection（ids 預設、ips）：delivery() 決定封包怎麼交給 Suricata；之後的黑名單、雲端判定要不要真的擋也看它
│   ├── datapath/           核心 eBPF 程式在每個 port 掛在哪、怎麼掛（mod.rs 只放 pub mod / pub use）
│   │   ├── firewall.rs     我們自己的 nft table（inet wnc_gw）：forward chain 依序是 counter、連線第一次經過時設 FORWARDED_MARK（0x40000000，3d 和 trust add 只看有這個位元的連線）、jump ids（2026-11-14 起信任在 TC，進到 netfilter 的封包都不是信任的，L2 和純 SYN 也在 TC 做）；ids 依 Suricata 狀態換成送檢查或沒就緒的規則（WhenUnavailable、Inspection），每種狀態都要以判決結尾，否則控制封包會回到 forward 再進一次 ids；送檢查依 Delivery：Queue 是 `queue`（accept 時加 bypass），Copy 是 `log group N accept`，多個 group 時 ids 是 `symhash mod N vmap` 跳到 ids_g<group>（這些 chain 一直在，各一條 log … accept）；install()、start_inspection()、stop_inspection()、remove()；forwarded() 列有 FORWARDED_MARK 的連線
│   │   ├── hook.rs         XdpPolicy（xdp 設定）、CoreHook、core_hook() 選擇規則（2026-11-14 起 xdp 只決定之後算特徵的程式，核心程式一律 TCX）
│   │   └── ingress.rs      CoreProgram：attach(ports, mode) 設 CONFIG、PEER 再掛上；trust／untrust（兩個方向，FiveTuple ↔ FlowKey）、trusted（兩個方向配成一條，依方向欄位顯示）、packets／redirected；嵌入的 ELF（include_bytes! 包在 align(8) 的 struct，ELF 解析要對齊）、attach(ports)：載入後掛到每個 port 的 TCX ingress 第一位（LinkOrder::first）、id()、packets()；drop 時 aya 關掉 link 的 fd，kernel 就卸下（不 pin，wnc-gw 被 kill -9 也一樣）
│   ├── ids/                跟 IDS engine 打交道的薄模組（mod.rs 只放 pub mod）
│   │   ├── eve.rs          EVE 檔（只讀新增的部分）：EveFile（啟動時從檔尾開始；半行等寫完；被換掉時先讀完舊檔再從頭讀新檔；被截斷從頭讀；超過 1 MiB 的行丟掉；一次最多讀 32 MiB）、parse_alert()（先用字串判斷 event_type 是不是 alert 才解析，typed struct）、Alert、EveInterval（設定寫秒、可以有小數，0.05–10，預設 0.5；內部取到毫秒）
│   │   ├── delivery.rs     Delivery：Queue(QueueRange)（ips，等 Suricata 判決）或 Copy(GroupRange)（ids，NFLOG 送複本、kernel 照常轉送）；firewall 和 spawned 共用
│   │   ├── lifecycle.rs    Suricata 生命週期的介面：trait Lifecycle（next_event、allow_restart、stop）、Event（Ready、Stopped）、Exit；DEFAULT_READY_TIMEOUT
│   │   ├── spawned.rs      O14 的 (b)：wnc-gw 自己啟動 Suricata（NOTIFY_SOCKET 收 READY=1、輸出轉成 log、Stopped 之後等 allow_restart 再退避重啟、ready_timeout、stop_timeout（SIGTERM 後等多久才 SIGKILL，每 10 秒記一次 still stopping）、PR_SET_PDEATHSIG；--set 強制 runmode=workers、detect.delayed-detect=no、coredump.max-dump=0、stream.midstream=true、stream.midstream-policy=ignore、engine.init-failure-fatal=no（FORCED_SETTINGS）；Delivery::Queue 用 -q、強制 nfq.fail-open，exception policy 跟著 when_unavailable（exception_policies()）；Delivery::Copy 用 --nflog，每次啟動前在 runtime_dir 寫 suricata-nflog.yaml（每個 group 1 MB buffer、上限 4 MB）再 --include（會整個取代使用者 yaml 的 nflog 清單），強制 capture.checksum-validation=none（GRO 合併的封包 checksum 不完整），exception policy 一律 ignore；加 -v，Suricata 回報有規則載入失敗時記 WARN；工作目錄是 log 目錄）
│   │   └── suricata.rs     Suricata（路徑由設定決定）：--build-info → SuricataInfo（NFQueue、NFLOG、Systemd 支援）；--dump-config -c（可以帶 --set）→ SuricataConfig（規則路徑）；check_rule_files()；scan()：正在跑的 Suricata（RunningSuricata：Capture、Owner、是否同一個 network namespace；hidepid 時 others_hidden）
│   ├── monitor/            執行中定期檢查、決定要不要記 log（mod.rs 只放 pub mod）
│   │   ├── alerts.rs       AlertMonitor：每筆 alert 記 DEBUG（連線、flow_id、sid、規則名稱、action），每 60 秒有 alert 時記一行 INFO 摘要（筆數、flow 數、最多的前 5 個 sid）；讀不到 EVE（只記第一次和恢復）、被換掉、被截斷、讀不完、壞掉或超長的行；AlertWatch：EveFile＋每 eve_interval 秒的計時＋摘要計時，run 的事件迴圈呼叫 next()
│   │   ├── conntrack.rs    ConntrackMonitor（INTERVAL 10 秒）：第一次讀到時記筆數和上限；到上限 90% 記 WARN、降到 80% 以下記 INFO（中間不重複記）；drop、insert_failed 有增加記 WARN「conntrack dropped packets」，early_drop 有增加記 WARN「evicted」（每個 CPU 的 u32 計數用 wrapping_sub，只算兩次都有的 CPU）；讀取失敗只記第一次，恢復時記一次。判斷（observe）是純函式，記 log 另外一層
│   │   ├── tcx.rs          CoreWatch（INTERVAL 10 秒）：每個 port 查 TCX ingress（kernel::bpf::tcx_ingress），position() 純函式判斷 First／Behind(前面的 id)／Detached（含介面消失 ENODEV）／Unknown；只在改變時記：Behind WARN D002、Detached WARN D003、Unknown WARN D004、回到 First INFO
│   │   └── nflog.rs        CopyMonitor（INTERVAL 10 秒）：ids 時 Suricata 漏掉的複本（它的 NFLOG socket 的 Drops）增加就記 WARN「suricata missed packet copies; that traffic was forwarded without inspection」；換 pid（重啟）從 0 算起，找不到 socket、讀不到都只記第一次
│   ├── forwarding/         轉送模式：Mode、trait Forwarding（required_modules、check_environment、notes），bridge.rs（Bridged）、routed.rs（Routed：不在 bridge、ip_forward、IPv4 位址、網段不重疊、預設路由走 WAN，note 寫內網 gateway 和上游路由）；Level：Required（error）、Awaited（必要但可能還沒好，warning）、Recommended（warning）
│   ├── platform/           因 OS 而異的部分：每種差異一個 trait，每個 OS 一個 struct
│   │   ├── mod.rs          trait BootConfig、Dirs、Services（BootState）；pub use debian::Debian as Current（編譯時選 OS）
│   │   └── debian.rs       Debian：/etc/modules-load.d/、/etc/sysctl.d/；/run/wnc-gw、/var/log/wnc-gw；suricata.service、cgroup 對應服務、systemctl is-enabled
│   ├── system/             和 OS 的檔案權限、外部程式、單一實例鎖打交道的工具（2026-11-14 從頂層搬進來）
│   │   ├── access.rs       除了 root 之外誰能改某個路徑（檔案本身、每一層目錄、跟著 symlink 之後的實際位置）；/etc/passwd、/etc/group 查名稱
│   │   ├── command.rs      執行外部程式的共用部分：逾時 5 秒、kill_on_drop、寫 stdin、收 stdout 和 stderr（output()、run()、CommandError）
│   │   └── instance.rs     同一台機器只跑一個 wnc-gw：flock <runtime_dir>/wnc-gw.lock 並寫入 pid；InstanceError::AlreadyRunning 帶持有者的 pid
│   └── kernel/             跟 Linux kernel 打交道的薄模組
│       ├── mod.rs
│       ├── netif.rs        rtnetlink 列介面、sysfs 讀 driver、MacAddr、LinkStatus；ipv4_routing()：IPv4 位址、main table 的路由（NextHop、metric、RouteKind）、rule（是否無條件查表）→ Ipv4Routing、Ipv4Net
│       ├── bpf.rs          包住 aya 0.16：TcxProgram（load(elf, name)、attach_ingress_first(ifindex)、id()、per_cpu_sum(map)）、BpfError（aya 的錯誤轉成字串，error_chain() 串起 source 但跳過已經包含在訊息裡的）；aya 的型別不出現在對外介面。tcx_ingress(ifindex) → TcxChain（revision、依序的 prog id）：自己呼叫 bpf(BPF_PROG_QUERY)，只要 CAP_NET_ADMIN（aya 的 query_tcx 會順便用 id 拿 fd，要 CAP_SYS_ADMIN，privd 沒有）；QueryAttr 照 kernel bpf_attr 的 query 段排列，測試用 offset_of! 檢查；錯誤分成 NotPermitted（EPERM／EACCES）、Unsupported（EINVAL：沒有 TCX）、NoDevice（ENODEV）、Io。program_names()：aya 的 loaded_programs() 列出 id → 名稱，要 CAP_SYS_ADMIN，doctor 只拿來顯示
│       ├── conntrack.rs    手寫 ctnetlink（netlink-sys 的同步 Socket，non-blocking）：set_mark（只動 mask 內的位元）、set_marks（一次 100 筆，只有最後一筆要 ACK，回傳失敗的那幾筆）、get、list（kernel 依 mark 過濾）、stats（IPCTNL_MSG_CT_GET_STATS 的筆數和上限，加上 GET_STATS_CPU 每個 CPU 的 drop、early_drop、insert_failed；筆電 kernel 沒有 /proc/net/stat/nf_conntrack，所以不讀 procfs）；Stats、CpuStats；FiveTuple（兩個位址要同一版本）、Protocol、TcpState、Connection（含兩個方向的 Counters：封包數、bytes，要 nf_conntrack_acct = 1 才有）；任一方向的五元組都找到同一筆
│       ├── modules.rs      /proc/modules + modules.{builtin,dep} → ModuleState；RequiredModule
│       ├── netdev.rs       netdev genetlink：每個介面的 native XDP 功能（XdpFeatures）
│       ├── nflog.rs        GroupRange（[suricata] group：NFLOG 的 group 編號，不能是 0，預設 10）；netfilter_sockets(pid)：程序的 netfilter netlink socket 和它的 Drops（/proc/<pid>/fd 的 socket inode 對 /proc/net/netlink；nfnetlink_log 只有 root 讀得到）
│       ├── nfqueue.rs      QueueRange（queue 設定：0 或 "0-3"）
│       ├── procs.rs        /proc 裡 comm 符合的程序：State、PPid、cmdline、VmRSS、cgroup、network namespace（Process）；讀不到 status 就當成已經結束；others_hidden()：hidepid 而且不是 root
│       ├── nft.rs          Nft（路徑由設定決定）：自己的 Table/BaseChain/RegularChain/Statement（Counter、Jump、Queue、Drop、Accept、CtMarkHas、CtMarkLacks、CtMarkSet、CtMarkClear、TcpFlagsAny、TcpFlagsEq、Log、JumpBySymhash）型別，queue 範圍產生 symhash → nftables crate 的 JSON → nft -j -f -（有逾時）；replace_table、replace_rules（同一個 transaction 裡 flush chain 再加規則）、delete_table；nft -V → NftInfo
│       └── sysctl.rs       讀 /proc/sys（key 不存在時回傳 None）
└── tests/unit/             白箱單元測試，路徑鏡像 src/（見 §3.7）
```

## 2. 分層：程式該放哪裡

依「它跟誰打交道、代表什麼」分，不是依「什麼時候用到」分。

| 層 | 放什麼 | 不放什麼 |
|---|---|---|
| `cli/`（bin） | clap 參數、子命令的膠水：載入設定、呼叫 lib、印結果、決定結束碼 | 功能本體。之後的 daemon（privd、agent）不經過命令列，也要能呼叫同樣的功能 |
| `config/`（`mod.rs`） | 讀 `setting.toml`、合併 CLI 覆寫、驗證，產出完整的 `Config` | 查 kernel、判斷執行環境 |
| `config/ports.rs` | LAN/WAN 角色模型：把使用者的指定對應到 kernel 介面 | 讀設定檔（它只接收 `PortSpec`，不知道值從哪來） |
| `datapath/` | 只負責一件事：核心 eBPF 程式在每個 port 掛在哪裡，以及怎麼掛上去、拆下來。一個功能一個檔案：`hook.rs`（`xdp` 設定和 `core_hook()`，目前只有 doctor 用）；之後加 `ingress.rs`（`IngressHook` trait 的 `NativeXdp`、`Tc` 實作，階段 2）、`egress.rs`、`maps.rs`（ban、trust map 的讀寫） | bpf syscall 和載入、掛載的底層操作（`kernel/bpf/`）；使用者的 eBPF 外掛（另開 `plugins/`）；讀特徵 map、合併、送雲端（另開模組，例如 `telemetry/`）；依 bridge/routed 而不同的轉送方式（`forwarding/` 的 trait 方法） |
| `forwarding/` | 依轉送模式（bridge、routed）而不同的部分：`trait Forwarding` 和各模式的實作。目前提供環境檢查（`EnvCheck`）和模式需要的模組，只有 doctor 用到；之後各階段需要依模式而不同的功能時，在 trait 上加方法 | 兩種模式共用的邏輯（例如 nft 規則、netdev ingress 打方向 mark）；嚴重程度（由 doctor 決定） |
| `datapath/firewall.rs` | 我們的 nft table 要長什麼樣子（table 名稱、chain、hook、priority、policy、規則），以及安裝、移除、切換 queue。信任（ct mark）的規則在這裡，L2 規則一定要在它前面；之後的黑名單 set 也加在這裡，放在 `jump ids` 前面。只用 `kernel::nft` 自己的型別。動態內容（之後的 set）會被 `replace_table` 清掉，所以執行中只用 `replace_rules` 換單一 chain | 產生 JSON、執行 nft（`kernel/nft.rs`）；依 bridge/routed 而不同的部分（`forwarding/`）|
| `system/access.rs` | 檔案存取權的事實：哪些非 root 的帳號（擁有者、群組、所有人）能改某個路徑，包含每一層目錄和 symlink 的實際位置；sticky 目錄只算擁有者 | 判斷好壞（doctor 決定給 warning）；要檢查哪些檔案（doctor 決定） |
| `kernel/` | 在 user space 跟 kernel 溝通：netlink、sysfs、procfs；之後的 nft、conntrack、bpf 載入、sysctl | 判斷好壞或嚴重程度；LAN/WAN 等 gateway 概念；讀設定檔 |
| `ids/` | 跟 IDS engine 打交道：執行 Suricata、解析它的輸出，之後的 EVE、unix socket 也放這裡。整合方式是 A（2026-10-25 決定）：Suricata 是獨立的 process，不內嵌 libsuricata。`suricata.rs` 是探測（`--build-info`、`--dump-config`、規則檔、寫 alert 的 eve-log 檔，給 doctor 和 run 用）。`eve.rs` 讀 EVE 檔並解析 alert（EVE 是不可信的輸入：壞掉的行跳過並計數，字串只在 log 裡用 Debug 格式跳脫）。`lifecycle.rs` 是 O14 的生命週期介面，對外只有「已就緒」「已停止」兩種事件；`spawned.rs` 是 wnc-gw 自己啟動 Suricata 的實作，之後 systemd 管理的實作也實作同一個 trait。實作自己記 log（啟動、就緒、結束、退避），用介面的一方（`run`、之後的 queue 管理）只依事件行動，不重複記錄 | 判斷好壞或嚴重程度（由 doctor 決定）；把封包導進 queue 的 nft 規則（`firewall.rs`） |
| `agent/` | 3d 的判斷：讀連線和 alert、決定信任或撤銷；判斷寫成純函式（`observe()`、`alert()` 輸出 Decision），寫入經 `Privd` trait，記 log 另外一層。之後拆成無特權的 agent process 時，`Privd` 換成跨 process 的實作 | 直接碰 ctnetlink 或 nft（經 `Privd`）；讀 EVE 檔（`ids/eve.rs`） |
| `monitor/` | `run` 執行中定期讀 kernel 的計數，判斷要不要記 log、用什麼等級（目前是 conntrack、ids 漏掉的複本、Suricata 的 alert 摘要；之後 Suricata 跟不上被 fail-open 放行的封包數、3d 的狀態表大小也放這裡）。判斷寫成純函式（輸入上一次和這一次的數字，輸出發現的事），記 log 另外一層 | 讀取本身（`kernel/`）；doctor 的一次性檢查（表滿不滿是執行中的狀態，不是「能不能運作」） |
| `platform/` | 真正因 OS 而異的東西：設定怎麼在開機後保留、服務管理（systemd 對 procd）、設定來源（檔案對 UCI）。每種差異定一個 trait，每個 OS 一個 struct 實作全部 trait；`Current` 在編譯時指向目前的 OS。目前有 `BootConfig`（kernel 模組和 sysctl 寫在哪裡才會在開機後保留，給 doctor 的修法提示用）、`Dirs`（wnc-gw 自己的執行期目錄和 log 目錄：使用者不能改，但不同 OS 不同，例如 OpenWrt 的 `/var` 在記憶體裡）和 `Debian`。每個 OS 的實作一律編譯（`pub mod`），只有 `Current` 依 feature 選，所以每次建置都會測到所有 OS。新增 OS：加 `<os>.rs`、`tests/unit/platform/<os>.rs`、一個 cargo feature，再讓 `Current` 依 feature 選 | netlink、nft、eBPF、`modprobe`、`sysctl -w`、`ip link` 這類 kernel 介面和立即生效的指令：在每個 OS 上都一樣，屬於 `kernel/` 或直接寫在呼叫端；不是由 OS 決定的選擇（fast path 後端依 probe、IDS engine 依 O6）也不放這裡 |

規則：

- **依賴方向單向**：`cli → config → agent → forwarding / config::ports / datapath / monitor → kernel`（`agent` 用 `datapath` 的核心程式和 `datapath::firewall` 的 forwarded 位元、`ids::eve` 的 Alert）（`config` 只用到 `forwarding::Mode` 和 `PortSelector` 這類值型別，以及 `kernel::nft`、`ids::suricata` 的預設路徑）。`platform`、`ids`、`system` 和 `kernel` 一樣在最底層，不依賴其他模組。下層不認識上層的概念。
- **薄模組**：外部 crate 的型別（`rtnetlink`、`netlink-packet-route`，之後的 aya 等）不出現在模組對外的介面上，對外一律用自己的型別。升級或替換 crate 時只動那個模組。需要轉換時寫私有函式（例如 `from_link_message()`），不要對外實作 `From<外部型別>`。
- **kernel 層只翻譯、不判斷**：例如 `Interface::link_status()` 把 admin 與 oper 狀態翻成 `AdminDown`、`NoCarrier` 等原因；「NoCarrier 算 warning」是 doctor 的判斷。
- **lib 與 bin 分開**：功能模組只在 `lib.rs` 宣告，`main.rs` 只宣告 `mod cli;`，bin 用 `security_gateway::…` 引用 lib。同一個模組若被兩邊各宣告一次，會被編譯兩次，變成兩個不同的型別。
- **eBPF 程式本身**（在 kernel 裡執行的部分）不放 `src/`：之後以 workspace 成員新增獨立 crate（例如 `gw-ebpf/`、共用型別 `gw-common/`），現有 package 繼續當 workspace 根，不需要搬檔案。`src/kernel/bpf` 只放 user space 的載入與 map 讀寫。
- **權限邊界**：`kernel/` 裡的寫入操作（nft、conntrack、bpf、sysctl）需要 `CAP_NET_ADMIN`／`CAP_BPF`，之後會是 privd 的範圍；讀取（列介面、讀模組）不需要權限，doctor 可以用沒有權限的帳號執行。例外是 ctnetlink：連讀取（`trust list`）都要 `CAP_NET_ADMIN`。

## 3. 加功能時的慣例

### 3.1 型別與錯誤

- 在邊界就解析成型別（parse, don't validate）。例如 MAC 讀進來就是 `MacAddr`，`Config` 的欄位沒有 `Option`，缺值在 `config::load()` 就回傳 `ConfigError::Missing`，下游不用再檢查 `None`。
- 衍生出來的資料寫成方法，不另存欄位（例如 `link_status()` 從 `admin_up` 和 `oper_state` 推算），避免兩份資料不一致。
- 錯誤用 `thiserror` 定義 enum，讓呼叫者能分辨種類。
- 錯誤型別和產生它的程式放在同一個檔案，不集中成整個 crate 共用的 `error.rs`。同一個資料夾裡有兩個以上的檔案共用同一個錯誤時，才放進那個資料夾的 `error.rs`（例如之後的 `kernel/bpf/`）。要用 `?` 傳遞好幾種錯誤時，在需要的那一層定義包裝的 enum（`#[from]`）。
- **錯誤訊息一律英文**：小寫開頭、結尾不加句號；CLI 印出時前綴 `error: `（和 clap 一致）。測試的 assert 訊息也用英文。
- 會解析使用者輸入的型別實作 `FromStr`（clap 直接用），需要從設定檔讀的再實作 `Deserialize`（內部轉呼叫 `FromStr`）。`Display` 要能和 `FromStr` 互相轉回，並寫測試確認。

### 3.2 設定與 CLI

- 設定值的來源：CLI 優先，其次設定檔；兩邊都沒有時，有預設值的設定（例如 `mode`）用預設值並記成 `Source::Default`，沒有預設值的（例如 port）報錯。需要能被 CLI 覆寫的值，在 `Config` 裡寫成 `Setting<T>`（值加上 `Source`），doctor 會顯示來源。
- 新增設定欄位時要一起做五件事：
  1. `config/mod.rs` 的私有檔案格式 struct（已開 `deny_unknown_fields`，打錯欄位名稱會直接報錯）。
  2. `Config` 的對應欄位與合併邏輯。
  3. 只在某個選項下才有作用的欄位：`Config` 裡用 enum 分開（例如 `TrustSettings::Auto(AutoTrust)`、`Delivery`），不要放一個「有時沒用」的欄位；另一個選項下設了就在 `merge()` 加進 `ConfigError::Inapplicable`（C004）（2026-11-14，DECISIONS.md §21）。
  4. `setting.example.toml`：用英文說明，值**註解掉**（範本不能替使用者決定）。現有測試會確認範本原樣解析後什麼都沒設、去掉 `# ` 後能解析，但**新欄位沒寫進範本時測試抓不到**，要自己記得補。
  5. `tests/unit/config/mod.rs` 的測試。
- 只有跨子命令共用的參數才設成 `global = true`（例如 `--config`、`--lan`、`--wan`、`--log-format`）。
- 每個子命令都有自己的 `Args` struct，即使是空的，例如 `DoctorArgs {}`；之後加參數只要新增欄位。分類多的功能用巢狀子命令，例如 `wnc-gw show interfaces`。
- clap 的 `///` 是 `--help` 的說明文字，不只是註解。開發者傾向刪掉說明性註解；遇到時提醒這會讓 help 變空，由開發者決定，不要自己加回去。
- 預設路徑用絕對路徑（`/etc/wnc-gw/setting.toml`）：systemd 和 `docker exec` 的工作目錄都是 `/`。
- 會被執行或讀取的外部檔案（nft、Suricata、Suricata 的設定檔）路徑可以設定，型別用 `AbsolutePath`：相對路徑在讀設定檔時就報錯，因為 `Command::new("nft")` 這種沒有斜線的寫法會去 PATH 找。預設值寫在擁有它的模組（`kernel::nft::DEFAULT_PATH`、`ids::suricata::DEFAULT_PATH`、`DEFAULT_CONFIG`）。新增這類路徑時，也要加進 doctor 的 `check_access()`，讓 doctor 檢查非 root 帳號能不能改它。

### 3.3 系統路徑與常數

- 系統路徑寫成**私有 `const`，放在擁有它的模組開頭**（例如 `kernel/modules.rs` 的 `PROC_MODULES`）。不要集中到 `constants.rs`；只有別的模組也要用時才加 `pub`（例如 `config::DEFAULT_PATH`）。`Path` 不能寫成 const，寫 `&str`，用的時候再 `Path::new()`。
- 從外部拿到的字串要接成路徑前，先確認它不可能含 `/` 或 `..`（例如介面名稱已經由 kernel 的 `dev_valid_name` 保證）。

### 3.4 相依套件與執行環境

- async 用 tokio，單執行緒 runtime；feature 只開用得到的（目前是 `rt`、`macros`、`process`、`time`、`io-util`、`signal`、`sync`、`net`）。**`ids/spawned.rs` 依賴單執行緒 runtime**：`PR_SET_PDEATHSIG` 是在 fork 子程序的那個執行緒結束時觸發，改成多執行緒 runtime 時要重新檢查。
- `unsafe` 只用在沒有安全 API 的系統呼叫，目前是 `ids/spawned.rs` 的兩處和 `kernel/bpf.rs` 的一處（2026-11-14 開發者同意：`BPF_PROG_QUERY` 的 syscall，aya 沒有只拿 id 的公開 API）（`gw-ebpf/` 是在 kernel 裡跑的程式，讀寫 map 的值和封包指標都要 `unsafe`，記憶體安全由 kernel verifier 檢查，不算在這條裡）：`pre_exec` 裡的 `prctl(PR_SET_PDEATHSIG)`（fork 之後不能配置記憶體，錯誤只用 errno），以及送 SIGTERM 的 `kill`（送之前先 `try_wait`，避免 pid 已被回收再被別的程序使用）。透過 `libc` crate 呼叫。新增 `unsafe` 前先跟開發者確認。
- netlink 用 rust-netlink 系列（`rtnetlink` 等）。這一系列的版本必須彼此對齊（共用同一個 `netlink-packet-core`），升級時整組一起升，並用 `Cargo.lock` 鎖住。netdev family 用 `genetlink` + `netlink-packet-generic` 自己實作在 `kernel/netdev.rs`。**netdev 這類新 family 不要用 dump**：kernel 的 dump 回應不帶 `NLM_F_MULTI`，netlink-proto 收到第一則就認定請求結束，其他裝置會被默默漏掉；改成每個介面各送一次帶 ifindex 的請求。其他缺口：`ethtool` crate 只能讀 feature。**ctnetlink 是例外，手寫在 `kernel/conntrack.rs`**（2026-10-28，O17）：Pi 上 netlink-proto 設一筆 51 µs、netlink-packet-netfilter 編碼 20 µs、手寫 13 µs，讀一筆 crate 解碼 74 µs、手寫 20 µs（musl 的記憶體配置慢）。netlink-packet-netfilter 只放 dev-dependency，測試比對兩邊的位元組。之後頻繁呼叫的 netlink 操作也要先量，不要直接假設 crate 夠快。
- 呼叫外部程式用 `Command::new().arg()`，不組 shell 字串，並加逾時。用 tokio 的 `Command`，設 `kill_on_drop(true)`，再用 `tokio::time::timeout` 包住，逾時時子行程才會被砍掉。這些都集中在共用的 `system/command.rs`：`run()`（結束碼不是 0 就是 `Failed`）、`output()`（結束碼本身就是答案時用，例如 `systemctl is-enabled`）、`CommandError`（錯誤帶執行檔的路徑；`NftError`、`SuricataError` 是它的別名）。2026-10-27 有了第三個呼叫者（platform 的 systemctl）之後抽出來，新的外部程式一律用它，不要再寫一份 spawn 加逾時。執行檔用絕對路徑，不從 PATH 找：之後由有權限的 process 執行時，PATH 可能被換掉，而且 Pi 上一般帳號的 PATH 沒有 `/usr/sbin`。
- **eBPF 的工具鏈**（2026-11-14）：`gw-ebpf` 用 `nightly-2026-11-13`＋`rust-src` 和 bpf-linker 0.13.0（GitHub release 的 musl 預編 binary，不用 cargo install：要綁 LLVM 23）；wnc-gw 本身照樣是 stable（aya 0.16 要 1.98）。換 nightly 日期時改 `build.rs` 的 `EBPF_TOOLCHAIN`，並在 Docker 和 Pi 重新驗證。aya-ebpf 0.3.0 的 TCX 回傳值在 `bindings::tcx_action_base::TCX_NEXT`。ELF 帶程式自己的 BTF（`-Clink-arg=--btf`），Pi（沒有 vmlinux BTF）上載入正常（`btf_id` 有值）。**寫 eBPF 要能在沒有 CAP_PERFMON 時通過 verifier**（之後的 privd 沒有，Pi 的 root 有，所以 Pi 上測不出來；筆電容器只給 NET_ADMIN、BPF 就能重現）：struct 不要先清成 0 再填（會變 memset 迴圈），key 不放 byte 陣列；封包的變數 offset 用 `ctx.load()`（bpf_skb_load_bytes），常見位置用固定 offset 直接讀（`tests/ebpf/README.md`）。成本（A3）：進 TCX 約 0.52 µs／封包，計數 +47 ns，解析＋查表 +449 ns。
- 新增 crate 前，用全域需求評估（之後是否還會用到、是否純 Rust、能否編 musl/aarch64、維護狀態、授權）。

### 3.5 log

- 用 `tracing`（`tracing-subscriber` 只開 `fmt`、`std`、`ansi`、`json`）。lib 只用 `info!`、`warn!`、`error!` 這類 macro 發出事件，**不設定輸出**；輸出由 bin 的 `cli/logging.rs` 決定，目前 `run` 和 `trust add/del` 會呼叫 `init()`。
- **格式**：`--log-format text|json`（全域參數，預設 text，2026-10-29）。放命令列而不是 setting.toml：log 在讀設定檔之前就開始（讀設定失敗也要記），而且格式取決於誰讀輸出，是執行環境的事。json 每行一個物件，欄位攤平在最外層（`{"timestamp":…,"level":"INFO","message":…,"uninspected_ms":97}`），數字欄位是 JSON 數字，不輸出 target 和 span。doctor 的報告（stdout）和 CLI 的 `error: …`（例如 `trust add` 找不到連線）不是事件，維持純文字；分析 `run` 的 log 時只讀 stderr。
- **報告和事件分開**：doctor 的報告印在 stdout（它是報告，見 `references/doctor-checks.md` §2）；`run` 這類長時間執行的命令，過程中發生的事一律記成事件，印在 stderr。用 systemd 執行時 stderr 直接進 journald。
- **每個 WARN、ERROR 事件的第一個欄位是 `code = %Issue::X`**（2026-11-14），`wnc-gw explain` 查得到說明；`tests/unit/issue.rs` 會掃 `src/`，漏了就失敗。新的事件要在 `src/issue.rs` 加 variant 和 cause／action。INFO、DEBUG 不用。
- 訊息照錯誤訊息的規則：英文、小寫開頭、結尾不加句號。會變的值放欄位，不要塞進訊息：`info!(table = table.as_str(), "table installed")`，錯誤放 `error = %e`。欄位名稱用 snake_case，有單位的寫在名稱裡（`ready_ms`、`uptime_s`）。字串欄位用 `as_str()` 記錄，輸出時會加引號，含空白也不會跟其他欄位混在一起。
- **會讓流量沒經過檢查的事件，一定要記**（開發者 2026-10-26 的要求）：Suricata 啟動、就緒、結束（結束碼或 signal、執行多久）、重啟，以及 queue 規則的裝上和拆掉。「從什麼時候到什麼時候沒有檢查」要能直接從 log 讀出來：目前是 WARN「forwarded traffic passes without inspection」（或 `is dropped without inspection`）到 INFO「forwarded traffic is inspected」（帶 `uninspected_ms`）。
- 時間是 UTC。Pi 沒有校時時，log 的時間不可信（2026-10-26 時 Pi 慢了 6 天）。
- **log 存在哪裡**：wnc-gw 不自己寫檔案。Debian 上由 systemd unit 的 `LogNamespace=wnc-gw` 保存（O15，2026-10-26 決定，寫 unit 時實作）；開發時直接跑 `run` 要自己導向，例如 `2> run.log`。
- 還沒做：在 journald 底下省略重複的時間（寫 systemd unit 時再加）、用設定調整等級（目前固定 INFO）。

### 3.6 註解

開發者偏好精簡的程式碼，「為什麼這樣寫」放在對話裡說明。只在不寫會被誤用或誤改的地方留簡短註解（中文即可），例如安全假設、反直覺的寫法（`from_str_radix` 接受 `"+f"`）。

### 3.7 測試

- 白箱單元測試放 `tests/unit/<與 src 相同的路徑>.rs`。src 檔案結尾只留三行：

  ```rust
  #[cfg(test)]
  #[path = "../../tests/unit/config/ports.rs"]   // 路徑相對於這個 src 檔所在的目錄（這是 src/config/ports.rs）
  mod tests;
  ```

  例如 `src/kernel/modules.rs` 用 `"../../tests/unit/kernel/modules.rs"`，`src/cli/doctor.rs` 用 `"../../tests/unit/cli/doctor.rs"`。測試檔用 `use super::*;`，所以私有函式也測得到。
- 不要把測試寫在 src 檔案裡，也不要為了測試把函式改成 `pub`（那會讓外部 crate 的型別流出薄模組）。
- `tests/*.rs` 和 `tests/*/main.rs` 會被 Cargo 當成整合測試（黑箱，只看得到 `pub`）。`tests/unit/` 不會被自動偵測，所以不衝突。之後的黑箱測試放在 `tests/` 的另一個子目錄，名稱跟開發者確認。
- 把 I/O 和邏輯分開，讓邏輯可以餵假資料測：例如 `ModuleIndex::load()` 讀檔，`from_parts()` 只解析字串；`config::load()` 讀檔，`parse()`、`merge()` 是純函式。
- 預期文字裡跟 OS 有關的部分用 `Current` 產生（例如 `Current.persist_module_hint("br_netfilter")`），各 OS 的完整文字只在 `tests/unit/platform/<os>.rs` 逐字檢查。這樣換 OS 建置時，其他測試不用改。
- 要讓 repo 內的檔案和程式保持同步時，用 `include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/…"))` 在測試裡讀進來檢查（`setting.example.toml` 就是這樣）。

### 3.8 use

- 同一個 crate、同一個第一層模組的 import 合成一條（2026-11-14，開發者要求）：`use security_gateway::ids::{delivery::Delivery, lifecycle::{Event, Lifecycle}, spawned};`，不要一條 `security_gateway::ids::delivery::…`、一條 `security_gateway::ids::lifecycle::…`。不同的第一層模組分開寫（`std::io` 和 `std::path` 是兩條）。
- 群組照原本的順序、用空行分開：std（`core`）→ 外部 crate → 本 crate（`crate::`、`super::`）；bin 裡 `security_gateway::…` 和外部 crate 放同一群，依字母排。
- 項目照 ASCII 排序、`self` 放第一個；一行超過 120 字元就斷行，每行縮排 4 格、結尾逗號；巢狀的群組本身太長時在裡面再縮排一層。
- 專案沒有用 rustfmt（程式是手排的，`cargo fmt` 會改到幾百處），所以這條要自己照著寫。`pub use`（mod.rs 的 re-export）和函式裡的 `use` 不受這條限制。

## 4. 新功能要配上 doctor 檢查

`wnc-gw doctor` 的定義是「載入設定後，檢查 gateway 能不能正確運作」。新功能如果依賴 kernel 模組、外部程式、sysctl 或硬體能力，就要在 doctor 補上檢查。安裝套件可能被誤刪、kernel 更新後可能少了模組，所以檢查的是**能力**，而且每次執行都檢查。

做法（探測／判斷分離、嚴重程度、輸出位置、需求清單、延後的檢查）見 **`references/doctor-checks.md`**。動手加任何檢查前先讀它。

## 5. 驗證：先 Docker，再 Pi

所有步驟（包括只讀的）都先在 Docker testbed 驗證，才搬到 Pi。Docker 共用筆電的 kernel，有些問題在 Docker 裡會被掩蓋，必須刻意設計情境才測得出來。

建置與掛載方式、testbed 拓樸、常用的模擬情境（介面關閉、沒有 carrier、歧義、模組）、Docker 和 Pi 的差異清單、Pi 的注意事項，見 **`references/testbed.md`**。

## 6. 收尾

- `cargo build --target x86_64-unknown-linux-musl` 沒有 warning，`cargo test --target x86_64-unknown-linux-musl` 全部通過。
- Docker 驗證要包含**失敗路徑**（錯誤的設定、找不到、缺少），不只是正常情況。測試用的介面、檔案用完要清掉，最後確認 cli→srv 仍然 ping 得通。
- 回報時分清楚：哪些在 Docker 驗過、哪些只有單元測試、哪些要到 Pi 才能確認。改了開發者的決定或自己替開發者做了選擇時，明確說出來。
- commit 只放這次相關的路徑；repo 裡常有開發者其他未提交的修改（`research/`、`.claude/`、`tests/dataset/`），不要一起帶進去。commit 和 push 都要開發者明確說了才做，授權只限那一次。
