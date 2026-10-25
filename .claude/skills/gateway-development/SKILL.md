---
name: gateway-development
description: 在 security_gateway/（執行檔 wnc-gw）加功能或改程式時的實作慣例：程式該放哪一層（cli/、config、ports、forwarding/、datapath/、kernel/、platform/，之後的 ids/）、型別與英文錯誤訊息怎麼寫、設定欄位與 CLI 參數怎麼加、單元測試放 tests/unit/ 並鏡像 src、新功能要在 wnc-gw doctor 補哪些檢查，以及「先在 Docker testbed 驗證、再上 Pi」的流程。只要要在 wnc-gw 新增或修改子命令、setting.toml 欄位、kernel 互動（netlink、sysfs、procfs、nftables、conntrack、eBPF 載入）、doctor 檢查或測試，或要在 Docker／Pi 上驗證 gateway，都先讀這份 skill，即使使用者只說「加一個功能」「檢查一下環境」「接下來做 X」。目標架構與安全底線另見 gateway-architecture。
---

# wnc-gw 開發指南

這份 skill 描述**現在的程式長什麼樣子，以及要怎麼往上加**。目標架構、插件點與安全底線在 `gateway-architecture`；兩份都適用時一起讀。內容反映 2026-10-25（commit `24b6710` 之後，加上 `wnc-gw run` 和 `firewall.rs`）的狀態，程式之後若有變動，以實際程式碼為準，並回頭更新這份 skill。

## 0. 動手之前

- **`.claude/CLAUDE.md` 的工作方式優先。** 先說明要做什麼、為什麼、有哪些選項，取得開發者同意才寫程式；一次只做一步；開發者問「為什麼」「這是什麼」時只解釋，不改程式。開發者說「可以」「好」之前，不要先動手。
- **用全域需求比較方案。** 不要只看「這一步」的成本，要列出這個模組之後所有已知的需求再比較。目標是後面的步驟只新增、不改寫前面的程式。依賴未決事項的部分要明說，並先把對外的型別定住。
- **程式不替使用者做決定。** 例如哪張網卡是 LAN/WAN 一律由使用者指定，有歧義就報錯、把決定交回使用者，不用啟發式規則去猜。相反地，**系統事實**（例如 kernel 從哪裡載入模組）要照實回報，不提供讓使用者覆寫的選項，否則檢查結果會和實際行為脫鉤。
- 待決事項先給選項分析（好處、代價、我的傾向），不要只問「選哪個」。

## 1. 現在的結構

```
security_gateway/
├── Cargo.toml              package = security_gateway（lib 名稱），[[bin]] name = "wnc-gw"
├── setting.example.toml    設定檔範本：說明用英文，所有值預設註解掉
├── src/
│   ├── main.rs             #[tokio::main(flavor = "current_thread")]，只呼叫 cli::run()
│   ├── cli/                ← bin：只放參數與膠水
│   │   ├── mod.rs          Cli（全域參數 -c/--config、--lan、--wan）、Command、run()
│   │   ├── doctor.rs       doctor：載入設定 → passes()（各項檢查、印報告，沒有 error 才回傳 true）→ 結束碼
│   │   ├── run.rs          run：載入設定 → doctor::passes()，有 error 就不啟動 → 先註冊 SIGINT/SIGTERM → 安裝 table → 等訊號 → 移除 table
│   │   └── show/           show 的巢狀子命令（mod.rs 分派，interfaces.rs 列介面）
│   ├── lib.rs              只宣告功能模組：config、datapath、firewall、forwarding、kernel、platform、ports
│   ├── config.rs           setting.toml + CLI 覆寫 → Config（每個值帶 Source）
│   ├── datapath/           核心 eBPF 程式在每個 port 掛在哪、怎麼掛（mod.rs 只放 pub mod / pub use）
│   │   └── hook.rs         XdpPolicy（xdp 設定）、CoreHook、core_hook() 選擇規則
│   ├── firewall.rs         我們自己的 nft table（inet wnc_gw）長什麼樣子；install()、remove()
│   ├── ports.rs            Role、PortSelector（名稱或 MAC）、resolve()
│   ├── forwarding/         轉送模式：Mode、trait Forwarding，bridge.rs（Bridged）、routed.rs（Routed）
│   ├── platform/           因 OS 而異的部分：每種差異一個 trait，每個 OS 一個 struct
│   │   ├── mod.rs          trait BootConfig；pub use debian::Debian as Current（編譯時選 OS）
│   │   └── debian.rs       Debian：/etc/modules-load.d/、/etc/sysctl.d/
│   └── kernel/             跟 Linux kernel 打交道的薄模組
│       ├── mod.rs
│       ├── netif.rs        rtnetlink 列介面、sysfs 讀 driver、MacAddr、LinkStatus
│       ├── modules.rs      /proc/modules + modules.{builtin,dep} → ModuleState；RequiredModule
│       ├── netdev.rs       netdev genetlink：每個介面的 native XDP 功能（XdpFeatures）
│       ├── nft.rs          自己的 Table/BaseChain/Statement 型別 → nftables crate 的 JSON → nft -j -f -（有逾時）；nft -V → NftInfo
│       └── sysctl.rs       讀 /proc/sys（key 不存在時回傳 None）
└── tests/unit/             白箱單元測試，路徑鏡像 src/（見 §3.6）
```

## 2. 分層：程式該放哪裡

依「它跟誰打交道、代表什麼」分，不是依「什麼時候用到」分。

| 層 | 放什麼 | 不放什麼 |
|---|---|---|
| `cli/`（bin） | clap 參數、子命令的膠水：載入設定、呼叫 lib、印結果、決定結束碼 | 功能本體。之後的 daemon（privd、agent）不經過命令列，也要能呼叫同樣的功能 |
| `config.rs` | 讀 `setting.toml`、合併 CLI 覆寫、驗證，產出完整的 `Config` | 查 kernel、判斷執行環境 |
| `ports.rs` | LAN/WAN 角色模型：把使用者的指定對應到 kernel 介面 | 讀設定檔（它只接收 `PortSpec`，不知道值從哪來） |
| `datapath/` | 只負責一件事：核心 eBPF 程式在每個 port 掛在哪裡，以及怎麼掛上去、拆下來。一個功能一個檔案：`hook.rs`（`xdp` 設定和 `core_hook()`，目前只有 doctor 用）；之後加 `ingress.rs`（`IngressHook` trait 的 `NativeXdp`、`Tc` 實作，階段 2）、`egress.rs`、`maps.rs`（ban、trust map 的讀寫） | bpf syscall 和載入、掛載的底層操作（`kernel/bpf/`）；使用者的 eBPF 外掛（另開 `plugins/`）；讀特徵 map、合併、送雲端（另開模組，例如 `telemetry/`）；依 bridge/routed 而不同的轉送方式（`forwarding/` 的 trait 方法） |
| `forwarding/` | 依轉送模式（bridge、routed）而不同的部分：`trait Forwarding` 和各模式的實作。目前提供環境檢查（`EnvCheck`）和模式需要的模組，只有 doctor 用到；之後各階段需要依模式而不同的功能時，在 trait 上加方法 | 兩種模式共用的邏輯（例如 nft 規則、netdev ingress 打方向 mark）；嚴重程度（由 doctor 決定） |
| `firewall.rs` | 我們的 nft table 要長什麼樣子（table 名稱、chain、hook、priority、policy、規則），以及安裝、移除。之後的 NFQUEUE、ct mark、黑名單 set 都加在這裡。只用 `kernel::nft` 自己的型別 | 產生 JSON、執行 nft（`kernel/nft.rs`）；依 bridge/routed 而不同的部分（`forwarding/`）|
| `kernel/` | 在 user space 跟 kernel 溝通：netlink、sysfs、procfs；之後的 nft、conntrack、bpf 載入、sysctl | 判斷好壞或嚴重程度；LAN/WAN 等 gateway 概念；讀設定檔 |
| `ids/`（尚未建立） | IDS engine 的 adapter（EVE、unix socket、探測）。Suricata 的整合方式 A/B/C 還沒決定，見 `research/literature/trust-bypass/suricata-integration.md` §9 | — |
| `platform/` | 真正因 OS 而異的東西：設定怎麼在開機後保留、服務管理（systemd 對 procd）、設定來源（檔案對 UCI）。每種差異定一個 trait，每個 OS 一個 struct 實作全部 trait；`Current` 在編譯時指向目前的 OS。目前只有 `BootConfig`（kernel 模組和 sysctl 寫在哪裡才會在開機後保留，給 doctor 的修法提示用）和 `Debian`。每個 OS 的實作一律編譯（`pub mod`），只有 `Current` 依 feature 選，所以每次建置都會測到所有 OS。新增 OS：加 `<os>.rs`、`tests/unit/platform/<os>.rs`、一個 cargo feature，再讓 `Current` 依 feature 選 | netlink、nft、eBPF、`modprobe`、`sysctl -w`、`ip link` 這類 kernel 介面和立即生效的指令：在每個 OS 上都一樣，屬於 `kernel/` 或直接寫在呼叫端；不是由 OS 決定的選擇（fast path 後端依 probe、IDS engine 依 O6）也不放這裡 |

規則：

- **依賴方向單向**：`cli → config → forwarding / ports / firewall → kernel`（`config` 只用到 `forwarding::Mode` 和 `PortSelector` 這類值型別）。`platform` 和 `kernel` 一樣在最底層，不依賴其他模組。下層不認識上層的概念。
- **薄模組**：外部 crate 的型別（`rtnetlink`、`netlink-packet-route`，之後的 aya 等）不出現在模組對外的介面上，對外一律用自己的型別。升級或替換 crate 時只動那個模組。需要轉換時寫私有函式（例如 `from_link_message()`），不要對外實作 `From<外部型別>`。
- **kernel 層只翻譯、不判斷**：例如 `Interface::link_status()` 把 admin 與 oper 狀態翻成 `AdminDown`、`NoCarrier` 等原因；「NoCarrier 算 warning」是 doctor 的判斷。
- **lib 與 bin 分開**：功能模組只在 `lib.rs` 宣告，`main.rs` 只宣告 `mod cli;`，bin 用 `security_gateway::…` 引用 lib。同一個模組若被兩邊各宣告一次，會被編譯兩次，變成兩個不同的型別。
- **eBPF 程式本身**（在 kernel 裡執行的部分）不放 `src/`：之後以 workspace 成員新增獨立 crate（例如 `gw-ebpf/`、共用型別 `gw-common/`），現有 package 繼續當 workspace 根，不需要搬檔案。`src/kernel/bpf` 只放 user space 的載入與 map 讀寫。
- **權限邊界**：`kernel/` 裡的寫入操作（nft、conntrack、bpf、sysctl）需要 `CAP_NET_ADMIN`／`CAP_BPF`，之後會是 privd 的範圍；讀取（列介面、讀模組）不需要權限，doctor 可以用沒有權限的帳號執行。

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
- 新增設定欄位時要一起做四件事：
  1. `config.rs` 的私有檔案格式 struct（已開 `deny_unknown_fields`，打錯欄位名稱會直接報錯）。
  2. `Config` 的對應欄位與合併邏輯。
  3. `setting.example.toml`：用英文說明，值**註解掉**（範本不能替使用者決定）。現有測試會確認範本原樣解析後什麼都沒設、去掉 `# ` 後能解析，但**新欄位沒寫進範本時測試抓不到**，要自己記得補。
  4. `tests/unit/config.rs` 的測試。
- 只有跨子命令共用的參數才設成 `global = true`（例如 `--config`、`--lan`、`--wan`）。
- 每個子命令都有自己的 `Args` struct，即使是空的，例如 `DoctorArgs {}`；之後加參數只要新增欄位。分類多的功能用巢狀子命令，例如 `wnc-gw show interfaces`。
- clap 的 `///` 是 `--help` 的說明文字，不只是註解。開發者傾向刪掉說明性註解；遇到時提醒這會讓 help 變空，由開發者決定，不要自己加回去。
- 預設路徑用絕對路徑（`/etc/wnc-gw/setting.toml`）：systemd 和 `docker exec` 的工作目錄都是 `/`。

### 3.3 系統路徑與常數

- 系統路徑寫成**私有 `const`，放在擁有它的模組開頭**（例如 `kernel/modules.rs` 的 `PROC_MODULES`）。不要集中到 `constants.rs`；只有別的模組也要用時才加 `pub`（例如 `config::DEFAULT_PATH`）。`Path` 不能寫成 const，寫 `&str`，用的時候再 `Path::new()`。
- 從外部拿到的字串要接成路徑前，先確認它不可能含 `/` 或 `..`（例如介面名稱已經由 kernel 的 `dev_valid_name` 保證）。

### 3.4 相依套件與執行環境

- async 用 tokio，單執行緒 runtime；feature 只開用得到的（目前是 `rt`、`macros`、`process`、`time`、`io-util`、`signal`）。
- netlink 用 rust-netlink 系列（`rtnetlink` 等）。這一系列的版本必須彼此對齊（共用同一個 `netlink-packet-core`），升級時整組一起升，並用 `Cargo.lock` 鎖住。netdev family 用 `genetlink` + `netlink-packet-generic` 自己實作在 `kernel/netdev.rs`。**netdev 這類新 family 不要用 dump**：kernel 的 dump 回應不帶 `NLM_F_MULTI`，netlink-proto 收到第一則就認定請求結束，其他裝置會被默默漏掉；改成每個介面各送一次帶 ifindex 的請求。其他缺口：`ethtool` crate 只能讀 feature；ctnetlink 只有封包型別。
- 呼叫外部程式用 `Command::new().arg()`，不組 shell 字串，並加逾時。用 tokio 的 `Command`，設 `kill_on_drop(true)`，再用 `tokio::time::timeout` 包住，逾時時子行程才會被砍掉（`kernel/nft.rs` 的 `run()`）。執行檔用絕對路徑，不從 PATH 找：之後由有權限的 process 執行時，PATH 可能被換掉，而且 Pi 上一般帳號的 PATH 沒有 `/usr/sbin`。
- 新增 crate 前，用全域需求評估（之後是否還會用到、是否純 Rust、能否編 musl/aarch64、維護狀態、授權）。

### 3.5 註解

開發者偏好精簡的程式碼，「為什麼這樣寫」放在對話裡說明。只在不寫會被誤用或誤改的地方留簡短註解（中文即可），例如安全假設、反直覺的寫法（`from_str_radix` 接受 `"+f"`）。

### 3.6 測試

- 白箱單元測試放 `tests/unit/<與 src 相同的路徑>.rs`。src 檔案結尾只留三行：

  ```rust
  #[cfg(test)]
  #[path = "../tests/unit/ports.rs"]   // 路徑相對於這個 src 檔所在的目錄
  mod tests;
  ```

  例如 `src/kernel/modules.rs` 用 `"../../tests/unit/kernel/modules.rs"`，`src/cli/doctor.rs` 用 `"../../tests/unit/cli/doctor.rs"`。測試檔用 `use super::*;`，所以私有函式也測得到。
- 不要把測試寫在 src 檔案裡，也不要為了測試把函式改成 `pub`（那會讓外部 crate 的型別流出薄模組）。
- `tests/*.rs` 和 `tests/*/main.rs` 會被 Cargo 當成整合測試（黑箱，只看得到 `pub`）。`tests/unit/` 不會被自動偵測，所以不衝突。之後的黑箱測試放在 `tests/` 的另一個子目錄，名稱跟開發者確認。
- 把 I/O 和邏輯分開，讓邏輯可以餵假資料測：例如 `ModuleIndex::load()` 讀檔，`from_parts()` 只解析字串；`config::load()` 讀檔，`parse()`、`merge()` 是純函式。
- 預期文字裡跟 OS 有關的部分用 `Current` 產生（例如 `Current.persist_module_hint("br_netfilter")`），各 OS 的完整文字只在 `tests/unit/platform/<os>.rs` 逐字檢查。這樣換 OS 建置時，其他測試不用改。
- 要讓 repo 內的檔案和程式保持同步時，用 `include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/…"))` 在測試裡讀進來檢查（`setting.example.toml` 就是這樣）。

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
