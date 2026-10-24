# 加 doctor 檢查

現有的實作在 `src/cli/doctor.rs`、`src/kernel/modules.rs`、`src/kernel/netif.rs`。加新檢查之前，先讀這三個檔案，照同樣的形狀寫。

## 目錄
1. 嚴重程度與結束碼
2. 輸出放哪裡
3. 一個檢查分兩半：探測與判斷
4. 加一個檢查的步驟
5. 需求清單：只需要加一筆的情況
6. 判斷原則
7. 已知但延後的檢查

## 1. 嚴重程度與結束碼

| 嚴重程度 | 意思 | 結束碼 | 例子 |
|---|---|---|---|
| `Error` | gateway 無法被正確設定或運作 | 1 | 設定檔錯誤、port 找不到或有歧義、必要的 kernel 模組 missing |
| `Warning` | 執行環境的暫時狀態，修好後 gateway 不用重啟就能運作；或無法確認 | 0 | link down、沒有 carrier、模組狀態 unknown |
| `Note` | 資訊，不需要處理 | 0 | driver 不回報 link 狀態（`UNKNOWN`） |

為什麼 link down 不算 error：之後 systemd 會在啟動 gateway 前跑 doctor，並以結束碼決定要不要啟動。gateway 串在網路中間，如果因為開機時線沒插好就拒絕啟動，等線插上之後網路會整個不通，或流量完全沒被檢查。

訊息要說明**怎麼修**，不只說出了什麼問題，例如 `bring it up with: ip link set eth1 up`。

## 2. 輸出放哪裡

- **stdout**：檢查報告，包括每一段的表格，以及最後集中印出的 `error:`、`warning:`、`note:`。設定檔錯誤也算報告的一部分。
- **stderr**：只有 doctor 自己沒辦法完成檢查時才用，例如 netlink 連線失敗。

這樣做的理由：透過 `docker exec` 或 SSH 執行時，stdout 和 stderr 是分開傳回來的，先後順序沒有保證。放在同一條管道，報告的順序才會固定，`wnc-gw doctor > report.txt` 也能存下完整內容。

報告的格式：

```
config: …                 ← 設定檔來源

<各檢查的段落，每段一個表格，段與段之間空一行>

error: …                  ← 全部 finding 集中印在最後，依檢查的順序
warning: …
```

## 3. 一個檢查分兩半：探測與判斷

| 半邊 | 放在哪裡 | 做什麼 | 怎麼測 |
|---|---|---|---|
| **探測**（probe） | lib，依它接觸的對象分層：kernel 的事放 `kernel/`，IDS 的事放 `ids/` | 只蒐集事實，回傳自己的型別。不判斷好壞 | 把 I/O 和解析拆開：解析函式吃字串，單元測試餵假資料；I/O 的部分在 Docker 或真機上跑 |
| **判斷**（judge） | `cli/doctor.rs` | 把事實轉成 `Finding`（嚴重程度加訊息） | 寫成純函式，單元測試直接餵事實 |

為什麼要分開：同樣的事實之後 daemon 也會用到（例如 link 狀態改變時要重新對應 port），但 daemon 的反應和 doctor 不同。嚴重程度是 doctor 自己的規則，不能放進 lib。

範例對照：

| 檢查 | 探測 | 判斷 |
|---|---|---|
| port 的 link 狀態 | `Interface::link_status()` → `LinkStatus` | `link_finding()` |
| kernel 模組 | `ModuleIndex::load()`、`state()` → `ModuleState` | `module_findings()` |

## 4. 加一個檢查的步驟

以「之後要檢查 X」為例：

1. **確認這個檢查現在就該做。** 對照 §7：它依賴的決定已經做了嗎？還沒有就先不做，把它記在 §7。
2. **探測**：在對應的 lib 模組寫一個回傳事實的函式，事實用自己的 enum 或 struct 表示。
   - 需要讀的系統路徑寫成模組開頭的私有 `const`。
   - 一次讀完所需資料，之後只查記憶體（`ModuleIndex` 就是這樣）。
   - 拿不到資料、無法判斷時，要有能表達「不知道」的值（例如 `ModuleState::Unknown`），不要默默當成「有」或「沒有」。
   - 探測本身失敗（例如讀不到 `/proc/modules`）時，回傳錯誤。在 doctor 裡把它轉成 `Warning`（`could not check …`），其他檢查照常進行。
3. **判斷**：在 `doctor.rs` 寫：
   - `check_x() -> Vec<Finding>`：呼叫探測、印出自己那一段表格、回傳 finding。
   - `x_findings(...) -> Vec<Finding>`：純函式，只負責事實轉 finding。
4. **接上**：在 `run()` 裡加一行 `findings.extend(check_x());`，位置放在相關段落的後面。
5. **測試**：
   - 探測的解析放在 `tests/unit/<lib 路徑>.rs`。
   - 判斷的規則放在 `tests/unit/cli/doctor.rs`，每個嚴重程度至少一個例子，並檢查完整的訊息文字。
6. **在 Docker 驗證**：正常情況，加上能模擬的失敗情況（見 `testbed.md`）。不能模擬的失敗（例如拿掉正在執行的 kernel 的模組）就靠單元測試，並在回報時說明。
7. **確認 Docker 和 Pi 的差異**：容器用的是筆電的 kernel，Docker 的結果不代表 Pi。回報時列出哪些項目要到 Pi 上再確認。

## 5. 需求清單：只需要加一筆的情況

新功能需要某個 kernel 模組時，不用寫新的檢查，只要在 `doctor.rs` 的 `REQUIRED_MODULES` 加一筆名稱和用途：

```rust
RequiredModule {
    name: "br_netfilter",
    purpose: "filtering bridged traffic",
},
```

用途會顯示在表格的 NEEDED FOR 欄和錯誤訊息裡，要寫成讓部署的人看得懂「為什麼需要它」。「為什麼需要」只寫在 `purpose` 這一個地方，不要另外加註解重複說明。

之後如果出現其他「同一種東西的清單」（例如需要的 sysctl 值），照同樣的形狀做：一個 `const` 清單，加上一個檢查函式。

## 6. 判斷原則

- **檢查能力，不檢查套件或版本號。** 例如 Suricata 要看有沒有編進 NFQueue 支援，不是看套件有沒有裝、版本是不是 8.0.7。只有在不同版本的行為真的不同、會影響我們的用法時，才把那個能力列成檢查項目（例如只有 8.0 才有 flow callback）。這是一個彈性框架，不鎖定實驗環境的版本。
- **跟實際會用到的那一方看同一份資料。** 例如模組要看 `modprobe` 會讀的 `/lib/modules/<uname -r>`，因為 kernel 自動載入時就是透過它。不要提供讓使用者改路徑的選項，否則 doctor 說可以、實際卻載入失敗。
- **用正在跑的狀態判斷。** 例如用 `/proc/sys/kernel/osrelease` 找模組目錄，而不是「最新安裝的 kernel」。kernel 更新後還沒重開機的情況，才不會被誤判成沒問題。
- **判斷不了就說判斷不了**（`Unknown` 加上 `Warning`），不要誤報 `Missing`，更不能誤報沒問題。

## 7. 已知但延後的檢查

| 檢查 | 等哪個決定 | 決定之後要做的 |
|---|---|---|
| Suricata | 整合方式 A/B/C（`suricata-integration.md` §9） | A：找到執行檔，並確認 `--build-info` 有 `NFQueue support: yes`，版本只顯示不判斷。B：plugin 必須和 Suricata 的 major.minor 一致，要檢查版本。C：檢查我們連結的 libsuricata 和規則目錄。新的探測放在 `ids/suricata.rs`；呼叫外部程式要加逾時（tokio 要開 `process`、`time`） |
| `nft` 執行檔 | O4：用 nft JSON 呼叫執行檔，還是直接走 netlink | 走 JSON 才需要 |
| `nf_conntrack_netlink` 模組 | N5：改 ct mark 用 ctnetlink 還是 nft set | 用 ctnetlink 才加進 `REQUIRED_MODULES` |
| sysctl、bridge 相關模組 | D3 已決定（2026-10-24），下一步實作 | L3：`net.ipv4.ip_forward`；L2：兩個 port 在同一個 bridge、`br_netfilter` **必須已載入**（它不會自動載入，沒載入時橋接流量完全繞過 nft）、`bridge-nf-call-iptables`/`ip6tables` 是 1。Pi 上沒有 `nf_conntrack_bridge`，不列為需求 |
| TCX 可用性（kernel ≥ 6.6、bpffs、JIT） | 階段 2 開始時 | 探測放在 `kernel/` |
| XDP 能力（netdev genetlink 的 xdp-features） | 換正式設備時（Pi 4 兩張網卡都沒有 native XDP） | rust-netlink 沒有 netdev family，要自己寫（約 150–250 行）。只接受 native XDP，不要退回 generic XDP |

做完其中一項，就把它從這張表移到實作裡，並更新這份文件。
