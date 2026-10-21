# 送雲端的欄位腳本

查證日期 2026-10-20。標「主 agent 核對」的已讀過原始公告，其他來自 subagent 調查。

## 1. 用途與介面 [建議]

- **用途**：讓使用者自己定義送雲端的欄位怎麼從原始 flow 特徵算出來。例如 `bytes_per_pkt = bytes / pkts`、把 port 分桶、做正規化。
- **形式**：腳本是純函式 `f(flow_record) -> fields`。
  - 輸入是核心給的 flow 記錄，唯讀、有型別：u64 計數器、port、proto enum、duration 等。
  - 輸出是設定檔裡事先宣告過的欄位。
- **不給 host callback**：腳本不能讀檔、連網或呼叫外部程式。能用的只有白名單裡的純數學函式和分桶函式。

## 2. 引擎選擇

| 引擎 | 沙盒 | 資源限制 | 已知漏洞 | ARM64 / musl / 大小 | 判斷 |
|---|---|---|---|---|---|
| CEL（crate `cel`，MIT） | 語言本身沒有副作用、保證會終止，**不是 Turing complete** | Rust 版沒有 cost budget（K8s 的 cost budget 是 cel-go 才有）；要限制資源只能靠 process 層級 | parser 有 3 個 High DoS 公告（見 §3） | 純 Rust，應可交叉編譯 [推測] | **第一版用這個** [建議] |
| Rhai（MIT/Apache） | 預設碰不到檔案和網路；`import` 可能載入檔案，要換掉 module resolver | 有 `max_operations`（**預設 0，等於無限**）、call levels、expr depth、string size（預設無限）、array/map size、`on_progress`；Turing complete | 沒有公告 | 純 Rust、支援 no_std | 需要多步邏輯時再加 [建議]；不能開 `unchecked` feature |
| wasmtime | wasm 本身沒有任何外部存取權限；WASI 採 capability 模式 | fuel 和 epoch | **GHSA-mghf-wjfp-p5xm（2026-10-19，Critical 9.9）：aarch64 預設設定下，使用者提供的 Wasm module 可讓程式跳到任意程式碼**（主 agent 核對）；修在 36.0.19、48.0.7、49.0.4 | aarch64 glibc 是 Tier 2，musl 只有 Tier 3；預設 release 約 19 MB | **不用** |
| wasmi | 同 wasm；純直譯器，不用 JIT | fuel、StoreLimits、遞迴與 stack 上限 | CVE-2025-66627（UAF，1.0.1 修） | 純 Rust | 只有在要做「編譯型外掛」時才考慮 |
| PUC Lua（mlua） | 沒有內建沙盒；`StdLib::ALL_SAFE` 不會排除 IO/OS | 記憶體上限、hook 計數 | 歷史上有 sandbox escape | C 實作 | **不用** |
| Luau（mlua `luau`） | `sandbox(true)` 最完整 | 記憶體上限、`set_interrupt` | 沒有公告 | 要 C++ runtime | 備選 |
| Starlark（starlark-rust） | 規格保證 hermetic、沒有 I/O | heap、tick、callstack 上限（best-effort） | 沒有公告 | 純 Rust；官方說 API 穩定不是目標 | 備選 |

**其他產品的做法**：
- Istio 的 Telemetry API 用 CEL 寫過濾條件。
- Kubernetes ValidatingAdmissionPolicy 用 CEL，並有 cost budget。
- Fluent Bit 用 Lua filter，文件沒有提到沙盒。
- Envoy 文件寫明 CEL 不在它的 threat model 內。

**Vector 的 VRL（crate `vrl`）**：
- 專為觀測資料轉換設計，有型別檢查、沒有迴圈、沒有自訂函式。
- 可以嵌入程式，函式清單由呼叫端決定。
- 缺點：
  - 授權是 MPL-2.0。
  - 預設 features 會帶進 env、network 函式，以及 tokio、reqwest，體積偏大。
  - 查不到 CPU 或記憶體上限機制。
- 可以當設計參考。

## 3. 已知漏洞決定的版本下限

- **cel-rust**（以下三個都要求 cel ≥ 0.14.3）：
  - GHSA-grff-fjh9-2rc7：約 125 bytes 的輸入就能讓 parser 用掉超過 1 GiB 記憶體，High 7.5，修在 0.14.3（主 agent 核對）。放大倍數約 10⁷，所以限制輸入長度擋不住。
  - GHSA-rjfc-c5r6-rqj7：panic，0.14.2 修。
  - CVE-2025-62162：panic，0.11.4 修。
- **parse 只在載入或熱更新時做一次**，而且要在受限的 process 裡做。
- **wasmi** ≥ 1.0.1。
- 所有依賴都固定版本，並追蹤 RustSec 和 GHSA 公告。

## 4. 在哪裡執行、要設哪些限制 [建議]

- 獨立的 `gw-transform` process：
  - 無特權，加 seccomp 或 landlock，設 `RLIMIT_AS` 和 `RLIMIT_CPU`，沒有網路。
  - 由 watchdog 監看，逾時就殺掉重啟，改送 default 欄位並累計 metric。
- **批次處理**：一次送一批 flow 進去、拿回一批欄位，把 IPC 成本攤平。
- 限制的起點，數值要在 Pi 4 上實測校準：
  - 原始碼 ≤ 4 KB，巢狀深度 ≤ 32。
  - 每筆 flow 的 operations 約 1e4（Rhai 用 `set_max_operations`；CEL 沒有這個功能，只能靠 process 逾時）。
  - string、array、map 都設小上限，記憶體控制在數 MB。
  - 輸出欄位 ≤ 64 個。
- 目前沒有可信的 Pi 4 效能和 binary 大小數據，要在 Pi 4 的 aarch64 上自己量。

## 5. 輸出 schema [建議]

```yaml
fields:
  - name: bytes_per_pkt
    type: f64
    range: [0, 65535]
    default: 0
    expr: "pkts > 0u ? double(bytes) / double(pkts) : 0.0"
  - name: dport_class
    type: enum
    values: [well_known, registered, dynamic]
    default: dynamic
    expr: "dport < 1024u ? 'well_known' : (dport < 49152u ? 'registered' : 'dynamic')"
```

- host 每一筆都要驗證輸出：拒絕 NaN 和 inf、超出 range 的值、不在 enum 裡的值；多出來的欄位丟掉；驗證失敗就用 default。
- **不輸出來自封包內容的字串**，包括 SNI、UA、DNS 名稱、URL、檔名。真的要用就送雜湊或分桶編號。
  - 理由：下游有 LLM 類決策模型，這類字串會造成間接 prompt injection（OWASP LLM01）。後果最嚴重的是攻擊者用字串把信任判定導向 trust，因為 trust 會讓流量繞過 IDS。
- 範例的 CEL 寫法（`0u`、`double()`）是示意，實作前要對照 cel-rust 實際支援的型別和函式。
