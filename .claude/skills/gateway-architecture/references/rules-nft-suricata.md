# nft 規則與 Suricata 規則

查證日期 2026-10-20，Suricata 以 8.0.7 為準。標「主 agent 核對」的已讀過原始文件，其他來自 subagent 調查（含讀 8.0.7 原始碼）。

## 目錄
- A. nftables：風險、開放的操作、Rust crate
- B. Suricata 規則：攻擊面、設定底線、規則 bundle 管線
- C. EVE JSON 裡不可信的欄位

---

## A. nftables

### 為什麼不開放 `nft -f`

- 整份檔案是一個原子交易，任何內容都會被套用：
  - `flush ruleset` 會刪光所有 table，包括放行管理連線的規則。
  - `include` 可以讀任意路徑，支援萬用字元。
  - `dup to` 可以把流量複製到別的位址；`fwd to` 也能轉送流量（只在 netdev hook）。
  - `queue` 可以改送到別的 queue；queue 不存在又沒設 bypass，流量就會斷。
  - 可以自己寫 `ct mark set` 把 flow 標成可信任，也可以改別的 table。
- 寫主機名稱會觸發阻塞式 DNS 解析。libnftables 可以用 `NFT_CTX_INPUT_NO_DNS` 關掉。
- **JSON 模式不能當防線。** `NFT_CTX_INPUT_JSON` 的行為是「先試 JSON，失敗就退回原生語法」（主 agent 核對：本機 nftables 1.0.9 的 `libnftables(3)`）。所以要先在 Rust 端用 serde 解析成自己的型別，再重新序列化成 JSON 才交給 nft。

### 開放的操作 [建議]

- 只開放：對自己 table（例如 `inet wnc_gw`）裡、名稱在白名單的 set，做 element add、delete（帶 timeout）和 list。
- 輸入的型別：
  - 只接受 `IpAddr` 或 CIDR，用 Rust 型別 parse，不直接拼字串。
  - timeout 有上限。
  - CIDR 前綴有下限，例如 IPv4 不能比 /24 還大。
- set 宣告一律明確寫出 `size`、`flags timeout` 和預設的 `timeout`。set 的預設 size 是多少沒查到，不要依賴它。
- 永不封鎖清單由 privd 檢查（SKILL.md §5 第 5 點）。
- base chain 和 set 宣告由 privd 用固定範本建立。使用者規則只能引用 set，不能新增 chain 或 rule。
- 執行 nft 的 process 只給 `CAP_NET_ADMIN`。
- JSON 格式依 `libnftables-json(5)`（主 agent 核對本機 man page），`timeout` 是數字：

```json
{"nftables": [{"add": {"element": {
  "family": "inet", "table": "wnc_gw", "name": "ban_v4",
  "elem": [{"elem": {"val": "192.0.2.10", "timeout": 3600, "comment": "cloud:block"}}]
}}}]}
```

### Rust crate

| crate | 做法 | 狀態 | 注意 |
|---|---|---|---|
| `nftables` 0.6.3 | 提供 JSON 型別，再 spawn `nft -j -f -` | 2025-08 更新，下載 3.0M | 依賴 nft 執行檔；可以傳 `-c` 只檢查；沒有 timeout |
| `rustables` 0.9.0 | 直接送 netlink | 2026-09 更新，下載 60K | **GPL-3.0-or-later**；作者自己說還有 rough edges |
| `nftnl` + `mnl` | 包裝 libnftnl、libmnl | Mullvad 維護 | 沒看到 set 的 timeout 和 flags API |

選哪個牽涉授權，見 `decisions.md` O4。

---

## B. Suricata 規則

### 攻擊面

- **Lua 規則**：
  - 8.0 起**預設啟用**，在 sandbox 裡執行（主 agent 核對 docs.suricata.io）。`security.lua.allow-rules` 預設是 true，設成 false 之後，`lua` 和 `luaxform` 規則會載入失敗。
  - sandbox 預設值：`max-bytes` 500000、`max-instructions` 500000；只提供 base、table、string、math、utf8，沒有 io、os、package、debug、coroutine。
  - sandbox 出過洞：
    - CVE-2026-45770：註冊過多 flow variable 可繞過 sandbox，High，影響 8.0.0–8.0.4（主 agent 核對；官方 workaround 是關掉 `allow-rules`）
    - CVE-2026-45763：記憶體上限沒有落實
    - CVE-2025-64344：Lua stack overflow
    - GHSA-g643-4v67-43w4：hashlib use-after-free，影響 8.0.7 以前
  - 規則可以指定任意路徑的 Lua 檔：絕對路徑不會被改寫，`..` 也不會被擋。
- **datasets**：
  - `datasets.rules.allow-absolute-filenames` 預設 false，但只限制 `save` 和 `state`。
  - `allow-write` 預設 true。
  - `load` 不受限制。
  - CVE-2026-45767：`save` 的絕對路徑檢查，可以被同一條規則裡的 `load` 繞過，影響 8.0.5 以前。
- **filestore**：file-store output 開啟後才會寫檔，預設是關的（`enabled: no`）。寫入的總量沒有上限。
- **pcre**：
  - `match-limit` 預設 3500、`match-limit-recursion` 預設 1500。
  - CVE-2025-29918：negated pcre 造成無窮迴圈，inline 模式下封包執行緒會卡死，影響 7.0.9 以前。
- **規則解析器會 crash**：例如 CVE-2026-63451（frame 加 transform 造成 heap overflow，8.0.0–8.0.5），advisory 明寫 `-T` 也會觸發。所以連 `-T` 都要在低權限沙盒裡跑。
- **unix socket**：權限 0660、沒有認證，指令包含 `shutdown`、`dataset-add`、`conf-get`。只能給 privd 用，不轉發給任何人。
- **suricata-update**：HTTPS 會驗憑證，但 `.md5` 只是用來判斷遠端有沒有變的快取，沒有簽章驗證。規則來源的真實性要自己驗，例如固定 sha256 或驗簽章。
- 2026-09-29 那批 advisory 都修在 8.0.7，所以版本至少要 8.0.7。

### Suricata 設定底線 [建議]

- `security.lua.allow-rules: false`：不用 Lua 規則時一定要設，因為 8.0 預設是 true。
- `datasets.rules.allow-write: false`：不需要 save 和 state 時設。
- 開啟 landlock（預設關），用非 root 帳號執行。`security.limit-noproc` 在 root 下沒有作用。
- 規則檔由 suricata.yaml 的 `rule-files` 指定。如果啟動時用了 `-s` 或 `-S`，之後的 live reload 會被拒絕。

### 規則 bundle 管線 [建議]

1. **收到 bundle**：驗簽章或 hash，確認版本號比現在的大。
2. **靜態檢查**（在 privd 以外的低權限 process 做）：
   - 拒絕 `lua`、`luaxform`、`filestore`，以及 dataset 的 `save` 和 `state`。
   - 拒絕 `pass` 和 `bypass`，因為它們會讓流量繞過 IDS。
   - 限制 sid 範圍、檔案大小、規則條數、pcre 長度。
3. **沙盒驗證**：在暫存目錄、唯讀 data dir、cgroup 資源上限、有逾時的條件下跑 `suricata -T -S <file>`。`-T` 會把 `engine.init-failure-fatal` 設成 1，任何一條壞規則都會讓它失敗。
4. **原子替換**：rename 成 active 規則集，保留上一版。
5. **reload**：透過 unix socket 送 `reload-rules`（會阻塞等待）或 `ruleset-reload-nonblocking`。
6. **確認 reload 結果**：socket 回 OK **不代表成功**，因為主迴圈忽略了 `DetectEngineReload` 的回傳值。要查 `ruleset-reload-time`、`ruleset-stats`（loaded 和 failed 數量）、`ruleset-failed-rules`。注意 live reload 時壞規則只會被跳過，其餘照樣載入。
7. **失敗就回退**：換回上一版再 reload 一次，並發出告警。

---

## C. EVE JSON 裡不可信的欄位

- **攻擊者能控制的字串**：
  - HTTP：`http.hostname`、`http.url`、`http.http_user_agent`、`http_refer`、cookie、自訂 header
  - DNS：`dns.queries[].rrname`、`answers[].rrname`、`rdata`
  - TLS：`tls.sni`、`subject`、`issuer`、`serial`、`ja3`、`ja4`
  - 其他：`fileinfo.filename`、ssh software_version、`ftp.command_data`、smb filename 和 ntlmssp user、mqtt client_id 和 topic、`dhcp.hostname`、`quic.sni`、rdp client_name、krb5 realm
- **規則內容也算**：`alert.signature` 是規則裡的 msg，規則來源不可信時，它也不可信。
- **JSON 層通常安全，解碼後不是**：Suricata 會把 `"`、`\` 和控制字元跳脫，但解碼後的字串仍然可能含 NUL、換行、ESC、`;`、`}`。
- **8.0.7 之前出過 JSON injection**：例如 GHSA-7839-m44v-xp2p，MQTT user properties 和 PostgreSQL startup 參數可以注入 key，偽造欄位甚至整筆記錄。所以 EVE 本身也不能當成可信來源。
- 實作規則：
  - 要做動作時，只取 IP 欄位，用 `IpAddr::parse` 重新驗證。
  - 字串絕不拼進 shell 或 nft 指令。
  - 寫 log 前先跳脫（Rust 用 `{:?}`）。
  - 不把原文送給 LLM（`field-scripts.md` §5）。
- EVE 用 `unix_dgram` 輸出時，讀太慢會**靜默丟事件**。agent 要優先處理 EVE，並自己監看 drop 數。
