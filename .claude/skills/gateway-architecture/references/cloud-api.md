# 雲端 API

查證日期 2026-10-20。這份大部分是設計提案（[建議]）；引用的外部做法標了出處。

## 1. 信任模型

- 假設雲端可能被攻破、連線可能被攔截，所以雲端回應可能是惡意的。
- 雲端能讓 gateway 做的事只有白名單裡的動作，而且每個動作都受本機上限約束。
- **雲端永遠不能下發程式碼**，包括 eBPF、腳本、nft 片段和規則（SKILL.md §5 第 1 點）。

## 2. 設定 [建議]

**[已決定] 2026-10-25（`decisions.md` O12）**：endpoint、path、上傳欄位都寫在 `setting.toml`；欄位格式見 `field-scripts.md` §5。下面的 YAML 是 10-20 的草稿，只用來說明有哪些項目，實際格式用 TOML，等實作時再定。

```yaml
cloud:
  endpoint: "https://ids.example.internal/v1"   # 只接受 https；只能在本機改，雲端改不了
  tls:
    ca_spki_pins: ["sha256/<主要>", "sha256/<備用>"]   # pin 私有 CA，不 pin leaf
    client_cert: /etc/wnc-gw/cloud/client.crt
    client_key: /etc/wnc-gw/cloud/client.key           # 0600，屬於 gw-agent
  schema_version: 1
  timeouts: { connect_ms: 3000, request_ms: 5000 }
  upload: { batch_max_records: 500, interval_ms: 1000 }
  limits:
    actions_per_minute: 60
    trust_ttl_max_s: 600
    block_ttl_max_s: 86400
    max_cidr_prefix_v4: 24
    max_cidr_prefix_v6: 64
```

- 設定檔屬於 root，`gw-agent` 只有讀取權限。
- 範例裡的數值只是示意，實際值要依量測和開發者的決定來定。

## 3. 傳輸與認證 [建議]

- **mTLS**，pin 自家私有 CA 的 SPKI，並準備一個 backup pin，不 pin leaf 憑證。依據：OWASP Pinning Cheat Sheet 一般不建議 pinning，但自家 client 連自家 server、又能安全更新 pinset 的情況適用。
- **請求和回應都簽章並防重放**：參考 RFC 9421（HTTP Message Signatures）的 `created`、`expires`、`nonce`、`keyid`。回應要綁定原請求的 id 和 gateway id。
- **參考 CrowdSec 的權限分離**：bouncer 拿到的 API key 是唯讀的，只能讀 decisions；也可以改用 mTLS，依憑證的 OU 欄位決定權限。

## 4. 上傳什麼

- 只上傳欄位腳本算出來、而且通過 schema 驗證的欄位（`field-scripts.md`）。
- 不上傳 payload，也不上傳來自封包的原文字串。
- 上傳量是研究要量的成本之一，所以 connector 要記錄每一批的 bytes 數。

## 5. 處理雲端回應 [建議]

**[已決定] 2026-10-25（`decisions.md` O12）：先做可設定的對應（R2）。** 設定檔描述「回應裡哪個欄位是判定結果、目標、TTL」，以及「對方的標籤怎麼對應到 trust、block、observe」。能做的動作只有這三種，對應不到的標籤一律丟掉並記錄。以下的檢查不論 R1 或 R2 都要做。之後可能改成固定格式（R1）。示意（格式未定）：

```toml
[cloud.response]
records = "/verdicts"      # JSON pointer，指向判定的陣列
action = "/label"
target = "/src_ip"
ttl = "/ttl"

[cloud.response.actions]
malicious = "block"
benign = "trust"
unknown = "observe"
```

- **schema 要嚴格**：serde 開 `deny_unknown_fields`。動作只能是 `trust`、`block`、`observe` 三種。
- **目標**：只能是單一 IP 或 flow 的 5-tuple；網段大小有上限。
- **TTL**：都有上限，trust 的上限比 block 短。
- **速率**：每分鐘最多 N 個動作、每個 set 最多 M 個元素，超過就丟掉並告警。
- **本機直接拒絕的情況**：
  - 目標在永不封鎖清單裡。
  - 要 trust 的 flow 有本地 Suricata 告警。
- **所有動作都寫 audit log。**
- **fail-safe**：簽章錯誤、動作速率異常、連不上時，停止接受新的 trust，維持本地規則。斷線時該 fail-open 還是 fail-closed，見 `decisions.md` O9。
- **CrowdSec 的教訓**：它的 firewall bouncer 用自己的 nft table，元素有 timeout，值會先經 `net.ParseIP` 驗證。但 bouncer 端沒有 set 大小和速率上限，限制都放在伺服器端的 allowlist。所以我們要在 gateway 端自己持有 allowlist 和上限，不能依賴雲端。

## 6. 規則與模型的更新包

- **minisign（Ed25519）**：本身不防 rollback。所以把版本號和到期時間放在 trusted comment，由我們自己檢查版本是否單調遞增。
- **TUF**：root 金鑰離線保存，有 threshold 簽章和過期時間，可以防 rollback 和 freeze。規模變大時再考慮。
- **Uptane**：用兩個 repository，攻擊者要同時攻破兩個才能推送惡意更新。只當參考。
- 雲端只能推資料類更新（規則、模型），而且都要驗簽章；不能推 eBPF 或腳本。

## 7. Transport 插件 [建議]

- 先做 HTTPS。之後可以加 gRPC 或 MQTT，但簽章和 schema 沿用同一套。
- 雲端端點的部署（自建、哪家雲）不在這份 skill 的範圍內。
