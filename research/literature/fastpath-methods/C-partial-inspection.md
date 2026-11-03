# C 組：部分檢查與交易層級抽樣

調查日期 2026-11-02。範圍：把「已信任 flow」的一部分封包（單一方向、一個應用層交易、或預篩命中的單一封包）送進 Suricata 時，Suricata 8.0.7 實際怎麼處理；以及文獻有沒有類似做法。唯讀研究，沒有跑 Suricata 或任何實驗；實驗全部寫在 §2 C7，等主 agent 排。

**讀了什麼版本**
- Suricata：`git clone --depth 1 --branch suricata-8.0.7`（tag 的 commit `d681600f3648`），放在 scratchpad `suricata-8.0.7/`，不在 repo 內。文件讀的是同 tag 的 `doc/userguide/`。
- 專案設定：`security_gateway/src/ids/spawned.rs`（唯讀）。
- ET Open 規則：`https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz`（tar 內時間戳 2026-10-30），放 scratchpad，只用 `python3 -I` 腳本數 `flow:` 欄位。
- 論文 PDF：`pdfs/hpa-erlacher2017/`、`pdfs/dpa-limmer2011/`、`pdfs/fpa-limmer2009/`（共約 1.7 MB）。

**證據標記**：照 SPEC §5。`[原始碼 檔:行 @8.0.7]` 都是我讀 `suricata-8.0.7` 的結果。凡寫「推導」的，是我從原始碼推出的行為，**沒有執行驗證**，對應到 C7 的實驗編號。

**專案現況對照**：wnc-gw 目前對 Suricata 強制 `stream.midstream=true`、`stream.midstream-policy=ignore`，ids（NFLOG）與 ips（NFQ）都一樣 [spawned.rs:26-33]；fail-open 為 false 時另設 `exception-policy=drop-flow` 與數個 memcap policy 為 drop-flow [spawned.rs:263-281]。沒有設 `stream.async-oneside`、`stream.drop-invalid`、`stream.inline`。

---

## 0. 結論（≤ 10 行）

1. **C1** midstream=true 時，任何帶 ACK 旗標的 TCP 封包（連純 ACK 都算）會直接建立 ESTABLISHED session，首封包的發送者被當成 client／to_server，window scale 一律假設 14 [原始碼 stream-tcp.c:1478-1566 @8.0.7]。IPS 預設若 midstream=false，`exception-policy: auto` 會變成 drop-flow，整條中途接手的連線被丟掉 [原始碼 util-exception-policy.c:259-270,303-305 @8.0.7；文件 exception-policies.rst:134-215]，wnc-gw 已強制 midstream=true 所以不會踩到。
2. **C2** HTTP 協定偵測靠 pattern：to_server 資料必須從 `GET `、`POST ` 等 method 開頭才認得 [原始碼 app-layer-htp.c:2579-2636 @8.0.7]，所以「從 request 第一個封包開始送」可解析；落在 request 中間的話偵測失敗，midstream session 只要 to_server 偵測失敗就整條 `DisableAppLayer`，之後 `http.*` 規則不再比對，只剩 raw stream／packet 規則 [原始碼 app-layer.c:586-610 @8.0.7]。MQTT 靠 port 1883 的 probing parser、不需要看到 CONNECT，但 protocol_version 恆為 0 且**不接受 gap**，中途漏封包就關掉整條 flow 的 app-layer [原始碼 mqtt.rs:179,263,682-704,793,821；app-layer-parser.c:1307-1316,1480-1487 @8.0.7]。
3. **C3** IDS（NFLOG）：app-layer 與 raw stream 只處理「已被對方 ACK」的資料（`UPDATE_DIR_OPPOSING`＋`last_ack` 上限），單向看不到 ACK 就不會餵 [原始碼 stream-tcp-reassemble.c:416-431,2021-2040 @8.0.7]；`stream.async-oneside=true` 才會改成逐封包餵並把 last_ack 推到 next_seq。IPS（NFQ）：inline 模式逐封包餵、不等 ACK，所以只送 C→S 時請求 payload 會被檢查；但**推導**（未實測，E3）只送 C→S 時，第二個帶新 ACK 號的客戶端封包會被判 `STREAM_EST_INVALID_ACK`，IPS 的 `drop-invalid`（預設開）會把它丟掉，連線可能被 Suricata 自己切斷 [原始碼 stream-tcp.c:1535,2927-2931,5866-5872,6742-6805 @8.0.7]。
4. **C4** 單一封包：**推導**（E2）接手那個封包本身沒有 `FLOW_PKT_ESTABLISHED`，而 ET Open 的 TCP 規則 97.2% 帶 `flow:established`，所以這些規則在該封包不會比對 [原始碼 flow.c:498-511、stream-tcp.c:2743 僅 3WHS 特例 @8.0.7；ET 自數 37,985 條中 36,938 條]；預設 TCP `content` 規則是 stream 規則，IDS 下資料沒被 ACK 就不可用且會跳過 packet payload，只有帶 `depth`／`offset` 的規則（要求 packet）才比對 [原始碼 detect-parse.c:2877-2905、detect-engine.c:1872-1912 @8.0.7]。
5. **C5** `request-body-limit`／`response-body-limit` 是「每個 HTTP 交易的 body」層級，headers 與 URI 照常解析；`stream.reassembly.depth` 是「每條連線每個方向」層級（以序號空間計，不是每交易），對 keep-alive 與長連線是反效果 [原始碼 app-layer-htp.c:591-632、stream-tcp-reassemble.c:650-715、suricata.yaml.in:1240-1246 @8.0.7]。兩者都只省 Suricata 內部 CPU，每個封包仍要走 NFQ 往返（確認，不是反駁）。
6. **C6** 找到兩篇直接相關且讀了全文：HPA（每個 HTTP 訊息只轉前 N bytes）與 DPA（每次方向改變後轉前 N bytes，只用 TCP 序號判斷）。它們是**確定性 cutoff**，不是隨機抽樣；相對未過濾的 Snort，DPA 分析 3.7% 資料、保留 89.8% 事件 [原文 DPA p.837]，HPA 分析 2.5% payload、保留 97.4% 事件 [原文 HPA p.421]。**沒有找到**單向檢查的 IDS 論文，也沒找到量測攻擊 payload 方向比例的論文；我用 ET Open 自數：有方向的 TCP 規則中 85.0% 是 to_server（只是規則數，不是攻擊流量比例）。
7. **跨交易的狀態延續（本組新發現，推導）**：Suricata 在取樣間隔內不會忘記這條 flow（TCP established 逾時預設 600 s [原始碼 suricata.yaml.in:1622-1630]），所以第二段取樣會撞到第一段留下的 session 狀態（stream depth 以序號空間計、ACK 視窗、MQTT 不接受 gap）。取樣間隔 > 600 s 才會變成新 session。見 E5。

---

## 1. 逐項

本組前半是 Suricata 8.0.7 行為查證（A1–A5，對應 C1–C5），後半是文獻（B1–B4，對應 C6）。

### A1. midstream session 建立與方向判斷（C1）

- **設定**：`stream.midstream` 由 `SCConfGetBool` 讀，沒設時先把值設 0，所以預設 false [原始碼 stream-tcp.c:552-554、conf.c:526-533 @8.0.7]；yaml 範本把它註解掉 [原始碼 suricata.yaml.in:1725-1726]。
- **midstream-policy 與 IPS 預設值**：
  - 明確設 `stream.midstream-policy` 時，midstream=true 只允許 `ignore`／`pass-flow`，其他值啟動直接 fatal [原始碼 util-exception-policy.c:337-354 @8.0.7]。
  - 沒設時看 master switch：yaml 範本 `exception-policy: auto` [suricata.yaml.in:1470]，`auto` 在「IPS 且 midstream=false」→ drop-flow，其餘 → ignore [util-exception-policy.c:259-270,295-310]。
  - 文件矩陣：IPS＋midstream 關＋auto → 「Flow DROPPED」；midstream 開＋ignore → 「Session and app-layer traffic tracked and parsed … **do** detection」[文件 doc/userguide/configuration/exception-policies.rst:134-215 @8.0.7]。
  - IDS 模式下 drop-flow／drop-packet 不合法（fatal）[util-exception-policy.c:355-363]。
- **建立 session**（`StreamTcpPacketStateNone`，stream-tcp.c:1197 起）依首封包旗標分四種：
  - RST：不建（1203-1207）。
  - FIN：midstream 開、payload>0、policy 為 ignore／pass-flow 才建，狀態 FIN_WAIT1（1209-1260）；payload=0 的 FIN 不建。
  - SYN/ACK：建 session 為 SYN_RECV，**`PacketSwap(p); FlowSwap(p->flow)`** 把方向翻過來，設 `MIDSTREAM|MIDSTREAM_SYNACK`（1331-1341）。
  - 帶 ACK（含 PSH|ACK 的資料封包與純 ACK）：建 ESTABLISHED（1478-1566）。`ssn->client.isn = seq-1`、`client.next_seq = seq+payload_len`、`client.last_ack = seq`；`server.isn = ack-1`、`server.last_ack = ack`、**`server.next_win = server.last_ack`**（視窗為 0）；兩邊 wscale 設 `TCP_WSCALE_MAX`（14）（1518-1535）。接手封包的 payload 當作 client stream 的第一段插入（1566）。計數器 `tcp.midstream_pickups` [stream-tcp.c:6139]。
- **方向判斷**：
  1. 預設：第一個看到的封包的發送端 = client = to_server（程式把它放進 `ssn->client`）；SYN/ACK 先到則翻轉（上面）。
  2. 協定偵測可以再翻轉：PM 在 midstream 下先試本方向的 pattern，沒中再試**對方向**的 pattern，中了就把 `rflow` 設為 true [原始碼 app-layer-detect-proto.c:326-400 @8.0.7]；`reverse_flow` 且 session 是 MIDSTREAM 但非 SYNACK 且對方向還沒偵測出協定時，`PacketSwap; FlowSwap` [app-layer.c:455-470]。所以「第一包是 HTTP 回應」會被修正成 server 方向；沒有協定 pattern 可依據的 flow（加密、未知協定）方向就維持「誰先出現誰是 client」。
- **IDS 與 IPS 的差異**（對 C1）：state machine 本身同一份程式碼；差異在 (a) exception policy 的預設值（見上）、(b) 之後餵資料的時機（A3）、(c) 被判為 invalid 時 IPS 會 `PacketDrop`（A3）。
- **對我們的意涵（[推測]）**：若取樣封包的第一包是 S→C 的純 ACK 或資料，該 flow 的方向會顛倒；`flow:to_server` 規則會對錯的方向比對，直到 app-layer pattern 修正（只對有 pattern 的明文協定有效）。取樣起點應選 C→S 的封包。見 E1。

### A2. 協定偵測與 parser 能否從 request 開頭／中間開始（C2）

- **HTTP 偵測**：`HTPRegisterPatternsForProtocolDetection` 對 28 個 method 名加空白或 tab 各註冊一條 PM pattern（depth 為 pattern 長度、offset 0、方向 to_server）；to_client 註冊 `HTTP/0.9`、`HTTP/1.0`、`HTTP/1.1`（offset 0）[原始碼 app-layer-htp.c:2579-2636 @8.0.7]。HTTP **沒有**以 port 為依據的 probing parser（`RegisterHTPParsers` 只註冊 PM，2638-2670）。
- **從 request 開頭起**：payload 以 `GET /` 開頭 → PM 命中 → `ALPROTO_HTTP1` → 資料交給 HTP parser（`htp_connp_request_data`）[app-layer-htp.c:791-842]。HTTP 的 request line、headers 都在 parser 內建 tx，`http.uri`／`http.method`／`http.host` 等是 app-layer 規則，可比對（[推測]：前提是下面 A4 的 `flow:established` 問題不擋住，E1/E2）。
- **落在 request 中間**：PM 在兩邊 pattern 都不中時，只有當資料長度 ≥ mpm maxdepth 才算「確定不是」並標 PM_DONE [app-layer-detect-proto.c:272-298,326-400]；PM 與 PP 對 to_server 都 done 之後，midstream session 呼叫 `DisableAppLayer`：註解寫「a midstream session MUST find its protocol in the toserver direction. If not, we assume the start of the request/toserver is incomplete and no reliable detection and parsing is possible. So we give up」[app-layer.c:586-610]。結果：`http.*` 規則在這條 flow 上不再比對，仍可比對 raw stream 的 `content` 與 packet 規則；並**不是**「從 request 中間開始解析 HTTP」。
- **HTTP 對 gap 的處理**：註冊時帶 `APP_LAYER_PARSER_OPT_ACCEPT_GAPS` [app-layer-htp.c:2680-2683]，gap 會被當資料交給 `htp_connp_request_data`（NULL＋長度）；htp 內部（`rust/htp`）怎麼處理 header 中途的 gap，**未能確認**，見 E6。
- **`http.request_body`**：body 暫存要等到下列任一條件才開始 inspect：body ≥ `request-body-minimal-inspect-size`（預設 32 KiB，範本 suricata.yaml.in:1143）、request 已完成、達 `request-body-limit`、或 `STREAM_EOF` [原始碼 detect-http-client-body.c:256-272 @8.0.7]。所以取樣到的 request 如果 body 沒收完（取樣在中途結束），`http.request_body` 要等到該交易完成或 flow 結束（逾時 pseudo packet）才比對。
- **MQTT**：
  - 偵測：`AppLayerRegisterProtocolDetection(&parser, 1)`，預設 port `[1883]`，`probe_ts`／`probe_tc` 都是 `mqtt_probing_parser`，min_depth 0、max_depth 16 [mqtt.rs:793-801]。probing parser 只要 fixed header 合法（message type 非 UNASSIGNED、QoS ≤ 2）就回 MQTT，**不要求 CONNECT** [mqtt.rs:682-704]。也就是 port 1883 上從 PUBLISH 開始可以偵測；非 1883 的 port 要靠 `detection-ports` 設定（未確認 8.0.7 yaml 的 mqtt 區塊有無 `detection-ports`：範本 suricata.yaml.in:936-944 沒列，其他協定如 pop3 有）。
  - 解析：`protocol_version` 初值 0，只有看到 CONNECT 才更新 [mqtt.rs:179,263]；沒看過 CONNECT 時 PUBLISH 的 properties 不會被拆（`parse_properties(i, protocol_version == 5)`，parser.rs:251），MQTT v5 的 PUBLISH 會把 properties 當成 message 內容 [推測，E6]。
  - 整則訊息才解析：`parse_message` 在資料不足時回 `Incomplete`；訊息長度超過 `max-msg-length`（預設 1 MiB）時回 `TRUNCATED`，沒有 topic 等欄位，直接跳過 [rust/src/mqtt/parser.rs:644-690]。
  - **不接受 gap**：`flags: 0`（mqtt.rs:821）；`AppLayerParserParse` 在收到 gap 且 parser 不接受時走 `error:` → `StreamTcpDisableAppLayer(f)`＋`AppLayerParserSetEOF`，整條 flow 的 app-layer 永久關閉 [app-layer-parser.c:1307-1316,1480-1487]。對「同一條長連線多段取樣」影響很大（A5/E5）。
- **對我們的意涵（[推測]）**：(b)「從某個 request 的第一個封包開始送」對 HTTP 與 port 1883 的 MQTT 在協定偵測這關是通的；起點不是訊息邊界時 HTTP 會永久關 app-layer。取樣起點必須由 kernel 側判斷訊息邊界（見 B1/B2 的 DPA 以序號方向改變判斷，不需解析應用層）。

### A3. 單向可見性（C3）

- **IDS（非 inline）餵資料時機**：`StreamTcpReassembleHandleSegment` 預設 `dir = UPDATE_DIR_OPPOSING`（2021），即「由對方向的 ACK 觸發 app-layer 更新」；inline、pseudo stream end、RST、FIN、CLOSED、ASYNC 才改成 `UPDATE_DIR_PACKET` 或 BOTH [原始碼 stream-tcp-reassemble.c:2021-2040 @8.0.7]。資料可用的右邊界在非 inline 時是 `MIN(GetAbsLastAck, right_edge)`（除非 `eof`）[stream-tcp-reassemble.c:416-431]。`client.last_ack` 只會被 **server 的封包**更新，所以只送 C→S 時，`last_ack` 停在接手時的 seq（1526），app-layer 與 raw stream 都吃不到資料，直到 FIN/RST 或 flow 逾時的 pseudo packet（`PKT_PSEUDO_STREAM_END`）才會全部 flush。
- **raw stream 規則的另一道門檻**：IDS 下 `StreamTcpReassembleRawCheckLimit` 要求「已 ACK 且尚未檢查的資料」≥ chunk size（`toserver-chunk-size` 預設 2560，隨機 ±10%），或 flag 為 DEPTH_REACHED／TRIGGER_RAW／NEW_RAW_DISABLED，或 session 狀態 > TIME_WAIT，或 pseudo packet [stream-tcp-reassemble.c:920-975；suricata.yaml.in:1735-1737,1689-1699]。
- **`stream.async-oneside`**（預設 false [stream-tcp.c:560-565]）：
  - midstream 在 ACK 分支接手時設 `STREAMTCP_FLAG_ASYNC`（1511-1514，SYN/ACK 與 FIN 分支也有同樣的設定 1242,1342,1427）。
  - ASYNC → `UPDATE_DIR_PACKET`（stream-tcp-reassemble.c:2037-2040）；`StreamTcpUpdateNextSeq` 會呼叫 `StreamTcpAsyncLastAckUpdate`，把 `last_ack` 推到 `next_seq`（stream-tcp.c:1091-1107），等於把送出的資料當成已 ACK。
  - `StreamTcpValidateAck` 對 ASYNC session 回「no further checks possible for ASYNC」，不再檢查 ACK 是否超出視窗（6783-6786）。
  - 一旦兩個方向都看過封包（`client.tcp_flags` 與 `server.tcp_flags` 都非 0），ASYNC 旗標自動解除（5695-5702）。
  - 文件：「Some of the network-traffic follows a different route than the other part… To make sure Suricata will check the one part it does see, instead of getting confused, the option 'async-oneside' is brought to life」[文件 suricata-yaml.rst:1326-1333]；analysis.rst:135 建議單向流量「優先修好」。
  - 這是**全域**設定，ASYNC 放寬的是 ACK／視窗檢查，不只對取樣的 flow；安全面的取捨需要另外評估。
- **`stream.inline`**：預設 `auto`＝跟引擎模式（IPS 開、IDS 關）；也可設 `yes`／`no` 強制 [stream-tcp.c:585-604]。inline 模式下 `StreamTcpInlineMode()` 為真：資料不受 `last_ack` 限制（stream-tcp-reassemble.c:420-430）、逐封包觸發 app-layer（stream-tcp-reassemble.c:2023-2024）、raw 用 sliding window（`StreamReassembleRawInline`）、重疊資料檢查自動開（stream-tcp-reassemble.c:495-497）、`drop-invalid` 才有作用（stream-tcp.c:443-447）。[推測] 在 IDS（NFLOG）設 `stream.inline=yes` 可能是 `async-oneside` 之外另一條讓單向資料即時被檢查的路，但沒有文件說明這樣用是否支援，E4 要比較。
- **IPS（NFQ）只送 C→S 時，請求 payload 會被檢查嗎？** 逐封包餵所以會；但有一個**推導出來的風險**：
  1. 接手時 `server.next_win = server.last_ack`（1535）。
  2. 之後每個 C→S 封包進 `HandleEstablishedPacketToServer`，第一件事是 `StreamTcpValidateAck(ssn, &ssn->server, p)`，失敗就 `STREAM_EST_INVALID_ACK` 並 `return -1`（2927-2931）。
  3. `StreamTcpValidateAck`：`ack > last_ack` 且 `ack ≤ next_win` 才快速通過；`next_win == last_ack` 時，只要 ack 比接手時大（server 在這段時間送了客戶端 Suricata 沒看到的資料）就落到 `state > SYN_SENT && SEQ_GT(ack, next_win)` → invalid（6742-6805）。`next_win` 要等到看過一個 server 封包才會被 `MIDSTREAM_ESTABLISHED` 分支更新（3110-3118）。
  4. 錯誤路徑上，`StreamTcpInlineDropInvalid()`（inline 且 `drop-invalid` 為真，預設為真 [stream-tcp.c:629-637]）會 `PacketDrop(p, ACTION_DROP, PKT_DROP_REASON_STREAM_ERROR)`（5866-5872）。
  5. 被拒的封包不會更新 `last_ack`、`next_win`，所以只要 server 不被看到，之後所有 ACK 號超過的客戶端封包都會被拒。
  - **推論**：設計 (a)「只送 C→S、放行 S→C」在 IPS 預設設定下，第一個確認了 server 新資料的客戶端封包就可能被 Suricata 丟棄，連線被切斷。避開方式有 `stream.async-oneside=true` 或 `stream.drop-invalid=no`；兩者都有安全副作用。**未實測**（E3）。
  - 緩解因素：wscale 假設 14 讓 `window<<14` 很大，若 server 已被看過一個封包後 `next_win` 就很寬鬆（3110-3118），所以風險集中在「接手後、第一個 server 封包被看到之前」。
- **對我們的意涵（[推測]）**：(a) 在 ips 與 ids 模式需要**不同**的 Suricata 設定才能讓單向可見；兩者的設定都是全域的。若要做 (a)，應在 kernel 側只送「有 payload 的 C→S 封包」（純 ACK 不送），因為 bulk 下載時客戶端的純 ACK 約占封包數一半（[推測]，未量測）。

### A4. 只收到一條 established flow 中的單一封包（C4）

只列「在 8.0.7 原始碼可確定的條件」，行為本身要靠 E2/E8 驗證。

- **接手與 flow 旗標**：單一帶 ACK 的資料封包 → 建 session、payload 成為 client stream 第一段、`p->flags |= PKT_STREAM_ADD`（stream-tcp-reassemble.c:2084）、`PKT_STREAM_EST` 在 `StreamTcpPacket` 結尾設上（stream-tcp.c:5815-5818）。但 `p->flowflags` 的 `FLOW_PKT_ESTABLISHED` 是在 `FlowUpdate`→`FlowHandlePacketUpdate` 設的，**發生在 `StreamTcp` 之前**（flow-worker.c:584 先於 :376 的呼叫路徑），判斷依據是 `f->flow_state == ESTABLISHED` 或 `ssn->state >= TCP_ESTABLISHED`（flow.c:498-511）；接手那一刻 `f->protoctx`（ssn）還是 NULL，所以**接手封包不帶 `FLOW_PKT_ESTABLISHED`**。stream-tcp.c 只有 3WHS 完成的特例會補設（2741-2744），不含 midstream 分支。`DetectFlowMatch` 看的就是 `p->flowflags & FLOW_PKT_ESTABLISHED`（detect-flow.c:112-117）。
  - **推導**：`flow:established` 的規則在這個封包上不比對。ET Open 的 TCP 類規則 37,985 條中 36,938 條（97.2%）帶 `flow:established`。
  - app-layer（tx）規則在「第一次檢查」時才跑 header／packet matches（detect.c:1281-1297）；失敗就 `return -1` 不存狀態，後續封包會重試，但**會不會再被重試**取決於 tx 有沒有更新，要實測（E2）。
- **packet 層 `content`（`alert tcp … content:"x"`，無 `depth`／`offset`）**：`SigConsolidateTcpBuffer` 把這類規則設成 `SIG_FLAG_REQUIRE_STREAM`，有 `depth`／`offset` 或 `stream_size` 才加 `SIG_FLAG_REQUIRE_PACKET` [detect-parse.c:2877-2905]；`flow:no_stream` 也是 REQUIRE_PACKET（detect-flow.c:448-450）。`DetectEngineInspectRulePayloadMatches`：先對 stream 找（需 `PKT_DETECT_HAS_STREAMDATA`），不中且「規則不要求 packet 且封包已加入 stream」就直接 NO_MATCH（detect-engine.c:1872-1912）。
  - IPS（inline）：`StreamReassembleRawHasDataReady` 在 `payload_len>0 && PKT_STREAM_ADD` 為真（stream-tcp-reassemble.c:1536-1538），stream 規則可比對這個封包的內容。
  - IDS：資料未被 ACK 就不是 usable data（A3），stream 規則不比對；有 `depth`／`offset` 的規則（REQUIRE_PACKET）才會看 packet payload。
- **app-layer 關鍵字**：IPS 下接手封包若以 method 開頭且 request 在一個封包內完整，`http.uri` 等會在這個封包後建好 tx（但受上面 `flow:established` 影響）；IDS 下 app-layer 要等 ACK（A3），單一封包不會有 parse。MQTT 同理。
- **`stream` 相關關鍵字**（`stream_size`、`flow:from_server` 等）：`stream_size` 規則被設成需要 packet（detect-parse.c:2897-2901），數值是 client／server stream 的長度，接手後只有看過的位元組，比對結果與完整觀察不同。
- **對我們的意涵（[推測]）**：(c)「kernel 預篩命中時只送命中的那一個封包」在 Suricata 這端幾乎只剩 `depth`／`offset` 型 packet 規則與無 `flow:established` 的規則可用（ET Open 約 2.8%）。要讓一般 ET 規則可用，至少要把命中封包與其後續封包一起送（E2 決定「後續幾個」）。

### A5. 交易層級的限制（C5）

- **`request-body-limit`／`response-body-limit`**（範本預設 100 KiB [suricata.yaml.in:1139-1140]；文件預設範例 3072 [suricata-yaml.rst:1647-1648]）：
  - 範圍是**單一 HTTP 交易的 body**：`AppLayerHtpCheckDepth` 比的是 `body->content_len_so_far` 與 `cfg->body_limit`（`HtpBody` 掛在 tx_ud 上，每交易一份），超過就不再 `HtpBodyAppendChunk` [app-layer-htp.c:591-632,1404-1425 @8.0.7]。
  - 不影響 headers／URI／method：它們在 HTP parser 內照常解析。
  - **不省 TCP 重組與 HTP 解析**：超過 limit 後 parser 仍然吃完整串流以維持交易邊界，只是不再存 body chunk（程式碼路徑只跳過 append；[推測] 沒有看到停止解析的分支，未逐行確認）。
  - 相關：`request-body-minimal-inspect-size` 32 KiB、`request-body-inspect-window` 4 KiB、`randomize-inspection-sizes: yes` [suricata.yaml.in:1143-1177]。
- **`stream.reassembly.depth`**（範本 1 MiB [suricata.yaml.in:1734]）：
  - 範圍是**每條連線每個方向**，以序號空間計：`seg_depth = STREAM_BASE_OFFSET + ((seq+size) - base_seq)`，超過就設 `DEPTH_REACHED` 並拒收之後所有資料 [原始碼 stream-tcp-reassemble.c:650-715 @8.0.7]。到達時通知 app-layer「此方向不會再有資料」（truncate）（2093-2105）。
  - 對 keep-alive HTTP 與長連線是**不利**的：後面的交易全部不看。Suricata 自己的 yaml 對 Modbus 的註解就是這個意思：長連線要把 depth 設為不限 [suricata.yaml.in:1240-1246]。
  - 沒有 per-protocol 的 HTTP／MQTT `stream-depth` 設定（範本只列在 pgsql、pop3、smb、modbus 等 [suricata.yaml.in:980,1074,1085,1246]）。
  - [推測，E5] depth 用序號空間計意味著：同一條 Suricata session 中，若第二段取樣的 seq 距離第一段起點超過 depth，這一方向可能直接被判 DEPTH_REACHED 而不再重組；是否如此，取決於 base_seq 在 gap 後有沒有前進，要實測。
- **MQTT**：沒有「看前 N bytes」的選項；訊息完整解析，或超過 `max-msg-length` 整則跳過（TRUNCATED，無 topic）[parser.rs:644-690]。
- **能否做到「每個交易只看開頭」**：HTTP body 可以（`request-body-limit`，但 headers 不受影響）；整個交易的前 N bytes（含 headers）沒有對應設定；TCP 層的 depth 是連線層級。
- **「只省 Suricata 內部 CPU，不省 NFQ 往返」——確認**：
  - 到達 depth 之後，封包仍然走完 `StreamTcpPacket`（只是設 `PKT_STREAM_NOPCAPLOG`，stream-tcp.c:5819-5828）與 flow 更新、packet 層偵測；IPS 下每個進 NFQ 的封包都必須回 verdict。
  - 唯一會讓 kernel 不再送封包的路徑是 `stream.bypass`／`bypass` 關鍵字→NFQ capture bypass→貼 mark，而且 mark 只貼在觸發的那個封包上、要靠我們自己的 nft ct mark 規則放行 [既有筆記 research/literature/trust-bypass/mechanisms.md M1、M2、M4]。
  - 平台數字（SPEC §1）：每個進 NFQ＋Suricata 的封包約 40 µs 固定成本；所以 body-limit／depth 對 Pi 轉送上限（30 kpps）沒有幫助。
- **對我們的意涵（[推測]）**：這些設定能降低「已被送進 Suricata 的那些封包」的內部 CPU，與 fast path 的目標（少送封包）正交，不能當成 fast path 的替代。

### B1. HPA（Erlacher & Dressler, IEEE LCN 2017）

- **書目／取得程度／差異**：Felix Erlacher, Falko Dressler, "High Performance Intrusion Detection Using HTTP-Based Payload Aggregation", 2017 IEEE 42nd Conference on Local Computer Networks (LCN), pp.418–425, DOI 10.1109/LCN.2017.18。**全文**（8 頁 PDF，`pdfs/hpa-erlacher2017/erlacher2017high.pdf`，來源 ccs-labs.org 書目庫；tkn.tu-berlin.de 的同一檔在本環境無法解析網域）。派工未給書目，是我搜尋得到。
- **機制**：
  - 在 Vermont 流量監測工具裡做 TCP 重組＋HTTP parser，對**每一個 HTTP 訊息（request 與 response）**只保留前 N bytes，各以一個新封包匯出給 Snort [原文 p.420]；暫存狀態讓 pipelined 訊息、跨封包的 request line 都能處理，缺封包時逾時匯出已解析部分 [p.420]。
  - 設計依據是規則分析：2017-01-15 的 Snort 全規則＋社群規則＋ET，active 規則 27,375 條，67% 與 HTTP 有關；使用 `http_*` content restrictor 的 12,141 條中 94% 作用在 HTTP header；全部 HTTP 規則中約 62%（占所有規則 42%）在訊息開頭做 content 搜尋 [p.419]。
- **偵測面**：
  - 評估資料是一個科學工作群 proxy 一週的 trace（約 2.2M 封包、2,996 條 IP flow），加上人為插入 5 種 2016 年 CVE 攻擊各 22 次（共 110 次；其中 4 種的特徵在 response、1 種在 request；21 次為 pipelined）[p.421]。
  - 全 trace：HPA N=500 B 分析 47,527 kB／1,878,836 kB（2.5%）[Table I，p.422]，**偵測到 97.4% 的事件**（以未過濾 Snort 的事件數為基準，不是以「真攻擊」為基準）[p.421]。
  - 人為攻擊：HPA 在 N=500、1000、2000 B 全部 22/22 命中；DPA 與 FPA 在 N=500 B 時 pipelined 版只命中 1/22（Table II，p.422）。
  - 失敗案例：SID 2015561 事件 134 → 0（N=500／1000），因特徵出現在 9000 bytes 之後 [p.422]。
  - **規避**：論文未討論攻擊者把 payload 放在 N bytes 之後或針對 cutoff 設計的規避（全文無 "evasion"／"attacker" 相關討論）。
- **成本面**：測試機 i5-4440、Linux 3.2、10 GbE、PF_RING。未過濾 Snort 約 15,000 pps 開始丟包；HPA 加 Snort 在 N=2000 B 約 180,000 pps、N=500 B 約 670,000 pps 零丟包，論文稱加速 12 倍與 44 倍 [p.423]。HPA 本身比 FPA/DPA 吃更多 CPU 與記憶體（要做 TCP 重組＋HTTP parser）[p.424]。匯出時**不帶 TCP 旗標**，Snort 因此看不到 RST，部分事件數反而比未過濾多 [p.421]。
- **對我們的意涵（[推測]）**：
  - 這是**確定性 cutoff**，不是抽樣；它證明「每則訊息前 N bytes」對 HTTP 規則集幾乎涵蓋所有事件，且這個前綴 cutoff 與「訊息邊界」綁定。
  - 無法直接搬到 tc eBPF：需要 TCP 重組與 HTTP parser（用戶態）；而且它轉的是**重建的新封包**，不是原始封包，Suricata 看不到真實 TCP 序號與旗標，與我們「ct mark 放行原始封包」的架構不同。
  - 可借用的是它的**數字**：以 N=500 B 為例，每個訊息的前 500 B 已含 97%+ 事件；與 §A2 推導的「從 request 第一個封包開始送」一致。
- **限制**：作者承認 N 的選擇會漏掉後面的特徵（SID 2015561）[p.422]；資料為單一 proxy trace，非 IoT 流量；事件數基準為 Snort 2.9.9.0 的告警（含誤報）[推測]。

### B2. DPA（Limmer & Dressler, IEEE INFOCOM 2011 GI Workshop）

- **書目／取得程度／差異**：Tobias Limmer, Falko Dressler, "Improving the Performance of Intrusion Detection using Dialog-based Payload Aggregation", IEEE INFOCOM 2011 Workshops (14th Global Internet Symposium), pp.833–838。**全文**（6 頁 PDF，來源 dcs.gla.ac.uk 的 GI 2011 會議站，`pdfs/dpa-limmer2011/p833-limmer.pdf`）。HPA 論文把它引為 [11]。
- **機制**：「DPA forwards the next N bytes of payload whenever a connection starts, or when the direction of the data transmission changes」[原文 摘要 p.833]。決策**只用網路層與傳輸層 header**（TCP 序號判斷方向改變），不解析應用層 [p.836]。FPA（Time Machine 的 IPFIX 版）只取連線前 N bytes，對 pipelined HTTP 會漏。
- **偵測面**：
  - 資料：大學對外鏈路的 600 條 10 分鐘 trace（平均 55 kpps／323 Mbit/s），Snort 規則集 Sourcefire、ET、BotHunter 2009-09 版，TCP 規則 [p.834-835]。
  - 在實際流量中，只有約 60% 的 URL 位於連線開頭 [p.835]，所以只取連線開頭（FPA）會漏。
  - 每個協定 N=2000 B：HTTP 分析 2.5%、偵測到 99.2% 事件；SSH 5.4%／100%；SMTP 7.0%／60.1%（SMTP 低是因為 shellcode 規則在郵件內文）；IRC 55.2%／99.7%；整體 3.7% 資料、**89.8% 事件** [p.837]。去除 shellcode 與誤報規則後可到約 95% [p.837]。
  - 對照：FPA 在 N=2000 B 整體 1.0% 資料、78% 事件 [p.835]。
  - **規避**：論文未討論針對 N 的規避；FPA 論文（B3）承認基於序號的簡單重組會被「相同序號、不同 payload、錯誤 checksum」的封包騙過，DPA 沿用相同的簡單重組 [推測]。
- **成本面**：理論加速 > 25 倍（假設處理時間與資料量線性）[p.837]；實測 Snort 的封包處理吞吐量提高 400% [摘要 p.833]；測試機 Core2 Quad 2.83 GHz [p.837 註 5]。
- **方向資訊**：Fig. 4 分方向量對話段長度：HTTP to-server 段 80% 在 300 B–1500 B [p.837]；以 2 kB 記錄可涵蓋 78%（to server）與 94%（to client）的整段對話 [p.836-837]。**這是對話段長度，不是攻擊 payload 在兩方向的比例**。
- **對我們的意涵（[推測]）**：
  - DPA 的觸發條件（序號方向改變）只需要每條 flow 一個小狀態（上次資料方向＋目前窗內已送位元組），**原則上可在 tc eBPF 用 per-flow map 實作**；但 Suricata 收到的仍然是原始封包流中的一段段**不連續視窗**，A1–A4 的狀態延續問題會出現。
  - 若採取「每次方向改變後送前 K 個封包」，就是 (b) 的近似實作（不依賴 HTTP 解析）。
- **限制**：作者承認 SMTP 的 shellcode 命中率低 [p.837]；N 固定；單一校園鏈路，非 IoT；事件基準為 Snort 告警。

### B3. FPA（Limmer & Dressler, IEEE LCN 2009 workshop）——略讀

- **書目／取得程度**：Tobias Limmer, Falko Dressler, "Flow-based Front Payload Aggregation", 34th IEEE LCN / 4th Workshop on Network Measurements (WNM), 2009, pp.1102–1109。PDF 已下載（`pdfs/fpa-limmer2009/limmer2009flow-based.pdf`）並轉文字，**只讀了威脅與限制段落，未精讀**；數字引用經 DPA 論文（B2）的二手引述，標 [二手 DPA p.835]。
- **相關內容**：論文承認 FPA 「does not circumvent this problem with its simple reassembly algorithm, so attacks directly targeted at the aggregation method cannot be detected」，例如重複同一序號但 payload 不同並帶無效 checksum 的封包 [原文 §III 末段]。

### B4. 規則方向統計與既有產品設定（自數＋文件）

- **ET Open 規則方向統計（自數，不是論文）**：
  - 資料：ET Open Suricata 7.0.3 套件，2026-10-30 版，52,803 條啟用的 alert 規則；以 `flow:` 選項判斷方向（`to_server`／`from_client` 算 to_server；`to_client`／`from_server` 算 to_client）。
  - TCP 類協定規則（`tcp`、`http`、`http1`、`tls`、`smb`、`ftp`、`smtp`、`ssh`、`rdp` 等）共 37,985 條：to_server 31,353、to_client 5,538、無方向 1,094；有方向者中 **to_server 占 85.0%**。HTTP 相關規則（協定為 http／http1，或含 `http.`／`http_` 關鍵字）共 23,430 條：to_server 19,751、to_client 3,621、無方向 58，to_server 占 84.5%。
  - 分類差異大：`emerging-web_specific_apps` 98.9% to_server；`emerging-web_client` 85.3% to_client；`emerging-attack_response` 83.9% to_client；`emerging-malware` 55.2% to_server、8.8% to_client、其餘多為 DNS／TLS／IP 型規則。
  - **解讀限制（[推測]）**：這是規則數，不是攻擊流量比例；一條 to_client 規則可能對應很罕見的攻擊。專案的保護範圍是公司內外網（見記憶「Gateway 保護範圍是公司內外網」），內網用戶端下載的惡意內容（web_client、exploit_kit）本來就在 to_client。所以「只檢查請求方向」會放掉約 15% 的規則面，不是小數。
- **Snort 2 stream5**：預設 `ports client 21 23 25 42 53 80 110 111 135 136 137 139 143 445 513 514 1433 1521 2401 3306`，語意「Specify the client, server, or both and list of ports in which to perform reassembly」[文件經 WebFetch 摘要 https://snort.org/faq/readme-stream5]；頁面沒有寫為什麼偏向 client，也沒有效能數字。這是主流 IDS 預設只對請求方向做 TCP 重組的先例，不是單向檢查的量測。（同一頁摘要也列 `stream_reassemble` 規則選項可對單邊關閉重組。）
- **Snort 2 http_inspect `flow_depth`／`client_flow_depth`**：既有筆記 M8 已涵蓋 [既有筆記 research/literature/trust-bypass/mechanisms.md M8]，未重查。

### B5. 搜尋紀錄（C6 要求）

八個查詢（2026-11-02，WebSearch）：(1) application-layer cutoff per-request per-message truncation first bytes HTTP request；(2) IDS inspect only client-to-server direction unidirectional asymmetric coverage；(3) transaction-level sampling IDS application-aware sampling protocol messages；(4) Madhyastha Krishnamurthy 應用專用 flow sampling；(5) Limmer Dressler DPA；(6) Snort stream5 ports client/server；(7) ET/Snort 規則 to_server／to_client 比例統計；(8) IDS 跳過 server response 只檢查 request 的效能評估。

- 找到：HPA、DPA、FPA（上列）。
- **沒找到**：(i) 隨機抽樣「應用層交易」的 IDS 論文；(ii) 量測「只檢查 C→S 方向」偵測損失的論文（只有廠商文件講非對稱路由使 stateful IPS 失效：Fortinet、Gigamon，屬 [二手-搜尋摘要]，內容是路由問題不是設計選擇）；(iii) 量測攻擊 payload 在請求／回應方向比例的論文。
- **僅二手、沒取得全文**：Madhyastha & Krishnamurthy, "A Generic Language for Application-Specific Flow Sampling", ACM SIGCOMM CCR 2008（搜尋結果給的 `web.eecs.umich.edu/~harshavm/papers/ccr08.pdf` 回 404；內容是以模板語言讓路由器依 IDS 規則產生 flow 樣本，粒度為 flow record 不是應用層訊息）[二手 搜尋摘要]；Braun, Münz, Carle, "Packet Sampling for Worm and Botnet Detection in TCP Connections", NOMS 2010（取連線前 N bytes 的取樣演算法，Time Machine 的變體）[二手 搜尋摘要，PDF 網址 director.net.in.tum.de/publications/papers/braun10packet-sampling.pdf 未下載]。

---

## 2. 各問題的回答

### C1. midstream 在 IPS／IDS 的建立與方向
見 A1。補充表格（8.0.7，wnc-gw 目前設定：midstream=true、policy=ignore）：

| 項目 | ids（NFLOG） | ips（NFQ） |
|---|---|---|
| 首封包為 ACK／PSH-ACK | 建 ESTABLISHED，首封包發送端＝client | 同左 |
| 首封包為 SYN/ACK | 建 SYN_RECV 並翻轉方向 | 同左 |
| midstream=false 的預設命運 | 忽略（不追蹤、不偵測）[文件 exception-policies.rst:158-172] | `exception-policy: auto` → drop-flow，整條流量被丟 [同文件 :195-212] |
| 資料何時餵 app-layer | 對方向 ACK 觸發，且只到 `last_ack`（A3） | 每個封包立即（A3） |
| 協定偵測可翻轉方向 | 是（app-layer.c:455-470） | 是 |
| invalid 封包 | 不處理，不丟 | `drop-invalid`（預設開）會丟 [stream-tcp.c:443-447,5866-5872] |

### C2. app-layer 協定偵測與 parser 能否中途開始
見 A2。摘要：HTTP 從 method 開頭起可偵測與解析；中間起點→偵測失敗→midstream 在 to_server 找不到協定就永久關 app-layer（raw／packet 規則仍有效）；`http.uri` 可比對（但受 C4 的 `flow:established` 影響）；`http.request_body` 要等 32 KiB／交易結束／EOF。MQTT：port 1883 的 PUBLISH 起點可偵測；protocol_version 恆 0（v5 屬性不解）；不接受 gap。

### C3. 單向可見
見 A3。摘要：IDS 要 `async-oneside=true`（或實驗 `stream.inline=yes`）才會在沒有 ACK 時餵資料；IPS 本來逐封包餵，但「只送 C→S」有 `INVALID_ACK`→`PacketDrop` 的推導風險（E3）。

### C4. 單一封包
見 A4。摘要：接手封包本身沒有 `FLOW_PKT_ESTABLISHED`（推導），97.2% 的 ET TCP 規則帶 `flow:established`；stream 型 content 規則在 IDS 下不比對（資料未被 ACK），在 IPS 下比對該封包；`depth`／`offset` 規則看 packet。

### C5. 交易層級限制
見 A5。確認：`request-body-limit` 是每交易 body、`stream.reassembly.depth` 是每連線每方向（序號空間）；兩者都不省 NFQ 往返。

### C6. 文獻
見 B1–B5。摘要：HPA（每訊息前 N bytes）、DPA（每次方向改變後前 N bytes，僅靠序號）、FPA（連線前 N bytes）是確定性 cutoff 家族；沒有找到隨機抽樣交易、單向檢查、攻擊方向比例的論文。自數 ET Open：有方向的 TCP 規則 85% to_server。

**對「均勻抽樣機率＝抽樣比例」問題的意涵（[推測]）**：
- 逐封包隨機抽樣的問題不只是機率，而是被抽到的封包是不連續片段，Suricata 對它的 app-layer 與 stream 規則幾乎都不比對（既有筆記 mechanisms.md §7.5；本組 A2–A4 補上具體機制）。
- 以「訊息」為單位抽樣（或 cutoff）可把「被抽到後能被偵測」的條件機率從接近 0 拉到接近 1（HPA 在 N=500 B 約 97%、DPA 在 N=2000 B 約 90%，皆為相對未過濾 Snort 的事件數），這是 (b) 的潛在可宣稱貢獻；但 HPA／DPA 的資料基準都不是攻擊者可預測 cutoff 的情境，**論文都沒有討論 cutoff 被規避**（HPA 全文無此討論；Time Machine 才有，既有筆記 §6）。
- 確定性 cutoff（每則訊息前 N）與隨機抽樣是兩種不同的風險：前者攻擊者把 payload 放在 N 之後就完全逃過；後者每則訊息只有機率 p。可行的組合（[推測]）：每則訊息前 N 必送（對應 DPA 的觸發）＋N 之後的訊息部分隨機抽樣，但目前沒有文獻量測這個組合。

### C7. 需要在 Docker 實測的問題（可直接設計實驗）

共通設定：Docker testbed 用 Suricata 8.0.7（與 Pi 同版）；wnc-gw 的 FORCED_SETTINGS 開著；`stats` 輸出 `exception-policy` 與 `ips.drop_reason`；EVE 開 `alert`、`flow`、`http`、`mqtt`、`stats`。ips 用 NFQ、ids 用 NFLOG（與專案 `Delivery::Queue`／`Delivery::Copy` 一致）。流量用 scapy 或 netcat／curl／mosquitto 產生，取樣用 nft 規則或預先切好的 pcap 控制「Suricata 看得到哪些封包」。可觀察計數器名稱（原始碼確認存在）：`tcp.midstream_pickups`、`tcp.sessions`、`tcp.ack_unseen_data`、`tcp.reassembly_gap`、`ips.drop_reason.stream_error`、`ips.drop_reason.stream_midstream`；stream 事件規則關鍵字 `stream-event:est_invalid_ack`、`pkt_invalid_ack`、`est_pkt_before_last_ack`、`reassembly_seq_gap`、`reassembly_depth_reached`。

測試規則（每個實驗共用）：
- R1 `alert http any any -> any any (msg:"R1"; flow:established,to_server; http.uri; content:"/evil"; sid:1;)`
- R2 同 R1 但 `flow:to_server`（不帶 established），sid:2
- R3 `alert tcp any any -> any any (flow:established,to_server; content:"EVIL"; sid:3;)`（stream 型）
- R4 `alert tcp any any -> any any (flow:established,to_server; content:"EVIL"; depth:200; sid:4;)`（packet 型）
- R5 `alert http any any -> any any (flow:established,to_server; http.request_body; content:"EVIL"; sid:5;)`
- R6 `alert mqtt any any -> any any (flow:established,to_server; mqtt.publish.message; content:"EVIL"; sid:6;)`
- R7 `alert tcp any any -> any any (stream-event:est_invalid_ack; sid:7;)`

| 編號 | 要回答的問題（對應） | 輸入流量 | 設定與切換 | 看什麼 | 判讀 |
|---|---|---|---|---|---|
| **E1** | midstream 起點與方向（C1、A1） | 一條 HTTP/1.1 keep-alive 連線，從 (i) client 的 request 第一包，(ii) server 的純 ACK，(iii) server 的 `HTTP/1.1 200` 資料包，(iv) request header 中間的封包，(v) POST body 中間，開始讓 Suricata 看到（之後所有封包都給） | ids 與 ips 各跑；`stream.midstream=true` | `tcp.midstream_pickups`；EVE `flow` 事件的 `src_ip`／`dest_ip`（誰被當 client）；`app_proto`；R1、R2 是否告警；`app_proto: failed`？ | (i) 應告警；(ii) 方向是否顛倒；(iii) 是否被協定偵測翻轉；(iv)(v) 是否 `app_proto` 為 failed 且 R1 不告警（驗證 A2） |
| **E2** | 接手封包是否缺 `FLOW_PKT_ESTABLISHED`（C4、A4） | 單一完整 `GET /evil HTTP/1.1` 資料封包（PSH\|ACK）；變體：之後多給 0／1／2 個封包（server 的 ACK、server 的回應） | ips 與 ids；把 `flow-timeouts.tcp.established` 調成 10 s 以便觀察逾時 pseudo packet 的告警 | R1、R2、R3、R4 各在哪個封包（EVE `pcap_cnt`）告警、有沒有告警；時間戳 | 若 R1 在只有該封包時不告警、R2 告警，驗證 A4 的 `flow:established` 推導；找出「至少後續幾個封包」才讓 R1 告警；是否要等逾時 |
| **E3** | IPS 下只送 C→S 是否被 Suricata 丟封包（C3、A3） | 客戶端 curl 下載 10 MB（server 大量回資料）；nft 只把 C→S 且 payload>0（變體：含純 ACK）的封包送 NFQ，S→C 與其餘 ct mark 放行 | (1) 預設；(2) `stream.async-oneside=true`；(3) `stream.drop-invalid=no`；(4) `stream.midstream-policy=pass-flow` | 下載是否完成與耗時；`ips.drop_reason.stream_error`；R7 告警數；`tcp.ack_unseen_data`；R1/R3 對 C→S payload 是否仍告警 | 若 (1) 下載卡住且 stream_error 增加，驗證 A3 的 INVALID_ACK→PacketDrop 推導；(2)(3) 是否消除；副作用（R3 是否仍比對） |
| **E4** | IDS 下只送 C→S 的延遲與可檢性（C3、A3） | 同 E3 的流量，用 NFLOG 只複製 C→S 封包 | (1) 預設；(2) `async-oneside=true`；(3) `stream.inline=yes`（IDS） | R1／R3 告警是否出現、距離封包的延遲（秒）；`app_proto`；`tcp.reassembly_gap`；是否等到 flow 逾時才告警 | 驗證 A3「IDS 單向預設吃不到資料」；比較 (2)(3) 的告警延遲與誤差 |
| **E5** | 同一連線多段取樣的狀態延續（C5、跨交易） | 一條 keep-alive HTTP 連線 200 個 request（含 /evil 在第 150 個）與一條 MQTT 長連線（PUBLISH 100 則）；Suricata 只看第 10–12 與第 150–152 個（兩段）；段間資料量 X ∈ {100 KB, 2 MB, 20 MB}、時間間隔 ∈ {10 s, > flow-timeouts.tcp.established（設 30 s）} | ips 與 ids 各跑；`reassembly.depth` 設 1 MiB 與 64 KiB 兩種 | R1／R6 是否在第二段告警；`stream.reassembly_depth_reached`（R 用 stream-event）；R7 `est_invalid_ack`；`tcp.reassembly_gap`；`ips.drop_reason.stream_error`；MQTT 的 `app_layer.error.*` gap 計數與 `app_proto` 是否保持 | 驗證 A5 的 depth 以序號空間計、A2 的 MQTT 不接受 gap、A3 的 INVALID_ACK 是否在跳號時出現；時間間隔 > 逾時是否變成新 session 而恢復偵測 |
| **E6** | parser 在中途／gap 的行為（C2） | HTTP：request header 中間起、有 gap 的 request（header 缺一個封包）、POST 缺 body 後半；MQTT：port 1883 與 1884 的 PUBLISH 起點、MQTT 3.1.1 與 5.0（帶 properties）的 PUBLISH | `detection-ports` 對 1884 開／關 | EVE `http`／`mqtt` 事件的欄位（uri、topic、message 是否含 properties 前綴）；`app_proto`；R5、R6 | 驗證 A2 的 gap 行為與 v5 屬性被當成 message 內容 |
| **E7** | body-limit／depth 只省 Suricata CPU、不省 NFQ 往返（C5） | POST 1 MB body，pattern 在 body 的 offset 200 與 200,000；keep-alive 連線上連續 50 個 request | `request-body-limit` ∈ {0, 4096}；`stream.reassembly.depth` ∈ {0, 64 KiB}；ips | R5 是否告警（兩個 offset）；後續 request 是否仍被解析（`http` 事件數）；Suricata worker 的 CPU（`/proc/schedstat` rq_cpu_time，非 /proc/stat，見記憶「Pi 量 CPU 的方法」）；NFQ 每秒封包數與 verdict 數不變 | 確認 A5：CPU 下降但封包往返數不變；depth 造成後續 request 漏檢 |
| **E8** | 單一封包的 stream／packet 規則（C4） | 單一 C→S 資料包 payload 含 `EVIL`（PSH\|ACK），無其他封包 | ips 與 ids | R3、R4 是否告警；ids 在封包後 5 s、flow 逾時後各是否告警 | 驗證 A4：IDS 下 R3 不告警、R4 告警；IPS 下 R3 告警 |
| **E9** | 方向顛倒的後果（C1） | 取樣起點為 S→C 純 ACK，隨後 C→S 的 `GET /evil`；變體：MQTT PUBLISH 起點在 server→client 方向 | ips | EVE `flow` 方向；R1／R2／R6 是否告警 | 驗證 A1 的方向修正只在明文 pattern 協定有效 |

**不需要實驗就能引用的結論**：IPS 預設 midstream 關會 drop-flow（文件矩陣＋程式碼一致）；HTTP 偵測靠 method pattern；MQTT parser 不接受 gap；`request-body-limit` 為每交易 body。**必須實驗才能下結論的**：E2（`flow:established`）、E3（INVALID_ACK→丟包）、E5（跨段狀態延續）。

---

## 3. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| ET Open 有方向的 TCP 規則中 to_server 比例 | 85.0%（31,353／36,891） | 37,985 條 TCP 類 alert 規則，2026-10-30 版 | 自數 `python3 -I` 腳本；規則檔取自 rules.emergingthreats.net |
| ET Open HTTP 相關規則 to_server 比例 | 84.5%（19,751／23,372） | 23,430 條 | 同上 |
| ET Open TCP 規則帶 `flow:established` 比例 | 97.2%（36,938／37,985） | 同上 | 同上 |
| HPA：分析的資料量／偵測到的事件 | 2.5%（47,527 kB／1,878,836 kB）／97.4% | N=500 B、proxy trace 一週＋110 次人為攻擊；事件以未過濾 Snort 告警為基準 | [原文 HPA p.421-422，Table I] |
| HPA 對 pipelined 攻擊 | 22/22；DPA、FPA 為 1/22 | N=500 B | [原文 HPA p.422，Table II] |
| HPA 吞吐量 | Snort 約 15,000 pps 開始丟包；HPA＋Snort 約 180,000 pps（N=2000 B）、670,000 pps（N=500 B）零丟包；加速 12 倍／44 倍 | i5-4440、PF_RING、10 GbE | [原文 HPA p.423] |
| HPA 規則分析 | 67% active 規則與 HTTP 有關；其中用 `http_*` 的 94% 作用在 header；約 62% HTTP 規則在訊息開頭搜 content | 2017-01-15 的 Snort＋社群＋ET，27,375 條 active 規則 | [原文 HPA p.419] |
| DPA：資料量／事件 | 3.7%／89.8%；HTTP 2.5%／99.2%；SMTP 7.0%／60.1% | N=2000 B、600 條 10 分鐘大學上行 trace | [原文 DPA p.837] |
| DPA 吞吐量 | 增加 400%；理論加速 > 25 倍 | Core2 Quad 2.83 GHz，Vermont＋Snort | [原文 DPA 摘要 p.833；p.837] |
| FPA（引自 DPA） | 整體 1.0% 資料／78% 事件；HTTP 83%、SMTP 60% | N=2000 B | [二手 DPA p.835] |
| 實際流量中 URL 位於連線開頭的比例 | 約 60% | 36 條 trace、130 萬個 URL | [原文 DPA p.835] |
| HTTP request 段長度 | 80% 在 300–1500 B | to-server 方向 | [原文 DPA p.837] |
| Suricata 預設 TCP established 逾時 | 600 s | 範本 yaml | [原始碼 suricata.yaml.in:1622-1630 @8.0.7] |
| Suricata `request-body-limit`／min-inspect／window | 100 KiB／32 KiB／4 KiB | 範本 yaml | [原始碼 suricata.yaml.in:1139-1146 @8.0.7] |
| Suricata `stream.reassembly.depth`／chunk size | 1 MiB／2560（隨機 ±10%） | 範本 yaml | [原始碼 suricata.yaml.in:1734-1737 @8.0.7] |
| midstream 假設的 window scale | 14（`TCP_WSCALE_MAX`） | ACK 接手 | [原始碼 stream-tcp.c:1518-1519 @8.0.7] |
| 平台成本（SPEC 給定，非本組量測） | 約 40 µs／封包進 NFQ＋Suricata；信任後省 39–67 µs | Pi 4、鎖 1000 MHz | SPEC §1 |

---

## 4. 建議追加閱讀（≤ 5 篇）

1. **Limmer & Dressler, "Flow-based Front Payload Aggregation", LCN 2009** —— 已下載，本組只略讀；若要宣稱 FPA 數字或其「簡單重組可被騙」的限制，需精讀。存在確認：全文已取得。
2. **Limmer 博士論文（2011，FAU Erlangen）** —— DPA 的完整版本，搜尋摘要說保留 89% 事件、分析約 4% 資料，可能有按方向或按規則類別的分析（本組沒取得）。存在確認：僅二手（搜尋摘要）。
3. **Tsikoudis, Papadogiannakis, Markatos, "LEoNIDS: A Low-Latency and Energy-Efficient Network-Level Intrusion Detection System", IEEE TETC 2016** —— HPA 引為 [21]，稱「每條 flow 取前 500 KB 涵蓋 99% 威脅」；若要引用請讀全文確認。存在確認：僅二手（HPA 引述）。
4. **Gonzalez & Paxson RAID 2006 / Maier et al. SIGCOMM 2008** —— 屬 SPEC 已讀範圍，不重讀；列在此是提醒「cutoff 被規避」的討論以它們為準。
5. **Suricata 官方 issue／論壇中 midstream 與 ACK 驗證的討論（`STREAM_EST_INVALID_ACK`、midstream pickup 後被丟封包的案例）** —— 為驗證 A3 的推導；我沒搜到，建議等 E3 結果再決定要不要查。存在確認：未能確認。

---

## 5. 自評：最不確定的三件事

1. **A3 的 INVALID_ACK→丟封包推導**（只送 C→S 的 IPS 設計 (a) 是否被 Suricata 自己切斷）。我讀了每一段相關程式碼，行為鏈成立（`server.next_win = last_ack`、`ValidateAck` 的 `SEQ_GT(ack, next_win)`、`drop-invalid` 預設開、`PacketDrop`），但沒有執行；可能有我漏看的前置路徑（例如 `StreamTcpPacket` 開頭的檢查或 keepalive／spurious retransmission 判斷）。E3 是第一優先，因為它決定 (a) 在 ips 模式能不能成立。
2. **A4 的「接手封包沒有 `FLOW_PKT_ESTABLISHED`」與 tx 規則是否會在後續封包重試**。旗標設定順序是從 `flow-worker.c` 與 `flow.c` 讀出來的，但 tx 規則在後續封包是否會重新檢查（取決於 `updated_ts`／`detect_progress` 狀態）我沒讀完；若會重試，單一封包 (c) 的影響會小很多；若不會，ET 規則 97.2% 帶 `flow:established` 使 (c) 幾乎無用。E2 決定。
3. **跨段取樣的狀態延續（stream depth 以序號空間計、MQTT gap、ACK 視窗）**。這是我從 `StreamTcpReassembleCheckDepth` 與 `AppLayerParserParse` 讀出的，尚未驗證 `base_seq` 在 gap 後是否前進；結論直接影響 (b) 的設計——若成立，取樣窗口之間必須 > 600 s 或某種方式讓 Suricata 丟掉舊 session，否則第二段之後的偵測可能全部失效。E5 決定。

附：論文部分，HPA／DPA 的「事件」都是相對未過濾 Snort 告警，不是真實攻擊偵測率；且兩篇資料都不是 IoT／公司內外網混合流量。
