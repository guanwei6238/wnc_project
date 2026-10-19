# 信任式 Fast Path：現有 IDS / Linux「讓 flow 跳過檢測」的實作機制調查

調查日期 2026-10-16。對應子題：`SPEC_ADDENDUM.md` §1（gateway 在 flow 開頭判定安全後走 fast path，仍抽樣送分析，異常則 ban 或轉回 slow path）。
本檔是**實作機制調查**，不是單篇論文報告；每個機制一節，欄位固定為：機制說明 / 放行判定時機 / 放行後保留的可見性 / 能否撤銷 / 對我們 Pi 的可用性與 [推測]。

---

## 0. 讀法、版本與證據標記

**實際讀的版本（重要，因為 Suricata 在 master 與 7.x 有行為差異）**

| 代號 | 內容 | 為什麼選它 |
|---|---|---|
| S7 | Suricata tag `suricata-7.0.10` 原始碼與文件 | Debian trixie 的 `suricata` 套件就是 `1:7.0.10-1+deb13u4`（含 arm64）；專案 `tests/ids_throughput/REPORT.md` 也用 7.0.10 |
| SM | Suricata `master`（約 9.0-dev，2026-10-16 下載） | 對照新版行為 |
| Snort3 / libdaq / Zeek | 各自 `master`（2026-10-16 下載） | Snort 3 實測版本為 3.12.2.0（見 REPORT.md），小版本差異未逐一比對 |
| K | Linux stable `v6.12` 原始碼與 `Documentation/` | Debian trixie / Raspberry Pi OS 的 kernel 線；實際 Pi kernel 的 config 未核對 |
| nft(8) | `manpages.debian.org/trixie/nftables/nft.8.en.html`（nftables 1.1.3-1） | trixie 的版本 |

**證據標記**

- `[S7 檔:行]` `[SM 檔]` `[K 檔:行]`：我讀了原始碼（以 curl 抓成純文字閱讀，未編譯、未執行）。
- `[文件 URL]`：官方文件原文。
- `[原文 p.N / §N]`：論文全文（已下載並以 pdftotext 閱讀）。
- `[二手-摘要]`：只透過搜尋摘要或 WebFetch 的摘要看到，沒讀到全文；此類結論可信度較低。
- `[推測]`：我的推論，不是來源寫的。`未能確認`：找不到證據。

**邊界聲明**：沒有對本機或 Pi 下任何 `nft` / `conntrack` 指令，沒有安裝任何東西；下載的檔案都放在 session scratchpad，只當文字讀。

---

## 1. 總覽矩陣

「放行單位」= 放行決定作用在什麼粒度；「誰擋封包」= 放行後封包是在哪一層被拿掉。

| # | 機制 | 放行單位 | 誰擋封包 | 放行後 IDS 還看到什麼 | 能撤銷？ | Pi 上可用？ |
|---|---|---|---|---|---|---|
| M1 | Suricata `stream.reassembly.depth`（不開 bypass） | TCP 單向 byte 數 | Suricata 內部（停止重組） | 封包仍進 Suricata；只有 packet 層規則、flow 記錄 | 否（無對應程式碼） | 可，僅 CPU 省一部分 |
| M2 | Suricata `stream.bypass` / `bypass` 關鍵字 / TLS・SSH `encryption-handling: bypass` | flow | 見 M3/M4/M5 | 見 M3/M4/M5 | 否 | 可 |
| M3 | Suricata local bypass | flow | Suricata（讀進封包、查 flow 表後直接放行） | 只有 flow 記錄與計數 | 否（只有逾時淘汰） | 可，但每個封包仍走 NFQ 往返 |
| M4 | Suricata capture bypass — NFQ | 觸發封包的 mark | **Netfilter 規則（需要我們自己寫）** | 只有觸發前的封包；EVE flow 的後續計數缺失 | Suricata 不能；kernel 端可 | 可（套件有 `--enable-nfqueue`），**需自寫 ct mark 規則** |
| M5 | Suricata capture bypass — AF_PACKET eBPF / XDP | flow（kernel map） | eBPF / XDP 程式 | 計數由 kernel map 回填 | 逾時後淘汰 | 文件限定 IDS（鏡像）情境，**不適用我們的 inline 轉送**；XDP native 未查 |
| M6 | Suricata `pass` 規則 | flow | Suricata（`FlowSetNoPacketInspectionFlag`） | Eve 仍產生 | 否 | 可（對照用，不省 NFQ 往返） |
| M7 | Snort 3 trust / DAQ `WHITELIST` | flow | Snort 內部；DAQ NFQ 與 AF_PACKET 模組把 WHITELIST 轉成 PASS | 無 | 否（未見 un-trust） | 可，但**只是 local，不是 kernel fast path** |
| M8 | Snort 3 depth 類參數 | 單一 inspector / 佇列 | inspector 內部 | 其餘照常 | 不適用 | 可 |
| M9 | Zeek `skip_further_processing` | connection | Zeek 內部（不重組、不產生 analyzer 事件） | 連線層事件、conn.log | 未見 un-skip BIF | Zeek 未在專案中使用 |
| M10 | Zeek BPF shunt / NetControl shunt | 連線 5-tuple 或 host pair | BPF capture filter / 外部交換器 | SYN・FIN・RST 仍放進來（BPF 版） | 是（逾時、解除 API，但 BPF 版延遲數分鐘） | 概念可借用 |
| M11 | Zeek XDP shunter（`xdp-zeek`，Corelight） | 5-tuple / IP pair | XDP_DROP | 計數在 BPF map，shunt 結束才寫 `xdp_shunt.log` | 逾時驅動，延遲 | 需 XDP；Pi 3B+ USB NIC 多半只有 generic（簡報稱 generic「僅供測試」） |
| M12 | Shunting 硬體（CCS'07）與 Time Machine cutoff | 連線；forward-N（序號空間） | NetFPGA 快取表 / 擷取層 cutoff | 控制封包（FIN/RST）永遠轉給 IDS／永遠存 | 是（IDS 改表；TM 可 suspend_cutoff） | 概念可借用 |
| M13 | SciPass / Science DMZ | flow（OpenFlow 規則對） | OpenFlow 交換器 | IDS 不再看到；防火牆也被繞過 | idle timeout 到期 | 概念可借用 |
| M14 | nftables flowtable | flow（conntrack） | netdev ingress hook 上的 fast path | 僅 conntrack 計數（需開 counter）；FIN/RST 回到一般路徑 | 逾時、FIN/RST、route 變動、ct 被刪 | 需確認 Pi kernel config |
| M15 | `ct mark` + `queue` 組合 | flow（ct mark） | forward chain 前段規則 | 規則計數、conntrack 計數 | 可（改 ct mark） | 可（nftables 1.1.3、kernel 6.x 皆有） |
| M16 | `numgen random` / `limit` 抽樣 | 封包 / 每元素 | forward chain | 被抽到的封包 | 不適用 | 語法細節待驗證 |

---

## 2. Suricata

### M1. `stream.reassembly.depth`（只截斷、不一定 bypass）

**機制說明**
- 設定鍵 `stream.reassembly.depth`：TCP 每個方向最多重組到這麼多 byte。文件原文：「Reassembling a stream is an expensive operation. With the option depth you can control how far into a stream reassembly is done. By default this is 1MB.」[文件 https://docs.suricata.io/en/latest/configuration/suricata-yaml.html，原始檔 `doc/userguide/configuration/suricata-yaml.rst` master 約 1365-1368 行]。
- Debian 套件隨附的設定檔 `reassembly:` 區塊有明確一行 `depth: 1mb  # reassemble 1mb into a stream` [S7 suricata.yaml.in:1614]。
- **預設值陷阱（我認為這點最容易被誤用）**：文件說「預設 1MB」，但程式碼在 7.0.10 與 8.0.0 的行為是：設定檔**沒寫這個鍵時** `reassembly_depth = 0`，而 0 的語意是「不限制」[S7 stream-tcp.c:619-631（`else { stream_config.reassembly_depth = 0; }`）；S7 stream-tcp-reassemble.c:657-661（"if the configured depth value is 0, it means there is no limit"）；8.0.0 tag 的 stream-tcp.c 同樣是 `= 0`]。master 才新增 `STREAM_DEPTH_DEFAULT 1024 * 1024` [SM stream-tcp.c]。所以 1 MiB 在 7.0.x 是「設定檔預設」而不是「程式碼預設」。
- 到達 depth 的後果：該方向設 `STREAMTCP_STREAM_FLAG_DEPTH_REACHED`，通知 app-layer「此方向不會再有資料」（truncate），封包標記不寫 pcap [S7 stream-tcp.c:5499-5520；SM stream-tcp-reassemble.c 約 2092-2108]。

**放行判定時機**：單向累積 byte 超過 depth 的那個封包（任一方向先到就算）。

**放行後保留的可見性**：封包仍進 Suricata 並建立／更新 flow、flow 記錄照常輸出；raw stream 與 app-layer 內容不再被檢測，packet 層規則仍可比對。論壇上有人在 IDS 模式觀察到 depth 前後的 packet 偵測行為不一致（跨越 depth 的封包不被偵測、之後又偵測到），但這是使用者回報不是開發者結論 [二手-摘要 https://forum.suricata.io/t/detecting-a-packet-after-reassembled/1436]，**我不把它當成結論**。

**能否撤銷**：未見對應程式碼。flag 一旦設上，該 session 一直保持。

**Pi 可用性與 [推測]**：直接可用，是純軟體設定。[推測] 它只省 reassembly／app-layer 的成本，每個封包仍要走 NFQ 到 Suricata 再回來，所以**不省 NFQ 往返成本**，也不省 kernel 轉送路徑；若目標是降低 Pi 上的轉送負擔，要靠 M2→M4。

### M2. bypass 的觸發源（stream.bypass、`bypass` 關鍵字、encryption-handling）

這些都不直接放行，而是呼叫同一個函式 `PacketBypassCallback(p)`（M3/M4/M5 才是真正的放行機制）。

| 觸發源 | 設定鍵與預設 | 觸發點 | 出處 |
|---|---|---|---|
| TCP depth 到達 | `stream.bypass`，預設 `no`；yaml 註解：「Bypass packets when stream.reassembly.depth is reached. Warning: first side to reach this triggers the bypass.」文件警告：「`bypass` can lead to missing important traffic. Use with care.」 | 任一方向到 depth 的封包 | [S7 suricata.yaml.in:1557-1559；S7 stream-tcp.c:5499-5507] |
| `bypass` 規則關鍵字 | 無鍵；規則寫 `bypass;`，例：`alert http any any -> any any (http.host; content:"suricata.io"; bypass; sid:10001; rev:1;)` | **post-match**：規則完整比對成功後才呼叫（`DETECT_SM_LIST_POSTMATCH`）；不能與 `filestore` 併用 | [文件 https://docs.suricata.io/en/latest/rules/bypass-keyword.html；S7 detect-bypass.c:94 與 Setup] |
| TLS/SSH/QUIC 加密後 | `app-layer.protocols.tls.encryption-handling`（以及 `ssh`、`quic`），預設 `track-only`，可為 `bypass`／`full`。文件：`bypass` 時「all processing of this session is stopped … This will also lead to the flow being bypassed, either inside Suricata or by the capture method」 | handshake 完成、判定為加密後；parser 設 `APP_LAYER_PARSER_BYPASS_READY` → `StreamTcpSetSessionBypassFlag` | [SM 文件 doc/userguide/configuration/suricata-yaml.rst:2018-2022；S7 app-layer-ssl.c:2357,2570；S7 app-layer-parser.c:1472-1479；S7 stream-tcp.c:6522-6525] |
| reassembly memcap 超限 | `stream.reassembly.memcap-policy: bypass`（僅 IPS 模式） | 超過記憶體上限時 | [SM 文件 suricata-yaml.rst:1362-1363] |

**版本差異（重要）**：7.0.10 中，TLS `encryption-handling: bypass` 設好 session 的 `STREAMTCP_FLAG_BYPASS` 之後，仍要 `StreamTcpBypassEnabled()`（即 `stream.bypass: yes`）為真才會呼叫 `PacketBypassCallback`；master 則無此條件 [S7 stream-tcp.c:5522-5526 與 6888-6891；SM stream-tcp.c 約 5873-5875]。意思是在 7.0.10 要讓 TLS 加密後真的 bypass，**兩個鍵都要開**。
在 7.0.10，`PacketBypassCallback` 的呼叫處只有 `stream-tcp.c`（3 處）與 `detect-bypass.c`（1 處）[S7 grep 結果]，所以 `stream.bypass` 與 TLS 路徑只作用於 TCP，UDP 只能靠 `bypass` 關鍵字；master 的 `app-layer.c` 另有呼叫處（7.0.10 沒有）。

**放行判定時機、可見性、撤銷、Pi**：見 M3/M4/M5。

### M3. Local bypass（Suricata 內部放行）

**機制說明**：`PacketBypassCallback` 在沒有 capture bypass 能力（`p->BypassPacketsFlow == NULL` 或回傳 0）時，把 flow 設成 `FLOW_STATE_LOCAL_BYPASSED` [S7 decode.c:442-485]。之後每個封包到 `FlowWorker` 先查 flow 表，狀態是 bypassed 就**跳過 stream、detect、output**，只累加 `flow_bypassed.local_pkts/local_bytes`，在 IPS 模式照常給 verdict [S7 flow-worker.c:242-263；文件 https://docs.suricata.io/en/latest/performance/ignoring-traffic.html 「Local bypass」段]。
- 逾時：`LOCAL_BYPASSED` 用 `flow-timeouts.<proto>.bypassed`（預設 100 秒，`emergency-bypassed` 預設 50 秒）；`CAPTURE_BYPASSED` 在 7.0.10 則是固定常數 `FLOW_BYPASSED_TIMEOUT 100`，不可設定 [S7 flow-private.h:65 與 102-128；S7 suricata.yaml.in:1500-1527]。local bypassed 的 flow 每來一個封包就更新 `lastts`，所以只要封包持續來就不會逾時 [S7 flow.c:423-444，非 capture-bypassed 分支更新時間戳]。

**放行判定時機**：由 M2 的觸發源決定（depth／規則比對成功／加密判定）。

**放行後保留的可見性**：flow 記錄（見 §2.7）、`stats.flow_bypassed.local_*` 計數。沒有 alert、沒有 app-layer 記錄；master 的程式碼註解說，轉入 bypass 時已排程的 tx logger 會先跑完再釋放 app-layer 狀態 [SM flow-worker.c:676 附近 `FlowIsBypassed` 清理段；7.0.10 對應段未逐行比對]。

**能否撤銷**：我在讀過的 `decode.c`、`flow.c`、`flow-worker.c` 中**沒有找到把 bypassed 狀態改回去的程式碼**；`flow.c:512-514` 還特別避免把 bypassed 狀態覆寫成 ESTABLISHED。唯一的「出口」是 flow 逾時被淘汰 [S7 flow.c:512-514；S7 flow-manager.c:215-258]。[推測] 結論是 Suricata 內部**不能對同一條還活著的 flow 再次開始檢測**；撤銷必須靠 flow 淘汰後以新 session 重新進來。

**Pi 可用性與 [推測]**：可用。[推測] local bypass 在 NFQ 模式下省的是 Suricata 的 CPU（stream／detect／output），**不省 netlink 往返**：封包仍要從 kernel 送到 userspace 再回 verdict。

### M4. Capture bypass — NFQ（我們最重要的一節）

**機制說明（逐步，全部來自原始碼）**

1. 設定 `nfq.bypass-mark` 與 `nfq.bypass-mask`（`suricata.yaml` 預設兩者都被註解，值例 `1`）。**只有 `bypass_mask` 非 0 時**，每個進來的封包才會掛上 `p->BypassPacketsFlow = NFQBypassCallback` [S7 source-nfq.c:248-253（讀設定）, 537-539（掛 callback）；S7 suricata.yaml.in:1919-1926]。沒設的話，NFQ 模式下的 bypass 只會是 M3 local bypass。
2. 觸發（M2）時 `PacketBypassCallback` 呼叫 `NFQBypassCallback`：它只做
   `p->nfq_v.mark = (bypass_mark & bypass_mask) | (p->nfq_v.mark & ~bypass_mask); p->flags |= PKT_MARK_MODIFIED;` 然後回傳 1，flow 狀態轉成 `FLOW_STATE_CAPTURE_BYPASSED` [S7 source-nfq.c:497-518；S7 decode.c:469-472]。
3. 送 verdict 時才把 mark 帶回 kernel：`nfq_set_verdict2(..., mark, ...)`，對應 netlink 屬性 `NFQA_MARK`，kernel 端寫入 `skb->mark` [S7 source-nfq.c:1117-1140；K nfnetlink_queue.c:1333 與 1462-1463]。
4. **整個 `source-nfq.c` 沒有任何 conntrack / connmark 操作**（我 grep 過 `conntrack|connmark|nfct|ct_mark`，無結果）。也就是說 **mark 只貼在觸發的那一個封包上**。yaml 註解寫得很直接：「Suricata will set the bypass mark/mask on packet of a flow that need to be bypassed. The Netfilter ruleset has to directly accept all packets of a flow once a packet has been marked.」[S7 suricata.yaml.in:1917-1920]。
5. 之後同一條 flow 的封包若仍進到 queue（規則還沒生效或沒寫），Suricata 在 `FlowUpdate` 看到 `CAPTURE_BYPASSED` 就直接 `TM_ECODE_DONE`，計入 `flow_bypassed.local_capture_pkts/bytes`，**不會再貼 mark** [S7 flow-worker.c:244-251]。
6. 若 `CAPTURE_BYPASSED` 的 flow 在超過 `FLOW_BYPASSED_TIMEOUT / 2`（常數 100 秒，所以 50 秒）沒有更新後又看到封包，flow 會被「降級」成 local bypass（`Downgrading flow to local bypass`）[S7 flow.c:433-439；S7 flow-private.h:65]。

**所以「是否用 conntrack mark？」的答案**：Suricata **不碰 conntrack**；它只給單一封包的 `skb->mark`。要讓「後續封包不進 queue」，必須由**我們的 nftables 規則**把這個 mark 存進 conntrack（`ct mark set meta mark`，nft(8) 範例原文：「save packet nfmark in conntrack. `ct mark set meta mark`」），並在 queue 規則**之前**用 `ct mark` 放行。這部分 Suricata 官方文件只說「規則集要直接 accept」，沒有給 nftables 範例 [S7 doc/userguide/setting-up-ipsinline-for-linux.rst 查無 connmark 字樣]。
- nft 端的語意細節（決定規則怎麼寫，詳見 M15）：`queue` 是終止性 verdict；userspace 回 accept 後「processing resumes with the next base chain hook, not the rule following the queue verdict」[nft(8) VERDICT STATEMENT；K nfnetlink_queue.c:312-368，`nf_reinject` 內 `++i; nf_iterate(...)`]。所以「queue 之後再寫 `ct mark set meta mark`」要放在**另一條 priority 更大的 base chain**。Suricata 官方文件建議把 IPS 鏈放在 `forward priority 10`，使它在防火牆規則之後才評估 [S7 doc/userguide/setting-up-ipsinline-for-linux.rst:133-136]。

**命名陷阱**：nft 的 `queue ... flags bypass`（舊語法 `options bypass`）意思是「沒有程式在聽這個 queue 時當作 accept（fail-open）」[nft(8) QUEUE STATEMENT；S7 setting-up-ipsinline-for-linux.rst:169-175]，**跟 Suricata 的 flow bypass 完全無關**。

**輔助：`nfq_set_mark` 規則關鍵字**：規則比對成功就在該封包貼上指定 mark/mask，在 verdict 時帶回 [S7 detect-mark.c:58, 232-250]。這是一條**從 Suricata 反向通知 kernel 規則**的現成管道（例如抽樣封包比對到告警規則 → 貼「撤銷」mark → 後續 nft 規則改 ct mark）。注意它也只貼單一封包，且使用者回報過 mark 沒出現的案例原因是設定鍵拼錯（`encrypt-handling` 應為 `encryption-handling`）[二手-摘要 https://forum.suricata.io/t/bypass-mark-bypass-mask-not-working-in-nfq-mode/3508]。

**放行判定時機**：同 M2；mark 在**觸發封包**的 verdict 才送出，所以 kernel 要到下一個封包才開始放行。

**放行後保留的可見性**
- Suricata 看不到任何後續封包（除了規則生效前漏進 queue 的）。
- NFQ 沒有註冊 `BypassUpdate` callback（`source-nfq.c` 中 bypass 相關行只有 160-162、248-253、492-539；kernel 計數無法回填），而 `FlowBypassedTimeout` 對沒有 `BypassUpdate` 的 flow 直接回傳「逾時」[S7 flow-manager.c:215-258]。結果是：**Suricata 會在約 100 秒後把這條 flow 淘汰，輸出的 EVE flow 記錄只含它自己看到的封包數與位元組**，而真實 flow 可能還在 kernel 裡跑 [S7 flow-manager.c:215-258；推測部分：實際 EVE 輸出沒有實測]。
- EVE flow 的 `bypassed` 物件對 NFQ 會是 0（`fc` 已建立但 kernel 回填欄位不會被更新）[S7 output-json-flow.c:199-210；推測]。
- 因此**要給雲端 IDS 完整 flow 記錄，不能依賴 Suricata 的 EVE flow**；[推測] 應從 conntrack 取（`net.netfilter.nf_conntrack_acct` 預設 0，要開才有 64-bit packets/bytes 計數 [K Documentation/networking/nf_conntrack-sysctl.rst]）。

**能否撤銷**
- Suricata 端：不能。`CAPTURE_BYPASSED` 的 flow 之後即使封包重新進 queue，也只會被當成 bypassed 而跳過（見 M3），要等 flow 被淘汰。[推測] 這會造成「撤銷後重新送檢，Suricata 卻仍然略過」的陷阱：只要被撤銷的 flow 在 Suricata 的 flow 表中還在（約 100 秒，或 local bypass 下封包持續就一直在），Suricata 就不會檢測它。
- kernel 端：可以。ct mark 由我們控制：`conntrack -U ... -m <mark>`（`--mark` 在 update 模式的遮罩語意見 conntrack(8)）或由 nft 規則改寫 [二手-摘要 https://manpages.debian.org/trixie/conntrack/conntrack.8.en.html；trixie 的 `conntrack` 套件為 1:1.4.8-2]。

**Pi 可用性與 [推測]**
- Debian trixie `suricata` 7.0.10 arm64 的 `debian/rules` 帶 `--enable-nfqueue`；而 `configure.ac` 在 `enable_nfqueue=yes` 時定義 `CAPTURE_OFFLOAD`，bypass 程式碼才會被編入 [二手-摘要 https://salsa.debian.org/pkg-suricata-team/pkg-suricata/-/raw/master/debian/rules；S7 configure.ac:2542-2544]。所以 NFQ capture bypass 在 Pi 的套件上可用。
- [推測] 實際可行的規則骨架見 M15。**未實測**。

### M5. Capture bypass — AF_PACKET + eBPF / XDP

**機制說明**
- AF_PACKET 介面設定：`bypass: yes`、`ebpf-filter-file: .../bypass_filter.bpf`（socket filter 版）或 `xdp_filter.bpf`（XDP 版）、`xdp-mode: soft|driver|hw`、`cluster-type: cluster_qm`（需要對稱 RSS）、`use-percpu-hash` 預設 `yes` [S7 doc/userguide/capture-hardware/ebpf-xdp.rst 約 198-296]。
- Suricata 觸發 bypass 時，把 flow 寫入 kernel 的 `flow_table_v4/v6` map；之後 eBPF／XDP 程式在 kernel 或驅動層丟棄該 flow 的封包。Suricata 的 `FlowBypassedTimeout` 會定期呼叫 `BypassUpdate` 讀回 kernel 的封包與位元組計數，沒有新封包就視為死 flow 並淘汰（約每 10 秒一輪）[S7 flow-manager.c:215-258；SM flow-bypass.c 的 `FLOW_BYPASS_DELAY 10`]。
- 文件原文限制：「bypassed packets don't reach the network so you can't use this on regular traffic but only on duplicated/sniffed traffic.」；另一處說 XDP bypass 與 AF_PACKET IPS mode 相容，bypassed flow 的封包直接從一張網卡送到另一張 [S7 ebpf-xdp.rst:21-24 與 291-292]。
- `stream.bypass: true` 在此情境的描述：「This will bypass flows as soon as the stream depth will be reached.」[ebpf-xdp.rst:140-145]。

**放行判定時機、可見性**：同 M2；可見性比 NFQ 好，因為 kernel map 內有每條 flow 的計數，逾時時回填到 EVE flow 的 `bypassed` 物件與 `stats.flow_bypassed.pkts/bytes` [S7 output-json-flow.c:199-210；ebpf-xdp.rst:545-599]。

**能否撤銷**：沒有單條 flow 的撤銷 API；kernel map 內的項目在逾時（沒新封包）後被 Suricata 刪除。可以用 `pinned-maps` 讓 map 在 Suricata 重啟後保留，或用 `USE_GLOBAL_BYPASS` 做全域旁路開關 [ebpf-xdp.rst:466-492]。

**Pi 可用性與 [推測]**
- 我們的 gateway 是**轉送設備**，專案走 nftables + NFQUEUE（`docs/02-architecture.md`），M5 的 AF_PACKET 路徑不是 inline 轉送路徑；文件把它限定在鏡像流量，IPS 例外只有 XDP 加 AF_PACKET IPS mode。[推測] 對本專案前期不適用。
- Debian 套件是否在 arm64 啟用 `--enable-ebpf`：`debian/rules` 以 `EBPF_ARCHS` 條件開啟，**arm64 是否在清單內未能確認**。套件有 `libbpf1` 依賴 [二手-摘要 packages.debian.org/trixie/suricata]。
- Pi 3B+ 的 USB 網卡是否支援 native XDP **本次未查**。Corelight 簡報稱 XDP 的「SKB or generic mode」是「for testing only」[Zeek 簡報 https://zeek.org/wp-content/uploads/2026/04/Shunting-with-Zeek-Export.pdf p.18，原文]。

### M6. Suricata `pass` 規則（對照用，不是 bypass）

- 文件：「Pass rules are Suricata rules that if matching, pass the packet and in case of TCP the rest of the flow … A big difference with capture filters is that logs such as Eve are still generated for this traffic.」[S7 doc/userguide/performance/ignoring-traffic.rst；同上 URL]
- 實作：第一個 pass／drop 勝出，`f->flags |= FLOW_ACTION_PASS; FlowSetNoPacketInspectionFlag(f)` [S7 detect-engine-alert.c:154-174]。**沒有呼叫 bypass callback**，所以 NFQ 模式下不會貼 mark，每個封包仍往返 userspace。
- 可見性：Eve 照常輸出；撤銷：無；Pi：可用，但對我們的 fast path 沒有幫助，列出只是為了避免與 M4 混淆。

### 2.7 bypass 後的 flow 統計與 EVE flow 記錄

- 統計（`stats.flow_bypassed`）：`local_pkts/local_bytes`＝Suricata 自己 bypass 的 flow；`local_capture_pkts/local_capture_bytes`＝capture bypass 生效前 Suricata 還看到的封包（文件：「There is almost always some for each flow because of the buffer in front of Suricata reading threads」）；`pkts/bytes`＝capture 方法回報的計數；`closed`＝已關閉的 bypassed flow [S7 ebpf-xdp.rst:580-599；S7 flow-worker.c:255-258 註冊計數器]。`iface-stat` 的 `bypassed` 是 flow 逾時時才加總 [ebpf-xdp.rst:545-560]。
- **EVE flow 記錄仍會產生**：`CheckWorkQueue` 對每一條被淘汰的 flow 都呼叫 `OutputFlowLog`，沒有排除 bypassed 的條件 [S7 flow-worker.c:203]。記錄裡 `flow.state` 為 `"bypassed"`，並多一個 `flow.bypass` 欄位值 `"local"` 或 `"capture"`；有 `FlowBypassInfo` 時另有 `flow.bypassed.{pkts,bytes}_to{server,client}` [S7 output-json-flow.c:199-210, 241-249]。
- `[推測]` 但有依據：NFQ 的 `local_capture_pkts` 是**驗證我們 ct mark 規則是否生效的現成指標**，規則正確時它應該只有每 flow 個位數。

---

## 3. Snort 3

### M7. trust 與 DAQ `WHITELIST`／`BLACKLIST` verdict

**機制說明**
- Snort 3 內部有「trust」動作：`Active::trust_session()` 在 force 時直接呼叫 `Flow::trust()`，否則先問 `flow->try_trust()`（可被 deferred trust 暫緩）[Snort3 src/packet_io/active.cc `trust_session`；src/flow/deferred_trust.h 檔頭註解]。`Flow::trust()` 做三件事：`set_ignore_direction(SSN_DIR_BOTH); set_state(Flow::FlowState::ALLOW); disable_inspection();` [Snort3 src/flow/flow.cc]。
- 對 DAQ 的 verdict：`distill_verdict()` 在 `session_was_trusted()`、flow 已 `ALLOW`、或雙向 ignore 時回傳 `DAQ_VERDICT_WHITELIST`；一旦是 WHITELIST／BLACKLIST／IGNORE 就是 **sticky verdict**（`p->flow->last_verdict` 被重複使用）；若 `cannot_trust()`（有 inspector 要繼續檢查）則降為 PASS [Snort3 src/main/analyzer.cc `distill_verdict` 與 `is_sticky_verdict`]。
- libdaq 對 WHITELIST 的定義：「Pass the packet and fastpath all future packets in the same flow systemwide.」BLACKLIST：「Block the packet and block all future packets in the same flow systemwide.」IGNORE：「… fastpath … for this application.」[libdaq api/daq_common.h:315-317]。
- **關鍵：開源 DAQ 的 NFQ 與 AF_PACKET 模組都把 WHITELIST／IGNORE 翻成 PASS，BLACKLIST 翻成 BLOCK**；NFQ 模組的 capability 只有 `DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INTERRUPT`，沒有 `DAQ_CAPA_WHITELIST`，verdict 只送 `NF_ACCEPT`／`NF_DROP`，不設 mark [libdaq modules/nfq/daq_nfq.c:92-98, 679-682, 784-786；modules/afpacket/daq_afpacket.c:1488-1490]。其他 DAQ 模組我沒有逐一檢查。
- Snort 3 另有 `flow.allowlist_cache` 之類的 flow cache 設定（`allowlist_cache`, `move_to_allowlist_on_excess`），是 Snort 內部 flow 表分區，不是 kernel 放行 [Snort3 src/flow/flow_config.h；`Flow::handle_allowlist`]。
- 規則動作層面：官方文件列 alert、block、drop、log、pass 與 react、reject、rewrite；`block`「blocks the current packet and applies to all the subsequent packets in this flow」，`pass` 只是「mark the current packet as passed」[文件 https://docs.snort.org/rules/headers/actions；Snort3 src/actions/act_pass.cc `action_help`]。**我在 snort3 開源碼中查到的 `ACT_TRUST` 呼叫點只在 `active.cc` 與 `deferred_trust.cc`，沒有找到由規則動作觸發 trust 的路徑**；誰在呼叫（例如商業版的 appid／policy 外掛）未能確認。

**放行判定時機**：由 inspector 或外掛決定，非固定時點。

**放行後保留的可見性**：Snort 內部不再檢測；因為 NFQ／AF_PACKET DAQ 不支援 whitelist，**每個封包仍從 kernel 進 userspace**，只是 Snort 立刻放行。

**能否撤銷**：`Flow::trust()` 之後我沒有找到對應的 un-trust；`BLACKLIST` 路徑有 `Stream::block_flow`。[推測] 沒有 un-trust。

**Pi 可用性與 [推測]**：Snort 3 3.12.2.0 在專案裡已有 Pi 版（REPORT.md）。[推測] 若要用 Snort 3 做 kernel 級 fast path，必須自己改 DAQ（讓 WHITELIST 設 mark）或在 Snort 外另做；開源 DAQ 現況下它的 trust 等價於 Suricata 的 local bypass（M3），不是 M4。

### M8. Snort 3 的「depth」類參數

- `http_inspect.request_depth`、`response_depth`：預設 `-1`（不限制），單位為訊息 body byte；`partial_depth_header`、`partial_depth_body`：預設 `0`（停用）[Snort3 src/service_inspectors/http_inspect/http_module.cc]。
- `stream_tcp.queue_limit.max_bytes`：預設 `4194304`，`max_segments`：預設 `3072`；說明為「don't queue more than given bytes per session and direction, 0 = unlimited」，這是**重組佇列上限**，不是「超過就停止檢測」的 cutoff [Snort3 src/stream/tcp/tcp_module.cc]。
- Snort 2 的 `server_flow_depth`／`client_flow_depth`：只有搜尋摘要層級的資料：pfSense 問題單稱數值過小會漏報、預設值在不同版本不同（資料互相矛盾，300／1460／0）[二手-摘要 https://redmine.pfsense.org/issues/15222 、 https://seclists.org/snort/2010/q1/600]。**未能確認 Snort 2 現行手冊原文**。
- 放行後可見性、撤銷：這些是 inspector 內部參數，超過後其餘封包仍進引擎，不是 flow 放行。Pi：可用。

---

## 4. Zeek 與 shunting 的學術／運維傳統

### M9. `skip_further_processing` 與 ConnThreshold

- 內建函式文件：「Informs Zeek that it should skip any further processing of the contents of a given connection. In particular, Zeek will refrain from reassembling the TCP byte stream and from generating events relating to any analyzers that have been processing the connection.」註記：「Zeek will still generate connection-oriented events such as `connection_finished`.」[Zeek src/zeek.bif:4867-4890，文件 https://docs.zeek.org/en/master/scripts/base/bif/zeek.bif.zeek.html]。
- 觸發時點由腳本決定。標準做法是 `ConnThreshold`：用 `conn_bytes_threshold_crossed`、`conn_packets_threshold_crossed`、`conn_duration_threshold_crossed` 事件，門檻用 `set_current_conn_bytes_threshold(cid, threshold, is_orig)` 之類設定；duration 事件「is raised when the next packet is seen after the threshold has been crossed」，閒置連線可能很晚才觸發 [Zeek src/analyzer/protocol/conn-size/events.bif 與 functions.bif]。
- 撤銷：`zeek.bif` 中只有全域的 `suspend_processing`／`continue_processing`，**沒有針對單一連線的 un-skip**（我 grep 了含 skip／process／analyzer 的函式名）。可見性：連線層事件與 conn.log 仍在；conn.log 位元組數在 skip 狀態下是否仍準確 **未能確認**。
- Pi：Zeek 目前不是專案元件，只作機制參考。

### M10. BPF shunt 與 NetControl shunt

- `PacketFilter::shunt_conn(id)`：用 BPF 讓資料封包「never reach Zeek」；對 TCP，「control packets are still allowed through so that Zeek can continue logging the connection and it can stop shunting once the connection ends」。實作上 TCP 的過濾式帶 `tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) == 0`（也就是 SYN/FIN/RST 不被 shunt）[Zeek scripts/policy/frameworks/packet-filter/shunt.zeek]。
  - `max_bpf_shunts` 預設 `100`；IPv6 連線無法用 BPF shunt（觸發 `Cannot_BPF_Shunt_Conn` notice）；`unshunt_host_pair` 不會立刻生效，「waits for the occasional filter update」，註解說 framework 每幾分鐘檢查一次 [同檔]。
- `NetControl::shunt_flow(f, t, location)`：「Stops forwarding a uni-directional flow's packets to Zeek」，`t` 為持續時間（`0` 表示無限）；實作是 `Rule($ty=DROP, $target=MONITOR, ...)`，並寫 `netcontrol_shunt.log` [Zeek scripts/base/frameworks/netcontrol/shunt.zeek]。實際由哪個後端（交換器等）執行取決於 NetControl 外掛，我沒有逐一檢查。
- 撤銷：BPF 版可（延遲以分鐘計）；NetControl 版靠 `expire`。
- 可見性：BPF 版靠放行 SYN/FIN/RST 維持連線生命週期的記錄。
- Pi：概念可借用——**保留控制封包**的設計與我們的 FIN/RST 處理直接相關（見 §7）。

### M11. XDP shunter 與 Corelight 簡報

資料來源是 Corelight 作者 Evan Typanski 與 Jan Grashöfer 的簡報「Addressing the Elephant in the Traffic: Shunting with Zeek」（32 頁，zeek.org 2026-04 上傳）[https://zeek.org/wp-content/uploads/2026/04/Shunting-with-Zeek-Export.pdf]，與 `xdp-zeek` 套件 README [二手-摘要 https://github.com/evantypanski/xdp-zeek]。

- 放行對象：加密後的 TLS 類流量（TLS／STARTTLS／明示 TLS／DTLS）[簡報 p.5]；「bulk traffic」：每個連線每個方向設 1 MB 門檻，且只對超過 10 個封包的連線生效以排除 DNS 這類短連線 [簡報 p.14-15，原文]。
- 效益：實驗室測試「Determine max. throughput without packet drops」，流量約 88% TLS，各設定增益 7%–38%，簡報自己警告「Your mileage may will vary!」[簡報 p.9]。其他圖（CPU 使用、丟包）只有圖，數字未能從文字確認。
- XDP 機制：XDP 程式檢查封包是否屬於 shunt 的 IP pair 或 5-tuple，命中就 `XDP_DROP`，其餘 `XDP_PASS`；兩張 map（`filter_map`、`ip_pair_map`）由 Zeek（使用者空間）管理；shunt 後 Zeek 看不到流量，所以「unshunt」是個難題 [簡報 p.19-23；README]。
- 簡報列出三種撤銷想法：(1) XDP 用 ringbuf 通知 FIN/RST（缺點：要輪詢、只對正常結束的 TCP 有用）；(2) 把 TCP 控制封包 `XDP_PASS` 給 Zeek（缺點：帶資料的 ACK，SSH 之類幾乎 shunt 不到）；(3)（目前採用）沿用 Zeek 逾時並新增 `connection_timing_out` hook，讓外掛可告訴 Zeek 不要移除連線（缺點：連線關閉後仍顯示為逾時、worker crash 會洩漏項目）[簡報 p.24-29]。
- 狀態：「Intended to get into Zeek 8.2」，仍是套件、仍在開發 [簡報 p.17、p.30]；README 的 TODO 也顯示載入／卸載流程尚未定案。
- Pi：[推測] 概念（flow map 加逾時式撤銷、被 shunt 的 flow 計數由 map 提供）可借用；XDP 本身受 Pi 3B+ 網卡驅動限制。

### M12. Shunting 硬體（CCS'07）與 Time Machine cutoff（學術上的原型）

**Shunting（González, Paxson, Weaver, CCS 2007）**[全文 https://www.icir.org/vern/papers/shunting.ccs07.pdf]
- 機制：inline 的小型硬體（NetFPGA 2 原型）維護「IP 位址」與「連線 5-tuple」快取表，加上固定的 IP／TCP flags 規則，最高優先序命中後對每個封包給出決定：forward、drop、或導給 IPS；IPS 透過改表決定「不想再看的流量」[摘要 p.139]。
- 放行時機：IPS 自己判定。範例：SSH 連線協商完加密後，IPS 下載一筆 per-connection 的 `forward` 項目；若 IPS 對 handshake 不滿意，下載 `drop`；無法判定則表不動，繼續收封包 [§1]。
- 動機論述：「a few of the connections carry just about all the bytes」且「the very beginning of the connection contains nearly all the information of interest from a security analysis perspective」[§1，原文]。
- `forward-N`：「skip the next N bytes」而非整條連線；**實作用 TCP 序號空間而非 byte 計數**，理由包含「packet loss or reordering, race conditions in installing the table entry, or deliberate attacker manipulation」；分析引擎在看到高於 cutoff 的 ACK 時移除該項目 [PDF p.5]。
- 控制封包：連線 forward 之後，仍由較高優先序的靜態過濾把 FIN/RST 導給 IPS [§6 Dynamic Protocol Detection 段末，PDF p.8 前後]。
- 效益（Bro 上的實作）：offload **55%–90%** 的流量 [摘要 p.139]；Table 2 的 6 條 trace，轉發（不經分析）的比例：位元組 54.9%–91.1%、封包 43.8%–88.0% [PDF p.8 Table 2]。HTTP 的 MIME 白名單範例仍會檢查每個項目的前 5 KB（預設）；Dynamic Protocol Detection 在前 2 KB 後把 signature analyzer 降級為非必要 [§6，PDF p.7-8]。
- 論文本身把 reinjection 視為做 normalization 的機會（避免 Ptacek & Newsham 式 evasion）[§1、結論]。論文是否量測「先正常後攻擊」或 forward-N 之後的攻擊：**我 grep 全文，沒有找到這類量測**（`attacker` 只出現在「封鎖攻擊者」、hash 抗操縱、序號計數的敘述）。

**Time Machine（Maier, Sommer, Dreger, Feldmann, Paxson, Schneider, SIGCOMM 2008）**[全文 https://www.icir.org/gregor/papers/sigcomm08-tm.pdf]
- 機制：每條連線只存前 N byte（cutoff），之後丟棄；cutoff 可依 storage class 調整。
- 數字：91–94% 的連線短於 N=10 KB；cutoff 20 KB 時可完整記錄 94–96% 的連線；在有 payload 的連線中，N=10 KB 截斷 14–19%、N=20 KB 截斷 9–13% [p.185，原文]。MWN 部署採 15 KB cutoff，cutoff 後剩餘流量「less than 6% of the original traffic」[p.187]。
- 與 NIDS 的耦合：NIDS 一旦告警，先對觸發連線送 `suspend_cutoff`，再用 `set_class` 把主機移到 `scanners`（cutoff 15 KB→50 KB）或 `alarms`（取消 cutoff）；兩週內 NIDS 送了 427 個 suspend_cutoff 命令、12,532 個 IP 進 scanners、592 個進 alarms [p.189]。**這是目前找到最接近「撤銷」機制的公開數字**。
- TCP 控制封包（SYN/FIN/RST）永遠儲存，讓 NIDS 仍能做連線層分析；但「there is little we can do about flows curtailed in the past」[p.192-193]。
- 規避風險直接討論（見 §6）。

### M13. SciPass／Science DMZ

- SciPass（Balas & Ragusa, Indiana University GlobalNOC, SC'14）[全文 https://scinet.supercomputing.org/community/documents/93/pap108s3.pdf]：Bro 透過 web API 對 SciPass controller 送 whitelist 請求（IP、協定、port），controller 在 OpenFlow 交換器裝一對（兩個方向）較高優先序的規則，讓封包不再送到 IDS（§2.2）；進一步可對「good flows」把防火牆也繞過（§2.3）。規則帶 idle timeout，flow 結束後自動清除。
- 放行依據：Bro 的策略，含時段、來源／目的 IP、協定與應用層資料；範例是某目錄、某遠端設施、星期五凌晨傳輸基因資料才放行（§2.3）。
- 反應時間：偵測 20 ms、建規則 4 ms、交換器安裝 40 ms，共 64 ms；反應式 bypass 在 250 ms 內達到防火牆路徑兩倍速率，1.5 秒內達 proactive 同速（§5-6）。防火牆路徑單 flow 1.30 Gbps、有 2838 次重傳，旁路後約 9.9 Gbps（§4）。這些是 10GbE 實驗室測試，非我們的規模。
- 安全面：論文討論「end host signaled」（XSP）方式，指出它「presupposes you trust the end hosts」，且組織通常要求安全人員保有策略控制權（§8）。
- 引用的 shunting 結果：Campbell & Lee 2012 稱 flow shunting 「reduce sensor work load by up to 88%」[二手，經 SciPass §8 引述；原論文 *Prototyping a 100G monitoring system*, Euromicro PDP 2012，未取得全文]。
- **關於你列的「ESnet Science DMZ elephant flow bypass」**：Science DMZ 概念引自 Dart et al., *Scientific Programming* 22(2), 2014, pp.173-185（經 SciPass 引述）。**我沒有找到 ESnet 自己用 Zeek 做 shunt 的原始文件**；搜尋到的 ESnet 資料是 OpenFlow 與 elephant flow 的 SDN 簡報，未提 Zeek shunt。**「Corelight / Arista dynamic shunting」商業文件與「dumbno」都未能確認**：前者只找到上節 Corelight 作者的簡報，後者搜尋沒有任何與 Zeek/Bro 相關的結果；SciPass 論文提到的 Arista DANZ 是 IDS 負載平衡而非 shunt。
- Pi：[推測] 「IDS 向控制面送白名單請求，控制面裝 flow 規則並帶 idle timeout」與我們的架構同型；差別是我們的「交換器」是 netfilter。

---

## 5. Linux nftables / netfilter

### M14. flowtable（software offload）

**機制說明（核心文件原文＋原始碼）**
- 核心文件：「A packet that finds a matching entry in the flowtable (ie. flowtable hit) is transmitted to the output netdevice via neigh_xmit(), hence, packets bypass the classic IP forwarding path (the visible effect is that you do not see these packets from any of the Netfilter hooks coming after ingress).」[K Documentation/networking/nf_flowtable.rst，https://docs.kernel.org/networking/nf_flowtable.html]。nft(8)：「Flowtables reside in the ingress hook that is located before the prerouting hook.」
- **所以被 offload 的封包不會經過 prerouting、forward、postrouting**，也就不會評估 forward chain 上的任何規則（包括 `queue`、`counter`）。核心文件範例特別說明：「you will observe that the counter rule … does not get updated for the packets that are being forwarded through the forwarding bypass.」
- 加入 flowtable：規則 `flow add @f`（nft(8) FLOW STATEMENT）。加入條件（`nft_flow_offload_eval`）：封包要有 conntrack；TCP 必須不是 FIN/RST 且 conntrack 已 established；conntrack 不可有 helper extension、不可有 `IPS_SEQ_ADJUST|IPS_NAT_CLASH`；ct 必須已 confirmed [K net/netfilter/nft_flow_offload.c:317-347]。TCP flow 加入時會把雙向 `IP_CT_TCP_FLAG_BE_LIBERAL` 打開。
- 不走 fast path、回到一般路徑的封包：分片、TCP FIN/RST、超過 MTU（核心文件）；TTL<=1 也回到一般路徑 [K nf_flow_table_ip.c:210]。FIN/RST 同時會 `flow_offload_teardown`，entry 失效 [K nf_flow_table_ip.c:22-34]。
- 計數：flowtable 宣告加 `counter` 才會把封包與位元組數同步回 conntrack（Linux 5.7 起）[核心文件 Counters 段；K nf_flow_table_ip.c:407-408 `nf_ct_acct_update`]。[推測] 這只在 conntrack 有 accounting extension 時才累加（`nf_conntrack_acct` 預設 0）：`nf_ct_acct_add` 以 `nf_conn_acct_find(ct)` 判斷 [K nf_conntrack_core.c:948-960]。
- 逾時：offload 的 TCP／UDP 項目預設 30 秒（`nf_flowtable_tcp_timeout`、`nf_flowtable_udp_timeout`）；過期後回到 conntrack 並調整 ct timeout [K nf_conntrack-sysctl.rst:220-231；K nf_flow_table_core.c:170-200]。

**放行判定時機**：由 forward chain 中 `flow add` 規則決定，天然在 flow 建立並 established 之後（第二個封包起；核心文件：「from the second packet on」）。

**放行後保留的可見性**：沒有封包層可見性。只有：`conntrack -L` 會標 `[OFFLOAD]`；`counter` 開啟後的 conntrack 計數；FIN/RST 回到一般路徑時我們的 forward chain 會看到。

**能否撤銷**：沒有「刪除單一 flowtable entry」的 nft 指令（nft(8) 的 flowtable 只有 add／delete／list 整張表）。entry 會因以下原因失效：gc 到期、`nf_ct_is_dying`（conntrack 被刪）、route／dst 變更、FIN/RST、封包超 MTU [K nf_flow_table_core.c:366-370, 417-423；nf_flow_table_ip.c:385-392]。[推測] 要撤銷單條 flow，只有 `conntrack -D`（連同 conntrack 項目一起殺，對 TCP 中途連線可能被當成 invalid 而被防火牆丟棄）或等逾時；刪整張 flowtable 會撤銷全部。

**Pi 可用性與 [推測]**
- nftables 1.1.3、kernel 6.x 在軟體 API 上支援。**Raspberry Pi OS 的 kernel config 是否編入 `NF_FLOW_TABLE`、`NFT_FLOW_OFFLOAD` 未能確認**，需要在 Pi 上檢查 `modinfo nft_flow_offload` 與 `/proc/config.gz`。
- [推測] 對 Pi 3B+（4 核 A53、USB2 網卡）很可能有效益，因為少掉 conntrack 與三個 hook；但這是推論，沒有量測。

### M15. `ct mark` 配合 `queue` 的 bypass 寫法

**語意基礎（已驗證）**
1. nft `queue` 是終止性 verdict，userspace accept 後從**下一個 base chain（同一個 hook 上 priority 數字更大的那一條）**繼續，不是同一條鏈的下一條規則 [nft(8) VERDICT STATEMENT；K nfnetlink_queue.c:312-368]。
2. userspace verdict 帶的 `NFQA_MARK` 會寫入 `skb->mark`（單一封包）[K nfnetlink_queue.c:1333, 1462-1463]。
3. 把封包 mark 存入 conntrack：`ct mark set meta mark`（nft(8) 範例）。
4. 在 base chain 中 `accept` 只結束該鏈，同一 hook 的其他 base chain 仍會評估 [nft(8) `accept` 說明]。

**規則骨架 [推測，未實測，語法需在 netns 中用 `nft -c` 驗證]**

```
table inet gw {
  # (1) 已信任的 flow：在 queue 鏈之前處理（priority 較小）
  chain trusted {
    type filter hook forward priority -10; policy accept;
    ct mark & 0x1 == 0x1 jump sample_or_pass
  }
  chain sample_or_pass {
    # 抽樣送 Suricata；語法見 M16，需驗證
    # numgen random mod 100 < 2 queue flags bypass to 0
    accept
  }
  # (2) 未信任的 flow：全部進 queue
  chain inspect {
    type filter hook forward priority 0; policy accept;
    ct mark & 0x1 == 0 queue flags bypass to 0
  }
  # (3) queue 判決之後：把 Suricata 貼的 mark 存回 conntrack
  chain post_queue {
    type filter hook forward priority 10; policy accept;
    meta mark & 0x1 == 0x1 ct mark set ct mark | 0x1
  }
}
```
- 對應 Suricata 設定：`nfq.bypass-mark: 1`、`nfq.bypass-mask: 1`（yaml 註解範例值）。
- 注意：Suricata 的 bypass 是單向的（M3/M4 無法撤銷），所以 [推測] 若要保留「撤銷」能力，**不要讓 Suricata 自己決定信任**，而是由我們的控制程式改 ct mark（見 §7）；`nfq_set_mark` 規則關鍵字可作為 Suricata → kernel 的反向通知（例如貼「撤銷」位元）。

**放行判定時機、可見性、撤銷**：時機＝ct mark 被設的時刻（最早在第一批封包 verdict 之後的下一個封包生效）；可見性＝nft counter、conntrack 計數、抽樣封包；撤銷＝改 ct mark（`conntrack -U ... -m` 或規則），**kernel 端立即生效**。

**Pi 可用性**：可用，這是最保守的路線——只用 forward chain 規則與 conntrack，不需要 flowtable。每個封包仍經過 conntrack 與三個 hook，只是不進 queue。

### M16. 以 `numgen random` 或 `limit` 抽樣送 queue

**已驗證**
- `numgen {inc | random} mod NUM [offset NUM]`：「In random mode, a new random number is returned. The value after mod keyword specifies an upper boundary … which is not reached by returned numbers.」[nft(8) NUMGEN EXPRESSION]。man page 的範例是放在 map 中做負載平衡；nftables wiki "Math operations" 有 `mark set numgen random mod 50 offset 20` [二手-摘要 https://wiki.nftables.org/wiki-nftables/index.php/Math_operations]。
- `meta random` 存在（「pseudo-random number」，32 bit）[nft(8) META EXPRESSIONS]。netfilter-devel 討論稱 iptables `statistic` 的機率比對對應到 `meta random` 的小於比較 [二手-摘要 https://lore.kernel.org/all/20160302124626.GA5243@salvia/T/]。
- `limit rate [over] N/second [burst N packets]`：token bucket，「A rule using this statement will match until this limit is reached」[nft(8) LIMIT STATEMENT]；dynamic set 內可做每個 key 的 limit，如 `add @flood { ip saddr limit rate over 10/second }`（需 `flags dynamic`，並建議設 `timeout` 與 `size`）[nft(8) SET STATEMENT]。
- `queue` 本身可接 `numgen`／`hash` 表達式決定 queue 號碼 [nft(8) QUEUE STATEMENT]，與「抽樣」不同，這是負載分散。

**未驗證（[推測]）**
- 「`numgen random mod 100 < 2` 後接 `queue`」這種比較寫法能否通過 nft 1.1.3 的語法檢查，我沒有找到範例原文，也不能對系統下指令，**未能確認**。
- 以 5-tuple 為 key 的每 flow 限速抽樣（`ip saddr . ip daddr . tcp sport . tcp dport` 當 key 的 dynamic set 加 `limit rate`）理論上可做到「每條 flow 每秒最多 N 個封包進 queue」，但 Pi 的記憶體與 set 元素 gc 成本未評估。

**放行後的可見性**：抽樣得到的是**不連續的封包子集**。對 Suricata 的後果見 §7.5。

### 5.4 flowtable 與「繼續抽樣」是否衝突

**結論：衝突，同一條 flow 不能同時 offload 又在 forward chain 抽樣。**
- 依據：offload 的封包在 ingress hook 就被 `neigh_xmit` 轉走，不再經過 prerouting／forward／postrouting（核心文件原文，見 M14）。forward chain 上的 `numgen … queue` 規則對這些封包根本不會被評估。
- 例外：只有 FIN/RST、分片、超 MTU、TTL<=1 與 lookup miss 的封包會回到一般路徑，forward chain 才看得到。
- [推測] 可行的折衷：
  (a) 不用 flowtable，用 M15 的 ct mark accept（保留抽樣，成本是 conntrack 與 hook 遍歷）；
  (b) 用 flowtable 並開 `counter`，抽樣改成「控制面週期性讀 conntrack 計數（ctnetlink）」做量級式異常判斷（只能抓流量型異常，看不到 payload）；
  (c) 在 flowtable 之前的 netdev ingress base chain（priority 比 flowtable 小）抽樣；此時 conntrack 尚未處理，無法用 ct mark 判斷信任，只能比對位址集合，且 `queue` 能否在 netdev ingress 使用與重入後是否接到 flowtable hook **未能確認**。
- 兩者選一：(a) 彈性高、單封包成本較大；(b) 單封包成本低但盲區大。

---

## 6. 規避文獻與實例（只列已確認存在者）

| 文獻 | 確認方式 | 與「放行／cutoff 後攻擊」的關係 |
|---|---|---|
| Ptacek & Newsham, *Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection*, Secure Networks Inc., January 1998 | 已讀全文（Stanford 課程副本 https://crypto.stanford.edu/cs155old/cs155-spring08/papers/IDSpaper.pdf） | 基礎文獻：被動協定分析因資訊不足與狀態耗盡而可被規避。§5.5.2 的「Sneakers」攻擊：靠等待讓 IDS 逾時丟狀態、或灌滿連線逼 IDS 做 garbage collection。**全文沒有討論 reassembly depth／cutoff**（`depth` 只出現在 "in-depth testing" 一句）。其中「狀態逾時」與我們的「信任逾時」類比，但那是我的類比，不是論文結論 |
| Handley, Paxson, Kreibich, *Network Intrusion Detection: Evasion, Traffic Normalization, and End-to-End Protocol Semantics*, USENIX Security 2001, pp.115-131 | 已下載全文（https://cs.fit.edu/~pkc/id/related/handley-uss01.pdf）；以 cutoff／depth 字串搜尋無相關結果 | 提出在鏈路上 inline 做 normalizer 消除歧義。與我們的關聯：fast path 若讓 IDS 只看到封包子集，就失去 normalizer 的前提（見 §7.5） |
| Maier et al., *Enriching Network Security Analysis with Time Travel*, SIGCOMM 2008, pp.183-194 | 已讀全文 | **直接討論 cutoff 規避**（下方原文）。 |
| Gonzalez & Paxson, *Enhancing Network Intrusion Detection with Integrated Sampling and Filtering*, RAID 2006, pp.272-289 | 已讀全文（https://www.icir.org/vern/papers/secondary-path-raid06.pdf） | 提出 BPF 隨機取樣（packet／connection／host 層級）與持久狀態；明講取樣路徑易被規避（下方） |
| González, Paxson, Weaver, *Shunting*, CCS 2007, pp.139-149 | 已讀全文 | 見 M12；用序號空間而非 byte 計數以抵抗「deliberate attacker manipulation」 |
| Balas & Ragusa, *SciPass*, SC'14 | 已讀全文 | 信任端點主機的疑慮（M13） |

**Time Machine §6 "Risk of Evasion"（p.192）原文**：「if an attacker delays his attack to occur after the cutoff, the TM will not record the malicious actions. This is a fundamental limitation of our approach. However, short of comprehensively storing all packets, any volume reduction heuristic faces such a blind spot.」作者提出的緩解：不同 storage class 配不同 cutoff、利用 NIDS 風險評估動態調整 cutoff、**把 cutoff 隨機化**（「an attacker cannot predict at which point it will go into effect」，且 cutoff 觸發後仍隨機記錄後續封包的子集）——後者是「plan to examine」的未來工作，**論文沒有量測它的效果**。

**RAID'06 PDF p.6 原文**：「analysis through the Secondary Path is often susceptible to evasion due to the inability to detect or resolve traffic ambiguities」（Secondary Path＝無重組的取樣封包路徑，作者承認的限制）。

**找不到的**：專門針對 Suricata／Snort 的 reassembly depth 繞過之同儕審查論文或 CVE 級案例，**我沒有找到**。已確認的只有：Suricata 文件對 bypass 的警語（M1/M2）、Suricata 論壇上使用者對 depth 後不檢測的觀察 [二手-摘要]、Suricata 一個與 depth 後 ACK 追蹤相關的 PR（#16334，屬正確性 bug 而非繞過手法）[二手-摘要]。Snort 2 flow depth 設太低會漏報只有二手資料。

---

## 7. 對信任式 fast path 的設計意涵

以下除非標明，都是從上面已驗證的機制推導；標 [推測] 者未經實測。

### 7.1 「只看 flow 開頭就決定」有現成的實證與先例，但先例的「開頭」都很具體
- Shunting 論文的核心論點（heavy tail＋開頭含大部分安全相關資訊）與 Time Machine 的 10–20 KB cutoff（91–96% 連線完整涵蓋）、Corelight 的「>1 MB 且 >10 封包」、Suricata 的 1 MiB depth，都把**位元組門檻**或**協定里程碑（TLS／SSH 協商完成）**當放行時點。沒有任何一個先例是「第 N 個封包」。[推測] 我們若以「雲端判定開頭安全」為放行時點，應同時定義一個位元組／里程碑門檻，並且**門檻要分方向、並要求最小封包數**（Corelight 的做法）。
- 這些數字都來自特定流量（校園／研究機構／Bro 流量），**不是 IoT 閘道器流量**；REPORT.md 也指出 IoT-23 約 98% 封包無 payload，對 payload 型門檻意義有限。

### 7.2 放行必須由 kernel 規則承擔，不能指望 IDS 的 bypass 狀態
- Suricata 的 NFQ bypass 只給單一封包一個 mark、不碰 conntrack（M4）；Snort 3 的開源 DAQ 把 WHITELIST 翻成 PASS（M7）。兩者都沒有給我們現成的 kernel fast path。**fast path 的狀態（ct mark）要由我們的規則與控制程式持有。**

### 7.3 保留控制封包
- Shunting（FIN/RST 恆導給 IPS）、Time Machine（SYN/FIN/RST 恆存）、Zeek BPF shunt（SYN/FIN/RST 不被 shunt）、flowtable（FIN/RST 回一般路徑並 teardown）四者**獨立地**採同一個設計。[推測] 我們的 fast path 也應讓 FIN/RST（與 SYN）仍進 forward chain 的計數或 queue，使 flow 記錄能正確結束、信任能在關閉時清除。

### 7.4 可見性要另外設計，不要依賴 Suricata 的 EVE flow
- NFQ bypass 後，Suricata 只看得到觸發前的封包，EVE flow 計數不完整（M4）。[推測] 給雲端 IDS 的 flow 記錄應從 conntrack（`nf_conntrack_acct=1`；flowtable 要加 `counter`）產生。三個可見性層級：(a) conntrack 計數（幾乎免費）；(b) nft counter／set；(c) 抽樣封包進 Suricata。
- Suricata 的 `flow_bypassed.local_capture_pkts` 可作為「ct mark 規則是否真的生效」的監測指標（§2.7）。

### 7.5 抽樣的陷阱：隨機抽樣的封包子集，對 Suricata 幾乎等於看不到
- 抽樣到的封包是流中的任意片段。依 Suricata 文件，`stream.midstream` 預設 `false`（「If you want Suricata to check the stream from that time on, you can do so by setting the option 'midstream' to 'true'. The default setting is 'false'.」）：中途才看到的 TCP 不會建立 session 做重組 [SM 文件 suricata-yaml.rst:1296-1300；S7 suricata.yaml.in 中為註解 `#midstream: false`]。即使開 `midstream: true`，缺封包的 stream 會有洞，跨封包規則（`content` 跨段、HTTP buffer）比對不可靠。[推測] 所以逐封包隨機抽樣主要適合**packet 層規則與統計型檢查**，不適合 stream／app-layer 簽章。
- RAID'06 作者也承認無重組的取樣路徑易被規避（§6）。
- 更接近「還能用 Suricata 簽章」的抽樣單位 [推測]：以**連續的視窗**（某條 flow 在某幾秒內全部進 queue，再恢復信任）而不是逐封包取樣；視窗起點應隨機（Time Machine 的隨機化 cutoff 想法，但該論文並未量測）。
- 抽樣封包到達時，Suricata 的 flow 表可能仍保留該 flow 的 bypassed 狀態並直接略過（M3/M4 撤銷陷阱）；因此 [推測] 用 Suricata bypass 做「信任」又同時用 Suricata 做「抽樣檢查」是互相打架的。較乾淨的做法是：**Suricata 不使用 bypass 標記來表達信任**，只負責看它收到的封包；信任純粹是 kernel ct mark，由控制程式維護。

### 7.6 撤銷能力要放在 kernel／控制面，而非 IDS
- Suricata（M3-M5）、Snort 3（M7）、Zeek（M9）都**沒有**對單一活 flow 的 un-bypass／un-trust API（我讀過的程式碼範圍內）。Time Machine 的 `suspend_cutoff`（兩週 427 次，p.189）是目前找到最接近的撤銷機制，但它作用在**記錄層**而非轉送層。
- kernel 端：ct mark 可由 `conntrack -U` 或 nft 規則立即改回；flowtable 沒有單條撤銷（M14），這是 flowtable 的缺點。
- [推測] 回饋鏈：抽樣封包 → Suricata 告警規則帶 `nfq_set_mark`（M4 輔助）→ `post_queue` chain 看到「撤銷」位元就 `ct mark set ct mark & ~0x1`（或改成 ban 的 mark 並在前段 `drop`）→ 後續封包立刻回到 `inspect` chain。反應時間＝抽樣間隔＋ Suricata 處理＋一次 netlink 往返，**沒有實測**；SciPass 量到的 64 ms（Bro＋OpenFlow 硬體交換器）不能直接類比。

### 7.7 flowtable 與信任式 fast path
- 它是「更快的 fast path」，代價是**失去抽樣與撤銷**（M14、§5.4）。[推測] 可作第二層：只有「高度信任＋高流量」的 flow（例如長時間大檔下載）才升級到 flowtable，並依靠 `counter` 加控制面輪詢做量級異常偵測；其他仍走 M15。這個分層是推論，沒有任何文獻支持。

### 7.8 攻擊者可利用的點（來自文獻與機制）
1. 先乖後壞：信任建立後再攻擊。Time Machine 明說這是方法的根本限制（§6）。
2. 把攻擊放在 depth／cutoff 之後：Suricata 的 depth 預設值在 7.0.x 與文件不一致（M1），且 `stream.bypass` 的警語「first side to reach this triggers the bypass」說明單邊先到就整條放行。
3. 可預測的抽樣或逾時：Ptacek & Newsham 的 Sneakers 攻擊與 Time Machine 的「rely on the fact that an attacker cannot predict when exactly a timeout will take place」都指向**隨機化**。
4. 狀態耗盡：Time Machine 提到攻擊者可產生大量小連線縮短保留時間；Zeek XDP 簡報指出 map 項目若不撤銷會「unbounded state growth」。[推測] 我們的信任表需要上限與逾時。

---

## 8. 未能確認與最不確定的事項

**未能確認清單**
1. Suricata NFQ 模式下實際 EVE flow 輸出（`bypassed` 物件是否為 0）與 flow 淘汰時機，只有讀碼推論，沒有跑。
2. Suricata 官方未給 NFQ bypass 的 nftables 範例；我的規則骨架（M15）完全沒實測。
3. `numgen random mod N < k queue` 的語法是否被 nft 1.1.3 接受；`queue` 能否用在 netdev ingress。
4. Raspberry Pi OS kernel 是否編入 flowtable 模組；Debian suricata 在 arm64 是否啟用 eBPF。
5. Snort 3 開源碼中誰呼叫 `ACT_TRUST`；其他 DAQ 模組是否支援 WHITELIST。
6. Zeek `skip_further_processing` 後 conn.log 位元組數的準確性；Corelight 簡報「Shunting in conn.log」「Shunted + Metadata」只有圖，欄位名未能確認。
7. 「dumbno」、Arista／Corelight 商業 dynamic shunting 文件、ESnet 的 Zeek shunt 原始資料：找不到。
8. Pi 3B+ USB 網卡的 native XDP 支援：未查。
9. Campbell & Lee 2012 的 88% 數字：只有經 SciPass 引述的二手資料。

**最不確定的三件事（請主 agent 優先處理）**
1. **NFQ bypass 的實際端到端行為**：我是從 Suricata 7.0.10 與 kernel 6.12 的原始碼推導出「mark 只貼單一封包、不碰 conntrack、需自寫 `ct mark set`」，以及「Suricata 端無法撤銷、flow 約 100 秒後被淘汰且 EVE 計數缺失」。結論邏輯一致但**沒有在 netns 實測**，建議第一個實驗就是在筆電 netns 驗證 M15 規則骨架與 `local_capture_pkts`。
2. **Suricata `stream.reassembly.depth` 的預設值與 TLS bypass 閘門**：7.0.10 程式碼（未設鍵＝不限，TLS bypass 需 `stream.bypass: yes`）與文件、master 不一致。專案若自己編譯 Suricata 或升級到 8.x／master，行為會變，需要鎖定版本並寫進實驗設定。
3. **抽樣封包對 Suricata 的實際可檢內容**：§7.5 的結論（逐封包抽樣近乎無法跑 stream／app-layer 簽章）來自 `midstream` 預設值與 TCP 重組原理的推論，文獻中沒有針對「抽樣＋簽章式 IDS」的量測。這直接決定「仍抽樣」的設計是否有意義，值得優先實測。

---

## 9. 來源索引

**Suricata**
- 文件：https://docs.suricata.io/en/latest/configuration/suricata-yaml.html 、 https://docs.suricata.io/en/latest/performance/ignoring-traffic.html 、 https://docs.suricata.io/en/latest/rules/bypass-keyword.html 、 https://docs.suricata.io/en/latest/capture-hardware/ebpf-xdp.html
- 原始碼（tag 7.0.10）：https://github.com/OISF/suricata/tree/suricata-7.0.10/src （`source-nfq.c`、`decode.c`、`flow.c`、`flow-worker.c`、`flow-manager.c`、`stream-tcp.c`、`app-layer-parser.c`、`app-layer-ssl.c`、`detect-bypass.c`、`detect-mark.c`、`detect-engine-alert.c`、`output-json-flow.c`）；`suricata.yaml.in`、`configure.ac`、`doc/userguide/setting-up-ipsinline-for-linux.rst`、`doc/userguide/capture-hardware/ebpf-xdp.rst` 在同一 tag
- Debian 套件：https://packages.debian.org/trixie/suricata 、 https://salsa.debian.org/pkg-suricata-team/pkg-suricata/-/raw/master/debian/rules
- 論壇（[二手-摘要]）：https://forum.suricata.io/t/bypass-mark-bypass-mask-not-working-in-nfq-mode/3508 、 https://forum.suricata.io/t/detecting-a-packet-after-reassembled/1436 、 https://forum.suricata.io/t/stream-reassembly-depth/1695

**Snort 3 / libdaq**
- https://github.com/snort3/snort3 （`src/flow/flow.cc`、`src/packet_io/active.cc`、`src/main/analyzer.cc`、`src/flow/deferred_trust.h`、`src/actions/act_pass.cc`、`src/stream/tcp/tcp_module.cc`、`src/service_inspectors/http_inspect/http_module.cc`）
- https://github.com/snort3/libdaq （`api/daq_common.h`、`modules/nfq/daq_nfq.c`、`modules/afpacket/daq_afpacket.c`）
- https://docs.snort.org/rules/headers/actions

**Zeek**
- https://github.com/zeek/zeek （`src/zeek.bif`、`scripts/policy/frameworks/packet-filter/shunt.zeek`、`scripts/base/frameworks/netcontrol/shunt.zeek`、`src/analyzer/protocol/conn-size/events.bif`、`functions.bif`）
- 簡報：https://zeek.org/wp-content/uploads/2026/04/Shunting-with-Zeek-Export.pdf ；套件：https://github.com/evantypanski/xdp-zeek

**論文**
- Ptacek & Newsham 1998：https://crypto.stanford.edu/cs155old/cs155-spring08/papers/IDSpaper.pdf
- Handley, Paxson, Kreibich 2001：https://www.usenix.org/legacy/events/sec01/handley.html
- Maier et al. 2008：https://www.icir.org/gregor/papers/sigcomm08-tm.pdf
- Gonzalez & Paxson 2006：https://www.icir.org/vern/papers/secondary-path-raid06.pdf
- González, Paxson, Weaver 2007：https://www.icir.org/vern/papers/shunting.ccs07.pdf
- Balas & Ragusa 2014（SciPass）：https://scinet.supercomputing.org/community/documents/93/pap108s3.pdf

**Linux / nftables**
- 核心文件：https://docs.kernel.org/networking/nf_flowtable.html （原文檔 `Documentation/networking/nf_flowtable.rst`）、`Documentation/networking/nf_conntrack-sysctl.rst`
- 核心原始碼（stable v6.12，git.kernel.org）：`net/netfilter/nft_flow_offload.c`、`nf_flow_table_core.c`、`nf_flow_table_ip.c`、`nfnetlink_queue.c`、`nf_queue.c`、`nf_conntrack_core.c`、`include/net/netfilter/nf_flow_table.h`
- nft(8)：https://manpages.debian.org/trixie/nftables/nft.8.en.html ；conntrack(8)：https://manpages.debian.org/trixie/conntrack/conntrack.8.en.html
- nftables wiki（[二手-摘要]）：https://wiki.nftables.org/wiki-nftables/index.php/Flowtables 、 https://wiki.nftables.org/wiki-nftables/index.php/Queueing_to_userspace
