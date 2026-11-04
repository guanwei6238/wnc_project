# 決策狀態

- 已決定的事項列在 SKILL.md §1，完整紀錄在 `research/literature/trust-bypass/SYNTHESIS.md` §10。
- 開發者希望待決事項**先看選項分析再決定**，不要直接問「選哪個」。
- 開發者做了決定之後：
  1. 把該項移到 SKILL.md §1。
  2. 寫進 SYNTHESIS §10。
  3. 在這裡標成已決定，並附上日期。

## SYNTHESIS 裡原本就有的待決事項

| 編號 | 主題 | 位置 |
|---|---|---|
| D2 | 自建延遲攻擊資料集的四個問題 | SYNTHESIS §11 |
| D3 | **[已決定] 2026-10-24：兩種都支援，預設 bridge**，bridge 預設由 OS 建立（SKILL.md §1）。Pi 上 `nf_conntrack_bridge` 確認沒有，走 `br_netfilter`；實測結果在 SYNTHESIS §11 D3。還沒決定：wire mode 要不要當第三種模式 | SYNTHESIS §11；`platform-backends.md` §3、§5 |
| D4 | 要不要在 Pi 4 上量決策模型 | SYNTHESIS §11 |
| D5 | 特徵來源表 | SYNTHESIS §11 |
| D6 | 階段 2 要不要提前。CLAUDE.md 的平台已改成 Pi 4，但「eBPF 是後期的事」那條規則還在。2026-10-25 決定最小的雲端迴路排在階段 2 前面（O13），所以 D6 的選項 (a)「把階段 2 列為第二步」已經不成立；CLAUDE.md 要不要改還沒決定 | SYNTHESIS §11 |

## 框架調查（2026-10-20）新增的待決事項

傾向欄都是 [推測]，開發者還沒同意。

### O1. 什麼時候拆 process

| 選項 | 好處 | 代價 |
|---|---|---|
| (a) 一開始就拆成 privd、agent、transform | 安全邊界最早成形 | 階段 1 就要寫 IPC，開發者要同時理解好幾個 process |
| (b) 階段 1 先單一 process，module 照邊界切，雲端或插件上線時再拆 | 符合「一次只做一步」 | 拆的時候要重構 |

傾向 (b)，但 privd 的介面從第一天就寫成 trait。

### O2. 欄位腳本用哪個引擎

| 選項 | 好處 | 代價 |
|---|---|---|
| (a) 只用 CEL | 保證終止、沒有副作用，有 K8s 和 Istio 的先例 | 只能寫單一運算式；Rust 版沒有 cost budget |
| (b) CEL，加上 Rhai 處理複雜邏輯 | 彈性大 | 兩套引擎、兩套限制都要維護 |
| (c) 只用 Rhai | 一套引擎就夠 | Turing complete，限制要全部自己設（預設是無限） |

傾向先用 (a)，有真實需求再加 Rhai。wasmtime 和裸 Lua 不考慮，理由見 `field-scripts.md`。

### O3. eBPF 外掛模型

| 選項 | 好處 | 代價 |
|---|---|---|
| (a) 只允許 EXT 分析外掛，只回傳特徵值 | 外掛碰不到 verdict 和 mark；白名單容易定 | 使用者不能寫會 drop 或 redirect 的外掛 |
| (b) 另外開放「動作外掛」，要管理者明確開啟 | 彈性大 | 外掛可以改變流量去向，安全審查成本高 |
| (c) 讓外掛直接掛 XDP/TCX | 最簡單 | 外掛等於擁有 verdict，可以偽造 mark 繞過信任模型 |

**[已決定] 2026-10-22：支援完整功能。** 掛點不限（TCX、XDP、socket filter、freplace 都可以），也可以 drop、redirect；掛在哪、做什麼是管理者的責任。開發者的說法：「eBPF 也可以被 doctor 來說明有什麼，這樣就是他管理的問題」。

- (c) 列的代價仍然成立。框架不擋，改成揭露：載入前掃描 ELF 產生能力報告，doctor 列出每個 port 上的程式（`ebpf-plugins.md` §1、§4）。
- ELF 掃描的結果用來揭露，不拿來拒絕載入。
- [建議] 開發者還沒確認：只有本機管理者能裝外掛，bundle 要有簽章；核心程式在 TCX 排第一，對永不封鎖清單回傳 PASS，預設開啟、可以關。

### O4. nft 操作用哪個 crate，以及專案授權

- 選項：
  - `nftables`（JSON，spawn nft 執行檔）
  - `rustables`（netlink，GPL-3.0-or-later）
  - `nftnl`/`mnl`
  - 自己寫 netlink
- 牽涉授權：Suricata 官方的 Rust crate 是 GPL-2.0-only，`rustables` 是 GPL-3.0+。專案的授權還沒定。
- 傾向：先用 `nftables` crate（JSON），並在 Rust 端驗證 schema。授權問題要找開發者或計畫方確認。

**[已決定] 2026-10-25：用 nft JSON**（`nftables` crate 產生 JSON，spawn `/usr/sbin/nft`）。table、chain、rule、set 元素全部經過 nft。

- 授權：專案可能閉源。`rustables`（GPL-3.0+）和 `nftnl`（要連結 GPL-2+ 的 libnftnl）都會讓 wnc-gw 受 GPL 約束，所以排除。spawn 獨立的 `nft` 程式不受影響。最後仍要請計畫方確認。
- 效能（2026-10-25 在 Pi 4 上量測，鎖頻 1000 MHz）：選哪個方案只影響寫入，不影響每個封包的轉送成本。
  - Plain set 加元素：nft 每次呼叫約 7.7 ms，自己寫 netlink 約 53 µs。一次寫 1000 個時，nft 要 17.2 ms，netlink 要 1.66 ms。set 裡已經有 10 萬個元素時，結果也一樣。
  - Interval set 會隨 set 變大線性變慢：set 有 10 萬個元素時，nft 每次寫入約 1.9 s，netlink 每次 commit 約 14.8 ms。原因沒有查證。
- 因此：
  - 寫入 set 元素的介面設計成一次給一批。privd 收集一小段時間的寫入，再一起送出。
  - [建議] 會常常變動的單一 IP 黑名單放 plain set；CIDR 或範圍清單放另一個 interval set，只在整批更新時重新載入。
  - 如果之後量到 nft 寫入太吃 CPU，只把「寫入元素」改成自己寫 netlink。只需要新增實作，table 和 rule 的程式不用改。

### O5. flowtable 要不要當 fast path 後端

- 只能在 L3 routing 模式下用（跟著 D3 決定）。
- 好處：kernel 會處理 conntrack 的生命週期，之後的正式設備還有機會用硬體 offload。
- 代價：
  - 撤銷只能刪 conntrack entry，撤銷之後 Suricata 看到的是 midstream。
  - 只支援 TCP 和 UDP。
- 傾向：如果 D3 選 L3，把它和 tc redirect 並列成兩種後端，做實驗比較。

### O6. OpenWrt 上的 IDS

| 選項 | 好處 | 代價 |
|---|---|---|
| (a) 自己替 Suricata 8 寫 OpenWrt 套件 | 和 Pi OS 用同一個引擎 | 工作量最大：musl、相依套件、Rust 部分都要處理 |
| (b) 在 OpenWrt 上改用 Snort 3（官方 feed 有） | 現成可用 | 要另外寫 IdsEngine adapter；規則和偵測結果要重新驗證 |
| (c) 正式設備改用 Debian 系統 | 不用移植 | 放棄 OpenWrt 的 offloading 生態 |

目前沒有傾向，要看正式設備的規格。

### O7. GRO 怎麼處理

- 選項：
  - (a) 用 `gso_segs` 修正封包數，接受封包大小失真
  - (b) 關掉 GRO
  - (c) 有 native XDP 的硬體上用 XDP 算特徵
- 要看雲端特徵需不需要每個封包的大小和到達間隔（IAT），也要在 Pi 4 上量 GRO 關掉之後的 CPU 成本。
- 2026-10-24：XDP 預設原則（SKILL.md §1）定了之後，(c) 在有 native XDP 的硬體上就是預設。Pi 4 還是走 TC，(a)、(b) 的問題仍在。掛 generic XDP 雖然也會關掉 GRO，但還多了複製的成本，不能當成 (b) 的做法。
- [建議] 同一個特徵在 XDP 和 TC 算出來的值不同，上傳的資料要記錄是在哪個 hook 算的（`ebpf-plugins.md` §8）。

### O8. 插件簽章與金鑰保管

- 選項：
  - (a) minisign，金鑰放開發者的筆電
  - (b) minisign，金鑰離線保存
  - (c) TUF 式的多角色金鑰
- 原型階段傾向 (a)，正式設備再改成 (b) 或 (c)。

### O9. 雲端斷線時要 fail-open 還是 fail-closed

| 選項 | 意思 | 風險 |
|---|---|---|
| fail-open | 雲端斷線時，還沒判定的 flow 照常轉送，只靠本地 Suricata | 攻擊者只要讓雲端斷線，就能把檢查降級成只剩本地 |
| fail-closed | 雲端斷線時，新 flow 不放行 | 雲端一斷，公司網路就跟著斷 |
| 折衷 | 還沒判定的 flow 照常走本地 slow path，只是不能升級成 trusted | 本地負載升高 |

傾向折衷：斷線時只停止發出新的 trust。這和 SKILL.md §5 第 11 點一致。

### O10. 規則 bundle 能不能由雲端推送

- 現在的底線是雲端不能推可執行內容。
- 規則是「資料」，但 Lua 規則等於程式碼，而且規則解析器出過記憶體破壞的漏洞。
- 傾向：允許雲端推送有簽章的規則 bundle，但一律先經過 `rules-nft-suricata.md` B 節的管線，而且 Lua 規則保持關閉。要開發者確認。

### O11. 我們的 nft table 從哪裡來、黑名單放哪裡

| 選項 | 好處 | 代價 |
|---|---|---|
| (A) 骨架寫死在程式裡，參數從設定檔讀 | 結構一定正確，程式可以依賴它；設定只能改數值，不會破壞信任模型 | 要加新的規則結構時得改程式 |
| (B) 整張 table 從檔案載入，使用者可以改 | 最有彈性 | 程式依賴的結構（ct mark 的值、queue 編號、set 名稱）可能被改壞；等於開放 `nft -f`，違反 SKILL.md §5 |
| (C) 骨架固定，另外留一個使用者 chain | 有彈性，骨架也不會被破壞 | 要定義使用者規則能寫什麼、怎麼驗證；需要時再加，不影響 (A) |

**[已決定] 2026-10-25：(A)。** 開發者的說法：nft 只負責決定封包往哪走，流程由我們定，不然程式會掛掉。

- table 的骨架（chain、hook、priority、policy、規則）寫在 `src/firewall.rs`。之後可以設定的只有參數，例如要不要送 IDS、queue 編號、bypass、set 的大小和 timeout，用到時才加進設定檔。
- 使用者只能管理 set 的**內容**。
- 使用者自己的防火牆規則寫在 OS 自己的 nftables 設定裡；我們只動 `wnc_gw` 這張 table。
- **黑名單放在 nft set，不交給 Suricata。** 分工是：Suricata 偵測、我們的程式判斷、nft 執行。理由：
  - 已信任的 flow（ct mark）和階段 3 的 fast path 都不經過 Suricata，黑名單放在 Suricata 就擋不到。
  - 放在 nft，被擋的封包在 kernel 查一次 hash 就丟掉；交給 Suricata 的話，每個封包都要先經過 NFQUEUE。
  - 和 10-22「Suricata 預設不做 inline drop，擋人由 nft 執行」的決定一致。
- 還沒決定，做黑名單時再談：
  - 使用者怎麼加：指令或設定檔裡的固定清單。
  - 重啟後黑名單還在不在：`run` 啟動時會重建 table，set 會被清空。
  - 永不封鎖清單。

### O12. 雲端 API 的格式由誰定

- request：格式寫死在程式裡，或由設定檔描述。
- 回應：
  - (R1) 格式由我們固定，雲端照我們的格式回。
  - (R2) 可以設定：哪個 JSON 欄位是判定結果、對方的標籤怎麼對應到我們的動作。

**[已決定] 2026-10-25：**

- **request 由設定檔描述**：endpoint、path，以及上傳的欄位（名稱、型別、範圍、預設值、CEL 計算式，格式見 `field-scripts.md` §5）都寫在設定檔。
  - 欄位的輸入可以是使用者 eBPF 程式的輸出、Suricata EVE、conntrack 計數。
  - 這是 10-22「框架只定描述語法，內容由使用者設定」的延伸。開發者的說法：這樣更彈性，也符合「自訂 eBPF 把要的資料算出來」。
  - 好處：不用等雲端由誰做、格式是什麼，先接我們自己的模擬雲端，之後改設定就能接上真正的雲端。
- **底線不變**：
  - 只上傳數值、bool 或事先宣告的 enum，載入設定時就檢查型別（SKILL.md §5 第 9 條）。
  - endpoint 只能在本機的設定檔改，只用 https。
  - 欄位數和 batch 大小有上限。
- **回應先做 (R2)**：
  - 能做的動作固定只有 trust、block、observe，數值一樣檢查上限，所以安全性和 (R1) 相同。
  - 開發者和計畫方討論之後，可能改成 (R1)。(R1) 等於把 (R2) 的對應層拿掉，不用改寫解析的程式。

### O13. 雲端迴路什麼時候做、雲端由誰做

| 選項 | 好處 | 代價 |
|---|---|---|
| (a) 照原本的順序：階段 1 → 階段 2（eBPF 特徵）→ 雲端 | 上傳的特徵一開始就是最終的形式 | 很晚才有完整的「地端加雲端」流程，研究最核心的卸載成本也要很晚才量得到 |
| (b) 階段 1 的地端執行點做完後，先接最小的雲端迴路 | 很早就有閉環：告警或 EVE flow → agent → 雲端 → trust/block → ct mark/ban set。之後 eBPF 特徵只是多一個輸入來源 | 早期的特徵比較粗 |

**[已決定] 2026-10-25：(b)。模擬的雲端由我們自己做**，可以回傳判定、設定延遲；真正的雲端出來之後，改設定檔接上。

- 早期的特徵來源：Suricata EVE 和 conntrack 計數。
- 影響：
  - O1 原本是「雲端 connector 上線時才拆 process」，這個時機跟著提前了，做雲端迴路之前要再決定一次。
  - D6 的選項 (a) 不成立。

### O14. Suricata 怎麼啟動、queue 編號、Suricata 沒在運作時怎麼辦

背景：7.0.10 和 8.0.7 都會在 NFQ 初始化時收到封包就 segfault，所以 Suricata 送出 `READY=1` 之後才能裝 queue 規則，重啟前也要先拆掉（專案記憶 `suricata-nfq-startup-crash`）。

| 子題 | 選項 | 取捨 |
|---|---|---|
| 誰啟動 Suricata | (a) systemd 管，用 `ExecStartPost`、`ExecStopPost` 通知 wnc-gw；(b) wnc-gw 自己啟動，設 `NOTIFY_SOCKET` 收 `READY=1` | (a) Suricata 可以有自己的帳號和沙箱，但協調跨兩個 process，Docker testbed 沒有 systemd 測不了。(b) 順序最好推理、能在 Docker 驗證、OpenWrt 也能用，但 Suricata 和 wnc-gw 共用帳號（換帳號要 `CAP_SETUID`，幾乎等於 root） |
| queue 編號 | 設定檔指定；或由 wnc-gw 自動找沒人用的 | 自動找：wnc-gw 非 root 讀不到 `/proc/net/netfilter/nfnetlink_queue`；用 Suricata 試綁，每次失敗都要重新載入規則；「沒人綁定」不等於沒有別人的規則在用；號碼不固定，log 難對照 |
| Suricata 沒在運作時 | 放行（fail-open）或丟掉（fail-closed） | 三種情況要一致：還沒就緒（不裝 queue／裝 drop）、當掉（queue 加或不加 `bypass`）、跟不上（`nfq.fail-open`）。我們的 table 只掛 forward，連到 gateway 本身的 SSH 不受影響 |

**[已決定] 2026-10-26：**

- **先做 (b)，之後加上 (a)，(b) 也保留。** 兩者實作同一個「Suricata 生命週期」介面，對外只有「已就緒」「已停止」兩種事件，裝拆 queue 的程式不用改。用 (b) 時 doctor 和啟動時都給 warning（Suricata 和 wnc-gw 共用帳號）。wnc-gw 本身照原本的設計，以非 root 帳號加 capability 執行，由安裝時設定。
- **queue 編號由設定檔指定，預設 0**，型別是範圍（`0` 或 `"0-3"`，多個 queue 時用 hash 分流，不用 `fanout`）。被佔用時 Suricata 會在 `READY=1` 之前退出，wnc-gw 報錯並寫進 log，不自動換號碼。之後真的需要再加 `"auto"`。
- **可以設定，預設放行。** 條件：一定要記 log，標出 Suricata 什麼時候掛掉、哪一段時間的流量沒有經過檢查。log 用 `tracing`，在 wnc-gw 開始管 Suricata 之前先做。
- **執行檔和設定檔的路徑可以設定**（`[nftables] path`、`[suricata] path`、`[suricata] config`），必須是絕對路徑。doctor 檢查非 root 帳號能不能改這些檔案或它們所在的目錄，可以的話給 warning（不擋）。
- 步驟：2b-1 路徑與設定檢查 → 2b-1.5 log 基礎 → 2b-2 wnc-gw 啟動和停止 Suricata → 2b-3 queue 規則與放行或丟掉 → 2b-4 檢查其他 Suricata。
- 2b-2 的細節（2026-10-26 決定）：
  - `queue` 設定提前到 2b-2：NFQ 模式一定要綁定 queue，Suricata 才能啟動。
  - `/run/wnc-gw`（通知用和 Suricata 控制用的 socket）和 `/var/log/wnc-gw/suricata`（Suricata 的 `-l`）不讓使用者改，但因 OS 而異，放在 platform 層的 `Dirs`。
  - Suricata 的 stdout、stderr 收進 wnc-gw 的 log，每行帶 `source="suricata"` 和 pid，依 `E:`、`W:` 對應等級。這是 supervisor 常見的做法：同一條時間線，又分得出是誰說的。
  - 退避從 1 秒加倍到 60 秒，就緒後穩定 5 分鐘就重算，不放棄。`[suricata] ready_timeout` 預設 300 秒。
  - 用 `PR_SET_PDEATHSIG`：wnc-gw 被強制結束（`kill -9`、OOM、SSH 斷線的 SIGHUP）時 Suricata 也會結束，不會留下佔著 queue 的孤兒。正式部署時 systemd 的 cgroup 也會清掉，這主要是給沒有 systemd 的情況。
- 2b-3 的細節（2026-10-26 決定）：
  - 設定是 `[suricata] when_unavailable = "accept" | "drop"`，預設 `"accept"`；`"accept"` 時 doctor 給 warning。
  - forward chain 最後 `jump ids`，queue 規則放在獨立的 `ids` chain。切換時在同一個 nft transaction 裡 `flush chain` 再加規則，不重裝整張 table：之後 table 裡會有黑名單 set 這類動態內容，重裝會清掉。
  - `ids` 的兩種狀態：就緒時 `counter queue num N`（`accept` 加 `bypass`）；沒就緒時 `counter accept` 或 `counter drop`（`accept` 原本是只有 `counter`、交給 policy 放行，2026-10-28 改成明確的 `accept`，見 O17）。`nfq.fail-open` 由 wnc-gw 用 `--set` 強制成和設定一致（`accept` 是 yes），不看 suricata.yaml。
  - 順序：裝 table（沒就緒狀態）→ `READY=1` 後換成 queue → Suricata 結束時先換回沒就緒狀態，**換好之後才呼叫 `Lifecycle::allow_restart()` 讓 supervisor 重啟**（不靠退避的 1 秒剛好夠）；換規則失敗就不重啟、停 Suricata、wnc-gw 以結束碼 1 結束 → 停止時也是先換回沒就緒狀態，再停 Suricata，最後移除 table。之後的 (a) systemd 模式，對應的關卡是 `ExecStartPre` 的 hook。
  - log：進入沒檢查的狀態時 WARN「forwarded traffic passes without inspection」或「…is dropped without inspection」（帶 `when_unavailable`）；恢復時 INFO「forwarded traffic is inspected」，帶 `uninspected_ms`（包含啟動時等 Suricata 就緒的時間）。移除 table 時 WARN「table removed; forwarded traffic passes without inspection」。兩種模式都用 WARN：丟掉是設定好的行為，失敗本身（Suricata 結束）另外有記。
  - 還沒做到：
    - Suricata 跟不上、kernel 因 fail-open 直接放行的封包，kernel 不計數（`/proc/net/netfilter/nfnetlink_queue` 的 `queue_dropped` 只算丟掉的），要比對 `ids` 的 counter 和 Suricata 自己的統計，留給之後的監控步驟，和「記下沒檢查的封包數」一起做。
    - `drop` 在 wnc-gw 結束、table 被移除後就不成立。**[已決定] 2026-10-28：停止時照現在的做法移除 table**，wnc-gw 沒在跑時流量就是直接通過（開發者：「沒 run 當然就是通過」）。
    - **[已決定] 2026-10-29：SIGHUP 和 SIGINT、SIGTERM 一樣正常停止**（收尾、移除 table）。原本沒處理，收到就直接結束：table 留著、Suricata 跟著結束，`drop` 模式下所有轉送流量被丟到 wnc-gw 重啟為止，而且這段時間沒有 log。SIGHUP 不再用來重新載入設定，之後要重新載入另外加指令。
      - 2026-10-29 Docker 驗證：`kill -HUP`、用 `script` 開虛擬終端機跑 `run` 再強制關掉終端機（kernel 送 SIGHUP，和 SSH 斷線相同）、輸出再經過管線（`| cat`）三種情況都正常收尾、結束碼 0、table 移除。
      - 測的時候發現：終端機斷掉後寫 log 失敗，`tracing-subscriber` 預設會用 `eprintln!` 回報，`eprintln!` 在 stderr 斷掉時 panic（結束碼 101），收尾沒做完、table 留著，Suricata 被 `kill_on_drop` 的 SIGKILL 殺掉。`cli/logging.rs` 改成 `log_internal_errors(false)`，寫不出去的 log 就丟掉。正式部署時 stderr 是 journald，不會遇到。
    - Suricata 當掉時還在 queue 裡等判決的封包會被 kernel 丟掉，`bypass` 只管之後進來的封包（Docker 實測：每秒 20 個 ping 掉 2 個）。
- 2b-3 之後在 Pi 上發現、2026-10-26 決定補上的三項：
  - **強制 `--set detect.delayed-detect=no`**：設成 yes 時 Suricata 先送 `READY=1` 才載入規則（Docker 實測），wnc-gw 會在沒有規則的期間記成「已檢查」。
  - **強制 `--set coredump.max-dump=0`，Suricata 的工作目錄設成它的 log 目錄**：Suricata 預設會把 core 上限放寬成 unlimited，core 寫在繼承來的工作目錄。Pi 上每次當機寫 154 MB（載入完整規則時約等於 RSS，1 GB 以上），寫檔期間 Suricata 卡在 D 狀態幾十秒、重啟跟著延後，反覆當機還可能寫滿 SD 卡。之後要用 core 除錯時再加設定。
  - **同一台機器只跑一個 wnc-gw**：`run` 載入設定後先 flock `/run/wnc-gw/wnc-gw.lock`，拿不到就報 `another wnc-gw is running (pid N)` 並結束。兩個同時跑時，一個收尾會刪掉另一個的 table，`notify.sock` 也會被搶。flock 在 process 結束時由 kernel 釋放，`kill -9` 不會留下過期的 lock；`/run` 是整台機器共用，不同 netns 也只能跑一個。
- 2b-4 完成（2026-10-27）：doctor 檢查其他正在跑的 Suricata（讀 `/proc`，不需要權限）和 `suricata.service` 會不會開機啟動。一律最多是 warning：佔了設定的 queue 也只是暫時狀態，wnc-gw 照常啟動並退避重試（code review 指出報 error 會讓 `run` 不裝 table，drop 模式失效；wnc-gw 當掉後還在收尾的舊 Suricata 也會擋住重啟）。是不是自己的看 cmdline 裡的 control socket 路徑，不看父程序名稱；佔用 queue 只在同一個 network namespace 才算衝突；只有 Suricata 自己的服務才建議 `systemctl disable --now`（Debian：`suricata.service`），其他給 `kill <pid>`。細節見開發 skill 的 `doctor-checks.md`。
- **`[suricata] stop_timeout`（2026-10-27 決定）**：wnc-gw 主動停止 Suricata 時（wnc-gw 結束、ready_timeout），送 SIGTERM 後最多等多久才 SIGKILL，預設 90 秒（和 systemd 的預設一樣），原本寫死 10 秒。Suricata 結束前會把每條還開著的 flow 寫進 eve.json，Pi 上 `full` 處理過 18 萬條 flow 要 11–13 秒，10 秒會被 SIGKILL，flow 紀錄和最後的統計都會遺失。代價：Suricata 卡死、不理 SIGTERM 時，要等滿 stop_timeout 才重啟。之後換規則要用 `reload-rules` 熱更新，不靠重啟。
- **多個 queue 的分流方式（2026-10-27 決定）：改用 symhash，和階段 1 的 ct mark 一起實作。** 原本的 `queue num 0-(N-1)` 由 kernel 只依兩端位址加協定做 hash，同一對主機的所有連線都擠進同一個 queue。
  - 量測（Pi 4、1000 MHz、`full`、全速，Suricata 直接跑 NFQ、綁 CPU 0、2、3）：42-1 用 3 個 queue，位址 hash 分到 5／7／88%、12.9 kpps；`queue to symhash mod 3`（含 port、對稱）分到 37／33／30%、26.4 kpps、0 丟失。其他 scenario 兩種 hash 相同；symhash 讓 kernel 每個封包多約 0.7–1.8 µs。單一連線佔大部分流量的（60-1 98%、Honeypot-7-1 96%）不管哪種 hash 都只有一個 worker 在忙，要靠信任機制解決。
  - 分片：symhash 對分片只用位址計算（kernel 不讀第一片的 port），沒有 conntrack 時，同一條連線的分片和其他封包會落在不同 queue（Pi bridge 實測 18/24）。table 用到 conntrack 時，kernel 會在進 queue 前組回分片（0/24），所以和 ct mark 一起做。這相當於 Suricata 在 af-packet 模式預設的 `defrag: yes`。
  - 2026-10-28 實作（3b）：queue 範圍產生 `queue to symhash mod N offset <first>`，單一 queue 仍是 `queue num N`。nft 1.1.3 接受非 0 的 offset（列出來是 `… mod 3 offset 2`，offset 0 時不印出來）；非 0 offset 實際怎麼分流沒有測。table 裡一定有 ct mark 規則，conntrack 一定是啟用的，所以不另外檢查。
    - Pi（bridge、wnc-gw、4 個 queue）：24 條連線 0 條被拆開，每條只進 queue 2 個封包（小 UDP、組回來的 datagram）；出口仍是每條 4 個 frame（bridge 送出時重新分片）。
    - Docker：同一對主機的 6 條 TCP 連線分到 3 個 queue（92／46／137 個封包）。
    - IPv6（2026-10-28，`FAMILY=6 frag_pi.sh`，Fragment 擴充標頭、UDP checksum 照算）：Pi bridge 也是 0/24、每條 2 個封包、出口 96 個 frame；`wgw` 關了 IPv6（`disable_ipv6=1`）也一樣。Docker（臨時容器、routed）IPv4、IPv6 都是 0/24。
  - 如果 ct mark 之前就需要多個 queue：加一條永遠不比對成功的 `tproxy` 規則，也會讓 kernel 組回分片（實測 0/24，每個封包約 +0.5–0.7 µs；`socket` 運算式沒有這個效果）。它靠的是副作用，只當暫時的做法。
  - conntrack 本身的成本要在加 ct mark 時重新評估：Pi 實測每個封包 +3.7 µs（單一連線）到 +10.6 µs（掃描，連線表到 65,536 上限，靠 early drop 才沒有丟封包）。3a 在 10,000 pps 重量是 −4.3～+3.5 µs，在雜訊內（O17）。
  - **外部送流量的容量（方案 B，2026-10-29）**：Pi 4、1000 MHz、bridge、`wnc-gw run`（`when_unavailable = "drop"`）、`full`。筆電的 tcpreplay（Docker 容器）從兩張實體網卡送進 Pi eth0 和 eth1.20，Pi 只做轉送和檢查。每個速率送一個 pcap（約 20 萬個封包）；容量上限＝「處理不過來而丟」（queue 滿、網卡丟、沒收到）≤ 0.1% 的最高實際速率（kpps）。2 輪結果相同。

    | scenario | 內容 | 1 queue | 2 | 3 | 4 | 全部信任（1 queue） |
    |---|---|---|---|---|---|---|
    | 1-1 (Hide and Seek) | 49% 是純 SYN | 30 | ≥ 60 | ≥ 58 | ≥ 58 | 40 |
    | 17-1 (Kenjiro) | SYN 掃描，99.8% 是純 SYN | 30 | ≥ 60 | ≥ 59 | ≥ 57 | 20（40 時丟 22%，和不信任相同） |
    | 60-1 (Gafgyt) | 一條 UDP 連線佔大部分 | 30 | 30 | 30 | 30 | ≥ 84 |

    - ≥ 是筆電送不出更快（兩張網卡一起送約 60 kpps，60-1 約 84 kpps），Pi 還沒丟；所以 3、4 個 queue 比 2 個多多少沒量到。
    - **更正（2026-10-30）：不是筆電的上限，是 Pi 用 Ethernet PAUSE 讓筆電變慢，瓶頸是 Pi 的 CPU 0。** 筆電不限速時一個 tcpreplay 送兩張網卡 856 kpps（只走 USB 網卡 836、只走 eno2.20 356–395），`--pps=200000` 準確送到，Pi eth0 的硬體計數全部收到；網線四端都是 1 Gbps，pcap 平均 60–71 bytes。Pi 的 eth0（bcmgenet）PAUSE 收送都開而且協商成功；Pi 所有網卡的中斷都在 CPU 0（eth0 只有一個 RX queue、RPS 沒開），CPU 0 收不完時網卡送 PAUSE，筆電暫停，所以 Pi 不丟、筆電看起來送不快。舊資料的徵兆：要求 70–120 kpps 時實際 2 queue 59.6、3 queue 58.9、4 queue 56.8（越多 queue 越低），Pi 真的丟的那次筆電照樣送滿 60。
      - 驗證（同樣拓樸、`wnc-gw run` ips、2 queue、full、17-1）：30、50 kpps 沒有 PAUSE，CPU 0 忙 46%、77%；要求 100 kpps 時實際 58.3、Pi 送出 24,878 個 PAUSE、0 丟、CPU 0 100%。Pi eth0 關掉 PAUSE（`ethtool -A eth0 rx off tx off`）後筆電照要求送：50 kpps 0 丟；60 kpps 網卡丟 9,617（4.8%）、CPU 0 100%；100 kpps 丟 41.7%。三次 Suricata 的 queue 都沒丟（`nfq_drop=0`）。所以 17-1、2 queue 的真正容量在 50–60 kpps 之間，卡在 CPU 0 收封包，不是 Suricata；3、4 個 queue 沒有幫助。10/29 NFLOG 那天「筆電只送到 40–49」應該也是同一個原因（沒驗證）。
      - 之後量容量：關掉 Pi eth0 的 PAUSE，或把 Pi 送出的 PAUSE 當成「處理不過來」（`planb_pi.sh counters` 已加 `pause_tx0`）。
    - 連線多的流量：2 個 queue 至少是 1 個的 2 倍，Suricata 的判決數各 queue 平均分配。一條連線佔大部分的（60-1）：symhash 把它全放進同一個 queue，加 queue 沒用，信任才有用。
    - 掃描流量信任沒有用：純 SYN 一定進 Suricata（L2 和清 bit 規則），17-1 幾乎全是純 SYN。
    - conntrack `insert_failed`（封包被 Suricata 放行後在 conntrack 確認時丟掉）：17-1 約 28%、全部信任時 48%；1-1 0.3–5%。只出現在高速重播大量新連線時，和 3a 的 INVALID 一樣當成重播假象，不算在容量裡；沒有驗證真實流量下不會發生。
    - 腳本與結果：`tests/ids_inline/planb_pi.sh`、`planb_run.sh`、`planb.py`；原始資料在筆電 `~/datasets/throughput/planb/planb.kvl`。

### O15. log 存在哪裡

wnc-gw 只把 log 印到 stderr，不自己寫檔案。用 systemd 執行時 stderr 會進 journald，但 Raspberry Pi OS 把 journald 設成 `Storage=volatile`（`/usr/lib/systemd/journald.conf.d/40-rpi-volatile-storage.conf`），重開機後 log 就消失，無法事後查 Suricata 什麼時候掛掉。

| 選項 | 好處 | 代價 |
|---|---|---|
| (a) 整個系統的 journald 改成 persistent | 一行設定 | 改的是整台機器，所有服務的 log 都寫 SD 卡 |
| (b) wnc-gw 自己寫 log 檔並輪替 | 不依賴 OS | 自己處理輪替和大小上限；log 存兩份 |
| (c) wnc-gw 用自己的 journald namespace（`LogNamespace=wnc-gw`） | 只有 wnc-gw 的 log 持久保存，可以單獨設大小上限 | 只能用在 systemd；OpenWrt（procd、logd 只在記憶體）要另外處理 |

**[已決定] 2026-10-26：Debian 用 (c)。** 在寫 systemd unit 和安裝程序時實作；OpenWrt 的做法放在 platform 層，到時再決定。開發時直接跑 `run`，就自己把 stderr 導到檔案。

### O16. Suricata 在 IPS 模式遇到「從中間開始」的連線怎麼辦

背景：Debian 的 suricata.yaml 是 `exception-policy: auto`，在 IPS（NFQ）模式等於 drop-flow；`stream.midstream` 預設關。2026-10-26 在 Pi 量測時，連 `empty` rule set 都丟掉 S_m39 26% 的封包：29 條 flow 從中間開始（midstream）、14 次 stream error，之後這些 flow 的封包全部被丟（`ips.drop_reason.flow_drop` 15,730）。

我們的設計會經常產生這種連線：
- AUDIT（SYNTHESIS §4.2）：已信任的 flow 在稽核窗內回到 slow path，Suricata 沒看過前面那段。
- Suricata 重啟（當掉、換規則）之後，所有既有的連線對新的 Suricata 都是從中間開始。

**[已決定] 2026-10-27：wnc-gw 強制讓從中間開始的連線照常放行並檢查**，像 `nfq.fail-open` 一樣用 `--set` 蓋過 suricata.yaml：midstream 不觸發丟包（midstream 的 exception policy 設 `ignore`），並開啟 `stream.midstream`，讓 Suricata 從中間接手 TCP 連線、照常重組和比對。
- 2026-10-27 實作：**只強制 `--set stream.midstream=true`**，`exception-policy` 維持 Suricata 的預設。Docker（Suricata 8.0.7）驗證：cli→srv 持續送 100 行的 TCP 連線，中途讓 Suricata segfault 重啟：

  | 設定 | 連線 | 重啟後的 alert | Suricata 丟的封包 |
  |---|---|---|---|
  | 預設 | 斷（只收到 27 行） | 沒有 | 整條連線（`exception_policy.tcp.midstream.drop_flow`） |
  | 只開 `stream.midstream` | 100 行都收到 | 有（`tcp.midstream_pickups 1`） | 0 |
  | 只改 `exception-policy: ignore` | 100 行都收到 | 有 | 5（`stream_error`，靠 TCP 重傳才沒斷） |
  | 兩個都改 | 100 行都收到 | 有 | 0 |
- 2026-10-27 code review 後補強：**另外強制 `--set stream.midstream-policy=ignore`**（全域的 `exception-policy` 仍維持預設）。原因：使用者的 yaml 若設了 midstream 專用的 policy，只開 `stream.midstream` 擋不住。Docker（8.0.7、已開 `stream.midstream`）實測 yaml 的 `stream.midstream-policy`：

  | yaml 的值 | Suricata 的反應 | 重啟後的連線 |
  |---|---|---|
  | `ignore`、`auto` | 沒有訊息 | 不斷，照常 alert |
  | `pass-flow` | 沒有訊息 | 不斷，但接手後**不再檢查**（alert 停了） |
  | `drop-flow`、`drop-packet`、`pass-packet`、`bypass`、`reject` | warning「not a valid exception policy when midstream is enabled」後照常啟動 | `drop-flow`：**被丟**（`ips.drop_reason.stream_midstream`），訊息說不合法，實際仍然丟 |
  | 上一列再加 `engine.init-failure-fatal: yes` | 同一句變成 `E:`，結束碼 1 | Suricata 起不來，wnc-gw 一直退避重試 |

  強制 `ignore` 之後，上面每一種 yaml 都是「連線不斷、照常 alert」，加了 `init-failure-fatal` 也能啟動（`--set` 蓋過 yaml）。doctor 原本加的 midstream-policy 檢查因此拿掉。
- 還沒處理的同類問題：`engine.init-failure-fatal` 會讓 yaml 裡**任何**一個 warning 都變成 Suricata 起不來，而 doctor 的 `--dump-config` 不做完整驗證（完整驗證要 `suricata -T`，Pi 上 `full` 要 30 秒以上）。可能的做法：執行時偵測「連續 N 次在就緒前結束」記 ERROR，或提供選擇性的完整檢查。
  **[已決定] 2026-10-28：wnc-gw 用 `--set engine.init-failure-fatal=no` 強制關掉**（壞掉一條規則不該讓整個網路失去檢查），並在 Suricata 回報「rules failed」大於 0 時記 WARN，讓偵測範圍變小看得到。完整的規則驗證放在規則管線（架構 §7 第 4 步，沙盒裡 `suricata -T` 通過才套用）。
  實作（2026-10-28）：`FORCED_SETTINGS` 加 `engine.init-failure-fatal=no`；Suricata 加 `-v`，因為「N rules failed」和實際生效的 master exception-policy 都是 Info，console 預設只印到 Notice（`-v` 之後等級名稱變成完整的 `Notice:`、`Info:`，`classify` 一起剝掉）。啟動時 Suricata 多約 10 行 log。驗證：一條正常、一條壞掉的規則，yaml 寫 `init-failure-fatal: yes`，直接跑 Suricata exit 1；經過 wnc-gw 照常就緒，log 有 Suricata 自己的 ERROR 加上 WARN `suricata could not load some rules; they are not used for detection failed=1`（Docker 8.0.7、Pi 7.0.10 相同）。
- **[已決定] 2026-10-28：其他 exception policy 跟著 `when_unavailable`**（memcap 用完、app-layer 解析錯誤等，也就是 Suricata 檢查不了某條 flow 的情況）：`accept` 對應 `ignore`，`drop` 對應 `drop-flow`，wnc-gw 用 `--set` 強制。理由：Suricata 在路徑上但只告警，記憶體不夠不該變成丟正常流量（Debian 的 `exception-policy: auto` 在 NFQ 模式等於 drop）；這和 `when_unavailable` 是同一個問題，只是範圍是一條 flow。
  實作（2026-10-28）：除了全域的 `exception-policy`，`stream.memcap-policy`、`stream.reassembly.memcap-policy`、`flow.memcap-policy`、`defrag.memcap-policy`、`app-layer.error-policy` 也逐項指定（yaml 個別設了也蓋得過去）；drop 時 flow 和 defrag 用 `drop-packet`（不支援 drop-flow），其他用 `drop-flow`；midstream 照 O16 一律 `ignore`。驗證（`tests/ids_inline/exception_policy_pi.sh`；flow memcap 調到 512 KiB，對 5000 個 port 各送 1 個 UDP）：

  | | Docker（8.0.7） | Pi（7.0.10） |
  |---|---|---|
  | `accept`（master exception-policy = ignore） | 5000／5000 送達 | 5000／5000 送達 |
  | `drop`（master = drop-flow） | 送達 2203，丟 2797（`ips.drop_reason.flow_memcap`） | 送達 2101，丟 2899（同） |

  兩個版本啟動時都沒有 warning（全域 drop-flow 加上 midstream 單獨 ignore 不衝突）。stream、reassembly、defrag、app-layer 這幾項沒有個別觸發過，用的是同一套機制。

### O17. 信任狀態放在哪裡、怎麼寫進 kernel（N5）

背景：階段 1 要讓已信任的 flow 不再進 Suricata（SYNTHESIS §4.2–4.4）。成本已量過：ctnetlink 改 mark 每筆約 13 µs、`conntrack -U` 每筆讀整張表不能用（下面 3c-1、`security_gateway/DECISIONS.md` §7）；spawn nft 一次約 7.7 ms（O4）。

| | (a) ct mark，用 ctnetlink 寫入 | (b) nft set，key 是五元組，元素帶 TTL |
|---|---|---|
| 信任的單位 | 一條連線（conntrack entry），新連線沒有 mark | 一個五元組，port 重用或偽造封包會被當成已信任 |
| TTL | wnc-gw 自己管 | kernel 的 set timeout |
| wnc-gw 重啟 | 舊 mark 留在 conntrack，啟動時要清 | 重裝 table 就清空 |
| 每個封包 | 需要 conntrack | 不需要 conntrack |
| 和其他規劃 | conntrack 本來就要用（O13 的 conntrack 計數、flowtable）；分片會先組回，symhash 不用 `tproxy` | 那些功能還是要 conntrack |

**[已決定] 2026-10-28：(a)。** 主要理由是安全：五元組信任可以被 port 重用或偽造封包繞過。要另外做的：wnc-gw 管 TTL、啟動時清掉舊 mark、conntrack 表的大小。

**地基實驗（3a，2026-10-28，Docker routed + Pi bridge）**：queue 規則前放 `ct mark & 0x1 == 0x1 accept`，用 ctnetlink 對傳輸中的 TCP 連線設 mark → 之後不進 Suricata、連線不斷；清掉 mark → 回到 Suricata，中間漏看一段仍照常 alert（AUDIT 的情況）。效能（Pi、10,000 pps、`full`、2 輪；整台機器 µs／封包，含 tcpreplay 自己）：

| scenario | 只轉送 | 全部進 Suricata | 全部信任 | 信任 + L2 | 控制封包 |
|---|---|---|---|---|---|
| 39-1 (IRCBot) | 37.1 | 105.1 | 38.5 | 96.7 | 91% |
| 1-1 (Hide and Seek) | 36.0 | 80.4 | 39.6 | 59.5 | 53% |
| 44-1 (Mirai) | 37.5 | 94.0 | 33.2 | 34.1 | 0.04% |
| Honeypot-5-1 (Amazon Echo) | 36.9 | 71.4 | 32.8 | 46.8\* | 0.06% |
| Honeypot-7-1 (door lock) | 40.2 | 103.0 | 38.8 | 39.7 | 0.01% |

- 信任每個封包省 39–67 µs，信任的封包和不檢查一樣便宜；conntrack + ct mark（全部信任 − 只轉送）在 −4.3～+3.5 µs，量測雜訊內。
- \* Honeypot-5-1 加 L2 後有 34% 封包被 conntrack 判 INVALID 而進 queue：L2 把 SYN 送進 NFQ，重播時後面的封包搶先經過 conntrack；降到 500 pps 時 0 個，是重播假象。
- 腳本與結果：`tests/ids_inline/ctmark_docker.sh`、`ctmark_pi.sh`、`trust_cost.sh`、`trust.py`、`results/trust1.kvl`。

**[已決定] 2026-10-28：L2（SYN／FIN／RST 一律送 Suricata）要放。** 長連線的成本約 +1 µs（控制封包 0.01–0.04%）；掃描類流量幾乎全是控制封包，但這類 flow 本來就不會被信任。

**3b 實作（2026-10-28）**：
- forward chain 依序是 `counter` → `tcp flags fin,syn,rst jump ids`（L2，一定在信任之前）→ `ct mark & 0x80000000 == 0x80000000 counter accept` → `jump ids`。
- `ids` chain 在每種狀態都要以判決結尾（`queue`、`accept`、`drop`）。`jump` 過去的 chain 沒有判決時會回到 forward 繼續比對：原本沒就緒的 `accept` 狀態只有 `counter`，控制封包會先經過 L2、再經過最後的 `jump ids`，被算兩次（Docker：轉送 2 個封包，`ids` 的 counter 是 4）。改成 `counter accept` 之後是 2；放行的效果相同（都只結束我們這張 table）。L2 後面的規則因此在任何狀態都不會看到控制封包。
- 信任用 mark 的最高位元（`firewall::TRUSTED_MARK`），規則只看這個位元：其他程式（例如 mwan3）用的是低位元。3c 寫入時要帶 mask（`CTA_MARK_MASK`），不動其他位元。
- Docker（routed）：用 `conntrack -U … --mark 0x80000000/0x80000000` 設上之後，`ids` 的 counter 和 alert 都停住、連線不斷；`--mark 0/0x80000000` 清掉後恢復；信任中結束連線時 `ids` 只多 2 個 FIN；100 行都收到。
- **連線表滿了時**（Pi bridge、wnc-gw、`empty`；一條被信任的 TCP 連線每 0.2 秒送一行，同時重播 39-1 的掃描）：

  | 重播方式 | 表滿所需時間 | early_drop | 因表滿而丟的封包 | 被信任的連線 |
  |---|---|---|---|---|
  | 整個 pcap、10,000 pps | 8 秒 | 114,845 | 0 | entry 一直是 ESTABLISHED、assured、mark 還在；沒有封包回到 Suricata；160／160 行 |
  | 掃描那一段（pcap 最後 78 秒，約 1,300–6,000 SYN/s、幾乎沒有回應）、原始時間間隔 | 掃描開始後約 20 秒 | 55,584 | 0 | 同上；460／460 行 |

  - early drop 只清沒有 assured 的 entry（掃描的 SYN），已建立的連線不受影響；`dmesg` 沒有「table full」。10,000 pps 一開始有 5–6 個 `insert_failed`／`drop`，同一段封包用原始速度重播是 0，和上面的 INVALID 一樣是重播假象。
  - 原本是推論、2026-10-28 實測（`PROTO=udp ctfull_pi.sh 10000 30`）：只有單向的 UDP 不會變成 assured，表滿時可能被 early drop 清掉，mark 跟著消失，flow 回到 Suricata（多檢查，不會少檢查）。表裡塞滿 assured 的連線（大量真的連線，或完成握手的連線洪水）時，新連線才會被丟。 實測：表滿後約 4 秒，被信任的單向 UDP（`UNREPLIED`）的 entry 被 early drop 清掉，下一個封包建新 entry、mark 0，之後全部進 Suricata（129 個），210／210 都收到、Suricata 0 drop。也就是說，掃描塞滿連線表可以讓單向 UDP 的信任失效、逼 gateway 多花 CPU，但不會漏檢查。
  - 先不改 `nf_conntrack_max`（Pi 預設 65,536）。之後的監控步驟要能看到 `nf_conntrack_count` 和 conntrack 的 `drop` 計數。
  - **2026-10-29 做了**（`monitor/conntrack.rs`）：`run` 每 10 秒用 ctnetlink 讀筆數、上限、每個 CPU 的 `drop`、`insert_failed`、`early_drop`（和 `conntrack -S` 同一個介面；筆電 kernel 7.0 沒有 `/proc/net/stat/nf_conntrack`）。啟動時記一次筆數和上限；到上限 90% 記 WARN、降到 80% 以下記 INFO；`drop` 或 `insert_failed` 增加記 WARN「conntrack dropped packets」；`early_drop` 增加記 WARN「conntrack evicted unassured connections to make room」；讀取失敗只記第一次。10 秒是因為 10,000 pps 時表 8 秒就滿；三個數字都先是常數。Docker 驗證讀到的數字和 `conntrack -C`、`nf_conntrack_max` 相同；計數增加和表滿要在 Pi 上把 `nf_conntrack_max` 調低再重播掃描才測得到（還沒做）。
- 腳本：`tests/ids_inline/ctfull_pi.sh`（表滿）、`frag_pi.sh`（分片，pcap 由腳本自己產生）。

**3c-1 實作（2026-10-28）**：wnc-gw 自己的寫入路徑，取代 `conntrack -U`。
- 實作方式（Pi、1000 MHz、單核、表 1,000 筆；µs／筆；`tests/ctnetlink/bench/`）：

  | | 設一筆 | 一次 100 筆 | 讀一筆（ID、mark、狀態） |
  |---|---|---|---|
  | netlink-packet-netfilter 編碼 + netlink-proto | 51–52 | 13.5–13.9（每筆都要 ACK） | — |
  | netlink-packet-netfilter 編碼 + netlink-sys `Socket` | 19.9–20.8 | 5.4（只等最後一筆 ACK） | 74 |
  | 手寫位元組 + netlink-sys `Socket` | 13.0–13.7 | 2.4（只等最後一筆 ACK） | 19.6 |

  netlink-proto 每個請求經兩個 channel 和 task 切換；crate 每筆配置好幾層 `Vec`，musl 的記憶體配置慢（筆電同一個 bench 讀一筆：glibc 3.7、musl 8.5–8.9 µs）。兩種編碼出來的位元組完全相同。
- **[已決定] 2026-10-28：手寫**，在 `kernel/conntrack.rs`。netlink-packet-netfilter 只放 dev-dependency，單元測試比對兩邊的位元組和解碼結果。這是「netlink 用 rust-netlink」的例外，只限 ctnetlink。
- 實作後在 Pi（表 6 萬筆）：設一筆 14.5、讀一筆 23.4 µs；`list`（kernel 依 mark 過濾）信任 0–100 筆時 37 ms、1 萬筆 111 ms、6 萬筆全部信任 445 ms。
- kernel 的行為：conntrack 的 hash 放了兩個方向的 tuple，用任一方向的五元組都找到同一筆；更新只看五元組、不比對 `CTA_ID`（3d 先讀一筆比對 ID 再設，擋 port 重用）；更新不帶 `NLM_F_CREATE`，找不到就是 `ENOENT`，不會事先建立 entry（那等於五元組信任）；不帶 `NLM_F_ACK` 的訊息成功時不回、失敗仍回錯誤，批次只讓最後一筆要 ACK；請求在 send 裡就處理完、dump 的後續部分在 recv 裡產生，所以 socket 設 non-blocking，收不到就是錯誤。
- `wnc-gw trust add|del|list`：手動信任沒有 TTL，到 entry 消失、`del` 或之後 `run` 重啟時清掉為止；TTL 屬於 3d 的狀態機。`add`、`del` 記 log 事件。所有 ctnetlink 訊息（包括讀）都要 `CAP_NET_ADMIN`。
- conntrack 只在有規則用到它的 network namespace 追蹤連線（kernel 4.10 起）：Pi 上沒有 `run` 時沒有 entry，`trust add` 是 `connection not found`；Docker 容器裡 Docker 的 `table ip nat` 會讓它一直追蹤。
- `nf_conntrack_netlink` 會在需要時由 kernel 自動載入（2026-10-28 Pi：`rmmod` 之後 `wnc-gw trust list` 照常成功，模組回來了），所以 doctor 列為 `must_be_loaded: false` 是對的。
- 3c-2（`run` 啟動時清掉舊 mark）見下面。

**純 SYN 清掉信任 bit（2026-10-28）**：forward chain 的第二條規則是 `tcp flags & (syn | ack) == syn ct mark & 0x80000000 == 0x80000000 counter ct mark set ct mark & 0x7fffffff`，在 L2 和任何判決之前。
- 為什麼：TCP 舊連線沒有 FIN／RST 經過 gw 就消失時（裝置重開機之類），entry 停在 ESTABLISHED（最長 5 天）；同一組五元組的新 SYN 會被 conntrack 忽略、SYN-ACK 回來時重新同步到舊 entry，**entry 的 id 不變、mark 被沿用**（kernel 6.18 `nf_conntrack_proto_tcp.c`）。舊連線有 FIN／RST 經過時（TIME_WAIT、CLOSE），新 SYN 會讓 kernel 刪掉舊 entry 重建，沒有這個問題。
- Docker 重現（`tests/ids_inline/synreuse_docker.sh`，wnc-gw run，Suricata 的 tcp established 逾時改成 5 秒）：沒有這條規則時，新連線的資料全部當成信任放行、只有 4 個控制封包進 Suricata；有這條規則時 SYN 經過就清掉，新連線全部進 Suricata。實際上最容易發生在「信任很久」的連線：信任期間 Suricata 只看到控制封包，它自己的 flow 會閒置逾時（預設 600 秒），新 SYN 對它是新連線；conntrack 的 entry 還在。
- Suricata 的 flow 還沒逾時就重連時，Suricata 會把新的 SYN 當成 stream error 丟掉（`ips.drop_reason.stream_error`），新連線要等它的 flow 逾時才連得上。這是 Suricata inline 的行為，和信任無關。
- Pi（bridge，`tests/ids_inline/synreuse_pi.sh`）結果相同：`early` 時 Suricata 丟掉 7 個 SYN、連線逾時；`clear` 時新連線全部進 Suricata；`noclear` 時 mark 被沿用、只有 4 個控制封包進 Suricata。
- 規則判斷錯的方向只會多檢查：偽造一個純 SYN 可以讓一條被信任的連線回到 Suricata（多花 CPU），不會讓沒被信任的連線被放行。UDP 沒有這種訊號，只能靠 TTL。
- **3d 要處理**：id 不變，所以「觀察時記下 id、信任前比對」擋不住這種沿用；判定送到前新連線的 SYN 已經過去的話，設 bit 還是會落在新連線上。
- 成本（Pi、10,000 pps、`empty`、2 輪；`trust_cost.sh` 的 C3／C4／C5，C5 是同一條規則複製 500 條）：每條規則每個封包 52 ns（44-1，大多是 UDP，第一個比對就失敗）到 159 ns（39-1，91% 是控制封包），1 條（C4 − C3）在量測雜訊內（−0.9～+1.8 µs，整台機器 34–80 µs／封包）。結果：`tests/ids_inline/results/synclear.kvl`。

**3c-2 啟動時清掉上一次留下的信任（2026-10-28）**：`run` 停掉（包括 `kill -9`、當機）之後信任 bit 留在 entry 上，連線不結束就不會消失；`kill -9` 時 table 也留著，這些連線照樣被放行。
- **[已決定] 2026-10-28**：只在啟動時清，**在裝 table 之前**（table 一裝上舊 mark 就生效；`when_unavailable = "drop"` 時它們會在其他流量都被丟掉時通過）。停止時不清：table 跟著移除，留下的 mark 沒有規則看。做法是 `list`（kernel 依 mark 過濾）再批次清 bit（一次 100 筆、只有最後一筆要 ACK），不刪 entry（刪了連線狀態就沒了，使用者另設的 NAT 會斷），也不用世代值（要多佔 mark 的位元、會繞回）。清不掉時照常啟動、記 ERROR：拒絕啟動的話 table 不會裝，所有流量都不經檢查，更糟。
- log：有清到東西時 INFO `cleared trust left by an earlier run`（`cleared`、`gone`＝清之前連線已經結束、`clear_ms`）；清不掉的每一筆 ERROR，寫明這條連線結束前都不經檢查。`run` 沒跑時用 `trust add` 設的信任也會在下次啟動時清掉。
- 清不掉的例子：外部工具（`conntrack -U`）在 ICMP 之類沒有 port 的 entry 設了這個 bit，我們的五元組編碼沒有 ICMP 的欄位，kernel 回 `EINVAL`。wnc-gw 自己只信任有 port 的協定。
- 成本（Pi、1000 MHz、表 6 萬筆；`tests/ctnetlink/bench/`）：信任 0–100 筆時啟動多 37–38 ms，1 萬筆 151 ms，6 萬筆全信任 636 ms（清除每筆約 3.2 µs）。
- 驗證：Docker 信任一條傳輸中的連線、`kill -9` wnc-gw，重新 `run`：log 在 `table installed` 之前寫 `cleared=1`，連線的封包回到 `ids`，150 行都收到；Pi 在 `wgw` netns 用 `conntrack -I --mark 0x80001234` 建一筆，`run` 後是 0x1234。


### O18. ids／ips 模式

背景：2026-10-29 開發者提議加一個模式，前期都用 ids（只標記不擋），「要做兩個模式就要做最好」。設定名稱和現有的 `mode = "bridge"` 撞名，提議 `protection = "ids" | "ips"`（未定）。ips 走現在的 NFQ；ids 的候選：(A) NFQ 但永遠放行、(B) NFLOG 送複本、(C) af-packet（看不到 ct mark，信任沒有用，排除）。**[已決定] 2026-10-29：觀察期間有 alert 的連線不信任**（開發者：「先不信任」），兩種模式都一樣。

**[已決定] 2026-10-29：ids 用 B（NFLOG 送複本），ips 用 A（NFQ）。** B 強制 `-k none`（GRO 合併過的封包 checksum 不完整，不關的話 payload 規則比對不到），依「不安全的模式保留但要警告」在 doctor 和啟動時說明 insertion 風險；漏掉的複本數（`/proc/net/netlink` 的 Drops）之後放進 `monitor/`。log 規則和 queue 規則一樣等 `READY=1` 才裝。設定名稱和預設值（提議 `protection`、預設 `"ids"`）實作時再確認。依據見下面的量測。

**NFLOG 的 Docker 功能驗證（2026-10-29，`tests/ids_inline/nflog_docker.sh`，Suricata 8.0.7，不經過 wnc-gw）**：forward chain 用 `log group N` 送複本、`suricata --nflog` 收。

| 項目 | 結果 |
|---|---|
| 複本完整 | TCP 第一段 1300 bytes 之後的標記照樣 alert。但要 `-k none`（關掉 checksum 檢查）：NFQ 會由 kernel 標出「checksum 還沒算」的封包（Suricata 對它們跳過檢查），NFLOG 沒有這個資訊，veth 的封包全部被當成 checksum 錯誤（`tcp.invalid_checksum` 28/28），stream 不重組、payload 規則不命中 |
| 信任 | 傳輸中 `wnc-gw trust add` 之後 log 規則的計數停住（47 → 47，42 個封包走信任的 accept），`trust del` 後恢復（→ 77） |
| Suricata 被 SIGKILL | ping 100/100，轉送不受影響；沒有程式收的 group，kernel 只是不送複本 |
| 有流量時啟動 | **也會當**：`ping -f` 下啟動、停止 20 次，5 次 segfault（`ReceiveNFLOGThreadInit` → `nflog_set_timeout` → `nfnl_process`），和 NFQ 同一類問題；15 次有 `nflog_handle_packet error -1` 的 warning。所以 log 規則也要等 `READY=1` 才裝，wnc-gw 現在對 NFQ 的順序就是這樣 |
| 多個 group | `symhash mod 2 vmap { 0 : jump g0, 1 : jump g1 }`，每個 chain 一個 `log group`，Suricata `--runmode workers` 每個 group 一個 worker：8 條連線兩個方向都在同一個 group，8/8 alert |
| 跟不上時漏掉的複本 | 預設 `buffer-size` 18 KB、UDP 2 Gbit/s 3 秒：轉送 535,824/535,837；log 規則送出 535,868 份，Suricata 收到 535,531，差 337 份，剛好等於 `/proc/net/netlink` 上 Suricata 那個 socket 的 `Drops`。group 對應哪個 socket 看 `/proc/net/netfilter/nfnetlink_log`（group、portid），`/proc/net/netlink` 一般帳號能讀，**`nfnetlink_log` 只有 root 能讀**（2026-10-29 第 2 步時更正；wnc-gw 不是 root，第 3 步改從 Suricata 的 `/proc/<pid>/fd` 找 socket inode 對到 `/proc/net/netlink`）。Suricata 自己的統計不算這些，只印一行 warning |

- `-k none` 的代價：Suricata 會接受接收端因 checksum 錯誤而丟掉的封包，攻擊者可以塞進接收端根本沒收到的資料混淆檢查（insertion）。Pi 上從網路來的封包 checksum 是真的，但 GRO 合併過的封包 checksum 欄位不完整，所以 Pi 上大概也需要 `-k none`，要實測。
- 還沒做（要 Pi）：A 和 B 每個封包的 CPU、容量上限；`buffer-size`、`qthreshold` 怎麼調；Pi 的 7.0.10 有沒有 NFLOG、GRO 的封包 checksum。

**Pi 上的 A 對 B（2026-10-29，`trial.sh` 加了 `IMPL=nflog`、`run_nflog.sh`、`nflog.py`，結果 `tests/ids_inline/results/nflog1.kvl`）**：Pi 4、1000 MHz、Suricata 7.0.10、veth（env.sh）、10,000 pps、1 個 queue／group、2 輪；兩者都直接跑 Suricata（A 是 `-q 0`，B 是 `--nflog`，NFLOG `buffer-size` 1 MB），checksum 檢查都關（make_configs.sh 原本就是）。µs／封包：

| scenario | rules | worker A | worker B | 整台機器 A | 整台機器 B |
|---|---|---|---|---|---|
| 60-1 (Gafgyt) | empty | 40.2／41.2 | 19.1／19.1 | 102.8／102.8 | 101.7／101.7 |
| 60-1 (Gafgyt) | full | 42.6／42.5 | 20.5／20.4 | 101.4／101.5 | 101.8／101.8 |
| 1-1 (Hide and Seek) | empty | 44.3／44.2 | 22.5／22.5 | 115.1／103.0 | 103.7／103.0 |
| 1-1 (Hide and Seek) | full | 49.5／49.0 | 25.2／25.2 | 104.6／104.3 | 103.2／103.2 |
| 17-1 (Kenjiro) | empty | 43.5／43.4 | 22.1／22.1 | 103.7／102.7 | 103.3／103.0 |
| 17-1 (Kenjiro) | full | 45.9／46.1 | 23.9／23.9 | 103.0／102.7 | 103.3／103.2 |

- **（2026-10-30 更正：「整台機器」這兩欄量錯了，不能用。）** `trial.sh` 的整台機器 CPU 讀 `/proc/stat`，Pi 的 kernel 是 tick 取樣（`TICK_CPU_ACCOUNTING`、HZ 250、沒有 `IRQ_TIME_ACCOUNTING`），10,000 pps 的固定間隔和 tick 對齊，Suricata 所在 CPU 時而多算一倍、時而幾乎算成 0；tcpreplay 預設的 gtod 計時又忙等吃滿 CPU 1，NFLOG 在 CPU 1 上的轉送被它蓋住。表裡約 100 µs 幾乎就是 CPU 1 的 20 秒 ÷ 20 萬個封包。`trust_cost.sh`（10/28）已經改用 `/proc/schedstat` 的 rq_cpu_time 和 `tcpreplay -T nano`，這裡沒有跟上。worker 欄是 Suricata 執行緒的 schedstat，仍然正確。下面這段原本的結論「NFLOG 不省總 CPU」因此沒有根據，要重量。
- 原本的記錄：**整台機器的 CPU 一樣**（含 tcpreplay；兩者都沒丟、沒降頻）。A 的 worker 比較貴，是因為判決之後 kernel 的轉送在 worker 的 syscall 裡做；B 的轉送照樣要做，只是在別的 CPU 的 softirq。所以 NFLOG 不省總 CPU，省的是「Suricata 那一個 worker」的工作（約一半），轉送也不用等 Suricata。
- Pi 上 7.0.10 有 NFLOG。有流量時啟動也會當：`nflog_startup_pi.sh`，10,000 pps 下 20 次有 4 次 segfault（Docker 8.0.7 是 5/20；Pi 升級 8.0.7 後是 2/20，2026-10-30）。
- 還沒做：容量上限（要方案 B 的外部流量，Suricata 那個 worker 成本減半、轉送不受 Suricata 限制時上限會到哪裡）、多個 group 在 Pi 上、實體網卡 GRO 的封包是不是一定要 `-k none`。

**8.0.7 重量、加上 runmode（2026-10-30，`run_nflog.sh` 加 `RUNMODES`，結果 `tests/ids_inline/results/nflog2.kvl`）**：Pi 4、1000 MHz、Suricata 8.0.7（full 規則和 7.0.10 一樣載入 52,606 條、0 失敗）、veth、10,000 pps、1 個 queue／group、2 輪、都沒丟。`trial.sh` 改了量法：整台機器的 CPU 讀 `/proc/schedstat` 各 CPU 的 rq_cpu_time（含 tcpreplay 送封包的成本，所以只看差距；另外用「經過時間 − idle」交叉檢查，大小順序都一致），tcpreplay 用 `-T nano`；Suricata 欄是收封包到判決的執行緒（autofp 再加 RX、TX）。µs／封包：

| scenario | rules | Suricata A workers | Suricata B workers | 整台 A workers | 整台 B workers | Suricata A autofp | Suricata B autofp | 整台 A autofp | 整台 B autofp |
|---|---|---|---|---|---|---|---|---|---|
| 60-1 (Gafgyt) | empty | 40.8／41.2 | 19.2／19.3 | 80.7／80.0 | 55.8／56.6 | 72.3／57.8 | 33.6／33.6 | 112.7／95.1 | 71.3／72.5 |
| 60-1 (Gafgyt) | full | 43.3／42.3 | 21.1／21.2 | 87.1／81.2 | 58.2／59.5 | 58.7／59.5 | 35.7／36.0 | 94.8／96.9 | 74.2／74.5 |
| 1-1 (Hide and Seek) | empty | 43.9／43.0 | 22.1／22.2 | 83.7／81.6 | 60.0／61.6 | 69.3／67.2 | 37.8／37.9 | 109.5／105.3 | 76.4／78.2 |
| 1-1 (Hide and Seek) | full | 47.8／47.0 | 24.4／24.4 | 86.0／85.4 | 62.2／63.5 | 68.4／69.0 | 41.1／41.1 | 105.3／106.3 | 80.9／81.6 |
| 17-1 (Kenjiro) | empty | 35.3／35.5 | 21.3／21.3 | 66.2／66.9 | 59.7／60.3 | 62.5／61.6 | 36.2／36.2 | 103.1／101.0 | 76.2／76.0 |
| 17-1 (Kenjiro) | full | 37.6／37.8 | 23.4／23.3 | 68.2／68.7 | 64.4／63.2 | 64.1／63.8 | 38.3／38.6 | 104.0／102.7 | 77.8／81.0 |

- **NFLOG 省整台機器的 CPU**（推翻 10/29 量錯的「一樣」）：workers 下 60-1、1-1 省 22–25 µs（約 3 成），17-1 只省 4–6 µs（約 1 成）。17-1 的 A 比 7.0.10 時便宜（43.5 → 35.4），其他 scenario 和 7.0.10 差 1–2 µs 以內；這次同時換了版本和 tcpreplay 的計時，分不出是哪一個造成的。
- **autofp 每個封包都比 workers 貴**：Suricata 那邊 A 多 15–30 µs、B 多約 15 µs，整台機器多 15–35 µs。一個封包要經過 RX → worker →（NFQ 再到 TX 送判決）兩三條執行緒交接。60-1 幾乎是一條連線，autofp 下也只有一條 W 在忙；1-1、17-1 平均分到 4 條 W（各約 1 秒），有用到多核，總成本還是比較高。拆開看，autofp 的 W 合計只有 14–25 µs，貴在 RX＋TX（A 43–54、B 約 19 µs）。A 的 autofp 跨輪變動較大（60-1 empty 72.3 對 57.8）；試跑時 tcpreplay 用預設的 gtod 計時（封包間隔很平均），A 的 autofp 是 72 µs，用 `-T nano` 是 58 µs，autofp 的成本和封包到達的方式有關。
- 還沒量：autofp 的容量。接收和判決分到別的執行緒後，一個 queue 的上限可能比 workers 高，要用方案 B 從外部送流量才量得出來。
- **[已決定] 2026-10-30：wnc-gw 強制 `runmode=workers`，多核靠多個 queue／group（symhash）。** 理由：每個封包最便宜；分流放在 kernel（symhash 每個封包 +0.7–1.8 µs）比 autofp 在 Suricata 裡交接（B +15–17、A +21–27 µs）便宜很多，兩者都是同一條連線交給同一條執行緒，分得一樣平均；只剩 1 核時 autofp 的幾條執行緒擠在同一顆核上更差；之前的效能決策（多 queue、方案 B）都是在 workers 下量的。代價：queue／group 只有一個時（目前的預設）只用一顆核心檢查，autofp 下這一個 queue 有 4 條 W 分攤，預設開幾個要另外決定。autofp 單一 queue 的容量沒量，單一連線要超過約 30 kpps 時再用方案 B 補量。
  - 實作：`spawned::FORCED_SETTINGS` 加 `runmode=workers`（doctor 的 `--dump-config` 跟著帶上）。`--set runmode=` 會蓋過 yaml 的 `runmode:`。
  - 驗證（`protection_docker.sh runmode`、`protection_pi.sh runmode`，Docker 和 Pi 結果相同）：ids `group = 10` 只有 `W#01-10`，`"10-11"` 是 `W#01-10`、`W#01-11`；ips `queue = 0` 是 `W-NFQ#0`，`"0-3"` 是 `W-NFQ#0`–`#3`；都沒有 RX、TX，ICMP 都 alert。yaml 明寫 `runmode: autofp`（`--dump-config` 顯示 autofp）時結果一樣。原本的 ids1、groups、ips、missed、startup 在 Docker 照常；Pi 的 ids1、groups 照常，`ping -f` 下啟動 20 次都 exit 0、沒有 core 檔。

**容量和 checksum（2026-10-29，方案 B 的拓樸：筆電兩張實體網卡送、Pi bridge；`planb_pi.sh`、`planb_run.sh` 加了 `IMPL=nflog`，`planb.py` 分轉送上限和檢查上限；結果在筆電 `~/datasets/throughput/planb/nflog.kvl`、`checksum.kvl`、`bufcheck.kvl`）**：
- B 的 table 和 wnc-gw 一樣先 `ct mark` 信任 accept（用到 conntrack），full 規則。今天筆電最多只送到 40–49 kpps（昨天 60），所以都是下限（2026-10-30 更正：應該是 Pi 送 PAUSE 讓筆電變慢，見 O14 方案 B 的更正）。

  | scenario | A（wnc-gw NFQ）1 queue | B 1 group：轉送 | B 1 group：Suricata 沒漏 | B 2 group：轉送 |
  |---|---|---|---|---|
  | 1-1 (Hide and Seek) | 30（同日重量，和昨天相同） | ≥ 44 | ≥ 44 | ≥ 40 |
  | 17-1 (Kenjiro) | 30（昨天） | ≥ 42 | 30；40 時漏 1.2% | ≥ 38 |
  | 60-1 (Gafgyt) | 30（昨天） | ≥ 49 | 30；40 時漏 1.8% | ≥ 46 |

  - **B 的轉送在所有速率都沒丟**（到筆電的上限）。漏掉的只有給 Suricata 的複本：30 kpps 以下全部 0；40 kpps 時 6 次有 3 次漏 1.2–7.4%，更高的 42–49 kpps 反而 0。60-1 用 2 個 group 在 40 kpps 連送三次是 0、2.8%、3.8%，Suricata 也警告 buffer 已到上限（2 MB）。60-1 幾乎是一條連線，全部進同一個 worker；full 規則 10 kpps 時這個 worker 每封包約 20.5 µs，理論上限約 49 kpps，所以 40 kpps 已接近，偶爾停頓就漏。原因沒有完全確認。
  - **conntrack `insert_failed`：B 全部 0，A 同日 1-1 是 4.1%（昨天 17-1 是 28%）。** 推測：NFQ 讓新連線的第一個封包在 queue 裡等（entry 還沒確認），同一組五元組的下一個封包（重送的 SYN）另建一個 entry，確認時撞在一起被丟。重播把封包的時間間隔壓縮了才常見；真實的 SYN 重送間隔約 1 秒，除非 NFQ 延遲接近那麼久。
- **GRO 和 checksum**：用 Docker 錄的 iperf3 大量 TCP（先用 `tcprewrite --fixcsum` 修好 checksum），經實體網卡送進 Pi：31,433 個封包到 Pi 只剩 4,675 份複本（GRO 每份平均合併 6.7 個，10 kpps 也合併），`-k all` 時 10,436／14,069（74%）被判 checksum 錯誤。沒修 checksum 的版本 99.99% 被判錯，證明 `-k all` 確實在檢查。1-1、Honeypot-7-1 這類重播（封包分散）0 個錯、也沒合併。**結論：B 一定要 `-k none`**（或關 GRO，代價是每個封包都要個別處理）。A（NFQ）由 kernel 標出這些封包，不用關。

**實作第 1 步（2026-10-29，主體）**：`protection.rs`（`Protection`）、`ids/delivery.rs`（`Delivery`：Queue 或 Copy）、`kernel/nflog.rs`（`GroupRange`，不能是 0，預設 10）；設定是最上層 `protection`、`[suricata] group`，`Config::delivery()` 依 protection 選 queue 或 group。firewall 的 ids chain、Suricata 參數、`run` 的 log（`delivery=nflog 10`）都改用 `Delivery`；ips 的規則和參數和原本相同。nft 的 `symhash` 當 vmap 的 key 時明確給 `offset 0`（crate 沒給會寫成 `null`）。三個錯誤訊息改成兩種模式都適用的「send forwarded traffic to suricata」。
- Docker 驗證（`tests/ids_inline/protection_docker.sh`，wnc-gw run）：ids chain 是 `log group 10 accept`、Suricata 帶 `--nflog --include /run/wnc-gw/suricata-nflog.yaml`；ICMP 和 TCP payload（1300 bytes 之後的標記）都 alert；信任中 ids chain 的計數停住（45 → 45），`trust del` 後恢復（→ 75）；SIGKILL Suricata 時 `accept` 120/120、`drop` 98/120（重啟約 1.1 秒），兩者都記沒檢查的時段；`group = "10-11"` 時 nft 接受 symhash vmap，8 條連線分成 112／112、8/8 alert；`protection = "ips"` 時和原本一樣是 `queue … to 0`、`-q 0`；`ping -f` 下啟動、停止 10 次，Suricata 都正常結束（log 規則等 `READY=1` 才裝）。
- 還沒做：doctor（第 2 步，現在仍只檢查 NFQ 的模組和 Suricata 的 NFQueue 支援）、漏掉的複本（第 3 步）、Pi 驗證（Pi 的 7.0.10 有沒有 `--include` 還沒確認）。（三項都已完成，見下面）

**實作第 2 步（2026-10-29，doctor）**：
- 標頭多一行 `protection: ids (default), suricata receives nflog 10`。
- kernel 模組依模式：ips 是 `nft_queue`、`nfnetlink_queue`，ids 是 `nft_log`、`nfnetlink_log`（`nfnetlink_log` 有 `nf-logger-*` 別名，kernel 需要時自己載入）。
- Suricata：`--build-info` 多讀 `NFLOG support`（8.0.7、7.0.10 都有這一行），表格多一欄；沒有就是 error，只檢查目前模式要用的那一種。就緒通知的訊息改成「before sending it packets」。
- warning：ids 時三條（偵測不會擋流量；checksum 不檢查與 insertion 風險；跟不上時不管 `when_unavailable` 都照樣轉送）。`when_unavailable = "accept"` 的訊息在 ids 時只說「starts or restarts」，跟不上那部分交給上面第三條。
- group 被佔用：`/proc/net/netfilter/nfnetlink_log` 只有 root 能讀，和 queue 一樣不在 doctor 判斷。執行時 Suricata 印 `nflog_bind_group() failed` 後在就緒前結束，wnc-gw 加記 ERROR「suricata cannot bind the nflog group; another program is using it」，照常退避重試。doctor 看到別的 Suricata 是 `--nflog` 時給 warning，說它可能佔了我們的 group。
- Docker 驗證：ids、ips 的 doctor 輸出如上；手動開一個綁 group 10 的 Suricata 時 doctor 給提示，`run` 每次重試都記 ERROR，對方停掉後下一次就緒（`uninspected_ms=7380`）。觀察到 Debian 預設 yaml 下 NFLOG 是 `autofp` runmode（Pi 量測用的是 `workers`），wnc-gw 不強制，Pi 驗證時一起看差異（2026-10-30 量過後改成強制 workers，見上面「8.0.7 重量、加上 runmode」）。

**實作第 3 步（2026-10-29，漏掉的複本）**：`kernel/nflog.rs` 的 `netfilter_sockets(pid)` 從 Suricata 的 `/proc/<pid>/fd` 找 socket inode，對到 `/proc/net/netlink` 協定 12 的列讀 `Drops`（kernel 以有號整數印，轉成 u32 讓相減時繞回）；`monitor/nflog.rs` 的 `CopyMonitor` 每 10 秒比較，增加就記 WARN「suricata missed packet copies; that traffic was forwarded without inspection」（`missed`、`interval_s`）。只在 ids、Suricata 就緒之後才讀；Suricata 重啟（新 pid、新 socket）從 0 算起，因為 log 規則就緒後才裝，之前不會有複本被丟。Suricata 結束前最後一段（上次讀到結束之間）漏掉的算不到：程序結束後 `/proc/<pid>/fd` 就讀不到了。
- Docker 驗證（`protection_docker.sh missed`）：iperf3 UDP 200 Mbit/s 6 秒，中間 SIGSTOP Suricata 3 秒：轉送 107,160/107,160；kernel 的 Drops 53,425，wnc-gw 記 `missed=53425`。
- 讀取成本沒量（每 10 秒讀一次 fd 目錄和 /proc/net/netlink），Pi 驗證時一起看。

**Pi 驗證（2026-10-30，第 1–3 步一起，`tests/ids_inline/protection_pi.sh`）**：Pi 4、1000 MHz、bridge（env.sh 的 wgw 加 fcli、fsrv），Suricata 7.0.10，用 include 系統 suricata.yaml 的 yaml。
- 7.0.10 接受 `--include`：Suricata 印 `Configuration node 'nflog' redefined`，group 10 的 `buffer-size`、`max-size` 生效；`device: 10: … invalid chksum: 0`。
- 結果和 Docker 相同：ICMP 2、payload 1 個 alert；信任中 ids chain 計數停住（45 → 45，del 後 75）；SIGKILL 時 `accept` 120/120、`drop` 97/120（`uninspected_ms=1292`）；`group = "10-11"` 8/8 alert；ips 是 `queue … to 0`、`-q 0`；`ping -f` 下啟動、停止 **20 次都正常結束**；missed：python 送 UDP 10 kpps 6 秒、SIGSTOP 3 秒，60,000/60,000 送達，kernel Drops 28,016 = `missed=28016`；另一個 Suricata 先綁 group 10 時 doctor 給提示、`run` 每次重試記 ERROR，對方停掉後就緒。
- doctor：ids 列 `nft_log`、`nfnetlink_log`（開機後都是 loadable），ips 列 `nft_queue`、`nfnetlink_queue`；NFLOG 欄 yes；root 和 wnc 帳號的輸出相同。
- SSH 斷線經過 sudo（`ssh -tt … sudo ip netns exec wgw wnc-gw run`，殺掉筆電的 ssh）：log 印在終端機、導到檔案兩種都正常停止（`stopping signal="SIGHUP"`）、table 移除、Suricata `exit code 0`。
- `netfilter_sockets(pid)` 一次約 340 µs（wgw：Suricata 9 個 fd，`/proc/net/netlink` 7 列、141 µs）；主 namespace 的 `/proc/net/netlink` 26 列 205 µs，fd 多的程序（pid 1，108 個 fd）1.6 ms。每 10 秒一次，可以忽略。
- **同一天把 Pi 升級到 Suricata 8.0.7**（trixie-backports，只換 `suricata` 一個套件，相依套件 Pi 都有；yaml 沒改過，直接換成 8.0.7 的預設檔）後整組重跑，結果相同：doctor 的 READY NOTIFY 變成 yes、沒有「cannot verify systemd support」；ICMP 2、payload 1；信任 45 → 45 → 75；`accept` 120/120、`drop` 96/120；groups 8/8；missed 28,016 一致；bind 一樣；`ping -f` 下啟動 20 次都正常結束、沒有 core 檔。runmode 仍是 autofp。
- **runmode**：Debian 預設 yaml 沒設 `runmode`，NFLOG 是 `RunModeIdsNflogAutoFp`（RX#01-10 一個收封包、W#01–04 四個 worker），**NFQ 也是 autofp**（RX-NFQ#0、TX#00、W#01–04）；之前所有 Pi 量測用的是 `workers`。wnc-gw 兩種模式都沒強制，差異還沒量（2026-10-30 量過後改成強制 workers，見上面「8.0.7 重量、加上 runmode」）。

### O19. Edge AI 的介面與 CPU 分配（2026-11-02 新增）

背景（2026-11-02 開發者轉述和老師的討論）：
- 地端有 rule（Suricata）和 edge AI，再加上雲端。
- edge AI 和雲端一樣是和其他教授合作的部分，輸入、任務、模型目前都不確定。
- edge AI 跑在 gateway 同一台機器上。正式設備之後不是 Pi，但開發者自己的研究在 Pi 4 上做。

已知的影響：
- edge AI 和網卡中斷、Suricata worker、轉送共用 CPU。Pi 4 的網卡中斷全在 CPU 0，上限約 50–60 kpps（O14 方案 B）。信任每個封包省 39–67 µs（O17），省下的 CPU 就是 edge AI 能用的預算。
- 文獻裡 Pi 上的推論成本（模型不同，只能當量級）：Kitsune（KitNET）在 Pi 3B 單核每個封包約 175–1,100 µs（讀圖，`research/literature/papers/kitsune.md`）；eBPF/XDP-DL 的 GRU 在 Pi 4B 每條 flow 平均 10.38 ms（`research/literature/papers/ebpf-xdp-dl.md`）。Suricata 每個封包約 40 µs。所以 edge AI 不太可能逐封包看完全部流量，比較適合吃抽樣資料或每條 flow 的彙總特徵。
- Suricata 要完整的 stream，吃不了零散的抽樣封包（`research/literature/fastpath-methods/C-partial-inspection.md`）；edge AI 的模型不需要前後文，可以吃抽樣資料。

待決：
1. 傳輸方式：O12 的 https 是給雲端的，同一台機器要另外選（例如 Unix socket、共用記憶體、直接讀 BPF ring buffer）。
2. 權限：[建議] edge AI 是獨立的無特權 process，和雲端一樣只能回 trust/block/observe，由 agent 和 privd 檢查後才動 ct mark（SKILL.md §3）。
3. edge AI 要不要看 payload：SKILL.md §5 第 9 條目前只允許數值、bool、enum。要給 payload 得另外設計並做安全檢查，因為那等於把攻擊者控制的 bytes 交給另一個程式。
4. CPU 怎麼分：哪些核給網卡中斷、Suricata、edge AI；固定分配還是依負載調整。照 CLAUDE.md 規則 6 要實測。類似框架的調查在 `research/literature/edge-colocation/`。
5. 合作方的模型出來之前：[建議] 用每次呼叫 CPU 成本可調的替身（和 O13 的模擬雲端同一種做法），量「edge AI 用掉多少 CPU 時，轉送和 Suricata 還剩多少」。
6. 結果要能換到正式設備：報每個封包、每次推論的 µs（換硬體要重量），以及各層處理的封包比例（可以直接搬）。

**實測（2026-11-02 晚，`tests/cpu_alloc/README.md`；Pi 4、1000 MHz、方案 B、PAUSE 關）**：
- CPU0 只是轉送和信任流量的天花板：只轉送時 RPS 分到 CPU1–3 從 100 到 300 kpps；信任的單一 flow 把收封包移出 CPU0（IRQ 29 → CPU1、threaded NAPI 或 RPS）從 50 到 80 kpps。eth0 的流量全在 IRQ 29（RX 與 5 個 TX ring），IRQ 28 只管 link；USB 網卡（xhci、brcmstb MSI）的 IRQ 搬不動。
- 全部檢查（ips、full）每個封包 55–61 µs，4 核心約 60 kpps 就滿；2、3、4 個 queue 都一樣。信任的封包約 14 µs，edge AI 的 CPU 幾乎全部來自信任。
- edge AI 替身（40 kpps）：純運算的 AI 綁在 Suricata 以外的核心時 0 干擾；和 Suricata 共用核心時即使 `SCHED_IDLE` 也丟 28–47%；**記憶體頻寬是共用的**：吃記憶體的負載綁在別的核心仍讓 Suricata 每封包成本變 2 倍、丟 32%，權重 6 MiB 的 MLP 讓它貴 15–17%（不丟），限制工作比例 25%／50% 時貴 16%／32%。
- 把 eth0 的 IRQ 搬到 CPU1 後，CPU0 可以放 edge AI（cpu、mlp 都不丟）。
- 對第 4 點的意涵：「綁核心」是必要但不夠，要依 Suricata 的負載調整 AI 的工作比例；Pi 4 沒有 MPAM，不能用硬體限制記憶體頻寬。

### O20. 已信任 flow 的「部分檢查」用哪種切段（2026-11-03 新增，待決）

背景：實驗 3–5（`tests/partial_inspect/README.md`）。只檢查每段開頭可以抓到長連線後段的攻擊，成本約 5–8% 的封包；但固定長度會被「先塞資料再攻擊」繞過。

| 選項 | 做法 | 後段攻擊／先塞 4 KB 再攻擊（實驗 5） | 送出封包 | 代價 |
|---|---|---|---|---|
| (a) DPA | 看 TCP 序號，每次方向改變後送前 N bytes | 100%／0% | 8% | 不懂協定、最好放進 kernel；會被繞過 |
| (b) HPA | 解析 HTTP（header 結尾、`Content-Length`），每個訊息送前 N bytes | 100%／100% | 8% | kernel 裡要掃 payload、解析數字；chunked、HTTP/2 沒處理；HTTPS 看不到；攻擊放在單一訊息 body 深處仍擋不住 |
| (c) 隨機 N 的 DPA | 每條 flow 的 N 隨機（1–16 KB） | 100%／83–90% | 14% | 不懂協定；機率性 |
| (d) DPA + 隨機稽核窗 | (a) 再以機率 a 整段全送 | 100%／約 a | 17–19% | 對繞過只多 a |

- 都還沒在 Pi 上量 tc eBPF 的實作成本（照 CLAUDE.md 規則 6 要量）。
- 送給 Suricata 的子集要從訊息邊界開始、跳過的量要小於 Suricata 看到的接收視窗（實驗 3）。

### O21. 稽核前要不要讓 Suricata 先忘掉這條 flow（established 逾時）（2026-11-03 新增，待決）

背景：信任期間 Suricata 看不到這條連線。取消信任時它若還記得，序號和 ACK 都過時：app-layer 規則漏、ips 還會自己丟封包；它若已逾時忘記，會當成新的 midstream session，ids 全部抓到、ips 只漏第一個交易的 established 規則（實驗 3b，Docker、逾時 10 秒）。`flow-timeouts.tcp.established` 預設 600 秒。

| 選項 | 好處 | 代價 |
|---|---|---|
| (a) 調短逾時（例如 60 秒） | 信任後更早可以稽核 | 全域：所有閒置超過逾時的連線都會被忘掉，ips 下下一個交易的 established 規則漏（ET TCP 規則 97.2% 要求 established）；flowbits、threshold 等連線內狀態被清掉；EVE 的一條連線拆成多筆 flow；記憶體用得少 |
| (b) 不調，只稽核信任超過 600 秒的連線 | 不影響其他連線 | 短的信任期不能稽核（信任主要省的是長連線，影響可能不大，[推測]） |
| (c) 只在 ids 模式稽核 | 新 session 第一個交易也抓得到 | ips 模式沒有稽核 |
| (d) ips 下取消信任時，等下一個 server→client 的封包才開始送 | 第一個 request 也抓得到（實驗 3 E1 ii、iii） | [推測] 還沒在真的連線測過；要多一條 nft 規則 |

- 只在 Docker 用 10 秒測過，Pi 上沒量。

### O22. 3d：wnc-gw 怎麼拿到 Suricata 的 alert（2026-11-04）

背景：3d 要做到「有 alert 的連線不信任、已信任的撤銷」（O18 已決定有 alert 的連線不信任）。2026-11-04 開發者決定 11/09 的報告以「3d 最小版」為目標：1 讀 EVE 的 alert → 2 定期讀 conntrack 計數建觀察表 → 3 自動信任加 TTL、alert 撤銷 → 4 Pi 驗證與 demo。

**[已決定] 2026-11-04：**
- 觀察期間的封包數和 bytes 用 conntrack 計數（`nf_conntrack_acct`，每個封包多 0.1–1.3 µs，`tests/cpu_alloc` 實驗 3）；EVE 只拿來讀 alert。EVE 的 flow 事件要等連線結束或逾時才輸出，長連線等不到。
- alert 從 suricata.yaml 裡設定的 eve-log 檔讀（enabled、filetype regular、types 有 alert）。不強制 Suricata 另外輸出：`--include` 會蓋掉整個 `outputs` 清單，`--set` 指定清單位置又很脆弱。不用 unix_stream：live 模式讀取端跟不上時事件被默默丟掉，執行中也沒有計數（`tests/eve_output/README.md`）。
- 只讀檔案新增的部分，每 `[suricata] eve_interval` 秒（預設 0.5、範圍 0.05–10，可以有小數）讀一次；原本是 `eve_interval_ms`，2026-11-04 開發者要求和其他時間設定一樣用秒（「統一改秒好了，這樣比較直觀」）。開發者：「放在 setting 更有彈性，先定 0.5 秒，使用者可以依效能調整或用 inotify」；原本也做了 `eve_watch = "inotify"`，Pi 量測後刪掉（下面 Pi 那行；開發者 2026-11-04：「poll 是最佳解，沒理由用 inotify」），連帶拿掉唯一的 `unsafe`（`kernel/inotify.rs`）。
- wnc-gw 的 log 只放重要資訊和出事時能定位的資訊：每筆 alert 是 DEBUG（加 `--log-level debug` 才印），每 60 秒有 alert 時記一行 INFO 摘要；講到連線的 log 帶五元組和 Suricata 的 `flow_id`，可以回 eve.json 找完整紀錄。

**實作（步驟 1，2026-11-04）**：`ids/eve.rs`（EveFile、parse_alert、EveInterval）、`monitor/alerts.rs`（AlertMonitor、AlertWatch）、`ids/suricata.rs` 的 `alert_file()`；`run` 在 Suricata 第一次就緒時才開始讀（之前不會有 alert，也避免檔案還沒建立時記 WARN），停止時讀完最後一段並記摘要；doctor 的 Suricata 設定表多一列 eve-log，沒有寫 alert 的輸出時給 warning；CLI 加 `--log-level`。
- Docker 驗證（`tests/ids_inline/protection_docker.sh alerts`，刪掉 inotify 前後都跑過）：fast.log 的 5 筆 alert 和 wnc-gw 的 DEBUG 筆數相同；`mv eve.json` 後對 Suricata 送 SIGHUP（輪替）、`: > eve.json`（截斷）都接著讀，各記一行 INFO；停止時 `suricata raised alerts alerts=5 connections=4`。
- 檔案被移走時：Suricata 重開檔案之前仍寫在舊檔（改了名的那個），所以 wnc-gw 繼續讀手上的舊檔，等新檔出現才讀完舊檔、切到新檔。
- Pi（2026-11-04，鎖 1000 MHz，`autotrust_cost_pi.sh eve|latency`）：wnc-gw 讀 EVE，poll 每筆 alert 16 µs、沒有 alert 時 0.37 ms／秒；inotify 每筆 51 µs、0.20 ms／秒。inotify 貴是因為監看整個目錄，eve.json 和 fast.log 交替寫入時 kernel 合併不起來，每次寫入都叫醒（每秒 1000 筆時被叫醒 1966 次）。延遲：poll 0–500 ms；inotify 在 alert 稀疏時中位數 2.5 ms，每秒 10 筆時和 poll 一樣受 500 ms 間隔限制。因此刪掉 inotify（程式留在 `~/datasets/throughput/func_20261104/worktree_with_inotify.diff`）。

**步驟 2、3（2026-11-04，開發者：「先完成 3d 的四個步驟，我再一起看」，所以下面的數值都是 [建議]，待開發者確認）**：
- 設定 `[trust]`：`auto`（預設 false）、`min_packets`（10）、`min_age`（5 秒）、`ttl`（900 秒）、`check_interval`（5 秒），都有上下限。Suricata 在檢查的期間，兩個方向都有 `min_packets` 個封包、觀察滿 `min_age`、沒有 alert 就信任；只信任 TCP（已建立）和 UDP；有 alert 不信任或立刻撤銷；TTL 到期回到檢查，再觀察一次才會再信任；Suricata 停止時觀察重來。
- forward chain 多一條 `ct mark & 0x40000000 == 0 ct mark set ct mark | 0x40000000`（連線第一次經過時設 forwarded 位元，只寫一次），wnc-gw 用 ctnetlink 依這個位元列連線，gateway 自己的連線不算進來。ct mark 的位元：`0x80000000` 信任、`0x40000000` 經過 forward，其他位元留給別的程式。
- `src/agent/`：`TrustAgent`（狀態機）、`Privd` trait（`forwarded_connections`、`trust`、`untrust`）和同一個 process 的 `LocalPrivd`；`kernel/conntrack.rs` 多讀 `CTA_COUNTERS_ORIG／REPLY`。
- doctor：開著時一律 warning；`nf_conntrack_acct` 不是 1、讀不到 alert 時是 error；ips 模式下 `ttl` 不比 Suricata 的 `flow-timeouts.tcp.established` 長時 warning（O21）。wnc-gw 執行中發現連線沒有計數時記一次 WARN。
- Docker 驗證（`protection_docker.sh autotrust`）：乾淨的長連線約 3 秒信任、ids chain 計數停住、TTL 到期後再信任、結束時 FIN 的 alert 撤銷；**ids 模式下帶攻擊標記的連線先被信任、結束時才撤銷，ips 一開始就不信任**。[推測] ids 的 raw stream 比對要等重組累積到 `toserver-chunk-size`（2560 bytes）或連線結束，所以低流量連線的 alert 比 `min_age` 晚。待決的做法：ids 時要求送往 server 的資料超過 chunk 才信任、調小 chunk、加大 `min_age`。
- Pi 驗證（2026-11-04）：`protection_pi.sh autotrust` 和 Docker 相同（含 ids 的 alert 晚到）；routed 模式（veth）也正常；demo 全流程（`tests/demo/README.md`）。
- Pi 成本（`autotrust_cost_pi.sh saving|check`）：8 條 TCP、4,000 封包／秒，Suricata 100.5 → 13.6 ms／秒、wnc-gw 0.5 → 1.9 ms／秒，每個封包省 21 µs。每次讀 conntrack 固定約 7 ms（kernel 掃全機共用的 65,536 個 bucket）＋每條經過 gateway 的連線 9.4 µs；讀表是同步的，期間事件迴圈停住（1 萬條約 0.1 秒）。

**待決**：自動信任的預設值（上面的 [建議]）、ids 模式 alert 晚到的處理；讀 conntrack 要不要移出事件迴圈（另一個執行緒或改用 conntrack 事件）；log 保存多少——wnc-gw 自己的 log 要等 systemd unit（O15 的 journald namespace，`SystemMaxUse`），Suricata 的 eve.json、fast.log、stats.log 目前沒有上限（Pi 的 SD 卡），做法待選：限制 eve 的事件種類、Suricata 輪替加上 wnc-gw 刪舊檔、logrotate。

