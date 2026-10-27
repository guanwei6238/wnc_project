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
  - `ids` 的兩種狀態：就緒時 `counter queue num N`（`accept` 加 `bypass`）；沒就緒時 `counter`（`accept`，交給 policy 放行）或 `counter drop`。`nfq.fail-open` 由 wnc-gw 用 `--set` 強制成和設定一致（`accept` 是 yes），不看 suricata.yaml。
  - 順序：裝 table（沒就緒狀態）→ `READY=1` 後換成 queue → Suricata 結束時先換回沒就緒狀態，**換好之後才呼叫 `Lifecycle::allow_restart()` 讓 supervisor 重啟**（不靠退避的 1 秒剛好夠）；換規則失敗就不重啟、停 Suricata、wnc-gw 以結束碼 1 結束 → 停止時也是先換回沒就緒狀態，再停 Suricata，最後移除 table。之後的 (a) systemd 模式，對應的關卡是 `ExecStartPre` 的 hook。
  - log：進入沒檢查的狀態時 WARN「forwarded traffic passes without inspection」或「…is dropped without inspection」（帶 `when_unavailable`）；恢復時 INFO「forwarded traffic is inspected」，帶 `uninspected_ms`（包含啟動時等 Suricata 就緒的時間）。移除 table 時 WARN「table removed; forwarded traffic passes without inspection」。兩種模式都用 WARN：丟掉是設定好的行為，失敗本身（Suricata 結束）另外有記。
  - 還沒做到：
    - Suricata 跟不上、kernel 因 fail-open 直接放行的封包，kernel 不計數（`/proc/net/netfilter/nfnetlink_queue` 的 `queue_dropped` 只算丟掉的），要比對 `ids` 的 counter 和 Suricata 自己的統計，留給之後的監控步驟，和「記下沒檢查的封包數」一起做。
    - `drop` 在 wnc-gw 結束、table 被移除後就不成立，和 O9「停止時 table 要移除還是保留」一起決定。
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
  - 實作時要做：queue 範圍用 `queue to symhash mod N offset <first>`（offset 的語法還沒驗證）；開了多個 queue 時，doctor 和啟動要確認 conntrack 已啟用，否則報錯或給 warning；IPv6 的分片要另外驗證。
  - 如果 ct mark 之前就需要多個 queue：加一條永遠不比對成功的 `tproxy` 規則，也會讓 kernel 組回分片（實測 0/24，每個封包約 +0.5–0.7 µs；`socket` 運算式沒有這個效果）。它靠的是副作用，只當暫時的做法。
  - conntrack 本身的成本要在加 ct mark 時重新評估：Pi 實測每個封包 +3.7 µs（單一連線）到 +10.6 µs（掃描，連線表到 65,536 上限，靠 early drop 才沒有丟封包）。

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
- 還沒決定：其他 exception policy（memcap 用完、app-layer 解析錯誤等，也就是 Suricata 檢查不了某條 flow 的情況）。傾向跟 `when_unavailable` 一致：`accept` 對應 `ignore`，`drop` 對應 drop-flow。

