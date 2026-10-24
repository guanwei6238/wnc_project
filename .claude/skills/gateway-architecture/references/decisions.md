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
| D6 | 階段 2 要不要提前。CLAUDE.md 的平台已改成 Pi 4，但「eBPF 是後期的事」那條規則還在 | SYNTHESIS §11 |

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
