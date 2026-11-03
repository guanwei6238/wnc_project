# Galette（框架子題補讀）

頁碼規則沿用既有報告：`[原文 p.N]` 的 N 是 PDF 實際頁碼（論文印刷頁碼 = N − 1）。`[GitHub]` = 2026-10-27 查 galette 與 galette-paper 兩個 repo 的 README、目錄（未讀程式碼、未執行）。PDF 存於 `research/literature/framework/pdfs/galette/galette.pdf`（作者版，全文）。

## A. 書目
GALETTE: a Lightweight XDP Dataplane on your Raspberry Pi，Simpson, Williamson, Paul, Pezaros，IFIP Networking 2023，DOI 10.23919/IFIPNetworking57963.2023.10186412。既有報告：`research/literature/papers/galette.md`。書目經重讀確認無誤；取得程度：全文（作者版，與出版版可能有差異 [原文 p.1]）。

## G. 框架專屬欄位

**G1 抽象。** 框架定義四樣東西：(1) NF 的 Rust API：`#![no_std]` crate、`#[maps]` 巨集把 (K,V) 欄位轉成 `Map<K,V>`、`packet(pkt: impl Packet, maps) -> Action`，`Packet` trait 同時由 XDP context 與 UMEM frame 實作 [原文 p.5 Listing 2]；(2) TOML chain：`[functions.x]`（`maps=`、`disable_xdp=true`）、`[maps.x]`（type、size，可跨 NF 共用）、`[[links]]`（`from`/`to` 陣列），保留名稱 `rx/tx/pass/abort/drop`，`"!dpi"` 前綴強制該 NF 在 userland 跑 [原文 p.4–5 Listing 1]；(3) 編譯規則：chainsmith 用 `syn` 解析 `lib.rs`，檢查 maps 欄位數、`Action` 變體數與 chain 的 `to` 數量一一對應，再產生 eBPF `.elf` 與 `.so` 兩份 [原文 p.5]；(4) 放置規則：鏈長超過 32 強制 upcall [原文 p.5]。留給使用者：NF 內容、map 型別與大小、哪些 NF 放哪層。沒有定義：偵測語意、輸出 schema、與 Suricata 類外部程式的介面。

**G2 生命週期。** 載入：SBC 端 control plane 載 eBPF、`dlopen` dylib、裝共享 map 與 PROG_ARRAY、最後把第一個 NF 掛上 XDP [原文 p.6]。串接：tail call 進 PROG_ARRAY，動作表放在 map，所以改接線不必重編 NF [原文 p.5]。切換：PROG_ARRAY 單一元素原子更新；整條鏈改動時，先建出新的樹、再原子換掉進入樹根的 tail call，未變動的 NF 共用同一批 map，最壞等於重建整條鏈 [原文 p.6]；userland 用 function trampoline 換單一 NF [原文 p.6]。切換期間在途封包如何處理：論文未說明。重配置時間或中斷：**沒有量測**（§V–VI 只有轉送與昂貴 NF 實驗）。NF 以 128-bit UUID 識別，只下載缺的；XDP 與 userland 兩個版本一起下載，用較長的首次傳輸換較短的重配置 [原文 p.6 註 1]。**論文與程式碼不一致**：README 寫明 chainsmith「目前不具備動態重配置所服務之 SFC、也不能提供會變的 map 內容」[GitHub README]，即 §IV-E 的動態重配置在公開原型裡沒有完整實作。

**G3 分層。** Kernel：XDP + eBPF，狀態在 BPF map；userland：每執行緒一個 AF_XDP socket、共用單一 UMEM、第一個執行緒負責回收 frame、其他執行緒經 ring buffer 交還 [原文 p.6]；upcall 時在 headroom 加 8 B metadata 記 NF ID 與 action index，封包只進不回 XDP [原文 p.5–6]。外部：編譯伺服器兼 control plane，SBC 週期性連線拉取 chain、NF 二進位並同步 map [原文 p.6]；測試時控制流量走獨立 WiFi [原文 p.7]。

**G4 外部依賴。** 控制伺服器斷線時的行為（fail-open/closed、是否沿用舊 chain）：論文未說明、未驗證。作者只提到 IoT 長時間離線與無 ECC 記憶體會威脅金鑰完整性 [原文 p.6]。[推測] 已掛載的 XDP 程式留在 kernel，資料面不依賴伺服器。

**G5 價值怎麼證明。** 實際做的只有兩組實驗：(a) Macswap 的轉送效能，XDP vs AF_XDP vs AF_PACKET，Pi 與 NUC，DPDK testpmd 當上限 [原文 p.7–8]；(b) 以合成的 100k 次運算 NF，機率 P ∈ {0…1}，比較「全放 XDP」與「昂貴 NF 上 userland」，並掃 userland 核心數 [原文 p.7, p.9 Fig.6–8]；結果：Pi P=0.5 吞吐 ×25.7 [原文 p.9]。作者也承認便宜 NF 鏈在 Pi 上分流沒有好處 [原文 p.9]。**沒有**：和手寫 eBPF 比框架 overhead（「Pure XDP」本身就是 Galette 產生的）；tail call、map 查表成本的量測（只引 Polycube 說「可忽略」[原文 p.6]）；鏈長掃描；LoC 或開發時間；真實偵測 NF 的案例研究；重配置時間；安全評估；測試或 CI（repo 目錄無 `.github`、無 tests，主分支僅 2 個 commit [GitHub]）。

**G6 量測方法**（可照做的部分；未寫的列在後）：

| 項目 | 內容 |
|---|---|
| 拓撲 | TrafGen（NUC8i7BEK，Ubuntu 22.04 lowlatency 5.15.0-56）→ TP-Link TL-SG108S GbE 交換器 → DUT（Pi 3B，內建 USB2 LAN9514 100BASE-T；或 NUC，I219-V PCIe）；編譯/控制機用共享 WiFi，不在測試路徑上 [原文 p.7] |
| 流量產生與量測 | TrafGen 上的 Pktgen-DPDK 同時送與收，由它量吞吐與延遲；所有資料面機器裝 DPDK 22.07；ASPM 盡量關閉；IRQ throttling 在 NUC 與 TrafGen 關閉（Pi 端未提）[原文 p.7] |
| 基準 | DPDK testpmd 跑 Macswap；Pi 上走 AF_PACKET，NUC 另有 e1000e PMD [原文 p.7] |
| 矩陣 | 速率 0.1/1/10/50/100 Mbit/s（NUC 加 1000，Fig.4 另有 0.5）× 封包 64/128/256/512/1024/1280/1518 B × {Pure XDP, AF_XDP} × {IRQ（阻塞讀，1 ms timeout）, Poll} [原文 p.7] |
| 每格 | burst 11 s、10 trials；userland 單執行緒釘 core 1 [原文 p.7] |
| CPU | DUT 上每 0.5 s 讀 `/proc/stat` [原文 p.7] |
| 功耗 | RDTech UM24C USB 負載監測器，由 TrafGen 經藍牙每 0.25 s 輪詢，只量 Pi（接法論文未詳述，[推測] 串在供電線上）[原文 p.7]；需 bluez、rfcomm [GitHub galette-paper README] |
| 呈現 | 表格 95% CI、延遲 boxplot 為 1/25/50/75/99 百分位 [原文 p.7] |
| DPDK 前置 | 手動設 hugepages（`dpdk-hugepages.py -p 1G --setup 2G`）、Pktgen 機裝 Lua `inspect` [GitHub galette-paper README] |

論文**未寫**：Pktgen 的核心數、queue、descriptor 數、封包內容與 flow 數；延遲打時間戳方式與單向或來回；暖機（反而把起停算進吞吐，所以 NUC 在 64 B、1 Gbit/s 只有 744.8 Mbit/s [原文 p.8]）；CI 算法；丟包判定。未引用 RFC 2544 / 9411。Pktgen 設定應在 galette-paper 的 `pktgen-measure.lua` 與 `machines.toml`，**本輪依限制未讀**。

**G7 安全模型。** 誰能載入：SBC 主動連線到「從一開始就被信任」的編譯伺服器 [原文 p.5]，以預先配置的 TLS 金鑰與憑證做雙向認證 [原文 p.6]；下載的是 eBPF 與原生 `.so`，SBC 直接載入與 `dlopen`。檢查：kernel verifier 只管 eBPF；dylib 無 verifier 或沙箱，userland NF 可連結 C 函式庫 [原文 p.4]；NF 本身沒有簽章，完整性只靠 TLS 與對伺服器的信任（論文未提簽章）。未來工作：TEE 編譯、PUF 重新認證金鑰 [原文 p.6]。README 另寫：`wss://` 需 PUF 挑戰-回應資料庫，`ws://` 不需 [GitHub README]，即原型可走無認證明文通道。**對照我們的規定**：Galette 的設計正是「遠端伺服器產生並下發可執行碼」，我們禁止；但差異在信任關係：Galette 的伺服器是裝置擁有者自己的編譯機（因 Pi 3B 太弱不能本機編譯 [原文 p.5]），不是第三方分析雲。我們是本機管理者安裝、驗簽章，雲端只回 trust/block/observe。同組後續論文指出 ELF 檔缺乏完整性檢查，竄改可造成 DoS（摘要）[二手：OpenAlex 摘要，DOI 10.1109/cns66487.2025.11194984]。

**G8 對照。**
- 已做過，不能宣稱新：SBC 上的 eBPF 鏈 + 動作表放 map [原文 p.5]；「便宜過濾留 kernel、昂貴分析隔離到其他核心，以保護正常流量」[原文 p.4, p.9]（我們 eBPF → NFQUEUE → Suricata 的結構同理）；Pi 上 CPU/功耗/延遲的量測 [原文 p.7–9]；外部編譯再推送 [原文 p.5–6]。
- 他們有、我們沒有，值得考慮 [推測]：單一原始碼編成 kernel 與 userland 兩版以便搬移；整鏈原子切換（樹重建 + 換根）；機率式昂貴 NF 實驗（P = 需要 Suricata 的封包比例）。
- 我們有、他們沒有 [推測]：真實 IDS 整合（Suricata/NFQUEUE）、nftables 政策與 ct mark、簽章與不收遠端碼、無 native XDP 時走 TCX 而非 generic XDP、曾量到 bridge 與 NFQ 的成本基準、雙埠轉送（Galette 只量 Macswap 把封包送回同一埠，單一 DUT 連線 [原文 p.7]，[推測] 未驗雙埠 redirect）。
- 取捨不同、論文需說明：Galette 用 XDP，在 SBC 上沒有 native 支援時是否成立；它的 upcall 以 `bpf_get_prandom_u32` 隨機分流 [原文 p.5]，[推測] 會打散 flow，對需要 flow 狀態的 IDS 不合；封包進 userland 後不再回 kernel [原文 p.6]，我們的 NFQUEUE verdict 會回到 netfilter。

**G9 用途**（最多 5 條）：(1) 支撐「SBC 上兩層分工有前例」[原文 p.4, p.9]；(2) 量測矩陣、10 trials、95% CI、`/proc/stat` 與電表取樣可借 [原文 p.7]，並補上它缺的暖機、丟包判定、idle 基線；(3) tail call 原子換樹可當熱切換前例，但它沒量中斷 [原文 p.6]；(4) 以 USB 輪詢（1 ms）主導 Pi 3B 延遲 [原文 p.7–8]，說明絕對延遲不能直接外推；(5) 反面對照：遠端編譯下發可執行碼 [原文 p.5–6]。

## D5 可信度（只補 Pi 4 部分）
論文**沒有任何 Pi 4 實驗**，也無雙網卡轉送；所有 Pi 數字來自 Pi 3B（100 Mbit/s USB 網卡）[原文 p.6–7]，Pi 4 的內建 GbE 網卡不經 USB，沒有 LAN9514 的 1 ms 輪詢（USB 網卡那一埠仍經 USB），延遲結論不可套用；Pi 3B 吞吐受 100 Mbit/s 網卡限制，不能外推到 GbE。重做時可信度風險：主分支僅 2 個 commit 的研究原型，README 稱 experimental [GitHub]；評估腳本在另一 repo（含 `runner/`、`results/`、`plots/`、`tables/`），結果可重現性需實際跑才知，**未驗證**。

## D6 移植到 Pi 4 的障礙
| 障礙 | 內容 | 狀態 |
|---|---|---|
| native XDP | 論文未寫 attach 模式；Pi 3B 的 LAN9514 驅動無 XDP（既有報告查 5.15 原始碼）。Pi 4 的 bcmgenet 與 USB 網卡依本子題前提無 native XDP；bcmgenet 的 XDP 補丁在 2026-03 至 04 仍於 netdev 審查（v8 於 4/28），**是否合入未確認** [二手：https://lkml.indiana.edu/2604.3/08455.html]。結果：Galette 在 Pi 4 只能走 generic（skb 之後），失去「SKB 前」的優勢，AF_XDP 也只能 copy 模式 | 前提 + [推測]（generic 下 AF_XDP 僅 copy 為已知 kernel 行為，本輪未查證） |
| BTF / CO-RE | Galette 的 redbpf 不支援 CO-RE，裝置須回傳 vmlinux [原文 p.6]；README 要求目標 kernel 含 XDP、eBPF、BTF [GitHub]；作者為此重編 kernel（這些選項預設關閉）[原文 p.7]。Pi OS 無 BTF（前提）→ 要自編 kernel，與「用原廠 kernel」衝突 | 已讀原文；Pi 4 為前提 |
| 工具鏈 | eBPF 要 Rust 1.59（redbpf 的 LLVM 限制），主程式 1.65 [原文 p.7]；Galette 的 kernel 為 5.15，Pi OS trixie 的 kernel 更新，相容性未知 | 未驗證 |
| 單一 queue | 作者前提：GbE 以下網卡只有單一 Rx/Tx queue [原文 p.4]；[推測] Pi 4 同理，故 userland 分流設計仍適用 | [推測] |
| 授權 | repo 為 MIT [GitHub]；其依賴 libelf（elfutils）是否影響閉源需另查 | 未驗證 |
| 結論 | 不建議直接移植；可借的是設計與量測方法，不是程式碼 | [推測] |

## E. 新增數字（既有報告沒有）
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| tail call 上限 / verifier 限制 | 32 / 4096 指令、512 B stack | 背景描述，非量測；新 kernel 可能已放寬 [推測] | [原文 p.3] |
| upcall metadata | 8 B | NF ID + action index | [原文 p.5–6] |
| NF 識別 | 128-bit UUID | 重配置時只拉缺的 | [原文 p.6] |
| 重配置時間 | 無 | — | — |
| 掃描範圍 | 7 種封包大小、P 共 7 值、Fig.8 userland 核心數 1–7 | — | [原文 p.7, Fig.8] |
| 工具版本 | DPDK 22.07；Rust 1.65.0 / 1.59.0（eBPF） | — | [原文 p.7] |
| NUC AF_XDP IRQ CPU | 1.5(4) / 5.1(9) / 1.2(5)% | 64 B；10 / 50 / 100 Mbit/s | [原文 Table III]（非單調，疑筆誤） |
| repo 規模 | 2 commits，無 `.github`、無 tests；macswap `lib.rs` 250 B | 查詢日 2026-10-27 | [GitHub] |
| 被引用 | OpenAlex 列 10 筆 | 同上 | [二手：api.openalex.org/works?filter=cites:W4385192336] |

## D9 建議追加閱讀
1. Miano et al., "A Framework for eBPF-Based Network Functions in an Era of Microservices"（Polycube），IEEE TNSM 2021，DOI 10.1109/TNSM.2021.3055676。被 Galette 比較的同類框架，可看框架 overhead 怎麼量。存在確認：DOI 經 OpenAlex 確認，內容未讀。
2. Høiland-Jørgensen et al., "The eXpress Data Path", CoNEXT 2018，DOI 10.1145/3281411.3281443。Galette 引用的 XDP 量測方法與「XDP 輸 DPDK 但低速率省 CPU」的來源。存在確認：DOI 經 OpenAlex 確認，內容未讀。
3. Rose et al., "We're eBPF'd: Exploring Adversarial Manipulation of ELF Files in eBPF-Based Programmable Network Stacks"，IEEE CNS 2025，DOI 10.1109/CNS66487.2025.11194984。同組後續，直接支撐「不收遠端執行碼、要驗簽章」。存在確認：OpenAlex 確認並讀到摘要，全文未讀。
4. Holík, Jouët, Pezaros, "An eBPF-Based Programmable Network Architecture for OT Digital Resilience Use-Cases"，IEEE ISCC 2025，DOI 10.1109/ISCC65549.2025.11325939。同組，小型裝置上的 eBPF 鏈 + controller，可作替代設計。存在確認：OpenAlex 確認並讀到摘要，全文未讀。
5. Xing et al., "Runtime Programmable Switches"，NSDI 2022。Galette 引用其「program consistency」作為原子換鏈依據 [原文 p.6]。存在確認：僅見於 Galette 參考文獻，DOI 未驗證。

## F. 自評
- 未能確認：Pktgen-DPDK 實際參數（檔案未讀）；延遲時間戳方式；CI 算法；斷線行為；Pi 4 是否真的可跑（無人驗證，我也未實測）；bcmgenet XDP 補丁是否合入。
- 既有報告核對：未發現事實錯誤，Table I–III 數字與抽查的 Q3/Q4 引用相符。僅一處可補：D6 寫「Pi OS 現行 kernel 是否預設啟用這些選項未查」，原文 p.7 說 XDP、eBPF JIT、BTF 在其使用的 Pi OS 11 kernel 預設關閉（Pi OS trixie 仍待實機確認）。
- 最不確定的三件事：(1) 「Pure XDP (Poll)」為何有約 25% CPU，我的解讀（userland 輪詢執行緒在跑）仍是 [推測]；(2) README 的「不能動態重配置」是原型現況還是已過時（README 與論文寫作時間不明）；(3) Pi 4 上 generic XDP 與 AF_XDP copy 模式的實際行為，是依 kernel 常識推測，未查證原始碼。
