# Wang & Chang 2022（框架子題精讀）

頁碼規則：`[原文 p.N]` 的 N 是期刊頁碼，等於 PDF 頁碼（共 17 頁）。`[Fig.N 目視]` 是我從圖上目視估讀的數值，誤差約 ±200 Mbps，不是論文寫出的數字。`[sapo-boi 報告]` 指 `research/literature/papers/sapo-boi.md`，只引用該報告寫的內容，我沒有重讀 Sapo-boi 原文。圖表已用 pdftoppm 渲染目視：Fig. 7–12、Fig. 17、Fig. 21–26。

## A. 書目與取得狀況
- 標題：Design and implementation of an intrusion detection system by using Extended BPF in the Linux kernel
- 作者：Shie-Yuan Wang, Jen-Chieh Chang（National Yang Ming Chiao Tung University）
- 出處：Journal of Network and Computer Applications 198 (2022) 103283；Received 2021-05-30，Accepted 2021-11-15，Available online 2021-11-30 [原文 p.1]
- DOI：10.1016/j.jnca.2021.103283（PDF 第 1 頁與 PDF metadata 皆列此 DOI）
- URL：https://doi.org/10.1016/j.jnca.2021.103283
- 與給定資訊的差異：無。補充：OpenAlex（W3216686227）的 publication_year 記 2021（線上首發），卷期年份為 2022；cited-by 41、參考文獻 29（2026-10-27 查）。
- 取得程度：**全文**（使用者經學校下載，17 頁）。本論文沒有舊版精讀報告，這是第一次精讀。

## B. 核心貢獻
1. 在 XDP 層（論文稱 eBPF FPM，fast pattern matcher）用 Aho–Corasick DFA 掃封包 payload，封包內沒有出現任何規則的 fast pattern 就丟棄，不交給 user space；有命中才用 perf event 送出（第一個事件帶整個封包）[原文 p.1, p.6, p.7, p.10]。
2. User space 的 control program 是自己寫的，不是 Snort：把 Snort 規則依 (協定, src port, dst port) 分成 port group，每組建一棵 rule tree，用 BFS 判斷封包命中哪條規則 [原文 p.10–11]。
3. 被動鏡像情境、修改過的 Snort registered ruleset 子集、合成流量下，最大無損吞吐約為單執行緒 Snort 2.9.15.1 的 3 倍 [原文 p.1, p.15–16]；作者自己提醒這個增益只在「修改過的規則集」脈絡下成立 [原文 p.16]。

## C. 指定的 9 項

**1. Research Problem**：Snort、Suricata 這類 user-space IDS 在 DPI 下吞吐低；Snort 和 Suricata 雖有 eBPF 支援，但只解析到 L3，無法在 eBPF 內比對 payload [原文 p.1–2]。作者要做的是「在核心用 eBPF 做 payload 比對，預先丟掉不可能命中任何規則的封包」。問題設定是 IDS 自身吞吐，不是偵測力。

**2. Architecture**：被動 NIDS，監看的是交換器鏡像出來的副本，「丟棄」指丟掉副本、不影響原流量 [原文 p.2 Fig.1, p.6]。
```
NIC (RSS，8 個 RX queue) -> [XDP: 剝 VLAN -> 非 IP 丟 -> TCP/UDP 用 (src,dst) 兩層 map 找 AC 起始 state
                             -> 逐 byte 掃到 MAX_SCAN_LEN(1520) 或封包尾]
   無 port group / 無 fast pattern 命中 -> 丟
   有命中 -> perf event（第一個事件帶整個封包 + ac_state，之後同封包的事件只帶 ac_state）
user space: 單執行緒 control program 輪詢每核一個的 perf buffer
   -> 以 state 找 port group -> BFS 評估 rule tree -> 命中則套用規則動作，否則丟
```
無 Flow 層（沒有 flow table 或 conntrack）、無雲端 [原文 全文未出現]。

**3. Processing Location**：核心（XDP）做 port group 查找與 fast pattern AC 掃描；user space 做 rule tree 評估與告警 [原文 p.6–11]。

**4. Hardware**（全部 x86，無 ARM）[原文 p.12 Table 5, Fig.17]：

| | Packet generator | IDS host |
|---|---|---|
| 機型 | 未列 | Asus TS300-E10-PS4 |
| CPU | Core i7-9700 @3.0 GHz，表列 8 cores | Xeon E-2134 @3.5 GHz，表列 8 cores |
| RAM | DDR4-2666 32 GB | DDR4-2667 16 GB |
| NIC | Mellanox ConnectX-3 CX311A（表中橫跨兩欄） | 同左 |
| OS | Ubuntu 19.10 | Ubuntu 20.04 LTS（但 §7.1 說 kernel 為 Ubuntu 19.10 的 5.3，見 D5）|

兩條 10 Gbps 單向光纖：一條產生器到 IDS host 傳流量，另一條傳控制命令 [原文 p.12]。Xeon E-2134 我印象中是 4 核 8 緒，所以表列的「8 cores」可能是邏輯 CPU 數 [推測，未查證]。

**5. Dataset**：沒有公開資料集，全為合成流量 [原文 p.12–13]。
- 背景流量：iperf3 多個實例（TCP 組與 UDP 組，以 `-b` 控制比例）產生、tcpdump 擷取成 pcap，再用 tcpreplay-edit 以 `-M` 控制速率、`--mtu` 控制最大封包長度重播；封包長度分佈仿 CAIDA nyc-A 2019-01-17 trace（Fig.18 對 Fig.19）；TCP:UDP = 90:10，30 條並行 flow [原文 p.12–13]。
- 告警流量：pytbull（約 300 個測試、11 個模組）在兩台 Vagrant VM（client/server）上跑，於 server 端用 tcpdump 擷取成 pcap [原文 p.13 Fig.21]。
- 作者承認：想用 UGR'16、CTU-13 等較真實的資料，列為未來工作 [原文 p.16]。

**6. Baseline**：只有 Snort 2.9.15.1（原始碼自行編譯；當時 Snort 3 還是 beta）。同一台機器、同樣的修改過的規則集；Snort 只留 frag3 preprocessor，其餘全關 [原文 p.12, p.14]。**沒有和 Suricata 比**，雖然引言與相關研究都提到 Suricata [原文 p.1–2]。

**7. Metrics**：(i) system / user / softirq 的單核 CPU 百分比（8 核上限 800%）與封包遺失率，掃 0–10 Gbps；(ii) 無損最大吞吐（二分搜尋）[原文 p.14]。無延遲、無記憶體、無能耗、無傳輸量、無偵測力或告警一致性量測。

**8. Limitations（作者承認）**：eBPF 的 verifier 限制使它不能做複雜檢查，目前只支援 Snort 的常用功能；效能比較用的是「修改過的規則集」，所以增益要小心解讀 [原文 p.16]；control program 單執行緒是可能的瓶頸，8 核沒用滿（只有 3×）[原文 p.16]；流量是合成的，不夠真實 [原文 p.16]；加密 payload 偵測不到 [原文 p.6]；寫 eBPF 需要進階技巧 [原文 p.16]。

**9. Research Gap**
- 作者自述：多執行緒 control program；用更真實的資料集（UGR'16、CTU-13）；防火牆規則異常解決；延伸到 Customer Edge Switching 與惡意程式簽章偵測 [原文 p.16]。
- [推測]：沒有偵測一致性量測、沒有 inline、沒有 ARM 或低資源硬體、沒有規則熱更新、沒有 flow 狀態、沒有延遲。

## D5. 實驗可信度
- 流量為合成並重播（tcpreplay-edit），速率 0–10 Gbps；**每個點重複 10 次取平均，Fig.22–26 只畫平均值，沒有誤差線、沒有 CI、沒有變異量** [原文 p.14–15]。
- **沒有 ablation**：沒有拆開「port group 過濾」與「AC payload 掃描」各自的貢獻，也沒有「只有 user-space control program（無核心前置）」的對照。
- **全文沒有報告任何系統實際產生的告警數**，沒有和 Snort 的告警比對。ATTR 的定義是「會命中至少一條規則的流量比例」[原文 p.12]，但 pytbull 的流量是獨立產生的；規則集大小 NR 是取修改規則集的前 N 條，論文沒說明怎麼確認這些流量在不同 NR 下仍會命中規則 [論文未說明]。
- 「送到 user space 的封包比例」（預過濾後的縮減比）**沒有報告數字**，只寫「非常高比例被丟、只有一小部分送出」[原文 p.14–15]。
- 修改後規則集的總條數**未報告**。最大使用 12,000 條，接近 registered 未註解規則總數 12,630 [原文 p.5 Table 3, p.12, p.16]，而排除了不支援選項、需 preprocessor、無 content、短 fast pattern 的規則之後仍有 ≥12,000 條，代表可能取消註解了預設停用的規則 [推測]，論文未說明。
- 論文內部不一致：Table 5 的 IDS host 為 Ubuntu 20.04，§7.1 卻說用 Ubuntu 19.10 附的 Linux 5.3 kernel [原文 p.12, p.14]；「8 cores」疑為邏輯 CPU（見 C4）。
- 程式碼與資料：論文**沒有任何公開聲明或 URL**。sapo-boi 報告寫該論文把 Wang & Chang 的系統「自行重寫，因原碼不可得」為 PF IDS [sapo-boi 報告 C.6]，與此一致。
- 跨論文對照（只引 sapo-boi 報告 E 表，該報告引 Sapo-boi 原文 Table 4/6）：重寫版 PF IDS 在 8000 規則、1–10 Gbps 下損失約 1.84–2.25%（同表 Snort 3.74–91.39%、Suricata 0–6.22%）；它的 perf event 傳輸在 1 rule、100 萬封包下遺失 744.0 ± 276.5 個（最低一格）到 114803.2 ± 144410.1 個（8 Gbps），Sapo-boi 的 AF_XDP 傳輸最高 7214.5 ± 10207.1（7 Gbps）。這與 Wang & Chang 自承 perf event 可能溢出遺失 [原文 p.10] 相符，但那是別人重寫的版本、不同硬體（i7-12700、kernel 6.8、mlx4 加 memcpy 補丁）與不同指標（固定速率損失率），**不能驗證或推翻 3×**。

## D6. 移植到 Pi 4 的障礙
| 項目 | 內容 | 狀態 |
|---|---|---|
| kernel 版本 | 需要 bounded loop（Linux ≥ 5.3）[原文 p.7, p.14]；Pi OS trixie 的 kernel 更新，不是障礙 | 已讀原文；Pi 端 [推測] |
| BTF / CO-RE | 論文沒有提到使用 CO-RE、kfunc 或 BTF；程式只用 map 與 perf event [原文 p.7–10]，[推測] 沒有 BTF 不構成阻礙 | [推測] |
| 掛點 | XDP，attach 模式（native 或 generic）**論文未說明**。Mellanox mlx4 是否 native 我沒查證。我們的 Pi 4 兩個 port 都沒有 native XDP（SPEC_ADDENDUM 前提），只剩 generic（skb 配置之後）或 TCX。作者把 softirq 節省歸因於「XDP 在網路堆疊最早階段丟包」[原文 p.15]，generic XDP 與 TC 都在 skb 之後，這個優勢 [推測] 會大幅縮小 | 前提 + [推測] |
| 記憶體 | 每個 ac_state = int32 has_match + int32 next[256] = 1028 B [原文 p.7 Listing 2]；所有 state machine 放在同一個 `aho_nodes_global` 陣列 map [原文 p.8–9, Fig.11]；總 state 數與記憶體用量論文未報告。state 數的上限是所有 fast pattern 長度總和 [推測，trie 性質]，`any` 埠規則還會被複製進多個 port group [原文 p.10 Fig.15]。Pi 4 是否放得下 12,000 條規則：**未能確認** | 未驗證 |
| 每封包成本 | 每個 TCP/UDP 封包從 start_pos（TCP 為 54）逐 byte 掃到封包尾或位置 1520，每 byte 一次 map 查表 [原文 p.7–8]。Cortex-A72 上的每封包成本論文沒有、我們也沒測 | 未驗證 |
| 多核 | 作者靠 8 queue RSS 讓 eBPF 在多核跑，control program 單執行緒 [原文 p.11, p.16]。Pi 4 內建 GbE 與 USB 網卡有幾個 RX queue：未查證 | 未驗證 |
| inline | 整個設計是「丟副本」。inline 時安全封包必須轉送、可疑封包才進 IDS；perf event 複製封包的作法可以讓原封包照常轉送，但這樣 IDS 就不能擋 [推測]，論文沒有討論 | [推測] |
| 結論 | 沒有程式碼可用，需重寫；成本模型能否在 Pi 4 成立要實測 | [推測] |

## D9. 引用網路
OpenAlex cited-by 41 篇，我逐條看了前 40 筆的標題。多數是 eBPF + ML 偵測或綜述，沒有一篇直接在 ARM 上驗證這個設計。建議追加閱讀（≤5）：

| # | 書目 | 為什麼 | 存在確認 |
|---|---|---|---|
| 1 | Magnani, Doriguzzi-Corin, Siracusa, "Enhancing Network Intrusion Detection: An Online Methodology for Performance Analysis," IEEE NetSoft 2023, DOI 10.1109/NETSOFT57336.2023.10175465 | 引用 Wang & Chang（OpenAlex cited-by 列出）。摘要（二手，OpenAlex 摘要經 WebFetch 轉述）：以線上方式模擬 monitoring、detection、mitigation 全流程，重配置下吞吐可下降超過 50%，且好的偵測指標不代表攻擊真的被擋。補 Wang & Chang 沒量的「偵測力與實際阻擋」 | DOI 已確認（OpenAlex）；全文未讀 |
| 2 | Miano et al., "Securing Linux with a Faster and Scalable Iptables," SIGCOMM CCR 49(3):2–17 (2019), DOI 10.1145/3371927.3371929 | Wang & Chang 引用的 eBPF 防火牆 [原文 p.17]；我們在 nftables 與 TC eBPF 之間取捨時的 baseline 前例 | DOI 取自 Wang & Chang 參考文獻 [原文 p.17]，未另行查證 |
| 3 | Leblond & Manev, "Introduction to eBPF and XDP support in Suricata," Stamus Networks whitepaper, 2019-07-16 | Wang & Chang 自述 Suricata 的 eBPF 有「XDP-based flow bypassing」[原文 p.2]，那是我們「以 flow 為單位略過 IDS」最直接的既有前例；頁面說初始支援在 Suricata 4.1，5.0 大幅擴充 [二手：頁面，WebFetch 2026-10-27] | 頁面已確認存在；bypass 機制細節未讀 |
| 4 | Hu, Yu, Asghar, "Analysing performance issues of open-source intrusion detection systems in high-speed networks," J. Inf. Secur. Appl. 51:102426 (2020), DOI 10.1016/j.jisa.2019.102426 | Wang & Chang 只比單執行緒 Snort 2，沒比 Suricata；這篇討論 Snort/Suricata 多執行緒設定，可補 baseline 設定 | sapo-boi 報告 D9 寫「已確認 DOI（OpenAlex）」，我未另查 |
| 5 | Zhang, Gupta, Dezfouli, "Understanding Linux Kernel-Based Packet Switching on WiFi Access Points," IEEE TNSM 2025, DOI 10.1109/TNSM.2025.3603597 | OpenAlex cited-by 列出。摘要（二手）：常見統計在 AP 上會誤導，driver 速率實作影響封包切換與處理器使用率指標的準確度。對「低資源 Linux 轉送裝置的量測陷阱」有用，但和 IDS、eBPF 無關，**關聯度低** | DOI 已確認（OpenAlex）；全文未讀 |

已有報告、不需追加：Sapo-boi（JBCS 2026，DOI 10.5753/jbcs.2026.5551）是最直接的後續（AF_XDP 取代 perf event，並重寫 Wang & Chang 當 baseline）[sapo-boi 報告]。

## G. 框架專屬欄位

這不是框架論文，而是單一用途的 IDS 設計。以下照實寫「沒有」。

**G1 抽象。** 論文定義的只有「Snort 規則 -> eBPF map 內容 + user-space 資料結構」的轉換：port group、每組一個 AC DFA、每組一棵 rule tree [原文 p.8–11]。eBPF 程式本身是固定的 C 程式（用 clang 編譯後載入），規則只進入 map（`l1_map`、`l2_map`、`aho_nodes_global`），初始化順序是：解析規則、建 DFA、編譯並載入程式、填 map、建 perf buffer、最後才 attach [原文 p.8–9 Fig.12]。沒有 API、描述語言、設定格式或 pipeline 模型；使用者要改行為只能改 C 程式。結論稱 eBPF 機制有潛力當作實作高效能 IDS 的框架 [原文 p.16]，但論文本身沒有建構框架。

**G2 擴充與生命週期。** 沒有模組、插件或串接。§5.2 說明用 tail call 與 bpf-to-bpf call 克服指令數限制 [原文 p.6–7]，這是程式內部拆分，不是擴充點。**規則更新、程式替換、熱切換、重配置時間：論文完全沒有討論，也沒有量測。** 因為程式與規則分離，[推測] 原則上更新規則只需重寫 map 而不必重載程式，但所有 state machine 放在同一個大陣列、規則改動會重建 DFA，原地更新不是原子的 [推測]，需要雙緩衝或 map-in-map 之類的作法；論文沒做。

**G3 分層。** 核心：XDP 程式，狀態是唯讀的 AC DFA map；多核下 map 對 eBPF 端是唯讀所以沒有競爭，perf buffer 每核一個 [原文 p.11]。User space：單執行緒 control program 輪詢所有 perf buffer，保存「目前封包」的緩衝區，並用事件的 timestamp 判斷第一個事件是否遺失，遺失就丟棄同封包的後續事件以避免誤報 [原文 p.10]。層間通道：map（初始化時 user 到 kernel）、perf event（kernel 到 user，帶封包副本）。外部（controller、cloud）：沒有。**全系統沒有 flow 狀態**，每個封包獨立判斷。

**G4 外部依賴可選性。** 不適用（沒有外部依賴）。control program 跟不上時 perf event 會溢出遺失，論文只用 timestamp 避免誤報，不補救漏報 [原文 p.10]；control program 掛掉時行為未討論；被動模式下沒有 fail-open 或 fail-closed 問題。

**G5 價值怎麼證明。** 只有一個比較：最大無損吞吐 vs 單執行緒 Snort 2.9.15.1，ATTR、NR、MPL 兩兩掃描 [原文 p.15–16]。**沒有**：與手寫版本或其他框架的 overhead 比較、可擴充性示範、開發成本（LoC、時間）、可維護性、預過濾對偵測力的影響、對 Suricata 或 Snort 3 的比較。

**G6 效能量測方法**（可照做的部分，與論文未寫的部分）：

| 項目 | 內容 |
|---|---|
| 拓撲 | packet generator 與 IDS host 之間兩條 10 Gbps 單向光纖，一條傳流量、一條傳控制命令；IDS host 上的 Python 監控程式透過命令鏈路控制產生器的速率與流量屬性 [原文 p.12 Fig.17] |
| 流量 | 背景：iperf3（TCP、UDP 兩組，`-b` 控制比例）擷取成 pcap，tcpreplay-edit 重播（`-M` 速率、`--mtu` 最大封包長度）；封包長度分佈抄 CAIDA nyc-A 2019-01-17；90% TCP / 10% UDP；30 條並行 flow。告警：pytbull 全部測試，tcpdump 擷取成 pcap [原文 p.12–13] |
| 參數 | ATTR（告警流量比例）預設 1%，範圍 1–10%，間隔 1%；NR（規則數）預設 6000，範圍 0–12,000，間隔 1200；MPL（背景流量最大封包長度）預設 1500，範圍 100–1500，間隔 200；每組實驗只變動兩個參數 [原文 p.12, p.15 Table 6]；作為次要參數時只取最小、預設、最大三個值 [原文 p.15] |
| 最大無損吞吐 | 二分搜尋（Algorithm 5）：下界 0、上界 10,000 Mbps；每個速率跑 20 秒取遺失率；遺失率 ≤ 0 且區間 < 100 Mbps 時停止；重複 10 次取平均 [原文 p.13–14] |
| CPU / 遺失 | 掃 0–10 Gbps 的負載，量 system、user、softirq 三項單核 CPU 百分比（8 核上限 800%）與遺失率 [原文 p.14–15] |
| 暖機、CI、標準 | 沒有暖機（只說 20 秒「夠穩定」[原文 p.14]）、沒有 CI、沒有 RFC 2544 或 RFC 9411 |

論文**未寫**，重做時要自己決定：量測 CPU 的工具、遺失怎麼計數（如何區分網卡、backlog、perf buffer 的遺失）、XDP attach 模式、NIC queue 與 IRQ affinity、Snort 的 DAQ 模式與輸出 plugin、perf buffer 大小、pcap 長度與重播次數、告警流量與背景流量如何混合重播（Fig.21 只畫到擷取為止）。二分搜尋假設遺失率隨速率單調上升，Fig.24 中 Snort 的曲線有起伏，這個假設 [推測] 不一定成立。

**「3×」的條件：** 對象是單執行緒 Snort 2.9.15.1（user CPU 在 >2500 Mbps 時頂在 100% [原文 p.14]）；修改過的規則集；被動鏡像；合成流量；MPL = 1500。作者的算法是 6000/2000 [原文 p.15–16]。目視 Fig.26：NR ≥ 1200 時本系統約 5.5–6.2 Gbps、Snort 約 1.1–1.8 Gbps，比值約 3–5。Fig.25 目視：MPL 小時比值更大（MPL = 100 約 2.9 對 0.3 Gbps），因為單執行緒 Snort 受每秒封包數限制，所以 3× 是大封包下的偏保守值。NR = 0 的 9.8 Gbps 只代表 XDP 基本丟包能力：依 Fig.9，沒有 port group 時封包在 `get_start_state` 就被丟、不掃 payload [推測]；論文沒解釋為何 NR = 0 到 1200 從約 9.8 掉到約 6 Gbps。

**G7 安全模型。** 沒有威脅模型，只提到 verifier 檢查指令數、路徑與記憶體存取 [原文 p.6]。誰能載入程式、規則檔是否可信、control program 權限：論文未說明。作者發現短 fast pattern 的規則（如單一 `\0`）會讓幾乎所有封包命中、壓垮 FPM，做法只是排除這類規則 [原文 p.12]；對抗性流量沒測。

**G8 與我們設計對照。**
- **這篇已做過、我們不能宣稱是新的**：(1) 核心內以 AC 比對 payload 的 fast pattern、其餘規則交 user space 評估的兩段式 IDS，規則轉成 map [原文 p.1, p.6, p.8–11]；(2) 依 (協定, 埠對) 分組的 AC [原文 p.8, p.10]；(3) perf event 當 kernel 到 user 通道並自行偵測遺失 [原文 p.10]；(4) 以 Snort 規則做核心預過濾的 3× 級增益宣稱（但條件見 G6）。另外 Wang & Chang 自己寫 Suricata 的 eBPF 有「XDP-based flow bypassing」[原文 p.2]，所以「在核心以 flow 為單位略過 IDS」也有前例；我們的差異必須落在 ct mark 與 nftables/TC 的實作、無 native XDP 的 Pi 4、使用者定義的信任政策與雲端判定，而不是「flow bypass」本身 [推測]。
- **這篇做了、我們沒有，值得考慮 [推測]**：(1) 把規則集轉成 (埠對, fast pattern) 預過濾，nftables 可先用 concatenated set 做埠對那一半（sapo-boi 報告 Q7 也提到）；(2) 用 timestamp 偵測 kernel 到 user 事件序列遺失 [原文 p.10]，類似的遺失偵測可以用在我們任何 kernel 到 user 的事件通道；(3) 二分搜尋找最大無損吞吐 [原文 p.14]。
- **我們有、這篇沒有 [推測，不誇大]**：Pi 4 級 ARM 實測、inline 轉送、flow 層決策、原版 Suricata 與完整規則（逐項見下方「具體回答」）。另外它比較時連 Snort 的 stream preprocessor 也關掉 [原文 p.12]，所以它的「不漏檢」只在逐封包語意下成立。
- **取捨不同、我們要在論文說明理由**：(a) 保留 Suricata 完整語意，付出 NFQ 約 27–29 µs/封包（SPEC_ADDENDUM 第 2 節的實測）；Wang & Chang 靠重寫引擎省下這個成本，但規則覆蓋縮小；(b) 它的預過濾是「不會漏掉任何可能命中的封包」（逐封包、支援子集內），我們的 ct mark 信任 flow 是**有損的**：被標記信任的 flow 之後的封包即使含攻擊內容也不再送 IDS，所以不能借它的「無漏檢」論述，需自己量「有無 ct mark 的告警一致性」[推測]；(c) XDP drop 與 TC/generic XDP 在 skb 配置之後的差別（D6）。

**G8 對指定問題的具體回答。** 這篇削弱的是「核心內預過濾後交給 user space 規則分析」這個概念本身的新穎性；**沒有削弱**「Pi 級 ARM、inline、原版 Suricata 全規則、以 flow 為單位（ct mark）」的組合主張，四個要素它各缺一個：
- Pi 級 ARM：沒做（Xeon + ConnectX-3 10 GbE）。
- inline：沒做（鏡像副本；沒有轉送路徑，沒有延遲量測）。
- 原版 Suricata 全規則：沒做（自寫 control program；Snort 2.9 單執行緒當 baseline；規則只剩支援選項的子集，子集大小未報告）。
- 以 flow 為單位：沒做（逐封包；無 flow 狀態）。它做的部分是：預過濾後只送可疑封包給 user-space 規則評估，以及 3× 的吞吐增益宣稱。

**G9 對碩士論文的用途**（最多 5 條）
1. 引為「核心內預過濾 + user-space 規則評估」的最近前例，並如實描述它是被動、x86、規則子集、自寫引擎 [原文 p.1, p.6, p.12]。
2. 支持「逐封包 payload 預過濾對工作負載敏感」的論點：它必須排除短 fast pattern 的規則才能維持效能 [原文 p.12]，且預過濾放行率從未報告；我們的實驗應報告放行率（送進 IDS 的封包比例）。
3. 量測方法可借：二分搜尋找最大無損吞吐、20 秒探測、10 次重複、sys/user/softirq 三分法 [原文 p.13–15]；要補它缺的 CI、暖機、遺失計數定義、idle 基線。
4. 反面的 baseline 公平性教材：8 核 eBPF 對單執行緒 Snort 2.9，作者自己承認 [原文 p.16]；我們比較時要給 Suricata 設好 worker 數（Pi 4 有 4 核）並寫明設定。
5. 成本推算的出發點 [推測]：預過濾要划算，其每封包成本須低於「被擋下的封包比例 × 省下的 NFQ+Suricata 成本」；省下的成本用我們自己 Pi 4 實測（NFQ→Suricata 約 27–29 µs/封包）；eBPF 掃描在 Cortex-A72 上的成本論文沒有、需自己測。

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| Snort 最大無損吞吐 | 約 2000 Mbps | NR = 6000、ATTR = 1%、MPL = 1500；Snort 2.9.15.1；user CPU 在 >2500 Mbps 時頂在 100% | 原文 p.14 |
| 本系統最大無損吞吐 | 約 6000 Mbps（作者算式 6000/2000）；目視 5.5–6.2 Gbps | 同上 | 原文 p.15–16；Fig.24/26 目視 |
| NR = 0 | 本系統約 10 Gbps（近 line rate）；Snort 約 2500 Mbps | 預設 ATTR、MPL | 原文 p.15 |
| NR = 12000、ATTR = 10% | 本系統約 4.4–4.6 Gbps；Snort 約 1.1–1.3 Gbps | ATTR > 6% 時略降 | 原文 p.15（降幅敘述）；Fig.24/26 目視（數值）|
| softirq（單核 %） | 本系統約 400%，Snort 約 600% | 負載 9500 Mbps，8 核上限 800% | 原文 p.15 |
| user CPU | 本系統「很小」（無數值） | 預設參數 | 原文 p.14 |
| 遺失率（9500 Mbps） | 本系統約 17–18%，Snort 約 60% | 預設參數 | Fig.22/23 目視 |
| MAX_SCAN_LEN | 1520 | 以 MTU 1500 + 14 B Ethernet 為依據 | 原文 p.7 |
| ac_state 大小 | 1028 B/state | int32 + int32[256] | 原文 p.7 Listing 2 |
| 預設參數 | ATTR 1%、NR 6000、MPL 1500；TCP:UDP = 90:10；30 flows | | 原文 p.12 |
| 量測 | 20 秒/探測、二分搜尋停止於區間 <100 Mbps、10 次取平均 | | 原文 p.13–14 |
| 規則數 | registered：共 50,979、未註解 12,630；community 3,917；Emerging Threats 27,982 | 論文當時可得版本 | 原文 p.5 Table 3 |

## F. 自評

**未能確認**：XDP attach 模式（native 或 generic）；修改後規則集的總條數與是否取消註解了預設停用的規則；pcre、byte_test、file_data 在 user space 如何評估（p.5 說支援，§5.8 只描述 content pattern 的 rule tree）；port list、port range、否定埠（如 `$HTTP_PORTS`）如何處理；IPv6 與 IP fragment 的處理（start_pos 以 14+20+20 = 54 計 [原文 p.8 Fig.8]，[推測] 僅設想 IPv4 且無選項）；預過濾放行率；記憶體用量；Snort 的 DAQ 與輸出設定；原始碼是否存在。

**與既有報告的出入（只列，不改）：**
- `framework/papers/ebpf-security-slr.md` D9 #1 把這篇描述成「user space 做完整規則分析」。原文只支援規則子集：flow、flowbits、byte_jump、isdataat、urilen 不支援 [原文 p.5]，需 preprocessor 與無 content 的規則被排除 [原文 p.12]。「吞吐最高 3× Snort」也不精確：摘要寫「many tested conditions 下為 3 倍」[原文 p.1]，目視 Fig.25 在小封包下比值更大。
- `papers/sapo-boi.md` Q1 與 Q2 把「否定 content、否定埠」歸為沿用 Wang & Chang 的排除準則。Wang & Chang §6.2 列的四類排除是：不支援的選項、幾乎所有封包都命中的規則（短 fast pattern）、需 preprocessor 的規則、無 content 的規則 [原文 p.12]，**沒有提到否定 content 或否定埠**。該報告引的是 Sapo-boi 自己的 p.10，Sapo-boi 是否擴充了準則我無法判斷，但從 Wang & Chang 本文看不到這兩項。另外該報告 Q1(e) 擔心 `any` 埠規則的處理：Wang & Chang 的設計明確處理了（Fig.9 的 `l1_map[any]`、`l2_map[any]` 與 Fig.15 的 port group 聯集）[原文 p.8, p.10]，該擔憂是針對 Sapo-boi 本身，不是 Wang & Chang。

**我最不確定的三件事：**
1. 「預過濾不會造成漏檢」只是我從設計推得（每條規則至少有一個 content，沒有 fast pattern 就不可能命中；逐封包語意）。這成立的前提包括：只考慮支援的規則子集、封包長度 ≤ 1520、規則的 content 全部需出現且不處理跨封包。論文自己沒有任何實驗，我也沒有看原始碼，所以有沒有實際漏檢無法確認。
2. Fig.24–26 的數字與比值是目視估讀；3×/3–5× 的區間可能有 ±10% 以上的誤差。
3. 「8 cores」與 Xeon E-2134 規格的關係、Ubuntu 20.04 對 kernel 5.3 的矛盾，我只能指出不一致，不能判斷實際用的是哪個 kernel 與幾顆核心。
