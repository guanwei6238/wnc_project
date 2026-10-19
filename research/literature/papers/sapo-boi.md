# Sapo-boi（精讀版）

頁碼說明：`[原文 p.N]` 的 N 是 JBCS 版 PDF 的實際頁碼（共 17 頁；PDF 用 pdftotext 逐頁抽取）。`[原文 Table N]` 為論文表號。

## A. 書目與取得狀況
- 標題：Sapo-boi: Bypassing Linux Kernel Network Stack in the Implementation of an XDP-based NIDS
- 作者：Raphael Kaviak Machnicki, João Ribeiro Andreotti, Ulisses Penteado (Bluepex Cybersecurity), Jorge Pires Correia, Vinicius Fulber-Garcia, André Grégio（其餘為 UFPR）[原文 p.1]
- 出處：Journal of the Brazilian Computer Society 32(1), 2026；Received 2025-02-24、Accepted 2025-07-11、Published 2026-03-02 [原文 p.1]；CC-BY
- DOI：10.5753/jbcs.2026.5551（OpenAlex 可解析）
- URL：https://journals-sol.sbc.org.br/index.php/jbcs/article/view/5551 ；PDF https://journals-sol.sbc.org.br/index.php/jbcs/article/download/5551/3827
- 與給定資訊的差異：無實質差異。補充：本文是 SBSeg 2024 短版 "SAPO-BOI: Pulando a Pilha de Rede no Desenvolvimento de um NIDS Baseado em BPF/XDP"（pp.538-553，https://sol.sbc.org.br/index.php/sbseg/article/view/30048，頁面 HTTP 200，**內文未讀**）的擴充版。OpenAlex 顯示本文 cited-by = 0（2026-10-10 查）。
- 取得程度：**全文**（17 頁）

## B. 核心貢獻
1. 兩段式 NIDS：XDP 程式（Suspicion Module）在核心用 Aho-Corasick（AC）掃 payload 中各規則的 fast pattern，無命中即 `XDP_DROP`，命中才經 AF_XDP 連同 metadata 送 user space 的 Evaluation Module [原文 p.1, p.6-8]。
2. Evaluation Module 靠 metadata（port-pair index、規則 index、payload offset）直接索引規則，免搜尋 [原文 p.7, p.9]。
3. 與 Snort 3、Suricata 7、重新實作的 PF IDS（Wang & Chang 2022，perf event 傳輸）比較封包損失率、CPU、模組間通訊損失；規則 ≥2000 時 XDP 系統損失約 2.2% 且對規則數不敏感，Snort 在 8000 規則 2 Gbps 起損失逾 50% [原文 Table 4, Table 5, Table 6]。

## C. 指定的 9 項
1. **Research Problem**：Snort/Suricata 在高速率與大量規則下封包處理率低、丟包高 [原文 p.1]；問題設定是 NIDS 自身的封包分析率與 CPU，不是偵測力 [原文 p.1「not focused on directly increasing the number of detected malicious packets」]。
2. **Architecture**：被動式 NIDS（鏡像流量的副本，XDP_DROP 只丟副本，不影響原流量）[原文 p.6]。
   ```
   NIC(RSS 多 queue) -> [XDP: 解 Eth/VLAN/IP/TCP|UDP -> 查 (src,dst) port pair -> 該 pair 的 AC 自動機掃 payload]
       無 port pair 自動機 / 無 fast pattern -> XDP_DROP
       命中 -> 加 metadata -> bpf_redirect_map -> AF_XDP socket(每 queue 一個, UMEM 4096x4096B=16MB)
   user space: 每 socket 一個 thread, poll() -> 以 metadata 索引規則 -> 驗證其餘 content -> 寫 log
   ```
   無 Flow 層、無雲端 [原文 全文未出現]。
3. **Processing Location**：核心（XDP，driver 層）做 port pair + fast pattern；user space 做其餘 content 驗證與告警 [原文 p.6-10]。
4. **Hardware**：Ubuntu 24.04、kernel 6.8.0-31、x86_64、Mellanox ConnectX-3 (MT27500) 10 Gbps、i7-12700「16 cores」、16 GB、SFP+ 銅纜直連，兩台規格相同（一台送流量）[原文 Table 3, p.10]。無 ARM、無 IoT 設備。
5. **Dataset**：非公開資料集。用 Snort registered ruleset 的修改子集；惡意封包由 Scapy 程式依規則偽造，良性流量由 iperf3 產生，存成 pcap，以 tcpreplay 限速重播 [原文 p.10-11]。作者明說未用 CICIDS 等資料集 [原文 p.15]。
6. **Baseline**：Snort 3 (版本字串寫 "3.81.84")、Suricata 7.0.5、PF IDS（自行重寫，因原碼不可得）；同硬體同規則子集（Suricata 語法微調）[原文 p.10]。
7. **Metrics**：(i) 未分析封包率（損失率）；(ii) user/kernel/softirq CPU（pidstat、mpstat，總和範圍 0-1600%）；(iii) 模組間通訊遺失封包數 [原文 p.10, p.13]。
8. **Limitations（作者承認）**：見 Q5。
9. **Research Gap**：
   - 作者自述：加密流量無法 DPI；DoS 風險（偽造近似命中序列使 AC 狀態頻繁變動）；僅支援 pattern-matching 子集；未來可做 HIDS 化 [原文 p.15]。
   - [推測]：無偵測力量測、無 ARM/低階硬體、無 inline 轉送情境、無延遲、無雲端卸載。

## Q1. Suspicion Module 的篩選條件
- **條件（原文）**：只處理 Ethernet（可剝 VLAN）、IPv4/IPv6、TCP/UDP，其他協定一律 `XDP_DROP` [原文 p.6-7, Algorithm 1 p.8]。取 (src port, dst port)，到該協定的 map-of-maps 找對應自動機；找不到 = 直接丟 [原文 p.7, p.8]。找到後逐 byte 掃 payload，遇到任何 final state 即停止並 redirect，掃完無命中則丟 [原文 Algorithm 2, p.8]。因此篩選 = **埠對 + 協定 + payload 內是否含該 port-pair 組內任一規則的 fast pattern**。看的欄位只有 port、協定與 payload；IP 位址、TCP flags、flow state 在篩選中**論文未說明**（規則範例 Fig 2 的位址欄位是否被檢查亦未說明）。
- **如何從規則導出**：Evaluation Module 啟動時自動處理規則檔：依 (src,dst) 與 TCP/UDP 分組、每組的 fast pattern 合併成一個 AC 自動機，寫進 BPF hash map（key=(state, byte)，value=下一 state+final 旗標）[原文 p.7, p.9]。fast pattern = 規則的 `fast_pattern` content，缺省取最長 content [原文 p.2-3]。導出是**自動**的；但「哪些規則進子集」是依 Wang & Chang 的準則過濾：去掉無 content 的、需要 Snort plugin/module 的、含否定 content 或否定埠的規則 [原文 p.10]，過濾是否為腳本論文未說明。
- **偵測損失（漏檢）**：
  - [推測，邏輯推論] 在「子集規則、單一封包、與規則同埠對」的前提下，凡能觸發原規則的封包必含其 fast pattern，故被丟的封包不會觸發原規則——設計上等價。
  - [推測] 但等價前提很多，論文均未討論：(a) 跨 TCP segment / IP 分片 / 重組（規則的 content 被切開，Snort/Suricata 做 stream reassembly，XDP 逐封包掃）；(b) 非 TCP/UDP 與 ICMP 規則、無 content 規則整類被排除；(c) Algorithm 1 以固定 sizeof(IPv4_hdr) 推進，IP options、IPv6 extension header 的處理未說明；(d) 大小寫（nocase）、offset/depth/within/distance 等修飾字：論文未說明，從 §4.2.5 的流程看（只要 content 都「出現」即成立 [原文 p.10]）[推測] 並不檢查位置關係，可能產生與原規則語意不同的誤報；(e) 帶 wildcard 的埠：Fig 7 把 `any` 規則複製進每個組，但 Fig 8/Algorithm 1 只做一次 (src,dst) key 查找，**論文未說明**封包埠 (13,55) 如何落到 (13,any) 組；若無 fallback 查找則會漏掉 any-port 規則，需對照程式碼確認；(f) 作者第一次命中就 redirect，Evaluation Module 之後「再掃其他 fast pattern」[原文 p.10]，流程未交代是否保證不漏第二條規則。
  - 規則語意：論文定義「一個封包一條規則命中後即停止評估」[原文 p.2]；Snort/Suricata 是否同樣只報一條，論文未驗證。
- **有沒有量化漏檢**：**沒有**。沒有任何與 Snort/Suricata 的告警一致性比對、偵測率、false negative 實驗。唯一與告警有關的量化是 Table 6（redirect 之後在 user space 沒被收到的封包數，即模組通訊遺失）[原文 p.14]。§1 稱「achieved the highest alert-triggering rate」[原文 p.2]，但 §6 找不到對應的表或圖。

## Q2. Evaluation Module 的「常數時間找規則」
- **資料結構**：TCP、UDP 各一個 port-pair array；每個 pair 有 rules array；kernel 的 map-of-maps 的 index 與 user space port-pair array 的 index 一致 [原文 p.9, Fig 9]。Suspicion Module 送來 (port_pair_index, rule_index, payload offset) 三個 metadata（用 `bpf_xdp_adjust_meta`，並註冊 BTF）[原文 p.7, p.9]，故兩次陣列索引即定位規則，O(1)。
- **之後的驗證**：每條規則一個 AC 自動機（user space 的 graph，不是 BPF map），掃 payload；找到的 pattern 數等於規則登記的 content 數即告警；否則視為「falsely suspicious」，再重掃 payload 找其他 fast pattern 並逐一驗證 [原文 p.9-10]。所以「常數」只指第一次定位規則；驗證與重掃仍是 O(payload) 且非常數。
- **支援**：多個 content（AND）、fast_pattern、固定或 any 埠、TCP/UDP、sid [原文 p.2-3, p.7]。
- **不支援**：無 content 規則、需 plugin/module 的規則（未列舉，pcre、flowbits、http buffer、stateful 等關鍵字論文**均未提及**）、否定 content、否定埠 [原文 p.10]；作者自述只做 pattern matching，避免過大的 XDP 程式與 tail call [原文 p.15]。

## Q3. 與 Snort/Suricata 比較是否公平（我們自己實驗要避開的陷阱）
已寫明的條件：
- 同硬體、同規則子集（Suricata 做語法微調）；每次只跑一套 NIDS [原文 p.10]。
- Snort/Suricata：停用所有與 pattern detection 無關的 preprocessor/plugin/module；採各自「預設」擷取模式——Snort 用 libdaq（libpcap 抽象層），Suricata 用 AF_PACKET [原文 p.10]。
- 每格 10 次，報 mean ± SD（Table 4、Table 6；Table 5 只報 mean，作者說為了排版）[原文 p.12, p.13, p.14]。
- 丟包定義：「抵達主機但因速率、規則數、流量性質而未被 NIDS 擷取分析者」[原文 p.11]。Snort/Suricata 取其結束時統計的已分析封包數；XDP 系統在 XDP 程式中加 BPF map 計數 [原文 p.11]。

不公平或未交代之處：
1. **核心不同**：XDP 系統用的核心在 mlx4 driver 的 XDP 呼叫前加了一個 `memcpy` 來模擬「user-space 方案處理副本」；Snort/Suricata 用標準核心 [原文 p.10]。測的是被修改的核心。
2. **損失定義不同類**：XDP 系統的「已分析」= 到達 XDP 程式的封包（計數器在 Suspicion Module）；redirect 之後的通訊遺失另列 Table 6，不計入 Table 4 [原文 p.11, p.14]。Snort/Suricata 的損失是整條擷取+偵測路徑。Table 4 內的 Sapo-boi 數字因此不含 Evaluation Module 的容量。
3. **設定未列**：Snort 的 packet thread 數（`--max-packet-threads`）、Suricata 的 worker/threading、AF_PACKET cluster type、Suricata 與 Snort 的 pattern matcher（hyperscan 或 AC-bnfa/ac-ks）、是否 inline、`--daq-mode`、ring buffer 大小、NIC queue/中斷親和：**論文均未說明**。唯一線索：Snort「在單一核心擷取、跨核心處理」[原文 p.11]，且 Snort 在 1 rule 時已用 ~480-1000% CPU [原文 Table 5]，表示有多個 packet thread，數量未知。
4. **規則數**：只給載入數（1/200/500/2000/4000/7000/8000/13000/16000），子集本身的總條數、各規則的 fast pattern 長度與重複度**論文未說明**。XDP 系統各規則數下 ~2.2% 恆定損失，原因論文未解釋 [原文 Table 4]。
5. **流量對載入規則的耦合**：1 rule 情境之所以 XDP 系統 0% 損失、0% user/kernel CPU，是因為該規則的 port pair 在流量中不出現 [原文 p.12, p.13]；Fig 11 全良性流量下 XDP 損失 0% 也是 port pair 都不命中 [原文 p.11]。這說明結果取決於良性流量的埠是否落在規則埠對內。論文未說明良性（iperf3）流量的埠，也未測「大量良性流量落在 HTTP 等熱門埠」的情境，那正是 AC 自動機最大、掃 payload 最多的情境 [推測]。
6. **同條件的數字不一致**：13000 規則、10 Gbps、高 flow：Fig 11 全良性流量下 Suricata 14.68%（p.12 內文），Table 4（含 5% 惡意）為 7.88% ± 2.52；Snort 8 Gbps 全良性 82.97%（p.12），Table 4 為 91.36% [原文 p.12]。論文未解釋為何流量組成不同造成這樣的差距，顯示變異來源（流量內容、flow 數）未被控制。
7. **變異量**：有 10 次的 SD，但無 CI、無顯著性檢定；多格 SD ≥ mean（如 Suricata 13000 規則 2 Gbps 0,002% ± 0,006；Table 6 PF IDS 1 Gbps 7218.3 ± 21148.45）[原文 Table 4, Table 6]，分佈偏斜。
8. **傳送端未驗證**：tcpreplay 是否真能以設定頻寬送出 1000 B 封包（10 Gbps 約 1.2 Mpps），實際送出速率論文未說明 [推測，需確認]。
9. **CPU 度量**：user/kernel 來自 pidstat（行程）、softirq 來自 mpstat（全系統），單位為各核心百分比總和；未除以處理的封包數 [原文 p.13]。

## Q4. 「Snort 8000 規則，2 Gbps 超過 50%、8 Gbps 超過 90%」
- 條件：Snort 3（版本字串 3.81.84）、libdaq、其餘 preprocessor 關閉；規則子集載入 8000 條；高 flow 流量（Fig 10/11 的高 flow 為 500 flows；Table 4 僅寫 high-flow）；3,000,000 封包、payload 1000 B、5% 惡意、90% TCP/10% UDP；10 次平均 ± SD；i7-12700 + ConnectX-3 10G [原文 p.12, Table 3]。
- 原文數字（Table 4，8000 規則，Snort）：1 Gbps 3,74% ± 0,009；2 Gbps 53,55% ± 0,01；4 Gbps 78,70% ± 0,005；8 Gbps 90,81% ± 0,02；9 Gbps 90,02% ± 0,05；10 Gbps 91,39% ± 0,04 [原文 p.12, Table 4]。同規則數 Suricata：0 / 0 / 0,49 / 4.17 / 5,24 / 6,22 %；Sapo-boi 約 1,84-2,20%；PF IDS 約 1,84-2,25% [原文 Table 4]。
- 補充：200 規則 2 Gbps Snort 2,31%，500 規則 26,71%（表外）[原文 p.12]。內文稱 Snort 在 8000 規則「1 Gbps 失去 5%」，表中為 3,74%，兩者略有出入 [原文 p.13]。

## Q5. 限制
作者承認（§7, p.15）：
1. XDP 受 verifier 限制（最多 100 萬指令），故只做 pattern matching；只比 signature-based NIDS，只用 Sapo-boi 支援的規則子集，Sapo-boi/PF IDS 只能執行成熟方案的子集功能。
2. 沒用 CICIDS 等貼近真實的資料集，偏好可控的流量。
3. 可能遭 DoS：攻擊者知道規則集後偽造近似命中的封包，使 AC 狀態頻繁變動。
4. 加密流量無法 DPI（NIDS 通病），HIDS 化為未來工作。
5. （§6.3）環境不支援 XDP ZERO_COPY，每封包多一次 DMA→UMEM 拷貝；Sapo-boi 仍有模組間封包遺失（Table 6，如 7 Gbps 7214.5 ± 10207.1）[原文 p.14]。

我觀察到而作者沒承認：
1. 沒有偵測力量測與告警一致性比對；§1 的「highest alert-triggering rate」在 §6 無對應數據（見 Q1）。
2. 封包逐一處理，無 TCP 重組/分片處理說明，與 Snort/Suricata 的語意差距未量化（Q1 [推測]）。
3. 評估是被動鏡像場景，從不量測 inline 轉送的吞吐與延遲，也不量測告警延遲 [原文 p.6 Fig 6 說明；§6 無延遲數據]。
4. 良性流量埠與規則埠對的關係未交代（Q3.5），最壞情況（熱門埠大量良性流量）沒測。
5. 所有結果單一 x86 平台；「16 cores」與 i7-12700 的核心規格（[推測] 12 核/20 緒）不符，可能指邏輯 CPU 數，未說明。
6. 損失率 ~2.2% 恆定不隨速率變，原因未解釋，卻被用作 Sapo-boi 的主要數字。
7. Snort/Suricata 設定不完整（Q3.3），且 Snort 版本字串疑為筆誤。

## Q6. 流量與偵測率
- 惡意封包：Scapy 程式「分析規則並偽造惡意封包」，良性：iperf3，存為 pcap，tcpreplay 重播並限速 [原文 p.10-11]。含 payload（1000 B）。
- Table 4/5：3M 封包、1000 B payload、5% 惡意、90/10 TCP/UDP、高 flow [原文 p.12]。Fig 10/11：20 flows 對 500 flows，Fig 11 為 13000 規則、全良性 [原文 p.11]。§6.3：100 萬封包、1 rule、每包皆送 user space [原文 p.14]。
- 偵測率：**未量測**（無與 ground truth 或與 Snort/Suricata 告警的比對）。因惡意封包依規則偽造，此流量不能代表真實攻擊或良性流量的分佈 [推測]。

## Q7. [推測] 若前段換成 nftables 預過濾
可借用：
- 規則依 (proto, src port, dst port) 分組，沒有任何規則的埠對直接不送分析；對應 nftables 的 set/map（concatenation：`ip protocol . th sport . th dport`）。論文 1 rule 的結果（Sapo-boi user/kernel CPU = 0，softirq 僅 2-29%）表示僅埠對就能擋掉大部分流量 [原文 Table 5]。
- 以 metadata 直接索引規則的設計；NFQUEUE 無 per-packet metadata 通道，可能需用 `meta mark`/ct mark 傳 pair index [推測]。
- 規則子集過濾準則、損失率/CPU 分解（user/kernel/softirq）、10 次重複與 SD 的做法。
- 「fast pattern 先篩、全 content 後驗」的二段驗證邏輯，可放在 user space 的 NFQUEUE 消費端。

依賴 XDP 的特性（不能直接借用）：
- 在 driver 層、skb 配置之前丟包：nftables 在 skb 之後，softirq 與 skb 成本仍在，論文的 softirq 優勢（Table 5，8000 規則的 softirq：Sapo-boi 43-240 對 Snort 177-584）有一部分來自此 [推測]。
- 在核心內做 payload 子字串掃描：nftables 只能比對固定偏移的位元組（payload expression）[推測，依我對 nftables 的了解，未在論文查證]，無 AC 等價物。
- RSS 多 queue + 每 queue 一個 AF_XDP socket：Pi 3B+ 內建 NIC 為單 queue USB 網卡 [推測]。
- 副本語意：論文是鏡像副本被丟棄；inline 閘道的「安全封包」需轉送而非丟棄 [原文 p.6]，成本模型不同。

## Q8. 程式碼
**公開**：https://github.com/rkmach/SAPO-BOI（論文聲明「source code and information to conduct experiments」[原文 p.16]）。我看到的頁面狀況（未執行、未下載）：README 為葡萄牙文，含 `ids/`, `rules/`, `testenv/`, `send_packet.py`；未見 pcap 與實驗腳本；未見授權檔；31 commits，1 star [二手：WebFetch 摘要]。XDP attach 模式（native/skb）README 未明說。PF IDS 重寫版與 Snort/Suricata 設定檔是否在內，未能確認。

## D. 補充欄位
**D1**
- C1 封包處理 ○（XDP 前篩 + AF_XDP）；C2 Flow 收集 ×（以單封包 payload 掃描，無 flow）；C3 雲端卸載 ×（只有核心→user space 二層，無雲端）；C4 降成本 △（量測本地 CPU，無傳輸成本）。
- K1：量了 IDS 的分析率，沒量轉送吞吐/延遲；K2：沒量偵測力；K3：沒量延遲。

**D2**：送到 user space 的是完整原封包 + 3 項 metadata；決策者是 XDP 程式，依據是 port pair 命中且 payload 含 fast pattern [原文 p.7-8]。縮減比：惡意佔 5% 時約 95% 封包被丟 [原文 p.13]，但被送往 user space 的實際比例未直接報；偵測力損失未量測。

**D3**：地端 CPU 有量（Table 5）；RAM：只說明 UMEM 16 MB [原文 p.9]，無整體記憶體量測；能耗、傳輸頻寬、雲端：無。time-to-detection：無。

**D4**：規則式（簽章）；不需解密但無法處理加密 [原文 p.15]。成本模型（early drop + 少量送 user space 重驗）本質上就是規則式 IDS，可套到 Suricata/Snort；但其效益依賴「大多數封包不落入規則埠對或不含 fast pattern」[推測]。

**D5**：重播流量（合成），速率 1-10 Gbps，每組 10 次，有 SD，無 CI，無 ablation（例如沒拆開「只做埠過濾」與「埠過濾 + AC」的貢獻），程式碼公開（見 Q8）。

**D6**：依賴 kernel 6.8、mlx4 網卡驅動（含自行改過的 memcpy 補丁）、多 queue RSS、libbpf/libxdp [原文 p.10, p.7]。能否在 Pi 3B+ 跑：**未驗證**。[已查] 我取得 Linux mainline master 的 `drivers/net/usb/lan78xx.c`、`smsc95xx.c`、`usbnet.c`，三者 grep `xdp|ndo_bpf` 皆為 0 筆（2026-10-10 抓取）。Pi 3B+ 的 LAN7515 走 lan78xx（USB），所以 [推測] 內建 NIC 僅能用 generic（skb）XDP 與 AF_XDP copy 模式；generic XDP 在 skb 配置之後執行，「driver 層早丟」的優勢大幅減少；Pi vendor kernel 是否另有補丁未查。另外 Pi 內建 NIC 是單 queue，RSS 平行化無法使用。

**D7**
- Edge–Cloud IDS 分工：無關（無雲端）；僅提供「本地二層過濾」的類比。
- Flow Feature Compression：無關。
- Dynamic Flow Monitoring：無關。
- XDP-eBPF 真正省多少：支持（x86 + 10G + 修改核心，Snort 8000 規則 10 Gbps：user 1019 / kernel 581 / softirq 584 對 Sapo-boi 8 / 46 / 240）[原文 Table 5]，但條件偏有利（Q3），且 1 rule 時的 0 CPU 說明大部分節省來自埠對提早丟棄。
- Cloud Data Offloading 成本-時效：無關。
- 不同硬體限制：無證據（僅一種 x86 平台；作者指出 ZERO_COPY 不可用 [原文 p.14]）。

**D8 可借用**：port-pair 分組與 fast pattern 二段驗證 [原文 p.7-10]；損失/CPU/通訊遺失三類指標與 10 次重複 [原文 p.10-14]；規則子集過濾準則 [原文 p.10]。
**可改進（全為 [推測]）**
1. 拆開「埠對過濾」與「payload 掃描」的貢獻（基於 D5 無 ablation）。
2. 補偵測一致性實驗：與 Snort/Suricata 告警逐條比對（基於 Q1 無漏檢量化）。
3. 在 Pi 3B+（generic XDP/nftables）重做相同流量與指標（基於 D6 缺 ARM 資料）。
4. 報告 inline 情境的轉送吞吐與延遲（基於 K1/K3 未量測）。
5. 把流量組成（良性埠是否落入規則埠對）列為實驗變數（基於 Q3.5）。

**D9 建議追加閱讀**
1. Wang & Chang (2022), Design and implementation of an IDS by using extended BPF in the Linux kernel, JNCA 198:103283，DOI 10.1016/j.jnca.2021.103283：直接前身（PF IDS）；已確認 DOI（OpenAlex，cited 41）。
2. Machnicki et al. SBSeg 2024 短版（https://sol.sbc.org.br/index.php/sbseg/article/view/30048）：同系列早期版，實驗細節可能不同；已確認頁面存在，未讀內文。
3. Hu, Yu, Asghar (2020), Analysing performance issues of open-source IDS in high-speed networks, JISA 51:102426，DOI 10.1016/j.jisa.2019.102426：Snort 3 / Suricata 10-100 Gbps 基準設定參考；已確認 DOI（OpenAlex）。
4. Waleed, Jamali, Masood (2022), Which open-source IDS? Snort, Suricata or Zeek, Computer Networks 213:109116，DOI 10.1016/j.comnet.2022.109116：Snort/Suricata 比較方法學參考；已確認 DOI（OpenAlex）。
5. Shuai & Li (2021), Performance optimization of Snort based on DPDK and Hyperscan, Procedia CS 183:837-843，DOI 10.1016/j.procs.2021.03.007：本論文引用的 DPDK + hyperscan 對照；已確認 DOI（OpenAlex）。

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| Snort 損失率 | 3,74 / 53,55 / 78,70 / 90,81 / 90,02 / 91,39 % (1/2/4/8/9/10 Gbps) | 8000 規則，5% 惡意，3M 封包，10 次平均 | 原文 Table 4 (p.12) |
| Suricata 損失率 | 0 / 0 / 0,49 / 4.17 / 5,24 / 6,22 % | 同上 | 原文 Table 4 |
| Sapo-boi 損失率 | 1,84% (1 Gbps)；2,19-2,20% (2-10 Gbps) | 8000 規則 | 原文 Table 4 |
| PF IDS 損失率 | 1,84-2,25% | 8000 規則 | 原文 Table 4 |
| 16000 規則 10 Gbps | Sapo-boi 2,23 / Suricata 9,61 / Snort 91,70 % | 同上 | 原文 Table 4, Fig 12 |
| 1 rule、10 Gbps | Sapo-boi 0 / PF IDS 0 / Snort 0,2 / Suricata 2,41 % | 規則不命中任何 port pair | 原文 Table 4, p.12 |
| 全良性、13000 規則、10 Gbps、500 flows | Suricata 14,68% | Fig 11 | 原文 p.12 |
| 低 flow（20）10 Gbps | Suricata 89,61%；Snort 85,15% | 13000 規則，全良性 | 原文 p.12 |
| CPU（user-kernel**softirq，%） | 8000 規則 10 Gbps：Sapo-boi 8-46**240；PF IDS 16-20**160；Snort 1019-581**584；Suricata 1019-385**396 | 16 核，單位 0-1600% | 原文 Table 5 (p.13) |
| CPU 1 rule、10 Gbps | Sapo-boi 0-0**29；Snort 572-1000**971；Suricata 421-316**424 | | 原文 Table 5 |
| 模組通訊遺失（封包數） | Sapo-boi 0 ± 0 (1 Gbps) 至 7214.5 ± 10207.1 (7 Gbps)；PF IDS 744.0 ± 276.5 至 114803.2 ± 144410.1 (8 Gbps) | 1 rule、100 萬封包、10 次 | 原文 Table 6 (p.14) |
| UMEM | 4096 frames x 4096 B = 16 MB | | 原文 p.9 |
| XDP 處理能力引用 | 24 Mpps（6 核） | 引自 Høiland-Jørgensen 2018，非本文實測 | 原文 p.11-12 |

## F. 自評
未能確認：Snort/Suricata 執行緒與 pattern matcher 設定、規則子集總數、良性流量埠、XDP attach 模式與 GitHub 內容細節（只看到 WebFetch 摘要）、SBSeg 短版內文。
最不確定的三件事：
1. 「any 埠規則如何在單一 key 查找中被匹配」：我只依 Fig 7/8/Algorithm 1 判斷論文未說明，需讀原始碼才能確認是否有漏檢。
2. 篩選等價性的結論（Q1 [推測]）是我的邏輯推論，論文沒有實驗佐證。
3. Pi 3B+ XDP 支援的結論只基於 mainline 原始碼 grep，未查 Raspberry Pi vendor kernel。
