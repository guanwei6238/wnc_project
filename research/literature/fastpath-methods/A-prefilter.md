# A 組：預篩式 fast path

日期 2026-11-02。唯讀研究；下載檔在 `research/literature/fastpath-methods/pdfs/<slug>/`（pigasus、split-detect、shunt-fpga、sapo-boi、hyperscan；`xdp-ids-prefilter` 是第三方原始碼，2026-11-03 已移到 repo 外的 `~/datasets/literature/xdp-ids-prefilter/`）。頁碼規則：Pigasus 用 USENIX 頁碼（1083–1100）；Split-Detect 用 SIGCOMM 頁碼（327–338）；Shunt FPGA 論文無頁碼，用 PDF 頁；Sapo-boi、Wang & Chang 用論文／PDF 頁碼；Hyperscan 用 NSDI 頁碼。「專案快照」指 `/home/sixsquare/datasets/rulesets/snapshot_2026-10-30_suricata-8.0.7/rules`。

## 0. 結論

1. **A1 比例**：文獻報的是「不必完整檢查的比例」，不是偵測損失，且依賴良性流量與規則集。Pigasus：Snort 3 的 fast pattern＋header 預篩讓約 89% 封包不進 full match；加掃全部字串後只剩 5% 封包（平均 1.1 條規則／封包）送 CPU（Snort Registered 約 10K 規則、Stratosphere CTU 流量）[原文 p.1091–1092]。CloudNet 2026（僅二手）：Suricata 8.0.0＋ET Open 子集，XDP 預篩移除 28.1–39.2% 封包 [二手 README]。Split-Detect：40 B 簽章切 4–10 片，3.4–10.9% 封包被分流（只模擬、沒裝 piece）[原文 Fig.7 p.337]。
2. **A1 偵測損失**：只有 CloudNet 2026 實測告警一致（3 條 trace、10 kpps、單次：248→252、362→362、0→0），但只涵蓋分析器篩過的 34,111 條規則，排除了其 2024-11-12 快照中 15.5%（6,263／40,374）的啟用規則（其中 4,097 條是無 content 或有狀態規則）[二手＋自算]。Pigasus 只靠「filter 無 false negative」的設計論證 [原文 p.1091 fn.7]；Sapo-boi、Wang & Chang 沒量偵測一致性。
3. **A2 不重組**：只有 Split-Detect 正面處理：簽章切 K 片，任一片命中或「小封包＋間距近／亂序」累積到 K−1 次就分流；代價是要求端點改 TCP（weak atomicity）、且只能偵測 Almost(S)（缺頭尾片）[原文 p.328, p.331–334]。Pigasus 選擇在 FPGA 內做重組 [p.1088–1089]。三篇 eBPF 工作（Sapo-boi、Wang & Chang、CloudNet）都逐封包掃，**文獻與 README 都沒有處理跨封包 pattern**。
4. **A3 命中後送什麼**：Split-Detect 先送「小封包／含片段封包」的副本，觸發後送「該封包起的整條剩餘 flow」，慢路徑自己重組 [p.333–334]；Pigasus 送重組後的封包＋規則 ID，FPGA 保留狀態 [p.1087, p.1093]；CloudNet 作者自己的筆記記錄了缺前後文的後果：request 被丟時 response 規則不觸發，建議「一旦放行就整條 flow 都放行」[二手 analyzer/PROBLEMATICHE_PATTERN.md]。
5. **A4 eBPF／ARM**：沒找到任何在 ARM／Pi 或 tc 上做 payload 多字串預篩的論文（搜尋紀錄見 §2）。x86 XDP 有三條做法：BPF hash map 放 AC（Sapo-boi）、array map AC＋bounded loop（Wang & Chang，MAX_SCAN_LEN=1520）、kernel module kfunc＋AC＋n-gram（CloudNet，1500 B payload 掃 4.7 µs、256 B 掃 1.0 µs，Xeon Skylake VM）[二手]。verifier 上限 1M 指令 [原始碼 include/linux/bpf.h:1928 @v6.12]。Pi 每封包成本：無文獻數字。
6. **A5 無法預篩的規則**：專案 ET Open 快照 52,798 條啟用規則，1,253 條（2.4%）沒有 content，其中 1,249 條是 flowbits／threshold 等有狀態規則 [自算]。但「有 content」不等於可在原始封包上預篩：92.3% 的 content 規則是 http／dns／tls 等 app-layer 規則，比對的是解析後 buffer [自算，粗略]。
7. **對我們（[推測]）**：在已信任 flow 上每封包做便宜的 payload 預篩，偵測是「含 fast pattern 就送」的確定性，不是抽樣比例；前提是先解決跨封包切割、Suricata 缺前後文、以及 GRO 合併封包超過掃描上限。

## 1. 逐篇

### Pigasus（OSDI 2020）
- **書目／取得**：Zhipeng Zhao, Hugo Sadok, Nirav Atre, James C. Hoe, Vyas Sekar, Justine Sherry (CMU)，"Achieving 100Gbps Intrusion Prevention on a Single Server"，OSDI '20, pp.1083–1100。PDF：https://www.usenix.org/system/files/osdi20-zhao_zhipeng.pdf。**全文**。與給定資訊無差異。
- **機制**：FPGA 先做 TCP 重組，再用 MSPM 對每個封包的每個位置比對 10K 規則的 header 與字串。Snort 3 的 MSPM 只查一條 fast pattern，Pigasus 查全部字串（shift-or＋每長度一張 1-bit hash table，再用 128-bit fingerprint 比對規則的其餘字串）[原文 p.1087, p.1091–1092]。MSPM 輸出空集合就直接放行，否則封包轉 CPU 做 full match（regex、剩餘字串）[p.1087]。
- **偵測面**：filter 設計上不產生 false negative [原文 p.1091 fn.7]；論文沒有與 Snort 告警比對的實驗（論文未說明）。規避：威脅模型把 reorder／duplicate 列為繞過手法，並說 Snort 3 的 timeout 與記憶體上限作法對 Pigasus 而言 "straightforward" 可複製 [p.1087]。OOO 記憶體超過 90% 時丟掉 linked list 最長的流 [p.1089]。亂序攻擊對 goodput 的影響：攻擊流量 10 Gbps、其餘 90% 有序時，總 goodput 81.0 Gbps [Table 1, p.1090]。
- **成本面**：Intel Stratix 10 MX FPGA＋i9-9960X 主機；Snort Registered ruleset snapshot29141（約 10K 條）、Stratosphere CTU-Mixed-Capture-1–5（before.infection）與 CTU-Normal-12／-7 [p.1093]。Snort 3 的 MSPM 對 89% 封包輸出空集合 [p.1091]；Pigasus 初版 11% 封包送 CPU、每封包 4.4 條規則，加非 fast pattern 比對後 5%、1.1 條 [p.1091–1092]。惡意封包比例 < 15% 時單核夠用，16 核可撐到 50% [p.1095]。MSPM 3.3 MB BRAM、Reassembler 2.61 MB BRAM（100K 流）[Table 2, p.1093]。Snort 3 的 MSPM 至多佔 CPU 時間 46%，MSPM 無限快也只加速 85% [p.1085]。
- **對我們的意涵（[推測]）**：整套靠 FPGA，不能搬。可借的是概念：多層 filter（便宜的先、貴的後）、快慢路徑分離（有序封包只查 next-seq 表，亂序進慢路徑）、以及 Amdahl 提醒——只加速 MPM 最多省 46% CPU，Suricata 的解析與重組成本不會因預篩消失。
- **限制**：作者：OOO 慢路徑可被攻擊拖慢（Table 1）；NFPSM 峰值只有 50 Gbps，過載時把封包直接轉 CPU [p.1092]。我觀察：只用 Snort ruleset，沒有告警一致性實驗；比例 89%／5% 依賴 CTU 流量大多良性。

### Split-Detect（SIGCOMM 2006）
- **書目／取得**：George Varghese, J. Andrew Fingerhut, Flavio Bonomi (Cisco／UCSD)，"Detecting Evasion Attacks at High Speeds without Reassembly"，SIGCOMM '06, Pisa, pp.327–338。PDF（UCSD cryptosec 站，作者機構頁）：https://cryptosec.sysnet.ucsd.edu/miscpapers/evasionSigcomm06.pdf。**全文**（12 頁）。與給定資訊無差異。
- **機制**：把簽章切成 K 片（每片 ≥ 4 bytes）。fast path 只對「曾送過小封包」的流存狀態（NES、OOO、length、count、LUT 共 48 bits＋流 ID 96 bits）[p.333]。小封包定義為 payload 在 [1, 2·PieceSize−2]。count 在兩種情況遞增：條件 1 兩個連續小封包的 seq 差 ≤ 簽章長度；條件 2 兩個連續小封包之間有亂序。流被分流的條件：封包含任一 piece，或 count = K−1 [p.332–333]。IP 分片與含分片的連線一律分流 [p.330]。
- **偵測面**：有證明（Theorem 1、2）：含簽章 S 的連線，在 critical packet 之前會被分流，collaborator 封包的副本已送慢路徑 [p.335]。三個前提：端點做 weak atomicity（遇到與已交付資料不一致的重疊就重設連線）、接受只偵測 Almost(S)（去掉頭尾片）、只處理精確字串或固定長度 regex [p.328, p.331]。作者提出的補救：把每個封包最前與最後 X bytes 都送慢路徑，平均封包 200 B、X=10 時多 10% 流量 [p.337]。慢路徑用單一版本重組，第一次看到不一致資料就丟後續封包，並尋找 Pieces 2..K−1 的連接 [p.334]。
- **成本面**：CAIDA OC-48 2002/2003、LBNL、UF、大型企業 trace（Fig.6）。**模擬時沒有裝任何 piece**，所以只反映「小封包／亂序」觸發的分流 [p.336]。40 B 簽章切 4–10 片：追蹤 3.69–6.76% 的流，分流 3.43–10.85% 封包／4.04–9.98% bytes [Fig.7, p.337]；他處（30 B 簽章 5 片）1.52–8.81% 封包 [Fig.9, p.338]。5% 的 100 萬流需 7.5 Mbits [p.336]。
- **對我們的意涵（[推測]）**：證明所需的 weak atomicity 無法在我們的 gateway 取得（端點不受控）。但「每流 48 bits 的小封包／亂序計數」是可在 tc eBPF map 實作的觸發條件，可用來決定何時撤銷信任。我們的場景不同：已信任 flow 可以把門檻設嚴（任何 seq 不等於 NES 就撤銷），代價是 Pigasus 量到的約 0.3% 亂序封包 [Pigasus p.1088]。這是我的設計推論，Split-Detect 沒討論。
- **限制**：作者：weak atomicity「seems fundamental」[p.328]；會引入新的 DoS（注入不一致資料造成重設）[p.331]。我觀察：trace 是 2002–2003 年的明文流量，現在多數是 TLS；沒有真實簽章與誤報量測。

### The Shunt（FPGA 2007）
- **書目／取得**：Nicholas Weaver, Vern Paxson, Jose M. Gonzalez (ICSI)，"The Shunt: An FPGA-Based Accelerator for Network Intrusion Prevention"，FPGA '07, Monterey, Feb 18–20, 2007。PDF：https://www.icir.org/vern/papers/shunt-fpga-2007.pdf（作者主頁，8 頁）。**全文**。與給定資訊無差異；它是 CCS'07 Shunting（已讀）的硬體實作配套，整體評估在 Gonzalez 2005 博士論文 [PDF p.1]。
- **機制**：只看 L3／L4 header 的表（IP 位址表、連線表、固定規則），三選一 forward／drop／divert，另有 sample（帶機率的複本）；沒命中預設 divert [PDF p.3]。IP 分片、IP options、TCP SYN／FIN／RST 固定 divert 到 host [PDF p.3]。連線表可帶一個「seq 小於 N 時用另一動作」的記錄，用來跳過串流中段 [PDF p.3, p.6]。
- **偵測面／成本面**：沒有 payload 比對，因此與 A1–A3 只有間接關係；沒量偵測損失。表是 host 管理的 cache，被逐出時安全（miss 就 divert）[PDF p.6]。硬體只到 480 Mbps（FIFO bug），直通封包多 5–6 µs [PDF p.7]。
- **對我們的意涵（[推測]）**：與我們現有的 ct mark 信任機制同構（命中表放行、miss 就檢查、SYN／FIN／RST 一律檢查），沒有新機制。有用的細節：「cache 被逐出是安全的」這個設計原則；兩者都沒有處理「放行後才出現攻擊」。
- **限制**：作者承認 Gbps 吞吐受 bug 限制 [PDF p.7]。論文引用的 Snort Offloader [17]（FPGA 上靜態規則的過濾前端）正是 payload 預篩，但本次未取得。

### Wang & Chang 2022（JNCA）
- **書目／取得**：Shie-Yuan Wang, Jen-Chieh Chang，"Design and implementation of an intrusion detection system by using Extended BPF in the Linux kernel"，J. Network and Computer Applications 198 (2022) 103283，DOI 10.1016/j.jnca.2021.103283。**全文**：專案內既有使用者取得的副本 `research/literature/pdfs/1-s2.0-S1084804521002769-main.pdf`（非本次下載）；既有筆記 `research/literature/framework/papers/wang-chang.md`。我重讀了 verifier、loop、規則排除、吞吐段落。
- **機制**：XDP 程式依 (src,dst) port 兩層 map 找到 AC 起始 state，逐 byte 掃 payload；沒命中任何 fast pattern 就丟（被動鏡像副本）；命中用 perf event 送 user space，第一個事件帶整個封包＋ac_state，之後同封包事件只帶 ac_state [原文 p.7]。
- **eBPF 限制與做法**：作者寫 verifier 限制是「所有路徑 < 100 萬指令、單一程式 < 4096 指令」，用 tail call 與 BPF-to-BPF call 繞過 [p.6]；Linux 5.3 起的 bounded loop 才讓逐 byte 迴圈可行，MAX_SCAN_LEN 寫死 1520 [p.7]。ac_state 每個 1028 B（int32 has_match＋next[256]）[既有筆記，原文 Listing 2]。
- **偵測面**：沒有告警一致性比對；沒報告預篩後送出的封包比例（只寫「很小一部分」）。規則集只留 Snort 支援的選項：排除不支援選項、幾乎所有封包都命中的短 fast pattern（例如單一 `\0`）、需要 preprocessor 的規則、沒有 content 的規則 [原文 p.12]。被排除的條數論文未說明。
- **成本面**：x86（Xeon E-2134、ConnectX-3 10G），修改過的 Snort registered 規則集最多 12,000 條；最大無損吞吐約為單執行緒 Snort 2.9.15.1 的 3 倍，且作者提醒要在「修改過規則集」脈絡下解讀 [原文 p.15–16]。每封包成本論文未說明。
- **對我們的意涵（[推測]）**：只有 XDP；bcmgenet 無 native XDP，tc 上的 skb 路徑（含 GRO 合併封包，超過 1520 B）此論文完全沒碰。作者自己指出 Suricata 不能在 eBPF 內做 payload 比對 [p.2]。
- **限制**：合成流量、單一 baseline（沒和 Suricata 比）、無誤差線（既有筆記 D5）。

### Sapo-boi（JBCS 2026）
- **書目／取得**：Machnicki et al. (Bluepex／UFPR)，"Sapo-boi: Bypassing Linux Kernel Network Stack in the Implementation of an XDP-based NIDS"，J. Braz. Comput. Soc. 32(1), 2026，DOI 10.5753/jbcs.2026.5551，CC-BY。PDF：https://journals-sol.sbc.org.br/index.php/jbcs/article/download/5551/3827/37006（已下載 pdfs/sapo-boi/）。**全文**；既有筆記 `research/literature/papers/sapo-boi.md` 逐項核對過，我另行核對 verifier 段（p.15）與 Table 4（p.12）。
- **機制**：XDP 的 Suspicion Module 依 (src port, dst port) 找該 port pair 的 AC 自動機（狀態轉移放在 BPF hash map，key=(state,byte)），每個 byte 查一次 map；沒有 fast pattern 就 `XDP_DROP`，命中經 AF_XDP 連同 metadata 送 user space [原文 p.6–8]。無 flow 層。
- **偵測面**：沒有偵測力量測。作者承認只做 pattern matching 子集，以避免超過 verifier 的「100 萬指令」並避免大量 tail call [原文 p.15]。作者指出 DoS 風險：知道規則集的攻擊者偽造近似命中的序列，讓 AC 狀態頻繁變動 [p.15]。跨封包／分片：論文未說明。
- **成本面**：x86（i7-12700、ConnectX-3 10G）；規則 1–16,000 條；AC 版損失率在 ≥ 2000 條時約恆定 2.2%（Snort 3 在 8000 條 2 Gbps 起超過 50%，Suricata 7.0.5 同條件 6.22%@10 Gbps）[Table 4, p.12]。每封包 µs 成本論文未說明。
- **對我們的意涵（[推測]）**：一次一個 byte 的 hash map 查表在 Cortex-A72 上會是主要成本；Table 4 同時顯示 Suricata 7.0.5 自己的 MPM 在 x86 已能撐住 16,000 條規則（9.61%@10 Gbps），預篩在 x86 的邊際利益有限，Pi 上則不同（Pi 的 NFQ＋Suricata 每封包約 40 µs 固定成本，見 SPEC）。
- **限制**：作者：流量為合成、無 CICIDS 類資料集 [p.15]。我觀察：核心被修改（mlx4 前加 memcpy）[既有筆記 Q3]。

### CloudNet 2026 "Exploiting Rule Skewness"（**僅二手**）
- **書目／取得**：M. Federico, A. Tulumello, G. Belocchi, G. Bianchi，"Exploiting Rule Skewness: An eBPF/XDP Prefilter for Signature-Based Intrusion Detection"，IEEE CloudNet 2026（出處與作者取自 repo README）。**論文 PDF 找不到**（arXiv API 搜標題關鍵字與作者 Belocchi 得 0 筆相關；網路搜尋無結果）。可讀到的是作者 GitHub repo https://github.com/kobero98/xdp-ids-prefilter（GPL-2.0，HEAD f18737f，2026-11-02 讀取）的 README、設計筆記（義大利文）與一個 XDP 程式原始碼；存在確認程度＝僅二手。已存 pdfs/xdp-ids-prefilter/。
- **機制**：離線分析器讀 pcap 與 Suricata 規則，為每條規則挑「在該 pcap 中最少出現的 content」，建成封鎖清單；XDP 對每個封包掃清單，**沒有命中就 `XDP_DROP`**，命中、SYN／FIN／RST、無 payload、或 {proto,port} 不在監控表則 `XDP_PASS` 給未修改的 Suricata 8.0.0（AF_PACKET）[二手 README；原始碼 kernel/ac/xdp_prog_ac.c]。引擎是 kernel module 暴露的 `bpf_xdp_ac_scan` kfunc：scalar Aho-Corasick（Hopcroft 最小化、16-bit state、pattern 截成前 12 bytes）加 n-gram bitmap 預篩 [二手 OTTIMIZZAZIONE_AC.md]。
- **偵測面**：10 kpps 單次 pass 告警 Suricata 單獨 vs. 加預篩：NF 248 vs 252、mixed 362 vs 362、good 0 vs 0；NF 多出的 4 條歸因於 Suricata 的 4 KiB HTTP body 檢查窗，窗放大到 8 KiB 後兩邊相同 [二手 README]。**限制**：Suricata 載入的是分析器篩過的規則（NF 34,111 條、good 36,100 條）[二手 rulesets/*_sids.txt 行數]，相對 40,374 條啟用規則；沒載入的 6,263 條中，4,097 條是無 content 或有狀態規則 [自算]。作者的筆記還記錄兩個缺前後文的案例：(1) request 被丟、response 命中 → 沒有 HTTP 上下文，`flow:established,to_client` 規則不觸發；(2) 純 ACK 因乙太網 padding 被誤掃而丟掉，打斷 Suricata 的 TCP 重組（修正後 mixed trace 不再少告警）[二手 PROBLEMATICHE_PATTERN.md、OTTIMIZZAZIONE_AC.md]。
- **成本面**：4-vCPU Xeon Skylake VM、mlx5、kernel 6.8.12、DPDK 重播。預篩移除 NF 39.2%、mixed 28.1%、good 34.7% 封包（mixed 約 50% bytes）；系統損失（rx_missed＋AF_PACKET drops，3 次平均）200 kpps：NF 24.0%→11.6%、mixed 25.1%→12.1%；400 kpps：NF 56.5%→47.7%、mixed 58.6%→33.9%、good 33.5%→10.8% [二手 README]。pattern 數／DFA state 數 18,757／55,568（NF），截 12 bytes 後表 28 MB；掃 1500 B payload 4.7 µs、256 B 1.0 µs [二手 results/README.md]。同一份筆記另寫 n-gram 預篩版 1500 B 為 2.66 µs（情境：mixed、2500 Mbps）[二手 OTTIMIZZAZIONE_AC.md]，兩處數字條件不同，我無法核對。
- **對我們的意涵（[推測]）**：這是最接近我們設計的一篇（Suricata 8＋XDP 預篩＋ET Open）。阻礙：(a) 用 XDP＋kernel module，Pi 的 bcmgenet 無 native XDP，tc 版要重做；(b) 作者說 BPF 程式與 module 因使用 GPL-only kfunc 必須 GPL [二手 README]，與專案可能閉源的限制衝突；(c) 表 28 MB、bitmap 約 2.5 MB，Cortex-A72 的 L2 只有 1 MB（我的背景知識，未查證），x86 數字不能外推。
- **限制**：論文 PDF 未讀；repo 沒有討論跨封包切割或規避（我 grep 設計筆記 segment／split／evasion 只有一處與重組變化有關）；分析器 README 描述的是較早的 Hyperscan 版，論文版 AC 版可能已改。

### Hyperscan（NSDI 2019，背景；只讀相關段）
- **書目／取得**：Xiang Wang et al. (Intel, KAIST)，"Hyperscan: A Fast Multi-pattern Regex Matcher for Modern CPUs"，NSDI '19。PDF：https://usenix.org/system/files/nsdi19-wang-xiang.pdf。**全文已下載，只精讀 prefilter、decomposition、streaming 相關段**。
- **內容**：Snort／Suricata 的做法是每條 regex 指定一條字串作 prefilter，字串命中才跑 regex [p.631 摘要段]。以 ET-Open 2.9.0 與 Talos 2.9.11.1 對真實流量，content 式 prefilter 觸發的 regex 次數比 Hyperscan 自動抽字串多 131–697 倍（因 content 常含單字元字串）[原文 Table 3、4, p.641]。IDS 的 regex 規則有 87%–94% 至少有一個可抽出的字串 [原文 p.634]。Streaming 模式「掃多個 block 而不保留舊資料，每流固定大小的 stream state」，因為 pattern 可能跨封包 [原文 p.643]。
- **對我們的意涵（[推測]）**：streaming 的 per-stream state 是不做重組也能跨封包比對的標準答案，但它假設封包依序到；亂序、重疊仍要走別的路。

### Košař ISCC 2023／Šišmiš & Kořenek PAM 2023（**僅摘要**）
- Košař, Šišmiš, Matoušek, Kořenek，"Accelerating IDS Using TLS Pre-Filter in FPGA"，28th IEEE ISCC, Tunis, 2023, pp.436–442, DOI 10.1109/ISCC58397.2023.10218049；VUT FIT 登錄頁無全文連結，只有 IEEE Xplore。摘要：硬體 TLS pre-filter 移除加密 TLS 流量，平均處理速度約兩倍，不限制 IDS 規則類型，Agilex FPGA 達 100／400 Gbps [摘要 https://www.fit.vut.cz/research/publication/c185159]。
- Šišmiš & Kořenek，"Analysis of TLS Prefiltering for IDS Acceleration"，PAM 2023, LNCS 13882, pp.85–109, DOI 10.1007/978-3-031-28486-1_5。摘要：比較現有 TLS bypass 方案，軟體版 TLS Prefilter 使 IDS 效能三倍，偵測結果誤報較低 [摘要 https://www.fit.vut.cz/research/publication/c185697/.en]。
- 兩篇都找不到合法全文，**沒有讀**。與 A 組的關聯是「預篩條件是 TLS 加密 payload」，不是 pattern 命中；與我們的 ct mark 信任機制較相關。

### Suricata 背景（文件與原始碼，非論文）
- fast pattern 選擇：先看 buffer 優先序，再取最長，再比 Pattern Strength（字元多樣性），最後左到右 [原始碼 doc/userguide/rules/fast-pattern-explained.rst @suricata-8.0.7；對應 docs.suricata.io/en/latest/rules/fast-pattern-explained.html]。一條規則只有一個 content 進 MPM [文件 https://docs.suricata.io/en/latest/rules/prefilter-keywords.html]。
- 沒有 MPM pattern 也沒有 prefilter engine 的規則被放進 "non-prefilter" 引擎，不經 prefilter 篩選就要評估 [原始碼 src/detect-engine-prefilter.c:888–897 @suricata-8.0.7]。
- MPM 同時對封包 payload 與重組後 stream 做 [原始碼 src/detect-engine-payload.c:74, 116 @suricata-8.0.7]。
- Hyperscan 只支援 Intel x86；ARM 用 Vectorscan 替代 [原始碼 doc/userguide/performance/hyperscan.rst:13 @suricata-8.0.7]。Vectorscan README：ARM NEON／ASIMD "100% functional" [二手 https://github.com/VectorCamp/vectorscan]。Pi 上的 Suricata 實際用 `hs` 還是 `ac` 我沒有查（需 `suricata --build-info`）。

## 2. 各問題的回答

### A1　預篩能讓多少比例不必完整檢查？偵測有沒有損失？

| 來源 | 比例 | 條件 |
|---|---|---|
| Pigasus | Snort 3 MSPM 後 89% 封包不進 full match；Pigasus 全字串預篩後 5% 封包、1.1 條規則／封包送 CPU [p.1091–1092] | Snort Registered ~10K 規則、Stratosphere CTU 良性為主的 trace、100 Gbps |
| Split-Detect | 分流 3.43–10.85% 封包（40 B 簽章 4–10 片）；1.52–8.81%（30 B／5 片，4 條 trace）[Fig.7、9] | 2002–2003 明文 trace，**未安裝 piece** |
| CloudNet 2026（二手） | 移除 28.1–39.2% 封包，mixed 約 50% bytes | ET Open 子集、Suricata 8.0.0、HTTP 為主的 3 條 trace |
| Sapo-boi | 惡意佔 5% 時約 95% 封包被丟 [既有筆記 sapo-boi.md D2；實際送 user space 的比例論文未直接報] | 合成流量，依規則偽造的惡意封包 |
| Hyperscan | 用 content 當 prefilter 的 regex 觸發次數是自動抽字串的 131–697 倍 | ET-Open 2.9.0／Talos 2.9.11.1、真實流量 |

- 偵測損失：CloudNet 有告警一致結果（見 §0 第 2 點與 §1），其餘沒有。預篩要「保守」，必須挑出每條規則「必要」的內容；CloudNet 選「最少出現的 content」，Wang & Chang 與 Sapo-boi 選規則的 fast pattern。**比例越高通常代表 pattern 越少見、規則集越窄**，所以表中的比例不能互相比較，也不能直接拿來預測 Pi 上的比例。
- 還有一個缺口：這些工作都假設「規則只在單一封包內命中」，跨封包切割的偵測損失沒有人量。

### A2　不做 TCP 重組，怎麼防拆 pattern、亂序、重疊？

| 做法 | 代價 | 出處 |
|---|---|---|
| Split-Detect：切片＋小封包／亂序計數＋分流；重疊靠端點 weak atomicity；IP 分片整條分流 | 端點要改；只偵測 Almost(S)；每流 48 bits；3–11% 封包分流 | [p.330–334] |
| Pigasus：在 FPGA 內重組，有序封包只查 next-seq 表，亂序進 linked list 慢路徑；記住前一封包最後幾個 byte 供跨封包比對 | 2.61 MB BRAM（100K 流）；亂序每流平均約 5 KB；記憶體 > 90% 時丟最長亂序流 | [p.1086, p.1088–1089, Table 2] |
| Hyperscan streaming：每流固定大小 state，不留舊資料 | 要依序到達；亂序／重疊另處理 | [p.643] |
| Shunt：IP 分片、IP options、SYN／FIN／RST 一律進 host | 只是不放行，沒有 payload 比對 | [PDF p.3] |
| Sapo-boi、Wang & Chang、CloudNet：逐封包掃 | 論文／README 均未說明跨封包 | [原文 p.15；README] |

- 對 CloudNet：pattern 截成前 12 bytes 比對 [二手]，若前 12 bytes 被切到兩個封包就兩邊都不命中。我沒有在論文看到處理方式 [推測，需讀論文確認]。
- **對我們的可行組合（[推測]）**：已信任 flow 上，tc eBPF 每流存「預期下一個 seq」（Split-Detect 的 NES）與最近幾個封包的小封包計數，seq 不等於預期、或出現連續小封包就撤銷信任並把後續封包交給 Suricata；跨封包 pattern 用「前一封包最後 N−1 bytes」或 AC state 帶到下一封包（Pigasus／Hyperscan 的做法）。這些都沒有人在 eBPF 實作過、沒有成本數字。
- 另一類規避不是切封包而是編碼：Suricata 比對的是正規化後 buffer（HTTP URI 解碼、gzip、chunked；DNS 標籤編碼），原始 payload 上的預篩看不到。CloudNet 的分析器用 sticky buffer 前綴（例如 `\r\nUser-Agent: `）補強，並列出 `file.data`、`tls.sni`、`dns.query` 等沒有前綴 [二手 analyzer/README.md §6、§8]。這是 [推測] 的規避路徑：例如 URI 內 percent-encoding 不會被原始位元組比對命中。

### A3　預篩命中後送什麼？缺前後文怎麼辦？

| 來源 | 送出內容 | 前後文處理 |
|---|---|---|
| Split-Detect | 平常：小封包與含 piece 封包的**副本**；觸發後：**該封包起整條剩餘 flow** | 慢路徑以 5-tuple 存副本，觸發時用副本＋後續封包自己重組 [p.333–334] |
| Pigasus | 該封包（已重組後的 in-order 封包）＋規則 ID；FPGA 保留封包副本，CPU 回 (packet ID, 判定) | FPGA 持有流狀態；CPU 的 Snort 3 被改成直接收 "reconstructed PDUs and rule IDs" [p.1087, p.1093] |
| Sapo-boi、Wang & Chang | **該封包**（＋metadata／ac_state）；user space 是自寫的評估程式，不是 Suricata | 單封包語意，沒有前後文問題 [原文 W&C p.7；既有筆記] |
| CloudNet | 命中的封包；SYN／FIN／RST、無 payload 封包一律放行 | 作者筆記：request 被丟時 response 規則失效；提出「一旦放行，同 flow 後續全放行」的 flow 表，未見已實作 [二手 PROBLEMATICHE_PATTERN.md] |

- Shunt 與 Split-Detect 的共通點：**進慢路徑的資料單位是 flow（連線），不是封包**。
- 我們的差別（[推測]）：Suricata 收到信任 flow 裡單獨一個封包時沒有 TCP 握手與 HTTP 上下文，依賴 `flow:established` 或 HTTP 解析的規則可能不觸發；CloudNet 的經驗與此一致，但我沒有在 Suricata 8 實測。可能的緩解：(a) 命中時改把該 flow 撤銷信任，從這一封包起整條交給 Suricata（Split-Detect 做法，但前面的封包 Suricata 沒看過，等於 midstream）；(b) 先讓 Suricata 看過該 flow 前 N 個封包（我們現有做法已是如此）。

### A4　eBPF／XDP／tc／ARM 上的 IDS 預篩或多字串比對

搜尋紀錄：用 eBPF XDP Aho-Corasick IDS prefilter、Raspberry Pi／ARM eBPF signature、Suricata XDP verifier loop、Vectorscan ARM、Pi 上 Suricata 效能等組合多次搜尋；讀到的論文：Sapo-boi（全文）、Wang & Chang（全文）、CloudNet'26（二手）。另查到但非 payload 比對：Pi 4 上的 eBPF DDoS rate-based 緩解（arXiv 2508.00851，只看摘要頁，無 pps／µs）[二手]；Pi 4B 上 XDP 抽 flow 特徵每封包 1.85 µs（avg）[既有筆記 framework/papers/ebpf-xdp-dl.md，原文 Table 3]，那是特徵抽取不是 payload 掃描。一份 KAIST／S2W 專利（US 12,244,565 B2）把 DFA 轉移表放進 eBPF map 做 payload 檢查，頁面沒有效能數字也沒有跨封包處理 [二手 patents.google.com]。**結論：沒有找到 ARM／Pi／tc 上的 payload 預篩論文或可信技術文章。**

| 項目 | Sapo-boi | Wang & Chang | CloudNet 2026 |
|---|---|---|---|
| 掛點 | XDP | XDP | XDP |
| 自動機位置 | BPF hash map，每 byte 一次查表 | array map，next[256]×int32 | kernel module kfunc，16-bit state |
| 能放多少 | 規則 1–16,000 條（port pair 分組）| 最多 12,000 條 | 18,757 pattern／55,568 states／28 MB |
| 每封包成本 | 論文未說明 | 論文未說明 | 1500 B 4.7 µs、256 B 1.0 µs（Xeon VM）[二手] |
| verifier 相關 | 100 萬指令，避免 tail call [p.15] | tail call、bounded loop（≥ 5.3）、MAX_SCAN_LEN 1520 [p.6–7] | 迴圈移出 BPF，改 kfunc（需 BTF／kfunc、kernel module）|
| 平台 | x86、kernel 6.8 | x86、kernel 5.3 | x86 VM、kernel 6.8.12 |

- verifier 數字：`BPF_COMPLEXITY_LIMIT_INSNS 1000000`、`MAX_TAIL_CALL_CNT 33`、`BPF_MAX_LOOPS 8M` [原始碼 include/linux/bpf.h:1928–1935 @v6.12]。
- Linux 內建的 `xt_string` 一個規則一個 pattern（textsearch 單 pattern 演算法），不是多字串比對 [原始碼 net/netfilter/xt_string.c:56 @v6.12]。
- **Pi 每封包成本完全沒有文獻數字**。x86 的數字不能線性外推：CloudNet 的 28 MB 表遠大於 A72 的 L2（1 MB，背景知識）；Sapo-boi 的 hash map 逐 byte 查表在 A72 上也沒有數據。Hyperscan 在 ARM 要靠 Vectorscan [原始碼 hyperscan.rst:13]，Pi 上 Suricata 的 MPM 實際用什麼未確認。
- **tc 特有的問題（[推測]）**：三篇都是 XDP 的 `xdp_buff`，tc 的 `skb` 若是 GRO 合併後的大封包，payload 可能超過 1520 B，而 W&C 的掃描上限寫死 1520；非線性 skb 的資料也不能直接 pointer 存取。專案已知 GRO 會影響 NFLOG 擷取（見 memory：GRO 讓 NFLOG 一定要 -k none），預篩若在 GRO 之前（網卡 XDP）或關掉 GRO 才與這些論文等價。

### A5　無法預篩的規則佔多少？

**在 /home/sixsquare/wnc_project 下找 `*.rules`：**
```
find /home/sixsquare/wnc_project -iname '*.rules'
→ ./docker/suricata-rules/suricata.rules（只有 1 條 icmp 測試規則）
grep -cE '^(alert|drop|reject|pass) ' docker/suricata-rules/suricata.rules   → 1
grep -c 'content:' docker/suricata-rules/suricata.rules                       → 0
```
wnc_project 底下沒有 ET Open。但 `tests/ids_rules/README.md` 說明規則快照放在 repo 外的 `/home/sixsquare/datasets/rulesets/`，我唯讀計數專案凍結的快照（ET Open，Suricata 8.0.7 版，下載 2026-10-30）：
```
cd /home/sixsquare/datasets/rulesets/snapshot_2026-10-30_suricata-8.0.7/rules
cat *.rules | grep -E '^(alert|drop|reject|pass)[[:space:]]' | wc -l                   → 52798（啟用）
cat *.rules | grep -E '^(alert|drop|reject|pass)[[:space:]]' | grep -c 'content:'      → 51545
cat *.rules | grep -E '^(alert|drop|reject|pass)[[:space:]]' | grep -vc 'content:'     → 1253
cat *.rules | grep -E '^(alert|drop|reject|pass)[[:space:]]' | grep -c 'fast_pattern'  → 31424
cat *.rules | grep -cE '^#[[:space:]]*(alert|drop|reject|pass)[[:space:]]'             → 19507（註解停用）
```
`python3 -I` 依 sid 去重後的明細（與 grep 數字一致）：

| 項目 | 條數 | 比例 |
|---|---|---|
| 啟用規則 | 52,798 | — |
| 有 content（含否定）| 51,545 | 97.6% |
| 沒有 content | 1,253 | 2.4% |
| 　其中含 flowbits／threshold／detection_filter／flowint／xbits | 1,249 | — |
| 　其中既無 content 也無上述狀態關鍵字 | 4 | — |
| 啟用規則中含上述有狀態關鍵字（不論有無 content）| 4,202 | 8.0% |
| header 為 tcp 的規則中沒有 content | 830／4,092 | 20.3% |
| header 為 ip 的規則中沒有 content | 416／442 | 94.1% |
| header 為 http／dns／tls 的規則中沒有 content | 0／22,358；1／13,932；0／9,792 | ≈ 0% |

同一個程式碼對 2026-10-11 的 Suricata 7.0.10 版快照得到 52,606 條啟用、1,246 條無 content（2.37%），與 `tests/ids_rules/README.md` 記的 52,606／19,494 一致。另對 CloudNet 作者 repo 內的 suricata-update 快照（2024-11-12，含 Suricata 內建規則）：54,070 條、啟用 40,374、有 content 38,824（96.2%）、無 content 1,550（3.8%，其中 1,046 條含 flowbits、1,261 條含 threshold、316 條是 decode／stream／app-layer-event 事件規則，類別有重疊）[自算，`~/datasets/literature/xdp-ids-prefilter/rulesets/`（筆電，repo 外）]。ET Open 壓縮包不含 Suricata 內建的事件規則（它們全無 content），所以專案快照的 2.4% 比含內建規則的 3.8% 低。

「有 content」不等於「可預篩」（以下為粗略的 regex 計數 [自算]，專案快照）：
- 92.3% 的 content 規則 header 協定是 http／dns／tls 等（比對解析後 buffer，不是原始 payload）。
- 最長 content ≥ 8 bytes 的佔 91.3%；≤ 3 bytes 的 474 條（0.92%），這些是容易讓預篩幾乎全命中的規則（W&C 為此排除短 fast pattern [p.12]）。
- 兩個以上 content 的佔 39.9%（20,541 條），其中只有 13,997 條明寫 fast_pattern。

文獻數字：
- Hyperscan：IDS 的 regex 規則有 87%–94% 至少有一個可抽出的字串，即 6%–13% 沒有 [原文 p.634]；這是 regex 規則，不是全部規則。
- Wang & Chang、CloudNet 分析器、Sapo-boi 都直接排除沒有 content 的規則，W&C 與 Sapo-boi 沒報被排除的條數；CloudNet 分析器的排除類別為有狀態（flowbits／threshold／detection_filter／flowint／limit）、協定不符、無 content、多 content 但無 fast_pattern 等 [二手 analyzer/README.md §4]。
- CloudNet 實驗載入的規則集：NF 34,111 條（無 content 159 條＝0.47%、含有狀態關鍵字 22 條）；未載入的 6,263 條中，無 content 1,391 條、有狀態 4,077 條、兩者聯集 4,097 條、其餘 2,166 條（http 為主）[自算，pdfs/xdp-ids-prefilter/rulesets/NF_sids.txt 對 2024-11-12 快照]。這表示該篇的「偵測一致」不涵蓋這些規則。
- Suricata 對這些規則的處理：non-prefilter 引擎，不經 MPM 篩選就評估 [原始碼 src/detect-engine-prefilter.c:888–897]。
- 我的觀察（[推測]）：無 content 規則大多是 flowbits 設定、threshold、tcp／ip header 條件，這些規則依賴的是狀態與計數，預篩（逐封包找字串）本來就不適用；它們在信任機制下是否要持續看到封包，需要另行決定。

## 3. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| Snort 3 MSPM 後不進 full match 的封包 | 89%（11% 進）| Registered ~10K 規則、CTU trace | Pigasus p.1091 |
| Pigasus 送 CPU 的封包／規則 | 5%、1.1 條／封包 | 同上，含非 fast pattern 比對 | Pigasus p.1091–1092 |
| 單核可撐的惡意封包比例 | < 15%（16 核至 50%）| 合成混合 | Pigasus p.1095 |
| MSPM 佔 Snort 3 CPU 時間 | 至多 46%；無限快僅加速 85% | 7 條 trace | Pigasus p.1085 |
| OOO 封包比例 | 0.3% | Stratosphere trace | Pigasus p.1088 |
| Split-Detect 分流封包 | 3.43–10.85%（40 B／4–10 片）；1.52–8.81%（30 B／5 片，4 條 trace）| 2002–2003 trace，未裝 piece | Split-Detect Fig.7 p.337、Fig.9 p.338 |
| Split-Detect 每流狀態 | 48 bits＋96 bits ID；追蹤 3.7–6.8% 的流 | 同上 | Split-Detect p.333, Fig.7 |
| CloudNet 預篩移除封包 | 39.2%／28.1%／34.7%（NF／mixed／good）| ET Open 子集、Suricata 8.0.0、10 kpps | [二手 README] |
| CloudNet 告警 | 248→252、362→362、0→0 | 同上；載入 34,111／36,100 條 | [二手 README、rulesets] |
| CloudNet 系統損失 | NF 24.0%→11.6%（200 kpps）；56.5%→47.7%（400 kpps）| 4-vCPU Xeon VM、mlx5 | [二手 README] |
| CloudNet AC 掃描 | 4.7 µs／1500 B、1.0 µs／256 B；2.66 µs 為另一條件 | Xeon Skylake VM | [二手 results/README.md、OTTIMIZZAZIONE_AC.md] |
| Hyperscan kfunc 掃描 | 平均 5.9 µs；clean 4.4 µs；命中 20 µs | 同上 | [二手 NOTES_it.md] |
| Sapo-boi 損失 | AC 版約 2.2%；Suricata 7.0.5 6.22%、Snort 91.39%（8000 條，10 Gbps）| i7-12700、ConnectX-3、5% 惡意 | Sapo-boi Table 4 p.12 |
| Wang & Chang 吞吐 | 約單執行緒 Snort 2.9.15.1 的 3 倍 | 修改過規則集、Xeon E-2134 | W&C p.15 |
| verifier 指令上限 | 1,000,000；tail call 33 | Linux v6.12 | include/linux/bpf.h:1928–1929 |
| 專案 ET Open 快照 | 啟用 52,798；無 content 1,253（2.4%）| 2026-10-30、Suricata 8.0.7 版 | 自算 |
| 有狀態關鍵字規則 | 4,202（8.0%）| 同上 | 自算 |
| IDS regex 規則含可抽字串 | 87%–94% | Snort／Suricata 規則集 | Hyperscan p.634 |

## 4. 建議追加閱讀

1. **CloudNet 2026 論文本身**（Federico et al.）：最接近我們的設計，要確認跨封包處理、等價性定義與 flow 表。存在確認：僅作者 repo README（二手），論文 PDF 找不到；可直接聯絡作者。
2. **XNET: Intelligent Dynamic Sampling for High-Speed Network Security Monitoring**（Papastergiou, Subramani, Reilly, Adjibi, Skafidas, Perdisci，arXiv 2608.18349，2026-08-18）：XDP 取樣放在 Suricata 前面，且報了「隨機封包取樣在 75% 縮減下只保留 1.2% 告警」[二手 linuxsecurity.com 報導]，與抽樣子題直接相關，應交給取樣組。存在確認：arXiv API 查得摘要（摘要稱偵測率 99.6%），全文未讀。
3. **Šišmiš & Kořenek, PAM 2023**：TLS 加密流量預篩並宣稱偵測不降。存在確認：VUT FIT 登錄頁摘要；全文需 Springer。
4. **Song, Sproull, Attig, Lockwood, "Snort Offloader"**（Shunt FPGA 論文參考文獻 [17]）：FPGA 上靜態規則的 payload 預篩前身。存在確認：僅 Shunt FPGA 論文的參考文獻列（二手），年份與出處未查。
5. **Dharmapurikar et al., "Deep Packet Inspection using Parallel Bloom Filters"**（IEEE Micro 2004）：CloudNet 設計筆記把它當作最近的前人工作。存在確認：僅 CloudNet repo 的 PREFILTER_LETTERATURA.md 提到（二手），我沒有查證。

## 5. 自評：最不確定的三件事

1. **CloudNet 2026 的論文沒讀**。它是最相關的一篇，我引用的全是作者 repo 的 README、設計筆記與一個 XDP 原始碼檔；分析器 README 描述的是較早的 Hyperscan 版，論文版（AC 版）的跨封包處理、等價性定義、10 kpps 單次結果的可信度都無法確認。兩份筆記對 1500 B 掃描成本寫了 4.7 µs 與 2.66 µs，條件不同，我沒有解開。
2. **A4 的否定結果**：我只用公開網路搜尋，沒有進 IEEE Xplore、ACM DL 全文庫。可能有付費牆後的 ARM／tc 論文漏掉。Pi 上每封包成本完全沒有數字；我對 A72 L2 容量與 GRO 影響的說法是背景知識與推論，沒有查證或實測。
3. **A5 的計數口徑**：`content:` grep 只是「規則文字含 content」，不等於 Suricata 實際選得出一個夠長、夠少見的 fast pattern；「app-layer 規則佔 92.3%」與「最長 content ≥ 8 bytes」用 regex 近似，可能有誤差。快照在 wnc_project 之外（用 manifest 找到的專案凍結快照），且 ET Open 不含 Suricata 內建規則。CloudNet「未載入的 6,263 條」是我用 sid 清單與快照比對推出的，載入規則的實際篩選邏輯未讀。
