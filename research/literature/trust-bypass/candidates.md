# 信任式 Fast Path（Trust-based Bypass）開放搜尋候選論文清單

搜尋日期：2026-10-16。範圍：2015–2026 年。另開「範圍外」一節放 3 篇早於 2015 但與本子題直接相關的論文（不計入主清單篇數）。
不重複精讀清單：FlowLens、HorusEye、Edge Multi-agent IDS、Host-Aggregation IDS、eBPF/XDP-DL、Kitsune、Galette、Sapo-boi、Simioni、Alikhanov（見 `../SYNTHESIS.md`、`../candidates.md`）。

子題問題（取自 `SPEC_ADDENDUM.md`）：session 開頭經雲端判定安全 -> gateway 下規則走 fast path、不再上雲 -> 仍抽樣送分析，異常則 ban 或轉回 slow path。
角度：a 信任／白名單式 fast path；b 只看開頭、之後降低檢測的成本效益，或 adaptive per-flow inspection depth；c 放行後持續監控（抽樣、trust decay、re-verification）；d 針對這類機制的規避；e 以上傳 bytes／頻寬為指標的卸載策略。

證據標記沿用 `SUBAGENT_SPEC.md` 第 4 節：`[原文]` 在全文看到、`[摘要]` 只在摘要或出版社／機構庫頁面看到、`[二手]` 別人的描述、`[推測]` 我的判斷、`未能確認`。
全文以 pdftotext 抽取，沒有可靠頁碼，所以 `[原文]` 後面寫章節、圖表編號或「內文」。下載的 PDF 放在 `pdfs/search/`（檔名見各篇「檔案」欄）。
所有條目都是我實際打開出版社頁面、arXiv、機構庫或作者 PDF 後寫的；打不開的部分我明說，沒有用盜版來源，也沒有繞過 Springer 的 bot 驗證頁。

## 總覽表

| # | 簡稱 | 角度 | 年 | 存在確認 | 取得 | 優先度 |
|---|---|---|---|---|---|---|
| 1 | Kučera ICCD'18 informed discarding | b, a, d | 2018/19 | 已確認（FIT VUT 結果頁 + 作者 PDF） | 全文 | 高 |
| 2 | NetBeacon (USENIX Sec'23) | b, c, d | 2023 | 已確認（USENIX 開放全文） | 全文 | 高 |
| 3 | immUNITY | a | 2026 | 已確認（arXiv，預印本） | 全文 | 高 |
| 4 | Grashöfer DPD 攻擊 | d | 2019 | 已確認（arXiv，預印本） | 全文 | 高 |
| 5 | P4-ONIDS (SBRC'21) | b, a | 2021 | 已確認（SBC 頁 + PDF） | 全文 | 中 |
| 6 | P4ID (NFV-SDN'19) / 4MIDable (JNSM'23) | a | 2019/23 | 已確認（機構庫書目頁） | 僅摘要（P4ID 另有作者簡報） | 中 |
| 7 | Hamza MUD+SDN (SoSR'19) | a, c, d | 2019 | 已確認（作者 PDF 含 ACM DOI） | 全文 | 中 |
| 8 | Kabasele & Sadre two-level IDS (ICS-CSR'18) | a, c | 2018 | 已確認（UCLouvain 機構庫） | 全文 | 中 |
| 9 | NetMasquerade (NDSS'26) | d | 2026 | 已確認（NDSS 頁面 + PDF） | 全文（只讀關鍵章節） | 中 |
| 10 | Chae on-off 信任管理 (TPDS'15) | d, c | 2015 | 已確認（URI 機構庫頁；DOI 可解析） | 僅摘要 | 中 |
| 11 | Retina (SIGCOMM'22) | b | 2022 | 已確認（作者 PDF 含 ACM DOI） | 全文 | 中 |
| 12 | FastFlow (SIGMETRICS'25) | b | 2025 | 已確認（arXiv 頁面） | 全文（arXiv 預印版） | 中 |
| 13 | HybridMon (NOMS'25) | e, b | 2025 | 已確認（作者 PDF 含 IEEE DOI） | 全文 | 中 |
| 14 | NOS-Gate (IEEE TCE'26) | d, c | 2026 | 已確認 arXiv；正式版 DOI 可解析但頁面讀不到 | 全文（arXiv v2） | 低 |
| A | Time Machine (SIGCOMM'08) | b, d | 2008 | 已確認 | 全文 | 高（範圍外） |
| B | Papadogiannakis selective discarding (EuroSec'10) | b, d | 2010 | 已確認 | 全文 | 高（範圍外） |
| C | SciPass (SC14) | a | 2014 | 已確認（作者 PDF；出版年來自二手） | 全文 | 中（範圍外） |

主清單 14 篇，其中 12 篇讀得到全文（#9 只讀關鍵章節），2 篇（#6、#10）僅摘要。

---

## 1. Kučera, Kekely, Piecek, Kořenek — General IDS Acceleration for High-Speed Networks（角度 b、a、d）

- 書目：Jan Kučera, Lukáš Kekely, Adam Piecek, Jan Kořenek（Brno Univ. of Technology / Liberouter）。2018 IEEE 36th International Conference on Computer Design (ICCD 2018), Orlando, pp. 366–373。DOI 10.1109/ICCD.2018.00062。FIT VUT 記錄標 Published 2019（proceedings 年份差異），https://www.fit.vut.cz/research/result/c155086/ 。
- 存在確認：已確認。FIT VUT 結果頁（含 DOI、摘要、ISBN）[摘要]；作者組 PDF https://www.liberouter.org/wp-content/uploads/2018/10/IDS-SDM-paper.pdf 全文已讀，內文頁首含 DOI。
- 取得：全文（作者版）。檔案：`pdfs/search/kucera_iccd18_ids_accel.pdf`。
- 對應：b（只處理每條 flow 前 N 個封包）、a（把不像威脅的流量 bypass）、d（作者自述盲區）。
- 重點：
  - 以 Suricata 為 IDS，把每條 flow 第 N 個封包之後全部丟棄（bypass），N 隨 buffer 溢位情形調低、負載下降再調高。[原文 §IV 系統設計、§V]
  - 真實流量（作者所屬全國級網路中一條線路的未取樣 pcap：285,833,947 封包、8,642,744 flows、約 2 Gbps、826 秒），13,642 條 ET 規則；以離線全量分析為 100% 基準。[原文 §III]
  - 只看每條 flow 前 5 個封包仍偵測到超過 80% 的事件，N>30 時超過 90%；每條 flow 前 50 個封包只佔全部封包不到 20%。[原文 §III, Fig.3] 對照：原版 Suricata 在 10 Gbps 時丟包超過 60%、只偵測到不到 40% 的事件。[原文 §III, Fig.1]
  - 作者明說這個設計「不會偵測發生在前 N 個封包之後的攻擊」，並以其 trace 估計這類事件少於 10%（N=30）。[原文 §IV]
- 與我們構想的關係：
  - 支持：「只看 flow 開頭」在 Suricata + ET 規則上有實證的成本效益曲線；流量的重尾分布讓「每條 flow 只處理前 N 個封包」可省掉大部分封包。
  - 反駁／缺口：它對 N 之後的 flow 完全不再看（沒有抽樣、沒有撤銷，N 是依負載而不是依信任調整）。「事件」是 Suricata 告警相對離線告警的比例，不是人工標註的真攻擊，且 trace 不是 IoT 流量。[推測] 以此作為「不抽樣的 cutoff 基線」，我們的抽樣＋撤銷設計可與它比較。
  - 硬體：Xeon E5-2670 8 核 64 GB + FPGA 卡（SDM），不是 Pi；軟體版本（只用 Suricata input plugin 丟包）在概念上可移植到 NFQUEUE 前置層，是 [推測]。
- 優先度：**高**。原因：唯一找到用 Suricata 規則量到「前 N 封包 vs 事件偵測率」曲線、同時有真實流量與吞吐量結果的論文，且作者白紙黑字承認 N 之後的盲區。

## 2. NetBeacon — An Efficient Design of Intelligent Network Data Plane（角度 b、c、d）

- 書目：Guangmeng Zhou, Zhuotao Liu, Chuanpu Fu, Qi Li, Ke Xu（清華）。32nd USENIX Security Symposium, 2023（Anaheim）。https://www.usenix.org/conference/usenixsecurity23/presentation/zhou-guangmeng 。USENIX 論文無 DOI。程式碼：https://github.com/IDP-code/NetBeacon [原文 腳註]。
- 存在確認：已確認（USENIX 開放全文 PDF，頁首含出處）。取得：全文。檔案：`pdfs/search/netbeacon_usenixsec23.pdf`。
- 對應：b（多階段 inference point）、c（flow class table 快取判定結果）、d（作者自己討論的 stealth attack）。
- 重點：
  - 多階段循序模型：在 flow 的第 n 個封包（實驗中為第 2、4、8、32、256、512、2048 個封包）做推論；某階段信心超過 determination threshold 就「預先判定」該 flow，不再做後續推論。[原文 §4.2；推論點位置見 §7 Evaluation 的 P2P 任務]
  - 判定結果存入 flow class table（以 5-tuple 為 key），之後的封包直接命中、不再過 ML；表項依 FIFO 或 LRU 定期移除。[原文 §5.2]
  - 安全分析段明列兩種針對自身參數的攻擊：「stealth attack：攻擊者先送良性封包，等 NetBeacon 判定 flow 類別後才送惡意封包」，以及 low-rate-long-flow（逼 flow 逾時）。建議的緩解是對 flow class table 項目加「最大 flow 長度上限」，以及依每條 flow 的最大 IPD 設逾時（例如兩倍）。[原文 §8 Discussion 的 Security Analysis 段]
  - 只對長 flow 維護 per-flow state 的決策：在 P2P 任務中，只對超過 8 或 16 個封包的 flow 用 flow-level 特徵，整體封包分類準確率與全部 flow 都用幾乎相同。[原文 §5.2, Fig.10]
- 與我們構想的關係：
  - 支持：flow class table 就是「信任快取」的現成設計，「判定一次就不再檢查」的作法有頂會背書；作者自己預見「先乖後壞」並給出緩解（最大長度、逾時）。
  - 缺口：論文沒有量測 stealth attack 的實際漏報（我檢索全文只看到這一段討論）作者自述這類攻擊有進入門檻，攻擊者需要先探測參數設定 [原文 同段]；沒有抽樣式複查。硬體為 Tofino。
  - 可借用：[推測] 「信任項目的最大存活長度／最大 bytes 數」可直接當作我們撤銷機制的參數，用它的 inference point 間距當作「複查節奏」的起點。
- 優先度：**高**。原因：同時有「判定後不再檢查」的機制與作者承認的對應規避攻擊，兩件事我們都需要。

## 3. immUNITY — Detecting and Mitigating Low Volume & Slow Attacks with Programmable Switches and SmartNICs（角度 a）

- 書目：Cuidi Wei, Shaoyu Tu, Daiki Hata, Toru Hasegawa, Yuki Koizumi, K. K. Ramakrishnan, Junji Takemasa, Timothy Wood。arXiv:2603.20573 [cs.NI]，2026-03-21，v1。https://arxiv.org/abs/2603.20573 。預印本，未見同行審查；正式出版未能確認。
- 存在確認：已確認（arXiv PDF 全文）。取得：全文。檔案：`pdfs/search/arxiv_2603.20573.pdf`。
- 對應：a。直接把設計「翻過來」：在交換器上建 benign-flow 白名單，命中者直接轉發到目的端，只有未知流量才送 SmartNIC 做 ML＋規則分析。[摘要][原文 §1]
- 重點：
  - 判定時點：SmartNIC 在 flow 的第 3 個封包（第一個帶 payload 的資料封包）才觸發 ML 分類，判為 benign 就把該 5-tuple 寫入交換器的 Overwriting Flow Filter (OFF)；少於 3 個封包的 flow 改用跨 flow 的規則式偵測。[原文 §3.6]
  - 作者特別強調「把惡意 flow 誤判為 benign」比「把 benign 誤判為 unknown」更糟，所以 OFF 的設計目標是壓低前者：被誤放行封包的 FPR 低至 0.0008%（trace 驅動模擬）。[原文 §3.3、§5.1]
  - 效益：100 Gbps 單一 SmartNIC 核心的實測中，端到端 96 Gbps，只有 0.14 Gbps 被送到 SmartNIC；外推到 1.5 Tbps 為 2.24 Gbps。[原文 §1]；掃描來源 IP 辨識率 99%（CAIDA trace）。[原文 §1]
  - 撤銷機制：白名單項目靠 OFF「始終是滿的快取、舊項被新項覆寫」淘汰；沒有另設逐 flow 的重新驗證。作者另設 Malicious Source Table，命中的來源改送 scrubber 而非丟棄。[原文 §3.2、§3.3]
- 與我們構想的關係：
  - 支持：「先由重一點的元件判斷、結果下放到前置過濾器」與我們的構想同構，而且有 trace 與硬體實測的流量比例（流量 Gbps 層級的 0.14/96）。
  - 缺口：白名單放行之後該 flow 不再被看；我用關鍵字檢索全文，未見對「已被放行的 flow 之後變惡意」的討論 [推測：這是未處理的缺口]。判定只用到前 3 個封包的 header 特徵。
  - 硬體：Tofino v1 + BlueField-3，不是 Pi；觀念（依 5-tuple 快取放行、FPR 優先）可移植，實作成本未驗證。
- 優先度：**高**。原因：2026 年最貼近「判定後放行 + 只對未知流量做重檢測」的完整系統，且量了 FPR 與送入慢路徑的流量比例。注意是預印本。

## 4. Grashöfer, Titze, Hartenstein — Attacks on Dynamic Protocol Detection of Open Source Network Security Monitoring Tools（角度 d）

- 書目：Jan Grashöfer, Christian Titze, Hannes Hartenstein（KIT）。arXiv:1912.03962 [cs.NI]，2019-12-09。https://arxiv.org/abs/1912.03962 。是否另有正式期刊／會議版本未能確認。
- 存在確認：已確認（arXiv PDF 全文）。取得：全文。檔案：`pdfs/search/arxiv_1912.03962.pdf`。
- 對應：d。主題是 IDS 只看連線開頭來決定協定、決定後固定，攻擊者把「真正的開始」往後推。這和「超過 inspection depth 才攻擊」是同一類弱點。
- 重點：
  - 提出 Deferred Start 與 Misleading Start 兩種技術：以大量無用資料（例如 CRLF stuffing）耗盡 IDS 用來辨識協定的 buffer，讓協定偵測失敗。[摘要][原文 §5.1]
  - Bro（現 Zeek）2.5.1 的協定辨識 buffer 預設只有 1024 bytes，是一個固定截斷點；在非標準埠（4242）上被 CRLF Stuffing 規避。[原文 §4.1、§6 Table 1]
  - Snort 3 與 Suricata 4.1.2 在 HELO Method 攻擊下被規避；Suricata 對 CRLF Stuffing 需要約十萬個 CRLF 才規避，作者評估實務威脅有限；增大 TCP reassembly buffer 沒能緩解。[原文 §6 Table 1 及 Suricata 小節]
  - 攻擊成功的後果：Suricata 不再產生 HTTP log、與 HTTP 相關的規則不再比對。[原文 §6]
- 與我們構想的關係：
  - 支持（作為威脅證據）：主流 IDS 都有「看一小段就定案」的機制，而攻擊者可以在那一小段內裝乖；這是真實可行的規避，不是理論推演。
  - 差異：這篇打的是協定辨識，不是「信任 flow 後降級」；轉到我們的設計是類比 [推測]。對應的設計提醒：[推測] 決定信任的「窗口」若固定且可預測，就能被填滿；Time Machine 與 Papadogiannakis 的建議（隨機化 cutoff）可以搭配（見範圍外 A、B）。
- 優先度：**高**。原因：唯一找到對 Zeek／Snort／Suricata 做實證規避的同行可查論文，直接說明「固定截斷點」的風險。

## 5. P4-ONIDS — A P4-based NIDS optimized for constrained programmable data planes in SDN（角度 b、a）

- 書目：Kairo Tavares, Tiago Ferreto（PUCRS）。SBRC 2021（39th，Uberlândia），pp. 434–447，SBC。DOI 10.5753/sbrc.2021.16738。https://sol.sbc.org.br/index.php/sbrc/article/view/16738 。
- 存在確認：已確認（SBC 頁面含 DOI；PDF 全文）。取得：全文。檔案：`pdfs/search/p4onids_sbrc.pdf`。
- 對應：b（把每條可疑 flow 的前 N 個封包送 Snort，其餘不送）、a（資料平面前置過濾）。
- 重點：
  - 做法：把 Snort 規則編譯成 P4 規則（規則數縮減超過 400 倍）；對命中的可疑 flow 只送前 N 個封包給 NIDS，N 由控制平面動態調整以免 NIDS 飽和，代價是降低分類準確度；以帶時間式刪除的 Count-Min sketch 追蹤已送封包數。[摘要][原文 §3 Proposed Solution]
  - 結果：N 加大時，被過濾封包比例趨近約 55% 而飽和；N=100 時平均過濾約 40% 封包，Tuesday 與 Friday 的 CICIDS2017 pcap 上告警準確度接近 90%。[原文 §4.2]
  - 作者承認的失敗案例：Wednesday（以 DoS/DDoS 為主）準確度一直很低，因為主要告警來自一條要「超過 200 pps」才觸發的 Snort 規則（SID 40063），而「只送前 N 個封包、flow 閒置後失效」的策略無法觸發速率型規則。[原文 §4.2]
  - 環境：Mininet + BMv2 emulation，CICIDS2017 pcap 以 2000 pps 重播，Snort。[原文 §4.1]
- 與我們構想的關係：
  - 支持：給出 Snort 規則式 IDS 上「前 N 封包 vs 告警比例」的另一組曲線，可與 #1 交叉比對。
  - 提醒（對規則式 IDS 重要）：[推測] 凡是依賴累計量／速率的規則（threshold、detection_filter），一旦 flow 被 bypass 就永遠不會觸發，所以放行前必須先決定哪些規則不能被繞過，或改用交換器／nftables 的計數器補。
  - 缺點：emulation、BMv2 無效能意義；準確度是「告警相對預期告警」的比例。
- 優先度：**中**。原因：數字比 #1 弱（emulation），但它點出的速率型規則盲區對 Suricata/Snort 很實際。

## 6. P4ID（NFV-SDN 2019）與 4MIDable（JNSM 2023）— 資料平面前置過濾＋IDS 回饋（角度 a）

- 書目 A：Benjamin Lewis, Matthew Broadbent, Nicholas Race。P4ID: P4 Enhanced Intrusion Detection。IEEE NFV-SDN 2019，DOI 10.1109/NFV-SDN47374.2019.9040044（僅 4 頁）。頁面：https://pure.sruc.ac.uk/en/publications/p4id-p4-enhanced-intrusion-detection/ 。
- 書目 B：Benjamin Lewis, Matthew Broadbent, Charalampos Rotsos, Nicholas Race。4MIDable: Flexible Network Offloading For Security VNFs。Journal of Network and Systems Management 31(3), Article 52, 2023。DOI 10.1007/s10922-023-09744-1 。頁面：https://pure.sruc.ac.uk/en/publications/4midable-flexible-network-offloading-for-security-vnfs/ 。
- 存在確認：兩篇皆已確認（機構庫書目頁，含 DOI 與摘要）。取得：僅摘要。IEEE 與 Springer 全文我都沒讀到（Springer 回傳 bot 驗證頁，我沒有繞過）。另取得第一作者的 CoSeNeRs 2019 簡報 `pdfs/search/p4id_coseners.pdf`，只當 [二手]。
- 對應：a。把 Snort/Suricata 規則轉成 P4 表項做 stateless 前置過濾，再加 stateful 階段。[摘要]
- 重點：
  - P4ID：stateless 階段決定丟棄、正常轉發或送 IDS；stateful 階段把每條新 flow 的前 n 個封包送 IDS。[二手：搜尋結果對 Lancaster／Napier 頁面的摘要；簡報顯示以暫存器記封包數與時間戳、計數器有可調逾時]
  - 簡報中的初步結果：偵測到的簽章最多 75%、只用 50% 的流量；最差約 55% 簽章、約 38% 流量，作者自己寫「想改善」。[二手：簡報，非論文本體]
  - 4MIDable：把 P4ID 做成讓「未修改的 IDS middlebox」取得 stateful 處理與回饋的 agent，宣稱「減少超過 80% 的流量處理量，且不降低威脅偵測率」。[摘要，條件未能確認]
- 與我們構想的關係：
  - 支持：「IDS 把結果回饋給前置過濾器」就是我們「雲端判定後下規則」的小型版本，並且是以 Snort 規則為基準。
  - 缺口：[推測] 簡報中純 stateful cutoff 損失明顯，4MIDable 的 80% 且無損失是靠回饋，但我看不到全文，無法確認回饋如何設計、有沒有討論規避。
- 優先度：**中**。原因：方向貼近但全文取不到，數字條件未知。建議有 Springer 權限時先看 4MIDable 的實驗設定與 IDS feedback 一節。

## 7. Hamza, Habibi Gharakheili, Benson, Sivaraman — Detecting Volumetric Attacks on IoT Devices via SDN-Based Monitoring of MUD Activity（角度 a、c、d）

- 書目：ACM SOSR 2019（San Jose）。DOI 10.1145/3314148.3314352。作者 PDF：https://cs.brown.edu/~tab/papers/SoSR19.pdf 。
- 存在確認：已確認（作者 PDF 內文含 ACM DOI）。取得：全文。檔案：`pdfs/search/hamza_sosr19.pdf`。
- 對應：a（MUD 白名單 = 放行規則）、c（放行後以計數器持續監控）、d（刻意設計「合乎白名單」的攻擊）。
- 重點：
  - MUD 的 ACL 只能允許或拒絕、沒有速率限制，所以符合 MUD 的流量仍可被拿來做 volumetric 攻擊；論文專門研究「合乎 MUD 的攻擊」，並自己實作 200 次、每次 10 分鐘、三種速率（1、10、100 pps）的攻擊，刻意不被 spec-based 偵測器抓到。[原文 §1、攻擊產生一節]
  - 放行後的可見性是 per-device 與 per-flow 的 SDN 計數器（不是封包檢視）；只有平均不到 1.16% 的封包（16 天、各裝置平均；最高的 WeMo motion 約 1.61%）被鏡射給檢查引擎，用途是維護 MUD 的 DNS 綁定與收緊 flow entry（以 WeMo motion 為例，其中 99.5% 是 DNS 回應），反應式 flow rule 讓之後的封包不需再檢查。注意這個「檢查」不是安全檢測。[原文 Processing Cost 一節, Table 8]
  - 偵測：邊界偵測＋Markov chain，1 分鐘窗 TPR 87.40%、200 次攻擊中 5 次低速攻擊漏掉；改用較大特徵集與 4 分鐘窗可到 TPR 90.80% 且全部低速攻擊都偵測到，代價是 FPR 較高與較多狀態。[原文 §5.2, Fig.7]
- 與我們構想的關係：
  - 支持：「放行 ≠ 安全」有實證；放行後只留計數器（流量層級的低成本可見性）也能抓到相當比例的 volumetric 攻擊，窗口越大越能抓低速攻擊。
  - 缺口：攻擊都是 volumetric，不是低速滲透或應用層入侵；偵測靠 ML 模型（每台裝置 14.96 MB 模型 [原文 Table 8 附近]），不是 Suricata 規則。
  - 硬體：OpenFlow switch + Faucet + 筆電等級主機，不是 Pi。
- 優先度：**中**。原因：IoT 場景、有放行後監控與合規攻擊的實測，但攻擊類型偏單一。

## 8. Kabasele Ndonda & Sadre — A Two-level Intrusion Detection System for Industrial Control System Networks using P4（角度 a、c）

- 書目：Gorby Kabasele Ndonda, Ramin Sadre（UCLouvain）。ICS-CSR 2018（Hamburg），2018-08。機構庫頁面未列 DOI。https://research.dial.uclouvain.be/handle/2078.5/256057 。
- 存在確認：已確認（機構庫書目頁 + 開放 PDF）。取得：全文。檔案：`pdfs/search/kabasele_ics-csr18.pdf`。
- 對應：a、c。第一層是 P4 交換器上的 flow whitelist 與 Modbus whitelist，第二層是 DPI 引擎，由第二層透過 SDN 控制器更新第一層白名單。[摘要]
- 重點：
  - 白名單命中就轉發；未命中的封包導向第二層。[原文 §4.1]
  - 新項目加入白名單有三種策略：(a) 關閉以求最嚴格、(b) 立即加入、(c) 觀察到一定數量「無可疑」封包後才加入；原型採用的是「看到成功的 TCP 三向交握且封包分析通過」就把該 flow 加入，所以 SYN flood 填不滿白名單。[原文 §4.2.3 / 加入白名單一節]
  - 放行後仍有逐封包的應用層檢查：Modbus 表比對 function code 與訊息長度，不符者送第二層。[原文 §4.1]
  - 評估：Mininet + bmv2 emulation，對通訊延遲影響小；對 Modbus/TCP 攻擊有效。[摘要][原文 §5]
- 與我們構想的關係：
  - 支持：「放行門檻」的選項空間（立即／觀察 N 個封包後／永不放行特定服務）可直接借來當我們「何時信任」的設計變數；「不放行高風險服務（例如 PLC 的 HTTP 設定頁）」是服務分級的實例。
  - 缺口：ICS 而非通用 IoT；我檢索全文未見對放行後 flow 變壞的討論；emulation。
- 優先度：**中**。原因：設計選項清楚，但證據只有 emulation。

## 9. NetMasquerade — A Hard-Label Black-Box Evasion Attack against ML-based Malicious Traffic Detection Systems（角度 d）

- 書目：Zixuan Liu, Yi Zhao, Zhuotao Liu, Qi Li, Chuanpu Fu, Guangmeng Zhou, Ke Xu。NDSS Symposium 2026。https://www.ndss-symposium.org/wp-content/uploads/2026-s916-paper.pdf （NDSS 頁面 https://www.ndss-symposium.org/?p=23637 ）。arXiv:2510.14906。
- 存在確認：已確認（NDSS 頁面與 PDF）。取得：全文，我只讀了摘要、攻擊設計與評估的目標系統章節。檔案：`pdfs/search/ndss26_netmasquerade.pdf`。
- 對應：d（mimicry）。用強化學習把攻擊 flow 改成像良性流量，只依賴 hard-label 輸出。
- 重點：
  - 對 6 個既有偵測系統、80 個攻擊情境，攻擊成功率超過 96.65%。[摘要]
  - 受測系統包含已在本專案精讀清單內的 FlowLens、Kitsune，也包含 NetBeacon 與 Whisper；平均 ASR 依序為 Whisper 0.9878、FlowLens 0.9717、NetBeacon 0.9809、Vanilla+RNN 0.9782、CICFlowMeter+MLP 0.9626、Kitsune 0.991（單一情境範圍 0.7475–0.999）。[原文 §VI-B, Table II]
  - 手法是加入非功能封包、改變封包大小與間隔，並以懲罰項保留攻擊功能。[原文 §V、§VI-A 基線說明]
- 與我們構想的關係：
  - 支持：[推測] 若 gateway 的「放行」判斷或雲端的判斷是 ML／flow 特徵式的，攻擊者可以讓開頭看起來良性；這篇說明這類偵測器對 mimicry 並不穩。
  - 差異：它打的是「偵測器判斷」，不是「放行後降級」；它沒有討論 bypass 或信任快取。
  - 硬體與場景：以骨幹／公開資料集為主，沒有 IoT gateway 實驗。
- 優先度：**中**。原因：能支撐「判斷只靠開頭特徵會被模仿」，但不是專門針對信任快取。

## 10. Chae, DiPippo, Sun — Trust Management for Defending On-Off Attacks（角度 d、c）

- 書目：Younghun Chae, Lisa DiPippo, Yan Lindsay Sun（Univ. of Rhode Island）。IEEE Transactions on Parallel and Distributed Systems 26(4): 1178–1191, 2015。DOI 10.1109/TPDS.2014.2317719。頁面：https://digitalcommons.uri.edu/cs_facpubs/38 。
- 存在確認：已確認（URI 機構庫頁；DOI 可解析到 IEEE Xplore document 6800056，IEEE 頁面本身我讀不到內容）。取得：僅摘要。
- 對應：d、c。研究「信任管理需要讓節點在犯錯後能恢復信任（redemption），但惡意節點會把攻擊偽裝成暫時錯誤，利用 redemption 取得更多攻擊機會」。[摘要]
- 重點：
  - 指出既有 redemption 機制可被 on-off 行為（好壞交替）利用。[摘要]
  - 提出能區分真暫時錯誤與偽裝的新信任管理與 redemption 方案，以分析與 WSN 模擬驗證；摘要沒有給數字。[摘要]
- 與我們構想的關係：
  - 支持：[推測] 我們若讓被撤銷信任的 flow／裝置「一段時間後可恢復」，就會遇到同樣的 on-off 利用；這篇是這個問題在信任管理領域的標準文獻。
  - 缺口：領域是 WSN 節點信任（推薦、轉發行為），不是封包檢測；全文未讀，所以細節、參數和模擬規模未能確認。
- 優先度：**中**。原因：直接對應「信任恢復／撤銷」的設計風險，但需要有 IEEE 權限才能看到方法細節。

## 11. Retina — Analyzing 100 GbE Traffic on Commodity Hardware（角度 b）

- 書目：Gerry Wan, Fengchen Gong, Tom Barbette, Zakir Durumeric。ACM SIGCOMM 2022（Amsterdam）。DOI 10.1145/3544216.3544227。作者 PDF：https://zakird.com/papers/retina.pdf 。
- 存在確認：已確認（PDF 內文含 DOI 與會議資訊）。取得：全文。檔案：`pdfs/search/retina_sigcomm22.pdf`。
- 對應：b。以「盡早、盡常丟掉不需要的流量與連線狀態」為核心；連線狀態機依訂閱內容決定何時停止解析。
- 重點：
  - 多層過濾：硬體 flow rule、封包過濾、連線過濾、session 過濾逐層縮減；連線狀態有 Probe、Parse、Track、Delete 四種，過濾失敗就刪除連線，必要時「停止處理連線中段的流量」（例如只訂閱 TLS handshake 時，握手後不再追蹤）。[原文 Fig.4 與 Application-layer Parsing 段]
  - 一個 100 GbE 範例：只有 35.4% 的封包通過封包過濾、1.54% 的封包需要重組，使用者 callback 只在 0.000188% 的封包上執行。[原文 §6.3, Fig.7]
- 與我們構想的關係：
  - 支持：「看完開頭就不再處理」在高速環境下的成本結構（各處理階段被觸發的比例與每階段 CPU cycles）有可借用的量測方法。
  - 差異：它的丟棄是依「分析範圍」而不是「信任」，也不是 IDS；全文我檢索不到對攻擊者利用截斷點的討論。x86 + 100G NIC，不是 Pi。
- 優先度：**中**。原因：方法學借鏡（分層成本量測），不涉及信任。

## 12. FastFlow — Early Yet Robust Network Flow Classification using the Minimal Number of Time-Series Packets（角度 b）

- 書目：Rushi Jayeshkumar Babaria, Minzhao Lyu, Gustavo Batista, Vijay Sivaraman（UNSW）。ACM SIGMETRICS 2025；Proc. ACM Meas. Anal. Comput. Syst.。arXiv:2504.02174。arXiv 頁面列出相關 DOI 10.1145/3727115（我未在 ACM 頁驗證）。
- 存在確認：已確認（arXiv 頁面與 PDF；arXiv 註記接受於 SIGMETRICS 2025）。取得：全文（arXiv 預印版）。檔案：`pdfs/search/arxiv_2504.02174_fastflow.pdf`。
- 對應：b。用 LSTM + 強化學習讓模型「動態決定每條 flow 需要看幾個封包」才給出已知類型或 unknown 的判定。[摘要]
- 重點：
  - 在校園網路一週部署（超過 2,290 萬條 flows，7 種應用類型、33 家內容供應商），平均只需 8.37 個封包、約 0.5 秒，應用類型準確率超過 91%、內容供應商超過 96%。[摘要]
  - 有 unknown 類別，用來處理訓練時沒見過的流量。[摘要]
- 與我們構想的關係：
  - 支持：adaptive per-flow inspection depth 的學習式作法：每條 flow 的決策點不固定。「unknown -> 繼續看或上送」的語意可類比我們的「判不準 -> 送雲端」。
  - 缺口：任務是流量分類（應用類型），不是入侵偵測；我檢索全文，攻擊／惡意字眼只出現在參考文獻，沒有討論規避。我只用關鍵字檢索全文，未見 Pi 級或嵌入式硬體的量測。
- 優先度：**中**。原因：adaptive depth 的最新方法，但領域不同，遷移到 IDS 要重做。

## 13. HybridMon — Advancing Network Monitoring with Packet-Level Records and Selective Flow Aggregation（角度 e、b）

- 書目：Ina Berenice Fink, Ike Kunze, Pascal Hein, Jan Pennekamp, Benjamin Standaert, Klaus Wehrle, Jan Rüth（RWTH Aachen 等）。IEEE NOMS 2025。DOI 10.1109/NOMS57970.2025.11073723。PDF：https://www.comsys.rwth-aachen.de/fileadmin/papers/2025/2025-fink-hybridmon.pdf 。程式碼 github.com/COMSYS/HybridMon [原文 參考文獻]。
- 存在確認：已確認（作者 PDF，頁尾含 IEEE DOI 與版權）。取得：全文。檔案：`pdfs/search/fink_hybridmon_2025.pdf`。
- 對應：e（輸出頻寬為主要指標）、b。Tofino 上對每個封包輸出濃縮的封包級紀錄，另對「較不重要的流量」選擇性聚合成 flow，並允許 IDS 回饋暫時性 filter 規則（例如停止監控已偵測到的高流量攻擊）。[摘要][原文 §1]
- 重點：
  - 輸出頻寬降到封包監控的 12%–20%；加上 heavy-hitter 子取樣（影響 7%–12% 的 flows）後降到原 trace 的 4.5%–10.5%。[原文 §V-B1]（CAIDA 四個 trace、每個 10 次、Tofino1 實測；單筆紀錄 50 B）
  - 作者承認比傳統 flow 匯出（YAF）輸出效率低，那是較高粒度的代價。[原文 §V-B1]
- 與我們構想的關係：
  - 支持：e 角度少見的「以輸出 bytes 為指標」的實測；封包級紀錄對時效與準確度的取捨可作參考。
  - 差異：輸出對象是 collector，不是雲端 IDS；場景是 Tbps 骨幹，不是 IoT；我檢索全文，未見規避討論。
- 優先度：**中**。原因：唯一把輸出 bytes 當首要指標、有真實 trace 與硬體的相近論文，但規模與場景相距很遠。

## 14. NOS-Gate — Queue-Aware Streaming IDS for Consumer Gateways under Timing-Controlled Evasion（角度 d、c）

- 書目：Muhammad Bilal, Omer Tariq, Hasan Ahmed。arXiv:2601.00389 v2，2026-06-01；註記「Published in: IEEE Transactions on Consumer Electronics，DOI 10.1109/TCE.2026.3682516」。
- 存在確認：arXiv 全文已確認。正式版：DOI 可解析（導向 IEEE Xplore document 11478475），但 IEEE 頁面讀不到內容，所以題名／卷期未能由出版社頁確認。取得：全文（arXiv v2）。檔案：`pdfs/search/arxiv_2601.00389.pdf`。
- 對應：d（時序控制的規避）、c（持續評分＋可逆的緩解）。
- 重點：
  - 家用 gateway 上的串流 IDS，只用 metadata；每條 flow 一個兩狀態單元，以 K-of-M 持續規則觸發後，暫時降低該 flow 在 WFQ 中的權重（可逆）。[摘要]
  - 威脅模型是攻擊者在預算內重塑時序與封包大小去模仿良性裝置；在 0.1% 誤報操作點，incident recall 0.952，最佳基線 0.857；單一 flow-window 評分約 2.09 µs。[摘要]（合成的 "worlds" 基準，作者自述不重現任何單一公開資料集 [原文 §1]）
- 與我們構想的關係：
  - 支持：「持續評分 + 持久性規則 + 可逆動作」是撤銷式設計的現成範本；明確把 gateway 的 CPU／延遲預算納入。
  - 缺口：合成資料；沒有放行／bypass 機制；沒有 Pi 實測（全文關鍵字檢索未見 Raspberry）。
- 優先度：**低**。原因：切題的是撤銷動作設計，但證據來自合成基準。

---

## 範圍外（早於 2015，但與本子題直接相關；不計入主清單篇數）

### A. Maier, Sommer, Dreger, Feldmann, Paxson, Schneider — Enriching Network Security Analysis with Time Travel（角度 b、d）

- 書目：ACM SIGCOMM 2008（Seattle）。PDF：https://www.icir.org/gregor/papers/sigcomm08-tm.pdf 。已確認（作者 PDF 全文；頁首含 SIGCOMM'08）。檔案：`pdfs/search/timemachine_sigcomm08.pdf`。
- 重點：
  - 核心主張：Internet 流量重尾，每條連線只存前 N bytes（cutoff）即可完整保留大多數連線；三個站點 91–94% 的連線短於 10 KB，cutoff 20 KB 可完整保留 94–96%。[原文 §2] 實測 cutoff 後剩餘流量低於原流量的 6%。[原文 §4.1]
  - NIDS 可動態控制 TM：對觸發告警的連線送 suspend_cutoff，並用 set_class 把來源 IP 放入掃描器（cutoff 提高到 50 KB）或告警（關閉 cutoff）類別；兩週內 NIDS 發出 427 次 suspend_cutoff、把 12,532 個 IP 放進 scanners 類別、592 個放進 alarms 類別。[原文 §5.2]
  - 明確的規避討論（Risk of Evasion）：「攻擊者若把攻擊延後到 cutoff 之後，TM 不會記錄」，作者稱之為根本限制，因為任何減量啟發式都有盲區；緩解方向是依服務設不同 cutoff、依 NIDS 風險評估動態調整，以及隨機化 cutoff，讓攻擊者無法預測 cutoff 何時生效，且 cutoff 之後仍隨機保留一部分後續封包（只是計畫，未實作或量測）。[原文 §6 Deployment Trade-offs]
- 與我們構想的關係：這是「cutoff + 放行後仍抽樣 + 風險升高時撤銷 cutoff」整套想法最早、最完整的描述，而且有 LBNL 實際營運的數字。限制：它是錄封包做事後分析，不是 inline 阻擋；隨機化 cutoff 只是計畫。
- 優先度：**高**（概念來源）。

### B. Papadogiannakis, Polychronakis, Markatos — Improving the Accuracy of Network Intrusion Detection Systems Under Load Using Selective Packet Discarding（角度 b、d）

- 書目：EUROSEC '10（Paris），ACM，2010。PDF：https://projects.ics.forth.gr/dcs/Activities/papers/discarding.eurosec10.pdf 。已確認（PDF 全文，頁首有 EUROSEC'10 版權段）。檔案：`pdfs/search/papadogiannakis_eurosec10.pdf`。
- 重點：
  - 在 Snort 2.8.3.2（9,276 條規則）加一個 preprocessor：依負載動態調整「每條 flow 最多處理幾個封包」的 cutoff；超過 cutoff 的封包在 user space 直接丟掉，而不是讓 kernel 隨機丟。[原文 §2.3、§2.4]
  - 實測：用的 trace 裡 90% 的告警由 flow 前 30 個封包觸發，第 100 個封包之後只佔 3%；cutoff 100 時 Snort 吞吐量由 560 Mbit/s 升到約 2 Gbit/s（3.62 倍），仍觸發 95% 的告警；人工注入的 276 個攻擊在 cutoff 低到 20 個封包時仍全部觸發；每個量測重複 10 次取平均。[原文 §2.1, §3.2]
  - 與 kernel 隨機丟包相比：500 Mbit/s 下改進後的 Snort 報出 2252 個告警中的 2234 個（99.2%），比原版高約 20 個百分點；原版在 900 Mbit/s 時約漏掉一半。[原文 §3.3]
  - 規避：作者承認「攻擊者可先用良性請求填滿 stream，之後在 cutoff 之後才送真正的攻擊」；辯護是許多服務在交易結束時會斷線，持久連線的重複行為可用協定語意偵測，且為防止攻擊者靠斷線重連重置計數，實作會精確追蹤 TCP 連線終止，讓新連線的前幾個封包一定被處理。[原文 §2.4、§5 結論前討論段]
- 與我們構想的關係：與 #1 同類但更早、對象是 Snort，並明確寫出「依負載調整 cutoff」的演算法與「cutoff 後攻擊」的辯護。[推測] 「新連線一定被完整檢查」的作法，對應到我們的設計就是：信任必須綁在連線（5-tuple + 生命週期）上，不能因為重連而繼承。
- 優先度：**高**（規則式 IDS 上最直接的 cutoff 實證）。限制：2010 年、x86、Snort 2.x。

### C. Balas & Ragusa — SciPass: a 100Gbps capable secure Science DMZ using OpenFlow and Bro（角度 a）

- 書目：Indiana University GlobalNOC。作者 PDF：https://scinet.supercomputing.org/community/documents/93/pap108s3.pdf 。出處：SC14 相關論文（年份與會議來自搜尋結果與 Datanami 報導 [二手]，PDF 內文未寫）。無 DOI。已確認（PDF 全文）。檔案：`pdfs/search/scipass_sc14.pdf`（以 WebFetch 取得的 PDF 轉文字閱讀）。
- 重點：
  - Bro 在每個 sensor 上辨識「好」的 flow（依時段、IP、協定、應用層資料的政策），透過 web API 通知 SciPass 控制器，控制器在交換器加兩條較高優先權的 OpenFlow rule（每個方向一條）使該 flow 繞過防火牆與 IDS 陣列；規則帶 idle timeout，flow 結束就清掉。[原文 §2.2、§2.3]
  - 偵測到下規則的延遲：Bro 偵測 20 ms + 建立規則 4 ms + 交換器安裝 40 ms = 總共 64 ms。[原文 §5, Table 1]
  - 效益：同一條 10 GbE 路徑上，經防火牆 1.30 Gbit/s（2,838 次重傳），繞過後 9.9 Gbit/s；這是效能而不是 IDS 負載的量測。[原文 §4.1、§4.2]
- 與我們構想的關係：這是「IDS 判定好流量 -> 控制器下規則 -> 交換器改走旁路、規則靠 idle timeout 失效」的最直接先例。我檢索全文，沒有討論被放行的流量日後變壞或攻擊者利用此機制 [推測：缺口]；安全性評估缺席。
- 優先度：中（先例價值；安全面證據不足；2014 年；高速 DTN 場景）。

---

## 搜尋了什麼但沒找到（判斷 research gap 的弱證據）

這一節的「沒找到」只代表我用的搜尋詞與資料庫沒找到，不代表沒人做過。搜尋以 WebSearch 為主，沒有用 Google Scholar／Semantic Scholar 的引用網路逐篇展開；IEEE、ACM、Springer 全文多半讀不到。

1. **在 IoT gateway／Pi 級設備上，用 Suricata 或 Snort 做「信任 flow 後降低檢測」並量測上傳 bytes 與偵測損失的論文：沒找到。** 找到的 cutoff／bypass 論文（#1、#5、B）都在 x86、FPGA 或 emulation 上，而且沒有雲端卸載。
2. **放行之後對已放行 flow 做隨機抽樣複查，並量化漏報率的論文：沒找到。** 最近的是 Time Machine 的「隨機化 cutoff」（只是計畫，未量測）、Cyber-AnDe（SDN 取樣率依 benign/suspicious/malicious 調整，見下方「找到但未列入」）、Hamza 的計數器式監控（#7）。
3. **量測「先正常後攻擊」打進白名單／bypass／flow class table 的實際漏報率的論文：沒找到。** 只找到作者在討論段自述盲區（NetBeacon、Kučera、Time Machine、Papadogiannakis）與 Grashöfer 對協定辨識 buffer 的實證規避。NetMasquerade 量的是 mimicry 攻擊成功率，不是「判定後翻臉」。
4. **針對 Suricata `stream.bypass`／stream depth bypass 被規避的同行審查論文：沒找到。** 只找到 Suricata 文件與論壇、郵件列表（非論文）。搜尋摘要提到 CVE-2024-55629（TCP URG 指標造成 reassembly 與端點不一致）屬於 reassembly 分歧，不是 bypass 缺陷，未列入。
5. **trust decay／信任分數衰減用在封包或 flow 層級 IDS 的論文：沒找到。** zero-trust IoT 文獻多落在「裝置身分／存取控制」層級（見下方「找到但未列入」），其中 trust decay 只在 2026 年一篇單作者 arXiv 質性論文中被提出，且沒有實驗。
6. **edge–cloud IDS 以「上傳 bytes／頻寬」為主要指標，且比較「原始封包 vs flow record vs 告警」上傳量的論文：沒找到。** 最近的是 HybridMon（#13，交換器輸出頻寬，非 IoT）與 immUNITY（#3，送到 SmartNIC 的 Gbps，非雲端）。搜尋也找到 SPATIO（IST Lisbon）宣稱在路由器端轉 flow metrics 以省頻寬，但我只看到作者 PDF 的搜尋摘要，沒有量測數字，未列入。
7. **Pi 3B+ 級硬體上的白名單 fast path 實作論文：沒找到。** 白名單前置過濾幾乎都在 P4 交換器、SmartNIC 或 FPGA 上。
8. **放行後撤銷（revocation）的反應時間量測：只找到裝置層級的。** 找到 2026 年 arXiv「Closing the Loop」（802.1X/RADIUS 逐出裝置 335.8 ms，再加憑證撤銷 111.5 ms），但那是裝置接入層級，不是 flow 層級（見下方）。SciPass 的 64 ms（範圍外 C）是放行規則的安裝延遲，不是撤銷。
9. **無法取得全文的：** P4ID（IEEE）、4MIDable（Springer 的 bot 驗證頁，我未繞過）、Chae TPDS 2015（IEEE）、NOS-Gate 正式版（IEEE）。這些條目只能寫到摘要層級。

## 找到但未列入主清單（原因）

- **Cyber-AnDe**（Niknami, Srinivasan, Wu，IEEE TIFS 19, 2024, pp. 9245–9257 [二手：搜尋結果對 NSF PAR 記錄的摘要；我讀的是 Temple 作者 PDF，未打開出版社頁]）：SDN 中以 RL 讓取樣率依 flow 狀態（malicious／suspicious／benign）調整，起始取樣率低、遇可疑才加；宣稱偵測最多提升 93%、overhead 平均降 34% [摘要／結論，皆為作者聲稱]。是 c 角度唯一的「依狀態調取樣率」論文，但是 SDN 控制器取樣、模擬為主，無規避討論，所以放在這裡。
- **Zero Trust for Multi-RAT IoT**（Shelby，arXiv:2602.08989，2026-02，Oxford）：質性分析，提出指數衰減的 trust decay 模型 `λ_j(R)` 並討論 Weibull／事件觸發衰減，明說衰減率需實測校準，沒有實驗。[原文 §4.3、結論] 與封包檢測無關。
- **Closing the Loop**（Korkmaz, Bicakci, Uzunay，arXiv:2607.11649，2026-07）：802.1X + RADIUS CoA 逐出裝置 335.8 ms、憑證撤銷再加 111.5 ms，單一 Raspberry Pi 感測器作為受測裝置；為裝置層級撤銷，且僅單台裝置。[摘要]
- **Zero Trust-Driven Collaborative Intrusion Detection in IoT: A Continuous Trust Assessment Approach**（Wang 等，IEEE Internet Computing 29(4):37–47, 2025，DOI 10.1109/MIC.2025.3610857）：機構庫頁面只有摘要，宣稱結合特徵式與異常式偵測與動態信任管理；全文未讀，無法判斷是否涉及流量層級。
- **ZFort**（Ashraf 等，Internet of Things 28, 101419, 2024，DOI 10.1016/j.iot.2024.101419）：SDN IoT 的 zero-trust，以 SDE 評估節點間信任，並以 CVE/CVSS 計風險；屬節點風險與路由，不是流量檢測。[摘要]
- **Trust Aware Continuous Authorization for Zero Trust in Consumer IoT**（Dimitrakos 等，TrustCom 2020，DOI 10.1109/TrustCom50675.2020.00247）與 **ZASH**（da Silva 等，SBSeg 2021，DOI 10.5753/sbseg.2021.17305）：都是智慧家庭的存取控制／持續授權，僅讀到摘要，不涉及封包檢測。
- **Pigasus**（Zhao 等，OSDI 2020）：FPGA 上以 fast path 處理大多數封包、少數送 CPU，與 Snort 規則相容；仍是效能導向的 fast/slow path，不是信任式，且需 FPGA SmartNIC。我只看到搜尋結果中的二手描述，全文未取得（嘗試下載 CMU 作者頁連結得到的是 HTML 而非 PDF，已刪除）。
- **Efficient Intrusion Detection on Low-Performance Industrial IoT Edge Node Devices**（Niedermaier 等，arXiv:1908.03964）：MCU 上的分散式 agent 加集中式 log，頻寬低是賣點，但沒有卸載決策；已下載 `pdfs/search/arxiv_1908.03964.pdf`，未列入。
- **The Shunt**（Weaver, Paxson, Gonzalez，FPGA 2007，ACM）：Kučera 的 Related Work 把它描述為「把可疑流量導給軟體進一步分析的硬體加速器」，只在 1 Gbps 鏈路上展示，且論文幾乎只談硬體架構 [二手，來自 #1 §II 與其參考文獻 [9]]；我沒有自行打開，早於範圍。
- **CHID／Conditional Hybrid IDS**（Alaidaros & Mahmuddin，UUM 論文與期刊）：先做 flow-based，標出的可疑 flow 才進 packet-level 檢測，在 200 Mbps 下記憶體少 50.6%、CPU 少 18.1% 且不丟包 [二手：搜尋結果對 UUM 機構庫摘要的轉述，我沒有打開該頁或全文]。切題（先便宜再貴），但只讀到摘要且場景是 Bro 實驗室測試，所以放這裡。
- **MUD 相關後續**（Hamza 2018 IoT S&P 的 MUD+SDN、2023 arXiv 的 microflow 監控）：只讀到搜尋摘要，主清單用 #7 代表。

## 觀察（≤200 字，全部 [推測]）

[推測] 「判定後放行」這件事在文獻裡有三個層次：(1) 交換器／FPGA 上的白名單或 flow class table（immUNITY、NetBeacon、P4ID 線、SciPass），(2) IDS 內部的 cutoff／selective discarding（Papadogiannakis、Kučera、Time Machine），(3) 信任管理的 redemption／decay 理論（Chae、Multi-RAT）。三者之間幾乎沒有交集：沒有論文同時有「放行機制」、「放行後的抽樣複查」、「對 cutoff 後攻擊的量測」。作者們普遍在討論段承認盲區並建議隨機化或最大長度限制，但沒有人量。規則式 IDS 上的證據主要來自 2010 年與 2018 年兩篇（x86），沒有 ARM。
