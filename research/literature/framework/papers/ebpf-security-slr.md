# ebpf-security-slr（eBPF-based cybersecurity mechanisms: a systematic literature review）

> 頁碼約定：`[原文 p.N]` 為 arXiv v1 PDF 的頁碼（24 頁）。期刊版同為 24 頁但分頁不同，引用時請以章節對照。
> 「SLR 說」= 回顧作者對某篇原始論文的轉述，我沒有讀該原始論文，不等於原始論文的內容。

## A. 書目與取得狀況

- 標題：eBPF-based cybersecurity mechanisms: a systematic literature review（arXiv 版為標題大小寫 "eBPF-Based Cybersecurity Mechanisms: A Systematic Literature Review"）
- 作者：Stamatios Kostopoulos, Panagiotis Tsakonas, Evangelos K. Markakis（Hellenic Mediterranean University, Heraklion, Greece）[原文 p.1]
- 出處：International Journal of Information Security 25(5), article 150, 2026（Regular Contribution）。Received 25 Feb 2026 / Accepted 19 Aug 2026 / Published online 29 Aug 2026 [期刊版 PDF p.1]；issue 5 來自 Crossref [二手 https://api.crossref.org/works/10.1007/s10207-026-01326-x]
- DOI：10.1007/s10207-026-01326-x；arXiv：2608.27511v1 [cs.CR]，2026-08-27 [原文 p.1]；arXiv 摘要頁的 journal-ref 寫 "Int. J. Inf. Secur. 25, 150 (2026)"，並列出同一個期刊 DOI [二手 https://arxiv.org/abs/2608.27511]
- 授權與資金：期刊版 CC BY 4.0（開放取用）[期刊版 PDF 版權頁；Crossref]；EU Horizon INTACT 計畫 Grant 101168438 [原文 p.22]
- 本地 PDF：`research/literature/framework/pdfs/ebpf-security-slr/arxiv.pdf`（arXiv v1）、`springer.pdf`（期刊版，CC BY 公開下載，未繞過任何付費牆）

**與給定資訊的差異：無。** 標題、期刊、年份、DOI、arXiv 編號互相指向同一篇，作者一致。arXiv v1（8/27）是在期刊接受（8/19）之後、線上發表（8/29）之前貼出的。

**arXiv 版與期刊版的差異：** 我對兩份 PDF 的文字層做逐詞比對，並另外比對所有數字 token。內文、表格數字、結論一致；D5 列出的內部不一致和 §4.1.3 的 "FILENAME" 占位字（應為 FineLame）在期刊版都還在。差異只有排版（Section→Sect.、標題大小寫、參考文獻格式、頁首、授權頁）。圖片與表格版面未逐格比對。以下以 arXiv 版為準。

**取得程度：全文**（兩版皆全文，不需要使用者另外下載）。

## B. 核心貢獻

1. 依 PRISMA 2020 對 eBPF 資安研究做系統性回顧：6 個資料庫 3735 筆，最後納入 54 篇（2018–2026），分成七類（DDoS、IDS、IoT、Container、Microservices、Networking、Tools & Frameworks）[原文 p.1, p.5, p.7]。
2. 彙整出量化結論：CPU overhead 中位數 2.4%、偵測準確率 94–99%，並列出限制（verifier、46/54 需低階知識、kernel 版本碎片化、52/54 未處理 eBPF 自身安全）[原文 p.1]。這些彙總值的計算方式沒有公開（見 D5）。
3. 整理評估方法與生態缺口：測試台為主（47/54）、36/54 無公開程式碼、缺標準化 benchmark、只有 5/54 提供可重用的框架或高階抽象 [原文 Table 8 p.20；p.17–18]。

## C. 指定的 9 項（SLR 版）

1. **Research Problem**：eBPF 資安研究散落在不同領域、評估方法與部署情境，缺少以資安為專題、方法透明的整理；既有 survey 多把資安當附帶應用，缺標準化 benchmark 實務與比較分析 [原文 p.1–2]。RQ1：eBPF 如何在不同運算環境實作資安機制；RQ2：eBPF 如何應對 DDoS、入侵偵測、流量分析等具體威脅 [原文 p.3]。
2. **回顧設計（取代 Architecture）**：PRISMA 2020 流程；兩位 reviewer 篩選、第三位處理衝突 [原文 p.3]；每篇依「主要研究目標」單一歸類，不依評估環境；telemetry 視為跨領域能力，不單獨成類 [原文 p.7]。
3. **處理位置（回顧對象的分布）**：以 kernel 內 hook 為主——XDP 早期過濾（DDoS 6/7、Networking 4/5、網路型 IDS 4/11 採用）、kprobe 系統呼叫追蹤（SLR 列出 12 篇受其併發上限影響）、socket 層；「kernel 做特徵擷取、user space 做 ML」是 IDS 的主要型態（7/11 用 ML，只有 2/11 在 kernel 內推論）；硬體加速（SmartNIC、P4、DPDK）11/54 [原文 p.17]。tc/clsact/TCX、netfilter、NFQUEUE、conntrack 在全文中**完全沒有出現**（我 grep 過）。
4–6. **回顧範圍（取代 Hardware / Dataset / Baseline）**
   - 資料庫：Google Scholar 2810、ACM 514、IEEE Xplore 211、SpringerLink 166、Scopus 17、MDPI 17 [原文 Fig. 2 p.5]。
   - 年份：2018–2026（IC3：2018 起，因為「2018 是資安導向研究出現的年份」）[原文 p.4]。
   - 關鍵字：Appendix A 的布林式由 5 層以 AND 串接——技術錨（"extended Berkeley Packet Filter" OR "eBPF"）、19 個安全詞、觀測／效能詞、網路情境詞（5G, edge computing, SDN, service mesh…）、應用域詞（HPC, IoT, smart cities, blockchain）[原文 p.21–22]。依字面，論文必須同時命中這 5 層；技術錨沒有 "XDP"。
   - 納入／排除（IC1–6、EC1–8）：同儕審查、英文、2018 起、eBPF 為主要實作機制、有原創實證；排除 review、未審查文獻、eBPF 只是順帶提及、品質不足（無實證／細節不足／「低影響力」venue）、取不到全文、重複 [原文 Table 2 p.4]。
   - 流程：3735 → 移除 1089（重複 409、2018 前 127、非英文 66、非同儕審查 259、其他 228）→ 2646 篩標題摘要 → 排除 2267 → 379 取全文 → 23 取不到 → 356 評估 → 排除 302（review 5、品質評估 297）→ **54 篇** [原文 Fig. 2 p.5；p.5–6]。我驗算過各步驟加減，算術一致。
   - 組成：30 篇會議（55%）、23 篇期刊（43%）、1 篇書章（2%）[原文 p.6]。
7. **Metrics（回顧抽取的欄位）**：CPU overhead、偵測準確率、throughput、延遲，加上品質維度（評估環境、效能指標是否齊全、threat model、meta-security、可重現性、baseline、規模、對抗式 ML）[原文 p.19–20]。抽取表（含品質分數）「可向通訊作者索取」，沒有公開 [原文 p.22]。
8. **Limitations（作者承認）**：全文**沒有**針對這份回顧本身的「限制／threats to validity」章節（我 grep 過）。唯一與回顧本身有關的說明：2024–2026 篇數偏低歸因於資料收集時間與索引延遲 [原文 p.6]。§5.2 的 limitations 全是在講 eBPF 技術與被回顧文獻。
9. **Research Gap**
   - 作者自述：eBPF meta-security（52/54 未處理）、multi-tenant 隔離（47/54 未處理）、對抗式 ML 穩健性（所有 ML 研究皆無）、production 驗證、可重現性、標準化評估框架與 production 規模 benchmark、verifier 對複雜安全邏輯的支援、in-kernel ML primitive、跨平台可移植抽象 [原文 p.20–21]。
   - [推測] 回顧沒涵蓋 tc/netfilter/NFQUEUE 這條「eBPF 與既有 user-space IDS 共存」的路徑，也沒有任何 ARM／單板電腦的資料（「Raspberry」0 次，ARM 只在兩處一句帶過 [原文 p.18, p.20]）。

## D. 補充欄位（SLR 版）

### D5. 回顧本身的可信度

**做得好的地方：** 搜尋式全文公開、PRISMA 各步驟數字公開且算術自洽、準則有編號、54 篇清單附參考文獻 [原文 p.4–9, p.21–24]。

**可信度疑慮（皆為我的核對，作者未承認）：**
- 沒有協定登記（PROSPERO/OSF）、沒有 snowballing、沒有 reviewer 間一致性（kappa）、沒有公開的品質評分量表。297 篇因「品質」被排除，是最大的一步，但判準只寫「缺實證／細節不足／低影響力 venue」[原文 p.4]。
- 彙總值無法重算：抽取表不公開，且「2.4% [1.1–8.6%]」的括號沒定義（摘要同時寫 hot path 為 10–20%，所以括號不是 min–max）[原文 p.1]。
- 內部不一致：

| 項目 | 一處寫 | 另一處寫 | 位置 |
|---|---|---|---|
| 年度篇數 | 2019 有 7、2021 有 11 | Table 3–4 逐列計數為 6 與 12 | p.6 vs p.8–9 |
| 品質排除數 | 297 | 293／300 | Fig. 2 p.5 / p.3 / Table 2 p.4 |
| production 驗證缺口 | 81.4%（44/54） | 87%（47/54） | Table 7 vs Table 8、結論 p.20–21 |
| 無公開程式碼 | 62.9%（34/54） | 66.6%（36/54） | 同上 |
| 無 baseline | 25.9%（14/54） | 27.7%（15/54） | 同上 |
| 微服務去中心化 | 83.3%（5/6） | 71%（5/7） | p.16 vs p.21 |
| 容器 observability-first | 50%（5/10） | 60%（6/10） | p.16 vs p.21 |
| 「可重用框架」的 5 篇 | [26][45][50][53][51] | [26][44][48][51][53] | p.17–18 vs p.20 |
| 處理 eBPF 自身攻擊面的研究 | [59] 與 [56] | [59] 與 [39] | p.18 vs Table 7 p.20 |
| 資料庫 | Table 2 的 IC6 列 ScienceDirect | §3.3 列 Google Scholar（無 ScienceDirect） | p.4 |

- 「94–99% 準確率」不是所有研究的範圍：同文 [38] 的流量式偵測只有 87.49% [原文 p.13]。
- 引用編號錯位：§4.5（微服務）和 §4.3.2/4.3.4（IoT）的敘述與 Table 3–4 的標題對不上。例如 §4.5.1 說 [42][43][44] 做 service mesh 的 mTLS／rate limiting，但表中這三篇是狀態機異常偵測、安全度量、µDetector；eZTrust 在表中是 [25]，文中寫成 [45]；Kmon 在表中是 [46]，文中寫成 [25] [原文 p.14 vs p.8–9]。→ 這幾節的「N 篇中有 M 篇…」統計（如微服務 5/6）不可直接採用。[推測] 描述並非逐篇精讀。
- 納入準則執行不一致：[30]（SDN smart city）文中自稱 survey（「The survey identifies…」）[原文 p.12] 應被 EC1 排除；[31] 的 DOI 是 Research Square 預印本（10.21203/rs.3.rs-…/v1）[原文 p.23]，應被 EC4 排除；[20] Spectre 在文中描述的是 eBPF JIT 成為攻擊面 [原文 p.11]，不是以 eBPF 實作的防禦機制；[61] Aeolia 是儲存堆疊（文中自稱「extending beyond security」）[原文 p.16]。
- 抽查原始論文，發現轉述有誤：SLR 說 Scholz 等人 [51]「XDP 吞吐提升最多 45%，但延遲更差」[原文 p.15]。我讀原文（https://www.net.in.tum.de/fileadmin/bibtex/publications/papers/ITC30-Packet-Filtering-eBPF-XDP.pdf）：45% 是**在 XDP 丟包範例中開啟 eBPF JIT 相對於不開**的提升（10 Mpps），不是 XDP 相對 iptables／nftables。SLR p.19 說「[51] 可降低 40–60% false positive」，原文沒有 false positive 的討論（grep 為 0）。
- 資料庫分布與參考文獻不符 [推測]：Fig. 3 / p.6 寫 MDPI 2 篇、SpringerLink 4 篇，但參考文獻清單中 MDPI 期刊至少 4 篇（[24][27][37][47]）、Springer 系至少 8 篇（[8][14][18][19][22][29][34][57]）；可能是「資料庫」與「出版社」口徑不同，作者沒說明。
- 重現性：搜尋式與清單可重現；抽取與篩選紀錄僅「依合理要求提供」，無公開 repo [原文 p.22]。

### D6. 移植到 Pi 4 的障礙

- 回顧提供的可移植性資訊只有：功能的 kernel 門檻（XDP ≥4.8，16/54；bounded loops ≥5.3，9/54；BTF/CO-RE ≥5.2，12/54），LTS kernel 有 2–4 年部署落差 [原文 p.19]；「ARM／MIPS／x86 異質性」一句話，無數據 [原文 p.18]。
- 回顧的效能結論（XDP 10–1200 Gbps、median 1.8%）來自 native XDP、SmartNIC 或伺服器環境 [原文 p.17]。全文沒有 generic XDP／driver 支援／skb mode 的討論（grep 為 0）。
- Pi 4 的限制（兩個 port 都無 native XDP、Pi OS kernel 無 BTF）來自本子題的平台前提（SPEC_ADDENDUM），我沒有獨立驗證。[推測] 在此前提下，回顧中依賴 native XDP、SmartNIC、CO-RE 的結論都不能直接搬；它的百分比 overhead 也不能和我們的 µs/封包數字比較（基準硬體、算法不同）。

### D9. 值得追的原始論文（≤8 篇）

只列回顧語料裡、且貼近「低資源 gateway 上可擴充 eBPF 安全框架」的原始論文。Polycube [45]、MiddleNet [50]、PALANTIR [24] 已在 `unread_paper_list.md`，不重複列入。

| # | 書目 | 回顧怎麼描述 | 為什麼值得讀 | 存在確認 |
|---|---|---|---|---|
| 1 | Wang & Chang, "Design and implementation of an intrusion detection system by using Extended BPF in the Linux kernel," J. Netw. Comput. Appl. 198:103283 (2022) | kernel 內 eBPF 模式比對先濾掉無關封包，user space 做完整規則分析；用修改過的 Snort 規則，吞吐最高 3× Snort [原文 p.10]（SLR 說，未驗證） | 回顧語料裡唯一「eBPF 前置過濾 + user-space 規則式 IDS」的先例，最接近我們的 eBPF→NFQUEUE→Suricata；要查預過濾是否損失偵測力、硬體、規則集 | 已確認 DOI 與標題（Crossref）；全文被 ScienceDirect 403，未讀 |
| 2 | Scholz et al., "Performance Implications of Packet Filtering with Linux eBPF," ITC 30, 2018, DOI 10.1109/ITC30.2018.00039 | XDP 吞吐最高 +45% 但延遲較差 [原文 p.15]——**轉述有誤**，見 D5 | 我讀了摘要與實驗設定、結果段落：MoonGen、10 GbE 直連、64 B、奈秒硬體時間戳、以 iptables／nftables 為 baseline、延遲百分位。可作量測方法範本（但硬體是 x86 10 GbE） | 已確認（開放 PDF，部分段落已讀） |
| 3 | Magnani, Risso, Siracusa, "A Control Plane Enabling Automated and Fully Adaptive Network Traffic Monitoring With eBPF," IEEE Access 10:90778 (2022), DOI 10.1109/ACCESS.2022.3202644 | 依使用者需求調整管理與資料擷取、吞吐下降極小、記憶體更省 [原文 p.16] | 「使用者只定義監控邏輯、控制面自動生成」與我們「框架只定描述語法」同向；摘要稱吞吐僅降 0.15%、比 nProbe 等快約 20× [二手 https://iris.polito.it/handle/11583/2972688] | 已確認（Crossref；摘要見 IRIS 頁），全文未讀 |
| 4 | Tian et al., "LBM: A Security Framework for Peripherals within the Linux Kernel," IEEE S&P 2019, pp. 967–984 | 統一 API 的 eBPF 安全框架，提供高階語言寫過濾機制，每封包約 1 µs overhead [原文 p.10] | 語料中少數「框架」型：API／語言／模組模型怎麼設計、如何載入與串接可對照 G1/G2；對象是週邊裝置而非網路 | 已確認（S&P 論文 PDF 存在；二手搜尋結果），全文未讀 |
| 5 | He et al., "Cross Container Attacks: The Bewildered eBPF on Clouds," USENIX Security 2023, pp. 5971–5988 | eBPF 的追蹤功能可被容器內攻擊者濫用；提出 CapBits 權限模型 [原文 p.13] | 我們讓使用者 eBPF 外掛掛任何掛點、可 drop／redirect；這篇是「eBPF 本身是攻擊面、權限怎麼限」的主要依據，回顧說僅 2/54 處理此事 | 已確認（USENIX 頁面） |
| 6 | Nam et al., "Secure Inter-Container Communications Using XDP/eBPF," IEEE/ACM ToN 31(2):934–947, DOI 10.1109/TNET.2022.3206781 | 每容器的 XDP/eBPF 強制堆疊，eBPF map 共享政策，可串接 DPI 等安全功能，附 policy assistant；單機／跨機通訊效能 +25.4%／+17.7% [原文 p.13] | 「map 放政策 + 安全功能串接 + 政策輔助」與我們的 pipeline 與擴充設計有對應；注意 ToN 卷期為 2023，SLR 寫 2022 | 已確認（IEEE／KAIST 紀錄），全文未讀 |
| 7 | Bertoli et al., AB-TRAP: "An End-to-End Framework for Machine Learning-Based Network Intrusion Detection System," IEEE Access 9:106790 (2021), DOI 10.1109/ACCESS.2021.3101188 | 資料集生成→訓練→實作→部署後評估；eBPF 做高吞吐封包擷取與即時模型更新 [原文 p.10] | 在單板電腦上做端到端並含「部署後評估」，是最接近 Pi 級硬體的一篇；搜尋摘要稱單板電腦 user space 約 1.4% CPU、3.6% RAM [二手 IEEE Access 摘要，未讀全文] | 已確認 DOI 與標題；eBPF 的使用方式未從原文確認 |
| 8 | Serror et al., "Towards In-Network Security for Smart Homes," ARES 2018, DOI 10.1145/3230833.3232802 | 列在 IoT 類 [原文 p.8] | 我讀了摘要、eBPF 段落與章節結構：家用路由器做規則式過濾 + 異常偵測的**設計空間**論文，eBPF 與 P4 是兩個備選；因路由器資源有限，監控只看標頭、長度與週期。**沒有評估章節**（章節為 Intro、Problem Analysis、Specification、Traffic Filtering、Anomaly Detection、Conclusion），可用於 gateway 成本論述，不可當實證 | 已確認（Crossref；PDF 部分已讀） |

## G. SLR 專屬欄位

**G1 分類法。** 七類（見 G2 表），以「主要研究目標」單一歸類，各類下再依機制分小節 [原文 p.7–16]，例如 DDoS 分 signature 過濾、軟硬體混合、應用層防禦、SDN 緩解；Container 分執行期稽核、異常偵測、政策自動化、exploit 評估、meta-security；Tools & Frameworks 分隱寫偵測、zero-trust、靜態分析／驗證、自適應控制等；IDS 不分小節。另有橫向模式（Table 5、§4.8）：syscall 監控、XDP 早期過濾、ML–eBPF 共生、硬體–軟體共設計、去中心化、observability-first。

**G2 每類篇數與代表論文**（篇數為我逐列計數 Table 3–4，與 p.7 一致；引用號為 SLR 的參考文獻編號）

| 類別 | 篇數 | 代表論文 |
|---|---|---|
| IDS | 11 | [15] eBPF 前置過濾 + Snort；[16] LBM；[17] AB-TRAP；[21] PortCatcher；[23] Kalium；[24] PALANTIR |
| Container | 10 | [32] saBPF；[35] Seccomp 自動化；[37] cryptojacking；[39] CapBits；[40] P4Control；[41] Bastion |
| Tools & Frameworks | 9 | [53] 隱寫偵測；[54] SysFlow；[56] 靜態分析；[58] K2；[59] HyperBee；[60] 自適應控制面 |
| DDoS | 7 | [8] signature + XDP；[9] SYN flood ML + XDP；[10] SmartNIC + XDP；[12] Coda；[13] FineLame |
| IoT | 6 | [26] CFPA 證明；[28] 智慧家庭 in-network security；[29] IoT 惡意程式沙箱 |
| Microservices | 6 | [44] µDetector；[45] Polycube；[46] Kmon；[47] AI-IDS（XDP + 神經網路） |
| Networking | 5 | [48] TCP Path Changer；[49] TANGO；[50] MiddleNet；[51] Scholz；[52] DNS 隱私 |

**G3 與 gateway／封包處理／IDS 整合／框架最相關的類別。**
- IDS 與 Networking 最相關。SLR 概括 eBPF IDS 「主要是 pattern-matcher 與 packet inspector」[原文 p.18]；與 user-space IDS 整合的證據只有 [15]（Snort）一篇，另有「eBPF 擷取特徵 → user-space ML」的模式（7/11）[原文 p.17]。
- 框架抽象相關：Tools & Frameworks 的 [60]、Networking 的 [50]、Microservices 的 [45]、IDS 的 [16]。SLR 稱只有 5/54（9.2%）提供可重用框架或高階抽象，「沒有跨類別的主導框架」[原文 p.17–18, p.20]；但五篇清單前後不一致，且含 [51] 這種效能研究（見 D5），這個數字要保守引用。
- 安全模型相關：Container 的 [39]、Tools 的 [59]、[56]；回顧稱只有少數幾篇觸及 eBPF 自身攻擊面（哪幾篇前後不一致，見 D5）[原文 p.18, p.20]。
- 通訊成本：SLR 引用 map 更新每次 5–20 µs、hybrid ML 0.5–2 ms [原文 p.19–20]，但其引用的 [31][32][37] 與內容對不上（[31] 是光通訊 BAN 論文），數字不可信。

**G4 作者列出的研究缺口。** 見 C-9 [原文 p.20–21]。引言另指出既有 survey 缺「安全用例比較」「標準化 benchmark 實務」「可解釋偵測與 AI 輔助 in-kernel 分析」[原文 p.2]。

**G5 回顧本身的限制。**
- 作者承認：2024–2026 篇數偏低是索引延遲 [原文 p.6]。
- [推測] 召回率偏低：技術錨只有 "eBPF"，沒有 "XDP"；5 層 AND 要求同時命中 IoT／HPC／smart cities／blockchain 之一；只有同儕審查文獻，排除預印本與白皮書；297 篇被「品質」排除，判準不透明。這些會讓「gateway 類 eBPF + IDS」的工作更可能被漏掉。回顧沒有 tc／netfilter／NFQUEUE／Suricata 的內容，**不代表文獻中沒有**。
- [推測] 精確率與可靠度：納入準則執行不一致、引用錯位、對原始論文的轉述有誤（D5）。
- 每篇只歸一類，跨領域資訊被壓縮（作者在 p.7 說明，p.18 以 Table 5 補）。

**G8 與我們設計的對照。**
- 已有前例、不可宣稱為新：eBPF 早期過濾 + user-space 規則式 IDS 分工（[15]）；XDP 當早期過濾（DDoS 6/7）；eBPF 當特徵／遙測擷取（7/11 IDS）；自適應、可執行期重配置的 eBPF 監控（[60]、[22]）；eBPF 模組化安全框架與 API（[16]）；以 eBPF map 放政策、串接安全功能（[41]）。
- 回顧提到、我們尚未涵蓋 [推測]：eBPF 程式載入前的稽核或權限模型（[59] HyperBee、[39] CapBits）——我們目前是簽章 + doctor 揭露，沒有針對外掛 eBPF 能力的細粒度限制；回顧列的品質維度（threat model 明確、對傳統工具的 baseline、公開 artifact、部署驗證）可當我們評估的檢查表。
- 我們有、回顧語料罕見 [推測]：Pi 級 ARM 硬體上的實測；tc/TCX + nftables + NFQUEUE + conntrack 這條與既有 IDS 共存的路徑；雲端可選且不在封包路徑上。注意這些在回顧中「沒出現」，不等於「沒人做過」。
- 取捨衝突：回顧稱 XDP 是高速封包安全的「de facto standard」[原文 p.17]，我們預設不用 generic XDP、只在 native 時才掛 XDP，需要說明理由——回顧的 XDP 數據都隱含 native／SmartNIC 環境，在 Pi 4 不成立。回顧的「% CPU overhead」與我們的「µs／封包」是不同指標，不能互比。

**G9 對碩士論文的用途（≤5）**
1. 動機：回顧報告可重用框架僅 5/54、無主導框架 [原文 p.17–18]，支持「可擴充框架」的缺口論點；引用時註明這是 SLR 的歸納、前後清單不一致。
2. 評估檢查表：用 Table 8 的維度（效能指標齊全、threat model、baseline、公開 artifact、規模、部署驗證）檢查自己的實驗設計 [原文 p.20]。
3. 設計理由：verifier／指令數限制（stack 512 B、指令 4K–1M）[原文 Table 6 p.20] 支持「複雜檢測交給 Suricata、kernel 內只做輕量分類」；kernel 版本碎片化支持 doctor 的版本與能力檢查。
4. 安全模型：52/54 未處理 eBPF 自身安全 [原文 p.20]，支持把外掛信任邊界與揭露機制寫成設計貢獻；配合 D9 #5。
5. 相關工作定位：用七類分類法說明本研究落在 IDS + Networking + Tools & Frameworks 的交集。**不要**引用回顧的彙總數字（2.4%、94–99%）當事實，要引就回到原始論文。

## E. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| 篩選漏斗 | 3735→2646→379→356→54 | 6 資料庫，2018–2026 | [原文 Fig. 2 p.5] |
| 各類篇數 | IDS 11、Container 10、Tools 9、DDoS 7、IoT 6、Microservices 6、Networking 5 | 單一歸類 | [原文 p.7；Table 3–4 p.8–9] |
| 年度篇數（表格計數） | 2018:3、2019:6、2020:6、2021:12、2022:9、2023:12、2024:2、2025:3、2026:1 | 與 p.6 文字（2019:7、2021:11）不同 | [原文 Table 3–4 p.8–9；p.6] |
| CPU overhead | 中位數 2.4%，[1.1–8.6%] | 「average CPU usage」；各研究硬體與負載不同；括號定義不明 | [原文 p.1] |
| 類別 overhead 中位數 | Container 3.1%、Microservices 4.7%、Networking 1.2%、DDoS 1.8% | 同上 | [原文 p.18] |
| XDP 路徑 | 10–1200 Gbps、median 1.8% | native XDP／SmartNIC 研究 | [原文 p.17] |
| 簡單過濾 vs 完整功能 | <1% vs 3–6% | ML、多階段、payload 檢查 | [原文 p.18, p.20] |
| 偵測準確率 | 94–99%；XGBoost 99.98% [18]；RNN 99.75% 且延遲 +2.98% [37]；流量式 87.49% [38] | 各研究資料集不同 | [原文 p.1, p.10, p.13] |
| in-kernel ML | 2/11（18.2%）；其餘 9/11 在 user space，0.5–2 ms | | [原文 p.17, p.19] |
| map 更新成本 | 5–20 µs／次；>10K 次／秒成為瓶頸 | 引用編號與內容不符，不可信 | [原文 p.19–20] |
| eBPF 前置過濾 + Snort | 最高 3× 吞吐 | SLR 轉述 [15]，未驗證 | [原文 p.10] |
| LBM | 約 1 µs／封包 | SLR 轉述 [16]；二手搜尋結果（S&P 摘要）一致 | [原文 p.10] |
| Bastion | 單機 +25.4%、跨機 +17.7% | SLR 轉述 [41]；二手搜尋結果（ToN 摘要）一致 | [原文 p.13] |
| kernel 門檻 | XDP ≥4.8（16/54）、loops ≥5.3（9/54）、BTF/CO-RE ≥5.2（12/54） | | [原文 p.19] |
| eBPF 限制（受影響篇數） | stack 512 B 5/54；指令 4K–1M 20/54；記憶體 11/54；迴圈 8/54；helper 15/54；syscall 15/54 | | [原文 Table 6 p.20] |
| 品質缺口 | testbed-only 47/54；缺 CPU／記憶體／延遲 23/54；threat model 缺 23/54；無公開程式碼 36/54；無傳統工具 baseline 15/54；規模過小 50/54 | Table 7 的對應值略不同，見 D5 | [原文 Table 8 p.20] |
| 評估規模 | 10–100 容器、1–100 Gbps、1K–1M flows；雲端導向 31/54（57.4%）；Linux 專用 | 合成流量與 benchmark 應用為主 | [原文 p.20] |
| production 部署 | 7/54（12.9%） | | [原文 p.21] |
| 抽查 Scholz [51] | JIT 開啟 +45%（10 Mpps）；MoonGen、10 GbE、64 B | XDP 丟包範例；JIT 開 vs 關 | [Scholz 原文 §V-B，我讀過] |

## F. 自評

**未能確認的欄位：** (1) 圖（Fig. 1、3–7）的數值沒有從文字層取得，只用文字敘述與 Table 3–4 的計數交叉驗證；(2) 期刊版與 arXiv 版的圖片與表格版面沒有逐格比對；(3) D9 的 #1、#3–#7 只確認存在與書目，沒有讀全文（#1 被 ScienceDirect 403 擋住，我沒有嘗試繞過）；#2、#8 只讀部分段落；(4) D6 的 Pi 4 硬體限制引自子題規格，非我驗證。

**最不確定的三件事：**
1. 這份回顧的內容品質：我找到不少內部不一致、引用錯位與一例轉述錯誤（Scholz），但只抽查了 2 篇原始論文，所以不知道錯誤的整體比率。是否因此降低引用價值，需要使用者決定；我的建議是把它當「分類法與缺口清單的來源」，不要引它的彙總數字。
2. 「§4.3、§4.5 的描述與表格標題對不上」是我依 Table 3–4 與參考文獻清單比對的結論；也可能是作者故意用別的編號，但同一份文件內互相矛盾仍然成立。
3. 召回率推論（技術錨沒有 XDP、第 5 層 AND 過窄）依搜尋式字面；各資料庫實際如何解析（Appendix A 說只有欄位語法的小調整 [原文 p.22]）我無法確認，所以「漏掉 gateway 類研究」是推測，不是已證事實。
