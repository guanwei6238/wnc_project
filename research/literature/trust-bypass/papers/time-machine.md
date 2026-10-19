# Time Machine（Kornexl et al., IMC 2005）

證據標記沿用規格。因為要同時引用兩篇，頁碼前加前綴：`K p.N` = Kornexl IMC'05（USENIX 版頁碼 267–272），`M p.N` = Maier SIGCOMM'08（頁碼 183–194）。`[計算]` = 我用論文數字自己算的。全文 PDF 已下載至 `research/literature/trust-bypass/pdfs/time-machine/`，並以 `pdftotext` 讀過兩篇全文。

## A. 書目與取得狀況
- 標題：Building a Time Machine for Efficient Recording and Retrieval of High-Volume Network Traffic
- 作者：Stefan Kornexl, Vern Paxson, Holger Dreger, Anja Feldmann, Robin Sommer [原文 K p.267]
- 年份／出處：2005，Proc. ACM SIGCOMM Internet Measurement Conference (IMC)，USENIX Association 出版，pp. 267–272 [原文 K p.267–272]。Maier 2008 的參考文獻 [15] 把它標為「Short Paper」[原文 M p.194]（全文僅 6 頁，與此吻合）。
- DOI：10.1145/1330107.1330137（OpenAlex 記錄；doi.org 可解析，已確認存在）。
- URL：https://static.usenix.org/event/imc05/tech/full_papers/kornexl/kornexl.pdf ；摘要頁 https://www.usenix.org/conference/imc-05/building-time-machine-efficient-recording-and-retrieval-high-volume-network
- 與給定資訊的差異：作者、年份、會議皆正確，無差異。僅補充兩點：它是 6 頁 short paper；Time Machine 並非「論文提出的規則/偵測」系統，而是封包錄製/檢索系統（下文會影響相關度判斷）。
- Maier et al. 書目（D9 要求）：Gregor Maier, Robin Sommer, Holger Dreger, Anja Feldmann, Vern Paxson, Fabian Schneider，"Enriching Network Security Analysis with Time Travel"，SIGCOMM '08（Seattle, Aug 17–22, 2008），pp. 183–194，ACM ISBN 978-1-60558-175-0/08/08 [原文 M p.183]。DOI：會議論文集 10.1145/1402958.1402980；CCR 38(4) 版 10.1145/1402946.1402980（兩者 doi.org 皆可解析，OpenAlex 的頁碼與作者一致）。給定資訊正確，但**作者有六位**（含 Schneider）。全文已取得（https://www.icir.org/gregor/papers/sigcomm08-tm.pdf）。
- 取得程度：**全文**（Kornexl 與 Maier 皆是）。

## B. 核心貢獻
1. 提出「每條連線只記前 N bytes（cutoff）」的錄製策略，利用流量 heavy-tail：多數連線很短、少數大連線佔大部分 bytes [原文 K p.267]。
2. 以三個 Gbps 站點（MWN、LBNL、NERSC）的 Bro 連線日誌做 packet-buffer 模擬，並在 LBNL 實機運行兩週：20 KB cutoff + 90 GB 可保留 TCP 3–5 天 [原文 K p.268, 272]。
3. 架構：capture → classification（BPF class + cutoff 追蹤）→ 記憶體/磁碟雙 ring buffer → 時間區間索引 → 查詢，並以一次 LBNL 入侵事件的事後鑑識作為實用性證據 [原文 K p.270–272]。

## C. 指定的 9 項
1. **Research Problem**：高流量環境無法整條串流全錄，靜態 tcpdump filter 必須事先決定「什麼會變重要」，產生盲點（LBNL 的 filter 有 85 項，只留約 4% 流量）[原文 K p.267]。目標是保留數天近乎完整的歷史封包，供事後鑑識與除錯。
2. **Architecture**：單機被動旁路（tap）。`Tap → libpcap/BPF → Capture → Classification(class 與 cutoff) → Storage Container(RAM ring + Disk ring) → Index(時間區間) → Query` [原文 K Fig.5, p.270–271]。沒有 Edge/Cloud 分工，也沒有 flow record。UI/查詢執行緒與錄製執行緒分離，錄製優先 [原文 K p.270]。
3. **Processing Location**：全在 user space（libpcap），僅用 kernel BPF 預先過濾 [原文 K p.270]。cutoff 是 user space 查 hash table 後丟棄封包 [原文 K p.271]。後續論文才計畫把 cutoff 下放到 kernel 或 FPGA（Shunt）[原文 M p.194]。
4. **Hardware**：IMC'05 論文只給設計目標「PC，2 GB RAM、500 GB 磁碟」[原文 K p.268]；實際部署主機規格論文未說明。（Maier 2008：MWN 為雙 AMD Opteron 244 1.8 GHz、4 GB RAM、Endace DAG 1 Gbps；LBNL 為 FreeBSD、雙 dual-core Pentium D 3.7 GHz、Neterion 10 Gbps NIC [原文 M p.186]。）無任何 ARM/低功耗平台。
5. **Dataset**：三個站點各一週的 Bro 連線摘要日誌：MWN 3.55 億筆（2004-10-18 起）、LBNL 2200 萬、NERSC 400 萬（2005 年）[原文 K p.269]。真實校園/研究所出口流量，非 IoT；是否公開論文未說明（含真實使用者，[推測] 不公開）。
6. **Baseline**：與「無 cutoff、只靠逾時淘汰的 bulk recording」比較（模擬，Te = 3 h）；沒有與其他系統在同硬體上重跑。商用錄製器因黑箱未比較 [原文 K p.268]。
7. **Metrics**：緩衝區所需體積（GB）、保留天數、被丟棄流量比例、儲存寫入速率、libpcap 丟包率 [原文 K p.269–272]。**沒有**偵測率、轉送效能、CPU、延遲的量測。
8. **Limitations（作者承認）**：連線日誌由 SYN/FIN 序號差推算大小，長連線漏 SYN/FIN 或超過 4 GB 時繞回，會**低估** heavy-tail [原文 K p.269]；模擬假設連線速率均勻 [原文 K p.268]；MWN 只做初步測試、NERSC 未實測 [原文 K p.272]；MWN 因 HTTP 較多、heavy-tail 較弱而需更積極的分類與 cutoff [原文 K p.272]。**論文完全沒討論 cutoff 之後的盲點或規避**（全文無 evasion/blind spot 相關段落，grep 確認）。
9. **Research Gap**：作者自述——加入遠端介面讓 NIDS 做即時查詢 [原文 K p.272]（即 Maier 2008 的工作）。[推測]——(a) 沒有任何偵測品質量測；(b) 「開頭最重要」無實證（見 T4）；(c) 狀態表在 flood 下的行為；(d) 無低資源/IoT 場景。

## D. 補充欄位
**D1. 與主題對照**
- C1 封包處理 △：libpcap + BPF + hash table 計 bytes，有 cutoff 但非高效能 packet path。
- C2 Flow 收集 △：以連線為單位計數與索引，但儲存的是原始封包而非 flow record；Maier 才提到「淘汰後聚合成 flow」為未來工作 [原文 M p.194]。
- C3 雲端卸載 ×：無雲端。
- C4 降成本 ○：核心就是降低儲存體積（98% 被丟棄，LBNL）[原文 K p.272]。
- K1 轉送效能 ×：被動 tap，未量測任何轉送 throughput/latency。K2 資料完整性 △：只以「保留多少連線完整」衡量，無偵測力量測。K3 即時性 ×（IMC'05）；Maier 量了查詢延遲，非偵測延遲。

**D2. 卸載與資料**：IMC'05 中沒有「送出」這件事，只有本地保留/丟棄；保留的是原始封包（含 payload）。決策者是靜態 class 設定 + 每連線 byte 計數；沒有信心值。體積縮減見 E 表（LBNL 實機 98% 丟棄）；偵測力損失**未量測**。

**D3. 成本記帳**：磁碟/RAM 預算與寫入速率有 [原文 K p.272]；CPU（Maier 才有）、能耗、傳輸頻寬、雲端皆無。time-to-detection 無。

**D4. 偵測方法與威脅模型**：本身不偵測，服務事後鑑識，需要 payload [原文 K p.268]；加密流量論文未說明。[推測] 成本模型（per-connection byte counter + 逾時）可套到 Suricata/Snort，因為兩者本來就維護 per-flow 狀態；但 TM 的 cutoff 作用於**錄製**而非**偵測**，語意不同（見 T6）。

**D5. 實驗可信度**：連線日誌驅動模擬（速率均勻假設）+ LBNL 兩週實機單次運行；無重複、無信賴區間、無 ablation（只比 10/20 KB 與 Te）。程式碼：Zeek 社群頁稱 TM 為開源（zeek/time-machine，BSD）[二手 https://old.zeek.org/community/time-machine.html、https://openhub.net/p/timemachine]，我未驗證能否編譯。資料 [推測] 不公開。

**D6. 移植障礙**：[推測，未驗證] cutoff 計數與 hash table 在 Pi 3B+ 上成本應很低；真正限制是 SD/USB2 儲存寫入與 1 GB RAM 能放的 ring buffer。論文無 XDP/eBPF 依賴（kernel/FPGA 化僅是 Maier 的未來工作 [原文 M p.194]），故不涉及 native XDP 支援問題。

**D7. 六個假說方向（只列本論文證據）**
- Edge–Cloud IDS 分工：無雲端；僅 Maier 有「便宜啟發式先找可疑池、再對小池昂貴分析」的兩層概念 [原文 M p.183]（無數據）。
- Flow Feature Compression：無關（封包級保留）；聚合為 flow 僅為 Maier 未來工作 [原文 M p.194]。
- Dynamic Flow Monitoring：Maier 支持（動態解除 cutoff、改 class，見 T3）；IMC'05 無。
- XDP-eBPF：無關。
- Cloud Data Offloading：無關；僅 Maier 顯示卸載後 NIDS CPU 40%→28% [原文 M p.191]。
- 不同硬體限制：無證據，只有 Gbps 級 PC。

**D8. 可借用與可改進**
可借用：(1) per-connection byte counter + hash table，單包/未完成連線用較短 inactivity timeout 以抗掃描/DoS [原文 K p.271]；(2) class 化（BPF 篩選 + 各自 cutoff/預算）[原文 K p.270–271]；(3) 用連線日誌與「速率均勻」假設快速模擬儲存需求 [原文 K p.268]——[推測] 可直接套 IoT-23 的 conn.log；(4) Maier：永遠保留 SYN/FIN/RST [原文 M p.193]。
可能改進（全部 [推測]）：
1. 量測「偵測所需的 byte 位置」：用有標記的攻擊 pcap 統計 Suricata alert 觸發於連線第幾 byte（基於：兩篇都沒有實證「開頭最重要」）。
2. cutoff 後保留隨機/週期抽樣窗口並量漏報（基於：Maier 自述隨機化與抽樣只是「計畫」[原文 M p.192]）。
3. 以 IoT 流量重算 CCDF 與 cutoff 曲線，掃描 1–20 KB 範圍（基於：兩篇只測 10/15/20 KB 且皆為校園/研究所流量）。
4. 信任表的容量上限與 flood 保護（基於：MWN 連線表 50 萬→3–4 百萬於 30 秒、耗盡記憶體 [原文 M p.192]）。
5. 本地 ring buffer 保留近期封包，雲端晚判時可回溯（基於：Maier 記憶體保留僅 169–421 秒 [原文 M p.187]，Pi 3B+ 1 GB 下會更短，需實測）。

**D9. 引用網路**（OpenAlex 2026-10 查詢：Kornexl 被引約 100 次、Maier 約 50 次；以 `filter=cites:` 列出後人工挑選）
Maier 2008 對 cutoff 的補充（已讀全文，簡述）：(a) 實機 15 KB cutoff，流量降至原本不到 6%、約 90% 縮減 [原文 M p.187]；(b) 明確寫出 cutoff 規避風險，是「fundamental limitation」[原文 M p.192]；(c) 加入 NIDS 驅動的動態解除 cutoff 與 host 重新分類 [原文 M p.189]；(d) 承認已被 cutoff 截斷的過去連線無法補救 [原文 M p.193]。

建議追加閱讀（≤5）：
1. Gonzalez, Paxson, Weaver, "Shunting: A Hardware/Software Architecture for Flexible, High-Performance Network Intrusion Prevention", ACM CCS 2007, pp.139–149, DOI 10.1145/1315245.1315264。理由：被 Maier 點名可實作 cutoff 的機制；NIDS 逐連線指示 forward/drop/divert，最貼近「判定後放行」。確認程度：DOI 已確認；內容僅看到二手摘要（https://www.osti.gov/biblio/993443），未讀全文。
2. Papadogiannakis, Polychronakis, Markatos, "Improving the accuracy of network intrusion detection systems under load using selective packet discarding", EUROSEC 2010, DOI 10.1145/1752046.1752049。理由：在 Snort 中專注於各 flow 早期封包、丟棄次要封包——直接是「只看開頭」對偵測力影響的實證候選。確認程度：DOI 已確認，摘要已讀（FORTH 頁面），未讀全文。
3. Papadogiannakis et al., "Tolerating Overload Attacks Against Packet Capturing Systems" (Selective Packet Paging), USENIX ATC 2012, pp.197–202。理由：以隨機化抵抗攻擊者預測被保留的封包，對應抽樣防規避。確認程度：USENIX 頁面已確認並讀摘要。
4. Papadogiannakis et al., "Scap: Stream-Oriented Network Traffic Capture and Analysis for High-Speed Networks", IMC 2013, DOI 10.1145/2504730.2504750（OpenAlex 顯示其引用 Maier 2008）。理由：後續改進者，在 kernel 層早期丟棄不重要的串流。確認程度：DOI 與摘要已確認；cutoff 具體機制我只看到摘要的「早期丟棄」，未確認。
5. Gonzalez & Paxson, "Enhancing Network Intrusion Detection with Integrated Sampling and Filtering", RAID 2006, LNCS 4219, pp.272–289, DOI 10.1007/11856214_14。理由：標題直指 NIDS 的抽樣+過濾整合；確認程度：書目已確認（LNCS 4219 目錄 + OpenAlex），**內容未驗證**（Springer 全文被擋，未取得摘要）。

## T. 信任式 Fast Path 專屬欄位
**T1 放行判定**：不是「信任判定」，而是**純 byte 計數**：每條連線累計到 N bytes 後丟棄之後的封包 [原文 K p.268, 271]；模擬中以「連線超過 N bytes 的時刻」停止計入 [原文 K p.268]。N 是否計 payload 或整個封包 bytes，論文未說明。時點為第 N byte，與內容無關。Class 由連線第一個封包比對 BPF 決定 [原文 K p.271]。Maier 版本才有內容相關決策：NIDS 因告警而解除 cutoff 或改 class [原文 M p.189]。

**T2 放行後可見性**：Kornexl：cutoff 後的封包直接丟棄，**不保留**；計數條目留在 hash table 直到 inactivity timeout [原文 K p.271]。Maier：同樣丟棄，但**總是保留 SYN/FIN/RST** [原文 M p.193]；且即時 NIDS 與 TM 同看一條 tap，NIDS 本來就看全部流量 [原文 M p.189]——也就是 cutoff 只影響「錄製」，不影響 NIDS 的即時偵測。這是與我們構想最大的結構差異。

**T3 撤銷**：IMC'05 無（靜態設定，僅能由使用者改整體參數）。Maier 有：`suspend_cutoff`（逐連線）與 `set_class`（逐 IP，改為 15→50 KB 或無 cutoff）[原文 M p.186, 189]；兩週內發出 427 次 suspend、12,532 個 IP 進 scanners、592 個進 alarms [原文 M p.189]。已被截斷的過去資料無法補回 [原文 M p.193]。指令生效延遲論文未說明；查詢延遲（記憶體內）平均 125 ms、最大 539 ms [原文 M p.188]。

**T4 規避風險**：
- IMC'05：**完全未討論**。唯一的「攻擊在開頭」論述是無引用、無數據的斷言："very often for forensics and trouble-shooting applications the beginning of a large connection contains the most significant information" [原文 K p.267]；證據僅一個軼事——LBNL 一起入侵事件，因為保留了三天後才被調查的 HTTP 回應而得以診斷 [原文 K p.272]（該案例證明的是保留**時間**，不是攻擊在連線內的**位置**）。
- Maier 2008：同樣是斷言（「for many uses the beginning ... is the most interesting part」[原文 M p.184]），沒有量化攻擊在連線中的位置分布。但**明確承認**："if an attacker delays his attack to occur after the cutoff, the TM will not record the malicious actions" 且是「fundamental limitation」[原文 M p.192]。緩解手段：不同 class 不同 cutoff、依 NIDS 風險評估動態調 cutoff、**計畫**隨機化 cutoff 並對 cutoff 後的封包隨機抽樣——後者僅為計畫，無實作與漏報數字 [原文 M p.192]。
- 有一個實例顯示截斷確實發生：木馬下載的二進位在 15 KB 被截斷 [原文 M p.190]。
- 先乖後壞（trust 被刻意養成）：論文未直接討論。與狀態耗盡相關：flood 時連線表由約 50 萬增至 3–4 百萬（30 秒內），造成大量丟包並耗盡實體記憶體；攻擊者也可大量產生小連線縮短保留時間 [原文 M p.192]。
- 抽樣漏報率：無量測。
- 證據強度評語：對「攻擊集中在連線開頭」，兩篇都只有作者經驗斷言與少量軼事，**無對照實驗、無漏報率**；不能當作該前提的實證。

**T5 量化效益**：見 E 表。flows 與 bytes 分開：>90% 連線在 10 KB 內結束，卻只佔少量 bytes；20 KB 下約 12–15% 的連線（Kornexl，分母為連線日誌的全部連線）含 87%–99.86% 的 bytes。偵測損失：兩篇皆未量測。Maier 的 NIDS 卸載實驗中，TM+NIDS 與純 NIDS 結果相符，但查詢的連線是以固定機率 p = 0.01 隨機挑選，並非依可疑度，且基準本身也是 15 KB cutoff，因此不足以代表「偵測力不變」[原文 M p.191]。

**T6 對我們構想的直接意涵（[推測]）**
- 支持：bytes 被少數大連線主導，因此「對長連線只處理開頭」在**成本面**很有效（15 KB cutoff 後實機只剩 <6%，LBNL 兩週約 2.6% 的 bytes 被保留）。
- 無法支持：「開頭安全就能放行」在**偵測面**沒有證據；這兩篇的 cutoff 套用於錄製，NIDS 仍看全部。Maier 自己把 cutoff 後攻擊視為根本限制。
- 設計建議：(1) 不要只用固定 N，採 class 化 N，並讓偵測端能 per-connection 解除放行（Maier 的 suspend_cutoff 模式）；(2) 放行後永遠保留 SYN/FIN/RST 與 per-flow 計數，作為 flow record；(3) 抽樣不要可預測（採用 Maier 計畫的隨機化）；(4) 信任表需上限與逾時，並對單包連線用短逾時 [原文 K p.271]；(5) N 的選擇需在目標流量（IoT-23 等）上自己掃描，本論文只給 10/15/20 KB。

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| 超過 20 KB 的連線比例 | LBNL 12%、NERSC 14%、MWN 15% | 2004–05 各一週 Bro 連線日誌 | K p.269 |
| 這些連線所佔 bytes 比例 | MWN 87%、LBNL 96%、NERSC 99.86% | 同上；句意為「大於 20 KB 的連線之 bytes 佔比」，我的解讀 [推測] | K p.269 |
| 20 KB cutoff 實機丟棄比例 | LBNL 98%（平均）；MWN 約 85%（初步） | LBNL 兩週實機；MWN 初步測試 | K p.272 |
| LBNL 儲存負載 | 平均 300 KB/s、最大 2.6 MB/s；libpcap 丟包 0.016% | 20 KB cutoff，三 class 預算 90+30+10 GB | K p.271–272 |
| MWN 儲存負載 | 平均 3.5 MB/s、最大 13.9 MB/s | 同上，初步 | K p.272 |
| LBNL 模擬峰值體積 | 68 GB（Te=4 d, 20 KB）vs 64 GB（Te=3 h, 無 cutoff）；保留時間約 32 倍 | 連線日誌模擬 | K p.269–270 |
| NERSC 平均（峰值）體積 | 135 GB（344 GB）→ 7.7 GB（14.9 GB） | Te=4 d, 20 KB cutoff vs 無 cutoff | K p.270 |
| cutoff 減半的效益 | 峰值記憶體僅降 1.44（LBNL）、1.40（NERSC）、1.50（MWN）倍 | 20→10 KB | K p.270 |
| MWN 模擬 Te=4 d 峰值體積 | 20 KB 約 1000 GB 以上、10 KB 約 780 GB、無 cutoff 約 230 GB | **目視圖估計**，非文字數值 | K Fig.2 |
| LBNL 實機保留 | TCP 3–5 天（90 GB）；UDP 4–6 天（30 GB） | 20 KB cutoff | K p.268, 272 |
| 連線短於 10 KB／20 KB | 91–94%／94–96%（可完整保留） | 2007-11 日誌，全連線為分母 | M p.185 |
| 有 payload 的連線 | 44–48%；其中 10 KB 截斷 14–19%、20 KB 截斷 9–13% | 同上 | M p.185 |
| 4 天保留所需磁碟（10 KB） | LBNL 約 100 GB；MWN、UCB 1–1.5 TB | 模擬 | M p.185 |
| 15 KB cutoff 後剩餘流量 | 兩站點皆 <6%；MWN 約 90% 縮減 | 實機，10 秒平均 | M p.187 |
| LBNL 兩週聯合運行 | 22.7 TB（155 Mbps）→ 0.6 TB（約 2.6%）[計算] | 15 KB cutoff | M p.189 |
| TM 本身 CPU | MWN 平均 25%（最大約 85%）；LBNL 平均 5%（最大約 50%） | 見 A 中 Maier 硬體 | M p.187 |
| 實機丟包 | MWN <0.04%；LBNL <0.03% | 19／26 天 | M p.187 |
| 記憶體內保留 | MWN 平均 169 s（最短 41 s）；LBNL 平均 421 s | 750 MB／150 MB buffer | M p.187 |
| 查詢吞吐／延遲 | 約 120 queries/s；延遲平均 125 ms（σ 51，最大 539） | LBNL 記憶體內查詢 | M p.188 |
| NIDS 卸載 CPU | 40%（σ 9%）→ 28%（σ 7%） | 75 分鐘 21 GB HTTP trace、p = 0.01 | M p.191 |
| 動態控制次數（兩週） | 427 次 suspend_cutoff；12,532 IP→scanners；592 IP→alarms | LBNL，通知中 98% 為掃描 | M p.189 |

## F. 自評
- 未能確認：IMC'05 實際部署硬體、N 的 byte 計算口徑（payload 或整包）、`suspend_cutoff` 生效延遲、兩個資料集是否公開、TM 開源程式現況（僅 [二手]）。
- 最不確定的三件事：
  1. Kornexl p.269 的 87%/96%/99.86% 是「大連線的 bytes 佔比」而非「被丟棄比例」，這是我依句意的解讀；它與實機 98% 丟棄在同一站點（LBNL）看似不一致（96% 佔比理應給出低於 96% 的丟棄），論文未說明，可能與其自述的日誌偏差有關，我未能驗證。另外 Kornexl 的 12–15% 與 Maier 的 4–6%（>20 KB）相差約 3 倍，我用「Maier 分母含無 payload 連線」（44–48% × 9–13% ≈ 4–6%）調和，屬 [推測]。
  2. MWN 模擬體積（Fig.2）為目視估計，只可當量級參考。
  3. D9 的 Shunting、Scap、RAID 2006 只確認到書目/摘要層級，其內容與建議理由尚未以全文驗證。
