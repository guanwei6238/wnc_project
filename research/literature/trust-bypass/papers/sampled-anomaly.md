# Sampled-Anomaly（Mai et al., IMC 2006：抽樣資料夠不夠做異常偵測）

頁碼約定：`PDF p.N` 是作者主頁 12 頁 PDF 的頁碼；ACM 正式頁碼 = N + 164（IMC'06 pp.165–176）。標「讀圖」者為從渲染圖估讀的近似值（誤差約 ±0.02）。

## A. 書目與取得狀況
- 標題：Is Sampled Data Sufficient for Anomaly Detection?
- 作者：Jianning Mai, Chen-Nee Chuah (UC Davis), Ashwin Sridharan, Tao Ye, Hui Zang (Sprint ATL) [原文 PDF p.1]
- 年份／出處：ACM SIGCOMM Internet Measurement Conference (IMC) 2006，Rio de Janeiro，2006-10-25~27 [原文 PDF p.1 頁尾]；pp.165–176 [二手：OpenAlex W2117747231 的 biblio 欄位]
- DOI：10.1145/1177080.1177102 [二手：OpenAlex 與搜尋結果一致；PDF 內未印 DOI]
- 全文 URL：https://www.ece.ucdavis.edu/~chuah/rubinet/paper/2006/imc06-isand.pdf（作者主頁，合法）；本地：`research/literature/trust-bypass/pdfs/sampled-anomaly/imc06-isand.pdf`
- 與給定資訊的差異：無。作者、標題、年份、會議皆吻合。補充：同一套實驗的期刊姊妹篇為 JSAC 2006 "Impact of Packet Sampling on Portscan Detection"（見 D9）。
- 取得程度：**全文**（12 頁 PDF 逐頁抽文字，Fig. 5、6 以 300 dpi 渲染讀圖）。此 PDF 含 ACM 版權區塊與 IMC'06 頁尾、PDF 建立日 2006-09-07，應為 camera-ready，但未與 ACM 版逐字比對 [未能確認]。

## B. 核心貢獻（≤3 條）
1. 在同一組 Tier-1 backbone 封包 trace 上，以相同「被保留 flow 數」做正規化，比較 4 種抽樣（random packet、random flow、smart、sample-and-hold）對 3 個偵測器（wavelet 流量異常、TRWSYN、TAPS）的影響；結論是 random flow sampling 失真最小，smart 與 S&H 最差 [原文 §1 PDF p.2、§5.1 PDF p.10–11]。
2. 指出兩種根本偏差：(a) flow 到達序列的局部/全域變異數比被壓縮（抽樣變異數佔比隨取樣間隔升至約 80%，N=1000）；(b) packet sampling 的 flow shortening 把多封包 flow 切成單 SYN flow，造成 TRWSYN 的假陽性暴增 [原文 §3.2 PDF p.6、§4.1 PDF p.8–9]。
3. 量化各抽樣方式的偵測退化曲線（Table 3、Fig. 5、Fig. 6），並說明「以偏向大 flow 為目標設計的抽樣（smart、S&H）不適合異常偵測」，因為攻擊常由小 flow 組成 [原文 §5.1 PDF p.11]。

## C. 指定的 9 項
1. **Research Problem**：抽樣（NetFlow 類）原本為流量工程設計，抽樣後的資料是否保留足夠資訊做異常偵測（流量異常、掃描）未知 [原文 Abstract、§1 PDF p.1]。
2. **Architecture**：路由器端抽樣（packet / flow / smart / S&H）→ NetFlow 式 flow record（5-tuple，1 分鐘 timeout 或 TCP 語意結束）→ 離線偵測器 → 與「未抽樣 trace 上的偵測結果」比對 [原文 §2.1 PDF p.3、§2.5 PDF p.4–5]。無 edge/cloud 分工。
3. **Processing Location**：概念上在 backbone 路由器；實驗是由原始 trace 離線產生抽樣 trace [原文 §2.5]。工具、語言論文未說明。
4. **Hardware**：論文未說明（離線分析，無平台資訊）。
5. **Dataset**：Sprint IPMON 擷取，只含每封包前 64 bytes IP header，無 payload [原文 §2.4 PDF p.4]。BB-East（2003-04-07，207 Mbps，17 h，含已知 DoS，用於 wavelet）、BB-West（2003-03-08，55 Mbps，1 h，含大量掃描）、Wireless（2004-04-01，7 Mbps，3 h）[原文 Table 1 PDF p.4]（日期為論文原格式 04-07-2003 等，月日順序未能確認）。非公開資料集、非 IoT-23/CICIoT2023；是否可取得論文未說明；SaND 專案頁未列出程式碼或 trace [二手：https://www.ece.ucdavis.edu/~chuah/rubinet/projects/sand.html]。
6. **Baseline**：同一 trace 未抽樣時偵測器自己的輸出（流量異常 21 個 [原文 Fig. 1 PDF p.5]；TRWSYN Rs = 79.6% [原文 §4.1 PDF p.8]；TAPS Rs 約 0.86 [讀圖 Fig. 6a]）。四種抽樣互比。沒有與其他研究系統比。
7. **Metrics**：偵測到的流量異常個數；掃描 Success Ratio Rs、False Negative Rf−、False Positive Rf+（皆以「真實掃描者數」為分母，故 Rf+ 可大於 1）[原文 §4 PDF p.8]；被抽樣 flow 百分比與封包百分比 [原文 Table 2]。無 throughput/latency/CPU/RAM 實測。
8. **Limitations（作者承認）**：(a) 掃描者 ground truth 是手工清單的近似，只用於相對比較 [原文 PDF p.8]；(b) 版面限制，掃描結果只放 BB-West，Wireless「結果相似」但未呈現 [原文 PDF p.8]；(c) CPU/記憶體難以公平正規化，故改以「抽樣 flow 數」為共同尺度 [原文 §2.5 PDF p.4–5]；(d) 無法列舉所有偵測器，只選三個代表 [原文 Abstract]；(e) 流量異常未追究根因 [原文 §3 PDF p.5]。
9. **Research Gap**
   - 作者自述：需要同時顧及異常偵測與流量工程的抽樣技術；偵測演算法應對抽樣造成的資訊損失做補償；跨多個觀測點關聯低取樣率資料 [原文 §5.2 PDF p.11]。
   - [推測]：沒有 payload/規則式 IDS；沒有 IoT；沒有對抗式規避；沒有「已建立 flow 的流內時間抽樣」；沒有以封包/位元組/CPU 為尺度的成本正規化；沒有變異量。

## D. 補充欄位
**D1. 與研究主題對照**
- C1 封包處理 △：定性討論「只有 packet sampling 不需對每個封包做 flow table lookup，CPU 最低」[原文 §2.5 PDF p.5]，無實測。
- C2 Flow 收集 ○：整篇是「抽樣後的 flow record 是否夠用」。
- C3 雲端卸載 ×。C4 降成本 △：動機是降低路由器 CPU、記憶體、頻寬 [原文 §1、§2.1]，只用 % flows、% packets 當代理指標。
- K1 轉送效能：未量。K2 資料完整性：○，量了偵測損失。K3 即時性：未量延遲；僅提到 TAPS 的 time bin 控制決策速度 [原文 §2.3 PDF p.4]，TRW 約需 6 個事件（引用他人結果）[原文 §2.3]。

**D2. 卸載與資料**：無卸載。送到偵測器的是抽樣後 flow record。決定者是抽樣器：封包以固定機率 r，flow 以機率 p，smart 以 p(x)=x/z（x<z），S&H 以位元組機率 h 起始並「持有」之後所有封包 [原文 §2.1 PDF p.3]。資料縮減（BB-West，Table 2）：封包取樣 r=0.1→0.002 時保留 34.4%→1.73% 的 flow、10.0%→0.201% 的封包。偵測損失見 E。

**D3. 成本記帳**：地端 CPU/RAM/能耗、傳輸 bytes、雲端運算、time-to-detection 皆未量。僅 Table 2 的 % flows / % packets 可當代理。

**D4. 偵測方法與威脅模型**：統計/序列假設檢定，非 ML、非規則式。流量異常（DoS、flash crowd）用 db5 小波 12 層 DWT，高/中/低頻帶，視窗 1 分鐘，局部/全域變異數比門檻 4.5 [原文 §3 PDF p.5]；TCP 掃描用 TRWSYN（單 SYN 封包 flow 視為失敗連線，只能偵測 TCP）與 TAPS（目的 IP/port 分佈比 + 序列檢定）[原文 §2.3]。不需 payload。可否套到 Suricata/Snort：本文只在 §2.3 提到 Snort 以門檻 k 的掃描規則，[推測] 計數門檻型規則在抽樣下期望計數縮為 r 倍，會與 TRW/TAPS 一樣受 flow reduction 影響；但簽章比對（逐封包 content match、stream reassembly）完全不在本文範圍，成本模型不能直接套用。

**D5. 實驗可信度**：離線、真實 backbone trace，速率 7–207 Mbps；抽樣間隔 N ∈ {10,20,50,100,200,500,1000} [原文 §2.5]。重複次數、隨機種子、信賴區間皆論文未說明，Fig. 5/6 為單點曲線（Fig. 5a smart 在 N=10、20 約 0.70、0.71 的小起伏 [讀圖]，可能含隨機噪音，[推測]）。流量異常沒有獨立標註，以「原始 trace 上同一偵測器的輸出」為真值，故只能說明「抽樣後少偵測了多少」，不能說明偵測對錯 [原文 §3 PDF p.5]。TAPS 每個取樣點都用「使 Rs 最大的 time bin」，是用 ground truth 調參的上界 [原文 §4.2 PDF p.9]。trace 為 2003–2004 年單向 backbone 流量。Table 2 的 random flow p 在 6.91% 列印成 0.691，應是 0.0691 的筆誤 [推測]。

**D6. 移植到我們平台的障礙**：本文無硬體依賴，抽樣可離線重現；若要重現需自行取得 trace 與重寫偵測器（[推測]：論文無公開程式碼）。Pi 3B+ 上做封包隨機抽樣在原理上可用 nftables 隨機匹配實作 [推測，未驗證]；真正的障礙是本文不涵蓋 payload/IDS，結論只能類推。無 XDP/eBPF 內容。

**D7. 對六個假說方向的證據**
- Edge–Cloud IDS 分工：無關。
- Flow Feature Compression：部分支持。抽樣可視為有損壓縮；本文指出哪些特徵被扭曲（flow 數序列變異數、flow 大小分佈），哪些對抽樣不敏感（TAPS 用的 address range 分佈，§4.2 PDF p.10）。
- Dynamic Flow Monitoring：弱支持。TAPS 最佳 time bin 隨取樣間隔增大 [原文 §4.2 PDF p.9]，暗示取樣率改變時偵測參數要連動；本文未測動態調整。
- XDP-eBPF 省多少：無關。Cloud Offloading 成本-時效：無關。不同硬體限制：無關。

**D8. 可借用與可改進**
- 可借用：(1) 以「保留 flow 數」為尺度比較不同抽樣的做法與 smart/S&H 的參數換算式 [原文 §2.5]；(2) Rs/Rf−/Rf+ 定義 [§4]；(3) 抽樣變異數模型 σ²(p)=p²σ²+λp(1−p) 與「抽樣後偵測到的尖峰必存在於原始序列，故無假陽性」的論證 [原文 Eq.(2)(3)、§3.2 PDF p.6]；(4) 「抽樣率—最佳 time bin」掃描方法 [§4.2]。
- 可能改進（皆 [推測]）：
  1. 改以封包數/位元組為成本尺度重跑比較（基於 §2.5 作者自承 CPU 難正規化；見 T6 的 Table 2 換算）。
  2. 加入「已建立 flow 的流內抽樣」情境與「抽樣後才出現的攻擊封包」注入（基於 T4：論文無規避/晚發攻擊分析）。
  3. 在 Pi 3B+ 實測封包抽樣 vs 保持 conntrack 計數的 CPU/吞吐差（基於 D3：無成本量測）。
  4. 把 TRWSYN 類依賴「單 SYN flow」的推論，換成不受 flow shortening 影響的特徵或只在握手完成後抽樣（基於 §4.1 的 flow shortening 機制）。
  5. 以 IoT 資料集（IoT-23、CICIoT2023）重做（基於單一 backbone、無 IoT）。

**D9. 引用網路**（OpenAlex：本文被引 208 筆；cited-by 2015 年後共 72 筆，已逐筆瀏覽標題，僅對下列 5 篇讀摘要，未讀全文）
- **Brauckhoff 書目確認**：D. Brauckhoff, B. Tellenbach, A. Wagner, M. May, A. Lakhina, "Impact of Packet Sampling on Anomaly Detection Metrics", ACM IMC 2006, pp.159–164, DOI 10.1145/1177080.1177101。**已確認存在且與給定資訊吻合**（OpenAlex W2108673751 的作者、標題、頁碼、DOI，並有 bibsonomy 的 DBLP 衍生紀錄為旁證）；正式頁碼緊接 Mai 之前。只有一份 IFIP 公告把它列為 "Impact of Traffic Sampling on Anomaly Detection"，疑為更名前標題 [二手]。取得程度：僅摘要。摘要稱：封包取樣不改變以 bytes、packets 量測的異常大小，但嚴重扭曲 flow 數；熵類摘要統計比量值類更耐抽樣 [二手：OpenAlex 摘要]。2015 年後「同方法的直接延伸」我沒找到；其最近的後繼是 Brauckhoff, Salamatian, May, INFOCOM 2010（早於 2015，HAL hal-00527132，未讀）。
- 建議追加閱讀：
  1. Brauckhoff et al. IMC 2006（見上）。為什麼：同場姊妹篇，其「bytes/packets 不受抽樣影響、flow 數嚴重偏差」直接決定我們該保留哪些計數器（見 T6）。存在確認：DOI 已確認，僅讀摘要。
  2. J. Mai, A. Sridharan, C.-N. Chuah, H. Zang, T. Ye, "Impact of Packet Sampling on Portscan Detection", IEEE JSAC 24(12):2285–2298, 2006, DOI 10.1109/JSAC.2006.884027。為什麼：本文掃描部分的完整版，並提出 TAPS-SYN 與「抽樣率低於 1/100 時 thinning 造成顯著誤差」的結論。存在確認：DOI 已確認；我讀了本地 PDF 的摘要、§III-C 與結論，非全文精讀。
  3. K. Bartoš, M. Řehák, "IFS: Intelligent flow sampling for network security – an adaptive approach", Int. J. Netw. Manage. 25(5):263–282, 2015, DOI 10.1002/nem.1902。為什麼：後繼者／替代方案；提出 late sampling（抽樣前先算特徵，附在存活 flow 上）與過度代表稀有 flow 的 adaptive sampling，與「保留計數器＋抽樣封包」同一思路。存在確認：DOI 已確認（OpenAlex 摘要），未讀全文。
  4. L. Braun, C. Diekmann, N. Kammenhuber, G. Carle, "Adaptive Load-Aware Sampling for Network Monitoring on Multicore Commodity Hardware", arXiv:1604.02322, 2016。為什麼：同題更貼近我們（DPI/IDS 在商用硬體上依處理能力調整取樣率），可借其負載感知調整。存在確認：arXiv DOI 10.48550/arxiv.1604.02322 已確認（OpenAlex 摘要），未讀全文，會議出處未能確認。
  5. C. Novo, J. M. C. Silva, R. Morla, "An Outlook on using Packet Sampling in Flow-based C2 TLS Malware Traffic Detection", NoF 2021, DOI 10.1109/nof52522.2021.9609889。為什麼：後續研究，摘要稱以輕量抽樣讓處理封包數降 10 倍而分類準確率只小幅下降，但僅 5 頁、被引 0 [二手：OpenAlex 摘要]，品質待查。存在確認：DOI 已確認，未讀全文。
- 其他曾看到但未列入：Jadidi et al. 2016（J. Networks 10(9)，ML 流式偵測的抽樣）、Cohen & Moroshko 2018（ToN，Sampling-on-Demand in SDN）、Xia et al. 2016（CIDS，以 IDS 回饋調整封包抽樣）、Hadian Jazi et al. 2017（Comput. Netw. 121，HTTP DoS 與抽樣，摘要取不到，內容未驗證）。

## T. 信任式 Fast Path 專屬欄位
**T1. 放行/信任的判定**：論文無放行概念，論文未說明。最接近的是抽樣器的決策：封包/flow 到達時依固定機率決定，與內容無關；smart sampling 依 flow 大小機率決定 [原文 §2.1 PDF p.3]。

**T2. 放行後的可見性**：未被抽中者完全不可見，論文沒有保留 per-flow 計數 [原文 §2.5：只有被抽樣的 flow 進偵測]。S&H 是「抽中即持有，之後每個封包都計入」[原文 §2.1]，與「抽樣命中後升級為全量檢查」同構 [推測]。

**T3. 撤銷**：論文未說明。僅有間接證據：TAPS 的最佳 time bin 隨取樣間隔增加 [原文 §4.2 PDF p.9]，即取樣越稀，判決所需觀察窗越長（反應時間與抽樣率耦合）；論文未量 time-to-detection。

**T4. 規避風險**：論文**未討論**「先乖後壞」、「cutoff 後攻擊」或針對抽樣的對抗式規避。它量到的是抽樣本身造成的漏報與誤報：
- 小 flow 攻擊被大 flow 偏向的抽樣忽略：N=500 時單 SYN flow 被抽中比例，random flow 1.72%、packet 0.449%、smart 0.278%、S&H 0.0624% [原文 Table 4 PDF p.9]（flow 對 S&H 約 28 倍，對 packet 約 3.8 倍，自行相除）。
- 流量異常（原始偵測到 21 個）：N=100 時 flow 18、packet 6、smart 1、S&H 2；N=1000 時 13、1、1、1 [原文 Table 3 PDF p.6]；所有方法無假陽性 [原文 §3.1 PDF p.6]。
- 掃描：N=100 時 TAPS Rs，flow 約 0.56、smart 約 0.31、packet 約 0.28、S&H 約 0.12（基準約 0.86）[讀圖 Fig. 6a]；N=500 時 packet 僅約 0.065、S&H 約 0 [讀圖]。
- 誤報方向：packet sampling 在 N=10 使 TRWSYN 的 Rf+ 由約 0.72 升到約 2.26（約 3 倍），來源是 flow shortening [原文 §4.1 PDF p.8、讀圖 Fig. 5b]；flow 類抽樣的 Rf+ 單調下降 [原文 §4.1 PDF p.9]。
- 對我們：若攻擊者知道抽樣偏向大 flow 或固定間隔，可把惡意活動拆成大量小 flow，或在被抽樣機率低的位置發動 [推測]；抽樣必須用不可預測的隨機源 [推測]。

**T5. 量化效益**：論文未量「被放行流量比例」（flows 與 bytes 皆無）。可用的只有 Table 2：在同樣保留 34.4% flow 時，封包抽樣用 10.0% 封包、random flow 用 34.4%、smart 用 84.5%、S&H 用 75.9%；保留 1.73% flow 時分別為 0.201%、1.78%、49.3%、36.1% [原文 Table 2 PDF p.6]。換算（自行相除）：同樣的 flow 數下，random flow sampling 的封包量是 packet sampling 的 3.4–8.9 倍，smart 為 8–245 倍，S&H 為 7.6–180 倍 [推測，由 Table 2 計算]。無 CPU、頻寬、儲存實測。

**T6. 對我們構想的直接意涵（建議皆 [推測]，本文不是在驗證信任旁路）**
- **建議抽樣單位：封包。** 對「已放行的 session」做隨機封包抽樣；所有 flow 的計數（packets、bytes、起迄時間）由 conntrack/nftables counter 全程保留，不抽樣；另可留 1–5% 已信任 flow 完全不旁路，當稽核樣本（flow 單位只用在這裡）。
- 理由一：本文對 packet sampling 的兩個主要批評（flow reduction 讓短掃描 flow 消失、flow shortening 造成單 SYN 誤判，兩者都作用於「發現新 flow／由 flow 形狀推論」的偵測）在我們設計中不在抽樣母體內，因為新 flow 的開頭在放行前已完整檢查、被放行者已過握手。這是本論文證據最需要小心類推之處。
- 理由二：本文的「flow sampling 最好」是在**相同保留 flow 數**下成立。我們的成本是封包/位元組，不是 flow 數；以 BB-West 約 10–11.5% 封包預算換算：packet sampling（N=10）TRWSYN Rs 約 0.815、TAPS 約 0.685，flow sampling（有效 N=50，保留 11.7% flow）約 0.745、0.64，即封包抽樣的 Rs 不輸，但 Rf+ 為 2.26 對 0.17（TRWSYN）、0.257 對 0.004（TAPS）[讀圖 Fig. 5/6 與 Table 2，換算為 [推測]]。誤報高的原因是 SYN 推論，與理由一的情境不同。
- 理由三：smart sampling 與 S&H 不要用。它們偏向大 flow，而被放行的正是大 flow，封包量會爆增（理由見 T5），且偵測最差。
- 理由四：位元組/封包計數不受封包抽樣偏差而 flow 數會，這是 Brauckhoff 摘要的說法 [二手，未讀全文]，與本文「抽樣後 flow 到達序列偏差」一致；因此 flow 數類指標應由 conntrack 全量計數，而不是由抽樣後的封包反推。
- **會翻轉這個建議的條件**：若放行後的抽樣封包要交給有 stream reassembly、flowbits、跨封包 content 規則的 Suricata/Snort，封包抽樣會破壞流內脈絡，那時應改用「以 flow（或連續封包時窗）為單位」的抽樣。本文只有 64-byte header，無法回答；需在 Pi 上用被抽樣的 pcap 跑 Suricata 實測 per-rule 偵測率。
- 參數起點（[推測]，僅供掃描）：本文資料顯示 N ≤ 100 時 packet sampling 的 TRWSYN 仍保有基準 Rs 的約 88%（0.70/0.796），N=500 時約 57%；TAPS 在 N=100 只剩約 33%，N=500 約 8%；JSAC 版結論稱低於 1/100 的取樣有顯著誤差 [原文 JSAC 結論，本地 PDF]。故起點可掃 N ∈ {10, 20, 50, 100}，並預期撤銷延遲隨 N 增大。
- 支持：低速隨機抽樣在統計型偵測上可保留相當偵測力；抽樣用於流量尖峰偵測不增加假陽性。反駁/限制：本文完全不涉及「只看開頭就放行」是否合理；packet sampling 的假陽性若直接觸發 ban 會誤殺，故抽樣封包應只用於逐封包規則匹配與「升級為全量檢查」，確認後才 ban [推測]。

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| 流量異常（基準） | 21 個 | BB-East，db5 小波，門檻 4.5 | Fig. 1, §3 PDF p.5 |
| 流量異常偵測數 N=10 / 100 / 1000 | packet 19/6/1；flow 21/18/13；smart 18/1/1；S&H 18/2/1 | BB-East，保留 flow 36.7%/8.03%/1.47% | Table 3 PDF p.6 |
| 抽樣變異數佔總變異數 | 約 80% | N=1000 | §3.2 PDF p.6 |
| Table 2：保留 34.4% flow 時的封包% | packet 10.0；flow 34.4；smart 84.5；S&H 75.9 | BB-West | Table 2 PDF p.6 |
| Table 2：保留 1.73% flow 時的封包% | packet 0.201；flow 1.78；smart 49.3；S&H 36.1 | BB-West | Table 2 |
| TRWSYN Rs 基準 | 79.6% | BB-West 未抽樣 | §4.1 PDF p.8 |
| TRWSYN Rs（packet）N=10→500 | 約 81%→45.6% | BB-West | §4.1 PDF p.8 |
| TRWSYN Rs（flow）N=500 | 約 0.68 | 較 N=1 降約 15% | §4.1 PDF p.9；讀圖 Fig. 5a |
| TRWSYN Rs（S&H）N=500 | 約 0.175 | 降逾 75% | §4.1 PDF p.9；讀圖 |
| TRWSYN Rs N=100（packet/flow/smart/S&H） | 約 0.70/0.725/0.655/0.48 | BB-West | 讀圖 Fig. 5a |
| TRWSYN Rf+ N=10 | packet 約 2.26（基準約 0.72，約 3 倍）；flow 約 0.37；smart 約 0.05；S&H 約 0.24 | BB-West | §4.1 PDF p.8；讀圖 Fig. 5b |
| TAPS Rs 基準 | 約 0.86 | BB-West | 讀圖 Fig. 6a |
| TAPS Rs N=100（packet/flow/smart/S&H） | 約 0.28/0.56/0.31/0.12 | 每點用最佳 time bin | 讀圖 Fig. 6a |
| TAPS Rs N=500（packet/flow/smart/S&H） | 約 0.065/0.375/0.105/0 | 同上 | 讀圖 Fig. 6a |
| TAPS Rf+ N=10 | packet 約 0.257；其餘 ≤約 0.05 | 基準約 0.08 | 讀圖 Fig. 6b |
| 單 SYN flow 被抽中比例 N=10 / 500 | packet 18.1%/0.449%；flow 34.4%/1.72%；smart 9.10%/0.278%；S&H 6.98%/0.0624% | BB-West | Table 4 PDF p.9 |

## F. 自評
- 未能確認：程式碼/trace 是否可取得（只確認專案頁未列出）；重複次數與種子；偵測器是否為重新實作；Wireless trace 的結果；PDF 與 ACM 正式版是否逐字相同；Brauckhoff 論文與 D9 其餘 4 篇的全文內容（只讀摘要）。
- 對本報告最不確定的三件事：
  1. 所有 Fig. 5/6 的數值與 Rs 相對比例都是讀圖，誤差約 ±0.02；文中排序句（例如「低取樣間隔 packet sampling 的 Rs 最佳」）只對 TRWSYN 成立，對 TAPS 在 N=10 是 flow sampling 較高（讀圖 0.755 對 0.685），論文內部有此不一致；另外 §1 稱 packet sampling「performs the worst」，與 Table 3、§5.1 稱 smart/S&H 在流量異常上更差不一致，排名隨指標而變。
  2. T6 的「建議封包抽樣」建立在 [推測] 上：本文是 backbone、header-only、離線統計偵測，與「已放行 flow 內抽樣＋規則式 IDS」差距大；等封包預算的換算又混用 BB-West 的 Table 2 與讀圖，且 Table 3（BB-East）無封包百分比，流量異常無法做同樣換算。
  3. 論文對規避、撤銷、放行比例皆無證據，T1–T5 多為「論文未說明」，不應被當作對信任旁路構想的實證支持或反駁。
