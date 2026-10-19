# mud-sdn（Hamza et al., SOSR 2019）

## A. 書目與取得狀況

- 標題：Detecting Volumetric Attacks on IoT Devices via SDN-Based Monitoring of MUD Activity
- 作者：Ayyoob Hamza, Hassan Habibi Gharakheili, Theophilus A. Benson, Vijay Sivaraman（UNSW Sydney；Brown University）
- 出處：Proceedings of the 2019 ACM Symposium on SDN Research (SOSR '19), San Jose CA, 2019-04-03/04, pp. 36-48（Crossref 查證）
- DOI：10.1145/3314148.3314352
- 取得 PDF：https://cs.brown.edu/~tab/papers/SoSR19.pdf（作者主頁，13 頁，PDF 內含 ACM ISBN/DOI，應為 camera-ready）。本機路徑 `research/literature/trust-bypass/pdfs/mud-sdn/sosr19.pdf`。
- 頁碼約定：下文 `p.N` 為此 13 頁 PDF 的頁碼（p.1 = ACM p.36）。ACM DL 回 403，未能比對 PDF 與正式版是否逐字相同。
- 與給定資訊的差異：無實質差異（標題、作者、年份、SOSR 皆正確）。補充：SOSR 在此指 Symposium on SDN Research；論文引用的是 MUD 草案 draft-ietf-opsawg-mud-25 [原文 p.13, ref 14]，不是 RFC 8520（RFC 同年 3 月才發布）。
- 取得程度：**全文**（逐頁讀完；表格用 `pdftotext -raw` 重核）。

**背景文件 RFC 8520（讀原文 rfc-editor.org/rfc/rfc8520.txt）**
- 書目：E. Lear, R. Droms, D. Romascanu, "Manufacturer Usage Description Specification", RFC 8520, IETF Standards Track（RFC Editor 狀態 PROPOSED STANDARD），2019-03, ISSN 2070-1721, DOI 10.17487/RFC8520, https://www.rfc-editor.org/info/rfc8520 。未被取代、無 updates（RFC Editor JSON 查證）。
- 摘要：假設 IoT 設備（Thing）用途單一，合法通訊模式因而很少。廠商發布一份 MUD file（YANG 序列化成 JSON，擴充 RFC 8519 的 ACL，另有 domain name 與 manufacturer/controller/local-networks 等抽象類別）。設備用 DHCP option、X.509 extension 或 LLDP TLV 發出 MUD URL（必須 https）[原文 RFC §1.5]；MUD manager 抓檔、驗簽章、把抽象類別換成實際位址，設到最近的 switch/router，設備斷線即移除 [RFC §1.8-1.9]。預設「未明確允許即拒絕」，本地 DNS/NTP 預設放行 [RFC §5]；ACL action 只建議 accept 或 drop，沒有限速語意 [RFC §2]。MUD file 是建議而非指令 [RFC §1.1]。cache-validity 24 至 168 小時，逾時不要求撤銷存取 [RFC §3.5]。安全考量：DHCP/LLDP 發出的 URL 可被謊報，建議 X.509；設備可偽造 L2/L3 來源 [RFC §16]。

## B. 核心貢獻

1. 針對「符合 MUD 規則、但量異常」的容量型攻擊（volumetric），用每條 MUD 規則的 OpenFlow 計數器做兩階段（device/channel 層、單一 flow 層）單類別異常偵測，同時指出是哪條 flow 受影響 [原文 p.1-2, p.4]。
2. 十種真實消費性 IoT 設備的 benign + 攻擊 pcap 與 flow 計數器，並公開 [原文 p.6-7]。
3. 原型：OpenFlow 交換器 + Faucet/Ryu/Gauge + MUD policy engine；只有約 1% 封包需鏡像到軟體檢測 [原文 p.7-8, p.12 Table 8]。

## C. 指定的 9 項

1. **Research Problem**：MUD 的 ACL 只能 allow/deny、無法限速，因此符合 MUD 的攻擊（直接 DoS 與經設備反射）仍可行 [原文 p.2]。要在不做全封包檢測、不靠已知簽章的條件下偵測並定位。
2. **Architecture**：
```
IoT --- OpenFlow switch (OVS on OpenWrt) --- Internet
 switch 對「DHCP、DNS 回應、無規則可匹配的封包」做 forward & mirror -> 鏡像介面 (VXLAN) -> MUD policy engine
   (規格式偵測 + DNS cache；對 domain 型 ACE 動態插入 reactive rule) [p.3-4, p.7]
 switch 對已匹配 MUD 規則的封包只 forward；MUD collector 每分鐘讀各規則 packets/bytes -> 特徵
   -> Stage-1 (local/Internet channel) -> Stage-2 (per-flow) 異常偵測 [p.4-5, p.8]
 MUD file server（廠商/校內雲端 VM）只提供 profile，不分析流量 [p.7]
```
   Packet 層：交換器 match-action 加計數；Flow 層：僅規則聚合計數器，無 5-tuple flow record；Edge：全部在本地；Cloud：無偵測任務。
3. **Processing Location**：交換器資料平面（OVS，規則匹配/計數）；user space（Java/netty 檢測引擎、R/Weka 異常偵測）[原文 p.7-8]。不含 Kernel 自製處理、不含雲端。
4. **Hardware**：TP-Link Archer C7（OpenWrt v18.06、OVS v2.8.2）兼交換器與閘道 [p.7]；容器在 Ubuntu 16.04 伺服器（未寫 CPU/RAM）[p.7]；訓練與耗時量測用 Intel Core 3.1 GHz、16 GB、macOS 筆電 [p.11]；閘道外接 1 TB 硬碟存 pcap [p.6]。無 Pi、P4、GPU。
5. **Dataset**：自行採集的 10 台設備（WeMo motion/switch、Samsung smartcam、TP-Link plug、Netatmo camera、Chromecast Ultra、Amazon Echo、Hue、iHome plug、LiFX），16 天；每台 15,000 分鐘 benign 訓練、28,730-55,400 分鐘測試 [Table 4 p.7]。公開（論文給 [31]；我查到 `iotanalytics.unsw.edu.au/attack-data.html` 目前可連、授權 MIT-0 [二手]；論文原網址已 404）。非 IoT-23/CICIoT2023。含因開啟 port forwarding 而出現的真實網際網路攻擊 [p.7, p.12]。
6. **Baseline**：Snort 社群規則集，用 tcpreplay 重播同一份 trace [p.12]；另以「僅 device 層兩個特徵」重跑自己的演算法代表其他 ML 做法 [Table 10 p.12]。皆在同資料上，但無轉送效能或資源的對照。
7. **Metrics**：Accuracy、TPR、FPR、F-score、Rand index；偵測延遲；攻擊 flow 辨識數；被鏡像封包比例、訓練時間、模型大小、特徵記憶體、推論時間 [p.8-12]。**未量**：throughput、轉送延遲、閘道 CPU/RAM/能耗、鏡像頻寬 bytes。
8. **Limitations（作者承認）**：低速率攻擊前幾分鐘漏報 [p.10]；L→d→L 本地廣播反射因只抓進入設備的本地流量而漏 [p.10]；ARP worker 造成 flow 辨識錯誤 [p.11]；準確率依賴訓練涵蓋所有 benign 狀態 [p.10]；FPR 5.1% 在大量設備時不理想 [p.9]；大視窗需更多狀態記憶體 [p.8]；精巧偽造攻擊可通過規格式偵測 [p.4]；緩解不在範圍 [p.11]；MUD 尚未被廠商採用，profile 由 trace 自動產生 [p.1, p.3]。
9. **Research Gap**：作者自述：攻擊者/受害者主機辨識需封包層特徵（範圍外）[p.5]；跨環境套用模型（範圍外）[p.11]；緩解 [p.11]。[推測]：無雲端分工；無轉送效能量測；偵測以分鐘為粒度；對抗式（模仿 benign 叢集）與訓練汙染未討論；已放行流量沒有任何抽樣/鏡像的保底。

## D. 補充欄位

**D1. 與研究主題對照**

| 項目 | 標記 | 證據 |
|---|---|---|
| C1 封包處理 | △ | 用交換器規則優先序避免多數封包進軟體檢測 [p.4]；無核心態/NFQUEUE/XDP 設計 |
| C2 Flow 收集 | ○ | 每規則 packets/bytes 每分鐘輪詢，每規則 20 個特徵 [p.5] |
| C3 雲端卸載 | × | 偵測全在本地（離線重播 CSV）[p.8]；雲端 VM 只放 MUD file [p.7] |
| C4 降成本 | △ | 被鏡像封包 0.92%（全設備）[Table 8 p.12]；無 CPU/頻寬對照基準 |
| K1 轉送效能 | 未量 | 只說明封包不送 controller、不致壓垮 controller [p.3] |
| K2 資料完整性 | 部分 | 與地面真值比對 TPR/FPR；無「全封包檢測」同管線對照 |
| K3 即時性 | 部分 | 平均 1.92 分鐘發現 [p.10]；推論 13 ms [p.12]；特徵粒度 1 分鐘 [p.5, p.8] |

**D2. 卸載與資料**：送出的是「原始封包副本」給本地檢測引擎（DNS 回應、無匹配封包、規則 k 的進入本地流量）[p.3-4]，加上規則計數器特徵；沒有雲端。決策者是交換器規則優先序：命中 MUD 規則則不鏡像（reactive 規則優先序略高於預設鏡像規則）[p.4]。縮減：僅 0.92% 封包被鏡像（Table 8，10 台設備、16 天）；正文卻寫「低於 1.16%」[p.11]，兩者不一致。偵測力損失：論文沒有與「全鏡像」比較，無法得知。

**D3. 成本記帳**：本地 CPU/RAM/能耗 未量；特徵狀態 3.56 KB/設備（FS3、4 分鐘視窗，全設備平均）[Table 8]；模型 14.96 MB/設備（R/Weka 會保留訓練資料，作者說可用 scikit-learn 縮小）[p.11]；訓練 221.9 s 平均、最長 419 s（Samsung）[Table 8, p.11]。傳輸 bytes 未量；雲端運算 不適用；偵測延遲 有量。

**D4. 偵測方法與威脅模型**：規格式（標頭是否符合 MUD + DNS cache）加異常式（PCA 取 Kaiser 規則主成分、X-means 叢集、第 97.5 百分位邊界、Markov chain）[p.3-6]。攻擊：ARP spoof、TCP SYN、Fraggle、Ping of Death，及 SNMP/SSDP/TCP SYN/Smurf 反射，1/10/100 pps，共 200 次，每次 10 分鐘 [p.6]。只用計數，不需 payload/解密。[推測] 成本模型（「命中允許規則者不進檢測、只檢視例外」）可移植到 Suricata/Snort 前面的 nftables accept 規則，但這會讓被放行流量失去內容規則檢查；論文也顯示 Snort 在這批 IoT 專屬容量型攻擊只抓到 40 種自製攻擊中的 2 種 [p.12]，兩者互補而非替代。

**D5. 實驗可信度**：真實設備與流量，攻擊為自製工具合成，benign 由觸控重播與語音合成模擬 [p.6]。重複次數未說明，未報信賴區間或變異量。有 ablation（FS1/2/3 × 視窗 1-8 分鐘、BD vs Markov、Stage 單獨 vs 組合）[Fig. 7, Table 5]。[推測] 特徵集與視窗在同一份測試資料上挑選，結果可能偏樂觀；訓練/測試是否時間分離，論文僅給筆數，未能確認。程式碼 github.com/ayyoob/mud-ie 可連線（HTTP 200，我未執行）。

**D6. 移植障礙**：論文未在 Pi 上驗證。依賴 Faucet、Ryu、Gauge、NATS、InfluxDB、H2、Java、R/Weka（跑在 Docker/Ubuntu 伺服器）[p.7-8]。[推測] 整套對 1 GB RAM 的 Pi 3B+ 太重；「優先序規則 + 計數器輪詢」可改用 nftables counter，訓練放離線/雲端，Pi 只跑推論（Pi 上耗時未知）。非 XDP 論文，不需查驅動。

**D7. 六個假說方向**：
- Edge–Cloud IDS 分工：無關（無雲端）；僅提供「便宜計數層 + 例外才進軟體檢測」的兩層概念。
- Flow Feature Compression：弱支持。只用 packets/bytes，PCA 把 Local worker 的 261 維降到 18 維、涵蓋 97.14% 變異 [Table 2 p.6]；FS1 1 分鐘視窗 TPR 87.40%，FS3+4 分鐘提高到 90.80% [p.8]。
- Dynamic Flow Monitoring：支持。reactive 規則加 idle-timeout（原型 60 分鐘）動態增刪 [p.7]。
- XDP/eBPF：無關。
- Cloud Offload 成本-時效：無關；僅提供計數式偵測的延遲基準（1.92 分鐘）。
- 不同硬體：無關（只有一種交換器，訓練在筆電）。

**D8. 可借用與可改進**
可借用：(1) 具體規則 priority 20/11/10…，預設 forward & mirror 墊底 [Table 1 p.4]；(2) 每規則 packets+bytes 每分鐘 + 2/3/4 分鐘視窗 total/mean/std [p.5]；(3) 兩階段（粗再細）降 FPR：Stage-1 單獨 14.4% / Stage-2 單獨 10.9% → 合併 5.1% [Table 5]；(4) 時間過濾（連續 2 分鐘才告警）FPR 2.4%、TPR 72.3% [p.9]；(5) 用 Rand index 決定最少訓練天數（4 天 91%）[p.11]。
可能改進（皆 [推測]）：
1. 對已放行流量加固定比例抽樣鏡像，補「僅計數」看不到的低速率與內容攻擊（基於 p.10 低速率漏報與只用計數）。
2. 異常告警自動把該規則升級為 forward & mirror 並轉慢路徑（本篇未做緩解 p.11；其 2023 延伸版有此機制，見 D9）。
3. 計數輪詢小於 1 分鐘，縮短偵測延遲（延遲被 1 分鐘粒度綁住 p.5）。
4. 以雲端判定取代 MUD 作為「放行依據」，保留本篇的計數監看（MUD profile 是 trace 自動產生，且 5 台設備無法收緊，見 D9 第 1 篇）。
5. 線上增量訓練或定期重訓，並測模仿攻擊（訓練 2 天準確率低於 50% p.10）。

**D9. 引用網路**（OpenAlex 顯示被引 194 次、Crossref 168 次；前 40 篇施引多為資料集/綜述，沒有看到直接討論「放行後抽樣」的後續）
1. Hamza, Gharakheili, Sivaraman, "Combining MUD Policies with SDN for IoT Intrusion Detection", IoT S&P '18, DOI 10.1145/3229565.3229571。前作，有規則數、idle-timeout、被檢測封包比例（已讀摘要與第 3-4 節，其餘未讀）。**DOI 已確認（Crossref）**。
2. Hamza, Gharakheili, Benson, Batista, Sivaraman, "Detecting Anomalous Microflows in IoT Volumetric Attacks via Dynamic Monitoring of MUD Activity", arXiv:2304.04987（arXiv 頁未載明正式出處）。後續版：異常時才鏡像並插入 5-tuple 規則。**arXiv ID 已確認；已讀關鍵段落非全文**。
3. Hamza et al., "Verifying and Monitoring IoTs Network Behavior Using MUD Profiles", IEEE TDSC, DOI 10.1109/TDSC.2020.2997898。同組期刊後續。**DOI 已確認（Crossref/OpenAlex），內容未讀**。
4. Sivanathan, Habibi Gharakheili, Sivaraman, "Managing IoT Cyber-Security Using Programmable Telemetry and Machine Learning", IEEE TNSM 2020, DOI 10.1109/TNSM.2020.2971213。同組、可程式化遙測加 ML，疑為更接近 flow 成本的替代做法。**DOI 已確認，內容未讀，推薦理由僅依標題**。
5. Krishnan, Jain, Buyya, "MUD-Based Behavioral Profiling Security Framework for Software-Defined IoT Networks", IEEE IoT-J, DOI 10.1109/JIOT.2021.3113577。他組後續工作（施引者）。**DOI 已確認，內容未讀**。

**本次額外讀到的他篇數字（不是本篇，標 [他篇原文]）**：
- 2018 前作 [IoT S&P '18]：Canary camera 平均 55 條規則、Netatmo 27、Awair 22，28 台設備平均約 33 條（idle-timeout 2 小時）降到約 25 條（2 分鐘）[p.4]；Table 1 為 24 條規則 [p.3]；全設備被檢測封包 0.98% 為 DNS 回應，idle-timeout 2 分鐘時最差 1.99% [p.4]；Blipcare 僅前 3 個封包被檢測（1 個 DNS 回應、2 個遠端 TCP 8777）[p.4]。
- 2023 延伸版 [arXiv:2304.04987]：Stage-3 常駐檢測時 26.0% 封包被標頭檢測（WM 9.3% 至 AE 45.4%），對比僅 Stage-1+2 時低於 1%；TCAM 項目 91/66/88 對比 36/30/45（Chromecast/WeMo switch/Samsung）；常駐 Stage-3 的 TPR 91.0%、FPR 8.6%（表）[PDF p.14]。
- 2023 版自承：極短暫的攻擊「出現又消失」可能繞過入侵偵測 [PDF p.5]。
- 本篇不報告 SDN 規則數與 TCAM 負擔；Table 1 僅示範 TP-Link plug 的 20 列規則 [p.4]。

## T. 信任式 Fast Path 專屬欄位

**T1. 放行判定**：依據是封包標頭是否符合 MUD 規則（MAC、ethertype、IP 或 domain、協定、埠），不是雲端分析、ML 分數或 byte 門檻。固定位址的 ACE 以 proactive 規則預先下；domain 型 ACE 要先看鏡像進來的 DNS 回應建立綁定，第一次出現時封包進檢測引擎，驗證後插入 reactive 規則，後續封包直接 forward [p.3-4, p.11]。決定時點：該 flow 的最初幾個封包（前作實測 Blipcare 為前 3 個封包）[他篇原文 2018 p.4]。本篇未給 N 的統計。

**T2. 放行後可見性**：保留「每條 MUD 規則的 packets/bytes 計數器」，每分鐘一次，無封包內容、無 5-tuple 紀錄 [p.5, p.8]。仍持續鏡像的：DNS 回應、無規則匹配者、規則 k 的進入設備本地流量 [p.3-4]。無 buffer 回溯。

**T3. 撤銷**：(a) reactive 規則有 idle-timeout（原型 60 分鐘）[p.7]；依 p.4 的優先序設計推得，過期後該 flow 會落回預設鏡像規則而再被檢測（[推測]，論文本篇未明說），這是閒置到期，不是異常觸發。(b) 異常偵測只「告警並指出 flow」，緩解「不在範圍」[p.11]，故本篇沒有基於異常的撤銷。反應時間：平均 1.92 分鐘 [p.10]。2023 延伸版才加入「異常即鏡像該 flow」[他篇原文 PDF p.5]。

**T4. 規避風險**（重點）：
- 本篇整個問題就是「符合允許清單的流量裡藏攻擊」：作者承認精巧偽造流量可通過規格式偵測，因此靠計數補 [p.4]。反射/直接攻擊都刻意做成符合 MUD [p.6]。
- 漏報數據：1 分鐘視窗 + 邊界與 Markov 時，200 次攻擊中 5 次低速率攻擊整段漏掉，TPR 87.40% [p.8]；未偵測到的實例其實是低速率攻擊的前幾分鐘 [p.10]；加 2 分鐘時間過濾後 TPR 降到 72.3% [Table 5]。
- 系統性盲點：L→d→L 本地廣播反射的原始攻擊流量不命中任何設備規則，只靠反射回來的流量剛好命中才被抓 [p.10]。
- 「先乖後壞」：計數式模型能抓「同一條允許 flow 上突然變大量」，但需要訓練涵蓋所有 benign 狀態，訓練 2 天時準確率低於 50%、再加 1 天升到 96.08% [p.10]。
- 論文未討論或量測：攻擊者知道模型而刻意壓在 benign 叢集內（模仿攻擊）、訓練期間被汙染、短於 1 分鐘的爆發（攻擊都持續 10 分鐘 [p.6]）、payload 層攻擊（本篇只管容量型）。這些是 [推測] 的缺口，非作者結論。
- 抽樣漏報：不適用，本篇沒有抽樣，是精確計數的聚合，風險在聚合粒度。

**T5. 量化效益**：被放行封包比例約 99.08%（100% 減 0.92%，[推測] 為我算的）[Table 8 p.12]；以 flows 計與以 bytes 計 論文未說明（只報封包%）。省下的 CPU/頻寬/儲存 未量（無全檢測基準）；唯一間接對照是 2023 延伸版：全檢測需 26.0% 封包進標頭檢測、TCAM 項目約加倍，而 TPR 91.0% 對比 89.7%，FPR 8.6% 對比 5.1% [他篇原文]。偵測損失：本篇 TPR 89.7%、FPR 5.1%、準確率 94.9% [Table 5]。

**T6. 對我們構想的直接意涵**（皆 [推測]）：
- 支持：「放行後仍留可見性、靠計數偵測異常」是可行的，且在這組資料上不比全檢測差很多（見 T5 他篇數字）；放行規則優先序疊在預設鏡像規則之上的結構可直接對應 nftables。
- 反駁/不足：本篇的信任來源是廠商宣告，不是雲端判定；放行後沒有抽樣，只有 1 分鐘計數，低速率前幾分鐘是盲區；無異常後的撤銷流程。
- 設計建議：抽樣比例本篇無數據可借，需自行實驗；異常時把該 flow 切回慢路徑（參考 2023 延伸版）；idle-timeout 要與規則上限一起調（2018 前作：2 小時降到 2 分鐘，規則數減少約 24% 至 60%，被檢測封包升至 1.99%）。

## E. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| 總準確率 / TPR / FPR | 94.9% / 89.7% / 5.1% | Stage-1+2 合併，10 台設備，FS3、4 分鐘視窗、BD | Table 5 p.10, p.9 |
| 2 分鐘時間過濾 | 準確率 97.5%、TPR 72.3%、FPR 2.4% | 同上 | Table 5 p.10 |
| 僅 Stage-2 / 僅 Stage-1 | 準確率 89.1% / 85.7%；FPR 10.9% / 14.4% | 同上 | Table 5 |
| 僅 Markov / 僅邊界 / 兩者 | TPR 54.55%（FPR 0.69%）/ 81.05% / 87.40% | FS1、1 分鐘視窗 | p.8 |
| FS3 + 4 分鐘視窗 | TPR 90.80% | 全低速率攻擊皆被偵測 | p.8 |
| 平均偵測延遲 | 1.92 分鐘 | 200 次攻擊、1/10/100 pps | p.10 |
| 被鏡像封包比例 | 0.92%（全）；1.61%（WeMo motion）；0.07%（Samsung） | 16 天；正文另寫 <1.16% | Table 8 p.12, p.11 |
| WeMo motion 被鏡像封包中 DNS 回應占比 | 99.5%，平均 3.13 封包/分 | 同上 | p.11 |
| 訓練時間 | 221.9 s 平均；419 s 最長；單一 flow 模型 <50 s | Intel Core 3.1 GHz/16 GB 筆電 | Table 8, p.11 |
| 模型大小 / 特徵記憶體 / 推論時間 | 14.96 MB / 3.56 KB / 13.04 ms | 全設備平均；Stage-1+2 皆觸發 | Table 8 p.12 |
| 每規則特徵數 | 20（正文另處寫每 flow 14 個，17 規則共 238 個） | 一分鐘計數 + 2/3/4 分鐘視窗 | p.5（內部不一致） |
| 訓練天數與準確率 | 2 天 <50%；3 天 96.08%；Rand index 4 天 91% | Samsung camera | p.10-11 |
| Snort 偵測自製攻擊 | 40 種中 2 種 | 社群規則集，tcpreplay | p.12 |
| 僅 device 層 2 特徵 | 例如 Netatmo TPR 0%、Echo 15.18%、TP-Link 95.19% | 同資料重跑 | Table 10 p.12 |
| 規則/TCAM 數 | 論文未報（TP-Link plug 範例 20 列） | | Table 1 p.4 |
| 轉送 throughput/latency | 論文未量 | | |

## F. 自評

- 未能確認：轉送效能與閘道資源（論文未量）；訓練/測試是否有時間洩漏（只給筆數）；ACM 正式版與我讀的 PDF 是否一致（ACM 403）；Table 8 的「<1.16%」與 0.92% 為何不同；Table 10 文字說 5 台但表列 10 台；每規則特徵數 20 與 14 不一致。
- 最不確定的三件事：
  1. 「約 99% 封包被放行」是 10 台設備 16 天的平均，其中 DNS 回應占大宗；換成流量更雜的設備是否成立，本篇無證據。
  2. D6 對 Pi 3B+ 可行性的判斷全是推測，論文與我都沒在 Pi 上驗證。
  3. D9 第 3-5 篇只確認 DOI，沒讀內容，推薦理由偏向出處與標題，可能不如預期貼近。
- RFC 8520 我讀了第 1-5、14-16 節與附錄 A 起頭；YANG 模組、DHCP/LLDP/X.509 編碼、IANA 等節只略讀，摘要不涵蓋這些細節。
- 他篇（2018、2023）的數字是為回答「規則數、交換器負擔」而補讀，未經過與本篇同等的逐頁核對；2023 版只讀相關段落。
