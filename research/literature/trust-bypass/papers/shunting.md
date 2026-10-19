# Shunting（Gonzalez / Paxson / Weaver, CCS 2007）

頁碼說明：`p.N` 指作者主頁 PDF 的第 N 頁（共 11 頁，對應 ACM CCS'07 pp.139–149 的第 N 頁）。論文只有 Table 1、Table 2、Fig.1–5。

## A. 書目與取得狀況
- 標題：Shunting: A Hardware/Software Architecture for Flexible, High-Performance Network Intrusion Prevention
- 作者：Jose M. Gonzalez（參考文獻中拼為 José M. González）、Vern Paxson、Nicholas Weaver（ICSI，Berkeley）[原文 p.1]
- 出處：CCS'07, Oct 29–Nov 2, 2007, Alexandria, Virginia [原文 p.1]；頁數 139–149 [二手：DBLP 搜尋結果摘要]
- DOI：10.1145/1315245.1315264 [二手：OpenAlex W2097980166]
- 全文 URL（作者主頁，合法）：https://www.icir.org/vern/papers/shunting.ccs07.pdf，已下載並用 pdftotext 讀完 11 頁，另渲染 p.8–10 圖表目視核對。
- 與給定資訊的差異：無實質差異。作者名第一作者在封面為 Jose M Gonzalez，參考文獻為 José M. González。
- 取得程度：**全文**

## B. 核心貢獻
1. 提出 Shunt：一個只看 header 的 in-line 硬體元件，用 IP 位址表、連線 5-tuple 表與固定 TCP flag 規則，以「最高優先權匹配」對每個封包做 forward / drop / shunt（轉給 IPS）三選一；沒命中就預設 shunt [原文 Abstract p.1; p.3–4]。
2. 表只是 IPS 可寫的 cache，由 IPS 決定何時「放行（cut through）」連線的剩餘部分，並提出 forward-N（用 TCP sequence 空間跳過接下來 N bytes）[原文 p.4–5]。
3. 以 Bro 實作並用 6 條 trace 評估：可放行 54.9%–91.1% bytes、43.8%–88.0% packets [原文 Table 2 p.8]。

## C. 指定的 9 項
**1. Research Problem**：Gbps 速率下，commodity PC 做 stateful inline 分析吃不消（僅監看就要 1 Gbps I/O 與記憶體頻寬）[原文 p.3]。利用 heavy-tail：少數連線佔多數 bytes，且「連線開頭幾乎含全部安全上有興趣的資訊」[原文 p.1–2]。注意這是作者「論述（argue）」，不是本文量測出的結論。

**2. Architecture**
```
封包 → [Shunt: IP表 + 連線表 + 固定規則, 優先權0-7]
        ├ forward → 對側網卡（不經 IPS）
        ├ drop
        └ shunt(預設) → Analysis Engine(Bro) ─ reinject 或 drop
                               ↑ IPS 直接寫 Shunt 的 SRAM 表（update cache）
```
Shunt 只讀表；IPS 管理表並保留每條連線的完整狀態，因為表是 cache、隨時可能被逐出 [原文 p.3–4]。

**3. Processing Location**：header 查表在 FPGA 資料平面；深度分析在 PC 的 user space（Bro）[原文 p.3, p.6]。

**4. Hardware**：NetFPGA 2：Virtex-2 Pro 30 FPGA、4×GbE、PCI 33 MHz/32-bit、2 條 2 MB SRAM（其一放 Shunt 表）；IP cache 32K 項、連線 cache 64K 項（皆 two-location associative）[原文 p.6]。韌體 bug 使硬體實際只到 480 Mbps [原文 p.6]。Bro 主機規格：論文未說明。

**5. Dataset**：6 條真實全封包 trace（含 payload）：University I/II/III（222/196/109 GB）、Lab I/II（89/117 GB）、SC I（73 GB）[原文 p.8]。非 IoT 資料；是否公開：論文未說明（推測為不公開）。僅用 University I 開發策略，其餘只作評估 [原文 p.8]。

**6. Baseline**：沒有與其他系統在同硬體同資料上重跑的實驗。related work 只做文字比較（Kruegel 的 slicer/scatterer、Deri、IXP、SCAMPI 等）[原文 p.2]。「Baseline」實質是「全部送 Bro 分析」，用放行比例對照。

**7. Metrics**：放行比例（bytes、packets）、依協定分解（Fig.4）、連線 cache miss rate（Fig.5）。**沒有** CPU、throughput、latency、偵測率的量測。

**8. Limitations（作者承認）**：只在「放行後仍安全」的環境有效，例如銀行必須檢視全部 Web 流量就不適用 [原文 p.1]；板子尚不支援所有功能、硬體限 480 Mbps [原文 p.2, p.6]；非 TCP 沒有 sequence 空間，無法做 forward-N，需另設 countdown counter，且不確定值得做 [原文 p.5]；HTTP 即使 Shunting 仍需大量分析（Fig.4）[原文 p.9]；Bro 對部分「presumed safe」檔案型別沒有分析器 [原文 p.8]。

**9. Research Gap**
- 作者自述：移植到 NetFPGA 2.1、24x7 營運部署、研究以可程式化韌體網卡實作 Shunt [原文 p.10]。
- [推測]：沒有偵測損失量測；沒有 sampling 的實驗；沒有撤銷延遲；沒有針對 cutoff 的規避測試；沒有雲端或 WAN 情境。

## D. 補充欄位
**D1 與研究主題對照**
- C1 封包處理：○（硬體 per-packet 三選一，p.3–4）
- C2 Flow 收集：△（連線表是 flow 狀態；放行流量只剩 SYN/FIN/RST 計帳，如 SSH 的量從 SYN/FIN seq 差計算 p.7；非 flow export）
- C3 雲端卸載：×（無雲；Analysis Engine 是本地 PC。[推測] 可類比為 slow path）
- C4 降成本：△（以放行比例代表卸載量，沒量 CPU/能耗/傳輸）
- K1：只有宣稱「negligible forwarding delay」「Bro 約 <1 ms/封包」[原文 p.3, p.7]，無量測；硬體僅 480 Mbps。K2：無偵測損失量測。K3：無。

**D2 卸載與資料**：送到 IPS 的是**完整原始封包**（未放行者）；放行/封鎖決策由 Bro policy 決定並寫表（Bro→Shunt 方向傳的是規則）。縮減比見 Table 2；偵測力損失：論文未量測。

**D3 成本記帳**：地端 CPU/RAM/能耗：未量。表大小有量：4K 項 two-location cache miss 1.9%，64 KB 夠用（以每項 16 B 估）[原文 p.10]。傳輸 bytes、雲端運算、time-to-detection：未量。

**D4 偵測方法與威脅模型**：規則/腳本式 NIDS（Bro 的 signature engine、協定 analyzer、掃描偵測、SSH 暴力破解計數、IRC bot）[原文 p.8–9]。需要 payload；不處理解密。成本模型能否套到 Suricata/Snort：[推測] 概念可套（決策點是「分析器是否還需要這條連線」），但要依賴 IDS 能暴露 per-flow 的 analyzer 狀態；我未在本次查證 Suricata/Snort 現有的 bypass 機制。

**D5 實驗可信度**：離線 trace 重播（修改 Bro 的 trace 讀取介面，先用 Shunt 決策表前處理封包）[原文 p.8]；每 trace 一次結果，無重複、無變異量/信賴區間；僅 University I 開發、其他 trace 為留出評估（有限度的泛化檢查）；無 ablation（Fig.4 依協定分解算部分）；Table 2 是否已含 cache miss 的影響，論文未明說；有兩位同事流量「live behind」的測試，僅軼事 [原文 p.10]；程式碼/資料公開：論文未說明。

**D6 移植障礙**：核心依賴 FPGA 與 PCI 卡，Pi 3B+ 無法直接用 [推測，未驗證]。邏輯層可用核心表替代 [推測]：forward=nftables accept 不入 queue、shunt=NFQUEUE、drop=drop、sample=numgen random 類規則、priority=規則順序，表用帶 timeout 的 set/map。Pi 3B+ 的 USB 網卡無硬體流表，所以「放行」只是省去 NFQUEUE 往返與 userspace 分析，不是省去 kernel 轉送 [推測]。

**D7 六個假說方向**
- Edge–Cloud IDS 分工：支持（部分）——「本地快路徑 + 重分析器 + 決策回寫」的結構成立，但分析器在本地匯流排後，回饋延遲在 WAN 下的行為論文無證據。
- Flow Feature Compression：無關（它丟封包，不壓縮特徵）。
- Dynamic Flow Monitoring：支持——per-connection 動態調整監看強度（forward/shunt/sample/drop、forward-N、SSH 以 100 ms polling 10 s）[原文 p.4–7]。
- XDP-eBPF 省多少：無關（沒有 CPU 數字）。
- Cloud Data Offloading 成本-時效：無關。
- 不同硬體限制：弱證據——狀態表很小即可（見 D3）；放行比例隨流量組成差異大（43.8%–88.0% packets）[原文 Table 2]。

**D8 可借用與可改進**
- 可借用：預設 shunt 的 fail-safe（只有被明確判定「安全/惡意」才無條件處理）[p.4]；forward 比 SYN/FIN/RST 的靜態規則優先權低，使連線結束計帳不丟 [p.6–7]；forward-N 用 TCP sequence 而非 byte counter（抗亂序、搶先、操弄）並自動失效 [p.5]；essential/unessential analyzer 模型 [p.6]；每方向各自的 action [p.4]；trace 驅動 cache 模擬 [p.9–10]；參數：DPD 2 KB、HTTP 超過 10 KB 才考慮跳過且前 5 KB 照看、SSH 10 s/100 ms/10 KB/門檻 10 [p.7–8]。
- 改進方向（全為 [推測]）：
  1. 補上偵測損失量測：用攻擊 trace（如 IoT-23）掃描 cutoff（缺口：論文只量放行比例）。
  2. 真的使用 sample 欄位並量測抽樣漏報與撤銷延遲（缺口：sample 從未被 Bro 策略使用或評估）。
  3. 放行規則加 TTL，強迫週期性重新審核（缺口：MIME 等由對端宣稱的屬性被當作信任依據，未討論被操弄）。
  4. 對被放行連線匯出 flow record 給雲端（缺口：放行後只剩 SYN/FIN/RST 計帳）。
  5. 非 TCP（IoT 常見 UDP）的放行機制（缺口：p.5 明說未解）。

**D9 引用網路**（OpenAlex cited-by 64 篇，我只讀了摘要，未讀全文）
1. Maier et al., "Enriching Network Security Analysis with Time Travel", SIGCOMM 2008, DOI 10.1145/1402958.1402980。後續作者群相同；NIDS 動態調整 TM 錄製參數並回溯取回過去流量，對應「撤銷/回溯」。已確認 DOI（OpenAlex）。
2. Kornexl et al., "Building a Time Machine for Efficient Recording and Retrieval of High-Volume Network Traffic", IMC 2005, DOI 10.1145/1330107.1330137。Shunting 引用的 10–20 KB cutoff 出處 [原文 p.2, ref.14]。已確認 DOI（OpenAlex）。
3. Košař et al., "Accelerating IDS Using TLS Pre-Filter in FPGA", ISCC 2023, DOI 10.1109/iscc58397.2023.10218049（另有同組 PAM 2023 "Analysis of TLS Prefiltering for IDS Acceleration"，DOI 10.1007/978-3-031-28486-1_5）。現代版「加密流量不送 IDS」，摘要稱平均處理速度加倍。已確認 DOI。
4. Miteff & Hazelhurst, "NFShunt: A Linux firewall with OpenFlow-enabled hardware bypass", NFV-SDN 2015, DOI 10.1109/nfv-sdn.2015.7387413。Netfilter conntrack 配合 bypass，最貼近 Linux 實作。已確認 DOI；摘要稱 policy 寫在 iptables 規則裡。
5. Amann & Sommer, "Providing Dynamic Control to Passive Network Security Monitoring", LNCS 2015, DOI 10.1007/978-3-319-26362-5_7。僅憑標題判斷與動態控制相關，OpenAlex 無摘要，相關性未驗證。

## T. 信任式 Fast Path 專屬欄位
**T1 放行判定**：沒有通用「安全分數」，是 per-protocol 的 policy，由 Bro 腳本決定：
- 預設：新連線無表項即 shunt，被完整分析 [p.2, p.4]。
- DPD：Bro 的 signature engine 看每條連線**前 2 KB**（預設）；到 2 KB 若沒有別的 essential analyzer，就裝 forward 跳過剩餘（SYN/FIN/RST 除外）[p.8]。已辨識出被分析的協定則維持 essential。
- SSH：每 100 ms 輪詢最長 10 s；傳輸超過 10 KB 視為已認證成功；若連線「看起來正常且/或閒置」則降為 unessential，之後放行 [p.7]。「正常」的判準論文未精確定義。
- HTTP：回應大於 10 KB（預設）且 MIME 在 presumed-safe 白名單才用 forward-N 跳過；長度未知（chunked）則完整分析；每個 item 前 5 KB 仍檢視 [p.7–8]。
- 白名單 IP（高流量伺服器、授權掃描器）走 IP 表 [p.4]。
- 時點是 bytes（2 KB / 5 KB / 10 KB）加上時間（10 s），不是第 N 封包。
- 信任依據是「分析器已沒東西可看」（加密已協商、媒體檔），不是「這條連線被判為良性」。

**T2 放行後的可見性**：TCP SYN/FIN/RST 與 IP 分片固定仍送 IPS [p.4, p.6–7]，因此連線起訖、總量（由 seq 差）、時間可計帳 [p.7]。Bro 對每條放行連線仍保留狀態 [p.3]。每個表項有 sample 欄位，可依機率複製封包給 IPS 以監看存活與流量 [p.4]（硬體為 3-bit 抽樣率 [p.6]）。**沒有 buffer、無法回溯**；放行的封包不會到達 IPS [p.10]。抽樣在整份論文中只出現在架構與硬體描述，策略與評估均未使用，論文也未說明是否已在硬體上實測。

**T3 撤銷**：表是 cache，IPS 隨時可改/刪表項、退回 shunt [p.3]。機制：(a) forward-N 以 seq 上限自動失效，超過後封包回到 shunt [p.5]；(b) IPS 在 IP 表放更高優先權的 drop/shunt 項封鎖主機 [p.4–5]；(c) cache 逐出只會讓 forward 退回 shunt，屬 fail-safe；但逐出高優先權的 drop 而留下低優先權 forward 會造成 priority inversion，IPS 須自行避免 [p.4–5]。觸發條件：IPS 能看到的只有 SYN/FIN/RST（與若啟用的抽樣封包）以及同主機的其他連線 [推測，由 T2 推得]。**反應時間：論文未量測。**

**T4 規避風險**：論文**未做任何**「先正常後攻擊」「攻擊放在 cutoff 之後」「抽樣漏報」的討論或量測。與此有關的僅有：(1) 位元組計數式 forward-N 會因亂序、安裝競態、「deliberate attacker manipulation」而記帳錯誤，故改用 sequence 空間 [p.5]；(2) cache 雜湊選用抗攻擊者操弄的函數 [p.4 fn.2]；(3) 預設 shunt 使 cache 壓力只會增加 IPS 負載而非漏檢，作者稱「better safe than sorry」[p.4]；(4) 作者自陳不適用於必須看全部流量的環境 [p.1]。「開頭含幾乎全部資訊」只有論述加上對 Time Machine 的引用 [p.1–2]，本文未量測攻擊落在 cutoff 之後的比例。[推測] 未討論的風險：MIME 與長度是由對端宣稱，可被攻擊者偽裝成 image/* 後在 5 KB 之後夾帶惡意內容；DPD 在前 2 KB 未辨識出協定的流量會被放行，之後的內容不再檢視。

**T5 量化效益**（Table 2 [p.8]，單位 %）

| Trace | 放行 bytes | 放行 packets |
|---|---|---|
| University I | 54.9 | 43.8 |
| University II | 58.1 | 47.0 |
| University III | 69.9 | 52.5 |
| Lab I | 84.5 | 75.7 |
| Lab II | 88.2 | 79.2 |
| SC I | 91.1 | 88.0 |

- **flows 比例：論文未報告**（只有 bytes 與 packets）。
- 作者指出 packets 的放行比例低於 bytes，因為效益集中於重尾大流 [p.9]。SSH 幾乎全放行，HTTP 即使有 Shunting 仍需大量分析 [p.9]。University III（凌晨）放行比例高於白天的 University I [p.9]。
- Table 1：University I 的 HTTP payload 中「presumed safe」類型合計 76.4%（我由表中 Yes 列相加：33.7+28.5+8.5+5.4+0.3）[原文 Table 1 p.8]。表頭是「payload data 百分比」，圖說卻寫「replies 百分比」，兩者不一致。
- 省下的 CPU、頻寬、儲存：論文未量測。偵測損失：論文未量測。

**T6 對我們構想的直接意涵**（全為 [推測]）
- 支持：「看開頭後放行，同時保留連線起訖計帳與狀態」的結構有實證支持其放行比例（約 44–88% packets），且機制完整（優先權、per-direction、預設 shunt、sequence 式 cutoff）。
- 未支持：沒有證據顯示「抽樣能抓到放行後才出現的攻擊」，因為 sample 從未被評估；沒有撤銷延遲數字；也沒有任何對抗性測試。
- 語意差異：Shunting 放行的是「規則式分析器本來就看不到或不分析的內容」，因此漏檢是由設計決定；我們構想是「雲端判定 session 安全後才放行」，殘餘風險是同一 session 後續出現的攻擊，這正是本文沒有回答的部分。
- 建議設計：放行規則附 TTL；以 seq 空間表達 cutoff；SYN/FIN/RST 保持送檢；cutoff 起點可從 2 KB（協定辨識）、10 KB（大小門檻）/5 KB（保留檢視）試掃；IoT 的 UDP 流量需另設計。

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| 放行 bytes | 54.9–91.1% | 6 條 trace，Bro 全分析器 + Shunt 策略，離線 | Table 2 p.8 |
| 放行 packets | 43.8–88.0% | 同上 | Table 2 p.8 |
| 連線 cache miss（direct-mapped） | 0.41% | 64K 項，University I 模擬 | p.9 |
| 2-way / 2-location / 2-way LRU | 0.11% / 0.092% / 0.059% | 同上 | p.10 |
| 2-location 4K 項 miss | 1.9% | University I | p.10 |
| 硬體表容量 | IP 32K、連線 64K 項 | NetFPGA 2 | p.6 |
| 硬體實測吞吐 | 限 480 Mbps | 韌體 bug 所致 | p.6 |
| Bro 每封包延遲 | 「typically well under 1 msec」 | 文字陳述，非量測 | p.7 |
| DPD / HTTP / SSH 參數 | 2 KB / 10 KB+前 5 KB / 10 KB、10 s、100 ms、門檻 10 | 預設值 | p.7–8 |
| TM cutoff（他人） | 10–20 KB | 引用 Kornexl et al. | p.2 |

## F. 自評
- 未能確認：Bro 主機規格、資料與程式碼是否公開、Table 2 是否已含 cache miss 影響、sample 是否在硬體上實測、cutoff 參數敏感度（論文前言說會評估「sensitivities to implementation parameters」[p.2]，但第 7 節只有 cache 大小的敏感度）。
- 對 Time Machine 的關係：本文只在 p.2 提及（引用其 10–20 KB 結果作為「開頭含大部分資訊」的佐證）；TM 本身的細節我只讀到 OpenAlex 摘要，未讀其全文。
- D9 的 5 篇我都只讀了摘要或標題，沒有讀全文。
- 最不確定的三件事：
  1. T4 的「未討論」是否漏看：我用關鍵字（evad、attack、cutoff、false）掃過全文，只有上述幾處，結論是整份論文沒有規避實驗。
  2. Table 2 的放行比例是否已包含 cache miss 與 SYN/FIN/RST 的影響，論文未明說。
  3. D6 中 nftables 對應關係與 Pi 3B+ 無硬體流表的判斷是 [推測]，沒有實機驗證。
