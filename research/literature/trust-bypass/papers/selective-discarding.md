# Selective Packet Discarding（Papadogiannakis et al., EuroSec 2010）

> 頁碼說明：下列 `p.N` 指我讀到的作者版 PDF 的第 N 頁（共 7 頁）；ACM DL 正式版頁碼是 15–21，兩者不同。
> `Fig.N 讀圖` 表示數值是我從圖上估讀，不是文字寫出的數字，有 ±2–3 個百分點誤差。

## A. 書目與取得狀況

- 標題：Improving the Accuracy of Network Intrusion Detection Systems Under Load Using Selective Packet Discarding
- 作者：Antonis Papadogiannakis, Michalis Polychronakis, Evangelos P. Markatos（FORTH-ICS, Heraklion；同時隸屬 University of Crete）[原文 p.1, p.7]
- 年份 / 出處：2010-04-13，Proceedings of the Third European Workshop on System Security (EuroSec '10), Paris, ACM, pp.15–21 [原文 p.1 版權頁；Crossref]
- DOI：10.1145/1752046.1752049（Crossref 已確認；Crossref 被引 32、OpenAlex 被引 41，截至 2026-10-16）
- URL：作者 PDF `https://projects.ics.forth.gr/dcs/Activities/papers/discarding.eurosec10.pdf`
- 與給定資訊的差異：標題、作者、年份、會議皆相符，沒有差異。補充 DOI 與 ACM 頁碼。
- 取得程度：**全文**。FORTH 伺服器 TLS 憑證鏈不完整（缺中繼憑證，curl 與 WebFetch 皆驗證失敗），我沒有用 `-k` 略過驗證，改取 Internet Archive 對同一份作者 PDF 的存檔（`web.archive.org/web/2012id_/http://dcs.ics.forth.gr/Activities/papers/discarding.eurosec10.pdf`，7 頁，PDF 建立日 2010-03-11，含 ACM 版權頁）。存檔版與 ACM 最終排版是否逐字相同未驗證，內容上看是 camera-ready。
- 本機檔案：`research/literature/trust-bypass/pdfs/selective-discarding/`

## B. 核心貢獻

1. 提出 **selective packet discarding（SPD）**：NIDS 預測到過載時，主動丟掉「較不影響偵測」的封包，而不是讓 kernel 隨機丟。「較不影響」的定義是**位置**：每條 flow 只處理前面的封包，超過 per-flow packet cutoff 的後段封包一律丟棄（保留 head、丟 tail）[原文 p.1–2]。
2. 實證動機：在教育網路 trace 上，90% 的 alert 由 flow 前 30 個封包觸發，只有 3% 來自第 100 個封包之後 [原文 p.2, Fig.1]；86% 的 flow 不超過 10 個封包、97% 不超過 70 個 [原文 p.3, Fig.2]。
3. 一套**負載自適應的 cutoff 控制**：每 N 個封包量測 kernel 丟包、CPU 使用率、處理時間 t 對封包到達區間 s，用兩個門檻（0.95 / 0.8）決定要多丟或少丟，並用「各 flow-size 區間的封包計數表」把「要丟幾個封包」換算成新的 cutoff [原文 p.3–4]。實作成 Snort 2.8.3.2 的 preprocessor。

## C. 指定的 9 項

**1. Research Problem**
NIDS 在流量過高或突發時 CPU 飽和，kernel 在封包送到 NIDS 之前隨機丟包，導致漏報 [原文 p.1]。例如未修改 Snort 只丟 0.096% 封包（400 Mbit/s）就漏 16 個 alert（0.7%）[原文 p.5]。

**2. Architecture**
單機被動式 sensor，沒有 edge/cloud 分工。流程：

```
封包 -> libpcap/kernel -> Snort Layer-4 decode
     -> [SPD preprocessor：hash 查 flow、更新 flow size、
         size > 目前 cutoff ? 丟棄 : 往下傳]
     -> 其他 preprocessor（flow tracking / stream reassembly）-> detection engine
每 N 個封包：量 kernel 丟包 / CPU / t vs s -> 調整全域 cutoff
```

SPD 是 Snort 的第一個 preprocessor，位置在 Layer-4 decode 之後、所有其他 preprocessor 與 detection engine 之前 [原文 p.4]。

**3. Processing Location**
User space（Snort 內）。論文明說 SPD 下所有封包先送到 user space 再被 preprocessor 丟棄，而未修改 Snort 是在複製到 user space 之前由 kernel 丟，這是 SPD 丟棄封包數較多的原因之一 [原文 p.6]。由此推得 SPD **不省 capture 與 kernel→user 複製成本** `[推測]`；論文沒有量這部分成本。

**4. Hardware**
流量產生機：Xeon 2.00 GHz、6 MB L2、2 GB RAM、10 Gbit NIC；NIDS 機：Xeon 2.66 GHz、4 MB L2、2 GB RAM、10 Gbit NIC；中間 10 Gbit 交換器；socket buffer 6 MB [原文 p.4]。CPU 核心數、NIC 型號、OS/kernel 版本、libpcap 版本：論文未說明。

**5. Dataset**
一小時 full-payload trace，來自教育網路對外連線（數千台主機），58,714,906 封包、1,493,032 flow、>40 GB [原文 p.4]；Snort 在上面產生 1976 個 alert、78 條規則。另外隨機位置混入 120 段真實攻擊 trace（取自 Polychronakis et al. LEET'09，polymorphic code injection），增加 276 個 alert、14 條規則，總計 2252 alert、92 個 signature [原文 p.2, p.4]。非 IoT 資料，是否公開：論文未說明（trace 看來未公開，`[推測]`）。

**6. Baseline**
唯一的 baseline 是**未修改的 Snort 2.8.3.2**（同硬體、同 trace、同規則、10 次重複）[原文 p.4–5]。規則集為「latest official rule set」共 9276 條，預設 preprocessor 全開 [原文 p.4]。沒有與明確的 random packet sampling、flow sampling、靜態 cutoff 策略或其他 load-shedding 設計做實驗比較；相關工作（Dreger、Lee、CoMo、Time Machine）只在文字上討論 [原文 p.6]。

**7. Metrics**
- 處理吞吐量（Snort 離線處理）= trace 大小 /（user + sys 時間）[原文 p.4]
- 偵測準確度 = 觸發的 alert 數 / 2252 [原文 p.4]
- CPU 使用率、kernel 丟包 %、SPD 丟棄封包 %、受影響 flow 比例 [原文 Fig.4, Fig.5, p.6]
- 沒有量：延遲、記憶體、能耗、per-flow 狀態表大小。

**8. Limitations（作者承認）**
- 精明攻擊者可先用良性請求填滿 stream 到 cutoff 之後再送攻擊，在 HTTP 這類 persistent connection 可行；作者只用定性論述反駁（其他服務會斷線；可用 request/response 語意偵測重複行為），**沒有實作或實驗** [原文 p.6]。
- 作者承認 1976 個背景 alert 沒有逐一人工確認是否為真陽性，「推測部分可能是誤報」，所以只有 276 個注入攻擊是確定的真陽性 [原文 p.4]。
- SPD 設計上「刻意相當積極」地丟包以預防 kernel 丟包 [原文 p.5–6]。

**9. Research Gap**
- 作者自述：論文沒有列出未來工作；結論只提到規避疑慮並以定性論述回應（p.6）。
- `[推測]` 缺口：(a) 沒量 cutoff 後的規避（先乖後壞），也沒有對策機制；(b) 單一 trace、規則集、硬體；(c) cutoff 只看序號，不分協定/服務，無單 flow 撤銷或升級；(d) 在 user space 丟棄，capture 成本沒省；(e) 沒討論 flow 表記憶體上限與 flood；(f) 缺 sampling 類 baseline；(g) 準確度以 Snort 全量 alert 為基準，非真實標註。

## D. 補充欄位

**D1. 與研究主題對照**
- C1 封包處理：△。降低進 detection engine 的封包量，但仍在 user space，capture 成本不變 [原文 p.6]。
- C2 Flow 資料收集：△。維護 flow hash 表與各 flow-size 區間封包計數，用於控制，不輸出 flow record [原文 p.3–4]。
- C3 雲端卸載：×。論文不涉及雲端。
- C4 降成本：△。本地 CPU 有降（未修改 Snort 在 ≥500 Mbit/s 時 CPU >99%，SPD 時約 82–87%，Fig.4/5 讀圖）；傳輸成本 ×。
- K1 轉送效能：未量。這是被動 IDS，不是 inline 轉送；只量 Snort 處理吞吐量。
- K2 資料完整性：有量，以 alert 保留率表示（見 E）。
- K3 即時性：未量，沒有延遲或 time-to-detection。

**D2. 卸載與資料**
沒有卸載。決策者是本機 SPD preprocessor，依據是封包在 flow 內的序號 vs 全域 cutoff，cutoff 由負載決定 [原文 p.3]，不是依 flow 內容判斷「安全」。縮減比與偵測損失見 T5、E。

**D3. 成本記帳**
本地 CPU：有（Fig.4/5）。RAM、能耗：未量。傳輸：不適用。雲端：不適用。端到端延遲：未量。

**D4. 偵測方法與威脅模型**
規則式（Snort VRT 9276 條，flow:established 規則佔 4627 條 [原文 p.2]）。威脅：web app 探測、資料庫探測、舊 buffer overflow、protocol violation、polymorphic shellcode 注入 [原文 p.4, p.2]。需要 payload（full payload trace）；加密流量論文未討論。成本模型能否套到 Suricata：`[推測]` 可以，因為機制只依賴 flow 計數與負載量測，與規則引擎無關；Suricata 本身有 stream depth 與 bypass 機制，但我未在本論文驗證，需另查官方文件。

**D5. 實驗可信度**
- 流量來源：tcpreplay 重播真實 trace，200–900 Mbit/s，每個速度重複 10 次，報告平均值 [原文 p.4–5]；沒有變異量、信賴區間。
- 離線 cutoff 實驗（Fig.3）用靜態 cutoff，在線實驗（Fig.4/5）才有動態調整 [原文 p.4]。
- 沒有 ablation（三種過載指標、0.95/0.8 門檻、N 的選擇）。門檻是在觀察多種速度下 CPU/丟包關係後設定 [原文 p.3]，是否與評估用同一 trace：論文未說明，`[推測]` 同一 trace。
- 數值一致性檢查（我的計算）：58,714,906 / 1,493,032 ≈ 39.3 封包/flow，但文中平均 flow 大小為 50.2 [原文 p.3]，兩者不一致，可能與 flow 定義（單向/雙向）有關，論文未說明。
- 原 trace 約 40 GB / 1 小時 ≈ 89 Mbit/s 平均，重播 200–900 Mbit/s 等於把時間壓縮約 2–10 倍，會改變 flow 閒置逾時（10 秒）與同時存在 flow 數的行為 `[推測]`。
- 程式碼：論文未說明是否公開。

**D6. 移植到我們平台的障礙**
無特殊硬體依賴，邏輯是 hash 表、計數器與 CPU 時間量測。Pi 3B+ 上的問題 `[推測，未驗證]`：Snort 2.x 在 Cortex-A53 上的基準吞吐量遠低於 560 Mbit/s；flow 表在 1 GB RAM 下需要上限；SYN flood 造成大量 flow 時行為未知。非 XDP/eBPF 論文，不涉及 USB NIC 驅動問題。

**D7. 對六個假說方向的證據**
- Edge–Cloud IDS 分工：無關（無雲端）。
- Flow Feature Compression：無關。
- Dynamic Flow Monitoring：**支持**。動態 per-flow 封包 cutoff 在 900 Mbit/s 下以 63% 丟包率保留 96.3% alert（Fig.5 讀圖、p.6）。
- XDP-eBPF 省多少：無關；但 p.6 顯示在 user space 丟棄不省 capture 成本，間接指出丟棄位置前移的潛在空間（未量測）。
- Cloud Data Offloading 成本-時效：無關。
- 不同硬體限制：弱相關。算法以自身 CPU 與到達率自校準，但只在單一 Xeon 平台驗證。

**D8. 可借用與可改進**
可借用：
- Fig.1 的方法：統計「觸發 alert 的封包在 flow 內的序號」CDF，用來決定 cutoff [原文 p.2]。
- flow-size 區間封包計數表，把「需丟 X 個封包」換算成 cutoff [原文 p.3–4]。
- 過載判定與遲滯：kernel 丟包、CPU>0.95 且 t>0.95·s 觸發；CPU<0.8 且 t<0.8·s 視為閒置；丟棄量為 max(kernel 丟包數, (t−0.95s)N/t)，放寬量為 (0.8s−t)N/t [原文 p.3]。
- 精確追蹤 RST/FIN 並在 10 秒閒置後結束 flow，使重連的新連線重新被完整檢查，防止以關開連線規避 [原文 p.4]。
- 評估法：把真實攻擊 trace 隨機插入大 trace，另外單獨報告注入攻擊的偵測率 [原文 p.2, p.6]。

改進方向（全為 `[推測]`）：
1. cutoff 後保留殘餘抽樣（例如每 N 個取 1 個），針對作者承認但未量測的「cutoff 之後才攻擊」[基於 p.6]。
2. cutoff 後仍放行 SYN/FIN/RST 等控制封包以維持 flow 狀態與 flow record [基於 p.2：4627/9276 規則依賴 flow:established]。
3. cutoff 依協定/服務分級，不用單一全域值（SSH/Telnet 暴力破解、persistent HTTP 與檔案傳輸性質不同）；論文的「大 flow 多為無害檔案傳輸」是未驗證假設 [基於 p.2]。
4. 把 cutoff 下放到 kernel（例如 nftables conntrack 計數後直接 accept，不進 NFQUEUE）以省 user-space 複製成本；是否可行與省多少需實測 [基於 p.6 承認先送 user space]。
5. 在 IoT-23 上重畫 Fig.1，並注入「先良性、後攻擊」的 flow 量測 cutoff 的規避率 [基於 p.4 資料集為 2010 年教育網路、p.6 規避未量測]。

**D9. 引用網路**（均未讀全文，僅確認書目存在）
1. Maier, Sommer, Dreger, Feldmann, Paxson, Schneider, "Enriching Network Security Analysis with Time Travel," SIGCOMM 2008, DOI 10.1145/1402958.1402980。為何：本文 [11] 引用的 per-flow cutoff 前身，本文說它用靜態 cutoff 減少為回溯分析而存入磁碟的封包 [原文 p.6]，對應我們「放行後仍可回查」的需求。存在：Crossref 已確認；內容未讀。
2. Gonzalez, Paxson, Weaver, "Shunting: A Hardware/Software Architecture for Flexible, High-Performance Network Intrusion Prevention," CCS 2007, DOI 10.1145/1315245.1315264。為何：本文未引用，但 shunting 與我們的 bypass 構想同題，且需要看撤銷與規避處理。存在：Crossref 已確認（標題 "Shunting"）。
3. Amann, Sommer, "Providing Dynamic Control to Passive Network Security Monitoring," RAID 2015, DOI 10.1007/978-3-319-26362-5_7。為何：OpenAlex 顯示它引用本文；標題顯示是被動監控的動態控制，我憑記憶認為涉及 Bro 與動態 shunt，但未讀文驗證。存在：Crossref 已確認。
4. Papadogiannakis, Polychronakis, Markatos, "Tolerating Overload Attacks Against Packet Capturing Systems," USENIX ATC 2012。為何：同作者，OpenAlex 顯示它引用本文，針對攻擊者刻意製造過載（與本文 p.6 的規避疑慮直接相關）。存在：USENIX 頁面存在（標題已確認），無 DOI，內容未讀。
5. Papadogiannakis, Polychronakis, Markatos, "Scap: Stream-Oriented Network Traffic Capture and Analysis for High-Speed Networks," IMC 2013, DOI 10.1145/2504730.2504750（延伸版 IEEE JSAC 2014, DOI 10.1109/JSAC.2014.2358831）。為何：同作者後續，標題顯示是 stream 導向 capture；依我的記憶其核心包含 per-stream cutoff 下放到更低層，但這點我沒有讀文確認，需先查證。存在：Crossref 已確認。

## T. 信任式 Fast Path 專屬欄位

**T1. 放行/信任判定**：依據是 flow 內的**封包序號**超過全域 cutoff，沒有內容、規則、ML 分數或白名單判斷。時點：第 N 個封包（N 為當下 cutoff）。cutoff 本身由負載驅動而不是風險驅動 [原文 p.3–4]。「大 flow 通常是無害的檔案傳輸、P2P、串流」是作者的經驗性假設，沒有以資料驗證 [原文 p.1–2]。

**T2. 放行後的可見性**：被丟封包不進其他 preprocessor 與 detection engine，等於完全不看；唯一保留的是 flow size 更新與 flow-size 區間計數 [原文 p.4]。沒有抽樣、沒有 flow record 輸出、沒有 buffer 回溯。

**T3. 撤銷**：沒有單一 flow 層級的撤銷（例如發現異常就重新檢查）。全域 cutoff 在每 N 個封包重估，閒置時（CPU<0.8 且 t<0.8·s）放寬 cutoff [原文 p.3–4]；N 的值論文未說明。由 p.4 的流程（每個封包更新 flow size 並與目前 cutoff 比較）推得，cutoff 放寬後已超過舊 cutoff 的 flow 可能恢復被檢查，但論文沒有明說 `[推測]`。新連線（RST/FIN 或 10 秒閒置後）一律重新從頭檢查 [原文 p.4]。

**T4. 規避風險**：
- 論文討論了：精明攻擊者可用良性請求填滿到 cutoff 之後再送攻擊，HTTP persistent connection 可行 [原文 p.6]。
- 論文的反論：其他服務在錯誤或協定違規後會斷線；persistent connection 的重複行為可由 request/response 語意偵測 [原文 p.6]。**這兩點都沒有實作或量測，沒有任何規避率數字。**
- 另一個反論：沒有 SPD 時，攻擊者可靠重複攻擊使過載的 NIDS 在某次漏掉，SPD 使這種過載攻擊更難 [原文 p.6]，同樣只是論述。
- 抽樣漏報：不適用（沒有抽樣）。
- 佐證有限：注入的 276 個攻擊來自短 trace（polymorphic code injection），攻擊向量原本就在 flow 開頭，「cutoff 低到 20 封包仍全數偵測」[原文 p.5] 因此不能證明「攻擊在 cutoff 之後」的情況 `[推測]`。從數字看：cutoff=100 時整體 alert 保留 95% [原文 p.5]，而 p.2 說 100 封包之後的 alert 只佔 3%，兩者差 2 個百分點論文沒有解釋。

**T5. 量化效益**：
- flow 比例：900 Mbit/s 時受 SPD 影響的 flow 僅 0.42% [原文 p.6]。
- 封包比例：SPD 丟棄約 13%（200 Mbit/s）、≈33%（500）、≈63%（900）[原文 Fig.5 讀圖]。**byte 比例：論文未說明**，flow、packet、byte 三者無法在這篇完整分開。
- CPU/吞吐：cutoff=100 時 Snort 處理吞吐量 2033 Mbit/s，是未修改版 560 Mbit/s 的 3.62 倍；cutoff=1000 時 1400；cutoff=10000 時提升 56%；cutoff=50000 時 675 Mbit/s [原文 p.5]。
- 偵測損失：cutoff=100 保留 95% alert；cutoff=10,000 漏 5 個；cutoff=50,000 漏 1 個 [原文 p.5]。在線 900 Mbit/s 保留 96.3%（漏 84 個），276 個注入攻擊全數偵測；未修改 Snort 同速度剩約一半 alert，注入攻擊只偵測到 55% [原文 p.5–6]。
- 等丟包率比較（我由圖比較，非論文直接寫）：SPD 在 600 Mbit/s 丟約 46% 封包仍保留約 99% alert（Fig.5 讀圖），未修改 Snort 在 900 Mbit/s kernel 丟 46% 時只保留約 48%（Fig.4 讀圖、p.5）。

**T6. 對我們構想的直接意涵**：
- 支持（有數據）：只看 flow 開頭足以覆蓋規則式 IDS 的大多數觸發點；heavy-tailed flow 使「少數 flow 佔大多數封包」，因此 flow 層級的 cutoff 以極少 flow（0.42%）換取大量封包縮減；丟掉 handshake 或前段封包代價遠大於丟尾段（隨機丟 0.096% 就漏 0.7% alert，p.5；4627/9276 規則依賴 flow:established，p.2）。
- 不支持/反駁：本文**沒有「信任」概念**，cutoff 是負載驅動的硬丟棄，沒有雲端判定、沒有抽樣、沒有撤銷，也沒有量規避。我們構想中的「抽樣 + 異常轉回 slow path」是本文的缺口，不是本文的成果。結論只適用 2010 年教育網路與舊規則集，對 IoT 流量不能直接套用。
- 建議設計（`[推測]`）：(1) 不要照搬 cutoff=100 這個數字，先用 IoT-23 + Suricata 重畫 Fig.1（alert 封包序號 CDF）再決定；(2) 放行後至少保留控制封包與 flow 計數；(3) 重連即重新計 flow、RST/FIN 精確追蹤（p.4）值得照做；(4) cutoff 後的抽樣率要用「先乖後壞」的合成 flow 量測，而不是用 head 位置的攻擊；(5) 撤銷觸發建議做成 per-flow（例如抽樣到異常就升級），而不是只靠全域負載。

## E. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| alert 位置 | 90% 在 flow 前 30 封包；3% 在第 100 封包後 | 教育網路 trace + 注入攻擊，2252 alert | 原文 p.2, Fig.1 |
| flow 大小分布 | 86% ≤10 封包；97% ≤70；平均 50.2 | 同上 | 原文 p.3, Fig.2 |
| 依賴 flow:established 的規則 | 4627 / 9276 | Snort 預設規則集 | 原文 p.2 |
| trace 規模 | 58,714,906 封包；1,493,032 flow；>40 GB；1 小時 | 教育網路對外連線 | 原文 p.4 |
| 未修改 Snort 處理吞吐量 | 560 Mbit/s | Xeon 2.66 GHz，離線處理 | 原文 p.5 |
| 吞吐量 vs cutoff | 100→2033；1000→1400；10000→+56%；50000→675 Mbit/s | 靜態 cutoff，離線 | 原文 p.5, Fig.3 |
| alert 保留 vs cutoff | 100→95%；10000→漏5；50000→漏1；注入攻擊在 cutoff=20 即全中 | 同上 | 原文 p.5 |
| 同上，低 cutoff | 10→約65%；20→約80%；50→約93% | 同上 | 原文 Fig.3 讀圖 |
| 未修改 Snort 丟包 | 15%（500）、46%（900）；400 Mbit/s 時 0.096% | 在線重播，10 次平均 | 原文 p.5, Fig.4 |
| 未修改 Snort alert 保留 | 400→漏 0.7%；500→漏 18%；900→約剩一半 | 同上 | 原文 p.5 |
| 注入攻擊（276）偵測 | 未修改：500→223/276；900→55%；SPD：全速度 100% | 同上 | 原文 p.5–6 |
| SPD alert 保留 | 500→99.2%（2234/2252）；900→96.3%（漏 84） | 在線重播 | 原文 p.6 |
| SPD kernel 丟包 | ≤600 Mbit/s 為 0；900→0.098% | 同上 | 原文 p.5 |
| SPD 丟棄封包 | 約 13%（200）、33%（500）、63%（900） | 同上 | 原文 Fig.5 讀圖 |
| 受影響 flow | 0.42% | 900 Mbit/s | 原文 p.6 |
| SPD 下 CPU | 約 55%（200）至 87%（900） | 門檻 0.8–0.95 | 原文 Fig.5 讀圖、p.5 |
| 未修改 Snort CPU | ≥500 Mbit/s 時 >99% | 在線重播 | 原文 p.5 |
| 門檻 | 0.95 / 0.8；flow 閒置逾時 10 s | | 原文 p.3–4 |

## F. 自評

- 未能確認：N 的實際值、OS/kernel/libpcap/NIC 型號、flow 的方向性定義、程式碼與 trace 是否公開、byte 層級縮減。論文都沒寫。
- 最不確定的三件事：
  1. 圖上讀出的數值（Fig.3/4/5）是估讀，已標「讀圖」；文字有寫的數字優先採用。
  2. T3 中「cutoff 放寬後超限 flow 是否恢復檢查」是我由 p.4 描述推得，論文沒有明說。
  3. D9 的五篇只確認書目存在、未讀全文，其中 Scap 的核心內容我只是憑記憶，已標明需先查證；也沒有讀 Time Machine 與 Shunting 原文，所以不能代表它們的結論。
