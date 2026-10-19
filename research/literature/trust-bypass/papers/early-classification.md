# early-classification（Bernaille et al., "Traffic Classification on the Fly", CCR 2006）

## A. 書目與取得狀況
- 標題：Traffic Classification On The Fly（HAL 版封面作 "Traffic classification on the fly"）
- 作者：Laurent Bernaille, Renata Teixeira, Ismael Akodjenou, Augustin Soule, Kavé Salamatian（UPMC Paris VI；Soule 為 Thomson Paris Lab）[原文 PDF p.2 / p.1]
- 出處：ACM SIGCOMM Computer Communication Review 36(2), pp.23–26, 2006 [原文 HAL 封面 PDF p.1]。OpenAlex 記載發表日 2006-04-28、類型 "editorial" [二手 https://api.openalex.org/works/doi:10.1145/1129582.1129589]
- DOI：10.1145/1129582.1129589；HAL：hal-01097551
- 取得全文的來源（作者自存的開放版，合法）：https://inria.hal.science/hal-01097551v1/file/bernaille-ccr06.pdf ，本機副本 `research/literature/trust-bypass/pdfs/early-classification/bernaille-ccr06.pdf`（HAL 封面 + 4 頁正文，共 5 PDF 頁）。ACM 頁面回 403，未使用。
- 以下頁碼一律指「HAL PDF 頁」（p.1 為 HAL 封面；正文 p.2–5 約對應 CCR p.23–26，此對應為我的推算，PDF 內無印出頁碼）。

與給定資訊的差異：
1. 第三作者拼法：給定 "Akodkenou"，論文本身寫 "Akodjenou"（DBLP 與 Giryes 等人的參考文獻 [49] 皆作 Akodkenou [二手]；給定資訊的拼法可能來自這類引用）。實為同一人，僅拼字差異。
2. **這不是完整研究論文**：作者自稱 "In this editorial"，只有 4 頁、一個 Matlab 概念驗證 [原文 PDF p.2 摘要；p.4 §5 "proof of concept"]。同一組人的完整版是 CoNEXT 2006 "Early Application Identification"（DOI 10.1145/1368436.1368445，由 CAIDA 書目條目確認存在 [二手 https://www.caida.org/archive/networkingbib/entries/bernaille06early/]，僅讀到摘要：八個網路的 trace、三種分群法、前 4 個封包 >90% 準確、未知應用約 60% 機率被標為 unknown [二手]）。若要「幾個封包、什麼準確度」的嚴謹數據，應讀該 CoNEXT 版，不是這篇。

取得程度：**全文**（HAL 開放版）

## B. 核心貢獻
1. 只用 TCP 連線前 P 個**資料封包**的大小（以正負號表示方向，排除三向交握）當特徵，不看 payload、port 即辨識應用 [原文 PDF p.3 §3.2；p.4 §4.1]。
2. 離線用 K-Means（P=5、K=50 clusters）分群，線上以「最近 cluster 中心 + 該 cluster 內最多數的應用標籤」分類 [原文 PDF p.4 §4.1–4.2]。
3. 概念驗證：用相隔約六個月的 trace，十種應用中九種的單類正確率 ≥81.8%，POP3 為 0% [原文 PDF p.5 Table 1]。

## C. 指定的 9 項
1. **Research Problem**：在 TCP 流結束前就線上辨識其應用（供安全與流量工程用），因為 port 法失效、payload 檢查有隱私與儲存/運算成本、flow 統計法要等流結束 [原文 PDF p.2 摘要、§1–2]。
2. **Architecture**：邊緣鏈路旁的監控卡擷取雙向封包標頭 → packet analyzer 取 5-tuple 與封包大小並濾掉握手封包 → 湊滿前 P 個封包後做 flow conversion（P 維點）→ cluster assignment → application identification [原文 PDF p.4 Fig.3, §4.2]。離線階段另用 Qosmos 的 payload 分析工具為訓練流貼標籤 [原文 PDF p.4]。**沒有 Cloud，也沒有 Edge/Cloud 分工。**
```
標頭流 → 解析(5-tuple,size) → 前P個資料封包 → P維點 → 最近cluster中心 → 多數標籤 / unknown
```
3. **Processing Location**：論文說可跑在「有線上標頭存取的管理主機，或路由器上的 network processor」[原文 PDF p.4 §4.2]；實際只是 Matlab 原型，離線模擬線上分類 [原文 PDF p.4 §5]。沒有 kernel/user space 的討論。
4. **Hardware**：只提到假設使用 Endace 監控卡擷取標頭 [原文 PDF p.4 §4.2、p.5 參考文獻 [9]]；實驗機型、CPU、RAM 論文未說明。
5. **Dataset**：某大學網路邊緣的 1 小時 trace（含 payload）做訓練；約六個月後同一鏈路的另一 trace 做評估；十種應用 [原文 PDF p.4 §4、§5]。流數、位元組量、日期論文未說明；非公開，非 IoT-23/CICIoT2023，不含任何攻擊流量。標籤由 Qosmos payload 工具產生，兩份 trace 皆然 [原文 PDF p.4]。
6. **Baseline**：無實驗比較。僅文字上對照 Moore & Zuev 的 Naive Bayes、BLINC 等 [原文 PDF p.2 §2；p.3 §3.3]，未在同資料重跑。
7. **Metrics**：僅「每應用準確率」＝分類器標籤與 payload 工具標籤相符的比例 [原文 PDF p.4 §5, p.5 Table 1]。無總體準確率、precision、FPR、throughput、latency、CPU、RAM。附帶統計：前 5 個資料封包內含亂序封包的 TCP 流 <4% [原文 PDF p.5 §6]。
8. **Limitations（作者承認）** [原文 PDF p.5 §6]：多出口網路需彙整；封包亂序；封包抽樣下準確度「掉得很快」，流抽樣則不受影響；不同應用若前 5 封包相近會被視為同類；新網路的應用行為會不同（可用限制 cluster 半徑把未見行為標 unknown，但未評估）；短流未測；**錯誤匹配使其不能用來自動封鎖或過濾，建議只用來早期標出可疑流並保存其所有封包供日後稽核**；**evasion：攻擊者可靠 padding 改變封包大小輕易規避**；需要更多 trace，標籤策略需改進（POP3 例）。
9. **Research Gap**
   - 作者自述：更廣的 trace、更好的標籤法（加 port、inter-arrival time）、短流、未知行為、抗規避 [原文 PDF p.5 §6]。
   - [推測]：完全沒有惡意流量，無法回答「安不安全」；無樣本數與變異量；無成本量測；僅 TCP；單點單鏈路。

## D. 補充欄位
**D1 與主題對照**
- C1 △：稱只讀 IP/TCP 標頭「很輕」[原文 PDF p.4 §4.2]，無量測。C2 △：每流只需存前 P 個大小，「限制每流記憶體」[原文 PDF p.2 §2]，無量測。C3 ×。C4 △：僅定性主張。
- K1 ×（未量）。K2 ×（無雲端 IDS；僅量每類正確率）。K3 △：在第 5 個資料封包決策，但未量時間。

**D2 卸載與資料**：無卸載。與我們有關的一句：可疑流可「早期標出並保存所有封包供日後稽核」[原文 PDF p.5 §6]，即保留可回溯資料而非即時封鎖。縮減比、偵測力損失：論文未說明。

**D3 成本記帳**：地端 CPU/RAM/能耗、傳輸量、雲端運算、time-to-detection 皆未量。

**D4 偵測方法**：非 IDS；是無監督 K-Means 的應用辨識，推論階段不需 payload（payload 只用於訓練標籤）[原文 PDF p.4]。成本模型能否套用規則式 IDS：[推測] 特徵抽取（取封包長度與方向）可由 NFQUEUE/conntrack 取得，但分類本身與規則比對無關，不能直接當作 Suricata 成本模型。

**D5 實驗可信度**：離線重播，Matlab 模擬；訓練/測試以時間切開（約六個月，有助於避免洩漏）[原文 PDF p.4–5]；無重複、無信賴區間；P=5、K=50 的選擇只口述「最佳」，未附比較數據；程式與資料論文未說明公開。

**D6 移植障礙**：[推測] 最近中心分類的運算量對 Pi 3B+ 微不足道；真正阻礙是需要有標籤的訓練資料與特徵分佈會因網路而異。未驗證。非 XDP/eBPF 論文。

**D7 六個假說**
- Edge–Cloud IDS 分工：無關（無雲端）。
- Flow Feature Compression：弱支持——五個帶正負號的大小數值即可在該資料上分出多數應用 [原文 PDF p.5 Table 1]；對攻擊偵測力的影響未測。
- Dynamic Flow Monitoring：弱支持——作者主張早期辨識可用於「封鎖、過濾或記錄」並降低每流記憶體 [原文 PDF p.2 §2]。
- XDP-eBPF、Cloud Offloading 成本-時效、不同硬體：無關。

**D8 可借用與可改進**
- 可借用：以「前 P 個資料封包的帶號大小」為向量（排除握手）[原文 PDF p.4]；K-Means + 最近中心 + 多數標籤；用時間相隔的兩份 trace 檢查漂移 [原文 PDF p.4]；限制 cluster 半徑以產生 unknown [原文 PDF p.5]。
- 改進方向（皆 [推測]）：(1) 加入目的 port 與 inter-arrival time 修正 POP3 類混淆（依據：POP3 0% 與作者自述）；(2) 把 unknown/半徑門檻當成 fast path 的「準入閘」，不在已知良性 cluster 內者一律走 slow path（依據：作者提出但未評估的 unknown 機制）；(3) 用 IoT-23/CICIoT2023 量測同一特徵對惡意流的漏報（依據：全文無攻擊流量）；(4) 在 Pi 3B+ 實測每流成本（依據：無成本量測）；(5) 放行後持續抽樣以對抗 padding 與後段變化（依據：作者承認 evasion）。

**D9 引用網路**
References 共 10 筆（皆為 2005 年前後的分類工作，無 IDS 論文）；cited-by 在 OpenAlex 上 2018 年後有 181 篇 [二手]；Giryes 等人（下列第 2 篇）在 related work 以參考文獻 [49] 引用本文，並轉述為「P=5、k=50 下多數類別約 80%」[原文 arXiv 2405.07232 p.3 related work]。以下 5 篇的 PDF 皆已下載並讀過相關章節（存於 `pdfs/early-classification/d9/`）：
1. Ahmad, Truscan, Vain, Porres, "Early Detection of Network Attacks Using Deep Learning", IEEE ICSTW 2022, DOI 10.1109/ICSTW55395.2022.00020（已確認，arXiv 2201.11628）。同題最貼近：CICIDS2017 週四網頁攻擊（僅 port 80），整體 balanced accuracy 0.803；平均只需 1–3 個封包（Brute Force 1.17、XSS 1.00、SQLi 2.80、Normal 2.11）[原文 arXiv p.7 Table V–VI]。註：SQL Injection 訓練流僅 15 條、recall 0.528。
2. Giryes, Shafir, Wool, "A Flow is a Stream of Packets: A Stream-Structured Data Approach for DDoS Detection", arXiv 2405.07232, 2024（已確認；OpenAlex 僅列為 preprint，未見正式出處）。同一個以完整流訓練的分類器只看前 2 封包：CICDDoS2019 準確率 0.99975（完整流 0.99980）；CICIDS2017 為 ST-2 0.8098、ST-4 0.9676、ST-14 0.9925、完整流 0.9965；FTP-Patator、SSH-Patator 在 ST-4 僅 0.7382、0.7927（完整流 0.9955、0.9889）[原文 arXiv p.11 Table XI–XII]。最能說明「不同攻擊類型需要的封包數差很多」。
3. Liu, Simsek, Nogueira, Kantarci, "Multidomain transformer-based deep learning for early detection of network intrusion", IEEE GLOBECOM 2023, DOI 10.1109/GLOBECOM54140.2023.10436976（DOI 取自 OpenAlex；arXiv 2309.01070 已讀）。SCVIC-TS-2022（衍生自 CICIDS2017）：前 2 封包 macro F1 <70%，超過 10 封包才 >80% [原文 arXiv p.5]；摘要稱 84.1% macro F1。
4. Panopoulos 等，"Dynamic Temporal Positional Encodings for Early Intrusion Detection in IoT", SpliTech 2025（DOI 10.23919/SpliTech65624.2025.11091651，取自 OpenAlex；arXiv 2506.18114 已讀）及其擴充版 A-THENA（arXiv 2604.21623, 2026-04，預印本；OpenAlex 列 DOI 10.1145/3811033，未驗證能否解析）。IoT 且在 Raspberry Pi Zero 2 W（Cortex-A53、512 MB）實測。A-THENA 五折交叉驗證：CICIoT23-WEB 99.87% 準確、earliness 1.2±0.4 封包；MQTT-IoT-IDS2020 100%、1.6±0.8；IoTID20 94.41%、需 30 封包全看 [原文 arXiv 2604.21623 p.26 Table 7]。**須謹慎**：SpliTech 版的 CICIoT2023 資料僅 6 類×3 條共 18 個樣本 [原文 arXiv 2506.18114 p.5 §V-A]，擴充版自己也提醒近乎滿分的結果需謹慎解讀 [原文 arXiv 2604.21623 p.26]。
5. Wan, Liu, Bronzino, Feamster, Durumeric, "CATO: End-to-End Optimization of ML-Based Traffic Analysis Pipelines", NSDI 2025（USENIX 頁面存在；arXiv 2402.06099 已讀）。**非 IDS**（IoT 裝置辨識等），但是少數把「看到第幾個封包」與端到端延遲/吞吐一起最佳化的工作：iot-class 用前 3 封包 F1 0.979、延遲 0.1 s，優於用前 10 封包的 RFE10（F1 0.970、7.9 s）[原文 arXiv p.9]。
- 另有兩條線索（僅 OpenAlex 書目，內容未讀，不計入上限）：FastFlow（POMACS 2025, DOI 10.1145/3727115）；Robust Network Flow Classification against Malicious Feature Manipulation（ICC 2020, DOI 10.1109/ICC40277.2020.9148644），可能與 padding 規避有關。

## T. 信任式 Fast Path 專屬欄位
- **T1 判定依據與時點**：非放行機制。決策依據是前 P=5 個資料封包（排除握手）的帶號大小，經最近 cluster 中心與多數標籤得到「應用」標籤 [原文 PDF p.3–4]。判定的是「是什麼應用」，不是「是否安全」。
- **T2 放行後可見性**：論文未設計放行。唯一相關描述：可疑流早期標出後「保存所有封包供日後稽核」[原文 PDF p.5 §6]，屬可回溯保存，而非抽樣。
- **T3 撤銷**：論文未說明（分類為一次性）。
- **T4 規避風險**：(a) 作者明說：攻擊者可用 padding 改變封包大小輕易規避 [原文 PDF p.5 §6]；(b) 作者明說：誤判使其「不能用於自動封鎖/過濾」，只適合標記後留存 [原文 PDF p.5]；(c) 封包抽樣會讓準確度「很快下降」，流抽樣則不影響 [原文 PDF p.5 §6]——對「抽樣放行後流量」的設計有直接意義；(d) 「先正常後攻擊」「攻擊放在前 5 封包之後」：論文**未討論也未量測**，無數字。[推測] 以前 5 封包決策的方法在結構上看不到之後的行為變化。
- **T5 量化效益**：被放行的 flow/bytes 比例、節省的 CPU/頻寬/儲存、偵測損失：全部論文未說明。
- **T6 對構想的意涵（皆 [推測]）**：
  - 支持的部分：僅憑前約 5 個資料封包的大小/方向，就足以在該資料集上辨識多數應用，連 SSH/HTTPS/POP3S 這類加密協定也有 81.8%–96.92% [原文 PDF p.5 Table 1]，支持「flow 開頭帶有可用資訊」。
  - 不能支持的部分：本文沒有任何惡意流量，所以**不能**拿來證明「flow 開頭可判斷安全」；作者自己也說不能據此自動放行/封鎖並承認易被 padding 規避。
  - 與 D9 合併的觀察：攻擊偵測所需封包數隨攻擊類型而異——DDoS 類 2 封包即近完整流準確度，但 CICIDS2017 整體 2 封包僅 0.81、4 封包 0.97，暴力破解類（FTP/SSH-Patator）4 封包仍只有約 0.74–0.79。
  - 設計建議：「開頭判定」若要成立，應只對特定攻擊類別使用，且放行後保留抽樣與回溯；起始參數可參考 P≈5 資料封包（排除握手）與「半徑外即 unknown 走 slow path」。

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| 使用封包數 P | 5 個資料封包 | 排除 TCP 握手；十種應用 | 原文 PDF p.3–4 |
| K-Means cluster 數 | 50 | P=5，作者稱為「最佳取捨」，無比較數據 | 原文 PDF p.4 §4.1 |
| 準確率 edonkey | 84.2% | 約 6 個月後的測試 trace，標籤為 Qosmos payload 工具 | 原文 PDF p.5 Table 1 |
| ftp | 87% | 同上 | 同上 |
| http | 99% | 同上 | 同上 |
| kazaa | 95.24% | 同上 | 同上 |
| nntp | 99.6% | 同上 | 同上 |
| pop3 | 0%（86.8% 被標 NNTP、12.6% 被標 SMTP） | 同上 | 原文 PDF p.5 Table 1、§5 |
| smtp | 84.4% | 同上 | 原文 PDF p.5 Table 1 |
| ssh | 96.92% | 同上 | 同上 |
| https | 81.8% | 同上 | 同上 |
| pop3s | 89.8% | 同上 | 同上 |
| pop3 若加目的 port | >90% | 作者估計，未實測呈現 | 原文 PDF p.5 §5 |
| 前 5 資料封包含亂序的流 | <4% | 該校園鏈路 | 原文 PDF p.5 §6 |
| 訓練 trace | 1 小時 | 大學網路邊緣，含 payload | 原文 PDF p.4 §4.1 |
| 測試 trace 與訓練的間隔 | 約 6 個月 | 同一鏈路 | 原文 PDF p.4 §5 |

## F. 自評
未能確認／論文未說明的欄位：流數與資料量、硬體規格、任何成本與延遲、重複與變異量、程式資料是否公開、放行與撤銷機制。

最不確定的三件事：
1. 這篇是 4 頁 editorial，數字缺樣本數與變異量；「≥80%」只能當概念驗證，不能當可引用的效能。完整數據在 CoNEXT 2006 版（我只讀到二手摘要，未取得全文）。
2. HAL PDF 頁碼與 CCR 印刷頁碼的對應是推算；若主 agent 要在正式文件引用，請以 DOI 版為準。
3. D9 中 Panopoulos 系列的近滿分結果建立在極小的資料集上（SpliTech 版僅 18 個樣本），我不確定擴充版 A-THENA 的實際資料量是否足以支撐其結論（我只讀了其中部分章節，未逐段核對）。
