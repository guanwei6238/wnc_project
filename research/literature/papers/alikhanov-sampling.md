# Alikhanov-Sampling（封包取樣對 ML-based NIDS 的影響）

## A. 書目與取得狀況
- 標題：Investigating the Effect of Traffic Sampling on Machine Learning-Based Network Intrusion Detection Approaches
- 作者：Jumabek Alikhanov, Rhongho Jang, Mohammed Abuhamad, David Mohaisen, Daehun Nyang, Youngtae Noh
- 年份／出處：2022（2021-12-23 出版、2022-01-18 現版），IEEE Access vol.10, pp.5801–5823 [原文 p.1]
- DOI：10.1109/ACCESS.2021.3137318（與 PDF 首頁一致）[原文 p.1]；CC BY 4.0 [原文 p.1]
- 程式碼：github.com/Jumabek/sampledFlowMeter、github.com/Jumabek/nids-with-sampling [原文 p.1]
- 與給定資訊的差異：無（書目、頁碼、DOI 皆吻合）。candidates.md 中「資料集名稱未能確認」現已確認為 CSE-CIC-IDS2018（AWS 版）[原文 p.7]。
- 取得程度：**全文**（本地 PDF，23 頁，逐頁抽文字；Table 與 Fig. 為圖片，靠渲染 130–260 dpi 讀圖，凡讀圖數字皆標「讀圖」，為近似值）。

## B. 核心貢獻（≤3 條）
1. 量測「先對封包取樣、再組 flow record」對 flow visibility（flow 至少被抽到一個封包的比例）的影響：1/10、1/100、1/1000 下惡意 flow 平均可見度約 85–90%、≈47%、≈7–22%（讀圖 Fig. 4）[原文 Fig. 4, p.14]；短 flow 攻擊最先消失。
2. 在 CIC-IDS-2018 上比較 4 種取樣器 × 3 種分類器，且分類器是在取樣後的 flow record 上訓練與測試 [原文 p.6、Table 10 caption p.17]；未取樣 RF 基準 Majority DR 98.31%、FAR 0.01% [原文 Table 9, p.16]，1/10、1/100、1/1000 的 DR 降至約 80 / 39 / 15%（讀圖 Fig. 6）。
3. 提出以「flow（連線）」而非 flow record 為單位的評估法（Any/Majority/All DR），並指出資料不平衡處理與 macro averaging 的重要性 [原文 p.11–13]；另有 flow cache 不足時（premature eviction）取樣反而有助的實驗 [原文 p.17–20]。

## C. 指定的 9 項
1. **Research Problem**：現有 ML NIDS 都假設 flow 特徵由全部封包算出，但實務上 flow exporter 在商用設備上必須取樣，取樣對偵測率（DR）與誤報率（FAR）的影響未知 [原文 p.1–2]。
2. **Architecture**：封包 →（取樣模組）→ CICFlowMeter flow metering/flow cache → flow export（FIN/RST、idle 15 s、active 120 s timeout、cache 滿時 LRU 踢出）→ collector → NIDS（ML 逐 record 推論，再聚合回 flow 層級評估）→ 通知防火牆/管理員 [原文 p.5–6, p.8, Fig. 2]。取樣模組「整合在 CICFlowMeter 內」，只有被抽到的封包才進 flow metering [原文 p.5]。**純離線模擬**，沒有 edge/cloud 分工。
3. **Processing Location**：flow metering 在「交換器/路由器等轉送設備」（概念上）；實際實驗是離線 pcap 處理 [原文 Fig. 2 p.6、p.8]。無 kernel/user space 討論。
4. **Hardware**：僅 V.D 提及 Intel Xeon E5-2640 v4 @2.40 GHz、40 核、64 GB RAM，RF 推論用單核 [原文 p.18]；CNN 訓練用 GPU 但型號論文未說明（只說 batch 大可利用 GPU 平行 p.14）。無任何嵌入式/ARM 平台。
5. **Dataset**：CSE-CIC-IDS2018 (AWS)，公開資料集，非 IoT-23/CICIoT2023；原為 450 台主機各自擷取的 pcap，作者合併成每日一個 pcap 以模擬轉送設備視角；排除 2018-03-02（Botnet）因攻擊時程與 flow ID 不符；自行修訂攻擊時程（Table 5）[原文 p.7–8, p.10]。13 類攻擊 + benign，flow 總數 40,975,291（benign 40,568,049）[原文 Table 3, p.8]；record 數 92,183,595 [原文 Fig. 5 caption p.15]。
6. **Baseline**：取樣率 1/1（不取樣）為基準；4 個取樣器互比（SRS 當 baseline sampler）；分類器互比。沒有與其他論文的系統在同資料上重跑 [原文 p.16]。
7. **Metrics**：flow visibility、flow-level DR/FAR（Majority 為主）、macro averaging、ANOVA（Table 10）、RF 總推論 CPU 時間（Fig. 10）、CNN 訓練時間（Fig. 5）。無 throughput/latency/記憶體/頻寬量測。
8. **Limitations（作者承認）**：只做 misuse detection，anomaly-based 留待未來；規模小（3 取樣率、4 取樣器、3 模型、4 種 cache 大小）；只用單一資料集 [原文 p.20–21]。
9. **Research Gap**
   - 作者自述：更密的取樣率、更多取樣器與模型、多個資料集、anomaly-based NIDS [原文 p.21]。
   - [推測]：無成本面量測；無補償/校正機制；無 IoT 流量；無即時性；無規則式 IDS。

### Q1–Q9 明確回答

**Q1 取樣方法/率/位置**
- 全為 **packet-level** 取樣，沒有 flow-level（flow sampling）或 time-based 取樣；發生在 **flow metering 之前（先取樣再組 flow）** [原文 p.5 III.A.2]。
- 四個取樣器 [原文 p.9–10]：SRS（計數 n 個封包取一個、取完後 n 重設為隨機數；無額外記憶體，保證固定取樣率）、SFS（SketchFlow，per-flow 系統取樣，sketch 近似計數，1 Mb 記憶體，偏好長 flow）、SGS（Sketch-Guided，非線性，flow 越大取樣率越低，偏好短 flow）、FFS（Fast Filtered，濾掉第 s 到 l 個封包，s=8、l=16，偏好短 flow）。
- 取樣率 1/10、1/100、1/1000（另加 1/1 無取樣用於 V.D）。SFS/SGS/FFS **不保證固定取樣率**，作者靠試參數調到整體約 1/10…（SGS：ε=0.05、1、11.5；SFS：1 層 5 bits、2 層 5 bits、4 層 4 bits；FFS 取樣模組 si=4/40/400），且「參數只適用於 CIC-IDS-2018 的流量分佈」[原文 p.9–10]。
- 與我們情境的差別 [推測]：我們若在 gateway 對所有封包建 flow（conntrack/NFLOG）再決定送什麼，則「取樣」不發生在封包入口，而是發生在 flow 之後（如 flow record 篩選/截斷）；這篇是「入口取樣→特徵失真+短 flow 消失」，與「完整 flow 再壓縮」是不同的損失機制。若我們為了省 CPU 對封包取樣，這篇才直接適用。另外它的前提是商用交換器流量速率高、flow cache 在 TCAM，Pi 3B+ 的瓶頸（USB2 網卡、單核軟體處理）不同。

**Q2 資料集/模型/特徵/偵測力曲線**
- 資料集：CIC-IDS-2018；模型：Decision Tree、Random Forest（scikit-learn 預設，100 棵樹）、CNN（2 個 1D conv、64 filters、kernel 3、1 pool、2 dense，來自 Kumar 的實作，batch 4096、Adam、lr 0.003）[原文 p.10–11]；特徵：CICFlowMeter 78 個 bidirectional flow 特徵（Table 4：封包數、位元組、IAT、flag、active/idle 等），無特徵選擇/壓縮實驗 [原文 p.8, p.10]。
- 未取樣基準（explicit balancing 訓練）：RF Majority DR 98.31% / FAR 0.01%；DT 97.22/0.09；CNN 95.64/0.16 [原文 Table 9]。
- 取樣後 RF 的 Majority DR（讀圖 Fig. 6，近似；文字另載 SFS+RF 1/10 為 80%、1/1000 漏掉 85% [原文 p.16]）：

| 取樣率 | SFS | SGS | SRS | FFS |
|---|---|---|---|---|
| 1/1（無） | 98.31（Table 9） | – | – | – |
| 1/10 | ≈80 | ≈77 | ≈72.5 | ≈73 |
| 1/100 | ≈37 | ≈39 | ≈38 | ≈36.7 |
| 1/1000 | ≈15 | ≈6.5 | ≈12 | ≈12 |

  DT、CNN 在各格差約 2–6 個百分點，RF 皆最高或相當 [原文 p.16；讀圖 Fig. 6]。
- FAR：RF 1/10 SFS 文字稱 0.5% [原文 p.16]（讀圖約 0.3%），1/1000 為 0.03% [原文 p.16]；FAR 隨取樣變狠而降，是因為 FAR 定義 = (1−benign DR)×benign visibility，上界為 benign 可見度 [原文 Eq.1–3 p.13, p.16]。**FAR 下降不代表品質變好**。
- 關鍵細節 [推測，由讀圖數字相除]：DR 的分母是「完整流量的全部 flow」[原文 p.12–13]，所以 DR ≲ 可見度。1/100 時 SFS 可見度≈47%、DR≈37%，條件 DR（對可見 flow）≈79%；1/10 約 80/90≈89%。即 **1/100 以下偵測力損失大半來自 flow 消失，而非特徵失真**。
- 各攻擊類型：論文**只提供 per-category 可見度（Fig. 4），沒有 per-category DR**。可見度（讀圖 Fig. 4）：
  - 1/10：DDoS-LOIC-UDP 最低≈31–33%（所有取樣器）；benign≈55–63%；多數 DoS/DDoS 75–100%；DoS-Hulk、Infiltration、XSS、SSH-BruteForce≈100%。
  - 1/100：benign 10–15%；SQL Injection 4–20%；DDoS-LOIC-HTTP 13–26%；DoS-GoldenEye 7–53%（SGS 最高）；SlowHTTPTest 9–48%；Slowloris 11–28%；FTP-BruteForce 24–37%；LOIC-UDP 19–23%；SSH-BruteForce 68–100%、Infiltration 100%、Hulk 90–100%。
  - 1/1000：多數短 flow 攻擊 <15%；Infiltration 0（SGS）到≈80（SFS）；Hulk≈20（SGS）到 100（SFS）。
  - 結論：長 flow 攻擊（Hulk、Infiltration、SSH-BruteForce、XSS）在低取樣率仍可見；短 flow（SQL injection、Slow DoS、LOIC-HTTP/UDP、FTP-BruteForce、掃描型）先崩 [原文 p.13, Fig. 3 caption p.9]。注意 Infiltration 僅 5 個 flow、SQL Injection 50 個 [原文 Table 3]，統計意義極弱。

**Q3 結論與建議/補償**
- 取樣整體降低偵測力；即使 1/10、1/100 的「溫和」取樣也使短惡意 flow 不可見 [原文 摘要 p.1、p.13、p.20]。
- 建議：若必須取樣，優先 per-flow 系統取樣（SFS）+ RF；攻擊主要為長 flow 選 SFS，短 flow 選 SGS（但 SGS 在 1/1000 崩壞）[原文 p.2、p.13、p.17]；決定「買硬體還是取樣」時應考慮 FAR 惡化 [原文 p.17]；flow cache 不足時，審慎選定的取樣率比不取樣更好，但過狠會降低 record 品質 [原文 p.20]。**未給具體可用取樣率門檻、未給特徵建議**。
- 補償機制：**無**（沒有對特徵做取樣率校正/逆推、沒有補抓短 flow 的機制）。唯一的「對策」是選取樣器、在取樣資料上重訓、資料平衡。

**Q4 成本量測**
- 幾乎只量偵測力。唯一成本量測：V.D 在 cache 受限下 RF 對所有 flow record 的**總推論 CPU 時間**（Xeon 單核）。讀圖 Fig. 10：不取樣時 cache 100%→0.1% 約 1,000 s→≈4,000 s；1/10 約 400 s→600–900 s；1/100 約 70–105 s；1/1000 約 5–13 s [原文 Fig. 10 p.20，讀圖]。增加原因是 record 數增加 [原文 p.20]。
- 沒量：取樣器本身的 CPU/記憶體節省、metering 成本、export 頻寬/bytes（僅引用「NetFlow 負載約為封包匯出的 0.2%」[原文 p.2，引他人]）、轉送效能、延遲。取樣器記憶體只說 1 Mb 設定 [原文 p.8]。
- 因此**不能直接回答成本-偵測力取捨**；只能提供偵測力端（可見度與 DR）的曲線，成本端需自行補量。且推論時間降低主要因為可見 flow 變少（也就是被漏掉）[推測]。

**Q5 切分/重複/變異/訓練方式**
- 自訂 stratified-style CV，確保同一 flow 的多筆 record 在同一 fold；折數**論文未說明** [原文 p.11–12]。CNN batch size 實驗用 4:1 train/test [原文 Fig. 5 caption p.15]。資料平衡只用在訓練集 [原文 p.15]。
- 重複：「Experiments are repeated three times for sampling rates of 1/10, 1/100, 1/1000」[原文 p.16]——語意上是三個取樣率各一次，並非重複三次；種子與重複次數**論文未說明**。Fig. 6/7/8 無誤差線、無信賴區間；Table 10 做 one-way ANOVA（比較三個分類器，非比較取樣器）[原文 p.16–17]，樣本單位未說明。
- **訓練方式**：分類器是在**取樣後**的 flow record 上訓練與評估（「trained and evaluated on sampled flow records」Table 10 caption p.17；III.B.2 p.6），不是用原始流量訓練再測取樣流量。例外：V.D 的 cache 實驗，訓練用 cache=100% 的 record，只在推論時縮小 cache [原文 p.18]（該訓練是否同取樣器取樣，論文未明說）。所以結論描述的是「部署端已知取樣設定並重訓」的上界；若部署時取樣率與訓練不一致，論文未測。
- 洩漏檢查：作者有避免同 flow 跨 split；explicit balancing 只作用在訓練集；但 over-sampling 小類別（Infiltration 5 個 flow）若發生在 fold 切分之前會洩漏，論文未說明順序 [推測]。

**Q6 限制**
- 作者承認：見 C.8。
- 我觀察到的未承認限制：
  1. [推測] 單一企業/雲端環境資料集，合併 450 台主機 pcap 後「模擬」交換器視角，內部主機間流量可能在兩端各錄一次而重複，時序也被人工合併；論文未討論。
  2. DR 分母為全部 flow，使 DR 混合「可見度」與「分類品質」，且沒有條件 DR（對可見 flow）；FAR 的定義使取樣越狠 FAR 越低，易誤導 [原文 Eq.1–3；推測其影響]。
  3. 無 per-attack DR，只有可見度；難以回答哪些攻擊「偵測」崩壞。macro 平均包含 5～117 個 flow 的小類 [原文 Table 3]，變異大。
  4. 取樣器參數只針對此資料集調整出名目取樣率，換流量實際取樣率會變 [原文 p.9]；各取樣器的實際取樣率不一致，比較不完全公平。
  5. 分類器全用預設超參數、無調參 [原文 p.10]；無誤差線。
  6. 文內數字不一致：摘要/結論稱「1/10 就有 50% 惡意 flow 不被匯出」[原文 p.20]，但 Fig. 4 與 p.13 文字顯示 1/10 惡意 flow 約 80–90% 可見，p.2 又寫 20/50/80% 損失對應 1/10、1/100、1/1000（讀圖 1/1000 平均可見度僅 7–22%）；p.16 文字 FAR 0.5% vs Fig. 6 讀圖≈0.3%；Table 7（標 Majority）CNN batch 4096 的 94.51/1.8 與 Table 9「All」欄 CNN 相同，而 Majority 欄為 95.64/0.16；Table 3 中 DoS-GoldenEye、FTP-BruteForce、DoS-Hulk 都是 14,116，疑似筆誤（未能確認）。
  7. 只有 enterprise 流量，無 IoT 低速/週期性流量，也沒有量取樣器自身開銷。

**Q7 程式碼/資料**：兩個 GitHub repo 存在且公開 [原文 p.1；WebFetch 確認 repo 頁面存在]。sampledFlowMeter 為基於 CICFlowMeter 的取樣 + pcap 修復/合併腳本（含 LICENSE.txt，授權類型未確認）；nids-with-sampling 有 environment.yml、訓練/CV 腳本，作者自述程式「雜亂」、頁面看不到執行說明（二手頁面描述，未實際 clone 重現）。資料集 CIC-IDS-2018 公開；作者修訂的攻擊時程在 Table 5 [原文 p.10]。

**Q8 [推測] 規則式 IDS（Suricata/Snort）的差異**
- ML 路徑：損失 = (a) flow 不可見 + (b) 可見 flow 的統計特徵（封包數、IAT、長度）因抽樣失真，且 FIN/RST 沒被抽到會使 flow 到期判斷不準 [原文 p.5]。
- 規則式：沒有「特徵失真」，但是「單封包簽章」若觸發封包沒被抽到就整個漏；n 個可觸發封包的偵測機率約 1−(1−p)^n（隨機取樣假設）。跨封包的需求（TCP stream 重組、flowbits、threshold/頻率規則、protocol parser 狀態）在有缺封包時會失效或誤判，且這類損失比 ML 更「全有全無」。論文 III.B.2 明說 signature-based 與規則計數式掃描偵測不在範圍 [原文 p.6]。
- 可借用：flow visibility 的定義與「短 flow 最先消失」；per-flow 取樣（保證每個 flow 抽到頭幾個封包）對簽章偵測可能特別有利，因為許多簽章落在握手後的前幾個封包 [推測]；評估方法（以完整流量 flow 為分母）。
- 不可借用：DR/FAR 數值、分類器比較、特徵品質結論、FAR 隨取樣下降的現象（那是 ML 與 FAR 定義產物）。

**Q9**：見 D9。

## D. 補充欄位
**D1. 與研究主題對照**
- C1 封包處理：△ 取樣是封包入口的處理，但未實作於 kernel，也沒量處理成本。
- C2 Flow 資料收集：○ 核心議題（取樣→flow record 品質、flow cache 受限）。
- C3 雲端卸載：× 無。
- C4 降成本：△ 取樣動機為降成本，但只量 NIDS 推論 CPU 時間（Fig. 10）。
- K1 轉送效能：× 未量。K2 資料完整性：○ 量了 flow visibility 與 DR/FAR 損失。K3 即時性：× 未量延遲；僅討論 Any/Majority/All DR 與即時性的關係 [原文 p.12–13]。

**D2. 卸載與資料**：無卸載。被送往 NIDS 的是 flow record（78 特徵）。取樣由取樣器隨機/系統決定。資料量縮減比：只有名目取樣率（1/10–1/1000）與對應 DR，record 數量變化未直接報告，只在 Fig. 10 間接呈現。

**D3. 成本記帳**：地端 CPU/RAM/能耗：未量；傳輸 bytes：未量；雲端運算：無；NIDS 推論 CPU 時間：有（Xeon 單核，總時間）；time-to-detection：未量。

**D4. 偵測方法與威脅模型**：監督式 ML（DT/RF/CNN）、misuse detection；13 類攻擊（DoS/DDoS/Brute Force/Web/Infiltration/SQLi）；不需解密或 payload（flow 特徵）[原文 p.3]。成本模型不能直接套到 Suricata/Snort：它量的是 ML 逐 record 推論時間，且取樣機制對簽章偵測的損失不同（見 Q8）。

**D5. 實驗可信度**：離線重播 pcap（合併）；無速率範圍；重複次數不明、無變異量、無 ablation（除資料平衡與 batch size）；有避免 flow 跨 split 的 CV；程式碼公開、資料公開（見 Q5–Q7）。

**D6. 移植到我們平台的障礙**：取樣部分只需 CICFlowMeter（Java）與 Python，原則上離線可在 PC 重現；在 Pi 3B+ 上執行 CICFlowMeter/CNN 未驗證 [推測]。SketchFlow/SGS 需 per-flow sketch 記憶體（1 Mb）[原文 p.8]，對 1 GB RAM 的 Pi 應可接受 [推測]。無 XDP/P4 依賴。

**D7. 對六個假說方向的證據**
- Edge–Cloud IDS 分工：無關。
- Flow Feature Compression：部分相關——僅「封包取樣」一種壓縮，顯示可見度損失為主因；無特徵層壓縮。
- Dynamic Flow Monitoring：部分支持——per-flow、flow-size-aware 取樣（SFS/SGS/FFS）與固定取樣率各有優劣；無動態調整。
- XDP-eBPF 真正省多少：無關。
- Cloud Data Offloading 成本-時效：無關（無傳輸/延遲量測）。
- 不同硬體限制下是否仍有效：部分——僅 flow cache 容量受限的模擬（Fig. 9–10），未涉及 CPU/RAM 受限的邊緣硬體。

**D8. 可借用與可改進**
- 可借用：flow visibility 指標與以「完整流量 flow」為分母的 DR [原文 p.11–13]；flow 感知 CV（同 flow 同 fold）[p.11]；三種 flow-level 聚合（Any/Majority/All）[p.12–13]；macro averaging 與 explicit balancing [p.12, p.15]；取樣器實作與腳本 [Q7]。
- 可能改進（皆 [推測]）：
  1. 補上成本端量測（Pi 上取樣器與 metering 的 CPU/RAM/吞吐）——基於 Q4 缺口。
  2. 報告條件 DR 與 per-attack DR，分離可見度與特徵失真——基於限制 2、3。
  3. 以「保證前 k 個封包」或 flow-size-aware 取樣保護短 flow——基於短 flow 先崩壞。
  4. 加入特徵層補償（以取樣率縮放計數、估計 IAT）——基於「無補償機制」。
  5. 用 IoT 流量（IoT-23/CICIoT2023）重做——基於單一企業資料集限制。

**D9. 引用網路**（OpenAlex 顯示被引 30 筆、引用 57 筆，OpenAlex W4205334018；僅依標題篩，未讀全文）
- 引用清單中**沒有**明確針對「取樣 + IDS + 資源受限/邊緣」的論文；最接近的是 Campazas-Vega 兩篇與 Viper。
- 建議追加閱讀：
  1. Campazas-Vega, Crespo-Martínez, Guerrero-Higueras, Álvarez-Aparicio, Matellán, Fernández-Llamas, "Analyzing the influence of the sampling rate in the detection of malicious traffic on flow data", Computer Networks vol.235, 2023, DOI 10.1016/j.comnet.2023.109951。為什麼：同題後續，ML 在多種取樣率訓練、以 BoT-IoT 和真實網路驗證，較貼近 IoT。存在確認：DOI 已確認（OpenAlex 摘要），未讀全文。
  2. 同作者群, "Malicious traffic detection on sampled network flow data with novelty-detection-based models", Scientific Reports 13, 2023, DOI 10.1038/s41598-023-42618-9。為什麼：本文未來工作（anomaly-based）的後續，聲稱 1/1000 取樣仍可偵測。存在確認：DOI 已確認（OpenAlex 摘要），未讀全文。
  3. R. Jang, D. Min, S. Moon, D. Mohaisen, D. Nyang, "SketchFlow: Per-flow systematic sampling using sketch saturation event", IEEE INFOCOM 2020, DOI 10.1109/INFOCOM41043.2020.9155252。為什麼：本文最佳取樣器的原始論文，可評估 Pi 上實作成本。存在確認：僅見於本文參考文獻 [18]，未獨立驗證。
  4. J. Mai, C.-N. Chuah, A. Sridharan, T. Ye, H. Zang, "Is sampled data sufficient for anomaly detection?", ACM IMC 2006, DOI 10.1145/1177080.1177102（以及 JSAC 2006 portscan 版 10.1109/JSAC.2006.884027）。為什麼：取樣對非 ML 偵測（掃描）的更早基準，與 Q8 的規則/閾值式機制相關。存在確認：僅見於本文參考文獻 [30][31]，未獨立驗證。
  5. X. Dong et al., "Viper: Priority-Based High-Visibility Per-Flow Packet Sampling for SDNs", IEEE Trans. Computers vol.75 no.3, 2025, DOI 10.1109/TC.2025.3642321。為什麼：針對提升短 flow 可見度的取樣（可能的替代方案），但場景為資料中心 SDN，貼近度有限。存在確認：DOI 已確認（OpenAlex 摘要），未讀全文。
- 另注意：OpenAlex 另有 IJERST 2024（DOI 10.63458/ijerst.v2i2.77）同標題條目，疑為轉載，不建議閱讀（未驗證）。

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| RF Majority DR / FAR | 98.31% / 0.01% | 無取樣、explicit balancing | Table 9, p.16 |
| DT Majority DR / FAR | 97.22% / 0.09% | 同上 | Table 9 |
| CNN Majority DR / FAR | 95.64% / 0.16% | 同上 | Table 9 |
| RF 無平衡 DR | 68.92%（FAR 0） | 無取樣 | Table 8, p.16 |
| RF cost-based DR | 69.08%（FAR 0.02） | 無取樣 | Table 8 |
| 取樣後惡意 flow 可見度（平均） | ≈83–90% / ≈47% / ≈7–22% | 1/10 / 1/100 / 1/1000，四取樣器 | 讀圖 Fig. 4 |
| benign flow 可見度 | ≈55–63% (1/10)；≈10–15% (1/100) | 同上 | 讀圖 Fig. 4；p.13 稱 1/10 約 50% |
| DDoS-LOIC-UDP 可見度 | ≈31–33% | 1/10 | 讀圖 Fig. 4 |
| SFS+RF DR | ≈80% (1/10)、≈37% (1/100)、≈15% (1/1000) | Majority DR | p.16 文字及讀圖 Fig. 6 |
| SFS+RF FAR | 0.5%（文字）(1/10)、0.03% (1/1000) | 同上 | p.16 |
| SGS 1/1000 DR | ≈6.5% | RF | 讀圖 Fig. 6 |
| 100%→0.1% cache 時 DR（無取樣） | ≈98→≈57% | RF，Majority DR | 讀圖 Fig. 9a |
| 同上（1/10 取樣） | ≈80→≈63–66% | RF | 讀圖 Fig. 9b；p.20 稱 >60% |
| RF 總推論時間 | 無取樣 ≈1000 s→≈4000 s；1/10 ≈400→600–900 s；1/100 ≈70–105 s；1/1000 ≈5–13 s | Xeon E5-2640 v4 單核，cache 100%→0.1% | 讀圖 Fig. 10，p.18 |
| CNN batch size 效果 | 訓練時間 batch 16 約 15+ h → 4096 約 4–5 h（讀圖）；DR 94.5–95.4%，FAR 1.8–3.6 | 20 epochs，explicit balancing | Fig. 5、Table 7（讀圖） |
| 取樣器記憶體 | 1 Mb | 各取樣器 | p.8 |
| 資料不平衡處理增益 | 「最多 42% DR 增益、50% FAR 下降」 | — | p.14（作者聲稱，未逐項驗算） |

## F. 自評
- 未能確認：k-fold 折數、隨機種子與重複次數、CNN 訓練 GPU 型號、Table 3 數字是否筆誤、V.D 訓練時是否同取樣器取樣、repo 授權與可重現性（未 clone 執行）。
- 最不確定的三件事：
  1. 所有取樣後數值皆為讀圖（Fig. 4/6/9/10 近似，誤差約 ±2–3 個百分點），文字與圖有數處不一致，我以圖為準並標明。
  2. 「1/100 以下的 DR 損失主要來自 flow 消失」是我用讀圖數字相除的推測，論文未提供條件 DR。
  3. 規則式 IDS 的影響（Q8）完全是推測，論文明確不在範圍內；D9 中兩篇 Campazas-Vega 論文只看到摘要，是否真貼近 IoT/邊緣未能確認。
