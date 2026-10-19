# simioni-offload（Simioni et al., Early-exit DNN NIDS 卸載）

> 精讀版。全文以 `pdftotext -f N -l N` 逐頁抽取，並渲染 p.12–14 圖頁人工核對圖中數字。[原文 p.N] 的 N 即 PDF 頁碼（共 17 頁；頁首的論文頁碼與 PDF 頁碼一致）。

## A. 書目與取得狀況
- 標題：An Energy-efficient Intrusion Detection Offloading Based on DNN for Edge Computing
- 作者：João A. Simioni, Eduardo K. Viegas, Altair O. Santin（PUCPR, PPGIa, 巴西）, Everton de Matos（TII, 阿布達比）[原文 p.1]
- 年份／出處：稿件版，頁首為 "IEEE Internet of Things Journal, VOL. X, NO. X, 2024"，稿件註記 "Manuscript received X XXXXXX 2025"，PDF 產生日 2025-09-18 [原文 p.1；pdfinfo]。正式卷期、DOI **未能確認**。
- URL：https://secplab.ppgia.pucpr.br/files/papers/2025_3.pdf ；程式碼 https://github.com/jasimioni/ids-ee-offload [原文 p.16]。
- 另見 SBC 版：CTD-SBC（Thesis and Dissertation Contest）引用紀錄，2026，Simioni, Viegas, Santin [二手 https://sol.sbc.org.br/index.php/ctd/article/cite/43048/CbeCitationPlugin]；前一輪記 DOI 10.5753/ctd.2026.19705，本輪未重驗。
- 與給定資訊的差異：給定資訊未指出期刊正式刊登；稿件版無法證實已刊出。Pi 型號全文一致寫 "Raspberry Pi 3 Model B"（非 B+）[原文 p.7, p.11]。
- **名稱撞名警告**：arXiv 2506.17041「MAWIFlow Benchmark」（Schraven, Windmann, Niggemann，2025）是**另一個**同名資料集（用 MAWILab v1.1、CICFlowMeter 格式、2011/2016/2021 三年）[二手 https://arxiv.org/abs/2506.17041]。本論文的 MAWIFlow 是 Simioni 自建（2016 全年、58 特徵、15 秒窗）[原文 p.6]，兩者不可混用。
- 取得程度：**全文**（作者機構稿件版）。GitHub 僅看 README/目錄（WebFetch 摘要，未執行任何程式碼）。

## B. 核心貢獻
1. 以早期出口（early exit）DNN 做 NIDS：第 1 分支在 End Device（Pi 3B）出判決，信心不足才把第 1 分支中間層輸出送到雲端執行第 2 分支 [原文 p.8, p.11]。
2. 用 NSGA-II 多目標最佳化（能耗 σ vs 錯誤率 ε）找各分支接受門檻；最後分支加 reject option，並對各分支做信心校準（ECE 導向的 temperature 搜尋）[原文 p.8–10, p.12–13]。
3. 在 Pi 3B + IBM Cloud 原型上以插座電表量能耗：AlexNet 版每事件能耗降到全本地的 1.0%、時間 0.9%，約 10% 事件卸載；MobileNetV2 版 41.2% / 32.5%、約 8% 卸載 [原文 Fig.10, p.14–15]。

## C. 指定的 9 項
1. **Research Problem**：DNN NIDS 太重，Pi 級裝置跑不動（AlexNet/MobileNetV2 在 Pi 3B 僅約 7 events/s）[原文 Table III, p.7]；全部卸載會耗盡頻寬 [原文 p.1–2, p.4]；且流量非穩態，固定模型準確率逐月下降（TN rate 到 11 月比 1 月低 28%/29%）[原文 Fig.2, p.7]。
2. **Architecture**：
   ```
   End Device(Pi 3B): Scapy 收包 → numpy 抽 15s 窗 flow 特徵(event) → Branch 1 (PyTorch)
        conf > t1 ? ──是──> 標籤交給 Alert
                   └─否──> 中間層輸出 x1 → RabbitMQ Offload queue (Pika)
   Cloud(IBM VM 2vCPU/8GB): Cloud Processor → Branch 2 (+ reject) → Label → Result queue → End Device → Alert
   ```
   [原文 p.10–11, Fig.5]。論文提到 End Device / Edge / Cloud 三層，但原型中 Edge 只是 RabbitMQ 通道的中介，實際只有兩個運算位置 [原文 p.11]。
3. **Processing Location**：全為 user space（Python：Scapy 2.5.0、numpy 1.26、PyTorch 2.1.0、Pika 1.3.2）[原文 p.10–11]。無 kernel/XDP/資料平面元件。
4. **Hardware**：End Device＝Raspberry Pi 3 Model B（4 核 Broadcom、1 GB、Pi OS kernel 6.1）；雲端＝IBM Cloud VM（2 vCPU、8 GB、Ubuntu 24.04），部署於 Brazil South 與 Central US；桌機對照＝Xeon E5-2640 v3 16 核、32 GB、Tesla T4 [原文 p.7, p.11, p.13]。Pi 的對外網路介面（有線/WiFi）論文未說明。
5. **Dataset**：自建 MAWIFlow，取自 MAWI samplepoint-F（日美跨洋骨幹，每日 15 分鐘 PCAP），2016 全年，Table II：總封包 27.72 B、總 flow 6.14 B、7.1 TB [原文 p.5–6]。非 IoT 流量。正文另稱 "more than 70 billion in network flows"（p.6）與 Table II 的 6.14 B 不一致 [原文 p.5–6]。公開：論文稱公開，repo 有 `dataset/2016_01.csv`…`2016_12.csv` 與 `dataset/full` [原文 p.16；repo 目錄 WebFetch 二手]。
6. **Baseline**：同硬體、同資料上重跑的對象只有「完整 AlexNet / MobileNetV2 全在 Pi 上跑」（Traditional）[原文 Fig.10, Table IV]。**沒有**與其他 NIDS 卸載方案、規則式 IDS、或「全部原始封包上雲」的實測比較（後者只用文字論述）[原文 p.15]。
7. **Metrics**：error rate、TPR/TNR、F1、ECE、Pi 每事件處理時間與能耗（µAh）、每事件卸載 bytes、雲端 zone 的事件推論時間、多 End Device 的平均回應時間 [原文 Fig.6–13, Table III–IV]。
8. **Limitations（作者承認）**：未來工作要「最佳化早期出口位置以進一步減少網路用量」及「利用被 reject 的事件增量調整模型」[原文 p.16]；雲端 zone 的 RTT 會影響時間、且與架構相關 [原文 p.14]；多裝置擴展測試假設全部事件上雲，與實際 10% 不同 [原文 p.15]。
9. **Research Gap**：
   - 作者自述：早出口位置最佳化以降網路用量；rejected events 的增量學習 [原文 p.16]。
   - [推測]：見 D8 與下方 Q1–Q7。

## 指定問題 Q1–Q7

**Q1 卸載決策機制**
- 決策變數：每個分支 i 一組接受門檻 tc_i = (t_n^i, t_a^i)，分別是「判為 normal」與「判為 attack」所需信心 [原文 p.8]。原型為單一早出口，故 4 個變數 (t_a1, t_n1, t_a2, t_n2) [原文 p.11]。（repo 內檔名為 `nsga2_2variables.py`，與「4 變數」是否一致未能確認 [二手：repo 目錄]。）
- 目標函數：同時最小化 σ（在資料集 D 與一組門檻下模型的平均推論能耗）與 ε（錯誤率）[原文 Eq.6, p.9]。假設：更多事件在早分支被接受 → 能耗降、錯誤升；更高 reject → 錯誤降、更多事件走到最後分支 [原文 p.9]。
- 求解：NSGA-II（pymoo），population 100、100 generations、crossover 0.9、mutation 0.1；稱改參數無顯著差異 [原文 p.12]。目標在 **1 月 validation set** 上評估，最終在 testing set 測 [原文 p.12]。輸出是 Pareto 前緣（Fig.6a），由操作者挑「operation point」；後續實驗取一個「平均」點 [原文 p.12]。σ 是「透過原型以電表量測」得到 [原文 p.12]；但 NSGA-II 的 10,000 次評估是否每次都實機量測，論文未說明 [推測：不太可能，較可能用實測的各分支單價 × 接受率組合]。
- 求解在訓練期、離線、不在裝置上；部署後門檻固定，但操作者可定期重評並調高 reject 比例而不必重訓 [原文 p.9]。
- reject option：只放在**最後分支（雲端）**，信心 p̂ ≤ t^{CN} 則輸出 ∅，不出判決（抑制不可靠分類、避免誤報）[原文 Eq.5, p.8; p.13]。被 reject 的事件之後如何處理（回傳裝置？存下重訓？）論文未說明，僅列為未來工作 [原文 p.16]。F1 / error 計算時 rejected 事件是否排除，論文未說明。Fig.8 平均 reject 率：AlexNet 8%、MobileNetV2 6%（全年）[原文 p.13]。
- 信心校準：Temperature scaling 風格，每分支以 10 個 bin 各自搜尋 T（0.0–1.0、步長 0.00001）使 ECE 下降，稱為 "simple heuristic-driven search" [原文 p.10, p.13]。結果：MobileNetV2 第 1 分支 ECE 0.068 → 0.039（−43%）；兩分支合計 AlexNet −38%、MobileNetV2 −40% [原文 Fig.7, p.13]。校準資料用 1 月 validation [原文 Fig.7]。
- 決策發生在哪：**End Device** 以第 1 分支信心與 t_n1/t_a1 比較決定「本地接受 vs 卸載」[原文 p.11]；雲端只做第 2 分支與 reject。

**Q2 實際傳到雲端的內容與量**
- 傳的是**第 1 分支中間層輸出 x_i（激活張量）**，不是原始封包、也不是 58 維特徵 [原文 p.8]。經 RabbitMQ Offload queue 發送；雲端回傳 Label 至 Result queue [原文 p.11]。
- 每個被卸載事件：AlexNet 約 7.2 KB、MobileNetV2 約 14.5 KB [原文 p.15, Fig.11a]。依操作點只有約 10%（AlexNet）、約 8%（MobileNetV2）的事件會卸載 [原文 p.15]。
- 對照：每個 flow event 約 11.6 個封包 [原文 p.15]；但論文**沒有給原始封包的 bytes**，也沒實測「全部封包上雲」，只是定性說「大幅降低」[原文 p.15]。58 個特徵若為 float32 約 232 B [推測，非論文數字]，則卸載 payload 比特徵向量本身大 30–60 倍。
- 只量「每卸載事件 bytes」，**沒有**量整體頻寬（bytes/s）、總傳輸量、或傳輸能耗的獨立項目（傳輸能耗只隱含在 Pi 電表量測中）[原文 p.11, Fig.11a]。
- 傳輸延遲：有量。平均 RTT Brazil 23.51 ms、US 157.48 ms；事件平均推論時間 AlexNet 28.36 ms（Brazil）vs 64.26 ms（US），MobileNetV2 223.09 vs 249.73 ms；本地全跑 1385.94 / 669.45 ms [原文 p.14, Table IV]。批次卸載（batch 5/10）可降每事件時間最多 70%/72% [原文 p.15, Fig.11b]。多 End Device：Brazil 最多 8 台、US 10 台平均回應時間不惡化（全部卸載的設定）[原文 p.15, Fig.12]。

**Q3 「1%」與「10%」的 baseline**
- 「能耗/處理成本降到 1%」＝ AlexNet 版、**Ours (Offload)** 對 **Traditional（整個 AlexNet 在 Pi 上本地跑）**，每事件：時間 0.9%、能耗 1.0% [原文 Fig.10a/b, p.14]。**僅 AlexNet**；MobileNetV2 為時間 32.5%、能耗 41.2% [原文 Fig.10c/d, p.14]。摘要與貢獻條列把 1% 寫成通則 [原文 p.1–2]，屬以最佳案例概括。
- 「10% 卸載」＝ AlexNet 在所選 operation point 的卸載比例（MobileNetV2 為 8%）[原文 p.15]。operation point 選自 1 月 validation 的 Pareto 前緣（Fig.6a，「平均」點），之後套用整年 [原文 p.12–13]。Table IV 稱為「entire MAWIFlow dataset」平均 [原文 p.14]；Fig.10 用的資料子集論文未明說。
- 比較是「全本地 vs 早出口＋卸載」，**不是**「全卸載 vs 全本地」，且沒有「全卸載到雲」的對照。
- 另有一個易混的 1%：Fig.6a 的 Pareto 前緣上，若容忍 10% error，正規化能耗可降到 1%；約 7% error 對應約 11% 能耗 [原文 p.12]。這是 1 月 validation 的目標函數值，與 Fig.10 的實測是不同量。
- 1% 的結構性原因：AlexNet 的早出口放在第 1 個卷積層之後，第 1 分支極輕（18.08 ms vs 完整 1385.94 ms）；MobileNetV2 出口在第 2 個 bottleneck 之後，第 1 分支已 217.13 ms，故只剩 32–41% [原文 p.14, Table IV]（作者也指出差異來自出口位置）。[推測] baseline 是把 58 個表格特徵硬轉成 48×48 影像的 AlexNet/MobileNetV2 [原文 p.6]，對表格資料並非合理強基準，Fig.2 也顯示 AlexNet 不比 MobileNetV2 準 [原文 p.7]，因此「降到 1%」的分母偏大。
- 準確度：F1 平均 +0.02（逐月 0.01–0.03）[原文 Fig.9, p.13]；error rate −2.9%（AlexNet）、−2.5%（MobileNetV2）[原文 Fig.6b, p.12]。部分增益來自 reject（抑制錯誤判決）[原文 p.13]；若 F1 排除 rejected 事件，則與 baseline 並非同事件集比較（論文未說明）[推測]。
- 內部不一致（未解）：Table III 稱 AlexNet 在 Pi 約 7.36 events/s（約 136 ms/事件）[原文 p.7]，但 Table IV 本地 AlexNet 總計 1385.94 ms/事件 [原文 p.14]。可能是批次 vs 單事件，論文未解釋。

**Q4 轉送效能、事件特徵來源、特徵抽取成本**
- throughput / packet loss：**沒有量任何轉送效能**。Pi 是被動監聽 NIC（Scapy）[原文 p.10]，不是 inline gateway；唯一「throughput」是 DNN 推論的 events/s（Table III）[原文 p.7]。「packet loss」只在討論中以「網路不穩時調 batch size」帶過，沒有量測 [原文 p.15]。
- 事件特徵：End Device 上用 Scapy 收包、numpy 算（Table I 的 flow 特徵，15 秒時間窗；共 58 特徵取自 Moore 2005）[原文 p.3, p.6, p.10]。**特徵抽取成本（CPU 時間、記憶體、能耗、掉包）論文完全沒報**。
- 是否計入「邊緣能耗」：Section VII-B 描述的是「idle 功耗與執行 early-exit 推論時的差值，且包含卸載動作」[原文 p.11]，未提特徵抽取。MAWIFlow 的特徵是離線由 PCAP 預先算好 [原文 p.6]，repo 的推論輸入是含 58 欄的 CSV [二手：repo]，故 [推測] 實驗是餵預算特徵，**特徵抽取成本未計入 1%**。注意 Scapy 在 Pi 上逐包處理對 100% 封包都要付成本，不受早出口影響 [推測]。
- 即時性影響 [推測]：event 定義為 15 秒窗彙整，故偵測延遲至少含窗長，論文報的 28–64 ms 只是「特徵就緒後」的推論時間。

**Q5 MAWIFlow**
- 標籤：用 MAWILab 的非監督式異常偵測演算法產生（二元 normal/attack）[原文 p.6，ref [41] Fontugne 2010]。論文未說明 MAWILab 標籤的準確度或雜訊；[推測] 這是異常偵測器的輸出，不是人工驗證的 ground truth，標籤雜訊與「attack」語意（異常 ≠ 攻擊）是風險。
- 切分：訓練只用 1 月，其餘 2–12 月作時間外推測試，無洩漏疑慮 [原文 p.7, p.13]。但 1 月內 training / validation / testing 如何切（隨機事件切？按日切？）論文未說明；若為隨機事件切，同日同主機的 flow 可能跨集 [推測]。operation point 與校準都在 1 月 validation 上選，之後固定 [原文 p.12–13]。訓練用 random undersampling [原文 p.6]。
- 公開：論文稱公開 [原文 p.6, p.16]；repo 有逐月 CSV（特徵層）[二手：repo 目錄]。7.1 TB PCAP 是否可取得未能確認。

**Q6 重複次數／變異量／信賴區間**：論文未說明。所有圖表（Fig.6–13, Table III–IV）均為單一數值或單一時間序列，無 error bar、無標準差、無 CI、無多次重跑說明；NSGA-II 只說改參數無顯著差異，未報種子變異 [原文 p.12]。電表精度與取樣率亦未說明 [原文 p.11]。

**Q7 把「DNN 信心值」換成「Suricata 規則命中與否」** [以下全為推測]
- 會失效：(1) 校準／ECE／temperature scaling——規則命中是離散二元訊號，沒有可校準的連續機率；(2) 以 (t_n, t_a) 為決策變數的 NSGA-II——無連續門檻可搜尋，除非自行定義分級訊號（規則 severity/priority、命中規則數、flow 已累積封包數）；(3) reject option 的語意；(4) 1%/41% 節省數字——它來自「廉價第 1 分支 vs 昂貴完整 DNN」的結構，Suricata 的本地成本主要是對每個封包做 pattern matching，並不存在可略過的「後半段」；(5) 卸載 payload（激活張量 7.2/14.5 KB）——Suricata 情境要送的是 flow record / 封包片段，bytes 需重量。
- 仍可借用：(a)「σ（本地成本）vs ε（錯誤率）的 Pareto 前緣、由操作者選 operating point」的框架，決策變數可改為卸載策略參數（如送哪類 flow、每 flow 送前 N 封包）；(b) 插座電表、扣 idle、把卸載成本計入每事件能耗的量測法 [原文 p.11]；(c) 部署後不重訓即可調整卸載比例（Fig.13）[原文 p.9, p.15]；(d) batch 卸載攤提 RTT 的效果（−70%）[原文 p.15] 與 RTT zone 敏感度 [原文 p.14]；(e) 以「訓練在 1 月、逐月評估」檢驗時間漂移的評估方式 [原文 p.7]，但規則式 IDS 的漂移形式（新攻擊無規則）不同。

## D. 補充欄位
**D1. 與研究主題對照**
- C1 封包處理 ×：只用 Scapy 收包，沒有封包處理優化 [原文 p.10]。
- C2 Flow 收集 △：有 15 秒窗 flow 特徵，但成本未量、也非論文焦點 [原文 p.3, p.10]。
- C3 雲端卸載 ○：核心 [原文 p.8, p.11]。
- C4 降成本 ○：能耗與每事件處理時間、每事件 bytes [原文 Fig.10–11]。
- K1 轉送效能：沒量（被動監聽、無 throughput/loss）。K2 資料完整性：△，量了 F1/error 相對全本地 DNN，未與「全資料上雲」比。K3 即時性：△，量事件推論時間與 RTT，未量封包到判決（含特徵窗）。

**D2. 卸載與資料**
- 送：DNN 中間層激活（非封包、非 flow record）。誰決定：End Device 第 1 分支信心 vs 門檻；門檻由 NSGA-II 離線求得、操作者可調。縮減比：卸載事件比例 10%/8%；但每事件 payload 7.2/14.5 KB（大於特徵向量 [推測]）；偵測力：F1 +0.02 vs 全本地 DNN [原文 Fig.9]，無「vs 全卸載」數據。

**D3. 成本記帳**
- 地端 CPU/RAM：未量（只量處理時間）；能耗：有（插座電表，µAh/事件）[原文 Fig.10]；傳輸 bytes：每事件有、總頻寬無；雲端運算：只量事件推論時間與 8–10 台裝置規模，無雲端成本/能耗 [原文 p.15]。time-to-detection：只有推論時間（Table IV），不含特徵窗。

**D4. 偵測方法與威脅模型**：異常/DL（二元 normal vs 異常），不需 payload（只用 flow 統計）；攻擊種類＝MAWILab 異常（未細分）[原文 p.6]。成本模型直接套 Suricata：不能（見 Q7）。

**D5. 實驗可信度**：流量＝離線 PCAP 衍生的預算特徵（[推測] 非即時流量）；速率不是變因；重複次數／變異量無；ablation：有 w/ vs w/o 校準（Fig.7）與 Brazil vs US、batch 大小；無「去掉 reject」的 ablation（[推測]，文中未見）；切分見 Q5；artifact：MIT 授權 repo、11 commits、含 calibration/dnn/nsga2/offload/evaluations、requirements.txt，但 README 未提電表量測腳本 [二手：repo WebFetch 摘要]，故能耗結果實際可否重現未能確認。

**D6. 移植障礙**：已驗證在 Pi 3B 跑 PyTorch 2.1 + Scapy + Pika [原文 p.10–11]。不需 GPU、特殊網卡、kernel 模組。障礙 [推測]：Scapy 在 Pi 3B（USB2 網卡）逐包處理吞吐未知；需自備雲端 broker。

**D7. 六個假說方向**
- Edge–Cloud IDS 分工：支持（僅限 DNN 事件；Fig.10, Table IV）。
- Flow Feature Compression：無關／部分反駁（卸載的是激活張量，大於特徵向量 [推測]；無壓縮實驗）。
- Dynamic Flow Monitoring：無關（僅有可動態調卸載率 Fig.13）。
- XDP-eBPF：無關。
- Cloud Data Offloading 成本–時效平衡：支持（卸載率 vs 處理時間 Fig.13、batch、RTT zone Table IV）。
- 不同硬體限制：弱支持（Pi vs 桌機 CPU/GPU 只有 Table III 推論吞吐；7.36 vs 247.34 vs 17,609 events/s）。

**D8. 可借用與可改進**
- 可借用：NSGA-II 設定 [原文 p.12]；ECE 校準流程 [原文 Eq.7–10]；電表量測法 [原文 p.11]；batch/RTT 實驗設計 [原文 Fig.11–12]。
- 改進方向（全 [推測]）：(1) 量入特徵抽取成本，因 Scapy 對 100% 封包付費（缺口：Q4）；(2) 把 σ 改為含頻寬/傳輸能耗的多目標，並加入偵測延遲目標（缺口：Q2、K3）；(3) 把卸載單位換為 flow record 或規則未命中的 flow，並與「全卸載」實測對比（缺口：Q3 無此 baseline）；(4) 用 Suricata 規則 severity、命中數等作分級訊號取代 DNN 信心（缺口：Q7）；(5) 補重複實驗與信賴區間（缺口：Q6）。

**D9. 引用網路（建議追加閱讀）**
1. Pacheco, Couto, Simeone, "Calibration-Aided Edge Inference Offloading via Adaptive Model Partitioning of DNNs," IEEE ICC 2021, arXiv 2010.16335。理由：本文校準＋卸載想法的來源（替代方案／被其引用的前作）。存在確認：已確認（arXiv 與 FAPESP 記錄）[二手 https://arxiv.org/abs/2010.16335v2]。
2. Pacheco, Couto, Simeone 等，"On the impact of deep neural network calibration on adaptive edge offloading for image classification," J. Netw. Comput. Appl. 217:103679, 2023, DOI 10.1016/j.jnca.2023.103679。理由：本文 ref [14]，校準對卸載的影響。存在確認：由本文參考文獻列出 DOI，未另行驗證。
3. Rahmath P 等, "Early-exit deep neural network – a comprehensive survey," ACM Comput. Surv. 57(3), 2024, DOI 10.1145/3698767。理由：早出口通論（本文 ref [17]），僅作查閱設計選項。存在確認：本文列出 DOI，未驗證。
4. Schraven, Windmann, Niggemann, "MAWIFlow Benchmark," arXiv 2506.17041, 2025。理由：同名資料集，可交叉檢視 MAWILab 標籤與時間漂移評估；注意與本文自建 MAWIFlow 不同。存在確認：已確認 [二手 https://arxiv.org/abs/2506.17041]。
- 本輪未找到引用本文的後續論文（搜尋未命中）。

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| 完整 DNN 在 Pi 3B 推論吞吐 | AlexNet 7.36、MobileNetV2 7.93 events/s | Pi 3B CPU | 原文 Table III, p.7 |
| 同上，桌機 CPU / T4 GPU | AlexNet 247.34 / 17,609；MobileNetV2 509.58 / 3,419 | Xeon E5-2640v3 / Tesla T4 | 原文 Table III, p.7 |
| 漂移：TN rate 降幅 | 28%（AlexNet）、29%（MobileNetV2） | 1 月訓練、11 月評估，無更新 | 原文 p.7 |
| 能耗（卸載） | AlexNet 1.0%、MobileNetV2 41.2% | 對全本地 DNN，每事件，電表 | 原文 Fig.10b/d, p.13–14 |
| 能耗（不卸載） | 12.1% / 47.1% | 兩出口皆在 Pi | 原文 Fig.10, p.14 |
| 處理時間（卸載／不卸載） | AlexNet 0.9%／11.4%；MobileNetV2 32.5%／37.8% | 同上 | 原文 Fig.10a/c |
| 卸載比例 | AlexNet 約 10%、MobileNetV2 約 8% | 所選 operation point | 原文 p.15 |
| 每卸載事件 bytes | 約 7.2 KB / 14.5 KB | 第 1 分支輸出 | 原文 Fig.11a, p.15 |
| 事件平均推論時間 | AlexNet 28.36 ms（Brazil）、64.26 ms（US）、本地 1385.94 ms；MobileNetV2 223.09、249.73、669.45 ms | Pi + IBM Cloud | 原文 Table IV, p.14 |
| RTT | Brazil 23.51 ms、US 157.48 ms | 實測平均 | 原文 p.14 |
| Batch 卸載降時間 | 最多 70%（AlexNet）、72%（MobileNetV2） | batch 10 | 原文 p.15, Fig.11b |
| 多裝置規模 | Brazil 8 台、US 10 台無影響 | AlexNet，全部事件上雲 | 原文 p.15, Fig.12 |
| 錯誤率變化 | −2.9%（AlexNet）、−2.5%（MobileNetV2） | vs 傳統，1 月 | 原文 Fig.6b, p.12 |
| F1 改善 | 平均 +0.02 | 逐月，無更新 | 原文 Fig.9, p.13 |
| Pareto 示例 | 約 7% error 對應約 11% 能耗；容忍 10% error 可到 1% | 1 月 validation，正規化能耗 | 原文 p.12 |
| ECE | 0.068 → 0.039（MobileNetV2 第 1 分支）；兩分支降 38%/40% | 1 月 validation | 原文 Fig.7, p.13 |
| Reject 率（全年平均） | 8%（AlexNet）、6%（MobileNetV2） | 所選 operation point | 原文 p.13 |
| 資料集規模 | 27.72 B 封包、6.14 B flows、7.1 TB；日均 610 Mbps | MAWI samplepoint-F 2016 | 原文 Table II, p.5 |

## F. 自評
- 未能確認：IEEE IoT-J 正式刊登與 DOI；rejected 事件的後續處理與 F1 對其處理方式；1 月內 train/val/test 切分；NSGA-II 的 σ 是否每次實機量測；Fig.10 所用資料子集；Pi 的網路介面；7.1 TB PCAP 是否可取得；repo 是否含能耗量測腳本（僅看 WebFetch 目錄摘要）。
- 最不確定的三件事：
  1. 特徵抽取成本是否計入能耗：論文只描述「推論 + 卸載」，我據此與 repo 以 CSV 為輸入推斷「未計入」，屬 [推測]。
  2. Table III（約 7 events/s）與 Table IV（本地 AlexNet 1385.94 ms）的不一致，原因（批次／單事件／量測方式）不明。
  3. 「F1 +0.02」是否因 reject 使比較事件集不同，論文未說明；影響「維持準確度」結論的可信度。
