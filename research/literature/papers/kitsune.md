# Kitsune（KitNET + AfterImage）
## A. 書目與取得狀況
- 標題：Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection
- 作者：Yisroel Mirsky, Tomer Doitshman, Yuval Elovici, Asaf Shabtai（Ben-Gurion University of the Negev）[原文 p.1]
- 年份 / 出處：NDSS 2018（18–21 Feb 2018, San Diego）[原文 p.1]；arXiv:1802.09089v2（27 May 2018）
- DOI：10.14722/ndss.2018.23204 [原文 p.1]
- URL：https://arxiv.org/abs/1802.09089 ；PDF 已下載至 scratchpad/kitsune/kitsune.pdf（共 15 頁，下文頁碼皆為該 PDF 實際頁碼）
- 與給定資訊的差異：書目一致。但上一輪 candidates.md 有三處需更正：
  (a) 「Pi 3B 做 active wiretap 橋接」是**攻擊者**的工具（Table III「Active Wiretap」攻擊，Tool 欄為 Raspberry PI 3B；p.10–11），不是 Kitsune 的部署方式；
  (b) 「Pi 約 1,000 pps（單一 autoencoder）、35 個時 5,400 pps」是 KitNET 的 benchmark，條件見 Q1；
  (c) benchmark 使用 n=198 特徵，與偵測實驗的 115 特徵不同（p.12 vs p.7）。
- 取得程度：**全文**（逐頁抽取文字；Fig.9 的柱狀數值以放大渲染圖逐一讀取）

## B. 核心貢獻
1. AfterImage：以 damped incremental statistics（(w, LS, SS, SR, T_last) 五元組，hash table，O(1) 更新）每封包輸出 115 維特徵，宣稱記憶體小 [原文 p.2, p.6–7]。
2. KitNET：k 個小型 3 層 autoencoder（每個輸入 ≤ m）加一個 output autoencoder，以 RMSE 聚合；訓練時一次只存一個 instance，一次 pass SGD；複雜度 O(k²) [原文 p.2, p.9–10]。
3. 在自建 IP 攝影機網路與 IoT 網路上，對 9 種攻擊做偵測，並在 Raspberry Pi 3B 單核上量 KitNET 的封包處理速率 [原文 p.10–14]。

## C. 指定的 9 項
**1. Research Problem**：閘道器/路由器資源不足，無法做監督式 ANN 的離線訓練與標註；要「即時、無監督、可 plug-and-play」的 NIDS，且封包處理速率須大於封包到達速率 [原文 p.1–2]。

**2. Architecture**：Packet Capturer → Packet Parser → FE（AfterImage）→ FM（把 n 個特徵以相關距離階層分群成 k 組，每組 ≤ m）→ AD（KitNET）[原文 p.5–6, Fig.3]。FE 每個封包取 SrcMAC-IP、SrcIP、Channel（IP 對）、Socket 四種聚合，各 5 個衰減窗（λ=5, 3, 1, 0.1, 0.01，對應 100ms–1min），共 115 特徵 [原文 p.7, Table II]。有 train-mode（FM 學分群、AD 學正常）與 exec-mode（參數凍結，只輸出分數）；分數 s ≥ φβ 即 alert，alert 只「記錄封包資訊」[原文 p.5–6]。**無雲端**，所有東西在單一設備。
```
封包 → [Capturer/Parser] → AfterImage(115維) → FM分群 → k個AE → output AE → RMSE → >φβ ? log alert
```
**3. Processing Location**：全部 user space 軟體；capturer 只舉例 NFQueue / afpacket / tshark，未選定也未量其成本 [原文 p.5]。無 kernel/XDP/交換器資料平面；無雲端。

**4. Hardware**：Pi 3B：Broadcom BCM2837、1.2 GHz、4 核、1 GB RAM；對照：Ubuntu VM（Windows 10 PC 上），Intel i7-4790 3.6 GHz、4 核（8 邏輯）、4 GB RAM [原文 p.14, Table V]。

**5. Dataset**：作者自建 testbed（非 IoT-23 / CICIoT2023）：(i) 2 組各 4 台 HD 監視攝影機（PoE、site-to-site VPN、DVR），(ii) Wi-Fi IoT 網路（9 個 IoT 裝置 + 3 台 PC），其中一台攝影機感染真實 Mirai 樣本 [原文 p.10]。9 種攻擊見 Table III（OS Scan、Fuzzing、Video Injection、ARP MitM、Active Wiretap、SSDP Flood、SYN DoS、SSL Renegotiation、Mirai）[原文 p.11]。論文本身只給 KitNET 程式碼連結；資料集 Google Drive 連結在 GitHub README [二手：https://github.com/ymirsky/Kitsune-py]。

**6. Baseline**：Suricata（13,465 條 Emerging Threats 規則）、Isolation Forest、GMM（離線）、incremental GMM、pcStream2（線上）；「每個演算法拿到完全相同的 Table II 特徵」，預設參數 [原文 p.11]。**效能 benchmark 只量 Kitsune 自己，沒有跑 baseline 在 Pi 上**；Suricata 沒有任何 Pi/速率比較。

**7. Metrics**：TPR/FNR @FPR=0 與 0.001、AUC、EER [原文 p.12, Fig.9]；封包處理速率 pps、單封包處理時間分布（µs）[原文 p.12–14, Fig.10–11]。沒有 CPU%、RAM 實測、延遲、能耗。

**8. Limitations（作者承認）**：(1) train-mode 假設流量全為正常，既有入侵者可躲過，需日後找過濾污染 instance 的機制 [原文 p.13–14]；(2) 針對 FE 的 DoS：隨機 IP 讓統計數量暴增耗盡記憶體，建議限制統計數量 [原文 p.14]；(3) m 是偵測力與速度的取捨，閾值 φ 的選法交由使用者 [原文 p.9, p.12]；(4) 實驗為單核，並行化列為未來工作 [原文 p.13]；(5) 若網路可能已被污染，建議搭配 Snort/Suricata [原文 p.14]。

**9. Research Gap**：
- 作者自述：污染資料下的訓練、多核平行化、閾值選取、FE 記憶體上限 [同 C8]。
- [推測]：整條 pipeline（含 capturer/parser/FE）在 Pi 上的端到端速率與轉送影響未量；無雲端卸載；exec-mode 不再學習（見 Q5）。

## D. 補充欄位
**D1. 與研究主題對照**
- C1 封包處理 △：只有 FE+KitNET 的計算成本，沒有封包路徑（capture/parse）成本。
- C2 Flow 資料收集 ○：AfterImage 是「每 channel 增量統計」的完整設計 [原文 p.6–7]，但是 per-packet 特徵、不是輸出 flow record。
- C3 雲端卸載 ×：論文反而主張「卸載到遠端做訓練會造成網路負擔且不可擴展」[原文 p.1]。
- C4 降成本 △：訴求是地端低成本（O(1) 更新、單核可跑），但只量 pps。
- K1 轉送效能：**未量**。K2 資料完整性：無壓縮/卸載，不適用。K3 即時性：只有 pps 與單封包處理時間（Fig.11），無 time-to-detection。

**D2. 卸載與資料**：無卸載；輸出只是本地 alert log。縮減比與偵測力損失：不適用。

**D3. 成本記帳**：地端 CPU 使用率 / RAM 實測 / 能耗：論文未說明；傳輸 bytes：無；雲端：無。記憶體僅有一句經驗估計（Q2）。端到端延遲：論文未說明。

**D4. 偵測方法與威脅模型**：無監督異常偵測（autoencoder 重建誤差），只用 header/時序統計，不需解密或 payload [原文 p.5–7]。成本模型能否套到 Suricata/Snort：[推測] 部分可。AfterImage 的成本（每封包 hash 查找 + 衰減 + 更新）與規則式 IDS 的成本結構不同（規則比對 vs 統計更新），但「每封包固定 O(1) 狀態更新」的量法可作為規則式 IDS 旁邊並行的 sidecar 成本；不能直接取代規則成本。

**D5. 實驗可信度**：資料為自建 testbed 擷取；偵測評估看起來是對錄好的 pcap 做離線評估（資料「recorded from the packet capture point」，並以「前 100 萬封包訓練、其餘執行」切分 [原文 p.10–11]，「離線重播」為 [推測]）。無重複次數、無信賴區間、無 ablation（沒有單獨量 FE 與單獨量 KitNET 的貢獻）。程式碼：KitNET-py 於論文 footnote 公開 [原文 p.2]；benchmark 的 C++ 實作未見公開（見 Q6）。

**D6. 移植到我們平台的障礙**：無特殊硬體依賴；論文已在 Pi 3B 上跑過 KitNET（已驗證，p.13–14）。阻礙 [推測]：(a) 公開版是 Python，作者 README 自承速度不佳，要 C++ 才快 [二手]；(b) 論文 Pi 數字不含 capture/parse；(c) Pi 3B+ 的 USB2 網卡中斷/復製成本與 KitNET 搶同一批 CPU。

**D7. 對六個假說方向的證據**
- Edge–Cloud IDS 分工：反駁/無關——論文立場是全本地，不卸載，但沒有實驗比較雲端方案。
- Flow Feature Compression：部分支持——增量統計取代保存視窗，狀態 O(1)/channel [原文 p.6]；沒量壓縮後對雲端偵測的影響。
- Dynamic Flow Monitoring：弱證據——只提「統計權重≈0 時可刪」與「應限制統計數量」，沒有動態調整監控粒度 [原文 p.6, p.14]。
- XDP-eBPF 省多少：無關。
- Cloud Offloading 成本-時效：無關（無雲端）。
- 不同硬體限制下是否有效：支持（有限）——Pi 3B 單核 1,000–5,400 pps，PC 7,500–37,300 pps，約 7× 差距 [原文 p.13]；僅限 KitNET 計算量。

**D8. 可借用與可改進**
- 可借用：(1) damped incremental statistics 的更新式與五元組狀態 [原文 p.6–7, Alg.3]；(2) 多時間尺度衰減窗 λ 值 [原文 p.7]；(3) 「Fig.9 的 FPR=0 / 0.001 上下界閾值」評估法 [原文 p.12, Fig.8]；(4) 以 k（ensemble 大小）取得速度-偵測取捨的旋鈕 m [原文 p.12–13]。
- 可能的改進 [推測]：
  1. 把 AfterImage 的聚合鍵與 Flow 收集合併（共用 conntrack/flow table），避免兩份 per-flow 狀態；依據：論文 FE 單獨維護 4 類聚合 hash table（p.7）。
  2. 對狀態表加上硬上限與 LRU/老化淘汰；依據：作者自承 FE DoS 與記憶體耗盡（p.14）。
  3. 對 FE 做取樣或只對可疑 flow 更新 5 窗口；依據：論文未量 FE 成本，且每封包做 115 特徵更新。
  4. exec-mode 加入安全的增量更新或定期重訓；依據：exec-mode 凍結參數（p.5）。
  5. 以 KitNET 分數當「本地不確定度」觸發向雲端送 flow record 的門檻；依據：論文無卸載機制，但 RMSE 分數天然可當門檻（p.9）。

**D9. 引用網路（≤5 篇）**
1. Han et al., Evaluating and Improving Adversarial Robustness of ML-Based Network Intrusion Detectors, IEEE JSAC 2021, arXiv:2005.07519。後續批評：摘要稱對 Kitsune「在半數情況 >97% 的 evasion rate」。存在確認：arXiv 摘要頁已確認。
2. Clements et al., Rallying Adversarial Techniques against Deep Learning for Network Security, IEEE SSCI 2021, arXiv:1903.11688。搜尋結果片段稱其評估 Kitsune，但 arXiv 摘要頁未提 Kitsune。存在確認：論文存在已確認；「評估 Kitsune」未驗證。
3. Sharon et al. (Shabtai/Elovici 同組), TANTRA: Timing-Based Adversarial Network Traffic Reshaping Attack, arXiv:2103.06297（2021）。摘要稱評估三個 NIDS，未指名；搜尋片段稱目標為 autoencoder NIDS。存在確認：論文存在已確認；是否含 Kitsune 未能確認。
4. （僅供追蹤）Stream Assembly Is an Uncontrolled Treatment in Streaming Intrusion-Detection Benchmarks, arXiv 2605.24696：Semantic Scholar 引用清單的二手摘要稱其指出 KitNET 在其 artifact 中無歸檔評估數字。存在確認：未驗證（未開原文）。
5. 實作資源：ymirsky/Kitsune-py（GitHub）。存在確認：已透過 WebFetch 確認頁面存在。

## Q1–Q7 專答
**Q1 Pi 3B 的速率條件**：
- 量的是 **KitNET（AD）的封包處理速率**，在 Pi 與 Ubuntu VM 上以 C++ 實作、n=198 個統計特徵、**單核**（Pi 為實體核、VM 為邏輯核）[原文 p.12]。該 n=198 與偵測實驗用的 115 特徵不一致，論文未解釋原因（p.7 vs p.12）。
- 速率：k=1 時 Pi 約 1,000 pps、PC 約 7,500 pps；k=35 時 Pi 約 5,400 pps、PC 約 37,300 pps（約 5× 提升）[原文 p.12–13]。Fig.11：k=1 時單封包處理時間約 950–1,100 µs，k=35 約 175–275 µs（讀圖，p.14）。
- 是否含 AfterImage 特徵抽取、Packet Parser、Capturer：**論文未說明**（文字只說「packet processing rate」）。
- CPU 使用率、RAM 使用量：論文未說明（Table V 只有硬體規格 p.14）。
- 哪些階段在 Pi 上：論文只說 benchmark 在 Pi 上跑，沒有逐階段分工；Fig.10 同時畫出 PI train-mode 與 exec-mode 曲線，顯示 benchmark 中訓練階段也在 Pi 上量過 [原文 Fig.10, p.14]。**偵測實驗（Fig.9）在哪台機器訓練與執行：論文未說明。**

**Q2 狀態成長與淘汰**：每條 incremental statistic 為 (w, LS, SS, SR_ij, T_last)，放在 hash table，單次更新 O(1)；統計量隨 distinct 的 SrcMAC-IP / SrcIP / IP 對 / socket 對（各×5 窗）增長 [原文 p.6–7]（socket 數量可隨連線大量增加為 [推測]）。淘汰：權重衰減到 0 時該統計可刪；實務上因 λ 大（衰減快）多數統計處於 w≈0，建議「定期搜尋並刪除 w≈0 的統計」[原文 p.6, p.14]。經驗值：C++ 實作約 1 MB RAM 可容納約 1,000 條 network link（每 link 5 個衰減窗）[原文 p.14]，換算約 200 B/（link·窗）為 [推測]。作者承認隨機 IP 的 DoS 可耗盡記憶體，建議限制統計數量；但**論文沒有實作或評估固定上限與淘汰策略**，也沒量 FM 的 O(n²) 相關矩陣之外的實測記憶體（只說訓練時為 O(n²)，p.8）。

**Q3 inline 還是單核軟體**：是「單核純軟體處理速度」benchmark，**不是 inline 轉送路徑**。Kitsune 只記錄 alert，不丟包/不阻擋 [原文 p.6]；Fig.7 的 Kitsune 位置是在網路中的擷取點。**論文沒有量轉送吞吐、延遲或對網路的影響**；唯一相關敘述是 ensemble 可降低處理時間變異（Fig.11）「對 jitter 敏感的應用可能有益」（p.13）。

**Q4 資料集與指標**：
- 來源：自建 testbed（非公開標準集）；切分為「前 1,000,000 封包訓練、其餘執行」，各資料集 train/execute 分鐘數見 Table III [原文 p.11]。
- 洩漏風險：(a) 時間序切分，攻擊在訓練之後才開始（Fig.8 的紅線，p.12），未見隨機洗牌洩漏；(b) 但 Table III 中 Mirai 只有 764,137 封包卻寫「前一百萬封包訓練」，兩者矛盾，Mirai 實際切點論文未說明；(c) **FPR=0/0.001 的閾值是用測試期分數反推的最佳/最差情形（Fig.8 的上下界）**，屬 oracle 閾值，不是部署時可得 [原文 p.12]；(d) 所有訓練與測試在同一網路，無跨網路驗證。
- 偵測數字（Fig.9 柱上標示值，Kitsune m=10 / m=1；Suricata 多為 0.5）：

| 資料集 | AUC m=10 / m=1 | EER m=10 / m=1 | TPR@FPR=0.001 m=10 / m=1 |
|---|---|---|---|
| ARP MitM | 0.58423 / 0.79499 | 0.45239 / 0.23152 | 0.00047 / 4e-05 |
| Fuzzing | 0.99995 / 0.99997 | 0.0012 / 0.00091 | 0.995 / 1 |
| Mirai | 0.99919 / 0.99857 | 0.00317 / 0.0032 | 0.997 / 0.997 |
| OS Scan | 0.94805 / 0.94806 | 0.09413 / 0.09412 | 0.00985 / 0.00986 |
| SSDP Flood | 0.99984 / 0.99997 | 0.00104 / 0.00067 | 0.999 / 0.999 |
| SSL Reneg. | 0.97353 / 0.9392 | 0.04603 / 0.10761 | 0.0247 / 0.0251 |
| SYN DoS | 0.95024 / 0.92289 | 0.07735 / 0.13557 | 0.246 / 0.246 |
| Video Inj. | 0.85378 / 0.80458 | 0.228 / 0.26756 | 0.0106 / 0.0106 |
| Active Wiretap | 0.88221 / 0.90876 | 0.17273 / 0.1693 | 0.00147 / 0.00046 |

  TPR@FPR=0 僅 Mirai 非零（0.3223 / 0.3210），其餘 ≤ 0.00014（SYN DoS）或 0 [原文 Fig.9, p.13]。（柱與圖例對應依圖面位置判讀，個別柱可能判讀有誤。）

**Q5 限制**：作者承認見 C8。我觀察到但作者未承認的 [推測]：
- exec-mode 參數凍結，min/max 正規化記錄只在 train-mode 更新 [原文 p.5, p.9]，所以遇到概念漂移（新裝置、行為改變）不會自我調整，與標題「online」的印象有落差。
- 封包級偵測在 FPR=0.001 時，若 5,400 pps 全速，理論上約 5 個 false positive/秒（算術推論），且上表多個資料集 TPR@0.001 很低（ARP、OS Scan、Wiretap、Video Inj. ≤ 0.011）。
- Suricata 對比不公平：Suricata AUC/EER 幾乎 0.5（p.13），攻擊類型多為規則集沒涵蓋的行為，並非代表規則式 IDS 的上限。
- 特徵使用 MAC/IP 位址與 port，換網路需重新訓練；IPv6 論文未說明。
- 無對抗式實驗（僅在 Sec.VI 討論），後續他人已展示 evasion（D9）。
- 僅單一作者團隊自建資料，缺跨資料集驗證。

**Q6 程式碼與重現**：KitNET-py 程式碼公開 [原文 p.2 footnote 1]；Kitsune-py 倉庫 MIT 授權、約 398 stars、118 forks、20 open issues，語言為 Python（含一個實驗性 Cython 模組），README 自承速度「not optimal」，要顯著加速需用 C++ 或完全 Cython [二手：https://github.com/ymirsky/Kitsune-py，經 WebFetch 摘要]。論文 Pi benchmark 用的 C++ 實作：倉庫頁面未見，**因此論文的 Pi pps 數字無法直接用公開程式碼重現（[推測]）**。後續批評見 D9：Han et al. 2021（已確認摘要含 Kitsune）；Clements et al.（Kitsune 內容未驗證）；Stream Assembly 論文（未驗證）。Cited-by 總數：Semantic Scholar 回應被截斷／429，未能確認。

**Q7 [推測] 放置位置**：論文線索只有兩點：capturer 舉 NFQueue / afpacket 為例（p.5），以及 FE 是 O(1) hash 更新（p.6）。其餘成本論文未量。推論：(a) 最安全是 user space，從 AF_PACKET（旁路複製）取樣封包，不放進 NFQUEUE verdict 路徑，避免 userspace 排隊拖慢轉送；(b) 若必須進核心，eBPF 內缺浮點，2^(−λt) 衰減需改用定點或查表，且每封包要更新 4 類 × 5 窗口的 map，成本未知；(c) 折衷：kernel 只做 per-flow 計數（nftables counter / conntrack），user space 以較低頻率批次更新 AfterImage 統計。這三點都需要實測，論文沒有答案。參考尺度：論文自己的攝影機流量為每台 195–350 pps、1.4–1.8 Mbit/s（Table IV, p.11），遠低於我們可能要處理的轉送速率。

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| KitNET 封包處理速率（Pi 3B） | ≈1,000 pps（k=1）；≈5,400 pps（k=35） | 單核，C++，n=198 特徵，是否含 FE 未說明 | p.12–13 |
| 同上（Ubuntu VM, i7-4790） | ≈7,500 pps；≈37,300 pps | 同上 | p.13 |
| 單封包處理時間（Pi） | k=1 約 950–1,100 µs；k=35 約 175–275 µs | 讀自 Fig.11 | p.14, Fig.11 |
| FE 記憶體經驗值 | ≈1 MB 容納 ≈1,000 links（每 link 5 窗） | C++ 實作 | p.14 |
| 特徵數 | 115（偵測）／198（benchmark） | — | p.7 / p.12 |
| 單 AE 輸入上限 m | 偵測實驗用 m=1 與 m=10 | — | p.11 |
| Suricata 規則數 | 13,465 | Emerging Threats | p.11 |
| 資料量 | 764,137–6,084,492 封包／資料集 | Table III | p.11 |
| 攝影機流量 | 195–350 pps、1.4–1.8 Mbit/s／台 | Table IV | p.11 |
| 偵測 AUC/EER/TPR | 見 Q4 表 | m=10 / m=1 | p.13, Fig.9 |
| Pi 的 CPU%、RAM 使用量、能耗、轉送吞吐、延遲 | 論文未說明 | — | — |

## F. 自評
- 未能確認：cited-by 總數與批評論文內容（Semantic Scholar 被 429／回應被截斷）；FE 是否含在 Pi 速率內；偵測實驗跑在哪台機器；Mirai 訓練/測試切點；n=198 的來源；公開資料集的正式版本資訊。
- 最不確定三件事：(1) Fig.9 數值是從圖的柱標籤判讀，個別柱對應演算法可能錯位；(2) Fig.11 的 µs 範圍為讀圖估計；(3) Q6 的後續批評論文，除 Han et al. 外，Kitsune 是否為其評估對象尚未用全文驗證。
