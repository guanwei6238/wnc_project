# edge-multiagent-ids（Edge Multi-agent IDS, ICPS 2024）

## A. 書目與取得狀況
- 標題：Edge Multi-agent Intrusion Detection System Architecture for IoT Devices with Cloud Continuum
- 作者：Gustavo Funchal, Tiago Pedrosa, Fernando de la Prieta, Paulo Leitão [原文 p.1]
- 年份 / 出處：2024，2024 IEEE 7th International Conference on Industrial Cyber-Physical Systems (ICPS)，pp. 1–6（ISBN 979-8-3503-6301-2）[原文 p.1 頁首；出處與頁數見 IPB 儲存庫 metadata，https://bibliotecadigital.unipb.pt/entities/publication/75f96c65-7805-4c7d-8688-2c4332aac10f/full]
- DOI：10.1109/ICPS59941.2024.10639952 [原文 p.1 頁首]。（IPB 儲存庫 metadata 另列了一個 10.4018/979-8-3693-2137-9.ch003，與論文頁首不符，應是儲存庫登錄錯誤；以論文頁首為準。[推測]）
- URL：IPB 儲存庫 PDF https://bibliotecadigital.unipb.pt/bitstreams/4f407a90-39c8-4f62-a554-012dc0e4e2e7/download（儲存庫標示 CC BY-SA 4.0，但 rcaap.rights 欄位寫 restrictedAccess，兩者互相矛盾；本次可直接下載到 6 頁全文，未繞過任何付費牆）
- 與給定資訊的差異：給定「Edge Multi-agent IDS, IEEE ICPS 2024，Edge–Cloud 協同 IoT IDS」。標題為縮寫，非完整標題；ICPS 實為 Industrial Cyber-Physical Systems，會議日期 12–15 May 2024（日期來自 PDF 內嵌資訊的二手摘要，非我直接在正文看到）。「Edge–Cloud 協同」需限縮理解：論文自己說**實作與評估只涵蓋 edge 層**，cloud 層留作 future work [原文 p.1 Intro、p.6 Conclusion]。
- 取得程度：**全文**（6 頁，我讀過全部內容；頁碼以 PDF 頁序計）

## B. 核心貢獻
1. 提出兩層（edge + cloud）MAS（multi-agent system）IDS 架構：edge agent 跑低複雜度模型，cloud agent 負責全域觀察、更新 edge 模型 [原文 p.2–3, Fig.1]。
2. 以 Petri net 規範 edge agent 行為（Fig.2），及 edge agent 間「遇到無法判定的事件就把資料送給其他 edge agent 重判」的協作協定與加權投票公式（Eq.1）[原文 p.4–5, Fig.2–3]。
3. 在 CICIoT2023 上用 3 個 agent（RF / SVM / LR）驗證 edge 層協作決策：Accuracy 0.9938、Precision 0.9806、Recall 0.9039、F1 0.9388 [原文 p.6 Table I]。

## C. 指定的 9 項
**1. Research Problem**：IoT edge 設備資源受限，傳統 ML 式 IDS 難以部署，且 edge 缺乏資料處理與模型學習能力 [原文 p.1]。目標是以 MAS 把偵測分散到 edge–cloud continuum 的多個節點。

**2. Architecture**：
```
Cloud 層：cloud agents（ML engine、storage、model owners）
   - 監看 edge agents 效能，劣化時建議/下發模型更新（FL 風格但同時交換模型資訊）[原文 p.3–4]
   - 彼此共識驗證 edge 建議的修改 [原文 p.3]
Edge 層：edge agents（各嵌一個低複雜度 ML 模型）
   - 週期監看 → threat analysis (t7) → 自己有結論(t8) 或 求助(t9,t10)
   - 收到求助：用本地模型跑對方資料(t5)，回傳分類結果 + 本地模型指標(t6) [原文 p.4 Fig.2]
```
論文沒有 Packet / Flow 層的設計；沒有哪一層負責封包擷取或 flow 抽取，輸入就是資料集的現成特徵列。Cloud 層**只有概念描述，未實作** [原文 p.1, p.6]。私密資料原則上只在 edge 間共享，不上傳 cloud [原文 p.4]。

**3. Processing Location**：只有 user space。JADE（Java）agent 以 Java Runtime 開 Python 子行程執行 scikit-learn 模型，用 stdin/stdout 溝通 [原文 p.5 Sec.V]。無 kernel / 資料平面處理。Cloud 部分論文未說明部署位置。

**4. Hardware**：論文未說明（未列任何 edge 或 cloud 的硬體型號、規格）。

**5. Dataset**：CICIoT2023 [5]，105 個設備、33 種攻擊，歸為 7 類（DDoS, DoS, Recon, Web-based, Brute Force, Spoofing, Mirai）[原文 p.5]。CICIoT2023 為公開資料集（Sensors 2023），非 IoT-23、非自有真實流量。論文只說 80%/20% 切分 [原文 p.5]，未說明用了資料集的哪些檔案/多少筆、是否取樣、是二元或多類。

**6. Baseline**：僅與「三個單獨模型（LR、RF、SVM）」比較，同資料、同切分 [原文 p.6 Table I]。沒有與其他 IDS 系統、其他論文方法、或 Suricata/Snort 類規則式系統比較。

**7. Metrics**：Accuracy、Precision、Recall、F1 [原文 p.5–6]。未量測 throughput、latency、CPU、RAM、能耗、通訊量。

**8. Limitations（作者承認）**：只實作 edge 層；cloud 層行為與 edge–cloud 協作（如模型更新）留待未來 [原文 p.6]。prevention 階段不在本文範圍 [原文 p.4]。作者也說明結果受 α、β、Mi 設定與加入的模組數影響，理論上可更好 [原文 p.6]。

**9. Research Gap**：
- 作者自述：cloud agents 的行為/互動規格、edge–cloud 模型更新機制；以不同資料訓練各 agent 以展現協作效益；納入 neural network 等其他模型 [原文 p.6]。
- [推測]：沒有任何資源量測，「lightweight」無證據；沒有即時/串流流量；沒有決定何時該送 cloud 的機制。

## D. 補充欄位
**D1. 與研究主題對照**
- C1 封包處理 ×：論文未涉及封包擷取或處理，輸入為資料集特徵 [原文 p.5]。
- C2 Flow 收集 ×：論文未說明特徵如何從流量產生。
- C3 雲端卸載 △（僅概念）：cloud agent 更新 edge 模型的描述 [原文 p.3]，但未實作、未量測；且傳的是模型更新而非流量。
- C4 降低成本 ×：口頭宣稱 lightweight / 不過載中央節點 [原文 p.6]，無任何成本數據。
- K1 轉送效能：未量測。K2 資料完整性：未量測（沒有壓縮或卸載）。K3 即時性：未量測（只在文字上宣稱「lower latency」[原文 p.1]，無數據）。

**D2. 卸載與資料**
- 被傳送的內容：edge agent 之間傳的是「事件的本地資料（含於訊息中）」，回傳的是分類結果 + 該模型的指標 [原文 p.5]；edge→cloud 方向傳模型參數/資訊（概念）[原文 p.4]，細節論文未說明。
- 誰決定：agent 在「無法以本地分析得出結論」時求助 [原文 p.4–5]；論文未給出具體判斷門檻或信心值條件。
- 縮減比：論文未說明。偵測力損失：不適用。

**D3. 成本記帳**：地端 CPU/RAM/能耗、傳輸 bytes、雲端運算、time-to-detection 全部論文未說明、未量測。

**D4. 偵測方法與威脅模型**
- ML（RF / SVM / LR，scikit-learn）監督式分類，加上加權投票（Eq.1）：以 F1 作為 Mi 與 Wi，α=0.6、β=0.9 [原文 p.5–6]。偵測 7 大類 IoT 攻擊（見 C5）。是否需 payload：論文未說明（CICIoT2023 為統計特徵 [推測]）。
- 能否套到 Suricata/Snort：[推測] 投票式融合需要每個偵測器輸出「機率/信心 + 歷史指標」，規則式 IDS 只有命中/未命中的二元警報，信心值需另行定義；而且本文沒有成本模型可借用，只有決策公式。

**D5. 實驗可信度**
- 流量來源：資料集離線評估，非重播、非即時 [原文 p.5–6]。速率範圍：無。重複次數、變異量、信賴區間：論文未說明（Table I 為單一數值）。Ablation：沒有（只有單一模型 vs 組合）。
- 訓練/測試洩漏：論文寫三個模型各自用 80% 訓練，投票也用同一份 20% 測試集評估 [原文 p.5]。但 α、β=0.9 的選擇與 Mi、Wi（F1）取自何處論文未說明；若 F1 取自該測試集則有洩漏風險 [推測]。又 CICIoT2023 為逐封包視窗特徵列，隨機 80/20 切分可能讓相鄰、近似的樣本同時出現在訓練與測試 [推測]。
- 結果解讀：Edge agents decision 的 Accuracy 0.9938 低於 RF 單獨的 0.9968，Recall 0.9039 也遠低於 RF 的 0.9645、僅略高於 SVM 0.9010；F1 0.9388 亦低於 RF 的 0.9658 [原文 p.6 Table I]。作者強調的是 Precision 提升（0.9806，最高）[原文 p.6]，但最佳單一模型 RF 在 Accuracy / Recall / F1 都優於組合決策。[推測] 這代表協作未必比單挑最強模型好。
- 程式碼與資料公開：論文未說明程式碼，未見 artifact 連結。

**D6. 移植到我們平台的障礙**
- 依賴：JADE（Java）+ Python 子行程 + scikit-learn [原文 p.5]。
- Pi 3B+ 能否跑：未驗證。[推測] JVM + 每個 agent 一個 Python 子行程 + 三個模型，對 1 GB RAM 的 Pi 3B+ 負擔不小，且 JADE 在此論文中沒有任何資源量測。本論文與 XDP/eBPF 無關，不需查網卡驅動。

**D7. 對六個假說方向的證據（僅限本論文）**
- Edge–Cloud IDS 分工：弱支持（概念層級）。有分工設計，但 cloud 層未實作、無量測 [原文 p.1, p.6]。
- Flow Feature Compression：無關。
- Dynamic Flow Monitoring：無關。
- XDP-eBPF 真正省多少：無關。
- Cloud Data Offloading 的成本-時效平衡：無關（無成本與延遲數據）。
- 不同硬體限制下是否仍有效：無證據（未報任何硬體）。

**D8. 可借用與可改進**
- 可借用：(a) Eq.1 的加權投票與最低信心門檻 β，作為「本地多偵測器融合 / 升級到 cloud 的判斷」的概念 [原文 p.5–6 Eq.1]；(b) 「本地判不出來才請求協作」的觸發流程（Fig.2 的 t9）與本專案「本地判斷不出來才送雲端」的方向類似 [原文 p.4 Fig.2]。
- 可能的改進方向（皆 [推測]）：
  1. 把「求助」觸發條件明確化為信心值門檻，並量測送出流量比例（基於：論文未定義求助條件、無傳輸量數據）。
  2. 補量 Pi 級硬體上的 CPU/RAM/延遲，驗證「lightweight」宣稱（基於：論文完全沒有資源量測）。
  3. 用時間切分或按擷取檔案切分測試，檢驗洩漏（基於：隨機 80/20 與 Mi/Wi 來源不明）。
  4. 把單一 RF 當強 baseline 做 ablation，檢驗協作是否真有增益（基於：Table I 中 RF 在 3/4 指標勝出）。
  5. 以 Suricata 告警取代部分 ML agent，測試規則式與 ML 的混合決策（基於：論文僅有 ML 式 agent）。

**D9. 引用網路**（僅查到下列；查詢工具為一般網頁搜尋，未進入 Semantic Scholar / OpenAlex，cited-by 清單未能確認）
1. Funchal, Pedrosa, De la Prieta, Leitão, "A Cloud-Driven Support Layer for Enhancing Distributed IDS in IoT Networks", SN Computer Science vol.7 no.2, 2026，DOI 10.1007/s42979-026-04750-x。理由：同作者的後續擴充，補上 cloud 層（cloud agents 用 reinforcement learning 建議 edge 決策參數）。存在確認：搜尋結果顯示 DOI 與題名（https://produccioncientifica.usal.es/documentos/69a3b1b2c355ec16584b78a4），未讀全文。
2. Funchal et al., "Distributed Machine Learning and Multi-Agent Systems for Enhanced Attack Detection and Resilience in IoT Networks", ICISSP 2025, pp.192–203。理由：同組的後續實驗（搜尋摘要稱 7.73%–32.18% 的錯誤預測修正改善，我未讀全文故不採信數字）。存在確認：已確認頁面 https://www.scitepress.org/PublishedPapers/2025/131544，DOI 未驗證。
3. Neto et al., "CICIoT2023: A Real-Time Dataset and Benchmark for Large-Scale Attacks in IoT Environment", Sensors 23(13), 2023。理由：本論文使用的資料集，需了解其特徵與切分方式。存在確認：書目見本論文 reference [5]，DOI 未驗證。
4. Roy, Li, Choi, Bai, "A lightweight supervised intrusion detection mechanism for IoT networks", Future Generation Computer Systems 127, 2022, pp.276–285。理由：本論文 related work 引用的輕量 IDS（B-Stacking），可作同題比較。存在確認：書目見本論文 reference [12]，DOI 未驗證。

## E. 關鍵數字表
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| LR | Acc 0.9890 / P 0.8631 / R 0.8904 / F1 0.8762 | CICIoT2023，80/20 切分，scikit-learn | [原文 p.6 Table I] |
| RF | Acc 0.9968 / P 0.9672 / R 0.9645 / F1 0.9658 | 同上 | [原文 p.6 Table I] |
| SVM | Acc 0.9924 / P 0.9465 / R 0.9010 / F1 0.9225 | 同上 | [原文 p.6 Table I] |
| Edge agents decision | Acc 0.9938 / P 0.9806 / R 0.9039 / F1 0.9388 | α=0.6, β=0.9, Mi=Wi=F1，3 agents | [原文 p.5–6 Table I] |
| 資料集規模 | 105 設備、33 攻擊、7 類 | CICIoT2023 | [原文 p.5] |
| 資源/延遲/頻寬 | 未量測 | — | 論文未說明 |

## F. 自評
- 未能確認 / 論文未說明：硬體、延遲、CPU/RAM、傳輸量、使用的資料筆數與特徵、二元或多類、Mi/Wi 的取得來源、程式碼公開與否、cited-by。原因是論文僅 6 頁且為架構性驗證，我也未進入引用資料庫。
- 最不確定的三件事：
  1. 洩漏風險（Mi/Wi 取自何處，隨機 80/20 切分）完全是依論文文字的推測，作者沒寫明。
  2. 論文頁碼是依 PDF 頁序推算（p.1–6），與 IEEE 出版頁碼一致但我未逐頁對照版面。
  3. 儲存庫 PDF 的存取權標示矛盾（restrictedAccess 與 CC BY-SA 開放），以及 DOI 差異的成因（我推測是儲存庫登錄錯誤），這些都未向來源確認。
