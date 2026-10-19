# HorusEye

> 頁碼一律用 USENIX 論文集頁碼（本文 p.571–588，含附錄）。Table / Fig 編號為論文原編號。

## A. 書目與取得狀況

- 標題：HorusEye: A Realtime IoT Malicious Traffic Detection Framework using Programmable Switches
- 作者：Yutao Dong, Qing Li, Kaidong Wu, Ruoyu Li, Dan Zhao, Gareth Tyson, Junkun Peng, Yong Jiang, Shutao Xia, Mingwei Xu（清華深圳國際研究生院 / 鵬城實驗室 / 港科大廣州 / 清華）[原文 p.571]
- 年份 / 出處：2023，32nd USENIX Security Symposium, Anaheim, CA, Aug 9–11；pp.571–588，ISBN 978-1-939133-37-3 [原文 p.571；會議頁面 https://www.usenix.org/conference/usenixsecurity23/presentation/dong-yutao]
- DOI：會議頁面未列 DOI；我也沒查到，記為「未能確認」。
- URL：論文 https://www.usenix.org/system/files/usenixsecurity23-dong-yutao.pdf ；附錄 https://www.usenix.org/system/files/usenixsecurity23-appendix-dong-yutao.pdf ；程式碼 https://github.com/vicTorKd/HorusEye（論文 p.572 腳註 3 所列；我另抓到的頁面顯示為 victorkdwu/HorusEye，大小寫/帳號名可能是轉址或改名，未深究）
- 與給定資訊的差異：書目（USENIX Security 2023）與給定一致。補充一個容易誤會的點：給定說「快速路徑初步過濾，複雜流量交控制平面」，這在論文中的「快速路徑」是 **P4 可程式交換器（Intel Tofino ASIC）資料平面**，「控制平面」是 **x86 伺服器 + GPU**，並非主機 kernel 與雲端 [原文 p.572, p.577]。
- 取得程度：**全文**（PDF 全文以 pdftotext 讀完，含附錄 A–E）。GitHub 頁面只看了 README/檔案清單，沒有跑程式碼。

## B. 核心貢獻

1. **iForest 轉成交換器白名單規則**：把訓練好的 iForest（多棵 iTree）聚合成 hypercube，再以向下取整得到整數邊界，用範圍比對規則實作；論文自稱是第一個能在資料平面偵測未知攻擊的非監督模型 [原文 p.571, p.573–574]。規則與原模型的 label 一致率 99.46%–99.68% [原文 Table 1, p.579]。
2. **交換器上的 burst 級特徵抽取**：burst segmentation（門檻 15 個封包）、bi-hash（XOR 兩個單向 hash 以匹配雙向流）、double hash table（降低碰撞）[原文 p.574–575]。32,000 flows、總位寬 18 時碰撞率約 0.6% [原文 p.575]（附錄 Table 8 的模擬為約 1.0%，兩者條件不同，見 F）。
3. **兩階段分工**：資料平面 Gulliver Tunnel 過濾正常流量，控制平面 Magnifier（輕量非對稱 autoencoder + separable/dilated conv + int8 量化）複查可疑流量。摘要宣稱資料平面偵出 99% 異常、從控制平面卸載 76% 流量 [摘要 p.571]；Gulliver Tunnel + Magnifier(int8) 達 12M pps [原文 p.582]。

## C. 指定的 9 項

**1. Research Problem**
現有 IoT 異常偵測把所有流量送到控制平面做，吞吐跟不上；全部上傳也造成通訊開銷 [原文 p.571]。目標：在交換器資料平面用非監督模型先濾掉大部分正常流量，只讓可疑流量進入較重的深度模型。威脅模型：被入侵的 IoT 裝置（Mirai 類 botnet、DDoS、掃描、資料外洩）；假設新裝置出廠時是良性、攻擊在 IP 層以上留有流量痕跡；不處理竊聽與 MAC spoofing [原文 p.572]。

**2. Architecture**
```
IoT 流量 ──> [P4 交換器 / Tofino]
              blacklist(port/proto) -> bi-hash 找 flow -> double hash table 存 burst 特徵
              burst 結束 -> iForest 白名單規則比對
              ├─ 命中白名單(正常)：轉發；鏡射封包只丟 payload、上傳 header 供儲存
              └─ 未命中(可疑)：回報 flow ID + burst 資訊
                              │
                              ▼
         [x86 控制平面 + GPU]  suspicious flow table
              異常頻率 > 門檻 -> 取歷史鏡射封包 -> Kitsune 特徵 -> Magnifier(autoencoder, RMSE)
              確認惡意 -> 寫回交換器 blacklist（封鎖或限速）
```
[原文 p.572 Fig.1、p.575–576 Step 1–3、p.572 Magnifier 段落]。控制平面也會在有新流量時更新 iForest 與深度模型 [原文 p.572]。

**3. Processing Location**
資料平面（Tofino 交換器 ASIC，P4 實作 ingress：流識別、特徵、偵測；egress：鏡射與轉發）；控制平面（x86 伺服器，PyTorch + TensorRT，跑在 GPU）[原文 p.575, p.577]。無 kernel / user-space 封包處理，無雲端。

**4. Hardware**
- 交換器：H3C S9830-32H-H 資料中心交換器，Intel Tofino ASIC [原文 p.577]。資源：SRAM 12160 kbit（9.90%）、TCAM 88 kbit（2.78%）、66 個 table [原文 Table 3, p.580]。
- 控制平面 GPU：GeForce RTX 2080 SUPER [原文 p.577]。伺服器 CPU/RAM 型號：論文未說明。
- 流量產生器：SPIRENT N11U [原文 p.580]。

**5. Dataset**
- 自建 testbed：8 種攝影機 + 7 種感測器 + 1 台 smart gateway，跑一個月，13.9 GB PCAP，已匿名並丟棄 payload；前 4 天訓練、後 2 天測試 [原文 p.577]。
- 公開正常流量 [32]（Sivanathan 等，UNSW IoT）：5 種攝影機 + 5 種感測器，隨機選 5 天訓練、各自隔天測試 [原文 p.577–578]。
- 攻擊：公開資料集 [5][10][18][26]（Bashlite/Aidra/Mirai、Bot-IoT 的 keylogging/data theft、Kitsune 資料集等）+ 自行感染一台裝置重現 Mirai、OS scan、service scan、TCP/UDP DDoS；共 10 種攻擊、26 種 IoT 裝置 [原文 p.577]。攻擊為與正常測試集混合 [原文 p.578]。Kitsune 的 Mirai 被降採樣到約 40,000 封包 [原文 p.578]。
- **不是** IoT-23 或 CICIoT2023。是否公開：README 指向 Google Drive 下載（[二手] GitHub 頁面，我沒有實際下載驗證）。

**6. Baseline**
Kitsune（非監督、Python 版，在控制平面）與 Mousika（監督式決策樹，資料平面）[原文 p.571, p.581]。偵測力比較在同一份資料上；吞吐比較時 Kitsune 用論文作者自己重現的 Python 版（fp32 對 fp32），C++ 版的「100 倍」是引用 Kitsune 自述而非重跑 [原文 p.582]。Mousika 僅在 botnet 三類攻擊上比較（2 種訓練、1 種當未知攻擊測試）[原文 p.581]。沒有跟 Suricata/Snort 這類規則式 IDS 比較。

**7. Metrics**
TPR@FPR≤5e-5 與 5e-4、PRAUC（正常資料降採樣至 10%）[原文 p.580]；hyperparameter 階段用 TPR/TNR [原文 p.578]；交換器資源（SRAM/TCAM）、吞吐、延遲 [原文 p.580]；控制平面 pps [原文 p.582]；規則數、枚舉數、label 一致率 [原文 p.579]；對抗與投毒下 TPR [原文 p.582]。

**8. Limitations（作者承認）**
- 規則可解釋、故無法防禦 white-box 攻擊 [原文 p.582]。
- 訓練集被污染超過 2% 時 Gulliver Tunnel 的 TPR 下降 [原文 p.582]。
- 所有方案在 FPR≤5e-5 下都難召回 HTTP DDoS（需看請求內容與頻率，要伺服器端更細判斷）[原文 p.581]；botnet 感染與資料外洩（SSH 傳輸）PRAUC 較低 [原文 p.581]。
- 威脅模型假設（裝置出廠良性、攻擊留下 IP 層以上痕跡）[原文 p.572]。
- 特徵必須是整數（浮點在資料平面不支援）才能用 Theorem 1 的取整 [原文 p.573–574]。

**9. Research Gap**
- 作者自述：對 white-box 攻擊的強健性留待 future work [原文 p.582]。
- [推測] 見 D8。

## D. 補充欄位

**D1. 與研究主題對照**
- C1 封包處理 △：硬體資料平面做 O(1) 特徵與規則比對 [原文 p.575]，但平台是 Tofino，不是 CPU/Linux 封包處理。
- C2 Flow 收集 ○：burst 級特徵 + bi-hash + double hash table 是核心貢獻 [原文 p.574–575]。
- C3 雲端卸載 △：只有「資料平面 → 控制平面」兩層；控制平面是與交換器直連的 x86 伺服器，非經 WAN 的雲端 [原文 p.572]；[推測] 可類比到 gateway → cloud。
- C4 降成本 △：降的是控制平面的處理量（卸載 76% 正常流量）[摘要]，不是地端運算或傳輸 bytes。
- K1 轉送效能：有量。100 Gbps 單埠、256–1500 B 與 IMIX 無丟包，延遲 1027–1142 ns，平均 1065.6 ns [原文 Table 4, p.580]。沒量：多埠、不同規則數下的延遲變化。
- K2 資料完整性：有量偵測力（TPR/PRAUC，Table 5/6/10）；沒量「資料量縮減後」的完整性，因為送出的是 flow ID，不是資料。
- K3 即時性：只量交換器逐封包延遲與控制平面吞吐；**沒有 time-to-detection / 端到端偵測延遲**（論文未說明）。

**D2. 卸載與資料**
- 送什麼：可疑 flow ID + 異常 burst 資訊（burst size、封包數）送控制平面；另外**所有鏡射封包**（正常者去 payload 只留 header，可疑者封裝 header）也送伺服器儲存，供控制平面事後取歷史封包 [原文 p.572, p.576]。
- 誰決定：資料平面依 iForest 白名單規則（未命中即可疑）；控制平面再用「異常頻率」F = 該 flow 被判異常的 burst 比例，超過門檻才跑 Magnifier [原文 p.572, p.579 Eq.3]。
- 縮減比：卸載 76% 正常流量（在自建資料測試集）、吞吐增益 4.13x [原文 p.582]。驗證集（HTTP DDoS）門檻 0.95 時可偵出 98.6% 惡意、卸載 96.0% 正常流量，且未使用 port 規則 [原文 p.579]。兩個卸載率條件不同（驗證 vs 測試），論文未解釋差異。
- 偵測力損失：HorusEye 與只用 Magnifier 的 macro TPR（FPR≤5e-5）自建資料 0.852 vs 0.825，PRAUC 0.973 vs 0.968 [原文 Table 5]，即論文稱兩者相當、甚至略好。
- [推測] 因為鏡射 header 持續送往伺服器，「傳輸 bytes」並未依 76% 縮減；論文沒有量這條鏈路的頻寬。

**D3. 成本記帳**
- 地端（交換器）：SRAM/TCAM 佔用有量 [Table 3]；功耗未量。
- 控制平面：只量吞吐（pps），CPU / RAM / 能耗未量；用 GPU。
- 傳輸 bytes / 頻寬：未量。
- 雲端運算：不適用。
- time-to-detection：未量。

**D4. 偵測方法與威脅模型**
非監督 ML + DL：iForest（burst 級特徵：封包數與 burst 大小，另加 destination port 的 port-level iForest 輔助）→ 白名單；Magnifier 用 Kitsune 特徵（5 個時間窗 × 20 特徵，+port，成 5@21 輸入）[原文 p.576–577]。偵測 botnet、資料外洩、掃描、DDoS。**不需解密、不看 payload**（資料集甚至已丟棄 payload）[原文 p.577]。
成本模型能否套到 Suricata/Snort：[推測] 部分可以。「先用廉價白名單濾掉多數正常流量，剩餘才進重檢測」的結構可類比；但 Suricata 的成本在 payload 規則比對，HorusEye 的白名單是行為特徵，兩者要濾的對象不同，卸載率不能直接搬過來。

**D5. 實驗可信度**
- 流量來源：離線 pcap（自建 + 公開）混合；交換器吞吐用 SPIRENT 產生合成流量 [原文 p.580]。
- 速率範圍：100 Gbps 單埠；各封包大小各一個數字。
- 重複次數 / 變異量 / 信賴區間：論文未說明；表格皆為單一數值，未見 error bar。
- Ablation：有（w/ vs w/o port rules、各超參數、fp32 vs int8、有無 Gulliver Tunnel）[Fig 6, Fig 8]。
- 切分：自建資料按時間切（4 天/2 天）[p.577]；**超參數用 HTTP DDoS 作攻擊驗證集 [p.578]，而 HTTP DDoS 也出現在 Table 5 測試結果中**，[推測] 這對 HTTP DDoS 一項構成輕微洩漏風險（論文未說明驗證與測試的攻擊流量是否分開）。
- 偵測力實驗為離線重播資料，非線上即時。
- 程式碼與資料：有公開 repo 與 P4 檔，USENIX 會議頁面顯示「Artifacts Available / Artifacts Functional」徽章（[二手] 會議頁面）。

**D6. 移植到我們平台的障礙**
- 資料平面必須是 Tofino 交換器（P4、resubmit、TCAM/SRAM）；**Pi 3B+ 無法跑**（[推測]，由硬體需求直接得出，未實測）。
- Magnifier 依賴 GPU + TensorRT int8；Pi 上無此條件。CPU-only 推論的可行性論文未評估。
- 可抽取的概念（[推測]，未驗證）：burst 特徵與 bi-hash 概念可用 eBPF hash map 或 conntrack 實作；iForest 範圍規則可嘗試 nftables 的 interval/concatenated set，但規則數量（port exact rules 達 3585 條、burst 範圍規則 77 條 [原文 p.580]）與比對效率需實測。
- 非 XDP 論文，故不適用 XDP 驅動檢查。

**D7. 對六個假說方向的證據（只限本論文）**
- Edge–Cloud IDS 分工：**支持**（邏輯層面）。先濾正常再複查可疑，吞吐增益 4.13x、偵測力不降 [原文 p.582, Table 5]；但「edge」是交換器，不是資源受限裝置。
- Flow Feature Compression：**部分相關**。把流壓成 burst 級（封包數、大小）特徵即足以識別多數攻擊，TPR 與完整 Magnifier 相當 [Table 5]；但這是偵測用特徵，不是上傳給雲的壓縮格式，也沒量位元組縮減。
- Dynamic Flow Monitoring：**弱相關**。有 burst 結束即釋放 register、異常頻率門檻動態決定是否送深檢 [p.575, p.579]；沒有動態調整監控粒度的機制。
- XDP-eBPF 真正省多少：**無關**。
- Cloud Data Offloading 的成本-時效平衡：**證據不足**。有卸載比與吞吐，但無 bytes 與 time-to-detection。
- 不同硬體限制下是否仍有效：**部分**。表 10 顯示在公開資料集（裝置少）上各方法差距縮小（macro TPR 0.782 vs Kitsune 0.760）[Table 10]，但沒有在較弱硬體上測試。

**D8. 可借用與可改進**
可借用：
- iForest→整數範圍白名單的轉換流程與 label 一致率驗證方法 [原文 p.573–574, Eq.4]。
- bi-hash（兩個單向 hash XOR）與 double hash table 的碰撞分析 [原文 p.574–575, Appendix B]。
- burst segmentation 的參數選擇方式（τ=1 s、門檻 15，由 burst 長度 PDF 決定）[原文 p.577, App. C]。
- 異常頻率 F 作為「送不送深檢」的門檻 [原文 Eq.3]。
- TPR@極低 FPR + PRAUC 的評估方式 [原文 p.580]。

可能的改進方向（全部 [推測]）：
1. 把白名單前置濾器做在 Linux nftables/eBPF，量測 Pi 上「濾掉比例 vs CPU」——基於 D6（Tofino 依賴）。
2. 量測並降低「鏡射 header 到伺服器」的傳輸量，補上 D3 缺失的 bytes 記帳——基於 D2 所述鏡射封包持續上傳。
3. 加入 time-to-detection 測量（burst 結束 + 異常頻率累積 + 複查）——基於 K3 缺口。
4. 用 CPU-only / 輕量模型替換 GPU 上的 Magnifier，觀察偵測力與延遲——基於 D6。
5. 與 Suricata/Snort 規則式檢測串接，把白名單未命中流量交規則引擎，比較偵測力——基於 Baseline 無規則式 IDS 比較。

**D9. 引用網路（建議追加閱讀）**
查詢方式：OpenAlex 全文搜尋「HorusEye」+ 論文 references；沒有取得正式 cited-by 清單，下列後續工作僅「全文提及 HorusEye」層級，是否為實質比較未逐篇確認。
1. Peregrine: ML-based Malicious Traffic Detection for Terabit Networks, arXiv 2403.18788。把 Kitsune 特徵計算卸載到交換器，推論留在控制平面；同題替代方案、同樣以 Kitsune 為基準。存在確認：已確認 arXiv（搜尋結果）。
2. Genos: General In-Network Unsupervised Intrusion Detection by Rule Extraction, Ruoyu Li et al., INFOCOM 2024, arXiv 2403.19248。同一實驗室，後續改進者（model-agnostic 規則萃取、增量更新規則）。存在確認：已確認 arXiv；與 HorusEye 的關係為作者重疊（Ruoyu Li, Qing Li, Dan Zhao, Yong Jiang）[二手 arXiv 頁面]，未確認內文比較。
3. Helios: Learning and Adaptation of Matching Rules for Continual In-Network Malicious Traffic Detection, 2025, DOI 10.1145/3696410.3714742。處理規則隨時間更新，對應 HorusEye 的模型漂移/重訓問題。存在確認：DOI 來自 OpenAlex（全文搜尋命中 HorusEye）；內容未讀。
4. Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection, Mirsky et al., NDSS 2018。HorusEye 的主要基準與 Magnifier 的特徵來源 [原文 ref 26]。存在確認：書目由 HorusEye 參考文獻確認；未查 DOI。
5. Realtime Robust Malicious Traffic Detection via Frequency Domain Analysis (Whisper), Fu et al., CCS 2021。HorusEye 稱其為純控制平面方案、與自己正交 [原文 p.571, p.583 ref 12]；作為不依賴交換器的軟體偵測基準。存在確認：書目由 HorusEye 參考文獻確認；未查 DOI。

## E. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| 異常召回 / 流量卸載 | 99% / 76% | 自建資料測試集，資料平面 | 摘要 p.571；p.582 |
| 吞吐增益 | 4.13x | 76% 正常流量不進控制平面 | p.582 |
| 交換器單埠速率 | 100 Gbps，0 丟包 | 256/512/1024/1500 B 與 IMIX | Table 4, p.580 |
| 逐封包延遲 | 1027 / 1033 / 1052 / 1074 / 1142 ns（256/512/1024/1500/IMIX）；平均 1065.6 ns | Tofino，SPIRENT N11U | Table 4, p.580 |
| SRAM / TCAM 佔用 | 12160 kbit（9.90%）/ 88 kbit（2.78%） | 66 tables | Table 3 |
| 控制平面 pps | Magnifier fp32 1,131,094；Kitsune Python 1575；HorusEye(G+M int8) 12M，為 Kitsune 的 7654x | RTX 2080 SUPER；Kitsune 為作者重現的 Python 版 | p.582, Fig 8(a) |
| 量化效果 | int8 吞吐 2.5x；macro TPR@FPR≤5e-5 0.675→0.636 | Magnifier fp32→int8 | p.582–583, Fig 8(b) |
| macro TPR@FPR≤5e-5 | HorusEye 0.852；Kitsune 0.705；Magnifier 0.825 | 自建訓練、自建+重現攻擊 | Table 5 |
| macro TPR@FPR≤5e-5（公開攻擊） | HorusEye 0.608；Kitsune 0.442；Magnifier 0.600 | 同上，攻擊 [5][18][26] | Table 5 |
| macro PRAUC | HorusEye 0.973；Magnifier 0.968；（公開攻擊）0.881 | | Table 5 |
| 未知 botnet PRAUC | HorusEye 0.781；Kitsune 0.723；Mousika 0.646 | 訓練含/不含攻擊的比較設定 | Table 6 |
| 規則-模型一致率 | 99.46%–99.68% | ψ=400, t=10…5000 等組合 | Table 1 |
| 規則數 | burst 範圍規則 77、port 精確規則 3585 | 實驗設定 | p.580 |
| 異常頻率門檻 0.95 | 偵出 98.6% 惡意、卸載 96.0% 正常 | 驗證集（HTTP DDoS），不含 port 規則 | p.579 |
| 低速率 DDoS | TPR 100% | 速率降 100 倍（900 pps） | p.582 |
| 投毒 | TPR 99%（1% 污染）；>2% 下降 | Mirai 混入訓練集 | p.582 |
| 雜湊碰撞 | double 約 1.03% vs single 約 11.3% | 同位寬，8000–64000 flows | Table 8, App. B |
| bi-hash 碰撞 | XOR 31.8%、加法 54.8%、五元組 29.0% | 2^16 flows，register 2^17 | App. B |
| 超參數 | t=200，ψ=5000，burst contamination 0.15，port 0.05，τ=1 s，分段門檻 15 | | p.577–579 |

## F. 自評

未能確認的欄位：DOI（頁面未列）；控制平面 CPU/RAM；重複次數與變異量（論文未說明，表中未見）；傳輸 bytes；time-to-detection；功耗；公開 repo 的 license 與資料集實際可下載性（只看 README 與檔案清單）。

最不確定的三件事：
1. 卸載率 76%（測試集）與 96.0%（驗證集 0.95 門檻）的條件差異，以及摘要的 99%/76% 是否為同一個運作點。論文沒有逐項對照，我只能分開引用。
2. 控制平面實際收到的位元組量：p.576 寫明所有鏡射封包的 header 都送到伺服器，但論文沒有量這條鏈路，我對「傳輸成本未降」的判斷屬 [推測]。
3. Fig 8(a) 各長條對應的數值，我是由圖中文字標註（1575、6514、1131094、2915116、12056569）與內文 7654x、4.13x、2.5x 做算術一致性比對推得，圖上的對應位置沒有人眼檢視。
