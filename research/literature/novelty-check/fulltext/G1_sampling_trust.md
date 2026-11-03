# G1：取樣／信任／過濾類 六篇全文查核

查核基準：`../SCREEN.md` 的 C1–C4（C1 放行後稽核與撤銷、C2 inline 部分檢查、C3 同機 rule IDS + ML 資源分配、C4 kernel fast path）。
六篇都已讀完全文（文字檔全部讀完；ISNCC 2025 另用 PDF 第 2–6 頁核對圖表）。
標記：overlap／related／none。「related（弱）」＝只有一個周邊要素重疊，引用即可，不構成威脅。

## 總表

| n | 論文 | C1 | C2 | C3 | C4 |
|---|---|---|---|---|---|
| 297 | Meng 2018, IEEE Computer | related（弱） | related（弱） | none | none |
| 449 | Goldberg & Rexford, Sarnoff 2007 | related（弱） | none | none | none |
| 468 | SparseIDS（Bachl et al.），CNS 2020 | none | related | related（弱） | none |
| 107 | Giacometti et al., ISNCC 2025 | related | related（弱） | none | related（弱） |
| — | Kodialam & Lakshman, INFOCOM 2003 | none | none | none | none |
| 395 | Valgenti, Sun, Kim, AINA 2014 | related | related | none | none |

六篇沒有任何一篇是 overlap。

---

## 1. n=297 Meng 2018

**書目**：Weizhi Meng（Technical University of Denmark），"Intrusion Detection in the Era of IoT: Building Trust via Traffic Filtering and Sampling"，IEEE Computer，2018 年 7 月，pp. 36–43（IEEE Computer 的 cyber-trust 專題文章，非完整研究論文）。

**他們做了什麼**
- 問題：IoT 流量暴增，IDS 處理不完而丟封包，導致「以流量為基礎的 trust 計算」失效（p.38）。
- 機制：IDS 前面串兩段減量：(1) traffic filtration（blacklist／whitelist，以 IP 為單位）；(2) traffic sampling（packet-based 的 systematic sampling，固定間隔取樣）。(p.39–41)
- trust 的意思是「節點（IoT node）的信譽值」，用 Bayesian 公式 (k+1)/(N+2) 由 IDS 判為正常的封包比例算出，低於門檻 0.8 就判為惡意節點（p.40）。這和我們的「flow 被信任後放行」不是同一個概念。
- blacklist filter 的行為：來源 IP 在 blacklist 上才對封包 payload 比對 signature；不在 blacklist 的封包送進 NIDS（p.41）。也就是 filter 是把「可疑」的拿出來，不是把「可信」的放行。whitelist 只有一句話：「Whitelisted packets can go directly to the target network」，且「whitelist can only be finalized and updated by the security administrator」（p.39）。
- 平台／IDS：論文未說明 IDS 軟體與硬體；沒有 ARM；非 inline 量測。與華南某 IT 中心合作，136 個 WSN 節點中的 55 節點子網路。
- 量測：平均 9,792 packets/s、最高 12,530 packets/s；用 6 個節點做 "betrayal attack"（benign 節點突然變惡意）；攻擊基礎比率約 0.004215；結果只有 Figure 5（trust value 隨小時變化的曲線），沒有漏報率、沒有每封包成本。

**對 C1–C4**
- C1：related（弱）。證據：p.41「betrayal attack, where a benign node suddenly becomes adversarial」——概念上是「先正常、後攻擊」，且 trust 值持續被取樣到的封包更新。缺：沒有 flow／連線層級的放行、whitelist 流量不再被抽回檢查（p.39 whitelist 只由管理員更新）、沒有撤銷機制、沒有量化「放行後才攻擊」的漏報。
- C2：related（弱）。證據：p.41 systematic sampling「selects ... a fixed periodic interval」，是以封包為單位的 1/N 取樣。缺：不是每段對話開頭、不是有狀態 IDS、非 inline、非 ARM、沒有處理填充規避。
- C3：none。無 ML 同機。
- C4：none。blacklist filter 是 IDS 前的應用層模組，不涉 kernel 機制，也沒有成本量測。

**可比數字**
- 9,792 pps（平均）／12,530 pps（最高）是他們認為「重流量」的情境（p.41）；我們 Pi 上整台約 60 kpps 才滿。
- 「Snort usually spends about 30 percent of its total computational power」在 payload 與 signature 比對（p.38–39），是泛稱，沒有量測方法。
- 這篇沒有可比的每封包成本、吞吐或偵測率。

**引用方式**：作為背景（IDS 前面做 filter+sampling 降負載是舊想法）；也可作為反駁對象——它用固定間隔 systematic sampling，而 Goldberg & Rexford（n=449）指出固定週期可被預測規避。要註明它的 "trust" 是節點信譽，與我們的 flow trust 不同，以免審查者混淆。

**雪球**（本篇引用中比它更接近的）
1. Papadogiannakis, Polychronakis, Markatos, "Improving the Accuracy of Network Intrusion Detection Systems Under Load Using Selective Packet Discarding," EUROSEC 2010（本篇 ref 11；Valgenti n=395 也引用）——IDS 過載時依 flow 內位置選擇性丟棄封包（Valgenti 描述為只重視 flow 前段位置的封包），最接近 C2 的「只看開頭」；兩篇都引，優先級最高。
2. Meng & Kwok, "Adaptive Blacklist-Based Packet Filter with a Statistic-based Approach in Network Intrusion Detection," J. Network and Computer Applications 39, 2014（ref 9）——依 IDS 歷史告警動態產生 filter，接近「依 IDS 結果調整放行」（C1／C4 邊緣）。
3. Meng et al., "Enhancing Trust Management for Wireless Intrusion Detection via Traffic Sampling in the Era of Big Data," IEEE Access 6, 2018（ref 14）——同作者的完整版研究，信任＋取樣，可能有更多實驗細節（C1）。
4. Androulidakis & Papavassiliou, "Improving Network Anomaly Detection via Selective Flow-Based Sampling," IET Communications 2008（ref 13）——flow 層級取樣（C1／C2 弱）。
5. Sforzin et al., "RPiDS: Raspberry Pi IDS," 2016 UIC/ATC/... 會議（ref 2）——在 Raspberry Pi 上跑 IDS，可能提供 Pi 上 IDS 的基準數字（C3／C4 的平台背景；Meng 這篇只當 IoT 背景引用，內容未說明）。

---

## 2. n=449 Goldberg & Rexford 2007

**書目**：Sharon Goldberg, Jennifer Rexford（Princeton），"Security Vulnerabilities and Solutions for Packet Sampling"，IEEE Sarnoff Symposium 2007（文字檔本身未印 venue，依任務說明）。約 4 頁。

**他們做了什麼**
- 對象：IETF PSAMP 的被動封包取樣（流量計量、計費、入侵偵測用），威脅模型是「敵手能控制封包所有欄位，企圖讓自己的封包不被取樣」。
- 結論：deterministic periodic sampling、不帶 key 的 hash 取樣、帶 key 但非密碼學強度的 hash（如 CRC）取樣都可被繞過（Sec II-B、III）；建議非協調取樣用密碼學強度亂數的 random sampling（Sec II-A），協調取樣用帶 secret key 的 PRF（Sec IV-B），並在側通道洩漏取樣歷史時換 key（Sec IV-C）。
- 是理論／安全分析，沒有實作、沒有量測、沒有 IDS、沒有硬體、沒有數字。

**對 C1–C4**
- C1：related（弱）。證據：Sec II-B 敵手知道取樣週期 T，就能讓自己的封包以 1−p 的機率完全不被取樣。這支持「固定稽核窗可被預測、稽核要隨機化」。缺：沒有 IDS、沒有放行後再檢查、沒有撤銷、沒有量化。
- C2：none。Sec III-B 的 footnote 3 提到「Host knows that only the first N bytes of each packet are used」可以針對性構造封包，這與 DPA 被填充繞過是類比，但對象是取樣器的 hash，不是 IDS。
- C3：none。
- C4：none。

**可比數字**：無。

**引用方式**：作為設計依據與反駁對象——說明為什麼稽核時間點／窗口要隨機（固定窗被預測就失效），並呼應我們實測「固定稽核窗約抓到 10%」。

**雪球**：引用清單都是計量取樣標準與同組作者的路徑品質量測（Duffield & Grossglauser "Trajectory Sampling" ToN 2001；IETF PSAMP drafts；Goldberg et al. 的 fault detection 技術報告），沒有比本篇更接近 C1–C4 的。

---

## 3. n=468 SparseIDS

**書目**：Maximilian Bachl, Fares Meghdouri, Joachim Fabini, Tanja Zseby（TU Wien），"SparseIDS: Learning Packet Sampling with Reinforcement Learning"，arXiv:2002.03872v3（2020-05-04），IEEE CNS 2020。

**他們做了什麼**
- 目標：RNN（3 層 LSTM，每層 128）的逐封包 flow 分類器，用強化學習（actor-critic）決定「下一個要看的封包是第幾個」，連續動作可跳過任意多個封包，以 α 參數權衡 sparsity 與準確率（Sec III）。
- 特徵只用標頭資訊：port、protocol、封包長度、IAT、方向、TCP flags、被跳過的封包數（Sec III-A）——不看 payload，不是 Suricata／Snort。
- 資料：CIC-IDS-2017，flow 截到最多 20 個封包（Sec V）；硬體只提到 NVIDIA Titan Xp（致謝）；離線評估、非 inline、非 ARM。
- Steering（Sec VII）：在部署時以閉迴路調整 α，使 sparsity 達到運算預算（Sec I：「given budget of computation power is not exceeded」）。Fig. 6 的範例從約 72.5% sparsity 要降到 50%，α 降到 0 後仍有約 71%。
- 基準方法（Sec IV）：random、every i-th、first m、relative first m。

**對 C1–C4**
- C1：none。Sec III-B 明說「one flow being only attack or non-attack but not mixed」——每個 flow 全惡意或全正常，「先正常後攻擊」被資料假設排除，也沒有放行／撤銷概念。
- C2：related。證據：Sec IV-B／C「first m」只取每個 flow 前 m 個封包；Sec VI-C 表 III 顯示 first m 是除 RL 外最好的基準（76.3% sparsity 下 accuracy 98.3%、recall 97.9%，RL 為 99.4%／99.0%）。支持「攻擊集中在 flow 開頭」，但：是 ML 標頭特徵分類器，不是有狀態 IDS；不處理中途接手、缺口；flow 已截到 20 個封包；沒有填充規避；非 inline、非 ARM。
- C3：related（弱）。證據：Sec VII steering 依運算預算調整 ML 的工作量（sparsity）。缺：沒有同機的 rule IDS，沒有量測互相干擾（記憶體頻寬、快取），預算是抽象的 sparsity 而非實測 CPU。
- C4：none。

**可比數字**
- sparsity 76.3%、accuracy 99.4%（RL，α=0.1，Table I）；first m 在同 sparsity 下 98.3%（Table III）；random 96.9%、every i-th 97.8%。
- Sec I：未共用權重時運算量為 2×，須取樣少於 50% 封包才有效率優勢；共用網路後無額外運算。
- 我們的 HPA 約 8% 封包送進 Suricata（約 92% 跳過）且後段攻擊 100% 抓到，與他們的 76% 跳過相比跳過比例更高，但偵測器與資料集完全不同，不能直接比。

**引用方式**：作為比較對象——「只看 flow 開頭」在 ML 分類器上已知可行，但它假設 flow 純淨；我們處理有狀態 IDS 與中途攻擊。

**雪球**
1. Ha et al., "Suspicious traffic sampling for intrusion detection in software-defined networks," Computer Networks 109, 2016（ref 8）——依可疑程度調整取樣，可能接近「可疑多看、正常少看」的 C1 精神，需查全文。
2. Bakhoum, "Intrusion detection model based on selective packet sampling," EURASIP J. Information Security 2011（ref 6）——為 IDS 選擇性取樣（Markov chain），接近 C2，需查全文。
3. Hartl, Bachl, Fabini, Zseby, "Explainability and Adversarial Robustness for RNNs," BigDataService 2020（ref 2）——本篇說它證實前幾個封包就足夠判斷；若有對取樣位置的對抗分析，可與我們的填充規避對照。
4. Kodialam & Lakshman 2003（ref 7）——已在本組。
5. Estan et al., "Building a better NetFlow," SIGCOMM 2004（ref 3）——依資源調整取樣率；偏計量，較不相關。

---

## 4. n=107 Giacometti et al., ISNCC 2025

**書目**：Luca Giacometti, Dario Crippa, Sebastiano Miano, Giacomo Verticale（Politecnico di Milano），"An Investigation on Packet Sampling between Kernel and User Space for NIDS"，2025 ISNCC，DOI 10.1109/ISNCC66965.2025.11250446，6 頁。

**他們做了什麼**
- 系統：以 Kitsune（KitNET，自編碼器集成，Python）為偵測器；特徵擷取改寫成 eBPF／XDP 在 kernel 內做，經 ring buffer 送到 user space（Sec III-C、Fig. 6）。
- 取樣：因 KitNET 太慢，只把一部分封包的特徵交給 KitNET（機率取樣，比例對應兩者吞吐比）；其餘封包交給「Wasp」：KitNET 判為惡意的 flow 被記住，之後同 flow 的封包一律標為惡意並需阻擋——「if a packet in a flow is malicious, all the packets in that flow are malicious」（Sec III-D）。
- 量測：(a) 偵測品質是離線在 Kitsune 的 Mirai 與 ARP MitM 資料集上，跑 300 次／每個取樣率；(b) 吞吐用兩台 Protectli VP6650（Intel i5-1235U、x86、64 GB、Ubuntu 22.04、10 GbE）以 iperf3 TCP、128 B／1500 B 框、各 10 次 × 10 分鐘、單核（Sec V）。
- 平台：x86，非 ARM；IDS 是 ML 異常偵測，不是 Suricata／Snort；「middlebox」但吞吐測試沒有放進實際阻擋。

**對 C1–C4**
- C1：related。證據：Sec III-D 對未取樣封包用「flow verdict cache」處理；隨機取樣讓未被標惡意的 flow 之後仍有機會被取樣到，被判惡意後整個 flow 被阻擋——結構上類似「不檢查 → 隨機再看 → 有問題就處置」。Table III／IV 給出 recall 對取樣率的曲線（Mirai：1/R=10^3 時 recall 79.054%，對比 Naive Sampling 0.088%）。缺：沒有明確的「信任／放行」狀態、沒有「放行後才攻擊」的場景（兩個資料集的攻擊是長時間的洪水／MitM）、偵測器是 ML 統計特徵而非有狀態規則 IDS、x86、離線評估、沒有稽核窗／撤銷的設計。
- C2：related（弱）。證據：Sec III-D 只把部分封包送去重量級偵測器。缺：取樣單位是隨機單一封包，不是每個訊息開頭；偵測器是 KitNET 不是有狀態 IDS；非 ARM；無填充規避。
- C3：none。它是同機的 eBPF 特徵擷取＋ML 推論管線，但只量各級吞吐（單核），沒有量互相干擾，也沒有依負載調整 ML 工作量（取樣比例是設計時依吞吐比設定）。
- C4：related（弱）。證據：XDP 在 kernel 內做特徵擷取，kernel→user space 管線上的吞吐有逐級量測。缺：被省下的是 user space 的 ML 推論，不是讓「已信任 flow」跳過 IDS；所有封包仍經 XDP 擷取特徵並進 ring buffer；沒有每封包成本；x86 10 GbE，非 ARM；整套取樣後的吞吐是「推算」而非實測（Sec VI：「If we apply the outcome ... can be relaxed from 5 Gbit/s ... to 5 Mb/s」）。

**可比數字**
- 特徵擷取（eBPF）>5 Gbit/s，KitNET 約 16 Mbit/s（Sec V-D，Fig. 7 為對數長條圖，其餘各點只有圖）。
- 取樣率門檻：約每 1000 個封包取 1 個，recall 才開始明顯下降（Sec IV-B）。
- Mirai：baseline recall 88.149%；Wasp 在 1/R=10^2 為 87.652%、10^3 為 79.054%、10^4 為 17.979%。ARP MitM：Wasp recall 在 1/R=10^4 仍 99.877%，precision 約 47–55%。
- 每封包 CPU 成本：論文未說明。

**引用方式**：作為比較對象——同樣是「只送部分給重量級偵測器＋flow 層級處置」，但他們沒有信任／稽核／撤銷的設計與放行後攻擊的量化；並且是 ML 偵測器、x86、離線。可用它的 recall–取樣率曲線對照我們「固定抽樣只抓到約 10%」的長連線場景。

**雪球**
1. Zhang, Chen, He, Chen, Li, "Real-time intrusion detection and prevention with neural network in kernel using eBPF," IEEE/IFIP DSN 2024（ref 3）——kernel 內的 IPS，與 C4（kernel 機制做 IDS／IPS）最接近，需讀。
2. Parola, Procopio, Querio, Risso, "Comparing user space and in-kernel packet processing for edge data centers," ACM SIGCOMM CCR 53(1), 2023（ref 6）——比較 XDP 與 user space 封包處理成本，可能含邊緣／IoT 情境與每封包成本，與 C4 的量測方法相關。
3. Hara & Sasabe, "Practicality of in-kernel/user-space packet processing empowered by lightweight neural network and decision tree," Computer Networks 240, 2024（ref 7）——kernel 與 user space 的 ML 推論比較，與 C3／C4 邊緣相關。
4. Osaki et al., "Dynamic fixed-point values in eBPF: a case for fully in-kernel anomaly detection," AINTEC 2024（ref 5）；Sakuraba et al., APNOMS 2023（ref 4）——eBPF 內異常偵測，較偏 ML，與 C4 距離較遠。

---

## 5. Kodialam & Lakshman, INFOCOM 2003（無 n）

**書目**：Murali Kodialam, T. V. Lakshman（Bell Labs），"Detecting Network Intrusions via Sampling: A Game Theoretic Approach"，IEEE INFOCOM 2003，pp. 1880–1889。

**他們做了什麼**
- 把「在網路各鏈路上取樣、檢查惡意封包」建模為營運者與入侵者的零和賽局：入侵者選路徑，營運者在總取樣預算 B（packets/s，整個網路）下分配各鏈路取樣率。解為 max-flow／min-cut：沿 min cut 取樣，賽局值 θ = B/Max-flow（Sec III）。
- 再討論如何改路由使賽局值更好（flow flushing、cut saturation 兩個啟發式，Sec IV），以及多攻擊點、多目標、最短路徑路由的變體（Sec V）。
- 評估是在兩個小型範例網路上的數值實驗（Table V、Fig. 9–10）。沒有真實 IDS、沒有硬體、沒有封包處理量測；惡意物件是「單一惡意封包」。

**對 C1–C4**：全部 none。
- C1：none。入侵者選擇路徑而非「在被信任後才攻擊」；沒有放行／稽核／撤銷。
- C2：none。取樣是鏈路層級選哪條鏈路取樣，不是 flow 內部的部分檢查。
- C3：none。C4：none。

**可比數字**：無。Sec II-C 的「sampling bound of B packets per second」是把偵測節點的處理能力當預算，概念上與 CPU 預算相同，但沒有實測值。

**引用方式**：作為背景——早期「取樣預算＋對抗性隨機化」的理論，可與 Goldberg & Rexford 一起支持「稽核要對抗預測」。

**雪球**：引用清單為賽局論、網路流量最佳化與 AQM（SRED、CHOKE、Washburn & Wood network interdiction 等），沒有更接近 C1–C4 的。

---

## 6. n=395 Valgenti, Sun, Kim, AINA 2014

**書目**：Victor C. Valgenti（Petabi）, Hai Sun（Washington State University）, Min Sik Kim（Petabi），"Protecting Run-time Filters for Network Intrusion Detection Systems"，IEEE AINA 2014，pp. 116–122，DOI 10.1109/AINA.2014.19。

**他們做了什麼**
- 對象：「run-time filter」＝ NIDS 前面的快速預濾器，先判斷封包不可能符合任何規則就不送完整檢查（Snort 的 fast-pattern 也算一種）。
- 攻擊（Sec III）：攻擊者送大量「部分符合規則」的封包使 filter 全部放行，NIDS 過載丟封包；他們用 Snort 實測：以 100 個部分符合的封包夾著 5 個攻擊封包（Fast Ethernet 滿速），只被辨識 1 個；改成 3 個攻擊封包則每次都 0 個被辨識。
- 防禦（Sec IV）：(a) 以 token bucket 限制送往 NIDS 的速率，超過 γ/2 後用類似 Random Early Drop 的機率轉送（式 3），讓攻擊者無法預測哪些封包會被送；(b) 把 filter 當成獨立異常偵測器，被 rate limiter 丟掉的封包記錄「可能符合的規則」到一個約 1 KB 的 bitmap，形成「audit trail」，使繞過不會無聲無息。
- 效率模型（Sec II）：work = αλ + pβλ，Filter Efficiency FEF = β/(α+pβ)；FEF<1 代表 filter 比沒有 filter 還糟。
- 評估（Sec V）：Perl 寫的模擬器，Snort VRT 規則集（2012-12-18，3013 條），資料為 DARPA 98 第 1 週、WSU 一週、DEFCON 11 與 17 CTF。假設 NIDS 單封包最長比對 100 µs、時間片 0.001 s（δ=10）、γ=25/50/100。非實機、非 ARM、非 inline 量測。

**對 C1–C4**
- C1：related。證據：Sec IV-B「making it impossible for a packet to slip past the system without some audit trace」。他們的 audit 是對「未被完整檢查的封包」留下記錄（哪些規則可能被符合），並用 RED 式隨機轉送避免被預測。缺：audit 只是記錄／告警，不是把放行的 flow 再送去完整檢查；沒有信任狀態與撤銷；攻擊情境是過載規避而不是「放行後才攻擊」；沒有量化放行後攻擊的漏報；模擬器而非實機。
- C2：related。證據：Sec II 說「more than 92% of all detected malicious traffic occurs within the first five packets」（Table I：8,089 個有告警的 flow 中，7,931 個在前 5 個封包內；逐資料集為 92.4%–98.9%），並引用 Papadogiannakis（只重視 flow 內特定位置的封包）與 Limmer & Dressler（在對話方向轉換處提高優先）。這是「攻擊集中在 flow／對話開頭」的先例。缺：本篇自己的系統不是部分檢查；沒有有狀態 IDS 處理缺口／中途接手；沒有填充規避；非 ARM；非 inline。
- C3：none。
- C4：none。filter 是 NIDS 前的模組（硬體或軟體皆可），不涉 kernel 機制；只有成本模型，沒有實測。

**可比數字**
- Table I：112,255,383 個封包、92,924 筆告警、9,733,751 個 flow；惡意流量「less than .0828%」的封包。
- 假設 NIDS 最慢單封包 100 µs（Sec V，系統設定值，非量測）；我們 Pi 上實測 55–61 µs／封包、conntrack mark 放行約 14 µs，可用 FEF 的記帳方式（α＝每封包都要付的前置成本、β＝完整檢查成本、p＝送去完整檢查的比例）呈現 C4 的效益。
- γ=100、1 ms 內 1250 個封包：多放行 57 個；γ=100 在重現攻擊時多放行約 2 個（Sec V-C）。
- 單封包實際 Snort／Suricata 成本：論文未說明。

**引用方式**：作為比較對象——「放行（過濾掉）的流量要留下 audit trail」與「隨機化以免被預測」的先例，但它的 audit 不是再檢查；也提供 FEF 成本模型，和 Table I 的「前 5 封包」統計可用來支撐 HPA 的動機。

**雪球**
1. Papadogiannakis et al., EUROSEC 2010（ref 11）——同上，兩篇都引，最優先。
2. Limmer & Dressler, "Improving the performance of intrusion detection using dialog-based payload aggregation," INFOCOM 2011（ref 7；本篇標為 INFOCOM 2011，可能是 INFOCOM workshop，需確認）——以「對話（dialog）」為單位、在方向轉換處優先檢查，比本篇更接近 C2 的「每段對話的開頭」。
3. Sourdis et al., "Packet pre-filtering for network intrusion detection," ANCS 2006（ref 17）；Song et al., "Snort offloader: a reconfigurable NIDS hardware filter," FPL 2005（ref 14）；Attig & Lockwood, "SIFT: Snort intrusion filter for TCP," HOTI 2005（ref 1）——硬體預濾器，與 C4 的 fast path 概念相近但為 FPGA，優先度較低。
4. Mai et al., "Is sampled data sufficient for anomaly detection?" IMC 2006（ref 9）；Mai et al., "Impact of packet sampling on portscan detection," JSAC 2006（ref 10）；Brauckhoff et al., "Impact of packet sampling on anomaly detection metrics," IMC 2006（ref 2）——取樣傷害偵測的實證，可作為「固定比例抽樣會漏」的背景，不構成撞到。

---

## 本組總結

1. **沒有任何一篇構成 overlap**。六篇都沒有同時具備：有狀態 IDS（Suricata／Snort）、信任後放行、之後再稽核並撤銷、以及「放行後才攻擊」的漏報量化。
2. **C1 最可能被撞到的是 ISNCC 2025（n=107）與 Valgenti AINA 2014（n=395），程度都只到 related**。
   - ISNCC 2025：結構最像（隨機取樣＋flow verdict 傳播），但沒有信任／稽核／撤銷、偵測器是 ML、x86、離線資料集中沒有「先正常後攻擊」。
   - Valgenti 2014：用詞最像（audit trail、隨機化轉送），但 audit 只是記錄被丟棄封包可能符合的規則，不是再檢查。
   - 審查者可能用這兩篇質疑 C1，論文需明確區分：我們是「已信任 flow 的再檢查與撤銷」，並且量了放行後攻擊的漏報（固定窗約 10%）。
   - Goldberg & Rexford（n=449）與 Kodialam 2003 提供「固定週期取樣可被預測規避、需隨機化」的理論依據，可用來支持我們的稽核設計，不構成威脅。
   - Meng 2018（n=297）的 "trust" 是節點信譽，且 whitelist 只由管理員更新，不要與我們的 flow trust 混用名詞。
3. **C2 的風險在「攻擊集中在 flow／對話開頭」這個觀察已有先例**：Valgenti Table I（前 5 封包 92% 以上）、SparseIDS 的 first-m 結果（76.3% sparsity 下 accuracy 98.3%）。但兩者都不是有狀態 IDS、不是 inline、不是 ARM，也沒有填充規避，與我們「每個 HTTP 訊息開頭送 Suricata、DPA 被填充繞過」不重疊。本組最大的漏網風險在雪球裡的 **Papadogiannakis EUROSEC 2010**（Meng、Valgenti 都引）與 **Limmer & Dressler INFOCOM 2011**（對話為單位）：它們可能已經做過以對話或 flow 位置決定檢查範圍，需優先讀全文。
4. **C3 本組沒有威脅**：六篇都沒有同機 rule IDS＋ML 並量測互相干擾。僅 SparseIDS 的 steering 觸及「依預算調整 ML 工作量」這一個要素（related（弱））。
5. **C4 本組沒有威脅**：ISNCC 2025 用 XDP 在 kernel 內擷取特徵，但目的是加速特徵計算而不是讓已信任 flow 跳過 user space IDS；x86、無每封包成本。最需要追的是它引用的 Zhang et al. DSN 2024（kernel 內 eBPF IPS）與 Parola et al. SIGCOMM CCR 2023（XDP 與 user space 的成本比較）。

**補充（不是這六篇引用的，來自我的背景記憶，未經查證）**：flow 判定可信後「shunt／cutoff」以避開 IDS 成本的做法在 Bro／Zeek 一系列工作中出現過，例如 Gonzalez, Paxson, Weaver, "Shunting: A Hardware/Software Architecture for Flexible, High-Performance Network Intrusion Prevention," CCS 2007；Maier et al., "Enriching Network Security Analysis with Time Travel," SIGCOMM 2008（stream cutoff）。這兩者與 C1／C4 的關係很可能比本組任何一篇都近，建議由其他組或另行搜尋確認，特別是 shunting 是否有放行後再驗證的機制。
