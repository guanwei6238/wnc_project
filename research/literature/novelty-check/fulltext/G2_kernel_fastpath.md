# G2 kernel fast path：全文精讀查核（n=116、284、289）

查核日期：2026-11-03。判斷基準是 `SCREEN.md` 的 C1–C4 定義。三篇都已讀完整全文（含圖表頁）。頁碼是 PDF 頁序；iKern 用期刊頁碼「x of 23」。「論文未說明」表示全文找不到，不推測補完。

## 總表

| n | 論文 | C1 稽核撤銷 | C2 inline 部分檢查 | C3 同機 IDS+ML 資源 | C4 kernel fast path |
|---|---|---|---|---|---|
| 116 | Hybrid kernel-user VNF (CNSM 2017) | related（弱） | none | none | related（本組最強） |
| 284 | iKern (Technologies 2024) | none | none | none | related（弱） |
| 289 | In-network disagg. + online learning (GLOBECOM 2025) | related（中，抽樣稽核的是模型不是 flow） | related（弱） | related（弱） | none |

---

## n=116　Architecture for Building Hybrid Kernel-User Space Virtual Network Functions

### 書目
Nguyen Van Tu, Kyungchan Ko, James Won-Ki Hong（POSTECH）。CNSM 2017（IFIP 2017，978-3-901882-98-2）。

### 他們做了什麼
- 通用架構：每個 VNF 切成 eBPF kernel 部分和 user space 部分。封包先經 eBPF 程式，查 eBPF matching table（key-value）；有命中就在 kernel 處理，沒命中就送 user space。user space 處理完後把「下一個封包怎麼處理」寫成規則裝進 eBPF table，之後同 flow 的封包留在 kernel（Sec. III-A、III-B，p.2–3）。
- 送 user space 的三種方式：不動封包讓它走 kernel stack、redirect 到 tap、clone 後 redirect（sniffing 用）（Sec. III-A.2，p.3）。
- 工作切分原則（Sec. III-D，p.3）：簡單的全在 kernel；能分 fast path／slow path 的用 hybrid；「需要所有封包 payload」的（例：Deep Content Inspection）退回全 user space。
- 兩個範例 VNF：
  1. Dynamic Load Balancer（eBPF 在 tc 層做 DNAT，user space 算加權輪詢）。
  2. DS-nDPI（Dynamic Sniffing nDPI）。eBPF 掛在 kernel traffic control 層，用 5-tuple（src/dst IP、src/dst port）查表；沒命中（還沒分類完的 flow）就 clone 封包送給 user space 的 MnDPI（改過的 nDPI）；分類成功後 MnDPI 經 AF_UNIX IPC 把該 flow 的 key 送給 Classified flows Listener，Listener 裝進 eBPF table；之後命中的封包「不需進一步動作」（Pass）。MnDPI 清除 idle flow 時，也通知 Listener 把該 entry 從 eBPF table 刪掉（Sec. V-A，p.5）。
- 平台：VirtualBox VM（Ubuntu、1 core、1 GB RAM；LB 實驗每台 VM 512 MB、1 core），host 是 Intel Core i5-3570、8 GB、Ubuntu 14.04（Sec. VI，p.5–6）。x86，非 ARM。
- IDS：沒有，是 nDPI 做流量分類（traffic classification），不是 Suricata／Snort，不是入侵偵測。
- 是否 inline：DS-nDPI 是 sniffing（clone 給 nDPI，原封包照常轉送），不是 inline 擋封包。
- 量測：虛擬 ethernet 鏈路（iproute 的 veth），用 tcpreplay 重播真實 Internet 流量（1200+ flows、28 種應用協定），量 tcpreplay 能達到的最大 throughput。BCC＋Python 實作。
- 之後會不會再檢查：只有 idle 清除（flow 閒置後 entry 被刪，重新出現就重新分類）；持續活躍的 flow 永遠不會被拉回來。論文未討論「分類之後 flow 內容變了」的情況。

### 對 C1–C4 的標記
- **C1：related（弱）。** 有「判定完成後讓 flow 跳過 user space」，缺了放行後的稽核、撤銷、「放行後才攻擊」的量化。唯一的回收機制是 idle 刪除：「remove the idle flows from the eBPF table」（Sec. V-A，p.5）。而且 nDPI 分類是「分類完就沒事做了」，不是「放行風險」，語意不同。
- **C2：none。** 沒有只送訊息開頭給有狀態 IDS 的設計。DS-nDPI 是「整條 flow 還沒分類完就整條都 clone 給 nDPI，分類完就停」，不是 per-message 開頭，也沒有討論 stateful 引擎接受不完整封包、中途接手、填充規避。
- **C3：none。** 沒有 ML 推論、沒有同機資源干擾量測。
- **C4：related（本組最強）。** 撞到的點：用 tc 層 eBPF 表，讓「已有結論的 flow」跳過 user space 的分析引擎，user space 判定後寫規則回 kernel（「installs an indication of processing next packets to the kernel space」，Sec. III-B，p.3；命中時「no further action is required」，Sec. V-A，p.5）。這是 kernel 繞過 user space 的同一種原理。缺了我們的關鍵要素：(a) 引擎是 DPI 分類器，不是 IDS／IPS；(b) 放行語意是「已分類」不是「信任」，沒有安全風險的討論；(c) 是被動 sniffing 不是 inline 轉送；(d) x86 VM 不是 ARM；(e) 沒有每封包成本，只有 tcpreplay 最大 throughput；(f) 只有 tc eBPF 一個機制，沒有和 conntrack mark／flowtable／XDP 比較。另外 Sec. III-D（p.3）自己把「需要所有封包 payload 的 VNF（Deep Content Inspection）」排除在 hybrid 之外，等於承認 IDS 類不適合直接套這個架構。

### 可拿來比的數字
- DS-nDPI 讓 tcpreplay 的最大 throughput 降 21%，標準 nDPI 降 43%；DS-nDPI 最大 throughput 是標準 nDPI 的 1.38 倍（Sec. VI-B，p.6；Fig. 5 長條約：無 nDPI 約 6000 Mbps、DS-nDPI 約 4800、標準 nDPI 約 3400，是從圖讀的近似值）。平台：VirtualBox VM 1 core，veth 鏈路。
- LB：hybrid LB 平均每 request 時間是全 kernel LB 的 1.2 倍、IPVS 的 1/1.5、HAProxy 的 1/2.8（Sec. VI-A，p.5；Fig. 4）。與我們無關，僅旁證「hybrid 比純 user space 快」。
- 沒有 pps、每封包 µs、CPU 使用率。無法和我們的 55–61 µs／14 µs 直接比。

### 我們論文怎麼引用
作為比較對象（C4 的前人）：「用 kernel 層 eBPF 表讓已判定的 flow 跳過 user space 分析引擎」這個原理早在 2017 年就有；我們的差異在於對象是 inline IPS（Suricata NFQUEUE）、放行語意是信任（會被稽核）、ARM 上的每封包成本、以及四種 kernel 機制的比較。不能宣稱「首先提出 kernel 表繞過 user space 分析」。

### 雪球
本篇引用的文獻中，沒有比它本身更接近 C1–C4 的。唯一值得一提的是原理層的前人（只看標題）：
- Qazi et al., "SIMPLE-fying Middlebox Policy Enforcement Using SDN", ACM SIGCOMM 2013。本篇說它是「只把未分類的 flow 送去 DPI」的 SDN 做法，可能是「已分類 flow 不再送 DPI」的更早出處；但在 SDN 層而非 kernel，與 C4 不同層。
- 其餘（InKeV 2016、BPFabric ANCS 2017、OpenBox SIGCOMM 2016、nDPI IWCMC 2014）是 eBPF 資料平面或 DPI 引擎本身，與 C1–C4 距離比本篇更遠。

---

## n=284　iKern: Advanced Intrusion Detection and Prevention at the Kernel Level Using eBPF

### 書目
Hassan Jalil Hadi, Mubashir Adnan, Yue Cao, Faisal Bashir Hussain, Naveed Ahmad, Mohammed Ali Alshara, Yasir Javed。Technologies 2024, 12(8), 122（MDPI），2024-07-30。

### 他們做了什麼
- 目標：IDPS（文中提 Snort、Suricata、Bro）在大流量下 buffer 掉封包；DDoS／多向量 flood 會讓 user space 偵測引擎過載。他們在 kernel 先偵測並丟棄 flood 封包，再把乾淨流量交給 user space（Abstract、Sec. 1，p.1–3）。
- 結構（Fig. 1，p.5）：Data Acquisition Module（DM，用 PF_RING 的 ring buffer，多核心用 cluster 做 per-flow／round robin 平衡）→ iKern Detection Module（eBPF VNF，包含 IDA 偵測演算法和 IDR 丟棄規則，bytecode 從 user space 注入，結果存 eBPF maps）。
- IDA（Algorithm 1，p.10）：在偵測時窗內數封包；封包數超過門檻後，看封包時間差 Δt < β×dt 就發 high-priority 警報，否則「Invoke ML_model with packet features」分類。ML 模型的種類、特徵、在哪裡跑，論文未說明。
- IDR（Algorithm 2，p.11）：有 WhiteList／GrayList／BlackList 三張 eBPF 表。收到警報後，high-priority 加入 GrayList 並設計時器、low-priority 加 GrayList 並設「expiration timer for false positives」，已在 GrayList 又收到警報就升到 BlackList。資料封包處理順序：在 WhiteList 就「Forward packet」；在 GrayList 且目的是受害者且計時器有效就丟；在 BlackList 就丟；都不是就「Forward packet to user space」。WhiteList 由使用者手動加入：「Legitimate IP addresses can be added to the iKern whitelist filter by users」（Sec. 3.5，p.10），用於「bypass the inspection of packets from trusted sources」。
- 偵測對象只有 volumetric／multi-vector flood（TCP SYN、UDP、UDP fragment、DNS amplification、CIC-DDoS2019 的各種 flood、HOIC／LOIC／HULK／RUDY 等工具）。不是簽章式 IDS，沒有用 Snort／Suricata。
- 平台：Intel Xeon E5-2630 v4 @ 2.2 GHz 10 核、64 GB、10 Gbps NIC、Ubuntu 20.04（Table 2，p.11）。x86 伺服器，非 ARM。
- 是否 inline：論文只描述「丟棄」和「轉給 user space」，沒有描述閘道器式的轉送路徑；是否 inline 論文未說明。eBPF 程式掛在 XDP 還是 tc，論文未明確說明（只在背景提到 XDP 是 eBPF hook 之一，p.1）。DM 用 PF_RING 擷取，與 eBPF 的先後關係全文描述不一致（Fig. 1 是 DM→eBPF，Fig. 2 又畫 ring buffer 旁有 eBPF），我們不能確定實際資料路徑。
- 量測：tcpreplay 重播 CIC-DDoS2019（以 max throughput 旗標）和攻擊工具產生約 1 Gbps 流量，連續 15–20 分鐘；比較 libpcap／AF_PACKET／PF_RING 的收包率，並量偵測準確率與每核心 CPU 使用率。
- 之後會不會再檢查：WhiteList 是使用者手動設定的靜態 IP 表，沒有稽核、沒有撤銷。GrayList／BlackList 有計時器，但那是「封鎖」的過期，不是「放行」的過期。

### 對 C1–C4 的標記
- **C1：none。** 有 WhiteList bypass，但是人工靜態名單，沒有 verdict、沒有抽樣稽核、沒有放行後攻擊的量化。GrayList 計時器是封鎖過期，方向相反（Algorithm 2，p.11）。
- **C2：none。** 全部在談 flood 的偵測與丟棄，沒有部分檢查或 stateful IDS 的討論。
- **C3：none。** Algorithm 1 提到在 kernel 引擎中「Invoke ML_model」（p.10），但沒有 ML 與規則式引擎的資源干擾量測，也沒有 ML 工作量調整；ML 細節論文未說明。
- **C4：related（弱）。** 有 kernel 層 eBPF 表在封包到 user space 前先處理：WhiteList 直接 Forward、BlackList 丟棄、其餘才「Forward packet to user space」（Algorithm 2，p.11）。缺了：(a) 它的 fast path 主要是「已知壞的先丟」（黑名單），不是「已信任的免檢」，白名單是人工 IP；(b) 沒有任何 Suricata／Snort 或 NFQUEUE；(c) x86 Xeon，非 ARM；(d) 沒有每封包成本（只給 Mbps、drop %、CPU %，沒給 pps 或封包大小分布，無法換算）；(e) 沒有 conntrack mark／flowtable／tc 的比較。

### 可拿來比的數字
- 3 個 core 各跑一個 iKern instance，replay CIC-DDoS2019 近 1 Gbps，每核心 CPU 約 92–97%（20 分鐘，Sec. 4.5，p.19–20）；Table 6 總結「throughput 1000 Mbps、CPU 97%、準確率 98.84%」（p.21）。平台：Xeon E5-2630 v4。因沒有 pps 或封包大小分布，我們不能換算成每封包成本；也因 Gbps 級 flood 以大量小封包為主，絕對不能與我們 Pi 的 60 kpps 直接比。
- 單核心單 instance 收 1 Gbps：64 B 封包掉約 30%、平均大小約 40%、1500 B 約 45%（Sec. 4.2，p.15）。
- libpcap 在 >120 Mbps 開始掉小封包（Sec. 4.1.1，p.12–13）；AF_PACKET 在 336 Mbps 時文字寫「reception of 64-byte packets dropped to 4%」，不清楚 4% 是接收率還是丟包率（Sec. 4.1.2，p.13），不建議引用。
- 各類 flood 被 eBPF 丟棄的比例：TCP SYN 98.9%、UDP 97.4%、DNS amplification 99.4%（Sec. 4.5，p.19）。與我們的問題無關。

### 品質提醒
- Table 6 把 iKern 標成引用 [33]（那是 Varghese 的 SDN IDS），引用編號有誤；全文各 eBPF 掛載點、資料路徑描述不清；ML 部分沒有細節。引用時只用於「kernel 層預先過濾」這個一般性主張，避免引用其數字。

### 我們論文怎麼引用
作為背景（kernel 層預過濾 flood、減輕 user space IDS 負擔的相關工作）；方向與我們相反（黑名單丟棄 vs 信任白名單免檢），可在 related work 一句帶過。

### 雪球（只看參考文獻標題，未讀）
- Wang & Chang, "Design and implementation of an intrusion detection system by using Extended BPF in the Linux kernel", J. Netw. Comput. Appl. 198, 2022（本篇 ref [1]）。把 IDS 做進 kernel eBPF，可能比 iKern 更清楚地描述 kernel IDS 的取捨，對 C4 值得確認。
- Sheeraz et al., "Advancing Snort IPS to Achieve Line Rate Traffic Processing for Effective Network Security Monitoring", IEEE Access 12, 2024。Snort IPS 的高速處理，可能含 inline 與 bypass／前置過濾，與 C4 的 IPS 效能量測有關。
- Hu, Yu, Asghar, "Analysing performance issues of open-source intrusion detection systems in high-speed networks", J. Inf. Secur. Appl. 51, 2020。Snort／Suricata／Zeek 的效能瓶頸分析，可當 C4 每封包成本的對照基線。
- Miano et al., "Securing Linux with a faster and scalable iptables", ACM CCR 2019；Bertrone et al., "Accelerating Linux security with eBPF iptables", SIGCOMM Posters 2018。netfilter 的 eBPF 加速，與 C4 的 fast path 選項比較（conntrack／nftables vs eBPF）相關，但不是 IDS。
- Miano et al., "A framework for eBPF-based network functions in an era of microservices", IEEE TNSM 2021；Miano et al., "High-Performance Server-based DDoS Mitigation through Programmable Data Planes", NFV-SDN 2019。eBPF 預過濾 user space，可能含 fast path 與 slow path 的切分。
- Hadi et al., "Real-time fusion multi-tier DNN-based collaborative IDPS with complementary features for secure UAV-enabled 6G networks", Expert Syst. Appl. 2024，及 IEEE IoTJ 2024 同組 UAV 論文。DNN IDS 與 edge 部署，C3 可能有關，但從標題看多半是偵測模型，優先度低。
- 以上都是「從標題猜」，不是讀過，可信度有限。沒有一篇的標題明確指向 C1 或 C2。

---

## n=289　In-Network Attack Detection Using Disaggregated Inference & Online Learning

### 書目
Gergely Sárközi, Péter Vörös（Eötvös Loránd University）。IEEE GLOBECOM 2025，DOI 10.1109/GLOBECOM59602.2025.11432439。

### 他們做了什麼
- 在可程式化交換器（P4）的資料平面做 random forest 推論來判斷 flow 是攻擊或正常；control plane 的「外部 IDS」給準確標籤，control plane 的 controller 用這些標籤用 online learning 重新訓練 RF 並換模型（Sec. III，p.2–3）。不需要預訓練模型（零接觸）。
- as-soon-as-possible 分類：每個 flow 長度（封包數）各訓練一個 RF（沿用 pForest），信心超過門檻就在 flow 還在進行時下判斷，摘要說「只需處理每個 flow 的幾個封包」（Abstract，p.1；Sec. III-C，p.3）。
- 抽樣回報：交換器依 flow identifier 和啟動時的隨機數，「Flows are selected at random」，把一小部分 flow 的特徵（和 in-network 判斷結果，若有）送到 control plane（Sec. III-C，p.2）。controller 把這些 flow 送給外部 IDS，得到「真標籤」，和 in-network 的預測比較，算出 in-network 分類器的 accuracy／F1；新模型比現有模型好超過某門檻（例：1%）才替換（Sec. III-C，p.3）。
- 模型分散（disaggregation）：把一個 RF 的不同決策樹放到串聯的不同交換器上，降低每台交換器的資源需求，讓交換器仍有餘力做路由等其他工作（Sec. III-E，p.3）。
- 特徵是封包長度、TCP flag 計數、port 等流量統計特徵；明確不做應用層特徵（Sec. III-B，p.2）。
- 平台：兩個 testbed——(1) 3 台 CPU-based eBPF 軟體交換器（P4-to-eBPF，經 nikss-ctl 控制）串成鏈；(2) 1 台 Intel Tofino 硬體交換器。eBPF 交換器所在的 CPU、OS 論文未說明；非 ARM（論文未提 ARM）。
- IDS：論文裡沒有真的 IDS。「外部 IDS」用 CIC-IDS-2017（改良版）的 CSV 標籤代替，「it returned the true flow labels specified in the dataset」（Sec. IV，p.3–4）。ML 是 scikit-learn 的 random forest。
- 量測：CIC-IDS-2017 的封包 trace 片段重播；指標是 accuracy 隨時間和整體 F1。沒有 CPU、沒有 pps、沒有每封包成本（只有模型部署時間和 Tofino 推論延遲）。

### 對 C1–C4 的標記
- **C1：related（中，是最接近的一點）。** 有「抽樣稽核 in-network 判斷」：隨機抽一小部分 flow 送外部 IDS 比對，發現 in-network 準確度下降就重訓換模型（Sec. III-C，p.2–3）；也有「放行後才攻擊」的現象：一開始空模型把全部 flow 判 benign，攻擊 flow 出現（約 150 秒）後 accuracy 掉下來，直到新模型部署（Sec. IV-A，p.4；Fig. 2）。缺了我們的關鍵要素：(a) 被審的是「分類模型」，不是「已被信任而跳過檢查的個別 flow」；稽核結果只用來重訓，沒有撤銷某條 flow 的信任（論文未說明 flow 被判 benign 後是否快取結論、是否繞過後續封包處理）；(b) 外部 IDS 是用資料集標籤模擬，沒有稽核成本、沒有量化「放行後才攻擊」的漏報；(c) 抽樣的目的是產生訓練資料，不是重檢驗信任。
- **C2：related（弱）。** 「Flows are classified as-soon-as-possible … only a few packets」（Abstract，p.1）與「只看 flow 開頭」概念類似，但：特徵是封包統計而非應用層訊息開頭；每個封包仍要經過資料平面計算特徵（register 累積 max length／flag 計數，Sec. III-B，p.2），不是「只送開頭給 IDS，其餘放行」；沒有 stateful IDS、沒有 ARM、沒有填充規避。
- **C3：related（弱）。** 動機相近：推論不能吃掉交換器轉送所需的資源，所以用 disaggregation 切到多台交換器（Sec. III 開頭，p.2：「leave enough free resources in the switches」做路由等其他工作；Sec. III-E，p.3 以拆樹到多台交換器降低每台資源需求）。缺了：這是「靜態切分到多台設備」，不是同一台設備上共存；沒有規則式 IDS 與 ML 共跑；沒有量測互相干擾（記憶體頻寬、快取）；沒有依負載動態調整。
- **C4：none。** eBPF 交換器本身就是在 kernel 處理全部封包，沒有「讓已信任 flow 跳過 user space IDS」的機制；唯一送 user space 的是約 5% 抽樣 flow 的特徵。沒有 ARM，沒有每封包成本。

### 可拿來比的數字
- Table I：抽樣比例 vs F1（eBPF testbed、DDoS）：1% 0.94、3% 0.96、5% 0.96、10% 0.95、25% 0.94、50% 0.91、100% 0.95（Sec. IV-D，p.5）。結論：只回報 5% flow 的特徵不降低偵測準確度。可旁證「抽樣稽核比例低也夠」，但它的抽樣是為了訓練模型，不是稽核放行的 flow，不能直接當我們稽核比例的依據。
- 整體 F1：DDoS（eBPF）0.96、portscan（Tofino）0.98、兩者合併（eBPF）0.95。
- Tofino 推論加轉送延遲約 0.7 µs（Sec. IV-G，p.6）。作者說 Linux host 上的 IDS 延遲是「幾十到幾百 µs」，但這是引用一般 TCP/IP 延遲文獻（[17]–[19]，不是 IDS 實測），不能當 Suricata 的數字引用。
- 模型部署時間：Tofino 數百 ms，eBPF 交換器數秒（>20 倍差，Sec. IV-E，p.5）。與我們無關。
- 沒有 CPU 使用率、pps、每封包成本。

### 我們論文怎麼引用
C1 的相關工作／反駁對象：說明「用抽樣回報＋外部 IDS 校正 in-network 判斷」在 P4 交換器的 ML 偵測有人做過，但對象是模型品質（online learning），不是撤銷已繞過 IDS 的 flow 的信任；我們的差異是針對 inline IPS 的 per-flow 信任稽核與其漏報成本。C3 可一句帶過作為「靜態切分」的對照。

### 雪球（只看參考文獻標題，未讀）
- Zang, Zheng, Dittmann, Zilberman, "Towards Continuous Threat Defense: In-Network Traffic Analysis for IoT Gateways", IEEE Internet of Things Journal 2023（本篇 ref [7]）。對象是 IoT gateway，in-network 推論加 online learning，每個封包特徵經 P4Runtime digest 回 control plane。場景比本篇更接近我們的 gateway，需確認是否有放行後再驗證／資源分配的內容。優先度高。
- Brandino, Grampin, Dietz, Wehner, Seufert, Hoßfeld, Casas, "HALIDS: A Hardware-Assisted Machine Learning IDS for In-Network Monitoring", TMA 2024（本篇 ref [9]）。in-network 分類器在信心不足時把特徵轉給外部 IDS，這是「本地先判、拿不準的送出去」的設計，與我們整體架構（本地優先、雲端卸載）和 C1 的升級邏輯相近。優先度高。
- Busse-Grawitz, Meier, Dietmüller, Bühler, Vanbever, "pForest: In-network inference with random forests", arXiv 1909.05680, 2019（ref [6]）。「看前 N 個封包就判 flow」的出處，與 C2 的「只檢查開頭」概念可能有關，但對象是 ML 流量特徵，優先度中。
- 其餘（Zheng et al., "DINC: Toward distributed in-network computing", CoNEXT 2023；Sultana et al., "Flightplan", NSDI 2021；Wang & Wu, "Supporting large random forests in the pipelines of a hardware switch…", IEEE Access 2023）是 P4 程式切分與 RF 編碼，與 C1–C4 距離比本篇更遠。

---

## 本組總結

1. **C4 最可能被這組撞到，但只是原理層，不是全面。** n=116（2017）的 DS-nDPI 是同一種做法：user space 引擎判定 flow 後，把 5-tuple 寫進 tc 層的 eBPF 表，之後該 flow 的封包不再送 user space，idle 時移除。撞到的程度是「機制概念相同」；沒撞到的是：它是 DPI 分類不是 IDS／IPS，是 sniffing 不是 inline，x86 VM 不是 ARM，只有 throughput 沒有每封包成本，只比 tc eBPF 一種機制，且「已分類」不是「已信任」。結論：C4 不能宣稱「首次用 kernel 表讓已判定 flow 繞過 user space 引擎」，但「在 ARM 上、對 Suricata NFQUEUE、量測 conntrack mark／flowtable／tc／XDP 各自的每封包成本」這部分在本組沒有被撞到。
2. **C1 只被輕微觸及。** n=289 有「隨機抽 flow 送外部 IDS 校正 in-network 判斷」，是本組最接近 C1 的一點；但稽核對象是 ML 模型，不是被信任的個別 flow，也沒有撤銷與放行後漏報的量化，外部 IDS 還是資料集標籤模擬的。n=116 只有 idle 到期回收，n=284 只有人工靜態白名單，皆不構成放行後稽核。建議雪球查 Zang 2023 和 HALIDS 2024。
3. **C2、C3 本組基本沒有被撞到。** 三篇都沒有把部分封包送給有狀態 IDS，也沒有 ARM 上規則 IDS 與 ML 同機干擾的量測；n=289 的 ASAP 分類和 disaggregation 僅在概念動機上沾邊。
4. 三篇都沒有 ARM 平台，也沒有 Suricata／Snort inline 的每封包成本，所以我們 C4 的實測數字（55–61 µs／14 µs／60 kpps／300 kpps）在這組文獻中沒有可直接對照者。
