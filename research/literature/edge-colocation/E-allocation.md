# E 組：資源分配與負載調適的方法

日期 2026-11-02。唯讀研究；下載檔在 `research/literature/edge-colocation/pdfs/<slug>/`（barlet-ros-atc07、dreger-ccs04、nfvnice、caladan、mt-edge-2506、rt-gang、iccd24-interference、plaiground、pytorch-rpi-tutorial、tomcore-pi4-net）。

頁碼規則：Barlet-Ros 用 USENIX 頁碼（59–72）；Dreger 用 ICIR 作者版 PDF 頁碼（共 11 頁，ACM 版是 pp.2–11，兩者不同）；NFVnice 用作者站 PDF 頁碼（14 頁，非 ACM 頁碼）；Caladan 用 USENIX 頁碼（281–297）；Georgiou、RT-Gang、ICCD'24、PLAIground 用 PDF 頁碼。Linux 文件與部落格沒有頁碼，用章節名。「經 WebFetch 摘要」表示該頁由小模型摘要後回給我，我沒有逐字核對。

## 0. 結論

1. **E1 怎麼知道負載**：兩條路線。預測式（Barlet-Ros）：每 100 ms 一個 batch，抽 42 個流量特徵，用線性迴歸預測這批要用多少 CPU cycles；預測誤差平均 0.65–1.2%（讀圖標註），預測子系統本身佔總 cycles 10.97% [原文 p.63, p.66–67]。反應式（Dreger）：看 2 分鐘平均 CPU 使用率，>90% 換到較省的 filter、<40% 換到較費的；作者試過用丟包當訊號，結果會震盪 [原文 PDF p.9]。
2. **E1 丟什麼、損失多少**：Barlet-Ros 對所有 query 套同一個 packet 或 flow 抽樣率，flow 抽樣每個 interval 換一次 H3 hash 以防規避 [原文 p.68]；但最像 IDS 的 pattern-search 與 trace 兩個 query 沒有量準確度，因為沒有還原抽樣前輸出的標準做法 [原文 p.70]。Dreger 丟的是「哪些 decoder 開著」，沒有量偵測損失 [原文 PDF p.8–9]。三個方法裡只有 Selective Packet Discarding 量了 alert 保留率（63% 丟包留 96.3%，Snort）[既有筆記 trust-bypass/papers/selective-discarding.md D7]。
3. **E2 可搬的**：NFVnice 的控制面——每個 NF 的 CPU 權重 = 到達率 × 單封包處理時間 的比例，每 1 ms 估一次、每 10 ms 寫一次 cgroup（寫一次約 5 µs），加上「在鏈的最前面就丟」的 backpressure [原文 p.6–7, p.12]；以及 Dreger 的預先編好的有序等級。**不可搬的**：Caladan 需要專用 scheduler 核心、KSCHED 核心模組、自家 runtime、kernel-bypass 網路與 Intel 記憶體頻寬計數器 [原文 p.285–286, p.293]；NFVnice 的資料面是 DPDK [原文 p.4]。
4. **E2/E3 的警訊**：排程優先權擋不住記憶體頻寬干擾。Caladan 的 Linux 基準（BE 任務用 SCHED_IDLE）在記憶體頻寬干擾下 tail latency 最高變 235× [原文 p.289–290]；RT-Gang 在 Pi 3 上讓 DNN 與吃記憶體的任務各佔 2 核共跑，DNN 慢 10.33×、對方只慢 1.05× [原文 PDF p.3]。Caladan 指出「減少給某任務的核心數就會減少它的記憶體頻寬」[原文 p.284]；PyTorch 官方 Pi 4 教學的做法同向：4→2 threads，最佳延遲 60→72 ms，但消除 128 ms 的尖峰 [文件 URL]。
5. **E3 沒有 Pi 4 的共存數據**：Georgiou 2025 把 Pi 4 只當單獨基準（1.12 batches/s、5 W、71.5 °C），共存實驗全在 Xeon 伺服器上 [原文 PDF p.7–8]；RT-Gang 是 Pi 3（Cortex-A53）；ICCD'24 是 Jetson Xavier（GPU+DLA）；PLAIground 是 Jetson Orin Nano。model 依負載切換有現成的簡單控制器（Pixie：窗口平均＋兩個門檻＋冷卻期）[原文 PDF p.3–4]，但它的切換成本 <10 ms 是因為模型預載在 GPU 記憶體 [原文 PDF p.4]，CPU-only 的 Pi 上未知。
6. **E4 Pi 4 網卡中斷**：Tomcore（Pi 4B 8GB，Alpine，kernel 5.15.4，iperf3 TCP 10 條）實測 eth0 兩個 IRQ 預設全在 CPU0、GICv2 一條 IRQ 只能指向一個 CPU；把 TX-complete 放 CPU1、RX 放 CPU2 後全雙工從 540/545 升到 613/864 Mbit/s，再開 RPS/XPS 升到 935/764 Mbit/s [二手 URL，我讀了原文 HTML]。這是端點 TCP 大封包吞吐，不是轉送 pps。
7. **E4 其餘手段在 ARM SBC 上沒有找到量測**：cgroup v2 cpu.max／cpu.weight／cpuset、SCHED_DEADLINE、nice、CPU 頻率 governor 對「封包處理或推論延遲」的影響，我沒有找到在 Pi 或其他 ARM SBC 上量過的論文或可信文章（搜尋紀錄見 §2 E4）。cpu.max 的 throttling 問題只有 x86 雲端的文章（Indeed，worst-case 回應從 >2 s 降到 30 ms）[二手 URL]。
8. **E5 [推測]**：「依負載調整稽核率」可直接套 Dreger 的分級＋遲滯迴路或 Barlet-Ros 的抽樣率公式；「同時調 edge AI 推論量」可套 Pixie 式的模型降級／升級或 NFVnice 式的權重分配。但**沒有任何一篇把 IDS 稽核量與 ML 推論量放進同一個預算**，這是空缺。
9. **E5 [推測]**：CPU 0 吃所有網卡中斷，文獻的對應做法是把兩個 IRQ 釘到不同核心、把 rps_cpus／xps_cpus 設成排除或包含 CPU0 的遮罩、kernel 文件建議高中斷率時把中斷 CPU 排除在 RPS 之外 [文件 URL]；Pi 4 的限制：Tomcore 只對 rx-0 設 rps_cpus、tx 有 tx-0 到 tx-4，暗示只有一個 RX queue，所以 RSS 不可用、只能靠 RPS（他沒有明說只有一個 RX queue，未能確認）[推測]。沒有任何來源量過小封包轉送（pps）下這些設定的效果。
10. **空缺**：(a) 共享預算；(b) Pi 4 上的干擾倍率與 cgroup／cpuset 效果；(c) load shedding 論文的準確度指標是計數誤差，不是攻擊偵測率；(d) 抽樣被攻擊者預測時的損失沒有人量過（Barlet-Ros 只用換 hash 防範）。

## 1. 逐篇

### Barlet-Ros 2007（USENIX ATC 2007）
- **書目／取得程度**：Pere Barlet-Ros, Gianluca Iannaccone, Josep Sanjuàs-Cuxart, Diego Amores-López, Josep Solé-Pareta，"Load Shedding in Network Monitoring Applications"，USENIX ATC '07，pp.59–72。PDF：`https://www.usenix.org/legacy/event/usenix07/tech/full_papers/barlet-ros/barlet-ros.pdf`。**全文**（14 頁）。作者、標題、年份、頁碼與給定資訊相符。給定資訊提到的 IEEE/ACM ToN 延伸版：我搜了作者名＋標題，只找到 2008 年博士論文（tesisenred.net/handle/10803/31780）和 ATC'07 本篇；找不到 ToN 版，未能確認存在。
- **機制**：CoMo 監控系統上同時跑多個 plug-in query，把每 100 ms 的流量切成一個 batch [原文 p.61–62]。對每個 batch 計算 42 個特徵（封包數、位元組數，以及 10 種 header 欄位組合各 4 個計數：unique、new、repeated 等），用 multi-resolution bitmap 計數（誤差約 1%）[原文 p.63]。用 FCBF（以相關係數篩選）每個 query 挑少數特徵，再用最近 60 個 batch（6 s）做多元線性迴歸，預測該 query 處理這批所需的 CPU cycles [原文 p.64–65]。實際用量用 TSC 在 query 前後各讀一次、以 cpuid 序列化；被 context switch 污染的觀測用預測值取代 [原文 p.65]。若預測總和 > 可用 cycles，就算抽樣率 srate = (avail − ls_cycles)/(pred × (1+error))，對所有 query 套同一個率；error 是預測誤差的 EWMA（α=0.9）[原文 p.68–69]。可用 cycles 還加了 TCP slow-start 式的「可延遲量」rtthresh，利用 capture 緩衝區容忍短暫超載 [原文 p.67]。
- **偵測面（損失面）**：準確度只量計數類輸出的相對誤差（packets、bytes、flows、high-watermark 等）[原文 p.70]。Table 6：預測式 0.54–2.88%，原版 CoMo（緩衝區滿了就丟）38–55%，反應式 8.9–12.5%；但反應式那次的流量只有約一半（403 vs 720–750 Mbit/s 平均）[原文 Table 5 p.70, Table 6 p.71]。pattern-search 與 trace 兩個 query **沒有量**，理由是沒有標準做法還原抽樣前的輸出 [原文 p.70]。規避：flow 抽樣的 H3 hash 每個 measurement interval 隨機重生，避免偏誤與刻意規避 [原文 p.68]；沒有實驗攻擊它。
- **成本面**：兩台 Pentium 4 3 GHz、Endace DAG 4.3GE 擷取卡、8 小時、7 個 query [原文 p.69]。預測子系統佔 CoMo 總 cycles 10.97%（特徵抽取 9.07%、特徵選擇 1.70%、MLR 0.20%）[原文 p.66]。8 小時內預測式 DAG 卡零丟包；原版有超過 20% 的 batch 整批沒被處理，反應式約 5% [原文 p.70]。系統需要的 cycles 超過可用的兩倍以上 [原文 p.71]。
- **對我們的意涵（[推測]）**：想法可搬：「用便宜的流量特徵預測下一個窗口的 CPU 需求，再算抽樣率」。Pi 上要先量的是特徵抽取成本——論文 10.97% 是在 3 GHz Pentium 4、100 ms 窗口、有 bitmap 的條件下；Pi 的 Suricata 已知每封包約 40 µs，若特徵只用 conntrack 新連線數與 pps 這類核心已有的計數器，成本可能遠低於論文，但這是推論未量。ARM 上沒有 TSC＋cpuid 的做法，需改用 schedstat 或 generic timer。抽樣率必須對應到我們能調的旋鈕（信任比例、SYN/FIN 以外的抽檢率）。
- **限制**：作者承認：所有 query 同一個抽樣率，不分效用；有些 query 無法從抽樣輸出還原 [原文 p.69]。我觀察到：正文說最大預測誤差約 10%，但圖例寫 13.9% 與 19.1%（Fig.6/7 圖內標註，p.67）；沒有在安全偵測任務上量；單一 ISP 鏈路。

### Dreger 2004（ACM CCS 2004）
- **書目／取得程度**：Holger Dreger, Anja Feldmann, Vern Paxson, Robin Sommer，"Operational Experiences with High-Volume Network Intrusion Detection"，CCS '04, pp.2–11，DOI 10.1145/1030083.1030086（Crossref 確認）。PDF：`https://www.icir.org/robin/papers/ccs04.pdf`（作者所在機構 ICIR 的版本，11 頁，含附錄）。**全文**。與給定資訊相符。
- **機制**：load-levels＝一組有順序的 packet filter，「越大」的 filter 讓 NIDS 多做越多分析；任何時刻 kernel 只裝其中一個 [原文 PDF p.8]。在 Bro 裡以 `capture_load_levels` 設定 DNS、SMTP、FTP 等 decoder 在哪個 level 以下才啟用 [原文 PDF p.9]。調整規則：兩分鐘平均 CPU 使用率高於 90% 就退到較省的 filter，低於 40% 就升到較費的 [原文 PDF p.9]。作者試過丟包與 CPU 使用率兩種訊號：丟包會震盪，CPU 使用率有效 [原文 PDF p.9]。所有 filter 預先編譯，因為即時編譯太貴；FreeBSD 換 filter 會清空擷取緩衝區，所以另外修了 driver [原文 PDF p.9]。另有 flood detector：以 1/100 抽樣連線嘗試，估計每分鐘新連線超過門檻（預設 30,000）就對受害主機裝 1:100 抽樣的 host filter [原文 PDF p.9]。
- **偵測面**：**沒有量化偵測損失**。作者明講資源與偵測率是「環境相關的政策決定」，並用不公開參數的方式避免可預測 [原文 PDF p.7 §4.6]。唯一的定量是 flood detector：在 mwn-irc-ddos trace 偵測到全部三個攻擊 burst，記憶體維持在 122M 以下，其他設定都在最後一個 burst 耗盡 1 GB [原文 PDF p.9]。作者也承認 Lee 等人的「量化每個分析工作的成本效益」類方法很難對高流量做出清楚的成本指標，因此他們只靜態定義等級 [原文 PDF p.2 §2]。
- **成本面**：Dual Athlon MP 1800+、2 GB、FreeBSD 5.2.1，MWN 約 44,000 pkt/s、1–2 TB/天 [原文 PDF p.2]。HTTP decoder 讓 run-time 增加 6.2×（mwn-www-full）與 5.6×（mwn-cs-full），相對只做連線摘要 [原文 PDF p.4]。午後流量約是夜間的 4 倍，夜間可以分析全部 HTTP [原文 PDF p.4]。最後的設定下丟包「每小時 2–3 次」[原文 PDF p.5]。
- **對我們的意涵（[推測]）**：控制迴路的形狀可以直接用：有限個預先定好的稽核等級＋CPU 使用率平均窗＋上下兩個門檻形成遲滯。Pi 上對應的等級可能是「信任比例／SYN-FIN 以外的抽檢率／哪些 app-layer decoder 或規則群組開著」。切換成本要看實際旋鈕：換 tc eBPF map 值應該便宜，Suricata 規則群組需要 reload，成本未量。2 分鐘平均窗對 Pi 上的短突發太慢，窗口與門檻要重新量。
- **限制**：作者承認：週期性突發仍會造成偶發丟包，並無完美設定 [原文 PDF p.5]。我觀察到：等級是人工排序的，沒有跟偵測損失掛鉤；90%／40% 是經驗值，無敏感度實驗。

### Selective Packet Discarding（EuroSec 2010）— 引用既有筆記
- 全文已讀，不重讀。要點見 [既有筆記 research/literature/trust-bypass/papers/selective-discarding.md D7, T1–T4]：依 flow 內封包序號設全域 cutoff，cutoff 由 kernel 丟包、CPU 使用率（0.95／0.8 門檻）決定；在 900 Mbit/s 下丟 63% 封包仍保留 96.3% alert（讀圖）；丟棄在 user space 做，不省 capture 成本；先良性、後攻擊的規避沒有量測。
- 與 E 組的關係：它和 Dreger 同一類（反應式、門檻、遲滯），差別是它的旋鈕是「每條 flow 看幾個封包」而不是「開哪些 decoder」，且是這三篇裡唯一量了 alert 保留率的。

### NFVnice（ACM SIGCOMM 2017）
- **書目／取得程度**：Sameer G. Kulkarni, Wei Zhang, Jinho Hwang, Shriram Rajagopalan, K.K. Ramakrishnan, Timothy Wood, Mayutan Arumaithurai, Xiaoming Fu，"NFVnice: Dynamic Backpressure and Scheduling for NFV Service Chains"，SIGCOMM '17, Los Angeles, DOI 10.1145/3098822.3098828 [原文 p.1 ACM Reference]。PDF：`https://faculty.cs.gwu.edu/timwood/papers/17-SIGCOMM-NFVNice.pdf`（共同作者 Timothy Wood 的站，14 頁）。**全文**。TON 2020 有延伸版（IEEE/ACM ToN 28(2):639–652，只有搜尋結果提到，未讀）。讀了 §1–§3、§4.1–4.2.1、§4.3.6–4.3.8、§5；§4.2.2、§4.3.1–4.3.5 只略讀。給定資訊相符。
- **機制**：每個 NF 是一個行程；NF Manager（專用核心）以 DPDK 收發封包，用 libnf 取得每個 NF 的到達率與單封包服務時間（每 1 ms 抽樣，取 100 ms 窗口的中位數以避開 context switch 污染）[原文 p.7]。權重公式：load(i) = λᵢ × sᵢ，Shares(i) = Priority(i) × load(i) / TotalLoad(core) [原文 p.6]。權重寫入 Linux cgroup（每 10 ms 一次），排程類別選 SCHED_BATCH [原文 p.5, p.7]。backpressure：NF 的接收佇列超過 HIGH_WATER_MARK 且排隊時間超過門檻時，在 service chain 的**入口**丟該 chain 的封包，降到 LOW_WATER_MARK 才解除（遲滯）[原文 p.6]。
- **偵測面（效果面）**：作者先證明 Linux 排程器本身做不到：三個 NF 成本 500/250/50 cycles、到達率相同時，SCHED_NORMAL 平均分 CPU，成本輕的 NF 拿到最高吞吐；SCHED_NORMAL 的非自願 context switch 約 65K/s，SCHED_BATCH 約 1K/s [原文 p.3–4, Table 2]。NFVnice 在 3 NF 單核鏈上吞吐最多約 2 倍（對 RR），上游丟包從百萬 pps 降到近零 [原文 p.8, Table 3]；3 核各一個 NF 時，同樣 0.6 Mpps 聚合吞吐，CPU 使用從 300% 降到 175%±3% [原文 Table 5 p.8]；6 個成本比 1:2:5:20:40:60 的 NF 共核，NORMAL 每個 NF 16.6% CPU，輕的拿 1.02 Mpps、重的 0.07 Mpps；NFVnice 輕的 1%、重的 46%，Jain's fairness 從 0.62 到 1.0 [原文 p.11–12]。
- **成本面**：Xeon E5-2697 v3、10GbE、DPDK、kernel 3.19 lowlatency、64 B 封包 [原文 p.7]。rdtsc 約 50 cycles，寫一次 cgroup 虛擬檔約 5 µs [原文 p.12]。作者曾試過自製「看佇列長度」的核心排程器，因為與核心同步佇列長度的頻率太高、成本蓋過好處而放棄 [原文 p.5]；用 syscall 改 priority 也被評為會不穩定 [原文 p.4]。
- **對我們的意涵（[推測]）**：控制面的想法跟平台無關：權重＝到達率×單位成本、cgroup 寫入夠便宜（5 µs 級，x86 數字）、儘早丟比做完才丟省。可套到 Suricata worker 與 edge AI 行程共享 4 核：load = 封包到達率×約 40 µs（我們已量）對 load = 推論請求率×單次推論時間。限制：資料面是 DPDK 輪詢＋run-to-completion NF，Suricata 的 NFQ 路徑不是；cgroup v1 的 cpu.shares 對應到 v2 的 cpu.weight（預設 100，範圍 1–10000 [文件 URL]），語意是否相同未驗證；Pi 上寫 cgroup 的成本未量。
- **限制**：作者承認：水位門檻對 path delay、鏈長度、NF 成本敏感，是「工程上的折衷」[原文 p.12]。我觀察到：全部在 DPDK＋Xeon 上，沒有 ARM 或小核心數結果；沒有比較「靜態 cgroup 權重」與動態權重。

### Caladan（USENIX OSDI 2020；Shenango 未讀）
- **書目／取得程度**：Joshua Fried, Zhenyuan Ruan, Amy Ousterhout, Adam Belay，"Caladan: Mitigating Interference at Microsecond Timescales"，OSDI '20, pp.281–297。PDF：`https://pdos.csail.mit.edu/papers/caladan:osdi20.pdf`（作者實驗室）。**全文**（18 頁）。讀了 Abstract、§1–§4、§5.1–5.2、§7 開頭與 §7.1、§8；**§5.3 KSCHED 內部、§6 runtime、§7.2 後半、§7.3、附錄 A 未讀**。Shenango（NSDI 2019）**沒有讀**，只從 Caladan §5.1 的比較知道它用佇列延遲當唯一控制訊號，且 scheduler 核心兼做封包處理 [原文 p.285]。
- **機制**：一個專用 scheduler 核心每 10 µs 輪詢共享記憶體裡的控制訊號，三個控制器：頂層 core allocator（佇列延遲超過 THRESH_QD=10 µs 就加核心）、記憶體頻寬控制器（全域頻寬超過 THRESH_BW 就從 BE 任務中 LLC miss 最多者撤核心）、hyperthread 控制器（LC 請求執行超過門檻就禁用同伴 hyperthread）[原文 p.285–287]。任務分 LC 與 BE；BE 沒有保證核心，只拿閒置核心 [原文 p.285]。KSCHED 核心模組用 IPI 批次下指令 [原文 p.285]。
- **偵測面（效果面）**：memcached 與有 GC 的 BE 任務共置，Parties*（500 ms 調整一次）的 99.9% 延遲比 Caladan 高 11,000×（580 ms 對 52 µs）[原文 Abstract p.281, §7.1 p.290]。Linux（BE 用 SCHED_IDLE，kernel 5.4.0）加上 stream-DRAM 干擾時 tail latency 最高變成無干擾時的 235×，Shenango 6× [原文 p.289–290]。Caladan 用「減少核心數」來降記憶體頻寬：「reducing the number of cores allocated to a task reduces its memory bandwidth usage」[原文 p.284]。
- **成本面**：2×12 核（24 hyperthread）Xeon Broadwell、ConnectX-5 40 Gb/s、關掉 TurboBoost／C-state／頻率調整；22 個保證核心＋1 個 scheduler 核心 [原文 p.289]。
- **對我們的意涵（[推測]）**：整套不能搬：(1) 一個專用核心在 4 核的 Pi 4 上是 25% 的算力；(2) 需要核心模組、自家 green-thread runtime 與 kernel-bypass；(3) 記憶體頻寬訊號靠 Intel DRAM 控制器計數器，Pi 4 是否有可用等價物未能確認（/proc/interrupts 看得到 arm-pmu，見 Tomcore 的 dump，但是否能取得 DRAM 頻寬未知）。可借的是兩個觀察：佇列延遲是通用的過載訊號（可對應 NFQ 佇列延遲或 Suricata worker 的排隊時間）、以及「干擾不能靠優先權、要靠核心數」。
- **限制**：作者承認：應用必須使用其 runtime，不用的只能放在不受管理的核心上、不能被限流；LC 任務必須暴露內部並行度；不處理 NUMA [原文 p.293]。

### Georgiou 2025（IEEE EDGE 2025）— E3，Pi 4 基準線
- **書目／取得程度**：Joanna Georgiou, Moysis Symeonides, George Pallis, Marios D. Dikaiakos，"Automating Multi-Tenancy Performance Evaluation on Edge Compute Nodes"，2025 IEEE International Conference on Edge Computing and Communications (EDGE), pp.103–114，DOI 10.1109/EDGE67623.2025.00021（Crossref 確認）；arXiv:2506.10461，作者版共 12 頁。**全文**；讀了 §I 與 §VI–VII，§II–V（框架設計）沒讀。
- **機制**：這不是排程器，是自動化 benchmark 框架：用 Docker Swarm 部署 MLPerf 影像分類（ONNX／NCNN／TensorFlow，CPU-only）、Apache Storm、MongoDB(YCSB) 與 CPU／記憶體／磁碟／網路 stressor 的組合，量 CPU、記憶體、功率、溫度與吞吐 [原文 PDF p.6]。沒有任何緩解干擾的機制。
- **成本面（有 Pi 4 的部分）**：Pi 4 Model B（4 核 Cortex-A72 1.5 GHz、4 GB）、各 stressor 用 4 workers [原文 PDF p.6]。ML 串流推論單獨跑：Pi 4 只有 1.12 batches/s，Xeon 三台是 9.5／7.2／16.6；Pi 功率 5 W，溫度 71.5 °C（比兩台大伺服器都高）[原文 PDF p.7]。**共存實驗（RQ2、RQ3）全部在 Medium 伺服器（2×Xeon E5620）上做，不是 Pi**：ML 吞吐單獨 7.29 batches/s；與記憶體 stressor 同跑掉到 2.54、與 CPU stressor 掉到 4.04、與磁碟／網路／資料庫／串流同跑約 4.5–5.5；ML 服務的 CPU 使用率從 16.73% 掉到約 8% [原文 PDF p.8]。
- **對我們的意涵（[推測]）**：唯一能直接拿來用的是**方向**：記憶體與 CPU 密集的鄰居最傷推論，網路 stressor 影響小；以及 Pi 4 單獨跑推論就接近熱上限（71.5 °C），共置時要把熱降頻列入變數。Pi 4 共存倍率沒有數據，必須自己量。
- **限制**：作者說參數是「trial and error」選的，每情境 20 分鐘單次執行 [原文 PDF p.7]。我觀察到論文內部不一致：RQ1 文字寫 Pi 每 batch 4.52 J，同段 Key Takeaways 寫 6.67 J [PDF p.7]；§I 說記憶體 stressor 使 cold start 增加 1.5×，RQ2 文字寫 244 s→505 s（約 2.07×）[PDF p.8]。

### RT-Gang（IEEE RTAS 2019）— E3/E4，Pi 3
- **書目／取得程度**：Waqar Ali, Heechul Yun，"RT-Gang: Real-Time Gang Scheduling Framework for Safety-Critical Systems"，RTAS 2019, pp.143–155，DOI 10.1109/RTAS.2019.00020（Crossref 確認）；arXiv:1903.00999v2，13 頁。**全文**；讀了 §I–II、§III 概述、§VI（平台與 DNN workload），演算法細節沒讀。
- **機制**：一次只讓一個 real-time gang（一個平行任務的所有執行緒）佔用所有核心，閒置核心跑 best-effort 任務，並用每核 HW 計數器限制 BE 任務的記憶體頻寬 [原文 PDF p.1–2, §III]。實作是改 Linux 4.4 的 `kernel/sched/rt.c`，約 500 行架構無關 C [原文 PDF p.8]。
- **效果面**：DeepPicar（DAVE-2 型控制 DNN）在 Pi 3 上 1 核 46.30 ms、4 核 22.86 ms [原文 PDF p.2]；DNN 用 2 核、記憶體密集的 BwWrite 用另 2 核，DNN 慢 10.33×，BwWrite 只慢 1.05× [原文 PDF p.3]。在 baseline Linux 上共排，Pi 3 的 DNN WCET 在所有設定下都超過單獨跑的 2 倍 [原文 PDF p.10]。RT-Gang 下延遲變得確定，但 Pi 3 上仍有一個固定的增量，作者推測是 cache 相關的 preemption 延遲 [原文 PDF p.10]。
- **成本面**：Raspberry Pi 3（Cortex-A53）與 Jetson TX2；兩個平台都固定最高頻、**關掉網路**、關 GUI [原文 PDF p.8]。
- **對我們的意涵（[推測]）**：給「共置時 DNN 會被吃記憶體的鄰居拖慢一個數量級」一個 ARM 低階核心的實例；但 Cortex-A53 的記憶體系統比 Pi 4 的 A72 弱，倍率不能直接搬。一次一個 gang 的策略在我們這裡意味著 Suricata 與 AI 輪流用核心，會造成封包排隊，是否可接受要看轉送延遲目標。需要 kernel 修改，不是 stock Linux。
- **限制**：作者承認一次一個 gang 可能讓核心閒置 [原文 PDF p.3]。我觀察到：沒有任何網路流量，網卡中斷與封包處理的干擾完全沒涵蓋。

### Kim 2024（IEEE ICCD 2024）— E3，干擾預測的做法
- **書目／取得程度**：Yeonjae Kim, Igjae Kim, Kwanghoon Choi, Jeongseob Ahn, Jongse Park, Jaehyuk Huh，"Interference-Aware DNN Serving on Heterogeneous Processors in Edge Systems"，ICCD 2024, pp.199–206，DOI 10.1109/ICCD63220.2024.00038（Crossref 確認）。PDF：`https://jeongseob.github.io/assets/papers/kim_iccd24.pdf`（作者主頁）。**全文**（8 頁）；讀了 §I–IV 開頭、§V-C、§V-D 與實驗設定，結果圖表細節沒讀。
- **機制**：量兩種干擾來源：共享記憶體頻寬與 GPU 執行單元，並指出受害模型有各自的「敏感度」（VGG-11 對記憶體頻寬比 SqueezeNet 敏感）[原文 PDF p.2–3, Fig.2–4]。用隨機生成的模型訓練一個 MLP 預測共跑造成的延遲增加，不需要事先知道真正的目標模型 [原文 PDF p.1]。排程時隨機抽 1000 個配置矩陣做模擬，挑最符合目標的；模擬 1000 個要 200 ms（在 Xavier 的 CPU 上），只在工作組合或請求率明顯改變時重跑 [原文 PDF p.6]。
- **效果面**：14 個真實模型上預測準確率 95.9%；相對 baseline，goodput（滿足延遲 SLO 的吞吐）平均 +40%、99% SLO 吞吐平均 +36.1% [原文 PDF p.1]。
- **成本面**：Jetson AGX Xavier（8 核 CPU、1 GPU、2 DLA）、TensorRT [原文 PDF p.6]；不是 ARM CPU 推論、也沒有封包處理。
- **對我們的意涵（[推測]）**：可借的是方法：把「壓力（鄰居用多少記憶體頻寬）」與「敏感度（受害者對頻寬多敏感）」分開量，離線建成查表。對 Pi 來說可以離線量「Suricata 在 X kpps 時對某個推論模型的拖慢」做成表；但 edge AI 的模型還不確定，無法預先建表。
- **限制**：作者的場景是 GPU／NPU 間干擾；我觀察到它沒有討論 CPU 核心被網路中斷搶走的情況。

### PLAIground／Pixie（IEEE SMARTCOMP 2026）— E3，依負載切換模型
- **書目／取得程度**：Milos Gravara, Cynthia Marcelino, Andrija Stanisic, Stefan Nastic，"PLAIground: SLO-Driven Runtime Model Selection for Compound AI Systems in the Edge-Cloud-Space Continuum"，SMARTCOMP 2026 pp.261–266（出處取自 arXiv 頁面，未另查 IEEE）；arXiv:2606.14356。**全文**（6 頁）；讀了 §III–IV 與 §V 的設定。
- **機制**：Pixie 對每個任務維護一個由高到低排序的候選模型表。窗口（k 次觀測）平均的延遲／成本／能耗與 SLO 算出「最緊的資源的剩餘比例 g」：g < τ_low 就降一級、g > τ_high 就升一級，之間不動；每次切換後清窗口並冷卻 k 次觀測，避免震盪 [原文 PDF p.3–4, Algorithm 1]。
- **效果面**：兩個 Compound AI workflow，最高準確度 91.3% 且守住 SLO；固定模型策略超出成本／延遲預算最多 21×，或準確度低 4% [原文 PDF p.1，摘要＋p.5–6]。
- **成本面**：邊緣是 Jetson Orin Nano（8 GB）跑 Triton；本地模型預載在 GPU 記憶體，切換 <10 ms 且無 cold start [原文 PDF p.4]。評估的訊號是能耗預算與成本，不是 CPU 競爭。
- **對我們的意涵（[推測]）**：控制器非常簡單（一個窗口平均、兩個門檻、一個冷卻期），與 Dreger 的 90%／40% 同構，可以直接當作「edge AI 依 CPU 壓力降級模型」的骨架。Pi 上的切換成本未知：多個模型同時常駐會吃 RAM，Georgiou 量到 CPU-only 的 TensorFlow cold start 356–375 s、ONNX／NCNN 30–40 s（在 Xeon 上）[Georgiou PDF p.9]，所以預載是必要條件。
- **限制**：作者把 Task SLO（準確度）分解列為未來工作 [原文 PDF p.4]。我觀察到：沒有與 CPU 競爭或共置的實驗。

### E4：Linux 文件與技術文章（不是論文，各自標取得方式）
這一段的量測數字只採 Tomcore（原文 HTML 我自己讀過）、PyTorch 教學（原文 HTML 我抓下來核對過）；其餘為文件或摘要。

- **Tomcore，"Raspberry PI 4B Network Performance"**（Thomas Zeman，2022 年 1 月量測，Alpine 3.15、kernel 5.15.4-0-rpi4、iperf3 `-P 10`，對端 Windows 10 PC）。`https://tomcore.io/docs/articles/RaspberryPI/raspberry-pi-4b-network-performance/`。取得：HTML 原文，已轉文字存 `pdfs/tomcore-pi4-net/page.txt`。內容：eth0 有兩個 IRQ（38＝送出完成、39＝收到資料），都只由 CPU0 處理；"The RPI4 ARM GICv2 cannot signal one particular interrupt to more than one CPU"，把 mask 設成 6 仍然只有 CPU1 處理。半雙工約 949/950 Mbit/s；全雙工同時收送只有約 540/545。IRQ 38→CPU1、39→CPU2 後 613 / 864（Pi 端 315 次重傳），再設 `xps_cpus`=f（tx-0…tx-4）與 `rps_cpus`=f（rx-0）後 935 / 764，`top` 顯示 CPU1 100% sirq、CPU0 98% idle。超頻到 2 GHz 只讓 764→773。**限制**：單一部落格、端點 TCP 吞吐（含 Pi 自己跑 iperf3）、不是 bridge／forward、不是小封包 pps；全雙工數字以 Windows PC 為對端，變異未報告。
- **Corner，"BIFRÖST Part 2 - RPi 4B Hybrid Bridging Router - Tuning Linux Network for Gigabit Line Speed"**（LinkedIn，2020-12-29）。取得：僅 WebFetch 摘要，未見原文。摘要內容：Pi 4B、Ubuntu 20.04、iPerf3 TCP 5 分鐘；調整前平均 615.58 Mbit/s 且 CPU0 滿載，把 eth0 的 IRQ 34、35 移到 CPU1、RPS／XPS 遮罩設 0xc 後 923.16 Mbit/s [二手 URL，經 WebFetch 摘要]。摘要也指出文章的 CPU 編號敘述自相矛盾，因此只當線索。
- **PyTorch 教學，"Real Time Inference on Raspberry Pi 4 and 5 (40 fps!)"**。`https://docs.pytorch.org/tutorials/intermediate/realtime_rpi.html`。取得：HTML 原文（已核對）。內容：在 Pi 4 Model B 4GB 上測；"If you have anything running in the background on the Raspberry Pi it may cause contention with the model inference causing latency spikes"；用 `torch.set_num_threads(2)`，shufflenet_v2_x1_5 的最佳延遲 60→72 ms，但消除 128 ms 的尖峰；預設設定下 MobileNetV2 量化版約 30 fps。**限制**：教學文章，尖峰的來源（哪個背景程式）與重複次數未說明，CPU 頻率與 governor 未說明。
- **kernel 文件 `Documentation/networking/scaling.rst`**（`https://docs.kernel.org/networking/scaling.html`，經 WebFetch 摘要）：RSS 是每個 queue 一個 CPU；RPS 預設關閉（遮罩為 0 時封包在中斷的 CPU 上處理）；RPS 不增加硬體中斷率但會引入 IPI；硬體 queue 數 ≥ CPU 數時 RPS 大概是多餘的，queue 少於 CPU 時可能有益；高中斷率時 "it may be wise to exclude the interrupting CPU from the map"；RFS 需先設 `rps_sock_flow_entries` 與 `rps_flow_cnt`。
- **kernel 文件 `Documentation/networking/napi.rst`**（`https://docs.kernel.org/networking/napi.html`，經 WebFetch 摘要）：threaded NAPI 是「用專屬 kernel thread 取代 softirq context 做 NAPI 處理」，由 netdev 的 sysfs `threaded` 檔開關，thread 名為 `napi/<ifc>-<id>`；文件建議把每個 thread 釘到服務該中斷的同一顆 CPU；文件未提優先權。[推測] 這讓網卡接收處理變成可用一般排程工具（優先權、cgroup）管理的執行緒，但 bcmgenet 是否能用、效果多少，沒有來源，未能確認。
- **kernel 文件 `cgroup-v2.rst`**（`https://docs.kernel.org/admin-guide/cgroup-v2.html`，經 WebFetch 摘要）：`cpu.weight` 預設 100、範圍 [1,10000]；`cpu.max` 預設 "max 100000"（period 100000 µs）；`cpu.idle`=1 使 cgroup 成為 SCHED_IDLE；"cgroup2 cpu controller doesn't yet support the (bandwidth) control of realtime processes"；`cpuset.cpus.partition` 可設 member／root／isolated，isolated 是「沒有排程器 load balancing」。
- **kernel 文件 `sched-deadline.rst`**（`https://docs.kernel.org/scheduler/sched-deadline.html`，經 WebFetch 摘要）：參數 runtime／deadline／period；admission 條件是各任務 runtime/period 之和小於上限，預設每 CPU 95%（`sched_rt_runtime_us`=950000）；deadline 任務的 CPU affinity 不能比所在的 root domain 小，所以不能用 `sched_setaffinity`，要靠 cpuset 建立受限的 root domain；runtime 用完會被 throttle 到下個 period。
- **Indeed Engineering，"Unthrottled: Fixing CPU Limits in the Cloud"**（Dave Chiluk，2019-12-05）。`https://engineering.indeedblog.com/blog/2019/12/unthrottled-fixing-cpu-limits-in-the-cloud/`。取得：WebFetch 摘要。內容：commit 512ac999d275 在 4.18 引入，造成 CFS bandwidth 在低使用率下仍 throttle，最壞回應延遲從超過 2 秒降到 30 ms。x86 雲端環境，與 Pi 無關，只說明 `cpu.max` 對延遲敏感工作有已知的坑。

## 2. 各問題的回答

### E1　IDS／網路監控 CPU 不夠時怎麼調適
- **預測或量測負載**：(a) Barlet-Ros：batch 的流量特徵→迴歸預測 cycles，TSC 量實際用量，EWMA 修正誤差 [原文 p.63–69]；(b) Dreger：兩分鐘平均 CPU 使用率＋上下門檻 [原文 PDF p.9]；(c) SPD：kernel 丟包、CPU>0.95 且處理時間>0.95×到達間隔，閒置條件 0.8 [既有筆記]。Barlet-Ros 的實驗顯示預測式比「用上一個 batch 的用量當預測」的反應式穩定：預測式 8 小時零 capture 丟包，反應式約 5% batch 整批遺失 [原文 p.70]，但兩次的流量不同（見該篇）。
- **丟什麼／少做什麼**：均勻封包或 flow 抽樣（Barlet-Ros）；關掉較貴的 decoder（Dreger）；每條 flow 只看前 N 個封包（SPD）；對受害主機的 flood 以 1:100 抽樣（Dreger）。
- **偵測損失**：只有 SPD 量了 alert 保留率；Dreger 沒量；Barlet-Ros 量的是計數誤差，pattern-search 沒量。三篇都沒有針對「攻擊者知道有 shedding」做量測，Barlet-Ros 的每 interval 換 hash 與 SPD 的 cutoff 規避疑慮是僅有的相關討論，後者沒有實驗。
- 對照我們：Suricata 本身的 stream depth、bypass 等旋鈕有沒有被當作 load shedding 旋鈕研究過，我的搜尋沒有找到論文（只看到 Suricata 文件與郵件列表）。

### E2　延遲敏感封包處理與其他工作共用核心
| 想法 | 來源 | 4 核＋無 bypass＋stock Linux 能用嗎 |
|---|---|---|
| 依 λ×s 比例設 cgroup 權重 | NFVnice | 控制面可（寫 cgroup 約 5 µs，x86 數字）；其資料面要 DPDK。[推測] |
| 在最上游先丟（backpressure） | NFVnice | 概念可：在 tc eBPF／nft 層先丟，不要等到 Suricata 或 AI 做完才丟。[推測] |
| 預編等級＋遲滯切換 | Dreger | 可。 |
| 預測再抽樣 | Barlet-Ros | 概念可，特徵成本要重量。 |
| SCHED_BATCH 減少 context switch | NFVnice p.4 | 可（stock Linux 有），效果在 Pi 未量。 |
| 專用 scheduler 核心＋微秒級重分配 | Caladan/Shenango | 不可：吃 1/4 算力、需核心模組與自家 runtime。 |
| 減少 BE 任務核心數以降記憶體頻寬 | Caladan p.284 | 可（cpuset／執行緒數），PyTorch 教學是同向的實例。 |
| 一次一個 gang＋BE 頻寬限流 | RT-Gang | 需改 kernel 且不涵蓋網路，不可直接用。 |

另一個重點：Caladan 的 Linux 基準（SCHED_IDLE）和 RT-Gang 的 baseline Linux 都顯示，優先權／排程類別不能防止記憶體頻寬干擾，倍率從 235×（x86 伺服器）到 10.33×（Pi 3）。

### E3　edge 推論與其他工作共存
- **干擾**：Georgiou 的 Xeon 實驗顯示記憶體／CPU 密集鄰居最傷（ML 吞吐 7.29→2.54／4.04 batches/s），網路 stressor 較輕 [PDF p.8]。Pi 3 上的 RT-Gang 顯示 10.33× [PDF p.3]。Pi 4（A72）的共存倍率：**未找到**。
- **interference-aware scheduling**：ICCD'24 的「壓力＋敏感度＋預測模型＋模擬選配置」，但平台是 GPU／DLA。
- **model cascade／依負載切換**：Pixie 型遲滯控制器；Simioni 以信心門檻調卸載比例（0–100%，不重訓）[既有筆記 framework/papers/simioni-offload.md G2, Fig.13]，與 Pixie 同樣是「改門檻不改模型」。
- **batching**：Simioni 的 batch 1／5／10 是為了雲端 RTT [既有筆記 G4]；Georgiou 的 MLPerf 有 batch 參數但沒有在 Pi 上掃。Pi／ARM 在共存下的 batching 數據：**未找到**。
- 我沒有系統性搜尋 2019–2026 的 model cascade 文獻，只做了三次搜尋＋讀 PLAIground；結論是「Pi 上的數據找不到」，不是「不存在」。

### E4　Linux 手段與 ARM SBC 上的量測
- **IRQ affinity／RPS／XPS**：有 Tomcore 與 Corner 兩個部落格量到 Pi 4 的 TCP 吞吐變化（見 §1），機制有 kernel 文件。**沒有小封包轉送（pps）或 bridge 的數字。**
- **RFS**：文件有，Pi 上的量測未找到。Tomcore 沒有開 RFS。
- **cgroup v2 cpu.max／cpu.weight／cpuset、SCHED_DEADLINE、nice**：有文件；ARM SBC 上對封包處理或推論延遲的量測：**未找到**。x86 上的 cpu.max 問題見 Indeed。SCHED_DEADLINE 的 affinity 限制（要靠 cpuset 建 root domain）對「把 Suricata worker 釘核心」是實作上的限制 [文件 URL]。
- **CPU 頻率／governor**：搜尋只得到 governor 的一般性描述與一份很舊的 OMAP 資料，**沒有封包處理或推論延遲的量測**。
- **搜尋範圍**：Pi 4 IRQ／RPS、RPS 在 ARM SBC 的論文、cyclictest／isolcpus、governor 與網路延遲、cpu.max throttling 共約 6 次；PREEMPT_RT 在 ARM 板的 MDPI 論文（Electronics 2021, 10(11):1331）只從搜尋結果看到標題，網站對我的抓取回 403，沒有讀到內容。
- 一個被查證推翻的搜尋摘要：搜尋引擎曾說 RT-Gang++（arXiv 2304.13110）在 Pi 4 上實作；我讀了 arXiv 頁面，該文用的是 Jetson Nano，沒有 Pi 4。

### E5　對我們的意涵（全部 [推測]）
- **依負載調整稽核率**：Dreger 的等級＋遲滯，或 Barlet-Ros 的 srate 公式。實作上的旋鈕只有我們能控制的：信任比例、SYN/FIN 以外的抽檢率、規則群組。訊號候選：Suricata worker 的 schedstat CPU 時間、NFQ／NFLOG 佇列延遲（Caladan 與 NFVnice 都以佇列為訊號）、conntrack 新連線率（Barlet-Ros 的 "new 5-tuple" 特徵）。這些都要先在 Pi 上量成本與穩定性才能選。
- **依負載調整 edge AI 推論量**：Pixie 的窗口＋兩門檻＋冷卻期；或降低推論頻率／threads（PyTorch 教學的做法：4→2 threads，最佳 +20%、消除尖峰）。因為模型不確定，只能先定介面：「AI 側暴露一組由重到輕的模式，由外部控制器切換」。
- **共享預算**：NFVnice 的 Shares(i) 公式是現成的分配規則：把 Suricata（λ=封包率、s≈40 µs）和 AI（λ=推論率、s=單次推論時間）當兩個 NF。要驗證的是 Suricata 在 NFQ 路徑下的 s 是否穩定、以及兩者在記憶體頻寬上的耦合（見 E2 警訊）。
- **CPU 0 吃所有網卡中斷**：文獻層面的對應做法：(1) 把兩個 IRQ 分開釘到不同 CPU（因 GICv2，每個 IRQ 只能指一顆）；(2) 用 RPS／XPS 把協定處理移出中斷 CPU（kernel 文件建議高中斷率時排除中斷 CPU）；(3) 用 threaded NAPI 把接收處理變成可管理的執行緒。Pi 4 大概只有 1 個 RX queue（見上，未能確認），因此無 RSS。這三者都沒有 pps 量測；而我們已知的 CPU0 上限 50–60 kpps 與 PAUSE 現象是專案自己的數據，文獻沒有對應。若要採用，需先在 Pi 上量 `rps_cpus` 排除 CPU0 與否對 kpps 上限的影響。
- **空缺**：(1) IDS 稽核量與 ML 推論量共享預算——沒有任何論文；(2) Pi 4 上共存干擾倍率與 cgroup／cpuset 的緩解效果——沒有；(3) load shedding 對攻擊偵測率（特別是 payload 規則）的影響——Barlet-Ros 明確跳過，Dreger 沒量，SPD 是單一 Snort trace；(4) 攻擊者能觀察到降載等級切換時的規避——沒有量測；(5) 降載等級切換與 ct mark 信任機制的互動（降載時是否擴大信任）——沒有討論。

## 3. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| Barlet-Ros 預測誤差 | 平均 1.2%（有 payload）／0.65%（無 payload）；最大 13.9%／19.1% | 7 個 query、2 條 30 分鐘 trace | [原文 Fig.6/7 圖例 p.67] |
| 預測子系統成本 | 10.97%（抽取 9.07、選擇 1.70、MLR 0.20） | P4 3 GHz、100 ms batch | [原文 p.66] |
| 過載下 capture 丟包 | 預測式 0（8 小時）；原版與反應式持續丟 | 平均 720–750 Mbit/s（反應式 403） | [原文 p.70] |
| 計數誤差（packets，application） | 預測 1.03%／原版 55.38%／反應式 10.61% | 同上 | [原文 Table 6 p.71] |
| Dreger 門檻 | CPU 2 分鐘平均 >90% 降級、<40% 升級 | Bro、FreeBSD | [原文 PDF p.9] |
| HTTP decoder 增加的 run-time | 6.2× 與 5.6× | 相對連線摘要 | [原文 PDF p.4] |
| NFVnice 權重更新 | 估計每 1 ms、寫 cgroup 每 10 ms；寫入約 5 µs；rdtsc 約 50 cycles | DPDK、Xeon | [原文 p.7, p.12] |
| NFVnice CPU 節省 | 同吞吐 0.6 Mpps，CPU 300%→175%±3% | 3 NF 在 3 核 | [原文 Table 5 p.8] |
| NFVnice 公平 | Jain 0.62→1.0；輕 NF 1%、重 NF 46% | 6 個成本比 1:2:5:20:40:60 的 NF | [原文 p.11–12] |
| Caladan 對 Parties* | 99.9% 延遲 11,000× 差（580 ms 對 52 µs） | memcached＋GC BE | [原文 p.281, p.290] |
| Linux（SCHED_IDLE）受記憶體頻寬干擾 | tail latency 最高 235× | memcached＋stream-DRAM | [原文 p.290] |
| Caladan scheduler 週期／延遲門檻 | 10 µs／THRESH_QD 10 µs | 專用核心 | [原文 p.286, p.289] |
| Pi 3 DNN 共排 | 10.33× 慢（BwWrite 1.05×）；WCET >2× 單獨跑 | DeepPicar，2+2 核 | [原文 PDF p.3, p.10] |
| Pi 4 ML 推論單獨跑 | 1.12 batches/s；5 W；71.5 °C | MLPerf 影像分類（串流模式） | [原文 Georgiou PDF p.7] |
| Xeon 上共存的 ML 吞吐 | 7.29→2.54（記憶體）／4.04（CPU）／約 4.5–5.5（其餘） | batches/s | [原文 Georgiou PDF p.8] |
| ICCD'24 預測／效益 | 準確率 95.9%；goodput +40%、99% SLO 吞吐 +36.1% | Jetson AGX Xavier，14 模型 | [原文 Kim PDF p.1] |
| 1000 配置模擬 | 200 ms | Xavier CPU | [原文 Kim PDF p.6] |
| Pixie 切換成本 | <10 ms | 模型預載 GPU | [原文 PLAIground PDF p.4] |
| Pi 4 IRQ 分開釘核＋RPS／XPS | 540/545→613/864→935/764 Mbit/s | TCP 10 條、端點、kernel 5.15.4 | [二手 Tomcore，讀原文 HTML] |
| Pi 4 PyTorch 4→2 threads | 最佳 60→72 ms，消除 128 ms 尖峰 | shufflenet_v2_x1_5 | [文件 URL PyTorch 教學] |
| Indeed throttling 修正 | worst-case >2 s→30 ms | x86 容器 | [二手 URL，WebFetch 摘要] |

## 4. 建議追加閱讀

1. Dreger, Feldmann, Paxson, Sommer，"Predicting the Resource Consumption of Network Intrusion Detection Systems"，RAID 2008，LNCS pp.135–154，DOI 10.1007/978-3-540-87403-4_8。理由：直接處理「預測 NIDS 的 CPU／記憶體用量」，與 Barlet-Ros 的黑箱特徵法對照。存在確認：Crossref（標題、作者、頁碼）；內容未讀。
2. Barlet-Ros 博士論文，"Load shedding in network monitoring applications"，UPC 2008（`https://tesisenred.net/handle/10803/31780`）。理由：搜尋摘要說它延伸出「讓 query 自訂降載方式」，處理不耐抽樣的 query（pattern search 屬此類），正好補 ATC'07 沒量的部分。存在確認：僅搜尋結果頁，內容未讀。
3. Papadogiannakis, Polychronakis, Markatos，"Tolerating Overload Attacks Against Packet Capturing Systems"，USENIX ATC 2012。理由：攻擊者刻意製造過載來觸發 shedding，與我們的 threat model（攻擊者知道有降載機制）相關。存在確認：[既有筆記 trust-bypass/papers/selective-discarding.md D9 #4] 已確認標題；內容未讀。
4. Seo, Cha, Kim, Huh, Park，"SLO-Aware Inference Scheduler for Heterogeneous Processors in Edge Platforms"，ACM TACO 2021，DOI 10.1145/3460352。理由：ICCD'24 引為前作（"PSLO-MAEL"），是更早的邊緣排程基準。存在確認：Crossref 確認；內容未讀。
5. "Performance Assessment of Linux Kernels with PREEMPT_RT on ARM-Based Embedded Devices"，MDPI Electronics 2021, 10(11):1331（`https://www.mdpi.com/2079-9292/10/11/1331`）。理由：同行審查的 ARM 板排程延遲量測，可能涵蓋負載下的結果。存在確認：僅搜尋結果列出標題與網址；網站對我的抓取回 403，內容未讀，數字不可引用。

## 5. 自評：最不確定的三件事

1. **「Pi／ARM SBC 上沒有 cgroup、cpuset、SCHED_DEADLINE、頻率對封包或推論延遲的量測」這個負面結論的可靠度**：我做了約 6 次針對性搜尋與 3 次 E3 搜尋，但搜尋工具回傳的是摘要，MDPI、ACM、par.nsf.gov 等站我連不上或被擋，可能漏掉在這些站上的論文。這是「我沒找到」，不是「不存在」。
2. **E3 的 Pi 4 共存倍率完全沒有數據**：Georgiou 只在 Pi 4 做了單獨基準，RT-Gang 是 Cortex-A53 的 Pi 3，倍率（10.33×）不能搬到 A72＋LPDDR4。model cascade 與 batching 的文獻我沒有系統性搜尋，只讀了 PLAIground 與引用既有筆記的 Simioni。
3. **E4 的 Pi 數字來源品質**：Tomcore 我讀了原文並核對，但它是單一部落格、端點 TCP 吞吐；Corner（BIFRÖST）與 kernel 文件、Indeed 都只經 WebFetch 小模型摘要，沒有逐字核對。它們都不是 bridge 轉送或小封包 pps，不能直接當作我們 CPU0 上限的對照。
