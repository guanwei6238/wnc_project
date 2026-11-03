# ebpf-xdp-dl（補讀：框架子題角度）

頁碼約定同既有報告：[原文 p.N] 為 PDF 頁碼（共 12 頁，期刊頁碼 = PDF + 16）。本次重新以 pdftotext 讀全文，並渲染 PDF p.4 目視 Fig.1。

## A. 書目
Liu, Law, Zhang, Lam, "Real-Time eBPF/XDP-Based Deep Learning Framework for Anomaly Traffic Detection in Internet of Things Networks", IEEE Internet Computing 30(3), 2026, DOI 10.1109/MIC.2026.3692726 [原文 p.1]。書目與既有報告一致，無誤。取得程度：全文。
既有報告：`/home/sixsquare/wnc_project/research/literature/papers/ebpf-xdp-dl.md`

## G. 框架專屬欄位

**G1. 框架的抽象**
- 論文說的 "framework" 是一個**特徵選擇演算法**（Alg.1：Gini 預篩 + GRU 增量評估），作者稱它是介於「raw traffic ingestion 與 threat detection」之間的 middleware [原文 p.3]。它不是軟體工程意義的框架：沒有 API、沒有描述語言、沒有設定檔格式、沒有模組介面。
- 框架固定的是 pipeline：Phase A 離線（選特徵、訓練）→ Phase B 線上（XDP 抽特徵 → BPF map → user space 輪詢 → GRU）[原文 p.3, Fig.1, Alg.2 p.6]。作者還把 eBPF/XDP 稱為 data plane、GRU 稱為 control plane [原文 p.3]；這個「control plane」是推論，不是控制或下發政策。
- 留給使用者的：資料集 D、原始特徵集 F、context 判斷（ports 可不可靠 → S_base 取 {Protocol, Ports} 或 {Protocol}）[原文 p.5 Alg.1 第 9 行]。這個判斷怎麼做論文未說明；CICDDoS2019 是作者**手動宣告**「ports 不可靠」（p.6 稱 "simulated"），不是演算法偵測出來的 [推測]。
- 換特徵集時要不要重新編譯 kernel 程式：**論文未說明**。只有 Fig.1 的虛線 "Configure Extraction Logic" 與 p.3 的 "eBPF programs ... are dynamically configured to extract only the features defined in S_opt"。沒說是 map 設定、重新編譯、還是重新載入。Alg.2 第 5 行 "if Feature f in S_opt is calculable in Kernel" 暗示 kernel 程式能依 S_opt 條件式計算，但實作未交代。
- 缺口 [推測]：Alg.1 的候選特徵直接取資料集欄位（第 7 行），沒有「kernel 是否算得出來」的過濾。IoT-23 選出的 conn_state_RSTOS0（p.8 Table 1）是 Zeek 的連線狀態欄位，XDP 內重現需要 TCP 狀態追蹤，論文沒討論；也只在 CICDDoS2019 驗證了線上部署（p.10）。

**G2. 擴充與生命週期**
- 沒有載入、替換、停用、串接機制，也沒有執行中切換或重配置時間的量測；全文只有一組固定的 XDP 程式 + 一個固定模型。「換環境」＝重跑 Phase A 離線流程後重新部署，論文未量這段時間。
- 重跑成本粗估 [推測，由 Alg.1 第 11–27 行推算]：CICDDoS2019 加入 4 個特徵、每輪對每個候選各訓練一次 GRU，約 20+19+18+17+16 ≈ 90 次訓練；每次耗時論文未說（Table 2 的 GRU 151.27 s 是 77 特徵、硬體未說明，p.9）。
- 「adaptive / dynamically」指的是每個環境離線選一次；部署後沒有線上調整特徵的實驗（既有報告 D7 的結論方向正確，見 F 第 1 點）。

**G3. Kernel / User space / 外部分工**
| 層 | 做什麼 | 通道與狀態 |
|---|---|---|
| Kernel（XDP） | 每封包抽 header context K（例：five-tuple），更新 flow 統計（bytes、packets），能在 kernel 算的 S_opt 特徵就算並更新，回傳 `XDP_PASS` [原文 p.6 Alg.2 第 2–8 行] | 狀態在共享 BPF hash map（「exports to user space via a hash map」p.2） |
| User space | 無限迴圈：逐 flow 讀 map → Z-score → GRU → 良性則從 map 刪除；惡意則告警並保留供鑑識；每輪 `Sleep(Interval)` [原文 p.6 Alg.2 第 11–23 行] | **輪詢**（poll，Fig.1 標 "Poll"/"Update"）；沒有 ring buffer、perf event 或 AF_XDP |
| 外部（cloud / controller） | 無 | 無 |
- 論文只說 map 要有 "strict memory bounding (e.g., hash map limits)"（p.2）與 "Preventing eBPF map overflows"（p.5）是設計目標，但 **max_entries、滿了怎麼辦、flow timeout、Interval 數值、map 類型（是否 LRU / per-CPU）都論文未說明**。
- 淘汰策略只有 benign-first eviction（良性刪除、惡意保留）[原文 p.6]。[推測] 這讓攻擊期間 map 只增不減，而且 user space 的批次輪詢使「首個推論」前的 flow 狀態被整筆刪除，下一封包重新建立 entry，flow 統計因此被切碎；論文沒討論。
- 「map 在 kernel、agent RSS 5.63 MB 在 user space」兩者分屬不同記帳，論文把「記憶體恆定」歸功於 map 設計（p.10），沒有單獨報 map 佔用。

**G4. 外部依賴可選性**
- 論文無 controller/cloud，不適用。附帶觀察：XDP 路徑一律 `XDP_PASS`（Alg.2 第 8 行），所以 user space agent 掛掉時封包仍轉送（fail-open），但論文**沒有驗證**這一點。Fig.1 寫 "Malicious: Alert & Block"（讀圖），Alg.2 輸出標 "Verdict and Mitigation"（p.6），演算法本體只有 "Alert and Retain"，阻擋機制論文未說明。[推測] agent 停止時 map 不再被清空，後續行為（新 flow 插入失敗）論文未討論。

**G5. 框架價值怎麼證明（照論文實際做的）**
- 做了：三個資料集上的特徵選擇軌跡（Table 1，摘要稱之為 "ablation studies"，p.2）、8 個 DL 模型比較（Table 2）、Pi 4B 上單一硬體 profiling（Table 3）。
- **沒有**：與手寫版本或其他框架比 overhead；與非 XDP 路徑（NFQUEUE、libpcap）比；開發成本（LoC、時間）；可維護性；模組數量或擴充案例；轉送 throughput/latency。三個「案例」是三個資料集，不是三種網路功能。

**G6. 效能量測方法（Pi 4B，Table 3）**
論文只寫了下面這些，其餘無法照著重做：
- 硬體：Raspberry Pi 4B，Cortex-A72 ×4 @1.5 GHz、4 GB，當 IoT Gateway [原文 p.10]。
- 流量：「replayed attack traffic from the CIC-DDoS2019 dataset under sustained stress for 100 s」[原文 p.10]。
- 量測：「monitored system resources in real-time」；Tkernel＝每封包 XDP 程式延遲（avg 1.85 μs / peak 20.11 μs）、Tuser＝每 flow GRU 推論（avg 10.38 ms / peak 57.89 ms）、agent CPU（avg 0.67% / peak 2%）、RSS 5.63 MB [原文 p.10, Table 3]。
- **論文未說明**：重播工具與來源機器、網卡/連結速率、封包大小與 pps、拓樸（有無第二個 port、有沒有轉送）、時間戳來源與方法（例如 `bpf_ktime_get_ns`、bpftool prog stats、perf）、取樣頻率與樣本數、warm-up、重複次數、標準差/CI、CPU 的分母（單核或全機、是否含 softirq）、是否遵循 RFC 2544/9411。重播用的是封包檔還是由特徵表還原，也未交代（ref 10 是 Kaggle 資料集頁面，我未能取得頁面內容確認其格式）。
- Tuser 10.38 ms/flow 對只有 5 個輸入的 GRU 偏大 [推測：可能含 Python/框架開銷與 map 讀取，論文未說明量測範圍]，因此不能當作「GRU 本身」的成本。
- **Pi 4 的 XDP 模式**：論文只說 XDP 掛在 "driver hook"（p.10）、"in the driver path"（p.1）並稱 "wire-speed"，沒有說 native / generic / offload，也沒說用哪個網卡或驅動，**論文未說明**。依據：Pi 4B 板載乙太網是 bcmgenet（背景知識，非論文所述）。[二手] 我查到 bcmgenet 的 XDP 支援為 2026-03 起的 netdev 補丁串，ratatoskr 頁面顯示 v9（2026-05-06）狀態為 "Pending"，沒有 applied/merged 訊息，最後一則討論為 2026-05-18（https://ratatoskr.run/netdev/2026/05/7948178/t；系列起點 https://lkml.iu.edu/2603.1/11168.html）。論文刊登於 2026-05-12，所以 [推測] 作者用的 kernel 若是未含此補丁的版本，只能跑 generic XDP，或使用其他網卡；但論文沒有任何證據，不能下結論。若為 generic，XDP 在 skb 配置之後才執行，1.85 μs 與「wire-speed」的意義都不同。

**G7. 安全模型**
- 論文未說明：誰能載入 XDP 程式或模型 M、有無簽章或完整性檢查、權限（root/CAP）、隔離方式。只在背景提到 eBPF 是 "sandboxed kernel virtual machine"（p.3）。威脅模型只涵蓋「被偵測的流量攻擊」，不含對框架本身的攻擊。
- [推測] 論文的測試情境是 spoofed-source DDoS，正好是對 per-flow map 做狀態耗盡的情境；但論文只報單一流量下的 RSS，沒有 map 滿載實驗。

**G8. 與我們設計對照**
- 這篇已經做過（我們不能宣稱新）：Pi 4B 上 eBPF/XDP 在 kernel 抽 flow 特徵、經共享 BPF hash map 由 user space 輪詢讀取 [原文 p.6]；kernel 與 user space 分段延遲加 CPU、RSS 的 profiling [原文 p.10]；把「要抽哪些特徵」由離線流程決定後設定進 kernel [原文 p.3, Fig.1]（機制未說明）。
- 這篇做了、我們沒有，值得考慮 [推測]：良性 flow 淘汰以界定 map 大小；用 avg/peak 分開報 kernel 與 user space 時間；特徵選擇當成「送雲端欄位」的產生器（對應我們由設定檔描述欄位，但我們目前沒有自動挑欄位的工具）。
- 我們有、這篇沒有 [推測]：真正的轉送路徑（nftables、NFQUEUE→Suricata）與其成本量測；執行政策（黑名單、ct mark；他們只有 `XDP_PASS`）；可選雲端與失效行為；使用者可擴充的外掛與欄位描述；安全模型；不把 generic XDP 當預設。
- 取捨不同：他們把 XDP 當預設資料平面並稱 "wire-speed"，卻沒說 Pi 4 上的模式；我們因為兩個 port 都沒有 native XDP，預設改掛 tc/TCX。他們的 kernel 程式不丟包，我們的外掛可 drop/redirect。他們靠輪詢+離線設定，我們靠設定檔描述式 schema。

**G9. 對碩士論文的用途（最多 5 條）**
1. Related work：Pi 4B 上 eBPF + user space 偵測的前例，可用來說明「kernel 抽特徵 → BPF map → user space」資料通道可行 [原文 p.6, p.10]；必須同時註明它沒量轉送效能且 XDP 模式未說明。
2. 定位對比：該文的 "framework" 是特徵選擇演算法，我們是可擴充的系統架構；可據此說明「框架類論文缺少 overhead 與擴充性證據」（G5 的「沒有」清單）。
3. 實驗設計借鑑（反面）：Table 3 的指標太少（無 throughput、latency、loss、重複、CI），我們應補足這些並公開重播工具、速率與量測方法。
4. 風險論證：benign-first eviction 在攻擊下 map 只增不減，可作為我們 map 上限與淘汰策略的動機 [推測]。
5. XDP 模式透明化：可引用「論文未說明 XDP 模式」支持我們在 doctor 揭露 native/generic 的設計 [推測]。

## D5（只補 Pi 4 部分）
流量為重播 100 s、速率未報、單次、無變異量 [原文 p.10]；Table 3 只有 avg 與 peak。程式碼與資料論文未說明公開。選特徵與最終準確率共用驗證結果的洩漏疑慮見既有報告 Q2，本次重讀未推翻。

## D6（只補 Pi 4 部分）
- 依賴 XDP 掛載點：bcmgenet 在 [二手] 資料中仍是進行中的補丁串（見 G6），USB 網卡依驅動而定；你們的 Pi 4 兩個 port 都沒有 native XDP（SPEC_ADDENDUM 第 1 節），因此這篇的 Tkernel 在我們平台上最多對應 generic XDP 或 TCX，數字不可直接引用，需重量。
- Pi OS kernel 無 BTF：論文未說明用 libbpf/CO-RE 或 BCC，無法判斷其程式能否在我們的 kernel 載入。
- user space 推論框架論文未說明，無法判斷在我們的映像裡能否直接跑。這些都是未驗證，只有 [推測]。

## E. 新增數字（既有報告 E 沒有、G 區塊用到）
| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| XDP 吞吐宣稱 | 26 Mpps/core | 背景引用，非本文量測；引用的 ref 1 是 Netfilter 封包路徑示意圖 | [原文 p.3, p.11 ref 1] |
| 候選集大小 / 改善門檻 | K=20、ε=0.001 | Alg.1 | [原文 p.4–5] |
| 特徵選擇訓練次數 | 約 90 次 GRU 訓練 | CICDDoS2019，加入 4 個特徵 | [推測，由 Alg.1 與 Table 1 推算] |
| CPU peak | 2%（avg 0.67%） | Pi 4B，100 s 重播，分母未說明 | [原文 p.10 Table 3] |
| Tuser peak 的歸因 | "system initialization or high-load conditions" | Pi 4B | [原文 p.10] |
| Tkernel peak 的歸因 | 新 flow entry 在 BPF hash map 的初始化 | Pi 4B | [原文 p.10] |

## F. 自評與既有報告檢查
未能確認（論文未說明）：XDP 模式與網卡、S_opt 如何設定進 kernel（map 或重新編譯）、map 類型與 max_entries、Interval、量測工具與樣本數、重播工具與速率、Tuser 的量測範圍、程式碼是否公開。

既有報告檢查（全文重讀，無重大錯誤，只有下列兩點）：
1. 既有報告 D7 第三行：「線上不會動態改特徵（S_opt 離線決定、部署時設定，p.3）」。原文 p.3 寫 kernel 程式 "dynamically configured to extract only the features defined in S_opt"，沒有說在執行中能否切換。「S_opt 離線決定」有出處；「線上不會動態改」是推論，應標 [推測]。
2. 既有報告 Q1：「key 為 five-tuple（"e.g."）[p.6]」。Alg.2 第 3 行只說 header context K "e.g., five-tuple"，沒說 K 就是 map 的 key；「每 flow 一個 entry」由第 12 行 "for each flow F in Shared Map" 支持，key 是推論。
另補足：既有 Q4 的 bcmgenet 補丁串狀態，本次查到 v9（2026-05-06）為 Pending、無 applied 訊息，仍不代表 Pi OS kernel 的實況。

最不確定的三件事：
1. bcmgenet XDP 的實際狀態：我只看到 netdev 補丁串與 ratatoskr 頁面（二手），沒查 mainline 或 Pi OS kernel 原始碼，也不知道作者用的 kernel 與網卡。
2. Tuser 偏大的原因（框架開銷或量測範圍）與 Tkernel 的量測位置，純屬我的推測，論文沒給方法。
3. 「重跑特徵選擇約 90 次訓練」與「輪詢會切碎 flow 統計」的推論：依 Alg.1/Alg.2 的字面推算，論文可能有未寫出的實作細節。
