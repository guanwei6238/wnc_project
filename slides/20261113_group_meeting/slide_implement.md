# slide_implement.md — Group Meeting 論文報告：NetBeacon

> 投影片的規格：每一頁放什麼、內容從論文哪裡來、講稿要講什麼。
> 與 `src/main.typ` 同步；兩者不一致時以 `main.typ` 為準。講稿：`逐字稿.md`；草稿：`user_draft.md`。
> 頁碼一律是投影片右下角顯示的頁碼（封面、章節頁、Q&A 不編號）。
> 「當場講」「補充」的內容不印到投影片上。
> 出處的頁碼是 PDF 頁序（1–19；PDF 第 1 頁是 USENIX 封面頁，論文頁碼 6203 = PDF 第 2 頁）。

---

## 0. 這次報告的定位

- 日期 2026-11-13，實驗室 group meeting 的論文分享。對象：老師和實驗室同學，**不一定熟 programmable switch／P4**，背景要先講。
- **純論文報告，不提 security gateway 專案**（使用者要求）。投影片、講稿都不出現 wnc-gw、Suricata、Pi、WNC、「我們的專案」。
- 論文：Guangmeng Zhou, Zhuotao Liu, Chuanpu Fu, Qi Li, Ke Xu（Tsinghua University、Zhongguancun Laboratory）. *An Efficient Design of Intelligent Network Data Plane*. 32nd USENIX Security Symposium, 2023, pp. 6203–6220。系統名稱 NetBeacon。PDF：`assets/netbeacon_usenixsec23.pdf`。
- 長度約 30 分鐘（2026-11-11 使用者要求講得比較詳細；沒有指定上限）。
- 章節順序（使用者指定）：Introduction、Motivation、Design、Evaluation、Conclusion；不放大綱頁。
- 這份報告和前幾次的週報沒有延續關係，不需要接前稿。

## 1. 查證結果（製作前，主 agent 對照 PDF 全文）

| 項目 | 論文位置 | 結果 |
|---|---|---|
| control plane 上的 ML 偵測只能到約 10 Gbps | p.2 §1 | 「can only process traffic at roughly 10 Gbps [14]」 |
| PISA 限制 | p.3–4 §2.1 | 支援 boolean、shift、add、subtract；不支援乘除、float、loop；Tofino 1 有 12 個 stage、每條 pipeline SRAM 120 MB、TCAM 6.2 MB；每個 register 一個 packet 只能存取一次 |
| flow-level features 的效果 | p.4 §2.2、Fig. 2 | 同樣數量的 feature，加入 flow-level 後 accuracy：P2P +11%、covert channel +43%、DDoS +21% |
| multi-phase sequential model | p.6 §4.2 | 在 flow 的第 n 個 packet（inference point）用前 n 個 packet 算的 feature 推論；非 inference point 的 packet 沿用最近一次的結果；每個 phase 有 determination threshold，機率超過就提前判定 |
| 模型種類 | p.6 §4.2 | Random Forest、XGBoost；論文是「選」decision tree based 的模型（sticks to），因為比 neural network 更像 match/action，不是「只能」用 tree |
| range marking | p.6–7 §5.1、Fig. 6 | 例子裡 leaf 5 用 ternary matching 要 48（8×1×6）個 entry，NetBeacon 每個 leaf 在 model table 只要 1 個 |
| 只對 long flow 存 state | p.9 §5.2、Fig. 10 | 用 80th percentile 的 flow 長度分 long／short；long-short 二元分類模型只用 per-packet features、逐 packet 判斷；訓練時取每條 flow 的前 N 個 packet 當樣本，P2P 任務 N=7、accuracy 82%（不是等 7 個 packet 才判斷）。Fig. 10：全部 flow、cutoff 8、cutoff 16 三種的整體 accuracy 很接近 |
| collision 處理 | p.9 §5.2；p.10 §5.3、Alg. 1 | index = H(5-tuple) % N；**每個 packet 一進來就先算 index**（Alg. 1 第 1–2 行），用它讀 register 裡存的 flow ID 比對（第 7、9 行）；新 flow 被判成 long（第 23 行）才檢查 register 是空的、或舊 flow 已判定／逾時（第 24–25 行），可以才佔用；否則退回只用 per-packet features。Fig. 3 把 Get Storage Index 畫在 Query Flow Class Table 之後，和 Alg. 1 的順序不完全一致 |
| flow class table | p.9–10 §5.2、§5.3、Alg. 1 | flow 判定後（過了最後一個 inference point，或中途機率 ≥ threshold）由 control plane 寫入，key 是 5-tuple；之後的 packet 命中就直接拿結果、不再推論；entry 依 FIFO 或 LRU 定期移除 |
| control plane 不在 critical path | p.10 §5.4 | 還沒寫進 flow class table 的 packet 照樣走一般推論流程 |
| 實作 | p.10 §6 | Tofino 1；P4 加 300 行 Python（control plane）|
| 三個任務與設定 | p.11–12 §7.1、Table 4 | P2P application fingerprinting（PeerRush，3 類，RF）、covert channel detection（FacetTraffic，XGB）、DDoS attack detection（8 種 DDoS＋MAWI 背景，XGB）。testing flows：246,278／400／191,009。high load 每秒新 flow 中位數：1,555／3,144／13,357 |
| inference points | p.12–13 §7.2 | P2P：{2, 4, 8, 32, 256, 512, 2048}；covert channel：{512, 1024, 1500, 2048, 3000, 4096, 6000, 8192, 10000}；DDoS：{2, 5, 8, 16} |
| 對 Mousika 的 accuracy 提升 | p.12 Fig. 13 caption | P2P 14%、covert channel 38%、DDoS 20% |
| storage 管理的效益 | p.12–13 §7.2 | 只有 P2P 論文說「完整版和 Ideal 相當，表示 storage 管理有效」；covert channel、DDoS 論文自己說 the quantitative benefits of stateful storage management are not significant |
| 資源用量 | p.12–13 §7.2 | P2P：12 stage、SRAM 17.29%、TCAM 31.25%；covert channel：12 stage、13.44%、34.03%；DDoS：9 stage、11.11%、1.85% |
| IndexSize | p.12 §7.2 | 16，也就是最多 65,536 個 per-flow state |
| table entry | p.13–14 §7.3、Fig. 14 | 同樣表現的模型，entry 少很多（covert channel 少 75%），論文歸功於 range marking 和 range coding（CRC）；§7.3 從 p.13 開始（ISCXVPN 的 (d) 任務、Mousika(RF Distilled) 的定義在 p.13）；75% 的字句在 p.14 §7.3，Introduction 的 up to 75% 在 p.3 §1 (ii)，Abstract 沒有 |
| throughput | p.14 §7.4 | 99.12／99.13／99.18 Gbps（100 Gb port）；mirror 的 packet 比例 3.8%、0.09%、1.28% |
| FPR／FNR | p.13 Table 5 | P2P 7.6%／12%／14.7%（multi-class FPR，1 vs. all）；covert channel 8.8%／10.9%；DDoS 0.7%／0.05%。Table 5 的 caption 只寫 The FPRs/FNRs in the three tasks，沒有標 per-packet 或 flow-level |
| determination threshold 的取捨 | p.14 §7.4、Fig. 15b | register 少時低 threshold 比較好（早點釋放 register）；register 多時高 threshold 比較好 |
| security analysis | p.15 §8 | stealth attack：先送 benign packet，等 flow class 判定後才送 malicious packet；low-rate-long-flow attack：逼 flow 逾時。作者說攻擊者要先探測參數、有門檻；緩解是 flow class table 的 entry 加 maximum flow length limit、每條 flow 用自己的 timeout（例如最大 IPD 的兩倍）。**兩種攻擊和緩解都只有文字討論，全文沒有對應的實驗**。low-rate-long-flow attack 論文只寫 the attacker forces the flow to timeout，沒有說手法（「把間隔拉長」是我們的理解） |

**要小心的地方**
- Fig. 13 的 14%／38%／20% 是 caption 的數字；各 load 的柱高不要自己讀圖報數字。
- Table 5 的 FPR／FNR **推論是 per-packet**（論文沒有在表上標明，是從 p.11 的指標定義和 p.13 Caveats 推論的；講稿講「論文沒標明，從上下文看應該是 per-packet」）；投影片只放 covert channel 和 DDoS 的數字，P2P 的三個數字只留在講稿補充；論文另外說 covert channel 以「至少 5 個 inference point 判對」算 flow-level 時 FPR 5.3%、FNR 7.3%（p.13）。
- 「stealth attack 沒有實驗」是我們讀全文的觀察，講稿要說「論文裡沒有看到」，不要說成作者承認。
- flow class table 的大小、FIFO／LRU 各自的效果，本文只在 Appendix 描述做法，沒有量。

## 2. 共通規則

- 只放重點；說明句寫在講稿，不印在投影片上。
- 技術名詞一律英文，全份統一：packet、flow、data plane、control plane、programmable switch、flow-level features、per-packet features、inference point、determination threshold、flow class table、register、table entry、stage、range marking、stateful storage、accuracy。
- 論文原圖從 `assets/netbeacon_usenixsec23.pdf` 裁出來放 `assets/`（檔名 `fig01_pisa.png` 這種形式），每張原圖下方用小字只標「Fig. N」（不放作者與出處；只放原圖的一部分時標「Fig. 2（下半）」「Fig. 14 (a)–(c)」「Fig. 15 (b)(c)」）；依論文的表重畫或整理的表，下方小字標「Table N 重畫」「Table N 整理」。裁圖用 `pdftoppm -r 200 -f P -l P -png` 再用 ImageMagick 裁；裁完要用 Read 看過，確認沒有切到字、沒有帶到旁邊的內文。
- 自己畫的圖（p9、p10）用 template 的 fletcher 節點，圖裡只放節點名稱和箭頭上的短標籤。
- 每頁的字不要多：標題＋圖／表＋最多 3 個短 bullet。
- 用 `../template.typ`，寫法參考 `../20261109_security_gateway_專案介紹_Demo/src/main.typ`；用 `../build.sh -p` 編譯並逐頁看 PNG 檢查排版（不能有溢出頁面或重疊）。
- 標題（`title:`）：`NetBeacon 論文報告`（PDF 檔名由它決定，不要放冒號）；`date: "2026-11-13"`。封面要看得到論文全名 *An Efficient Design of Intelligent Network Data Plane*、作者與「USENIX Security 2023」（template 的封面沒有欄位的話，在封面後自己加文字，或用 template 能做到的方式；不要改 `../template.typ`）。

## 3. 每頁規格

### 章節頁（不編號，共 5 張）
- 用 `= 章節名` 產生：Introduction（p1–p2 前）、Motivation（p3–p4 前）、Design（p5–p10 前）、Evaluation（p11–p14 前）、Conclusion（p15–p16 前）。
- 當場講各一句話帶過。

### 封面（不編號）
- 論文標題、「論文報告」、日期。作者、出處一行。

### p1　Intelligent Data Plane（IDP）
- 圖：自己畫的簡圖，兩條路徑對照：
  - 「ML 在 control plane」：switch → server（ML）→ 約 10 Gbps、多一段反應時間
  - 「ML 在 data plane（IDP）」：switch 內直接推論 → line-speed
- 投影片沒有 bullet。
- 當場講（直述、簡短，只講原因和作者的想法）：模型通常放在 end-host 或 network control plane（上排）→ 兩個問題：10 Gbps、reaction time → 作者的想法是直接放進 data plane（下排），line-speed，叫 IDP。data plane／control plane 各用一句話帶過。「以前 nearly impossible、programmable switch 出現後才可行」和 SDN（ASIC → SDN → PISA，p.3 §2.1）當場不講，只留在 p2 補充；「NetBeacon 的 control plane 做什麼」只留在補充。

### p2　Programmable Data Plane（PISA）
- 圖：`fig01_pisa.png`（Fig. 1，PDF p.3）。
- 表（只列 PISA 能做的；沒列的就是不能做，乘除、float、loop 用講的）：
  - Match：exact、ternary、LPM
  - Computation：boolean、shift、add、subtract
  - Match/action stage：數量有限（Tofino 1：12 個）
  - Stateful storage：register，一個 packet 對每個 register 只能存取一次
  - 出處都是 PDF p.3 §2.1。原本是「能做／不能做」兩欄各三列，同一列的左右兩格不相干，使用者要求改（2026-11-12）。圖寬從 16cm 縮到 13.5cm 讓四列放得下。
- 當場講：開頭「這篇論文是靠 PISA 把模型放進 switch 的」→ 三個元件 parser、match/action、deparser 各做什麼、都可以寫程式（P4）→ 表上四列 → 沒列的不能做（乘除、float、loop）→ 這些怎麼影響後面的設計：模型選 tree（比 neural network 更像 match/action）、variance 只能靠 shift 算，所以 inference point 要放在 2 的次方。

### p3　Comparison with prior art in IDP
- 表：依 Table 1（PDF p.4）重畫，三列 prior work＋NetBeacon，三欄 Line-Speed／Learning-Based／Flow-Aware，用 template 的 yes／no：
  - NetWarden、FlowLens：✗ ✓ ✓
  - Poseidon、Jaqen：✓ ✗ ✓（**沒有星號、沒有表下腳註**）
  - Planter、Mousika：✓ ✓ ✗
  - NetBeacon：✓ ✓ ✓
- 表下小字：「Table 1 重畫」。
- 表下三行（2026-11-12 改）：「NetBeacon 要比 Planter、Mousika 更進一步的兩件事」—— (1) Model deployment efficiency：表示模型用更少的 table entry；(2) Model accuracy：加入 stateful flow-level features。（各縮成一行，避免換行只剩一個字。）標籤出自 §1（p.3：advances state-of-the-art in both model accuracy and model deployment efficiency；(ii) reduces the table entry consumption），內容出自 §2.2（p.4：two major limitations）。原本寫「Planter、Mousika 的兩個限制」，使用者覺得把效率和準確度並稱「兩個限制」奇怪，所以改。
- 當場講（2026-11-12 改）：先講三個欄位的意思 → 六個 prior work 兩個一類、每類缺一欄 → NetBeacon 三個都要 → 三類都有限制，下方兩行只寫 Planter、Mousika 是因為同一條路線（報告人的解讀），兩個限制裡第一個不在表的欄位裡、第二個就是 Flow-Aware 的叉。Poseidon、Jaqen 的但書「部分 policy 要 control plane 參與，那時不是 line-speed」用一句話講出來（投影片沒有）。

### p4　Flow-level features 的必要性
- 圖：`fig02_flow_features.png`，**只有 Fig. 2 的下半**（三張 accuracy 長條圖＋圖例；上半的 feature importance 拿掉），圖說「Fig. 2（下半）」。
- 一行重點：同樣數量的 feature，加入 flow-level features 後 accuracy **+11%（P2P）、+43%（covert channel）、+21%（DDoS）**。
- 當場講：per-packet feature 是單一 packet header 看得到的（size、TTL、protocol）；flow-level feature 是同一條 flow 前 n 個 packet 的統計（packet size 的 mean、variance、IPD 的 min）。圖只描述下半：三個任務各兩根柱子，紫色斜線是只用 per-packet features、綠色交叉是 per-packet 加 flow-level features，feature 數量相同。feature importance 的內容（上半）只留在講稿補充備查。

### p5　The architecture of NetBeacon
- 圖：`fig03_architecture.png`（Fig. 3，PDF p.5）。
- 三行（論文 §1 的 (i)(ii)(iii)，PDF p.3；編號用 (i)(ii)(iii)，對應後面三頁）：
  - (i) data plane aware model design：multi-phase sequential model
  - (ii) efficient model representation（range marking）
  - (iii) stateful storage management

### p6　(i) Multi-phase sequential model
- 圖：`fig05_single_vs_multi.png`（Fig. 5，PDF p.6）。
- bullet：
  - 在 flow 的第 n 個 packet（inference point）各用一個模型推論
  - 其他 packet 沿用最近一次的結果
  - 機率 ≥ determination threshold → 提前判定這條 flow
- 當場講：flow-level feature 會隨 flow 進行而變（Fig. 4），只用單一模型會太早下結論。三個任務 multi-phase 都比較高；P2P 和 covert channel 差很多，DDoS 的縱軸從 96 開始，差距看起來比實際大。inference point 的位置依任務而定，例如 P2P 是第 2、4、8、32、256、512、2048 個 packet；用到 variance 時要放在 2 的次方（硬體只能 shift）。模型是 Random Forest 或 XGBoost。

### p7　(ii) Model representation：range marking
- 圖：`fig06_range_marking.png`（Fig. 6，PDF p.7）；圖很寬，佔滿頁寬。
- 一行重點：leaf 5 用 ternary matching 要 **48** 個 entry → NetBeacon 每個 leaf **在 model table** 只要 **1** 個。
- 當場講：programmable switch 不一定支援 range matching，要拆成 ternary；多個 feature 的範圍相乘就爆炸。NetBeacon 每個 feature 一張 feature table，把數值範圍轉成一個 bit string（range mark），model table 再用 range mark 的組合對到 leaf。細節不展開。

### p8　(iii) Stateful storage management
- 圖：自己畫的流程（fletcher），**沒有獨立的「算 index」節點**：
  `new flow` → `long-short 分類（per-packet features）` → `short`：`不存 state，只用 per-packet features 分類`；`long`：`H(5-tuple) % N 對到的 register 空的，或舊 flow 已判定／逾時？` → 是：`佔用 register，算 flow-level features`；否：`退回 per-packet features`
- 投影片沒有 bullet（原本的「80th percentile 當分界」「collision 時不搶還在分析中的 flow」已拿掉，改在當場講）。
- 當場講：register 數量有限（實驗用 65,536 個）。每個 packet 一進來都先算 index ＝ H(5-tuple) % N，用它找到 register、比對裡面存的 flow ID，才知道是不是已經有 state 的 flow；新 flow 才走圖上的路徑。long-short 模型只看單一 packet 的 per-packet features，long／short 用訓練集 flow 長度的 80th percentile 分，訓練時取每條 flow 的前 7 個 packet 當樣本、P2P accuracy 82%。short：不存 state。long：才看 register 能不能佔用（空的，或舊 flow 已判定／逾時），不能就退回 per-packet features，不搶還在分析中的 flow。Fig. 10 顯示只對超過 8 或 16 個 packet 的 flow 用 flow-level features，整體 accuracy 和全部都用很接近。
- 講稿補充要說明：這張圖把順序簡化了（index 其實每個 packet 都先算，依 Alg. 1 第 1–2 行）。

### p9　Integrated data plane processing logic（Alg. 1）
- 圖：自己畫的流程（fletcher），依 Alg. 1（PDF p.10）：
  `packet` → `flow class table 命中？` → 是：`直接用存的 class`（標「不再推論」）；否：`有 per-flow state？` → 有：`更新 state；inference point 才推論` → `機率 ≥ threshold？` → 是：`標記已判定，通知 control plane 寫入 flow class table`；沒有 state：`per-packet features 推論`
- bullet（兩條）：
  - entry 依 FIFO 或 LRU 移除
  - register 在 flow 判定後就能讓給新 flow
- 當場講：這是整個系統省資源的關鍵：flow class table 的 key 是 5-tuple，命中就直接拿存的 class；判定後由 control plane 寫入（「key 是 5-tuple；由 control plane 寫入」原本的 bullet 已拿掉，這兩點在當場講）。一條 flow 一旦判定，之後所有 packet 只查一張表。control plane 只負責寫表，不在 packet 的 critical path 上；還沒寫進去之前 packet 照樣走推論流程。這一頁的機制在 p15 會再回來討論它的風險。

### p10　Alg. 1 的例子：一條 long flow（P2P 任務）
- 表（報告人依 Alg. 1，PDF p.10 整理）：兩欄「packet／switch 做什麼」，五列：
  - 第 1 個：per-packet model 分類；判成 long 且 register 可用 → 佔用 register（Alg. 1 第 20–30 行）
  - 第 2 個（inference point）：更新 register → 算 flow-level features → 查 feature table、model table → class 寫回 register（第 9–13、17 行）
  - 第 3 個：更新 register，用 register 裡存的 class（第 10、18–19 行）
  - 第 4、8、32 … 個（inference point）：同第 2 個，換成該 phase 的 model；機率 ≥ threshold，或到第 2048 個 → 標記已判定，通知 control plane（第 14–16 行；最後一個 inference point 的判定見 PDF p.9 §5.2）
  - 寫入 flow class table 之後：5-tuple 命中 → 直接用存的 class，不再推論（第 4–5 行）
- 表下小字：「依 Alg. 1 整理」。
- 當場講：把 p5–p9 串成一條 flow 的時間順序；改 register 要 mirror packet（新 flow 初始化、inference point 寫回 class 兩種情況；比例在 p13）；沒拿到 register 的 packet 只用 per-packet model，下一個 packet 會再判斷一次（報告人從 Alg. 1 推得）。
- P2P 的 inference point {2, 4, 8, 32, 256, 512, 2048}：PDF p.12 §7.2。

### p11　Experiment setup
- 表（依 Table 4，PDF p.12）：三個任務 × **任務／Dataset／Model／Testing flows**（沒有 Inference points 欄）
  - P2P application fingerprinting：PeerRush（eMule、uTorrent、Vuze）／Random Forest／246,278
  - Covert channel detection：FacetTraffic（＋Univ2 背景）／XGBoost／400
  - DDoS attack detection：8 種 DDoS＋MAWI 背景／XGBoost／191,009
- 表下小字：「Table 4 整理」。
- 一行：Tofino 1；tcpreplay 重播 pcap；指標是 per-packet macro-accuracy。
- 當場講：三個任務各有 7、9、4 個 inference point（只講數量；位置 {2, 4, 8, 32, 256, 512, 2048}、{512, …, 10000}、{2, 5, 8, 16} 留在講稿補充）。baseline 是 Mousika（只用 per-packet features 的 binary decision tree）；另外有 NetBeacon 只用 per-packet 的版本、沒有 storage 管理的版本、以及用 Python 模擬的 Ideal（每條 flow 都有 storage）。network load 用每秒新 flow 數的中位數表示。

### p12　End-to-end system performance
- 圖：`fig13_end_to_end.png`（Fig. 13，PDF p.12；含圖例）。
- bullet（論文 §7 開頭的 (i)，PDF p.11；數字是 Fig. 13 caption）：
  - accuracy 比 Mousika 高 **14%（P2P）、38%（covert channel）、20%（DDoS）**
  - 和 stateful storage 不受限的 Ideal 相當
- 當場講：三張子圖橫軸是 network load（normal、medium、high），縱軸是 macro-accuracy。三個任務完整版都和 Ideal 很接近；P2P 這個任務，論文說這表示 storage 管理有效；covert channel 和 DDoS，有沒有 storage 管理差不多，論文自己說效益不明顯（p.13）。P2P 在 high load 只有 0.85% 的 flow 退回 per-packet features。資源：P2P 用 12 個 stage、SRAM 17.29%、TCAM 31.25%。

### p13　Model representation performance
- 圖：`fig14_table_entries.png`，**只有 Fig. 14 的 (a)–(c)**（P2P、covert channel、DDoS；(d) Traffic Type Classification 拿掉），圖說「Fig. 14 (a)–(c)」。
- bullet：
  - 同樣的 table entry 數，accuracy 比較高
  - 表現相近的模型，table entry 少很多（covert channel 少 **75%**）
  - （論文 §7 開頭的 (ii)、§7.3 的兩點結論，PDF p.14；throughput 屬於 §7.4，移到 p14）
- 當場講：三張子圖是三個任務，橫軸是 table entry 數、縱軸是 accuracy，同樣的 entry 數 NetBeacon 比較準；entry 少是 range marking 和 range coding 的效果。throughput 三個任務是 99.12、99.13、99.18 Gbps；需要 mirror 到 loopback port 更新 register 的 packet 只佔 3.8%、0.09%、1.28%。不再提圖上有第四張；ISCXVPN 的 traffic type classification 只在講稿補充備查。

### p14　NetBeacon deep dive
- 圖：`fig15bc_threshold_indexsize.png`（Fig. 15 的 (b) 和 (c) 兩張子圖，PDF p.14；(a)(d) 不放），圖說「Fig. 15 (b)(c)」。
- bullet：
  - Throughput：**99.12–99.18 Gbps**（100 Gb port）
  - Determination thresholds（左）：register 少 → 低 threshold 較好；register 多 → 高 threshold 較好
  - Size of stateful storage（右）：storage 越大 accuracy 越高；storage 有限時 storage management 有幫助
  - （小標用論文 §7.4 的段落名稱，PDF p.14；圖高 6.6cm）
- 當場講：threshold 是「準確」和「資源」之間的旋鈕；作者的結論是要依可用的硬體資源決定。(c) 顯示 register 越多 accuracy 越高，有 storage 管理的版本在 register 少的時候差距最明顯。

### p15　Discussion：security analysis
- 表（三欄：名稱／攻擊／作者提的緩解）：
  - Stealth attack：先送 benign packet，等 flow 被判定後才送 malicious packet ／ flow class table 的 entry 加 maximum flow length limit
  - Low-rate-long-flow attack：把 packet 間隔拉長，逼 flow 逾時 ／ 每條 flow 用自己的 timeout（例如最大 IPD 的兩倍）
- 一行（標明是報告人的話）：「報告人的觀察：兩種攻擊與緩解都只有文字討論，沒有實驗」。
- 小字一行：「Table 5　FPR／FNR：covert channel 8.8%／10.9%　DDoS 0.7%／0.05%」（**沒有 P2P、沒有寫 per-packet**）。
- 當場講：stealth attack 正好打在 p9 的機制上：判定之後不再看。作者認為攻擊者要先探測參數、有門檻。因為硬體限制，模型和 feature 都受限，論文說這可能影響複雜任務的 accuracy。Table 5 論文沒標明是 per-packet 還是 flow-level，從上下文看應該是 per-packet 的數字。P2P 的三個數字（7.6%／12%／14.7%）只留在講稿補充備查。

### p16　Conclusion 與討論
- 兩欄：
  - **論文的結論**（§10，PDF p.15）：model accuracy 與 model representation efficiency 都超過 prior art，靠三個設計：(i) multi-phase sequential model、(ii) efficient model representation、(iii) stateful storage management
  - **討論（報告人的問題）**：
    1. 判定後不再檢查 → 中途變惡意的 flow 會漏多少？（沒有量）
    2. maximum flow length limit 設多少？到期後是重新分析還是直接放行？
    3. determination threshold 要依硬體資源決定，能不能依負載動態調整？（投影片沒有括號說明；論文每個 phase 各有一個 threshold，Appendix C 說可以不停機更新，但只比較了 0.7 和 0.8 兩個值，沒有做動態調整，這些放講稿補充）
    4. flow class table 的大小與 FIFO／LRU 對 accuracy 的影響沒有評估
- 當場講：這四點是報告人讀完的看法，不是論文的內容，要講清楚。貢獻第 3 點補一句：論文用的詞是 potentially，超過 register 數的 flow 是退回 per-packet features，不是每條都有 flow-level features。

### Q&A（不編號）

---

## 4. 講稿（`逐字稿.md`）的格式

- 開頭：報告日期、對應的 PDF 檔名與頁數、使用方式。
- **一、當場講**：封面到 Q&A，每頁只放要講的話，可以連著讀。口語、短句。
- **二、補充**：頁碼對應，放：圖表怎麼讀（軸、圖例、縮寫的定義）、名詞解釋（PISA、ternary matching、IPD、macro-accuracy、digest、resubmit）、被問到時怎麼回答、容易講錯的地方（見 §1「要小心的地方」）。不用 `>` 混排。
- 不寫改動紀錄。
- 補充裡每個數字標論文出處（PDF 頁碼＋章節或圖表編號）。

## 5. 審稿與驗證後的調整（2026-11-10；這一節的頁碼是當時的編號）

- **驗證報告 17 條已套用**：`驗證報告.md`「要改的」中 4 條、低 13 條，講稿的「一、當場講」與「二、補充」都已改成最終說法；投影片上對應的部分（p8 的「在 model table」、p9 的流程圖、p15 的 Table 5 小字）已先改好，本檔 §3 與 `src/main.typ` 一致。
- **依兩個角度（指導教授、不熟 P4 的同學）的審稿，從投影片拿掉的項目**（這些資訊改在講稿「當場講」用一句話講出來，或留在「補充」備查）：
  - 所有圖說只剩「Fig. N」「Table N 重畫／整理」，不再放「（Zhou et al., USENIX Security 2023）」。
  - p2：拿掉 bullet「IDP ＝ 把 ML 模型直接放進 switch 的 data plane」。
  - p4：拿掉表下腳註「* 部分 policy 要 control plane 參與，那時不是 line-speed」和 Poseidon／Jaqen 那格的星號。
  - p5：圖只剩 Fig. 2 的下半（三張 accuracy 長條圖＋圖例），上半的 feature importance 拿掉。
  - p9：拿掉兩條 bullet（80th percentile 當分界；collision 時不搶還在分析中的 flow）。
  - p10：拿掉 bullet「key 是 5-tuple；由 control plane 寫入」。
  - p11：表拿掉「Inference points」欄，各任務 inference point 的位置留在講稿補充。
  - p13：圖只剩 Fig. 14 的 (a)–(c)，(d) Traffic Type Classification 拿掉。
  - p15：Table 5 小字只留 covert channel 與 DDoS，不寫 per-packet；P2P 的三個數字只留在講稿補充。
- **大綱頁與 Q&A 頁**：兩位審稿都認為可以拿掉，保留，因為是每次報告固定的結構頁。
- 改動紀錄只寫在本檔，不寫進 `逐字稿.md`。

## 6. 重排與講稿加深（2026-11-11）

- **使用者要求**：章節改成 Introduction、Motivation、Design、Evaluation、Conclusion；不放大綱頁；group meeting 要講得比較詳細，講稿要補到不會被問倒。
- **投影片**：
  - 拿掉大綱頁；加 5 張章節頁（不編號）。
  - 頁碼對應：原 p2–p10 → 現 p1–p9；新增 p10（一條 long flow 的處理過程）；p11–p16 不變。
  - 標題改兩個：「Background：Intelligent Data Plane」→「Intelligent Data Plane（IDP）」、「Evaluation：設定」→「實驗設定」（章節頁已經標出所在章節）。
  - 「限制與 security analysis」放在 Conclusion 底下（論文是 §8 Discussion）。
  - 其他頁的內容沒有改。
- **講稿「一、當場講」加深的地方**：
  - p1：data plane／control plane 的定義；NetBeacon 的推論全部在 data plane。
  - p2：match/action、ternary 的意思。
  - p5：Fig. 3 上下兩層、下層再分兩排、橘色箭頭的意思；七個步驟；三個設計不是三個模型；control plane 只做兩件事。
  - p6：每個 inference point 各訓練一個模型、訓練資料怎麼算；模型數量與大小（Appendix D）；所有 phase 共用同一組 table（§6.2）。
  - p7：range mark 的每個 bit 怎麼來、model table 怎麼用 \* 表示跨段的範圍。
  - p8：register 裡存什麼；每個 packet 都算 index；退回 per-packet features 的兩種 flow。
  - p9：判定的兩種情況；命中只看 5-tuple、不看內容；沒有判定後再檢查的機制。
  - p10：新頁的逐列說明。
  - p11：實機 Tofino 1、不是模擬；三個任務的流量來源；Ideal 是唯一的模擬。
  - p15：評估的流量裡沒有先 benign 後 malicious 的 flow；maximum flow length limit 沒有數值。
- **講稿「二、補充」**：重新編頁，拿掉大綱頁那一節，新增 p10；p1、p5–p9、p11 各補了出處與「論文沒有／報告人的理解」的標示。
- 這一輪沒有再做第 5 步的審稿（使用者要的是加深，不是刪減）；新寫的內容另外做了一次對照論文的驗證（Opus subagent，170 個說法，21 條要改，已全部套用），結果見 `驗證報告.md` 的第二部分。

## 7. 照論文的說法改寫（2026-11-11）

- **使用者要求**：「照論文說的寫，整份都一樣」——標題和 bullet 用論文自己的章節名稱與說法，不用報告人自己取的「結果 1／2／3」「設計 1／2／3」。
- **標題**：改成論文的章節名稱或圖表 caption：Programmable Data Plane（§2.1）、Comparison with prior art in IDP（Table 1 caption）、The architecture of NetBeacon（Fig. 3 caption）、(i)(ii)(iii) 三個設計（§1）、Integrated data plane processing logic（§5.3）、Experiment setup（§7.1）、End-to-end system performance（§7.2）、Model representation performance（§7.3）、NetBeacon deep dive（§7.4）、Discussion：security analysis（§8）、Conclusion（§10）。
- **Evaluation 三頁**：對應論文 §7 開頭說要證明的三件事 (i)(ii)(iii)；論文沒有用 research question 這個詞，所以不寫成 RQ。throughput 從 p13 移到 p14（論文在 §7.4）。
- **p3、p5、p12–p14、p16 的 bullet**：改成論文的說法（出處見各頁規格）。
- **不是論文的話、留在投影片上的只有兩處**，都有標示：p15 的「報告人的觀察」、p16 右欄的「討論（報告人的問題）」。p1、p8、p9 的圖和 p10 的表是報告人依論文畫／整理的，圖下有標。
- p16 的標題是「Conclusion 與討論」，避免和章節頁「Conclusion」同名。
- 講稿的頁標題、各頁開場、throughput 與 mirror 的位置已同步；這一輪改的是用詞和位置，沒有新增事實，新引用的原文（§7 開頭三件事、§2.2 two major limitations、§10 結論、§7.4 小標）是主 agent 直接對 PDF 文字查的。

## 8. 第 1、2、7 頁講稿調整與 source code 查證（2026-11-12）

- **使用者要求**：p1 講稿直述、只講原因和作者的想法；IDP 不要講成論文定義的名詞；模型用「訓練出來的／訓練好的」，不用「學出來的」；模型轉成 table 這一步先看 source code 再補。
- **p1**：模型通常放在 end-host 或 network control plane → 兩個問題（10 Gbps、reaction time）→ 作者的想法是放進 data plane。IDP 的說法改成「這個方向叫 Intelligent Data Plane，論文裡簡稱 IDP，也有人叫 in-network machine learning」：論文原文是「referred to as」，沒有宣稱自己命名；Taurus 的 arXiv 第一版（2020-02）標題就是 *Taurus: An Intelligent Data Plane*。這一點使用者指定不加進補充。第一句是使用者自己改的（「目前訓練出來的模型」）。
- **p2**：一度在開頭加了 ASIC → SDN → PISA（p.3 §2.1），使用者指出 p1 已經講了要把模型放進 data plane，p2 應該直接講放進 switch 的重點，所以拿掉，只留在補充。開頭改成「要把模型放進 switch，先要知道 switch 能做什麼、不能做什麼」。論文沒有把 SDN 和「ML 在 control plane」連在一起。
- **p7**：開頭加一句「轉換是離線做的，switch 上沒有模型，只有查表」。出處是作者公開的 source code（github.com/IDP-code/NetBeacon，2023-03-07 的版本，只讀沒有執行）：`model_generation/model_representation.py` 把模型檔轉成 entry 存成 `.pkl`，`switch/control_plane/controller.py` 啟動時裝進 switch。細節在講稿第 7、9 頁的補充，都標明出處是 source code。
- **p3**：只改講稿（先定義欄位、各缺一欄、說明下方兩行為什麼只寫 Planter、Mousika），投影片沒動。結尾明講「這兩點就是這篇論文的動機」，並交代證據位置（第二點在 p4，第一點在 p13）。
- **p3 投影片**：表下三行從「兩個限制」改成「更進一步的兩件事」（efficiency／accuracy），講稿同步。
- **p11**：講稿介紹 baseline 的地方補上 Mousika 和 NetBeacon 的關係（同一類做法、都用 tree；模型不同：BDT 對 RF／XGB；baseline 是作者重做的版本），投影片沒動。「所以和它比」是報告人的推論。
- **p4**：講稿開頭改成「論文做了一個實驗，說明加入 flow-level features 之後分類的 accuracy 會變高」，看圖之前先用三句講實驗怎麼做（三個任務各訓練兩個 decision tree、feature 數量一樣）；在講代價之前加一句論文的 Design Goals（p.4 §2.2）。投影片沒動。
- 投影片（`src/main.typ`）這一輪只改了 p2 的表和 p3 表下三行，其他頁沒有動；兩處的內容分別出自 §2.1 和 §1、§2.2，主 agent 直接對過原文，沒有另跑驗證 subagent。
