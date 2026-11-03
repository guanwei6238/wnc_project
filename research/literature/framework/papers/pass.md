# PASS

## A. 書目與取得狀況

- 標題：PASS: A Flexible Programmable Framework for Building Integrated Security Stack in Public Cloud
- 作者：Wenwen Fu, Jinli Yan, Jian Zhang, Yinhan Sun, Yong Wang, Ziwen Zhang, Qianming Yang, Yongwen Wang（國防科技大學 NUDT 計算機學院與北京國防科技創新研究院）[原文 p.1]
- 年份／出處：2025（2025-06-30 刊出；2025-05-12 投稿、06-09 接受），MDPI *Electronics* 14(13), 2650 [原文 p.1]
- DOI：10.3390/electronics14132650（Crossref 與 OpenAlex 皆查到，CC BY 4.0）
- URL：https://www.mdpi.com/2079-9292/14/13/2650
- 經費：National Key Laboratory 2023-KIWPDL-14 [原文 p.24]
- **與給定資訊的差異：無。** 標題、年份、期刊、DOI 全部吻合。僅 PDF 的 Citation 欄漏了 "Flexible" 一字（PDF 內嵌 metadata 的標題有），無實質影響。
- **取得程度：全文。** 開放存取 PDF（26 頁）。mdpi.com 直接用 curl 下載回 403（擋機器人）；我另一次嘗試被權限系統判為繞過擋機器人而拒絕，**沒有再試**。改用 WebFetch 取得 MDPI 自己的開放 CDN（mdpi-res.com）上的同一份 PDF，存到 `pdfs/pass/pass.pdf`（`pass.txt` 為 pdftotext 輸出）。Fig. 11–15 的數值我另外轉成圖片目視讀取，凡是從圖上讀的數字都標「圖讀」。

## B. 核心貢獻

1. 針對 SmartNIC（CPU+FPGA）上的安全功能，提出三平面架構（Security Controller／PASS Agent「security auxiliary plane」／data plane），把 policy 翻譯與規則分發從 controller 下放到裝置端 agent [原文 p.3, p.9–10]。
2. 資料平面把安全功能拆成 hSF（FPGA）與 sSF（CPU process），共用的 parse／classify 抽成 pre-process，並用 per-packet metadata（fid、path、action＋自訂欄位）傳遞中間結果、縮短 function chain [原文 p.11–12]。
3. 提供開發者 API（三個 callback）與自訂 southbound protocol，用 LoC 與效能數據宣稱降低開發成本 [原文 p.13–16, Table 3/4/5]。

## C. 指定的 9 項

1. **Research Problem**：公有雲多租戶需要在單一裝置整合多種安全功能；純軟體在 L4+ 有效能上限，客製硬體缺彈性，CPU/FPGA SmartNIC 則開發成本高、功能間協作有冗餘 [原文 p.2–3]。
2. **Architecture**：
   ```
   Security Controller (Java) --PASS protocol(抽象 policy)--> PASS Agent (C, 裝置 CPU)
        ^ 統計/告警                          | rule cache、GRT(fid)、SF start/stop、統計壓縮
        |                                    v
   pkt in -> [pre-process hSF: parse+classify, 寫 metadata] -> hSF1 -> hSF2 ... -> pkt out
                                  | action=To_CPU
                                  v  (PCIe/DMA)
                              sSF (OS process, payload 比對) <-> vSwitch <-> 其他 sSF
   ```
   Path 1＝header 類功能（PFW、SFW）全在 FPGA；Path 2＝header 在 FPGA，payload 比對（IDS）在 CPU [原文 p.11]。
3. **Processing Location**：資料平面在 FPGA（hSF）＋CPU user-space process（sSF，跑在 FAST OS）；agent 在裝置 CPU；controller 在外部 [原文 p.9, p.11]。
4. **Hardware**：Xilinx Artix-7 FPGA 經 PCIe 接 ARM Cortex-A9（866 MHz，單核雙 hardware thread，一條給 OS、一條給 sSF），1 GE 光纖；測 SFW 用 COTS server（型號未說明）；controller 主機規格論文未說明 [原文 p.17]。
5. **Dataset**：無資料集。流量由 FAST-ANT network emulator（約 10 µs jitter）或 iperf／Apache server 合成；控制面實驗取 Snort rule library 的 1,800 條規則分五類（版本未說明）[原文 p.17, p.21]。非 IoT-23／CICIoT2023／真實流量。
6. **Baseline**：作者自寫的 software-only 版本（同板同資料）、HW／SW direct forwarding（扣除 I/O）、控制面三種方案 S1／S2／S3、開發量的 "Strawman"（基於 FAST API 不重用模組）[原文 p.16, p.18, p.21]。VFP／OpenBox／ClickNP 只在 Table 2 做定性比較，**沒有重跑**。
7. **Metrics**：throughput（Mb/s）、latency（µs，RTT 扣 tester loopback）、TCP handshake 時間 CDF、每秒最大連線數、LoC、FPGA LUT／BRAM、policy 分發 latency（ms）與資料量（KB）[原文 p.16–21]。
8. **Limitations（作者承認）**：自訂 protocol 與 metadata 讓 PASS 無法與 OpenFlow 系框架相容，兩平面軟體都要換；controller 擴充性（多 controller）未做；對抗情境下的 trust model 留待未來；動態情境下的瓶頸分析留待未來 [原文 p.22]。
9. **Research Gap**：
   - 作者自述：多 controller／agent 通訊、tenant 信任模型、動態更新瓶頸、零拷貝等 I/O 優化整合 [原文 p.22–23]。
   - [推測]：從未量「PASS 抽象相對手寫 FPGA 版本」的效能 overhead；動機要 100G/400G [原文 p.4]，實測僅 1 GE；無 CPU／RAM／功耗；無重配置與 controller 斷線行為。

## D5. 實驗可信度

- 流量：合成（emulator、iperf、ab），1 GE，封包 256／512／1024／1500 B。
- 重複與變異：僅兩處有明確次數（handshake CDF 用 1000 條連線；最大連線數「每個 use case 做 100 次」）[原文 p.19]。throughput 長條圖無次數、無誤差線；latency 圖（Fig. 11b／13b／14b）有誤差線，但**未說明次數與誤差線代表什麼**（圖讀）。全文無信賴區間、無 warm-up 說明。
- Ablation：控制面 S1／S2／S3 是真正的分項比較；資料平面把「路徑壓縮」與「中間結果重用」的貢獻分開量的實驗沒有，論文只在 Summary 歸因 [原文 p.20]。
- 程式與資料：**未公開**（Data Availability 寫因隱私不公開，須聯絡通訊作者）[原文 p.24]。底層 FAST、FAST-ANT 有開源，PASS 本身沒有。
- 摘要數字是範圍的最大值：摘要「76%」對應 §5.3 的 SFW→IDS 吞吐 26–77%（p.20；引言寫 up to 76%，兩處差 1 個百分點）；摘要「90%」是 Table 7 中 S3 對 S1 的最大降幅（1 − 97/1422 ≈ 93%，[推測] 自行由 Table 7 計算），平均為 82%（作者 p.22 的數字）。
- 各功能「improvement」是扣掉 direct forwarding 後的差，公式論文未給 [原文 p.18]。從 Fig. 12a 圖讀，MSS 256 時 HW SFW 約 700 Mb/s、SW SFW 約 90 Mb/s，未扣 I/O 的原始差距遠大於 20.5–28%。

## D6. 移植到 Pi 4 的障礙

- 依賴 FPGA SmartNIC、PCIe、FAST 平台、Verilog、Java controller、自訂 protocol：**Pi 4 上無法直接跑** [推測，無 FPGA／SmartNIC 為事實；是否完全不能跑未驗證]。
- agent（C、800 LoC）本身輕量，但沒有 hSF 就沒有意義 [推測]。
- 論文不使用 XDP／eBPF，XDP 相關檢查不適用。
- 值得注意：論文的 software-only baseline 跑在 866 MHz 單核 A9 上，屬低資源環境，但 IDS 吞吐僅約 65–115 Mb/s（圖讀 Fig. 13a），且 IDS 是「simplified Snort」（只做 exact／regex match）[原文 p.14, p.16]，不能當真實 Snort／Suricata 的成本。

## D9. 引用網路

OpenAlex／Crossref 的 cited-by 只有 3 篇（SmartNIC 上的 ML IDS、10 Gbit/s FPGA DDoS 防護、一篇不相關的推薦系統），**沒有後續框架論文**，不值得追。PASS 的參考文獻全是 FPGA／SDN 系，沒有 eBPF 框架。建議追加閱讀（內容皆尚未讀全文，理由來自 PASS 的描述與搜尋摘要 [二手]）：

1. Bremler-Barr, Harchol, Hay. *OpenBox*, SIGCOMM 2016。被 PASS 比較的基準（Table 2），NF 抽象與共用元件，值得看它怎麼評估重用。DOI 10.1145/2934872.2934875（Crossref 已確認）。
2. Jamshed et al. *mOS*, NSDI 2017。PASS 引用的開發效率框架；USENIX 頁面摘要稱以 LoC 衡量開發量並量 overhead，正是我們要的評估方式。無 DOI，USENIX 頁面已確認。
3. Li et al. *Rubik*, NSDI 2021。PASS 的 [5]；摘要稱 TCP/IP stack 約 250 行、吞吐勝手寫 ≥30%，同時給 LoC 與 overhead 兩種證據。USENIX 頁面已確認；ToN 擴充版 DOI 10.1109/TNET.2023.3307641（Crossref 已確認）。
4. Zhao et al. *Pigasus*（Achieving 100Gbps Intrusion Prevention on a Single Server），OSDI 2020。與 PASS IDS 同構的「FPGA 先過濾、少量送 CPU 做完整比對」，同題。USENIX 頁面已確認，開源。
5. Li et al. *ClickNP*, SIGCOMM 2016。被 PASS 比較的基準，框架 vs 手寫 FPGA 的 overhead 量法。DOI 10.1145/2934872.2934897（Crossref 已確認）。

## G. 框架專屬欄位

**G1 框架的抽象**：框架定義三平面、per-packet metadata（generic：fid／path／action；其餘為 user-defined）、southbound protocol（general head＋六種 sub-protocol，規則內容為 JSON key→value）[原文 p.11, p.14–15, Fig. 4/9, Table 4]，以及 SF 的三階段模型（rule parsing／packet processing／statistics reporting）。開發者只寫三個 callback：`rule_mgt_callback`、`pkt_handler_callback`、`log_mgt_callback`，用 `pass_reg_*_handler()` 註冊；平台負責配置 CPU 與建 thread。API 共 9 個（Table 3），含 `pass_regex_match()`／`pass_exact_match()`；hSF 端使用者只寫 hardware rule table 與狀態機，Stride BV 查表以 IP block 提供 [原文 p.13–14]。規則內容、metadata 自訂欄位、fid 配置演算法留給使用者。

**G2 擴充與生命週期**：sSF 為 OS process，hSF 為 FPGA module；Table 4 的 Function Control 訊息動態啟停功能，Function Reconfiguration 訊息把軟體與硬體 executable 載入 CPU／FPGA [原文 p.15]。串接靠 metadata 的 path 欄位與每個 hSF 內的 path selector，不需要的功能直接略過 [原文 p.12]。規則更新用 entry 狀態旗標（=1 才有效），新規則生效前舊規則照常運作 [原文 p.22]。**沒有任何重配置時間、中斷時間或封包處理行為的量測**；FPGA bitstream 載入細節論文未說明。

**G3 分層**：controller 只送抽象 policy；agent 預取並快取整份規則，配 fid，只把 fid 下發給 SF，並壓縮統計後上報；資料面以 PCIe/DMA 在 hSF 與 sSF 間傳封包＋metadata，sSF 間經 vSwitch [原文 p.9–10]。狀態放在 agent 的 global rule table 與 hSF 的 flow table；metadata 在封包離開裝置時移除 [原文 p.11]。PASS protocol 的傳輸層論文未說明。

**G4 外部依賴可選性**：資料平面不必把封包送 controller [原文 p.21]，agent 有規則快取，所以資料面對 controller 低依賴。但 controller 斷線時的行為（fail-open／closed）、快取過期、預取成本，論文**未說明也未驗證**。

**G5 框架價值怎麼證明**（照論文實際做的）：

| 面向 | 指標 | 比較對象 | 結果 | 出處 |
|---|---|---|---|---|
| 開發成本 | 硬體＋軟體 LoC | 作者自寫 Strawman（FAST API、無模組重用） | PFW −77.7%、SFW −56.9%、IDS −60.7%，平均 65% | p.16 Table 5 |
| 資料面加速（單一功能） | throughput、latency、handshake、連線數 | 同板 software-only，扣除 direct forwarding | PFW +13–38%；SFW +20.5–28%；IDS 吞吐 +7–20%、latency −3–18% | p.18–19 |
| 資料面加速（chain） | 同上 | software-only chain | PFW→IDS 吞吐 +14–50%、latency −8–26%；SFW→IDS 吞吐 +26–77% | p.20 |
| 控制面 | 分發 latency、資料量 | S1（controller 翻譯）、S2（送 ID） | S3 恆 97 ms／0.4 KB；平均 −82%（對 S1）、−65%（對 S2） | p.21–22 Table 7 |
| 整合的功能數 | 實作幾種 | — | 3 種（PFW、SFW、IDS）、2 條 chain | p.16, p.20 |
| 資源 | LUT／BRAM | — | 共 25,544 LUT、81.5 BRAM；function-specific 占 21% LUT | p.17 Table 6 |
| 與其他框架 | 7 項功能勾選 | VFP、OpenBox、ClickNP | 定性表，無數據 | p.7 Table 2 |

**沒有做的**：框架 overhead 相對手寫版本（Strawman 只量 LoC，效能完全沒量）、開發時間、使用者研究、第三方開發者、可維護性、多租戶隔離實驗、CPU／RAM／功耗、重配置時間、與 VFP／OpenBox／ClickNP 的數值比較、真實 Snort。唯一接近 overhead 的證據：HW PFW 與 HW Direct FWD 的 latency 相同、無 jitter [原文 p.18]。

我的觀察 [推測]：(a) 摘要的「from scratch」其實是 Strawman，已經站在 FAST 之上，且 PASS 自己提供的 IP block 與比對函式計入了節省；(b) LoC 表未計入 PASS agent（800 行 C）、controller（2000 行 Java）與 PASS library 本身的行數；(c) Strawman 由同一批作者撰寫；(d) Table 6 的百分比是各類占「已用」資源的比例（27+52+21=100），不是占晶片容量；(e) 「把共用邏輯抽進 platform-basic 可降低開發量」的論述 [原文 p.16] 的證據是 FAST OS 的 LUT 占比，而 FAST OS 是第三方，並非 PASS 抽出的共用邏輯。

**G6 效能量測方法**（可重做程度：不足）：
- Testbed 1（PFW／IDS／PFW-IDS）：PASS prototype 與 FAST-ANT emulator 各一塊 Artix-7+A9 板，1 GE 光纖直連；emulator 產生使用者定義流量並量 RTT；發送間隔設 1 ms 以量「non-blocking latency」，被 socket queue 擋住的排隊延遲算進 I/O overhead；總 latency 扣掉 tester 的 loopback latency [原文 p.17–18]。
- 基準：另量 HW direct forwarding 與 SW direct forwarding，improvement＝（HW 處理 − SW 處理）扣掉 direct forwarding 的差 [原文 p.18]。
- Testbed 2（SFW／SFW-IDS）：兩台 COTS server 當 client／server；iperf 開 8 條 TCP 連線、掃 MSS；handshake CDF 取 1000 條連線；最大連線數為每秒送 20,000 個 TCP 請求、重複 100 次 [原文 p.17, p.19]。
- 封包大小 256／512／1024／1500 B，只有 1 GE。
- 控制面：1,800 條 Snort 規則分五類依序下發；latency＝controller 收到 policy 到收到 ACK [原文 p.21]。
- 未說明：每點量測時長、warm-up、throughput 重複次數、誤差線定義、controller 與 COTS 規格、遵循 RFC 2544／9411 與否（全文無 RFC 引用）。

**G7 安全模型**：多租戶隔離靠 agent 給不同 tenant 配不衝突的 fid，使其走不同路徑、命中不同 entry [原文 p.22]；sSF 用 OS process 取隔離與效率的平衡 [原文 p.9]。對抗情境的 trust model 留待未來。Function Reconfiguration 訊息可遠端載入軟硬體 executable，但**全文沒有說明驗證、簽章或威脅模型**（grep 全文無 authentication／signature）。

**G8 與我們設計對照**：

| 類別 | 內容 |
|---|---|
| 這篇已做過（不能宣稱新） | 框架定義 API、功能邏輯由使用者填（三個 callback）[p.13]；共用前處理一次、以 per-packet 資訊傳遞中間結果 [p.11]；flow 粒度的功能略過（「結果只決定是否略過後續功能」[p.3]，對應我們的 ct mark 信任 flow）；header 在快速層、payload 在軟體、只把需要的流量送軟體 IDS [p.19, p.11]；controller 只送抽象 policy、裝置端快取規則 [p.10]；以 LoC 與分發 latency 當框架價值證據 |
| 這篇做了、我們沒有 [推測] | 全域規則 ID（fid）與依 ID 刪除，可對照我們 nft set 的元素管理；有型別的控制訊息集（含 ACK、Device Status、統計）可補強 unix socket 協定設計；用 Strawman 比 LoC 的評估法；Table 2 式的框架功能比較表；分項（S1/S2/S3）量控制面延遲與資料量 |
| 我們有、這篇沒有 [推測] | 外掛簽章與只限本機管理者安裝；雲端只回 trust／block／observe、不能下發可執行物；在真實 Linux 上量逐段 µs 成本（bridge 3.1、nft+ct 10.7、NFQ→Suricata 27–29 µs）；用真實 Suricata 8 而非簡化 Snort；雲端斷線行為（我們需要設計並驗證，PASS 沒有這些，不代表我們已做完） |
| 衝突或取捨不同 | PASS 自訂 protocol 與 metadata、放棄 OpenFlow 相容，並承認代價 [p.22]；我們選標準 Linux 元件換取相容，代價是無法改封包格式與硬體。PASS 允許遠端載入 executable，我們禁止。PASS 的 agent 預取完整規則庫，我們的規則本來就在本地。PASS 是多租戶公有雲，我們是單租戶公司 gateway |

**公有雲設計能否搬到 Pi 4**（全部為 [推測]）：

| 設計 | 能否搬 | 理由與 Pi 4 對應物 |
|---|---|---|
| 共用前處理＋中間結果傳遞 | 部分能 | tc eBPF 解析一次，結果寫入 ct mark／skb mark（nft 讀得到）；容量只有 32 bit，不是任意欄位。XDP metadata 需 native XDP，Pi 4 兩個 port 都沒有 |
| flow 粒度略過後續功能 | 能 | 已在規劃（ct mark 信任 flow、nft 早 accept） |
| agent 快取與 ID 索引 | 能 | 成本低，與 nft named set 對應 |
| 三 callback 的開發模型 | 能 | 對應 Rust trait／plugin hook，與硬體無關 |
| 有 ACK 的型別訊息集 | 能 | 純軟體 |
| 評估方法（LoC、扣 direct forwarding、分項量控制面） | 能 | 與硬體無關 |
| hSF（FPGA）卸載 | 不能 | Pi 4 無 FPGA／SmartNIC；eBPF 與 Suricata 搶同一組 A72 核心，省的是路徑長度，不是釋放 CPU |
| 多租戶 fid 隔離 | 不需要 | 單租戶 |
| Java controller＋自訂 protocol | 不該搬 | JVM 不適合 Pi；雲端本就是可選外部服務 |
| 遠端載入 executable | 不能 | 違反我們的安全底線 |
| 100G／400G 設計目標 | 無關 | Pi 4 為 1 GbE 級 |

**G9 對碩士論文的用途**：
1. 引用 PASS 說明「框架類論文用 LoC 與控制面延遲證明價值」，並指出它缺「框架抽象 vs 手寫版本」的效能 overhead 量測 [p.16, p.18]，我們可補上這一項 [推測]。
2. 借 Table 7 的實驗設計（分項方案、依規則數掃描、同時報資料量與延遲）來量「雲端判決→nft 規則生效」的路徑 [p.21]。
3. 借「扣除 direct forwarding 基準」分離處理成本與 I/O 成本 [p.18]，對應我們 bridge-only 3.1 µs 的基準。
4. 借 §2.2 的論點「安全功能不改封包、功能鏈由 flow 特徵決定、結果只決定略過與否」支撐 flow 粒度的信任旁路設計 [p.3, p.6]。
5. 借 Table 2 的框架比較表格式，定位我們與 OpenBox／VFP／ClickNP（再加 eBPF 系框架）的差異 [p.7]。

## E. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| LoC 減量 | PFW 77.7%、SFW 56.9%、IDS 60.7%，平均 65% | Strawman（FAST API，無重用） vs PASS，HW＋SW LoC | 原文 p.16 Table 5 |
| LoC 明細 | PFW HW 2358→294、SW 865→424；SFW HW 5095→2129、SW 921→465；IDS HW 2873→809、SW 2247→1201 | 同上 | 原文 p.16 Table 5 |
| 框架自身 LoC | controller 2000 行 Java；agent 800 行 C；PASS library 行數未給 | — | 原文 p.15–16 |
| FPGA 資源 | 共 25,544 Slice LUT、81.5 BRAM；device／platform／function 占 LUT 27／52／21% | 百分比為占已用資源 | 原文 p.17 Table 6 |
| PFW 加速 | +13–38%（扣 I/O） | 256–1500 B，1 GE，A9 866 MHz | 原文 p.18 |
| HW PFW vs HW Direct latency | 相同、無 jitter | 同上 | 原文 p.18 |
| SFW 加速 | +20.5–28%（扣 I/O） | iperf 8 連線、掃 MSS | 原文 p.19 |
| TCP 建立時間 | HW SFW 15.5 µs、HW Direct 14.7 µs；SW SFW 約 100 µs、SW Direct 約 76 µs（80% 分位） | 1000 條連線 | 原文 p.19 |
| 每秒最大連線 | HW 約 8000；SW Direct 約 5500；SW SFW 約 2400 | 每秒 20,000 請求、重複 100 次 | 原文 p.19 |
| IDS 加速 | 吞吐 +7–20%、latency −3–18%；絕對吞吐約 65–115 Mb/s（圖讀） | exact＋regex 比對 | 原文 p.19；Fig. 13 |
| PFW→IDS | 吞吐 +14–50%、latency −8–26% | 同上 | 原文 p.20 |
| SFW→IDS | 吞吐 +26–77%；handshake 90 vs 140 µs（80% 分位） | 8 連線；1000 連線 | 原文 p.20 |
| 控制面分發 | S3 97 ms、0.4 KB（5 類皆同）；S1 329–1422 ms、6–260 KB；S2 200–478 ms、0.5–4 KB | 25–811 條 Snort 規則 | 原文 p.21 Table 7 |
| 控制面降幅 | S3 對 S1 平均 −82%，對 S2 平均 −65%；最大約 −93%（[推測] 自行由 Table 7 計算） | 同上 | 原文 p.22 |

## F. 自評

- **未能確認／論文未說明**：PASS protocol 傳輸層、controller 與 COTS 規格、throughput 量測時長與重複次數、誤差線定義、improvement 公式、重配置時間、controller 斷線行為、簽章與驗證、Snort rule 版本。
- **最不確定的三件事**：
  1. Fig. 11–15 的數值是我從圖片目視讀取，只可當量級參考，正式引用請以文字數字為準。
  2. 「Strawman 不是真的 from scratch」與「LoC 未計框架本身」的判斷，依據是全文找不到 PASS library 行數與 Strawman 效能；若補充材料有，我看不到。
  3. G8 的 Pi 4 可搬／不可搬判斷全是 [推測]，尤其「ct mark 可承載 metadata 的實用程度」沒有任何實測。
- 既有報告：本篇為新讀，無舊報告可核對。
