# G5 Elsevier 三篇：全文精讀查核（n=186、264、404）

查核日期：2026-11-03。判斷基準是 `SCREEN.md` 的 C1–C4 定義。三篇都已讀完整全文（含圖表頁；186 的 Fig. 22–26、404 的 Fig. 3–4 與 Table 7–8 對照 PDF 確認）。頁碼是期刊頁碼：186 用 article 內頁序 1–17（對應 JNCA 198, 103283），264 用 Comput. Commun. 31 的 1934–1944，404 用 JNCA 36 的 768–780。「論文未說明」表示全文找不到，不推測補完。標「我的計算」或「背景知識」的是我自己加的，不是論文寫的。

## 總表

| n | 論文 | C1 稽核撤銷 | C2 inline 部分檢查 | C3 同機 IDS+ML 資源 | C4 kernel fast path |
|---|---|---|---|---|---|
| 186 | Wang & Chang, eBPF IDS (JNCA 2022) | none | none（反面對照：無狀態，不支援 flow／stream） | none | related（本組最強，但不是 overlap） |
| 264 | Otrok et al., game-theoretic sampling (Comput. Commun. 2008) | related（弱，純理論） | none | none | none |
| 404 | Lin & Lee, NIDS bottleneck profiling (JNCA 2013) | none | related（中，只是建議，沒做） | none（只有 cache 旁證） | none |

---

## n=186　Design and implementation of an intrusion detection system by using Extended BPF in the Linux kernel

### 書目
Shie-Yuan Wang, Jen-Chieh Chang（國立陽明交通大學）。Journal of Network and Computer Applications 198 (2022) 103283。

### 他們做了什麼
- 目標：Snort 這類 user space IDS 吞吐低，所以把 Snort 的 fast pattern matching（FPM）搬進 kernel。每個進來的封包先經過 XDP 上的 eBPF 程式，用 Aho–Corasick 掃整個 payload，看有沒有任何規則的 fast pattern；沒有就在 kernel 直接丟掉，有才用 perf_event 把封包送到 user space 的 control program 做 rule tree 比對（Sec. 5.1，p.6；Abstract）。
- 狀態：完全 per-packet、無 flow 記憶。eBPF maps 全部唯讀（Sec. 5.10，p.11），只有 port group 對應的 AC 起始狀態；每個封包獨立被掃（Fig. 8–10）。沒有 flow table、沒有 conntrack、沒有「某 flow 已信任」的概念，也沒有「之後再拉回來檢查」。
- 部署模式：**不是 inline**。Sec. 2（p.2）的 IDS 接在 switch 旁邊，只收 mirror 複本，「does not block any traffic」。Sec. 5.1（p.6）明講「the packets that they check actually are mirrored copies」，所以 kernel 裡的 drop 只是丟掉複本，不影響轉送。論文沒有討論如果改成 inline 要怎麼放行（論文未說明）。
- 對 Snort 規則的支援很窄（Sec. 4.3.3，p.5；Sec. 6.2，p.12）：只支援 content、file_data、pcre、byte_test；**flow、flowbits、byte_jump、isdataat、urilen 不支援**；需要 Snort preprocessor 的規則整批排除，評估時 preprocessor 全關（只留 frag3）。也就是 stream reassembly、app-layer 解析都沒有。加密 payload 偵測不到（Sec. 5.2，p.6）。
- Control program 是他們自己寫的（不是 Snort 本體），單執行緒（Sec. 5.10，p.11；Sec. 8，p.16）。
- 平台：x86。IDS host 是 Asus TS300-E10-PS4、Xeon E-2134 3.5 GHz、8 核、16 GB DDR4（Table 5，p.12）；Linux kernel 5.3（Sec. 7.1，p.14）；10 Gbps 光纖直連；封包產生器是另一台 i7-9700。**非 ARM、非嵌入式**。
- IDS：Snort 2.9.15.1 為比較對象，用 Snort registered ruleset 刪減後的版本（6000 條預設、最多 12000 條）。Snort 的封包擷取方式論文未說明。
- 量測：CPU 使用率（system／user／softirq 分開，單核百分比最高 800%）、封包遺失率、「零遺失最大吞吐」（二分搜尋，10 次平均）。流量是 iperf3 背景流量＋pytbull 攻擊流量，用 tcpreplay-edit 重播；背景封包長度分佈取自 CAIDA；預設 ATTR（會觸發 alert 的流量比例）1%、MPL（最大封包長）1500、NR（規則數）6000、30 條並行 flow（Sec. 6.3，p.12）。
- 沒有報偵測率或漏報（論文未說明；全文沒有 false negative 或 detection rate 的比較，只比吞吐）。

### 對 C1–C4 的標記
- **C1：none。** 沒有信任／放行 flow 的概念，所以沒有放行後稽核。唯一沾邊的是 Sec. 4.3.2（p.5）提到 Snort 的 `pass` 動作「used for trusted hosts/network domains to speed up」，那是靜態主機名單，不是動態 flow 信任，也沒有撤銷。
- **C2：none。** 缺的關鍵要素：不是 inline；不是 ARM；不接有狀態 IDS（flow／stream／app-layer 規則全部被排除或不支援，Sec. 4.3.3、6.2）；每個封包都整包掃，不是只看開頭；沒有分析中途接手、缺口、填充規避。反而可當「無狀態 pre-filter 做不到有狀態規則」的反面對照。
- **C3：none。** 沒有 ML、沒有同機資源干擾。唯一相關的資源面向是 CPU 分解（softirq／user／system）。
- **C4：related（本組最強，不是 overlap）。** 撞到的點：用 XDP eBPF 在 kernel 裡讓大部分封包不必送到 user space 的 IDS，「pre-drop a very large portion of packets」（Abstract），user 態 CPU 因此「tiny」（Sec. 7.3，p.14）。缺了我們的關鍵要素：(a) 過濾單位是「單一封包的 payload 有沒有 fast pattern」，不是「已被判定可信的 flow」；(b) 沒有 per-flow 信任狀態，所以也沒有稽核或撤銷（C1 那一側）；(c) 評估是 mirror 複本的被動模式，不是 inline 轉送，放行語意不同；(d) x86 Xeon，不是 ARM；(e) 只報「零遺失最大吞吐」，沒有每封包成本；(f) 只有 XDP 一個機制，沒有和 conntrack mark／flowtable／tc 比較。另外 Sec. 3（p.2）自己寫「eBPF is used for three tasks in Suricata: ... XDP-based flow bypassing」，等於承認 Suricata 本身已有 kernel flow bypass 功能；我們的 C4 不能宣稱「kernel bypass Suricata」這個機制是新的，新的只能是信任語意、ARM 上的每封包成本、多機制比較。

### 可拿來比的數字（平台：Xeon E-2134、10 GbE、Linux 5.3，x86；與 Pi 不可直接比）
- Snort 2.9.15.1 單執行緒：零遺失最大吞吐約 2000 Mbps；負載超過約 2500 Mbps 後 user CPU 卡在 100%（Sec. 7.3，p.14；Fig. 22）。
- 他們的 eBPF IDS：NR=6000 或 12000 時約 6000 Mbps，「almost three times」（Sec. 7.4，p.15；Fig. 24–26）。NR=0 時接近 10 Gbps 線速，Snort 約 2.5 Gbps。
- 9500 Mbps 負載下 softirq：他們約 400%、Snort 約 600%（Sec. 7.3，p.14–15）。作者說原因是 XDP 在最早階段丟封包，省掉上層網路堆疊處理。這個「早丟省 softirq」可以旁證我們 conntrack mark 放行（14 µs vs 檢查 55–61 µs）的方向，但他們沒給每封包數字。
- 小封包：Fig. 25 在 MPL=100 時，他們約 3000 Mbps、Snort 約 300 Mbps（從圖讀的近似值）。我的計算：若全是 100 B 封包，Snort 約 375 kpps、≤ 約 2.7 µs／封包；MPL 是最大長度不是平均長度，所以只是上限推估、且 Snort 關了 preprocessor、被動模式、x86，**不能和我們 Suricata+NFQ 在 Pi 上的 55–61 µs 比**。
- ATTR 從 1% 升到 10% 時吞吐幾乎不變，只有 NR=12000 且 ATTR>6% 才略降（Sec. 7.4，p.15）：alert 流量少時 pre-filter 的效益才大，預設 ATTR 只有 1%。

### 我們論文怎麼引用
作為比較對象（C4 的相近工作）：「kernel 端 eBPF 讓大部分封包不送 user space IDS」在 2022 年已有人做，且報告用 XDP 能省 softirq；差異在於我們的放行單位是被信任的 flow（可稽核、可撤銷）、inline 轉送、ARM 上的每封包成本、多種 kernel 機制比較。同時作為 C2 的反面證據：無狀態 per-packet pre-filter 不能支援 flow／stream／app-layer 規則，所以不能拿來解決「只看訊息開頭」的有狀態 IDS 問題。

### 雪球
本篇引用的文獻裡，沒有哪一篇「研究論文」比它本身更接近 C1–C4，但有一項現成機制要查：
- Leblond & Manev, "Introduction to eBPF and XDP support in Suricata", Stamus Networks whitepaper, 2019（本篇 Sec. 3 引用）。理由：這是 Suricata 官方的 XDP／eBPF flow bypass 說明，和 C4「讓已判定的 flow 跳過 Suricata」是同一件事的現成實作。我們必須在論文裡說清楚與 Suricata 內建 bypass 的差異。（我的背景知識：Suricata 另有透過 NFQ mark 的 bypass 機制，本篇沒提，需另查官方文件。）
- Scholz et al., "Performance implications of packet filtering with Linux eBPF", ITC 30, 2018；Hohlfeld et al., "Demystifying the performance of XDP BPF", NetSoft 2019。理由：eBPF／XDP 過濾的效能量測，可能有每封包成本數字可和我們的 tc eBPF／XDP 比較（只看標題，x86）。
- Miano et al., "Securing Linux with a faster and scalable iptables", SIGCOMM CCR 2019（bpf-iptables）。理由：把 netfilter 過濾搬進 eBPF 並處理連線追蹤，可能和 C4 的 conntrack／flowtable 對照有關（只看標題）。
- Vieira et al., "Fast packet processing with eBPF and XDP", ACM CSUR 2020。理由：eBPF／XDP 綜述，可用來確認有沒有別的 IDS 繞過類工作漏網。
- 其餘（InKeV、Katran、Cilium、ebpfH 等）與 C1–C4 距離比本篇遠。

---

## n=264　Game theoretic models for detecting network intrusions

### 書目
Hadi Otrok, Mona Mehrandish, Chadi Assi, Mourad Debbabi, Prabir Bhattacharya（Concordia University）。Computer Communications 31 (2008) 1934–1944。

### 他們做了什麼
- 純理論模型。網路是有向圖，IDS 有一個全網路的取樣預算 B_s（packets／second），把它分配到各條 link 上抽樣封包看有沒有入侵（Abstract；Sec. 3.3，p.1937）。
- 攻擊者模型（Sec. 1，p.1935；Sec. 3，p.1936–1937）：(1) 聰明的單一攻擊者把一個入侵拆成 n 個 fragment，各自走不同路徑（MPLS 選路），IDS 要抽到至少 m 個才算偵測到；(2) 多個合作攻擊者各送一個 fragment，要全部被抽到才算偵測到。賽局是雙人零和、完全資訊，解法是 min–max：IDS 把取樣預算集中在 attacker 到 target 的 min-cut link 上（Sec. 5–7，p.1938–1941）。
- 延伸自 Kodialam & Lakshman（INFOCOM 2003）的取樣賽局，那篇只考慮一個封包就完成攻擊的情況（Sec. 2，p.1935–1936）。
- 平台、IDS 種類、inline 與否：**全部沒有**。沒有真實 IDS（沒有 Snort／Suricata／Bro）、沒有硬體、沒有實作系統。評估只是 C++ 在一張九個節點的範例圖（Fig. 3）上數值計算，比較 game／uniform／random 三種取樣策略的偵測機率（Sec. 8，p.1942–1943；Fig. 4–6）。預算掃 1–150 packets/s。
- 這裡的 "flow" 指 link 上的流量大小 f_e（max-flow／min-cut 用的容量），不是 5-tuple 的網路 flow。

### 對 C1–C4 的標記
- **C1：related（弱，純理論）。** 撞到的點：在固定檢查預算下用抽樣檢查流量，並考慮「知道取樣策略的聰明攻擊者」會怎麼避開（「a sampling budget of Bs packets/second over the entire network」，Sec. 3.3，p.1937）。缺了我們的關鍵要素：沒有「判定可信後放行」這一步，抽樣是在任何信任決定之前對全部封包做；沒有 flow 狀態、沒有撤銷；沒有「放行後才攻擊」的漏報量化；沒有任何實測成本。只能當「預算受限下的抽樣檢查有賽局理論分析」的背景。
- **C2：none。** 「把攻擊拆到多個封包」（「split his attack over multiple packets」，Sec. 1，p.1935）和我們的「先塞資料再攻擊」規避在概念上相鄰，但這篇是抽象的 m-of-n fragment 機率模型，沒有 TCP、沒有有狀態 IDS、沒有部分檢查的設計、沒有填充規避。
- **C3：none。** 沒有 ML、沒有同機資源。
- **C4：none。** 沒有 kernel 機制、沒有 fast path。

### 可拿來比的數字
- 沒有可和我們比的數字。只有數值模擬的偵測機率曲線：預算達到 attacker→target 的 max-flow（範例圖是 99）時，game 策略的偵測機率趨近 1（Sec. 8，p.1942；Fig. 4）；多攻擊者超過約一半時 uniform／random 反而比 game 好（p.1943；Fig. 6）。都不是真實系統量測，也沒有 CPU、每封包成本、時間。

### 我們論文怎麼引用
作為背景：Related work 裡一句話——「預算受限的抽樣式入侵偵測早有賽局理論分析（Kodialam & Lakshman 2003；Otrok et al. 2008），但都是封包層級、不含放行後的 flow 信任與稽核，也沒有實作與成本量測」。不需要比較。

### 雪球
本篇引用的文獻裡，沒有比它本身更接近 C1–C4 的。值得順帶列入背景引用的：
- Kodialam & Lakshman, "Detecting network intrusions via sampling: a game theoretic approach", INFOCOM 2003：本篇的前作，同樣是封包抽樣＋預算賽局，距離 C1 的程度和本篇相同，不更近。
- Ptacek & Newsham, "Insertion, evasion, and denial of service: eluding network intrusion detection", 1998（本篇 [3]）：有狀態 IDS 規避的經典，是 C2 討論「部分檢查會被規避」時應引用的底層文獻（只看標題與本篇用法）。
- Alpcan & Başar, CDC 2003／2004：IDS 賽局，離 C1–C4 遠。

---

## n=404　Re-examining the performance bottleneck in a NIDS with detailed profiling

### 書目
Po-Ching Lin, Jia-Hau Lee（國立中正大學）。Journal of Network and Computer Applications 36 (2013) 768–780。

### 他們做了什麼
- 用 PAPI 的 CPU cycle 計數器，把 Snort 2.8.5 和 Bro 1.5.2.7 的每個處理階段（Snort：decoding、preprocessing、mpse、rule tree、pcre、others；Bro：L3 analysis、connection analysis、event extraction、policy script）的執行時間拆開量，看 pattern matching 是不是真的瓶頸（Sec. 3.1，p.771–772；Sec. 4.1，p.776）。
- 平台：Intel Core2 Q9400、Linux 2.6.30，從 PCAP 檔離線讀（Sec. 3，p.771）。x86，不是 ARM；**不是 inline**，沒有 NFQUEUE／網路卡擷取成本；CPU 時脈論文未說明。
- 流量：真實流量（NCTU BetaSite 校園、校園出口鏡像）六類（HTTP、SSH、FTP、SMTP、線上遊戲、P2P，Table 1）、用 fragroute 切碎的 IP fragment／TCP segment、DEFCON-9／11、ISCX 攻擊 trace、20 GB 的整批流量（Sec. 3.2–3.6、4.2–4.4）。
- 主要結論：Snort 若整條連線的 payload 都掃，pattern matching 才會主導；預設只掃前面一小段時，pattern matching 只占兩成上下；stream5（連線追蹤＋重組）是 preprocessing 裡最貴的；Bro 的瓶頸是 policy script（Abstract；Sec. 5，p.778–779）。
- 部分檢查相關（對 C2 重要）：
  - Snort 預設 HTTP 每個方向「only the first 300 bytes」，SSH 只看每方向前 20 個封包（Sec. 3.2，p.772）。Bro 預設只重組連線的前 1 kB（Sec. 4.3，p.778）。
  - 把 http_inspect 的 server_flowdepth 設成 0（掃整條 server→client）：HTTP 吞吐從 83.3 降到 15.38 MB/s，FTP 從 63.49 降到 32.08 MB/s（Sec. 3.4，p.774）。
  - 長連線（任一方向 payload > 100,000 bytes）只占連線數 0.55%，卻占 payload bytes 98.70%（Sec. 3.6，p.775）。
  - 引用 Maier et al. 2008（時光機）說「most interesting information ... is in the beginning of a connection」，和 Lin et al. 2012a 說只掃連線開頭就能產生 Snort 大部分 alert，因而提議「dynamically reconfigure Snort to scan only the beginning of the connections ... if the system load is heavy」（Sec. 3.4，p.775）。
  - Sec. 5（p.779）建議「precisely specify the possible locations of the signatures」：以規則的 offset／depth／protocol field 限定掃描位置。
- 論文只量測與提議，沒有實作 gateway、沒有 inline 放行部分封包、沒有測偵測率或規避。

### 對 C1–C4 的標記
- **C1：none。** 沒有放行／信任／稽核。Sec. 2.2（p.771）有一句提到 Gonzalez et al. 2007 的「tracks the connections and diverts only the packets of interest」，那是別人的工作，本文沒有展開。
- **C2：related（中）。** 撞到的點：「只掃連線開頭、其餘不掃」的想法和預設做法（Snort flow depth 300 B、Bro 1 kB）都已存在，且他們量了整條掃的代價（吞吐降 5.4 倍：83.3→15.38 MB/s），並明確提議在系統負載高時動態縮小掃描位元組數（Sec. 3.4，p.775）。缺了我們的關鍵要素：(a) 只是提議，沒有實作也沒有評估；(b) 單位是連線開頭的位元組數，不是每個應用層訊息（HTTP message）的開頭；(c) 離線 PCAP、x86 Core2，不是 inline、不是 ARM；(d) 沒有分析有狀態 IDS 接受部分封包／中途接手／ACK 視窗；(e) 沒有討論「先塞填充再攻擊」會繞過固定位元組深度（全文沒有 padding；規避只談到 fragment／segment 切碎與 regex 複雜度攻擊，Sec. 3.2–3.3，p.774）。我們實測「只送每方向前 N bytes」被填充繞過（0%）、而 HPA 抓到 100%，剛好是這個提議的反例。
- **C3：none（有 cache 旁證）。** 沒有 ML、沒有同機干擾。旁證：(1) Sec. 3.5（p.775；Fig. 4b）每字元掃描時間的變化主要和 L1 cache 命中率有關（命中率多數在 0.95 以上、最低約 0.82，從圖讀）；(2) Sec. 3.6（p.775–776；Table 7）整批流量的 preprocessing 時間是分 10 份各自量測加總的 2.1 倍（125.54G vs 59.65G cycles），作者「speculate」是連線表大到放不進 CPU cache。這兩點支持「Snort 對記憶體階層敏感」，但只是推測，沒有實驗操縱記憶體競爭。
- **C4：none。** 沒有 kernel 機制、沒有 bypass。但成本拆解可當動機（見下）。

### 可拿來比的數字（平台：Core2 Q9400、Snort 2.8.5、離線 PCAP，與 Pi＋Suricata 8＋NFQ 不可直接比）
- Snort 各階段 CPU cycles／封包（Table 2，p.772，預設設定）：HTTP 合計 13.88K，其中 decoding 1.20K、preprocessing 4.09K、mpse 2.66K、rule tree 2.21K、pcre 434.61、others 3.29K。我算的占比：decoding 8.7%、preprocessing 29.3%、mpse 19.1%、rule tree 16.1%、pcre 3.1%、others 23.6%。（論文 Table 6 印的 HTTP default rule tree 占比是 12.88%，和 Table 2 的 4.75G／29.55G=16.1% 不一致，六項占比加起來只有 95.9%；引用時建議用 cycles 自己算。）
- 其他流量每封包合計：SSH 2.60K、FTP 4.08K、線上遊戲 10.87K、P2P 18.88K、SMTP 109.85K cycles（Table 2）。若以 Q9400 標稱 2.66 GHz（我的背景知識，論文沒寫時脈）估算，HTTP 約 5 µs／封包。這遠低於我們的 55–61 µs，差別來自離線讀檔無 NFQ、Snort 2.8.5、x86 桌機，不應直接比較。
- stream5（連線追蹤＋重組）是 preprocessing 中最大的一項：HTTP 53%、SSH 54%、FTP 90%、SMTP 46%、線上遊戲 45%、P2P 35%（Table 3，p.773；論文沒明說分母，從 Sec. 3.3 的用法推測是 preprocessing 階段時間）。這支持 C4 的動機：被信任而跳過 IDS 的 flow，省掉的不只是 pattern matching，還有 decode 加連線追蹤。
- 整條掃 vs 預設：HTTP 總 cycles 從 29.55G 增加到 315.42G（約 10.7 倍，我的計算；Table 6），mpse 占比從 19% 變成 64.20%。
- 攻擊流量（Table 5，ISCX）：mpse 占 HTTP DoS 30.67%、IRC DDoS 39.42%、SSH brute force 23.87%；preprocessing 各占 32.49%、22.72%、34.72%。
- 切碎封包（Table 4）：每封包總 cycles：IP fragment（48 B）5.90K、TCP segment（4 B）4.08K，其中 preprocessing 占 44% 與 51%。

### 我們論文怎麼引用
作為背景＋反駁對象。(1) C2：「只檢查連線開頭」的想法與預設（Snort flow depth、Bro 1 kB）早已存在，Lin & Lee 甚至提議在負載高時動態縮小；但那是固定位元組深度，我們實測會被填充繞過，所以我們提出以應用層訊息邊界（HPA）取代位元組深度。不能宣稱「首先提出只掃開頭」。(2) C3／C4 動機：引用他們的階段拆解，說明連線追蹤與 decode 在 IDS 成本中占的比例，因此整條 flow 跳過比只加速 pattern matching 省得多。

### 雪球
這篇引用的文獻中，下列比它本身更接近 C1–C4（只看標題與本文對它的描述，需要讀全文）：
1. **Gonzalez, Paxson, Weaver, "Shunting: a hardware/software architecture for flexible, high-performance network intrusion prevention", ACM CCS 2007。** 本文 Sec. 2.2（p.771）說它「tracks the connections and diverts only the packets of interest for the NIDS analysis」；標題是 hardware/software 的 inline 防禦（NIPS）架構。最可能同時撞到 C4（讓大部分封包不進 IDS）、C1（有沒有放行後重新檢查）、C2（只看連線前段）。最優先全文確認。
2. **Lin, Lin, Cheng, Chen, Lai, "Low-storage capture and loss-recovery selective replay of real flows", IEEE Commun. Mag. 50(4), 2012。** 本文 Sec. 3.4 說它顯示「只掃連線開頭就能產生 Snort 大部分 alert」，是 C2「只看開頭」前提的實證出處；需看它的涵蓋率數字與是否討論規避。
3. **Maier, Sommer, Dreger, Feldmann, Paxson, Schneider, "Enriching network security analysis with time travel", SIGCOMM 2008（Time Machine）。** 本文用它支持「重要資訊在連線開頭」與長尾分佈；它的 per-connection 截斷（cutoff）是 C2 的概念前人，也可能含有回頭查看的機制（對 C1），需讀。
4. **Lee, Cabrera, et al., "Performance adaptation in real-time intrusion detection systems", RAID 2002；Rehák et al., "Runtime monitoring and dynamic reconfiguration for intrusion detection systems", RAID 2009；Dreger et al., "Predicting the resource consumption of network intrusion detection systems", CCS 2008。** 依系統負載動態調整 IDS 設定，是 C3「依負載調整工作量」的 IDS 端前人（沒有 ML，但要確認有沒有「降級檢查」的策略）。
5. **Dharmapurikar & Paxson, "Robust TCP stream reassembly in the presence of adversaries", USENIX Security 2005；Vutukuru, Balakrishnan, Paxson, "Efficient and robust TCP stream normalization", IEEE S&P 2008；Handley, Kreibich, Paxson, "Network intrusion detection: evasion", USENIX Security 2001。** 有狀態 IDS 在缺口、重組、規避下的行為，是 C2「有狀態 IDS 能不能接受部分封包」那一塊的理論底層，需確認有沒有人處理過「只看部分 stream」。
6. **Hsu & Wang, "Embedded network intrusion detection systems with a multicore aware packet capture module", ICPPW 2011。** 嵌入式多核 NIDS，可能是 C3／C4 的嵌入式平台前人（只看標題）。
7. （非本文引用，我的背景知識，需查證）Gonzalez & Paxson, "Enhancing network intrusion detection with integrated sampling and filtering", RAID 2006：印象中是以抽樣與過濾降低 NIDS 負載，同一作者群的前作，可能比第 1 項更接近 C1／C2。

---

## 本組總結

- **最可能被撞到的是 C4，其次 C2。** C4：Wang & Chang（2022）已經用 XDP eBPF 讓絕大部分封包不進 user space IDS（預設 ATTR=1% 時 user 態 CPU 很小；論文沒給被丟封包的確切比例），並量到 softirq 比 Snort 低，而且他們自己指出 Suricata 本身就有「XDP-based flow bypassing」；所以「kernel 層讓封包／flow 繞過 user space IDS」這個機制不能宣稱新穎。但撞到的程度是 related，不是 overlap：他們是無狀態 per-packet payload 預過濾（不是 flow 信任）、mirror 被動模式（不是 inline）、x86 Xeon（不是 ARM）、只報吞吐（沒有每封包成本）、只有 XDP 一種機制，也完全沒有稽核與撤銷。C4 的新穎性只能放在：信任語意（對應 C1）、inline 放行、ARM 上的每封包成本、四種 kernel 機制（conntrack mark／flowtable／tc eBPF／XDP）的比較。C2：Lin & Lee（2013）提過在負載高時動態縮小到「只掃連線開頭」，Snort（300 B）與 Bro（1 kB）也有預設深度，所以「只檢查開頭」本身不新；程度是 related（中），因為他們只是提議、離線 PCAP、用固定位元組深度、沒有處理有狀態 IDS 與填充規避，而這些正是我們的 HPA 結果（8% 封包、後段攻擊與填充規避皆 100%，對比前 N bytes 的 0%）的獨特之處。Wang & Chang 反過來顯示無狀態 pre-filter 不支援 flow／stream／app-layer 規則，可佐證為什麼 C2 要接有狀態 IDS。
- **C1：本組幾乎沒有威脅。** Otrok 是純理論的預算抽樣賽局（封包層級、無信任與撤銷、無實作），related（弱）；Wang & Chang 與 Lin & Lee 都沒有放行後稽核。不過 Lin & Lee 引用的 Shunting（CCS 2007）與時光機（SIGCOMM 2008）有可能碰到 C1／C2／C4，要優先全文確認（雪球第 1、3 項）。
- **C3：本組沒有直接證據。** 三篇都沒有同機 ML 與 IDS 的干擾量測。Lin & Lee 的 cache 觀察（L1 命中率影響掃描時間；大連線表放不進 cache 時 preprocessing 時間是分開量測加總的 2.1 倍）是對「IDS 對記憶體階層敏感」的弱旁證，可當 C3 的動機，不影響新穎性。
- **本組沒有任何一篇可以標 overlap。**
