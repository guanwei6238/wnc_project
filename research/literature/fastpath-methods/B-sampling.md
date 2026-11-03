# B 組：有保證的抽樣

2026-11-02，唯讀研究。範圍：抽樣式入侵偵測的偵測機率模型、偏向抽樣、跨 flow／跨設備協同、對知道抽樣的攻擊者的賽局、對已放行 flow 的抽樣複查。本地 PDF 與全文文字在 `pdfs/<slug>/`（合計約 13 MB）。

頁碼約定：cSamp 用 USENIX 正式頁碼（PDF 第 N 頁 = 第 N+232 頁）；Cyber-AnDe 用作者版 PDF 頁碼（1–13，對應 TIFS 9245–9257，[推測] 為 9244+N）；FlipIt 用 J. Cryptology 正式頁碼（655–713）；CHID 用 RJIT 正式頁碼（55–65）；XNET、Vaněk、von Stengel 用 PDF 頁碼；STS 用作者草稿頁碼（草稿頁首標 DRAFT）。

## 0. 結論

1. **B1**：各篇算「抓到」的方式不同、前提都很重。Ha 2016（STS）與 Cyber-AnDe 把單一 flow 在一個節點的漏抓機率寫成超幾何（無放回）`C(r−m, γr)/C(r, γr)`，跨節點視為獨立相乘，且必須已知該 flow 在這個週期內有 m 個惡意封包 [STS 草稿 p.7 Eq.(4)(5)；Cyber-AnDe 作者版 p.8 Def.1]；cSamp 算的是「flow 被記錄的比例」，不是攻擊偵測機率 [cSamp p.235–236]。m=1 代入就是「漏抓 = 1−抽樣率」[推測：由 Eq.(5) 代入]。
2. **單包攻擊有硬上限** [推測：平均值論證，非論文結論]：預算只夠檢查 N 個封包中的 B 個時，攻擊者選最不被檢查的位置，單包偵測機率不可能高於 B/N；von Stengel 的檢查賽局在「無懲罰、單次違規」時價值剛好是 `−r(n−m)/n`，與此一致 [von Stengel p.5 Thm 1，代入 b=0,k=1 為我的推導]。超過這個上限只有靠「資訊」：偏向、多包放大、跨 flow 關聯。
3. **B2**：偏向抽樣的實證優勢很大，但都建立在「攻擊落在被偏向的類別」。XNET 在同樣削減 75% 流量下，Suricata 保留 99.6% alert，對照隨機封包 1.2%、sample-and-hold 2.9%、隨機 flow 21% [XNET Table 2 p.12]。偏向的依據：目的地冷門度（Tranco 排名加本地 client 數）、每條 flow 前 N 包 [XNET §3.2 p.4–5]；Cyber-AnDe 用分類器對 flow 的 malicious/suspicious/benign 機率 [作者版 p.7]；Androulidakis 用 flow 大小（偏向小 flow）[摘要＋二手投影片]。
4. **XNET 漏掉的 12 個 alert 正是我們的情境**：10 個落在被 1/10–1/100 隨機降取樣的「熱門」目的地，2 個是 Shared Services 第 15 包之後的明文 HTTP payload [XNET p.12]。這是目前找到最接近「對低風險／近似信任流量降取樣並量化漏報」的數字，但它以 alert 數計，同一 flow 內重複 alert 會讓比例偏高 [推測]。
5. **B3**：cSamp 以不相交 hash range 讓各路由器負責不同 flow，LP 最大化最小 OD 覆蓋率 [cSamp p.235–236]，對單一 gateway 退化成「一個節點」[推測]。「抓到一條就處理相似 flow」只有 CHID（flow 層判可疑，來源 IP 進 BPF filter 讓其後流量做封包層檢查，條目有逾時）[CHID p.57–58] 與 Cyber-AnDe（可疑 flow 取樣率 ×2，容量不足改由別的 switch 取樣）[作者版 p.6]；兩者都只管「之後」的流量。
6. **B4**：FlipIt 的答案取決於攻擊者能不能得知防守者時點。攻擊者不知道時：同速率下「隨機相位的週期策略」強支配所有 renewal（含指數）[FlipIt Thm 4 p.681]；攻擊者能得知防守者上一次動作時間（LM）時：週期策略的效益為負（除非快到逼攻擊者退出），指數（無記憶）使 LM 沒有額外優勢，延遲指數在模擬中更好 [FlipIt p.684–687]。Cyber-AnDe 明說沒處理 adaptive 攻擊者 [作者版 p.12]。
7. **B5**：沒找到對「已放行／白名單／bypass」flow 做抽樣複查並量化漏報的論文（約 10 組查詢，見 §2 B5）。最接近的是 XNET（對低風險類別降取樣並量化丟失的 alert）和既有筆記裡 Time Machine 的「計畫」。
8. **B6**：多數做法只需 header（5-tuple、flow 計數）；需要「雲端分數／IDS 回饋」的是 Cyber-AnDe、STS、CHID（可疑名單由別處產生）。純 hash／隨機抽樣可在 Pi 的 tc eBPF 或 nft 做；需要中央最佳化的（cSamp LP、STS 的 fmincon）在單一 gateway 沒有對象 [推測]。

## 1. 逐篇

### Kodialam & Lakshman（INFOCOM 2003）
- **書目**：Murali Kodialam, T. V. Lakshman, "Detecting Network Intrusions via Sampling: A Game Theoretic Approach," IEEE INFOCOM 2003, vol.3, pp.1880–1889，DOI 10.1109/INFOCOM.2003.1209210 [二手：Crossref 與 OpenAlex 查詢]。與給定書目一致；Nokia Bell Labs 頁面標題為單數 "Intrusion"，日期 2003-03-30 [二手：搜尋結果摘要]。
- **取得程度**：**僅摘要＋僅二手**。搜尋結果出現官方 INFOCOM 2003 站的 PDF（`https://infocom2003.ieee-infocom.org/papers/46_02.PDF`），但該站 TLS 憑證鏈在本環境驗證失敗，我沒有關閉驗證（自動模式拒絕了這個操作），所以沒下載；CiteSeerX 與 Wayback 副本皆 404；Semantic Scholar API 回 429。有 IEEE 帳號或瀏覽器的人可直接開官方 URL。
- **機制**（只有摘要）：問題是「偵測一個入侵封包」；偵測靠抽樣經過選定 link（router interface）的封包；抽樣有即時抽樣與封包檢查硬體成本，所以有總抽樣預算；入侵者選路徑（只能最短路徑時選 ingress point）以最小化被偵測機會，營運者選抽樣策略以最大化偵測機會；提出此賽局下最佳的抽樣方案 [摘要，取自 OpenAlex abstract]。
- **二手補充**：Vaněk 等人說 Kodialam 模型是「單一來源、單一目標、zero-sum，防守者沿來源到目標的路徑檢查」[AAMAS 2012 §2 p.2]；一篇賽局式 IDS 綜述的搜尋結果片段說它用 max-flow 解，最佳抽樣率優於均勻與隨機 [二手：搜尋結果片段，未打開原頁，不可靠]。
- **偵測面／成本面**：偵測機率公式、攻擊者資訊假設（是否知道抽樣機率）、數值結果、規避處理：**未能確認**。
- **對我們的意涵 [推測]**：模型單位是一個入侵封包穿越多個節點；單一 gateway 只有一個節點，賽局退化，最佳解就是把預算均勻攤在所有封包上，偵測機率 = 抽樣比例（見結論 2）。它的價值在「網路層級如何分配」，不是單點。
- **限制**：以上全部是二手，不能當原文引用。

### cSamp（NSDI 2008）
- **書目**：Vyas Sekar, Michael K. Reiter, Walter Willinger, Hui Zhang, Ramana Rao Kompella, David G. Andersen, "cSamp: A System for Network-Wide Flow Monitoring," NSDI 2008, pp.233–246。與給定一致。**全文**（`pdfs/csamp/csamp.pdf`，USENIX 開放）。
- **機制**：三個基本元件：flow sampling 取代 packet sampling（避免偏向大 flow，「對安全應用特別重要」）、hash-based 選擇（各路由器用同一個 hash、分配不相交的 hash 範圍，不需要互相通訊就不會重複記錄）、網路層級最佳化 [原文 p.233]。5-tuple hash 落在該路由器範圍內才記錄，hash 視為 [0,1] 均勻值 [原文 p.235]。LP：每條 OD 路徑 i 的覆蓋率 `C_i = Σ_j d_ij`（因範圍不相交所以直接相加），限制每台路由器可記錄的 flow 數 `Σ d_ij·T_i ≤ L_j`，先求最大化最小覆蓋率，再在該最小值之下最大化總覆蓋 [原文 p.236]。
- **偵測面**：量的是 flow 覆蓋率，不是攻擊被偵測的機率。Fig.5(a)：總 flow 覆蓋率為均勻封包抽樣的 1.8–3.3 倍 [原文 p.243]；把 1,000 條合成的單封包 flow（模擬 botnet C&C）注入 Internet2 flow 資料，cSamp 找到的是均勻封包抽樣的平均 12 倍 [原文 p.245]。沒有惡意 payload、沒有規避模型；僅在 Discussion 承認「對抗式流量下記憶體耗盡的公平性」是未解 [原文 p.245]。
- **成本面**：worst-case 處理開銷比 YAF 全記錄只多 5%（不是每個封包的 µs 數）[原文 p.241]；SRAM 每條 flow 12 bytes（4 B hash＋兩個 32-bit 計數）[原文 p.239]；在 Xeon 2.8 GHz 上，300 路由器等級的 manifest 計算 ≤ 11 秒 [原文 p.241 Table 3]。平台是路由器與 Emulab，不是 Pi。
- **對我們的意涵 [推測]**：(1) hash(5-tuple) < 門檻 的 flow 層級抽樣可直接搬到 tc eBPF 或 nft（既有筆記 M16 已列 `numgen`／hash）；它對同一條 flow 的決定固定，所以「同一條信任 flow 內多次出手」不會增加被抓機率（機率恆為 p，與封包數無關），而逐封包獨立抽樣是 `1−(1−p)^m`，但會破壞 Suricata 的 stream 脈絡（既有筆記 `trust-bypass/mechanisms.md` §7.5）。(2) 協同與 LP 對單一 gateway 沒有用，除非未來有多台 gateway 看到同一流量。
- **限制**：作者自承依賴 OD-pair 標記（改封包 header）與全網流量矩陣 [原文 p.245]。

### Androulidakis & Papavassiliou（IET Commun. 2008）
- **書目**：G. Androulidakis, S. Papavassiliou, "Improving network anomaly detection via selective flow-based sampling," IET Communications 2(3):399–409, 2008，DOI 10.1049/iet-com:20070231 [二手：NTUA DSpace 記錄]。與給定一致。
- **取得程度**：**僅摘要**（NTUA DSpace 沒有全文，IET 為付費）。另有同作者姊妹篇 IEEE Network 2009（"Network anomaly detection and classification via opportunistic sampling"）的布爾諾理工大學課堂投影片（捷克文，`pdfs/androulidakis/fit_slides.pdf`）作為**僅二手**。
- **機制**：提出偏向小 flow 的 flow 抽樣，理由是「小 flow 通常是惡意流量的來源」，並稱它是「可在處理資訊量與偵測準確度間取捨的彈性框架」[摘要]。投影片給的抽樣機率：`p(x)=c`（x≤z），`p(x)=z/(n·x)`（x>z），x 為 flow 大小；c、z、n 的意義投影片沒有定義，且這是 IEEE Network 篇的投影片，是否與 IET 篇相同**未能確認** [二手：投影片 p.7]。
- **偵測面**：用 sequential non-parametric change-point 偵測器，資料是真實校園網路；「改善偵測效果並同時減少被選取的 flow 數」，**摘要沒有任何數字** [摘要]。IEEE Network 篇的設定（二手）：NTUA–GRNET 骨幹、約 4,000 台主機、250 Mbit/s、攻擊為注入、對照未抽樣與隨機抽樣 [二手：投影片 p.12]。
- **成本面**：**未能確認**（需要每 flow 的大小計數）。
- **對我們的意涵 [推測]**：偏向「小」flow 對我們方向相反，因為信任的是長連線（大 flow），被偏向的是還沒信任的短連線。既有筆記 Mai 2006 的結論是偏向大 flow 的 smart／sample-and-hold 對異常偵測最差，因為攻擊常由小 flow 組成 [既有筆記 `trust-bypass/papers/sampled-anomaly.md` §B 第 3 點]，與此篇一致。
- **限制**：無全文，所有細節都不能引用。

### Cyber-AnDe（IEEE TIFS 2024）
- **書目**：Nadia Niknami, Avinash Srinivasan, Jie Wu, "Cyber-AnDe: Cybersecurity Framework With Adaptive Distributed Sampling for Anomaly Detection on SDNs," IEEE TIFS 19:9245–9257, 2024 [二手：搜尋結果的 NSF PAR／DBLP 記錄]。與給定一致。**全文**（Temple 作者版，13 頁，`pdfs/cyber-ande/cyber-ande.pdf`；未與 IEEE 版逐字比對）。
- **機制**：controller 以 sFlow／OpenFlow 讓 switch 把抽樣封包送 BMA 分類器，輸出 malicious 機率 p1、benign 機率 p2；`p1>τ` 為惡意、`p2>τ` 為良性，否則可疑 [原文 p.7]。動作三種：惡意→下 block 規則；可疑→提高取樣率；良性→一般轉送 [原文 p.4]。ADS 從最低取樣率 γ0（實驗用 1/10、1/100、1/1000）起算，可疑 flow 取樣率 `γ'=2γ`，switch 容量不夠就把該 flow 的取樣搬到別的 switch（動態 set cover）[Alg.3，原文 p.6]；良性 flow 的取樣間隔 `Tα=(1+α)T0`，沒有 alert 時 α 遞增到 αmax [原文 p.8]。另有 Q-learning（狀態＝三種流量狀態，動作＝加速率／停止／加輔助 switch）[原文 p.7]。
- **偵測模型**：Def.1：flow f 在 switch s 抽不到的機率 `p_{f,s} = C(r_s−m_f, γ_s·r_s) / C(r_s, γ_s·r_s)`（r_s 為該 switch 的封包數、m_f 為 f 的惡意封包數，視為從 r_s 個球無放回抽 γ_s·r_s 個），跨 switch 相乘，目標 `min_γ max_f p_f` [原文 p.8]。這個式子來自 STS（見下）。論文另以「假設 1% 抽樣偵測 80%、5% 偵測 95%」做說明，那是「let us assume」的假設，不是結果 [原文 p.3]。
- **偵測面**：摘要稱「偵測最多提升 93%」[原文 p.1]，內文沒有說明 93% 的基準與算法 [論文未說明]。具體數字：對固定取樣，false negative 約低 90%（γ0=1/100、1 Gb/s switch）[原文 p.10 Fig.11(b)]；達到 ≥90% 偵測率所需 switch 數平均少 48% [原文 p.10]；對 DDoS 資料集 HLD-DDoSDN，偵測率 93.45–97.46%，STCS 為 87.78–93.23%、FlowShark 為 90.67–95.11% [原文 p.12 Table I]；偵測時間比 OpenFlow 快約 46%、代價是 alert 訊息多約 15% [原文 p.9]。實驗：hping3 的 SYN／UDP flood 與畸形封包、Snort signature 模式、35 台伺服器＋15 台 SDN switch [原文 p.9]。**沒處理 adaptive 攻擊者**，作者自己寫「routine attacks without directly addressing adaptive adversaries」[原文 p.12]。
- **成本面**：以 controller 控制訊息量計：比 OpenFlow 低 42%、比固定取樣低 26% [原文 p.10]；Table I 中 Cyber-AnDe 的 overhead 為 0.14–0.25%（STCS 0.17–0.32%、FlowShark 0.13–0.26%）[原文 p.12]。沒有 CPU、每封包成本。
- **對我們的意涵 [推測]**：「起始低、遇可疑加倍、無警報就拉長間隔」的狀態式調速可以搬：可疑訊號 = 雲端 flow 分數或 Suricata 對抽樣封包的告警，調的是信任 flow 的複查率；但 Cyber-AnDe 的「良性」flow 仍以 γ0 持續被抽，這個 γ0 的偵測貢獻（先正常後攻擊）論文沒有單獨量。
- **限制**：評估混合模擬與測試床，baseline 的調參條件不明；93% 無定義；Table II 的偵測率寫成 0.83／0.65 這類小數卻標 %，單位不清 [原文 p.12 Table II]。

### FlipIt（J. Cryptology 2013）
- **書目**：Marten van Dijk, Ari Juels, Alina Oprea, Ronald L. Rivest, "FlipIt: The Game of 'Stealthy Takeover'," J. Cryptology 26:655–713, 2013（DOI 10.1007/s00145-012-9134-5）。與給定一致。**全文**：我讀的是 Rivest 在 MIT 主頁放的期刊版 PDF（59 頁，`pdfs/flipit/DJOR13.pdf`）；IACR ePrint 2012/103 對機器人回 403 所以沒用，MIT 另放的 2012 ePrint 版我下載後只確認標題就刪除。
- **讀了哪些章節**：摘要與 §1 的三點教訓（p.655–662）、§2.2 的應用例（p.665–667）、§3 形式定義（p.667–671）、§4 renewal 賽局 4.1–4.3（p.674–681）、§5 LM 攻擊者 5.1–5.5（p.682–688）、§7 延伸（p.694–695）。§4.4（RP 攻擊者）、§6 Greedy、附錄證明只看了標題，**沒讀**。
- **模型**：防守者與攻擊者爭奪一個資源；任一方可在任何時間「move」（付成本 k_i）奪回控制，**控制權歸誰要到有人 move 才知道**；每方效益 = 控制時間比例 − 移動成本 [原文 p.655–656 摘要]。回饋分 NA（無）、LM（move 時得知對方上次 move 的時間）、FH（全歷史）[原文 p.669–670]。「週期策略」每隔固定 δ move，第一次 move 的相位在 [0,δ] 均勻隨機，因為完全確定的週期會讓對手算出所有時點 [原文 p.670]。
- **結論（B4 要的）**：(1) 非適應性（NA／RP）下，同一速率的所有 non-arithmetic renewal 策略（含指數）都被「隨機相位的週期策略」強支配，殘存賽局就是週期對週期 [原文 Thm 4 p.681]。週期對週期的效益：α0≥α1 時 `β0=1−α1/(2α0)−k0α0` [原文 p.675]。(2) 攻擊者是 LM 時，週期防守者「效益為負」，因為攻擊者一次 move 後就知道相位，之後緊跟在防守者之後出手；只有 α0>1/k1（快到攻擊者無利可圖）時攻擊者才退出，此時 β0=1−k0/k1 [原文 p.684–685]。(3) 指數防守者：無記憶，LM 回饋對攻擊者沒有額外好處，攻擊者最佳反應是週期或不玩（λ≥1/k1 不玩）[原文 Thm 6–7 p.685–686]；「延遲指數」（固定等待 Δ 再加指數）在模擬中比指數效益高，但最優形式是開放問題 [原文 p.687]。(4) 教訓：「任何回饋對玩家都有利」，所以要常監看 [原文 p.661]。
- **偵測面／成本面**：沒有封包偵測，沒有流量資料；「move 成本」是抽象參數。§2.2 提到雲端稽核：稽核挑戰排程是「文獻中未處理的問題」，可用 FlipIt 建模，防守者每次 move = 一次 challenge/audit [原文 p.666–667]。
- **對我們的意涵 [推測]**：(1) 複查時點若可被預測就會被利用，所以要隨機；在攻擊者看不到複查時點（NA）的前提下，隨機相位的週期（固定間隔但相位隨機）比純隨機間隔好，這與直覺相反。(2) FlipIt 的「LM」回饋在我們情境對應「攻擊者能觀察到某次複查發生」；若複查只記錄不阻擋，攻擊者無從得知；若複查結果造成封鎖或延遲差異（NFQ 路徑約 +40 µs，SPEC 數字），就洩漏了時點。(3) **模型落差**：FlipIt 的攻擊是「持續佔領」直到防守者下一次 move 才失去控制，單一 XSS 封包是瞬間事件，不適用；它適用於信任後「長時間持續的惡意 session」。
- **限制**：作者承認只分析 renewal、LM；全適應性雙方與其他攻擊者類別是開放問題 [原文 p.662]。

### CHID（Res. J. Inform. Technol. 2016）
- **書目**：H. Alaidaros, M. Mahmuddin, "Conditional hybrid approach for intrusion detection," Research Journal of Information Technology 8(3):55–65, 2016，DOI 10.3923/rjit.2016.55.65，CC-BY 開放 [原文 p.55]。與給定的「CHID／Conditional Hybrid IDS」一致。博士論文（UUM 2017）為 restricted。
- **取得程度**：期刊論文**全文**（`pdfs/chid/rjit2016.pdf`，UUM 機構庫）；博士論文**僅摘要**。
- **機制**：flow 層偵測（softflowd 產 NetFlow，Bro 腳本）把可疑 IP 寫入紀錄檔，每筆有逾時；封包層的 Bro 起始時以 BPF 排除所有流量，經 Input Framework 讀入可疑 IP 表後，只檢查符合這些 IP 的流量並做 signature 比對 [原文 p.57–58]。設計依據：「重複性攻擊在未來連線中送出相似流量」，所以以未來封包驗證 flow 警報 [原文 p.57]。
- **偵測面**：IRC-bot 與 P2P-bot（ISOT、CTU-51/52/53，背景為 8 GB 校園 trace）；「偵測到所有被標註的感染主機」且零 false positive [原文 p.61]。指標是「感染主機有沒有被報」，不是逐封包或逐攻擊的偵測率；封包層只看 flow 層先標出的主機，所以 flow 層漏掉的就不會被檢查，論文沒有量這個漏報。作者說它只適合「在 flow 與封包兩層都可偵測」的攻擊，並非所有情境都適用 [原文 p.63]。
- **成本面**：兩台 i7 3.1 GHz／32 GB，Bro 2.3，tcpreplay 100–1000 Mbps [原文 p.60]。200 Mbps 的 IRC-bot：記憶體 −50.6%、CPU −18.1%、無丟包，而 Bro 全檢查在 200 Mbps 丟 5.12% [原文 p.61–62 Table 4]；P2P-bot 在 200 Mbps，CPU 由 97.7% 降到 72.4% [原文 p.62]；到 500 Mbps 時 CHID 總 CPU 近滿載，省的資源只到 500 Mbps 為止 [原文 p.62–63]。netflow 聚合的成本沒計入（假設網路已有）[原文 p.60]。
- **對我們的意涵 [推測]**：這是「抓到一條就處理相似 flow」最直接的做法：雲端或 Suricata 對某條 flow 判可疑 → 把來源 IP 放進帶 timeout 的 nft set，該 IP 的信任一律撤銷、其後流量全進 queue；逾時機制就是 trust decay。Pi 上的成本是 set 寫入（既有筆記量到 netlink 約 53 µs／次）加上撤銷時掃 conntrack 的 ct mark。**限制**：只影響「之後」的流量，第一個攻擊封包不被涵蓋。
- **限制**：實驗是 2016 年舊資料、Bro 2.3、僅兩種 botnet；沒有規避分析。

### STS／Ha et al.（Computer Networks 2016；補充，因 Cyber-AnDe 的模型出自這篇）
- **書目**：Taejin Ha, Sunghwan Kim, Namwon An, Jargalsaikhan Narantuya, Chiwook Jeong, JongWon Kim, Hyuk Lim, "Suspicious Traffic Sampling for Intrusion Detection in Software-Defined Networks"；出版處為 Computer Networks（Elsevier）[二手：ScienceDirect 記錄 PII S1389128616301645 出現在搜尋結果，卷頁未能確認]。**全文**：作者草稿（20 頁，標 DRAFT、日期 2016-03-04，Hyuk Lim 實驗室網站 `https://hlim.kentech.ac.kr/wiki/uploads/Publications/2016-comnet-sampling.pdf`），與正式版的差異未能確認。
- **機制與模型**：f 條 flow、n 個 switch；switch j 對 b_j 個封包以速率 x_j 抽樣，視為從 b_j 個球無放回抽 x_j·b_j 個；flow i 有 λ_i 個惡意封包，漏抓機率 `p_ij = C(b_j−λ_i, x_j b_j)/C(b_j, x_j b_j)`，跨 switch 相乘 [草稿 p.7 Eq.(4)(5)]。目標是 `min_x max_i p_i`（最差 flow 的漏抓率最小），作者刻意不用總和，因為總和可能犧牲少數 flow，「在安全上很危險」[草稿 p.9–10]。λ_i 未知，以 IDS 回報的惡意封包數與取樣數估計並做移動平均再迭代 [草稿 p.11–12 Alg.1]。
- **偵測面**：ns-2 模擬與 Snort 測試床；對照「每個 switch 均分取樣」的 naive 法，500 switch 網路下 naive 有超過 85% 的惡意 flow 沒被偵測 [草稿 p.16]。
- **成本面**：最佳化用 MATLAB fmincon，20 switch 約 4 ms，大型拓樸 3.6 s 與 8.79 s（Xeon E5-1650v2）[草稿 p.16–17]。
- **對我們的意涵 [推測]**：(1) 這個模型明確要求「已知 λ_i」，也就是需要預先知道一條 flow 裡有幾個惡意封包，對單包攻擊 λ=1，式子化簡為「漏抓 = 1−x」。(2) 值得借用的是它區分「封包驅動」與「時間驅動」取樣：時間驅動（每秒前 100 ms 全抓）能保留 stateful 攻擊的脈絡 [草稿 p.12]，與既有筆記提的「連續視窗」做法一致。
- **限制**：假設 IDS 對送達的惡意封包一定判對；假設各 switch 的取樣互相獨立。

### XNET（arXiv 2608.18349，2026-08）
- **書目**：Thomas Papastergiou, Karthika Subramani, Joseph Reilly, Boladji Vinny Adjibi, Pierros-Christos Skafidas, Roberto Perdisci, Manos Antonakakis（Georgia Tech、UGA），"XNET: Intelligent Dynamic Sampling for High-Speed Network Security Monitoring"，arXiv:2608.18349v1 [cs.CR]，2026-08-18。**不在給定書目內，B5 搜尋時發現**。**全文**（18 頁，`pdfs/xnet/xnet.pdf`）。這是 arXiv v1 預印本，是否經同儕審查未能確認。
- **機制**：XDP 程式在 driver 層解析 header（IP、port、UDP 53 DNS），查 eBPF map（外部 IP→類別）決定取樣策略：DNS 與「Rare」（只有 ≤15 個 client 連過，θR=15）全送；Shared Services（CDN／雲）與 Unidentified 只保留每 flow 前 N 包；本地熱門（client 數 >100）隨機取 1/10（τl）；本地加全球熱門（Tranco 排名）隨機取 1/100（τg）[原文 p.4–5、p.8]。類別表由使用者態 Traffic Profiler 依觀察到的 client 數與外部資料（Tranco、雲端 IP 範圍、passive DNS）更新，形成回饋 [原文 p.3–4]。它「本身不是偵測系統」，是 Suricata／Snort／Arkime 前面的預篩 [原文 p.3]。
- **偵測面**：20 個 malware-traffic-analysis.net 的 pcap（426,414 封包）混入 15 分鐘、800 個 client 的校園流量，重放後經 XNET 過濾，整體削減 75%，保留 88% 的 malware 封包與 13% 的良性封包 [原文 p.11]。Suricata alert 保留 2,780／2,792＝99.6%，Snort 99.5%，沒有新增 false positive [原文 p.12]。同樣削減 75% 的對照（各 1000 次）：隨機封包 1.2%、隨機 flow 21%、sample-and-hold 2.9% [原文 Table 2 p.12]；作者解釋隨機封包與 S&H 差是因為許多 Suricata alert 需要先建立的 flow 或較早的封包 [原文 p.12]。**漏掉的 12 個 alert**：2 個來自 Shared Services（明文 HTTP 的 payload 規則，超過前 15 包），10 個來自被重度降取樣的熱門目的地（Telegram SNI、FormBook C2 checkin 打到與 github 同 IP 的位址）[原文 p.12]。真實部署：16 天、100 GbE 學術網路（峰值 87 Gbps）流量削減 78–84% [原文 p.2、p.9、p.13]。
- **成本面**：2× Xeon Gold 5318N、250 GB RAM、100GbE ConnectX-6；壓力測試到 100 Gbps，20 個 RX queue 足夠 [原文 p.7、p.11]；沒有每封包的 µs 數。
- **對我們的意涵 [推測]**：(1) 這是「依類別給不同抽樣策略」的實證，對 B2 最強；對我們的信任 flow，可以把「類別」換成信任等級（例如雲端分數、目的地冷門度），低風險類別保留 1/10–1/100 隨機抽樣，其餘照樣檢查前 N 包。(2) XNET 的 99.6% 是 alert 計數，單條 flow 內同一規則重複命中很多次，會讓比例看起來高；論文自己也說被漏掉 payload 的 flow「前 15 包仍有 alert 所以 client 還是會被標出來」[原文 p.12]，這種「後來才出現的單包攻擊」並未獨立量測。(3) 平台是 XDP；bcmgenet 沒有 native XDP，須改用 tc eBPF（SPEC 前提）。
- **限制**：作者承認 IPv4 only、需要 native XDP [原文 p.16]；以熱門目的地為低風險的假設，被惡意軟體用雲端服務 C2 時會失效，作者的辯護是這類應由主機端處理 [原文 p.13]。內部不一致：§5.1.2 說 N=20 [原文 p.9]，而漏報分析說「前 15 包」[原文 p.12]，實際用哪個**未能確認**。資料集（校園流量）不公開 [原文 p.16]。

### Vaněk 等（AAMAS 2012；補充，Kodialam 的後繼）
- **書目**：Ondřej Vaněk, Zhengyu Yin, Manish Jain, Branislav Bošanský, Milind Tambe, Michal Pěchouček, "Game-theoretic Resource Allocation for Malicious Packet Detection in Computer Networks," AAMAS 2012。**全文**（`pdfs/kodialam/aamas2012_4E3.pdf`，ifaamas 開放）；我讀了 §1–§3 完整，§4 以後只讀標題與結論句。
- **機制與模型**：圖上有來源（攻擊者控制）、中間節點（可檢查）、目標（有價值 τ_t）；防守者在節點 n_i 檢查流量的比例 x_i，限制 `Σ x_i f_i ≤ B`（B 是延遲預算）；一個惡意封包沿路徑 p 逃過的機率 `π = Π_{i∈p}(1−x_i)`，因為各節點獨立檢查且**偵測器完美** [原文 p.3 Eq.(1)]。攻擊者**知道**防守者的抽樣機率（Stackelberg）[原文 p.3]。被偵測的來源要付懲罰 γ_s，所以一般是 general-sum；為了擴展性提出 zero-sum 近似與有誤差界限的貪婪演算法 Grande [原文 abstract、p.1]。
- **對我們的意涵 [推測]**：給出 B1/B3/B4 的乾淨模型：攻擊者知道抽樣機率但不知道實現值、單包逃過機率是 `Π(1−x_i)`、懲罰項把「被偵測」變成攻擊者成本。單一 gateway 時 `π = 1−x`。「偵測器完美」與「獨立檢查」是兩個強假設。

### von Stengel, Recursive Inspection Games（Math. Oper. Res. 2016；補充）
- **書目**：Bernhard von Stengel, "Recursive Inspection Games," Mathematics of Operations Research (2016)，arXiv:1412.0129v2。**全文已下載**（27 頁，`pdfs/inspection-games/vonstengel.pdf`）；讀了摘要、§1、§2 與 Thm 1，後面的 non-zero-sum、inspector leadership 只讀摘要。
- **模型**：n 個時段、m 次檢查、最多 k 次違規；檢查者只在「該時段有檢查」時才能發現同時段的違規（發現則賽局結束）；**被檢查者能觀察檢查者** [原文 abstract]。Thm 1：價值 `v=−t/s`，每個時段檢查機率 `p=s(n−1,m−1)/s(n,m)`，其中 `s(n,m)=Σ_{i≤m} C(n,i) b^{m−i}`（b 是被抓的懲罰因子）[原文 p.5]。
- **我的推導 [推測]**：b=0、k=1 時 `s=C(n,m)`、`p=m/n`、`v=−r(n−m)/n`，即未偵測機率正好是 (n−m)/n。所以懲罰為零時，最佳檢查策略與「每個時段以 m/n 隨機檢查」同樣，沒有比均勻好。b>0 時被檢查者的違規率 q 下降（威懾）；「檢查者先承諾策略」時，被檢查者在檢查尚有剩餘時守法 [原文 abstract]。對我們：攻擊被抓後會被封鎖或被查，這個「懲罰」才是抽樣能貢獻的威懾，不是偵測機率本身。
- **限制**：假設違規被檢查必被抓到（完美偵測）、檢查者不知道未被抓到的違規 [原文 §2]。

## 2. 各問題的回答

**B1：偵測機率模型與假設**
- 兩類：(a) 事件型（單一封包或 λ 個封包）：STS／Cyber-AnDe 用超幾何，要求已知每 flow 的惡意封包數 m 與每節點封包數 r，節點間獨立 [STS 草稿 p.7；Cyber-AnDe 作者版 p.8]；Vaněk 用 `Π(1−x_i)`，要求偵測器完美、節點獨立檢查 [AAMAS p.3]。(b) 覆蓋型：cSamp 的 `C_i=Σ d_ij`，因為 hash 範圍不相交所以不需要獨立假設，而是確定性地分工 [cSamp p.236]。(c) 持續佔領型：FlipIt，效益是控制時間比例 [FlipIt p.655]。
- 「攻擊持續多久、出現幾次」：STS 用 λ_i（每週期惡意封包數）當輸入且逐週期以 IDS 回饋重估 [草稿 p.11–12]；FlipIt 假設攻擊持續到防守者下一次 move [原文 p.668–669]；Kodialam 的細節**未能確認**。
- [推測，算術] 多包放大：逐封包獨立抽樣率 p 時偵測 `1−(1−p)^m`；p=1% 時 m=100 為 63%、m=458 才到 99%；flow 層 hash 抽樣則恆為 p，與 m 無關。以 SPEC 的每封包約 40 µs，1% 對 84 kpps 信任流量就是 840 pps、約 3.4% 的單核 [推測：SPEC 數字相乘]。

**B2：偏向抽樣比均勻好多少、依據哪裡來**
- 最強證據是 XNET：同為 75% 削減，99.6% 對 1.2%／2.9%／21% [XNET Table 2 p.12]。Cyber-AnDe：false negative 約低 90%（對固定取樣）[作者版 p.10]；cSamp 對單封包 flow 約 12 倍 [cSamp p.245]；STS 對 naive 均分在 500 switch 下 naive 漏 85% 以上 [草稿 p.16]。Androulidakis 只有「改善」的定性描述 [摘要]。
- 依據：目的地冷門度與本地 client 數（外部名單＋本地統計）[XNET p.4–5]；分類器信心度 τ [Cyber-AnDe p.7]；IDS 回饋估計的惡意率 [STS p.11–12]；flow 大小 [Androulidakis，二手]；營運者權重 [cSamp p.236]。
- **共同弱點**：優勢都建立在「攻擊落在偏向的類別」，XNET 自己漏掉的就是被降取樣的類別；沒有一篇偏向「同一條信任 flow 內的單一封包」。上述比較的 baseline 調參條件，除 XNET（明確調到同樣削減 75%）外多半**未說明**。

**B3：跨 flow／跨設備協同**
- cSamp：集中式 LP 加不相交 hash range，保證「最小 OD 覆蓋率」最大 [cSamp p.236]；STS：min-max 各 switch 取樣率，跨 switch 相乘 [草稿 p.7–10]；Cyber-AnDe：可疑 flow 取樣率加倍，容量不夠時搬到別的 switch [作者版 p.6]。
- 「抓到一條就處理相似 flow」：CHID 以來源 IP 為單位、帶逾時、只影響之後的流量 [CHID p.57–58]；Cyber-AnDe 以 flow 為單位。沒有找到以「主機」為單位擴大複查、並量化「少抓到幾條」的實驗。搜尋摘要提到 Lancope／Cisco 的專利「每主機累計可疑 flow 的 concern index」[二手：Google Patents 搜尋結果，與抽樣無關，未列入]。
- 對單一 gateway [推測]：跨設備協同沒有對象；跨 flow 傳播（以 IP 或 IP 對為單位的 timeout set）可直接用 nft set。

**B4：策略型攻擊者的賽局結論**
- Kodialam：攻擊者選路徑、營運者選抽樣，zero-sum（二手）[AAMAS p.2]；Vaněk：Stackelberg，攻擊者知道抽樣機率 [AAMAS p.3]；FlipIt：時點賽局，見上；von Stengel：檢查賽局，被檢查者能看到檢查。
- 「隨機 vs 週期」：攻擊者不知道時點 → 隨機相位的週期優於 renewal 隨機；攻擊者能知道上一次時點 → 週期被擊敗，指數無記憶最穩，延遲指數更好 [FlipIt p.681、p.684–687]。Cyber-AnDe 在其攻擊者模型下沒有討論 [作者版 p.12]。「最佳抽樣分佈」：單一節點單一封包時，最差情況就是均勻（見結論 2）。
- 一篇 2011 IEEE 論文（Stackelberg 的攻擊封包抽樣，系統用 SPSA 提高抽中攻擊封包的機率、攻擊者用注入演算法降低）只有搜尋片段 [二手：搜尋結果片段，ieeexplore.ieee.org/document/5948716]，未能確認內容。

**B5：對已放行／白名單／bypass flow 做抽樣複查並量化漏報**
- **沒找到**。查詢（皆 WebSearch，標準或延伸模式）：(1) whitelisted/trusted flows random re-inspection sampling bypass IDS missed attacks；(2) flow bypass／bypassed flows Suricata periodic sampling re-inspect；(3) trust but verify／continuous verification／periodic re-inspection 的 IDS 版；(4) IDS flow offloading after N packets residual sampling late attack cutoff evasion；(5) cached flow verdict revalidation IDS；(6) adaptive sampling escalate inspection of all flows from suspicious host；(7) game theory packet sampling attacker knows sampling rate；(8) inspection game random inspection times；(9) acceptance sampling for network intrusion detection；(10) Cyber-AnDe、Androulidakis、CHID 各自的書目查詢。結果多為專利或 SDN 取樣，沒有一篇直接做「放行後抽樣複查加漏報量化」。Semantic Scholar 查詢被 429 擋住，沒走引用網。
- 最接近：XNET（量化對低風險類別降取樣的 alert 損失）；Cyber-AnDe（良性仍以 γ0 取樣，但沒單獨量）；既有筆記 Time Machine（隨機化 cutoff 與抽樣只是計畫）、Shunting（sample 欄位未評估）[既有筆記 `trust-bypass/candidates.md`、`papers/time-machine.md`、`mechanisms.md`]。搜尋摘要提到 P4ID 把「IDS 對抽樣封包的回饋」列為未來工作 [二手：P4 綜述搜尋片段，未打開]。
- 類比：FlipIt §2.2 的雲端稽核排程 [FlipIt p.666–667]、inspection game 的有限檢查次數 [von Stengel]。

**B6：所需資訊、成本、放 Pi 還是雲端**
| 做法 | 需要的資訊 | 成本（原文數字） | 放哪 [推測] |
|---|---|---|---|
| cSamp 式 flow hash 抽樣 | 5-tuple | 比全記錄多 5%（YAF）、12 B/flow [cSamp p.239, 241] | Pi（tc eBPF／nft）；LP 對單 gateway 無用 |
| XNET 式類別抽樣 | header、DNS、外部 IP→類別表 | 無每封包 µs 數；2× Xeon、100 Gbps 無丟包 [XNET p.7, 11] | 類別表由雲端或 Pi 使用者態更新，Pi 只查表 |
| Cyber-AnDe 式狀態調速 | 分類器輸出（suspicious 機率）| 控制訊息 −42%／−26% [作者版 p.10] | 分數由雲端給，Pi 持有每 flow 取樣率 |
| STS 最佳化 | 每 flow 惡意率估計 | 4 ms–8.79 s（Xeon）[草稿 p.16] | 單 gateway 不需要 |
| CHID 式傳播 | flow 層可疑名單 | CPU −18.1%（200 Mbps，Bro）[CHID p.62] | 名單由雲端回傳，Pi 用 timeout set |
| FlipIt 式排程 | 只要時間，不需要資料 | 抽象成本 k0 | Pi |

## 3. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| Suricata alert 保留率 | XNET 99.6%；隨機封包 1.2%；S&H 2.9%；隨機 flow 21% | 同為 75% 流量削減；20 個 malware pcap＋15 分鐘 800 client 校園流量；對照各 1000 次 | XNET p.12 Table 2 |
| 漏掉的 alert | 12／2,792（10 熱門目的地、2 Shared Services） | 熱門 τl=1/10、τg=1/100；Shared Services 前 N 包（N=20 或 15，論文不一致） | XNET p.12 |
| Snort alert 保留率 | 99.5% | 同上 | XNET p.12 |
| 真實部署流量削減 | 78–84% | 100 GbE、16 天、峰值 87 Gbps | XNET p.2、p.9 |
| flow 覆蓋率倍數 | 1.8–3.3× 對均勻封包抽樣；單封包 botnet flow 12× | Rocketfuel／Internet2 拓樸 PoP 層級模擬；Internet2 資料注入 1,000 條 | cSamp p.243、p.245 |
| 協同的處理開銷 | +5% | 對 YAF 全記錄，最壞情況 | cSamp p.241 |
| False negative | 約 −90% 對固定取樣 | γ0=1/100、1 Gb/s switch、MTR 2.5% | Cyber-AnDe p.10 |
| 偵測率 | 93.45–97.46%（STCS 87.78–93.23；FlowShark 90.67–95.11） | HLD-DDoSDN | Cyber-AnDe p.12 Table I |
| ≥90% 偵測率所需 switch 數 | 平均少 48% | MTR 2.5% | Cyber-AnDe p.10 |
| naive 均分漏抓 | >85% 惡意 flow 未偵測 | 500 switch、λ=0.025 | STS 草稿 p.16 |
| CHID 資源 | 記憶體 −50.6%、CPU −18.1%、丟包 0 對 5.12% | 200 Mbps IRC-bot、Bro 2.3、i7 3.1 GHz | CHID p.61–62 |
| FlipIt 週期對週期效益 | `β0=1−α1/(2α0)−k0α0`（α0≥α1） | NA 回饋 | FlipIt p.675 |
| FlipIt LM 攻擊者對週期防守者 | `β0=−k0/δ0`（α0<1/k1）；α0>1/k1 時 `β0=1−k0/k1` | LM 回饋 | FlipIt p.684 |
| 檢查賽局價值 | `v=−t/s`；b=0、k=1 時未偵測機率 (n−m)/n | 被檢查者可見檢查 | von Stengel p.5（後者為我的推導） |

## 4. 建議追加閱讀

1. Kodialam & Lakshman 全文，官方 URL `https://infocom2003.ieee-infocom.org/papers/46_02.PDF`。理由：B1/B3/B4 的原始模型，我只有摘要。存在確認：URL 出現在搜尋結果，但本環境 TLS 驗證失敗未下載；請在瀏覽器開啟。
2. Bartoš, Řehák, "IFS: Intelligent flow sampling for network security – an adaptive approach," Int. J. Network Management 25(5):263–282, 2015（DOI 10.1002/nem.1902）。理由：B2，以特徵稀有度偏向，並提出「先抽特徵再抽樣」。存在確認：IDEAS／ACM 記錄出現在搜尋結果，全文未取得。
3. Avenhaus, von Stengel, Zamir, "Inspection Games," Handbook of Game Theory vol.3, ch.51, pp.1947–1987, 2002（DOI 10.1016/S1574-0005(02)03014-X）。理由：B4/B5 的標準理論（有限次檢查、威懾、檢查者承諾）。存在確認：IDEAS 與 HUJI 記錄；全文為付費。
4. "Research on Network Attack Packet Sampling Based on Stackelberg Game Theory"，IEEE 2011（`ieeexplore.ieee.org/document/5948716`）。理由：B4，攻擊者主動降低被抽中機率。存在確認：僅搜尋片段。
5. Wang, Li, Pack, Han, Leung, "STCS: Spatial-Temporal Collaborative Sampling in Flow-Aware Software Defined Networks," IEEE JSAC 38(6):999–1013, 2020。理由：B3，跨 switch 與跨時間協同；Cyber-AnDe 拿它當 baseline。存在確認：Cyber-AnDe 參考文獻 [30] [作者版 p.13]，全文未取得。

## 5. 自評：最不確定的三件事

1. **Kodialam 原文沒讀到。** B1／B3／B4 中對它的所有敘述只來自摘要（OpenAlex）與 Vaněk 的一句二手描述；偵測機率式、攻擊者是否知道抽樣機率、max-flow 解法全部是二手或未能確認。它是「有保證」這個題目的起點，這是本組最大缺口。
2. **B5「沒找到」的強度很弱，XNET 的數字要小心用。** B5 只靠約 10 組 WebSearch，沒走 Google Scholar／Semantic Scholar 引用網（API 429）。XNET 是 2026-08 的 arXiv 預印本，其 99.6% 以 alert 計數（同一 flow 重複命中會灌高）、N 值前後不一致（20／15）、資料不公開，且漏報樣本只有 12 個 alert。
3. **「單包攻擊偵測上限 = 抽樣比例」、inspection game 在 b=0 時價值 (n−m)/n、`1−(1−p)^m` 與 3.4% 單核，都是我的推導，不是論文結論。** 前提（攻擊者可選最不利位置、偵測器完美、一次得手即終局、抽樣獨立）未必符合我們；FlipIt 的「持續佔領」與單一 XSS 封包的對應也是我的類比。
