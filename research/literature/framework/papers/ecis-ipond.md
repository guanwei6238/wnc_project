# ECIS（Edge Computing IoT Security for My I-Pond）

> 取得程度：全文（6 頁）。頁碼一律用 IEEE 印刷頁碼 p.24–29（PDF 第 1–6 頁）。Fig. 1–9 與 Table I–VII 都已目視；Fig. 4 另用 pdfimages 抽出原圖放大看過。
> 「全文 grep」指我對 pdftotext 輸出做關鍵字搜尋，用來確認論文**沒有**寫某件事。

## A. 書目與取得狀況

- 標題：Edge Computing IoT Security (ECIS): Implementation of IPS and Encryption for My I-Pond [原文 p.24]
- 作者：Muhammad Abyan Harits、Muhammad Reza Aditria、Thufail Agung Fathi（Telkom University, School of Electrical Engineering）；Nyoman Karna、Istikmal（Telkom University, CoE Intelligent Sensing-IoT）[原文 p.24]
- 年份／出處：2025；2025 8th International Conference on Information and Communications Technology (ICOIACT)，IEEE，pp.24–29；ISBN 979-8-3315-5408-8/25 [原文 p.24]。會期日期以上一輪 Crossref 為準，全文只印年份。
- DOI：10.1109/ICOIACT67584.2025.11345049 [原文 p.24]
- URL：https://ieeexplore.ieee.org/document/11345049/（付費；本檔依使用者經學校下載的 PDF）
- 與給定資訊的差異：無（標題、年份、會議、DOI 相符）。
- 取得程度：**全文**
- 相關非本論文文件：第一作者的 Telkom University 學士論文（館藏 25.04.5624），只有摘要公開（`research/literature/framework/pdfs/ecis-ipond/`）。它的第 3–4 章可能有攻擊工具、規則細節，需登入 Telkom Open Library，未取得。

## B. 核心貢獻（≤3）

1. 把 Suricata IPS 與 AES-256-CBC（OpenSSL）放在 Raspberry Pi 4 Model B 上，位於 ESP32 感測器與 Firebase 之間，成為固定流程的整合方案；作者自稱 "novelty lies in its integrated design" [原文 p.24；Fig. 1、Fig. 4]。
2. 5 種攻擊（OS fingerprinting、TCP SYN scan、UDP scan、DDoS flood、ICMP flood）全部標 Detected / Mitigated / Prevented；DDoS 的 detection+mitigation 為 161.84 ms（insider）、206.08 ms（outsider）[原文 Table I、Table II，p.27]。
3. 以 TIPHON 分級報告 QoS（latency 186 ms、throughput 95.4 Kbps、CPU overhead 0.775%、RAM ±2.1%），10–50 client 皆標 "Stable"；另做 AES-256-CBC 對 ChaCha20-Poly1305 的單獨密碼測試 [原文 Table III–VII，p.27–28]。

## B2. 上一輪五個疑點的結案

1. **數字不一致**：
   - 摘要的 ">99% detection accuracy" 只出現在摘要（全文 grep）。結果章沒有準確率數字，沒有 false positive 測試，沒有分母；只有 "No false negatives" [原文 p.27] 與 Table II 的 5/5 Yes。學士論文的「100% 阻擋」對應 Table II 的 5/5 Prevented。
   - 摘要的 "CPU < 1%" 就是 Table VI 的 Overhead CPU 0.775% [原文 p.28]，與學士論文同一個數字。但摘要說的 "Compared to the baseline My I-Pond setup" 不成立：結論把「對無 ECIS 的 baseline My I-Pond 做 benchmark 以量化 overhead」列為 future work [原文 p.29]，也就是 baseline 比較**沒做**。0.775% 的定義與量法全文沒寫。
   - 摘要的 TIPHON "High"：§II-D 說 TIPHON 有 Best / High / Medium / Best Effort 四類 [原文 p.25]，Table VI 卻用 Good / Very Good / Very Light / Light 評等，正文寫 "Good" to "Very Good" [原文 p.28]。摘要的 "High" 在結果章沒有對應；學士論文摘要的 Good to Excellent 與結果章較接近。
   - 結論：本論文與學士論文是**同一組實驗**（0.775%、206 ms、5/5、無 packet loss、50 client）。不一致來自摘要改寫，以結果章 Table 為準。
2. **部署模式**：全文沒有出現 NFQUEUE、AF_PACKET、iptables、nftables、inline、bridge（全文 grep），也沒寫 Suricata 版本、監聽介面、運作模式。Fig. 2 的邏輯是 drop、加黑名單、產生新規則、送通知，語意像 inline IPS，但機制未說明；同一段又寫 Suricata "periodically inspecting incoming packets" [原文 p.26]，不是 inline 的說法。Fig. 4：Pi 是 isolated Wi-Fi AP，LAN 口上行到 router，橘色 "IPS Scope Area" 框住 ESP32 與 Pi，不含 router、Firebase、Server [原文 Fig. 4，p.26]。ESP32 以 HTTP POST 送到 Pi，Pi 自己收資料、加密、再送 Firebase [原文 p.26]。所以 Pi 是**終結連線的應用層節點**，不是轉送他人封包的 L2/L3 gateway；攻擊測試的目標論文沒說，[推測] 打的是 Pi 本機。
3. **規則與量測**：規則來源、條數、新規則怎麼產生，論文未說明。攻擊只列種類，沒有工具、參數、速率、攻擊機。insider＝本地連 Pi 的 AP，outsider＝經 VPN 與網際網路 [原文 p.27]。Table I 只有 DDoS 兩列，"average" 的樣本數未寫。**206 ms ＝ outsider DDoS 的 Detection Time 198.95 ms ＋ Mitigation Time 7.13 ms** [原文 Table I]；起訖點未定義。作者用 VPN／Internet 路徑解釋 insider 與 outsider 的差 [原文 p.27]，表示量到的時間包含網路路徑，[推測] 不是 Suricata 的處理延遲。
4. **Encryption**：用 OpenSSL 的 AES-256-CBC，在 Pi 上、Suricata 判定封包安全之後、送 Firebase 之前加密感測資料；後端 Flask 以同一把 key 解密，再由 Vite/Vue 儀表板顯示 [原文 p.26、Fig. 4]。ESP32 到 Pi 這一段是明文 HTTP POST（Fig. 4 圖例 Plain Text）。對效能的影響只有單獨的密碼微基準（Table III–IV），沒有加密開／關對 QoS 的對照。
5. **雲端**：Firebase Realtime Database 只是加密資料的存放與轉送端，Server 用 Firebase API 取資料、解密、顯示 [原文 p.26、Fig. 4]。沒有雲端分析、沒有卸載決策。Firebase 或網路斷線時怎麼辦，論文未說明、未測試（G4）。

## C. 指定的 9 項

1. **Research Problem**：水產養殖 IoT 在感測器、gateway、雲端之間的資料有被攔截與 DoS 的風險；先前 My I-Pond 只做水質監測與預測 [原文 p.24]。作者認為既有方案各自獨立或依賴集中式雲端，"an integrated, low-cost edge-layer framework remains an open challenge" [原文 p.24]。
2. **Architecture**：
   ```
   ESP32 + 溫度/pH/濁度感測器
     --Wi-Fi（Pi 為 isolated AP）HTTP POST，明文-->
   [Pi 4B：Suricata（IPS scope）→（ML 水質預測，僅 Fig. 4 畫出）→ OpenSSL AES-256-CBC]
     --LAN→router→Internet，密文--> Firebase RTDB
     --Firebase API--> Server（Flask 解密 + Vite/Vue dashboard）--> Users
   ```
   [原文 Fig. 1、Fig. 4、p.25–26]。Suricata 與加密模組之間的介面，論文只寫 "proceeds to the next stage" [原文 p.26]。
3. **Processing Location**：Suricata 與加密都在 Pi 本機，雲端只存密文、Server 解密 [原文 p.25–26]。Kernel／user space 分工論文未說明。
4. **Hardware**：Raspberry Pi 4 Model B；ESP32 Dev Kit V1；溫度、pH、濁度感測器；AC adapter＋USB 供電，裝在 My I-Pond 外殼內 [原文 p.25–26、Fig. 5]。Pi 的 RAM、OS、Suricata 版本、NIC、時脈、散熱論文未說明。
5. **Dataset**：沒有使用資料集。流量是作者自行發動的攻擊，加上 Locust／REST 腳本模擬 client [原文 p.27–28]。結論把 "larger and more diverse datasets" 列為 future work [原文 p.29]，也印證目前沒有。
6. **Baseline**：沒有系統層級的 baseline（見 B2-1）。唯一的比較是密碼層：AES-256-CBC 對 ChaCha20-Poly1305 [原文 Table III–IV]。與 Rasefiberry、Snort-on-Pi 的比較只在文字上（§II-B，p.24–25），沒有重跑。
7. **Metrics**：Detection／Mitigation／Total Response Time（ms）；Detected／Mitigated（二元）；latency、throughput（Kbps）、CPU 與 RAM overhead（%）、client 數；cipher time per block、avalanche changed bits [原文 Table I–VII]。沒有量：pps、轉送延遲、packet loss 的數值（只寫 "without packet loss"）、false positive、逐層成本。
8. **Limitations（作者承認的）**：future work 列出尚未測的 MITM、replay、malware injection；需要更大、更多元的資料集；需與其他 Pi-based edge security framework 比較；需與無 ECIS 的 baseline 比較以量化 overhead [原文 p.29]。適用範圍限定 "small to medium-scale deployments" [原文 p.28]。
9. **Research Gap**：
   - 作者自述：整合式、低成本的 edge-layer 方案尚缺 [原文 p.24]；上述 future work [原文 p.29]。
   - [推測]：沒有逐層或 inline 路徑的成本量測；沒有 baseline；沒有 IPS 失效或雲端斷線的行為；規則集大小的影響未探討；量測不可重做（見 G6）。

## D. 保留的補充欄位

### D5. 實驗可信度
- 流量來源：作者自產的合成攻擊，加 Locust／iperf3／Python REST 腳本 [原文 p.28]；沒有重播也沒有真實流量。論文稱 "realistic operational conditions" [原文 p.28]，但沒寫測試在池塘現場還是實驗室。
- 速率範圍：攻擊速率未寫；client 10–50 [原文 Table VII]；Fig. 9 的 x 軸是 Idle／1 Mbps／10 Mbps／100 Mbps／1 Gbps。
- 重複次數、變異量、信賴區間、ablation：**全部沒有**。Table I 的 "average" 沒寫樣本數，Table II 只有 Yes／No。
- 程式碼與資料：全文沒有任何公開連結或可用性聲明。
- 圖文不一致（我的觀察，非作者承認）：
  - Fig. 9 標題寫「vs Number of Simultaneous Clients」，圖上實際 x 軸是目標速率、y 軸是 Mbps；正文卻說 10–50 client、"minimum speed above 70 Kbps" [原文 p.28]；Table VII 的最低值是 88.1 Kbps。圖上 100 Mbps 與 1 Gbps 目標時實測都約 70 Mbps（目視讀值）。Kbps 與 Mbps 兩個單位在同一頁並存，無法判斷哪個才是作者要說的。
   - Fig. 7 圖例寫 AES-256-**GCM**，標題與正文是 CBC；圖上 AES 在 8192 與 16384 B 約 0.2、0.4 ms（目視），與 Table III 的 0.2855、0.5709 ms 不符。
   - Table VI 的 latency 186 ms、throughput 95.4 Kbps 不等於 Table VII 五個值的平均（170 ms、99.46 Kbps）[我的計算]，來源實驗不明。
   - 結論寫 avalanche 47–53%，Table V 換算是 49.9–54.0%（AES）、50.5–50.8%（ChaCha）[我的計算]。
- Avalanche 測試的問題 [推測，依密碼學一般性質]：ChaCha20 是 stream cipher，同 key、同 nonce 時翻轉 1 個明文 bit 只會讓密文變 1 個 bit，論文卻報 ~64.6／128，表示測的不是「明文單 bit 變化」。明文超過 16 B 時，「/128」也暗示只比了單一 block。這個測試對 ECIS 的系統評估沒有貢獻。

### D6. 移植到 Pi 4 的障礙
- 平台就是 Pi 4 Model B，沒有移植問題；但 OS、Suricata 版本、規則、RAM 都未寫，無法重現。
- 論文沒有 XDP／eBPF／tc，Pi 4 沒有 native XDP 的限制對這篇不構成影響。
- Fig. 9 的 ~70 Mbps 上限（目視）：沒寫瓶頸在 Suricata、Wi-Fi、iperf3 路徑還是別處，不能當作 Pi 4 + Suricata 的轉送上限。

### D9. 引用網路
本次沒有做網路查詢（任務限制不下載）。以下依論文自己的 reference list 與上一輪已查證的書目。

1. Simadiputra & Surantha，"Rasefiberry: Secure and efficient Raspberry-Pi based gateway for smarthome IoT architecture"，Bull. Elect. Eng. Inform. 10(2), 1035–1045, 2021，DOI 10.11591/eei.v10i2.2741。理由：ECIS 自述最接近的前身（Pi gateway＋Snort＋Twofish）[原文 p.24–25、ref 11]。存在確認：DOI 已由上一輪 OpenAlex 確認；全文未讀。
2. Ruíz-Lagunas 等，"How to Improve the IoT Security Implementing IDS/IPS Tool using Raspberry Pi 3B+"，IJACSA 10(9)，2019，DOI 10.14569/ijacsa.2019.0100952。理由：ECIS 方法章引為「Pi 上整合 IDS/IPS 的先例」[原文 p.25、ref 7]。存在確認：DOI 已由上一輪確認；全文未讀。
3. Garalov & El-Hajj，"Enhancing IoT Security: Design and Evaluation of a Raspberry Pi-Based Intrusion Detection System"，ISNCC 2023，DOI 10.1109/isncc58260.2023.10323656。理由：同題，ECIS 未引用。存在確認：DOI 已由上一輪確認；全文未讀。
4. ETSI TR 101 329-2，TIPHON QoS classes，2000 [原文 ref 13]。理由：確認「High」「Good」「Very Good」的實際定義，判斷摘要與 Table VI 差異的來源。存在確認：僅見論文的引用字串，未驗證。
5. 第一作者學士論文（Telkom Open Library 25.04.5624）。理由：全文可能補上攻擊工具、規則、重複次數；存在確認：頁面與摘要已確認（上一輪），第 1–6 章需登入。

## G. 框架專屬欄位

- **G1. 框架的抽象**：沒有 API、描述語言、設定格式或 pipeline 模型。"framework" 是固定流程：Suricata 判定 → 通過者加密 → 送 Firebase [原文 p.26、Fig. 2]。留給使用者決定的：沒有。
- **G2. 擴充與生命週期**：沒有插件、替換、串接機制；沒有重配置時間或中斷量測。唯一的執行期變更是 Fig. 2 的「偵測到攻擊後把攻擊者 IP 加黑名單並產生新規則」[原文 p.26]；規則怎麼載入、是否原子、期間封包如何處理，論文未說明。
- **G3. 分工與通道**：ESP32→Pi 為 Wi-Fi＋HTTP POST REST；Pi 內為 Suricata、ML 預測（只在 Fig. 4）、OpenSSL 加密；Pi→Firebase 為 Internet；Server 取 Firebase 資料、持有解密 key [原文 Fig. 4]。Suricata 與加密模組間的通道、Kernel／user 分工、黑名單存放（Fig. 2 只寫 "Stored in Rules"）論文未說明。
- **G4. 外部依賴可選性**：Suricata 在本機判定，不依賴雲端 [原文 p.25 "locally"]。Firebase 是資料出口，也是儀表板的唯一資料來源。雲端斷線時的緩衝、重送、fail-open／closed，論文未說明、未驗證。Suricata 本身掛掉時流量是放行還是中斷，論文未說明。[推測] 論文批評集中式雲端有 "single points of failure" [原文 p.24]，自己的資料路徑卻必經 Firebase，這點沒有討論。
- **G5. 框架價值怎麼證明**：實際做的只有：5 種攻擊的 Detected／Mitigated 表、一組 DDoS 響應時間、TIPHON 評等的 QoS 表、10–50 client 的 latency／throughput、密碼微基準。**沒有**：對 baseline 或手寫版本的 overhead 比較、多案例擴充示範、LoC 或開發成本、可維護性、與其他框架比較。
- **G6. 效能量測方法**（能寫到哪算哪）：
  - 工具：iperf3、Locust、Python REST 腳本（模擬 client 經 Pi 送資料到 Firebase）[原文 p.28]。
  - 拓樸：insider 為本地連 Pi 的 AP，outsider 為 VPN＋Internet [原文 p.27]；攻擊機型號、位置、攻擊工具未寫。
  - 響應時間：Detection Time、Mitigation Time、Total（Table I）；時間戳來源與起訖點未寫。
  - QoS：client 10–50，每階段時長、封包大小、warm-up、重複次數、CI 全部未寫。Latency 是 client 到哪裡未寫，[推測] 含 Pi→Firebase 的 Internet 往返。
  - 密碼：區塊 16–16384 B，"Ops/3 sec"（3 秒內完成次數），time per block＝3 s／ops（我驗算符合 Table III）。[推測] 這就是 `openssl speed` 的預設區塊大小與 3 秒窗口，但論文沒寫工具名稱。
  - 標準：未依循 RFC 2544／RFC 9411；TIPHON 只用於分級。
  - 結論：**照論文無法重做**。
- **G7. 安全模型**：
  - 加密：AES-256-CBC，同一把 key 在 Pi 與 Server 兩端（Fig. 4 兩端都畫 Private Key AES-256）；IV 產生、key 分發與輪替、padding、MAC 全未寫。
  - 摘要寫 "end-to-end data confidentiality"，但 ESP32→Pi 為明文 HTTP POST（Fig. 4）；實際是 Pi 到 Server 的機密性。
  - 作者以 "support for data authentication" 作為選 AES-256-CBC 的理由之一 [原文 p.28]。[推測，依密碼學一般性質] CBC 不提供完整性或認證，ChaCha20-Poly1305 才是 AEAD；論文選了沒有認證的那個，卻用認證當理由。
  - 誰能改規則或設定、有無簽章、隔離方式：論文未說明。威脅模型限於攔截與 DoS [原文 p.24]；MITM、replay 作者承認尚未測 [原文 p.29]。
- **G8. 與我們設計對照**：
  - **判斷：不能當「Pi 4 inline gateway、NFQUEUE→Suricata、逐層量成本」的前例。** 只能當「Pi 4 Model B 上可同時跑 Suricata、加密與 Firebase 上傳，並在作者的小負載下標 Prevented」的存在性前例，而且 Suricata 怎麼接進封包路徑論文沒寫。
  - **這篇已經做過、我們不能宣稱是新的**：Pi 4 Model B 上用 Suricata 當 IoT edge IPS，並對 5 種攻擊標示已阻擋 [原文 Table II]；偵測後自動加黑名單、產生新規則的迴路 [原文 Fig. 2]；以 QoS 分級報告資安整合的成本 [原文 Table VI]。
  - **這篇做了、我們沒有，值得考慮的**：Fig. 2 的迴路把「偵測到攻擊」直接接成「擋掉＋記入規則」，並報了 mitigation time 1.99–7.13 ms [原文 Table I]。[推測] 這個量級與我們在 Pi 上實測 spawn `nft` 的約 7.7 ms 同級，但論文沒說機制，不能據此推斷它怎麼做。資料送雲端前的應用層加密與其單機成本（Table III–IV）。
  - **我們有、這篇沒有的**：[推測] NFQUEUE 路徑與逐層成本（bridge 約 3.1 µs、加 br_netfilter／nft／conntrack 約 10.7 µs、NFQ→Suricata 約 27–29 µs）；`when_unavailable` 的失效行為；可選、不在封包路徑上的雲端與 trust／block／observe 回應；擴充點描述語法。論文在這些全部沒有任何描述（全文 grep），所以是「它沒做」而不只是「沒提」。
  - **衝突或不同取捨**：ECIS 的 Pi 是終結連線的應用層節點兼 AP；我們是轉送封包的 gateway。ECIS 的雲端是強依賴的資料出口，我們的雲端可選。ECIS 的 Suricata 預設就擋（Fig. 2 drop），我們預設不做 inline drop。這些取捨在我們的論文裡需要說明理由。
- **G9. 對碩士論文的用途**（≤5）：
  1. 相關工作：「Pi 4 上跑 Suricata 當 edge IPS」已有前例，但前例沒有說明部署模式也沒有逐層成本，我們補的是這個空白 [原文 Table II；全文 grep]。
  2. 量測方法的反面例子：沒有重複次數與分母、起訖點未定義、圖與文字單位衝突（Kbps／Mbps）、圖例與標題不符 [原文 Table I、Fig. 7、Fig. 9、p.28]。支撐「我們把量測寫到可重做」。
  3. 不要引用它的 ">99% accuracy" 與 "CPU < 1% vs baseline"：結果章沒有支撐，baseline 比較被作者列為 future work [原文 p.29]。要引用就引 Table I、II、VI 並註明限制。
  4. 若討論送雲端資料的加密成本，可引 Table III–IV 的 Pi 4 單機數字（AES-256-CBC 約 28.7 MB/s [我的計算]），但要另引來源說明 CBC 缺完整性、應選 AEAD [推測]。

## E. 關鍵數字表

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| Detection Time | insider 159.85 ms；outsider 198.95 ms | DDoS；Pi 4B；樣本數、規則、起訖點未寫 | [原文 Table I, p.27] |
| Mitigation Time | insider 1.99 ms；outsider 7.13 ms | 同上；機制未寫 | [原文 Table I, p.27] |
| Total Response Time | insider 161.84 ms；outsider 206.08 ms | 同上；= 偵測＋緩解（我驗算相加成立） | [原文 Table I, p.27] |
| 攻擊結果 | 5 種攻擊皆 Detected、Mitigated、Prevented | 次數、工具、速率未寫 | [原文 Table II, p.27] |
| False negative | "No false negatives" | 無 false positive 測試 | [原文 p.27] |
| AES-256-CBC time/block | 0.00060 ms（16 B）至 0.57088 ms（16384 B） | Pi 4B；3 秒窗口；工具未寫 | [原文 Table III, p.27–28] |
| AES-256-CBC 吞吐 | 約 28.7 MB/s（16384 B：5,255 ops／3 s） | 單一密碼運算，不含網路 | [我的計算，依 Table III] |
| ChaCha20-Poly1305 time/block | 0.000185 ms（16 B）至 0.05086 ms（16384 B） | 同上 | [原文 Table IV, p.27–28] |
| ChaCha20-Poly1305 吞吐 | 約 322 MB/s（16384 B：58,989 ops／3 s） | 同上 | [我的計算，依 Table IV] |
| Avalanche（改變位元／128） | AES 63.87–69.09；ChaCha 64.61–65.08 | 測法未寫 | [原文 Table V, p.28] |
| Latency | 186 ms（Good） | 起訖點、client 數未寫 | [原文 Table VI, p.28] |
| Throughput | 95.4 Kbps（Very Good） | Locust／REST 負載 | [原文 Table VI, p.28] |
| Response Time | 206.08 ms（Good） | 即 Table I 的 outsider 值 | [原文 Table VI, p.28] |
| CPU／RAM overhead | 0.775%（Very Light）／±2.1%（Light） | 分母、取樣方式、baseline 全未寫 | [原文 Table VI, p.28] |
| client 10→50 | latency 144→196 ms；throughput 112.8→88.1 Kbps；皆 Stable | 每階段時長、重複次數未寫 | [原文 Table VII, p.28] |
| Fig. 9 實測吞吐 | 約 70 Mbps（100 Mbps 與 1 Gbps 目標皆然） | iperf3 類掃描，是否經過 Suricata 未寫 | [原文 Fig. 9 目視讀值，非作者列出的數字] |

## F. 自評

**論文未說明（不是我沒找到）**：Suricata 版本、規則來源與條數、攻擊工具與參數、攻擊目標、模式（inline／IDS）、Pi 的 RAM／OS、CPU overhead 的定義、重複次數、程式碼是否公開、雲端斷線行為。

**最不確定的三件事**：
1. Fig. 9 到底量了什麼。我只能目視讀圖；圖（Mbps 與目標速率）與正文、Table VII（Kbps 與 client 數）互相衝突，上方「約 70 Mbps」不是作者寫的數字。
2. Detection Time 160–200 ms 的起訖點與是否含網路路徑。「含網路路徑、不是 Suricata 處理延遲」是我依作者對 insider／outsider 差異的解釋做的推測。
3. Pi 是否真的轉送他人封包。全文沒寫 ip_forward、NAT 或 bridge；「應用層終結節點」是依 Fig. 4 與 HTTP POST 的描述推論。

另外 D9 沒有做網路查詢，建議追加閱讀的存在確認只到「上一輪已查證 DOI」或「引用字串」。
