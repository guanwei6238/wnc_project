# 資料集與工具調查：有沒有現成資料可以測「延遲攻擊」（同一條 flow 內先正常、後攻擊）

> 撰寫日期：2026-10-20。調查者：資料集搜尋 subagent。
> 脈絡：`SYNTHESIS.md` §0、§3（G2：沒有論文量測「判定後才攻擊」的漏報）、§6（評估設計：延遲攻擊要自建）。
> 評分用的四條可復現準則出自 `slides/20261005_security_gateway_調查進度/查證_可復現準則.md`。
> 本檔所有「沒找到」都只是弱證據（見最後一節）。

---

## 0. 先講結論

1. **沒有找到同時滿足以下三點的現成資料：**（a）同一條 flow／session 內先正常、後攻擊；（b）標籤精確到封包、byte offset 或時間點；（c）有原始 pcap。
   - 有「封包層級標籤」的資料集（Kitsune、Gotham、Payload-Byte 版）不符合 (a)：Kitsune 的攻擊幾乎都是新連線，Gotham 與 Payload-Byte 的封包標籤是由 IP／5-tuple 規則繼承而來，同一個 5-tuple 內標籤恆定（§3.1）。
   - 有「同 flow 長連線攻擊」的資料集（CIC-IDS2017 的 Heartbleed、Slowloris、Web 攻擊）不符合 (b)：只有 flow 級標籤，且標籤依據是「攻擊者 IP＋時間窗」（§3.2）。
2. **結構性原因**：主流資料集的標籤單位是 flow，而且作者常**刻意避開混合**。
   - TRUST Lab（2026）明寫 "Single-Class Session Policy"：每次 capture 只含 benign 或單一攻擊家族，以避免 bi-flow 標籤模糊（§3.2 D16）。
   - Engelen／Liu 的修正是把沒有 payload 的攻擊連線改標 "Attempted"，方向也是讓 flow 標籤更純，不是更細（§3.2 D2）。
3. **最接近需求的組合不是單一資料集，而是「現成骨架＋自建注入」**：
   - CIC-IDS2017 的 Heartbleed 在 Engelen 文件裡是單一 src/dst port、約 20 分鐘（§3.2 D2）。這是現成資料裡最像「一條長連線內 handshake 之後才開始攻擊」的例子，但需填表才能拿 pcap，且只有一個樣本。
   - ID2T 提供「注入＋標籤檔」的流程，但依它的 Merger 描述，注入的是**新 TCP 流**，不是插進既有 flow（§3.5 T1，部分為 `[推測]`）。
   - tcpliveplay、suricata-verify 可作自建實驗的零件與 Suricata 行為驗證（§3.5、§3.6）。
4. **「attack position within flow」沒有找到專門論文**（§3.7）。
5. **建議自建**，並盡量沿用現有工具；理由與方案見「結論：要不要自建」。

---

## 1. 判讀方式

### 1.1 四條可復現準則（簡寫）

| 準則 | 意思 | 本檔怎麼評 |
|---|---|---|
| 1 | 原始資料可持久取得、有授權（ACM Artifacts Available、FAIR F1/A1/R1.1） | ✓ 有公開來源＋授權＋持久識別碼（DOI 或等價）；△ 缺其中一項；✗ 取不到原始資料 |
| 2 | 標籤可追溯到原始流量（Engelen (g)、Gebru §3.4） | ✓ 標籤規則明確且能對回封包；△ 只能由 IP／時窗等粗規則對回；✗ 無原始流量可對 |
| 3 | 產生過程有完整紀錄（FAIR R1.2） | ✓ 有論文＋腳本／設定；△ 只有論文或網頁描述 |
| 4 | 處理流程可重做（ACM Functional） | ✓ 有公開程式碼且我確認它對應資料；△ 有程式碼但未驗證或有缺漏；UNCLEAR 未能判斷 |

符號：✓／△／✗／UNCLEAR（無法判斷，通常因為沒打開關鍵頁面或資料）。

### 1.2 證據標記

- `[原文]`：我讀到該資料集官網、論文全文或 repo 原文。
- `[摘要]`：只讀到摘要或簡介頁。
- `[二手]`：來自別的論文或搜尋結果摘要對它的描述。
- `[推測]`：我的判斷，不是來源寫的。
- `[實測]`：我自己對公開檔案跑 tshark／API 等得到的結果。
- `未能確認`：沒打開或打不開。

### 1.3 取得限制與下載紀錄

- **登記表單**：CIC 系列（CIC-IDS2017、CICIoT2023、ISCX-IDS-2012、CIC Modbus 2023）的官方下載點都是 `cicresearch.ca` 的表單，要填姓名、Email、機構、職稱、國家 `[實測]`。**我沒有填，也沒有找鏡像**，所以這些資料集的 pcap 我都沒拿到；表中標「未取得 pcap」。
- **實際保存的檔案**：約 30 MB（論文 PDF、小型 pcap、README、目錄清單；位於 scratchpad 與 WebFetch 的暫存目錄，不在專案內）。其中唯一的 pcap 是 2.4 MB 的 `CTU-Manual-Capture-Attack-1` Heartbleed，用 tshark 看 TCP 連線。
- **一次超量的網路傳輸**：我用 `curl -r 0-0` 探測 UCI Kitsune 的 17.7 GB zip 是否支援 Range，伺服器忽略 Range 並開始串流，我在 30 秒逾時前收到並丟棄（寫到 `/dev/null`）約 282 MB。硬碟上沒有留下這些資料，但**網路傳輸量超過你設的 200 MB 上限**，這是我的疏失，之後沒有再對該伺服器做探測。
- 其餘 Range 讀取都用在 Zenodo／UPCT 的 zip 目錄與 README，每次數 MB 以內。

---

## 2. 總覽表

「同 flow 延遲攻擊」欄：是＝資料本身就含此結構並可定位；部分＝有類似結構但標籤不足以定位；否＝沒有。

### 2.1 資料集

| # | 名稱 | pcap | 標籤粒度 | 同 flow 延遲攻擊 | 取得／授權 | 準則 1／2／3／4 | 證據 |
|---|---|---|---|---|---|---|---|
| D1 | CIC-IDS2017（原版） | 有（未取得） | flow（IP＋時窗） | 部分（Heartbleed 單連線、Slowloris、Web keep-alive） | 填表；授權未明載 | △／△／△／✗ | [原文] |
| D2 | CIC-IDS2017 improved（Engelen WTMC'21、Liu CNS'22） | 無（需另取原版 pcap） | flow（附 Attempted 類），規則寫到微秒時窗 | 同 D1 | 大學主機 zip；無授權 | △／✓／✓／✓ | [原文] |
| D3 | LYCOS-IDS2017 | 未能確認 | flow | 未能確認 | 找到 TIB 紀錄與 DOI，未打開 | UNCLEAR | [二手] |
| D5 | CSE-CIC-IDS2018（＋Liu improved） | 有（每天 38–59 GB） | flow | 部分（同 D1 類攻擊） | 公開 S3；可轉散布須引用 | △／△／△／原版 ✗、improved ✓ | [原文] |
| D6 | UNSW-NB15 | 有（約 100 GB） | flow（GT 表） | 未能確認 | 學術永久免費 | △／△／△／UNCLEAR | [摘要] |
| D7 | UNSW-NB15 & CIC-IDS2017 Labelled PCAP（Payload-Byte） | 無（僅 CSV，含 payload bytes） | 封包，但由 flow 標籤繼承 | 否 | Zenodo DOI，CC BY 4.0 | ✓／△／△／✓ | [原文] |
| D8 | Kitsune Network Attack Dataset | 有（截成 200 B／封包） | **封包** | 部分（見 §3.1） | UCI DOI，CC BY 4.0 | ✓／△／△／UNCLEAR | [原文] |
| D9 | Gotham Dataset 2025 | 有 | 封包列，但規則為 IP／port／proto | 否 | Zenodo DOI，CC BY 4.0 | ✓／△／✓／✓ | [原文] |
| D10 | CIC Modbus 2023 | 有（未取得） | 攻擊事件（時戳＋TransactionID），非封包 | 部分（Modbus 長連線，OT） | 填表；可轉散布須引用 | △／△／△／UNCLEAR | [原文]＋[二手] |
| D11 | 2017-SUEE（慢速 DoS） | 有，只有標頭 | 封包，依攻擊者 IP | 否 | GitHub release；無授權 | △／△／△／△ | [原文] |
| D12a | USB-IDS-1 | 頁面只列 CSV | flow | 否 | 公開頁面；授權未見 | ✗／UNCLEAR／UNCLEAR／UNCLEAR | [原文] |
| D12b | CIC DoS 2017（慢速） | 頁面稱無法取得 | — | — | 頁面寫 "not available at this time" | ✗／—／—／— | [原文] |
| D13 | CTU-13 | 僅 botnet-only pcap | NetFlow flow | 否 | 公開；授權未明載 | △／△／✓／△ | [原文] |
| D14 | Stratosphere MCFP（411 個 botnet capture＋Normal／Mixed） | 有（單檔可達 GB） | 依 capture 而異：Argus flow、部分有 HTTP request 級 weblog | 否（抽驗 n=2） | 公開索引；授權未見 | △／△／✓／△ | [原文]＋[實測] |
| D15 | HIKARI-2021 | 有（Zenodo 內 GB 級 pcap） | flow（5-tuple 規則） | 否 | Zenodo DOI，CC BY 4.0 | ✓／△／✓／✓ | [原文] |
| D16 | TRUST Lab dataset（2026） | **不公開**（可申請） | flow，單類 session | 否（刻意排除） | UPCT DOI，CC BY 4.0 | △／✗／✓／△ | [原文] |
| D17 | DARPA 1999 | 有（tcpdump） | 攻擊實例（秒級起訖＋受害者） | 未能確認 | 直接下載；授權未見 | △／△／✓／UNCLEAR | [原文] |
| D18 | 其他（CICIoT2023、TII-SSRC-23、Edge-IIoTset、ISCX-IDS-2012、ISCX Botnet 2014、MAWILab、Bot-IoT） | 見 §3.8 | 多為 flow | 否 | 見 §3.8 | 見 §3.8 | 混合 |

### 2.2 工具與測試套件

| # | 名稱 | 用途 | 注入位置 | 標籤輸出 | 授權 | 準則 1／2／3／4 | 證據 |
|---|---|---|---|---|---|---|---|
| T1 | ID2T（含 WTMC'24 Gen 2） | 把合成攻擊合併進背景 pcap | 指定時戳；攻擊是**新 TCP 流** | XML：攻擊首尾封包時戳 | MIT | △／△／✓／△ | [原文] |
| T2 | FLAME（USENIX CSET'08） | 往 flow trace 注入異常 | flow 層，無 payload | flow trace | GPL，「向作者申請」 | ✗／—／△／— | [原文] |
| T3 | SAIBERSOC（ACSAC'20） | 對 SOC 重播攻擊 pcap | trace 層（tcpreplay） | 由攻擊庫 metadata | 開源，授權未確認 | △／UNCLEAR／△／UNCLEAR | [摘要]＋[二手] |
| T4 | tcpreplay 套件（tcprewrite、tcpliveplay） | 重放／改寫 pcap；tcpliveplay 對真實伺服器重放單一 TCP session | tcpliveplay：整條 session | 無 | GPL-3.0 | ✓／—／✓／✓ | [原文] |
| T6 | HTTP Evader（App::DubiousHTTP） | 產生怪異 HTTP 回應測 IDS／防火牆，可輸出 pcap | 單一回應內 | 測試案例 ID | 倉庫未標授權 | △／—／✓／✓ | [原文] |
| T7 | PYROLYSE（RAID'25） | 窮舉 IP／TCP 重疊重組測試，含 Snort／Suricata／Zeek | 重組層 | 各實作的行為描述 | Apache-2.0／MIT | ✓／—／✓／△ | [原文]＋[摘要] |
| T8 | suricata-verify（OISF） | Suricata 回歸測試，約 1.6 千個 pcap 相關檔 | 各測試自帶 | 預期的 eve.json 檢查 | MIT | ✓／✓／✓／✓ | [原文] |

---

## 3. 逐項記錄

### 3.1 封包層級標籤的 IDS 資料集

#### D8 Kitsune Network Attack Dataset（最接近「封包層級標籤＋先正常後攻擊」）
- 來源：<https://archive.ics.uci.edu/dataset/516/kitsune+network+attack+dataset>，DOI 10.24432/C5D90Q；論文 Mirsky et al., NDSS 2018（arXiv:1802.09089）。
- 存在確認：頁面與論文都讀到 `[原文]`（論文下載後以 pdftotext 檢視 Table III）。
- 內容：9 種攻擊（OS Scan、Fuzzing、Video Injection、ARP MitM、Active Wiretap、SSDP Flood、SYN DoS、SSL Renegotiation、Mirai），約 2,720 萬筆。每個攻擊一個資料夾，含 `*_pcap.pcapng`、`*_dataset.csv`（每列一個封包，115 個特徵）、`*_labels.csv`（每個封包一個 0／1）。
- pcap：有，但**每個封包截成 200 bytes**（頁面寫為了隱私）。所以 payload 簽章型 IDS（Suricata）看不到完整內容。
- 標籤粒度：封包。頁面寫 "Every capture starts with benign traffic before the attacker connects and launches the attack"，MitM 類是「經過攻擊者的封包全標 1」。
- 同 flow 延遲攻擊：**部分，且未驗證**。
  - Video Injection（"injects a recorded video clip into a live video stream"）與 ARP MitM／Active Wiretap 會改變既有連線的路徑，抓包點在 router，攻擊開始前就存在的長連線理論上會跨過攻擊起點 `[推測]`。
  - 其餘多為新連線（掃描、flood）。
  - 攻擊類型偏異常偵測（時序、速率），不是 Suricata 簽章能抓的內容。
- 授權與取得：CC BY 4.0；整包 17.7 GB zip，或 `ucimlrepo`。**我沒有下載**，所以無法確認 pcap 內是否真的有跨攻擊起點的 flow。
- 準則：1 ✓（DOI＋授權）；2 △（有 per-packet 標籤檔，但 UCI 頁面與論文都沒寫標籤如何產生）；3 △（NDSS 論文描述 testbed）；4 UNCLEAR（沒找到標籤腳本）。
- 對我們：它是少數**原生就有 per-packet 標籤**的公開 pcap，可以拿來驗證「從標籤推 offset」的流程；但攻擊類型與 payload 截斷讓它難以測 Suricata。

#### D9 Gotham Dataset 2025
- 來源：<https://zenodo.org/records/14502760>，DOI 10.5281/zenodo.14502760；論文 arXiv:2502.03134；標籤程式 <https://github.com/othmbela/gotham-network-packet-labeller>（Apache-2.0，最後 push 2026-08-23）。
- 存在確認：Zenodo API、論文、GitHub 原始碼都讀到 `[原文]`；用 Range 讀 zip 目錄（198 筆）。
- 內容：78 個虛擬 IoT 裝置的介面層擷取；原始 pcap＋逐封包 CSV（23 個特徵＋label）；攻擊含 Mirai、**Merlin C2（HTTP/1.1、HTTP/2、HTTP/3）**、掃描、CoAP amplification。總計 23.8 GB zip。
- 標籤粒度：CSV 每列一個封包。**但實際規則是 IP／port／protocol 比對**（`labeller.py` 的 `label_malicious_traffic_by_ip`，用 `ip.src`、`ip.dst` 正則，可選 `tcp.srcport/dstport`、`ip.proto`，沒有任何時間條件）`[原文]`。論文文字說 "timing synchronisation strategy"、"packets within the corresponding time window were labelled as malicious"，與程式碼不一致。
- 同 flow 延遲攻擊：**否**。每個 pcap 是單一情境，同一組 IP 的封包標籤恆定。Merlin 的 metadata 只有 `Merlin C&C Communication` 與三種 flooding 的 IP 規則。
- 授權與取得：CC BY 4.0，公開下載。
- 準則：1 ✓；2 △（規則可審，但與論文敘述不一致）；3 ✓；4 ✓（程式碼＋metadata 在 GitHub）。
- 缺漏：README 與論文都說 `raw/metadata/*.json` 在資料集內，**zip 目錄裡沒有 `raw/metadata/`**（只有 `raw/benign`、`raw/malicious/*`、`processed/`）。metadata 要去 GitHub 取。
- 對我們：C2 家族可作為「長期 C2 flow」的流量來源，但沒有「前段 heartbeat、後段指令」的封包級切點。

#### D7 UNSW-NB15 and CIC-IDS2017 Labelled PCAP Data（Payload-Byte）
- 來源：<https://zenodo.org/records/7258579>，DOI 10.5281/zenodo.7258579；工具 <https://github.com/Yasir-ali-farrukh/Payload-Byte>（MIT，最後 push 2024-07-12）。
- 存在確認：`[原文]`。
- 內容：兩個 CSV（CIC-IDS2017 4.9 GB、UNSW-NB15 270 MB），每列一個封包，Nx1504 整數（含 payload bytes）。**記錄內沒有 pcap**。
- 標籤粒度：封包，但頁面寫 "Each packet is labelled by comparing the eight distinct features"（源／目的 IP、port、起訖時間、protocol、TTL）與原 CSV 比對。也就是**封包標籤是從 flow 標籤繼承**，不是獨立的封包級 ground truth。
- 同 flow 延遲攻擊：否。
- 授權：CC BY 4.0。
- 準則：1 ✓（但無 pcap）；2 △；3 △（細節指向論文）；4 ✓（`Pipeline.ipynb`，需要原 pcap 與 CSV）。
- 另有 Hugging Face `rdpahalavan/nids-datasets` 的封包級子集 `[二手]`，未打開。

#### D10 CIC Modbus Dataset 2023
- 來源：<https://www.unb.ca/cic/datasets/modbus-2023.html>；下載 <http://cicresearch.ca/CICDataset/CICModbusDataset2023/>（表單）。
- 存在確認：官網 `[原文]`；封包級重標資訊來自一篇 2026-05 單作者預印本 arXiv:2605.04250 `[二手]`（我讀了 PDF 文字）。
- 內容：Docker 模擬變電所，pcap（切成 100 MB）＋攻擊日誌 CSV；9 種攻擊（reconnaissance、query flooding、loading payloads、delay response、modify length parameters、false data injection、stacking Modbus frames、brute force write、baseline replay）。日誌欄位含事件時戳、TargetIP、Attack、TransactionID。
- 標籤粒度：官方是**攻擊事件**，不是封包。預印本稱 "provides no packet-level labels"，並說攻擊 capture 中 94% 的流量是 benign polling，所以作者自行用「日誌時窗＋協定規則」重標（例如 brute force 要 `func_code = 5`），得到 10,747,066 normal 與 642,331 attack 封包 `[二手]`。作者自述標籤管線「未經第二位標註者驗證」。
- 同 flow 延遲攻擊：**部分**。Modbus/TCP 是長連線輪詢，攻擊與輪詢共存於同一批 capture，結構最像「既有 session 中途插入攻擊命令」；但這是 OT 協定、模擬環境，離「公司內外網」場景較遠，我也沒有拿到 pcap 驗證是否同一 TCP session。
- 授權：頁面寫可轉散布須引用。取得須填表。
- 準則：1 △；2 △；3 △；4 UNCLEAR（重標規則是第三方預印本，未找到程式碼）。

#### D11 2017-SUEE（HTTP(S) 慢速 DoS）
- 來源：<https://github.com/vs-uulm/2017-SUEE-data-set>；論文 arXiv:1804.06750（Lukaseder et al.）。
- 存在確認：README、release 資產 API `[原文]`。
- 內容：真實 benign 流量（1 天與 8 天）＋三種慢速攻擊（Slowloris、slowhttptest、slowloris-ng，各 50 個攻擊者）。SUEE1.pcap 163.7 MB、SUEE8.pcap 1.87 GB（release v1.1）。
- pcap：**只有標頭，沒有 application layer payload**（論文 "contain only header data"），IP 已匿名化。
- 標籤：依攻擊者 IP 範圍（README 另警告兩個 IP 被重複使用）。
- 同 flow 延遲攻擊：否（攻擊是獨立連線）。對 Suricata 無用（無 payload）。
- 授權：未標示。
- 準則：1 △；2 △；3 △；4 △。

#### 其他有「封包層級」字樣但不符合的
- **MAWILab**：pcap 只有 TCP/IP 標頭、無 payload；標籤是以 IP／port 描述的異常流量集合 `[二手]`（HIKARI 論文與 arXiv:1810.01945 的描述；官網憑證錯誤，沒打開）。
- **Bot-IoT**：原始標籤是 flow 級，封包級是別人重標 `[二手]`。
- **CICIoT2023**：官網沒寫標籤粒度，見 §3.8。

---

### 3.2 CIC-IDS 系列與修正版（flow 級標籤）

#### D1 CIC-IDS2017（原版）
- 來源：<https://www.unb.ca/cic/datasets/ids-2017.html>；Sharafaldin et al., ICISSP 2018，doi:10.5220/0006639801080116。
- 存在確認：官網 `[原文]`；下載點 `https://cicresearch.ca/CICDataset/CIC-IDS-2017/` 是表單 `[實測]`。
- 內容：5 天；頁面寫含 "full packet payloads in pcap format"；另有 MachineLearningCSV。攻擊時程含 Heartbleed（週三 15:12–15:32）、DoS Slowloris（9:47–10:10）、Slowhttptest（10:14–10:35）、Web 攻擊與 Infiltration。
- 標籤粒度：flow。頁面寫以 timestamp、IP、port、protocol 與攻擊類型標記。
- 授權：頁面沒有授權條款，只寫 "publicly available for researchers" 並要求引用。
- 準則：1 △（有 pcap、需填表、無授權、無 DOI）；2 △（Engelen 發現文件上的時窗「不精確」，得自行調整才能重現標籤）；3 △；4 ✗（Engelen 致謝向 Jin Li "providing us with the labelling code"，顯示公開管道沒有這份程式 `[推測]`）。
- 同 flow 延遲攻擊：見 D2。

#### D2 CIC-IDS2017 improved（Engelen et al. WTMC／SPW 2021；Liu et al. CNS 2022）
- 來源：
  - WTMC 版：<https://intrusion-detection.distrinet-research.be/WTMC2021/>，doi:10.1109/SPW53761.2021.00009。
  - CNS 版：<https://intrusion-detection.distrinet-research.be/CNS2022/>，IEEE 9947235。
  - 資料 zip：`/CNS2022/Datasets/CICIDS2017_improved.zip`（328 MB）、`CSECICIDS2018_improved.zip`（9.7 GB）`[實測]`。
  - 程式碼：<https://github.com/GintsEngelen/CNS2022_Code>（labelling notebooks）、<https://github.com/GintsEngelen/CICFlowMeter>（修正版）。
- 存在確認：論文全文、官網、GitHub `[原文]`。
- 它修了什麼：
  - CICFlowMeter 在第一個 FIN 就結束 flow，造成 "TCP appendices"，占整個資料集 25.9%。
  - 沒有 payload 的攻擊連線改標 "X - Attempted"（Attack Startup/Teardown Artefact、Target System Unresponsive 等類）。
  - Hulk 工具把 Connection 設成 close，攻擊其實沒有發揮效果。
- 標籤粒度：**flow**。每種攻擊的規則寫成「Src IP／Dst IP／Dst Port／Src Port 集合／Total Length of Fwd Packets／起訖 UTC 時間（到微秒）」。
- 與我們有關的細節（文件原文）：
  - **Heartbleed**：Src 172.16.0.1 port 45022 → 192.168.10.51:444，2017-07-05 18:12:15.650811 至 18:32:43.294455 UTC，"The attack involves a single src/dst port"。
  - **Slowloris**：12:48:54–14:20:08 UTC；例外：12:48:46 的 "early launch" 只送了第一個部分 GET 就關閉，標為 Attempted。
  - **Web Brute Force**：一類 flow 是 "Total Fwd Packet = 204, Total Bwd Packets = 105"，內含多次登入嘗試（keep-alive 長 flow）；文件另說 "One seemingly normal GET request would be interlaced with a flow containing brute force attempts"。
  - **XSS**：標籤規則含 `Total Fwd Packets >= 150`，也是多請求連線。
- 同 flow 延遲攻擊：**部分，但只能從連線內部切**。
  - Heartbleed 在表 I 是 11 筆 flow、同一 src port、約 1,228 秒。**我推測** 這是同一條 TCP 連線被 CICFlowMeter 的 120 秒 timeout 切成 11 列 `[推測]`，因為 1228/120 ≈ 10.2。若成立，這條連線前面是 TLS handshake（正常），之後全是 heartbeat 攻擊；TLS record header 的 content type 24（heartbeat）在加密後仍是明文，所以切點可以用 tshark 找。需要拿到 pcap 才能驗證。
  - 其餘攻擊在連線內從頭到尾都是攻擊，沒有「先 benign 請求再攻擊請求」的標示。
- 授權與取得：improved zip 沒有授權條款；程式碼 repo 授權欄為 NOASSERTION／空。原始 pcap 仍須向 CIC 填表取得。
- 準則：1 △；2 ✓（規則逐條公開）；3 ✓（逐攻擊文件）；4 ✓（CICFlowMeter fork＋notebook，README 步驟含 `pcapfix`、`reordercap`）。
- 同系列的 Lanvin et al., CRiSIS 2022（HAL hal-03775466，doi:10.1007/978-3-031-31108-6_2）：報告封包順序錯亂、封包重複、有執行但沒標到的攻擊 `[二手]`（只讀到摘要與引用該文的論文；全文未打開）。

#### D3 LYCOS-IDS2017
- Rosay et al., "From CIC-IDS2017 to LYCOS-IDS2017"（WI-IAT 2021，HAL hal-03508406）與 ICISSP 2022 版（doi:10.5220/0010774000003120，HAL hal-03563228）。
- 內容：用自家 LycoSTand 重抽 CIC-IDS2017 的流，修 TCP 結束問題；83 個特徵、約 1,837,498 筆 flow `[二手]`。
- 標籤：flow。pcap：未能確認。
- 取得：TIB 紀錄 DOI 10.57702/dgn75y2q，該頁被 Anubis 擋，沒打開；LycoSTand 的 GitHub 網址我沒找到。
- 準則：UNCLEAR。

#### D5 CSE-CIC-IDS2018（及 Liu improved）
- 來源：<https://www.unb.ca/cic/datasets/ids-2018.html>；S3 `s3://cse-cic-ids2018`。
- 存在確認：官網 `[原文]`；我用 S3 公開 ListBucket 直接列目錄 `[實測]`（42 個物件，合計 486 GB）。
- pcap：有。每天 `pcap.zip` 39–59 GB（週二為 `.rar` 44 GB）；`logs.zip` 約 0.15–0.24 GB；`Processed Traffic Data for ML Algorithms/` 為 CICFlowMeter CSV。
- 標籤：flow（官網："label the data per flow"）。
- 授權：頁面明寫 "You may redistribute, republish, and mirror ... in any form"，須引用。
- 同 flow 延遲攻擊：部分（同 D1 類攻擊：Slowloris、SlowHTTPTest、Heartbleed、Web、infiltration），未檢視 pcap。
- 準則：1 △（公開＋授權，無 DOI，量太大）；2 △；3 △（Liu 發現大量未記載錯誤）；4 原版 ✗、improved ✓（同 D2）。

#### D6 UNSW-NB15
- 來源：<https://research.unsw.edu.au/projects/unsw-nb15-dataset>。
- 存在確認：官網 `[摘要]`。
- 內容：tcpdump 100 GB 原始 pcap；Argus／Bro 衍生 49 特徵；GT 表 `UNSW-NB15_GT.csv` 與事件表 `UNSW-NB15_LIST_EVENTS.csv`；九類攻擊。
- 標籤粒度：頁面沒寫。CIC 的 UNSW-NB15 Augmented 頁面（<https://unb.ca/cic/datasets/cic-unsw-nb15.html>）寫它用 5-tuple 比對 GT，多筆時比時戳 `[二手]`。我沒拿到 GT 檔，**欄位名稱未能確認**。
- 授權：學術研究 "free use ... in perpetuity"，商用須與作者協議。
- 準則：1 △；2 △；3 △；4 UNCLEAR。

---

### 3.3 長連線、多請求、慢速攻擊

除了 D1／D2（Slowloris、Slowhttptest、Heartbleed、Web 攻擊）與 D11（2017-SUEE）之外：

#### D12a USB-IDS-1
- 來源：<https://idsdata.ding.unisannio.it/usbids1.html>（Catillo et al.，University of Sannio）。
- 內容：17 個壓縮 CSV（Hulk、TCPFlood、Slowloris、Slowhttptest 各搭 4 種 Apache 防禦模組，加一份 REGULAR）。**頁面只列 CSV**，沒有 pcap。
- 補充：同組後續頁面（Behind v2）指出 slowhttptest 有 bug，使其流量特別容易辨認 `[二手，搜尋摘要]`。
- 準則：1 ✗（無 pcap）；2–4 UNCLEAR。

#### D12b CIC DoS dataset 2017
- 來源：<https://www.unb.ca/cic/datasets/dos-dataset.html>。頁面寫 "We apologize, this dataset is not available at this time." `[原文]`。
- 內容描述：4 類工具、8 個應用層 DoS trace、與 ISCX-IDS 的無攻擊流量混合；聚焦 slow send 與 slow read。
- 準則：1 ✗。

---

### 3.4 C2 beaconing 與長期 malware capture

#### D13 CTU-13
- 來源：<https://www.stratosphereips.org/datasets-ctu13>（García et al., Computers & Security 2014）。
- 存在確認：官網 `[原文]`。
- 內容：13 個情境；**只公開 botnet-only 的 pcap，完整 pcap（含背景與 normal）因隱私不公開**；標籤寫在雙向 NetFlow（`.biargus`）裡，三類：Background、Botnet（C&C Channels）、Normal。
- 取得：`CTU-13-Dataset.tar.bz2`（1.9 GB）或逐一 capture；官網為準，另有 mega.nz 備份。授權未載，要求引用。
- 同 flow 延遲攻擊：否（flow 級，C&C 通道整條標為 Botnet）。
- 準則：1 △；2 △；3 ✓；4 △。

#### D14 Stratosphere MCFP（Malware Capture Facility Project）
- 來源：<https://mcfp.felk.cvut.cz/publicDatasets/>。
- 存在確認：我抓了根目錄索引與 411 個 `CTU-Malware-Capture-Botnet-*` 子目錄的檔案清單 `[實測]`。
- 內容：411 個 capture 中 407 個有 pcap；多數另有 Argus（biargus／binetflow）、Zeek（bro/）、Suricata（suricata/）等衍生檔；README 記錄感染時間線與主機 IP；58 個 capture 附 `ralabel.conf`／`ralabel-filters.conf` 標籤規則。
- 其中 113 個 capture 另有 `*.mitm.weblog` 檔（以目錄索引裡的實際檔案連結計算；不能用全文搜尋，因為 README 範本文字會在沒有該檔的 capture 也提到它）：README 說它是 "HTTP and HTTPS web log that includes Labels"，並有 `id` 欄 "unique for all the weblogs generated inside the same TCP connection ... all of them are assigned the same Id"，也就是**單一 TCP 連線內的每個 HTTP 請求各有一列與標籤** `[原文]`。
- 我抽驗 `CTU-Malware-Capture-Botnet-206-1` 的 weblog（12 列，4.2 KB）：連線 id 3、5 各含 2 個請求，**全部標 `CTU.206.1.Malicious`**（含對 microsoft.com 的連線檢查）`[實測]`。這是感染主機的所有流量都標惡意，沒有「前段 benign、後段惡意」的轉換。只抽驗 2 個 capture，不能推論全體。
- pcap 大小：該 capture 的 pcap 1.1 GB，biargus 307 MB，weblog 只有 4.2 KB。
- 同 flow 延遲攻擊：否（抽驗範圍內）。
- 另有 `CTU-Manual-Capture-Attack-1`：2014-04-12 Heartbleed 手動實驗，pcap 2.4 MB，README 寫攻擊腳本是「無限迴圈」，同時有人登入 Dradis 網頁。我用 tshark 看：3069 封包／268 秒，TCP 連線全是 10.0.0.42 → 10.0.0.40:3004，大量連線各 23 封包、約 5 秒，**每次 exploit 都是一條新連線** `[實測]`。無標籤檔，只有 README 時間線。所以它不是同 flow 案例。
- 準則：1 △（公開索引、無授權、無 DOI）；2 △（部分 capture 有標籤設定檔，只驗了 2 個 capture）；3 ✓（我看過的 capture 都有 README 與時間線）；4 △。
- IoT-23 衍生自 MCFP，本機另有 subagent 處理，這裡不重複。

#### 其他 C2 資料
- **Gotham Merlin**（D9）：IP 規則標籤，見上。
- **TRUST Lab C2Beaconing**（D16）：以多個短 `curl`／`dig`／`mosquitto_pub` 呼叫產生，每個 beacon 一條連線 `[原文：Scripts/C2-Beaconing.sh]`。
- **Cobalt Strike 標籤資料**：搜尋只找到 arXiv:2609.27311（2026-09，用 malware-traffic-analysis.net 的 64 個 pcap、以公開 IOC 清單標 flow），我只讀到 PDF metadata，內文未能確認。工具面有 dissect.cobaltstrike 的 `beacon-pcap`（解密用，非資料集）。

---

### 3.5 把攻擊注入背景流量的工具與方法

#### T1 ID2T（Intrusion Detection Dataset Toolkit）
- 來源：<https://github.com/tklab-tud/ID2T>（MIT，68 stars，最後 push 2023-06-22）；論文 Cordero et al., arXiv:1905.00304（ACM 版 doi:10.1145/3424155）；Gen 2：Farah, Nielsen, Vasilomanolakis, WTMC 2024，doi:10.1109/EuroSPW61312.2024.00042。
- 存在確認：repo、README、論文全文、DTU 版 Gen 2 論文都讀到 `[原文]`。
- 機制：輸入背景 pcap＋攻擊參數；Attack Controller 先產生**暫存的攻擊 pcap**，Merger 再 "merging that file with the input PCAP according to the timestamps of the packets"。輸出：注入後的 pcap、統計報告（TIDED）、XML 標籤檔（攻擊名稱＋起訖封包時戳）。
- master 分支的攻擊模組（`code/Attack/`）：DDoS、EternalBlue、FTPWinaXe、JoomlaRegPriv、MS17Scan、Memcrashed、P2PBotnet、Portscan、SMBLoris、SMBScan、SQLi、SalityBotnet。Gen 2 論文新增的 Log4Shell、Confluence、Droopescan 類攻擊**不在 master 的 Attack 目錄**（我查了 tree 與 `gh search code`），分支內是否有未能確認。
- 與我們的關鍵差異：**攻擊是新的 TCP 流**（自己的 IP、ephemeral port），位置由時戳參數決定。論文與 README 都沒有「把攻擊接進背景裡既有 TCP 連線」的功能。這是我從文件缺席得出的判斷 `[推測]`。
- 有用的點：Gen 2 論文描述了「動態產生 payload 時同步調整 TCP SEQ／ACK」（維持有效 TCP stream），以及 multi-stage 類的 "momentary sleep" 參數（時間型規避）；這些是自建時可參考的做法。論文也自承注入會留下 artifact，並提供 TIDED 檢查背景流量缺陷。
- 準則：1 △（GitHub 開源，無 DOI 封存）；2 △（標籤是時戳區間，不是逐封包）；3 ✓；4 △（Travis CI 徽章，維護狀態未確認）。

#### T2 FLAME
- 來源：Brauckhoff, Wagner, May, USENIX CSET 2008（<https://www.usenix.org/legacy/event/cset08/tech/full_papers/brauckhoff/brauckhoff_html/>）。
- 內容：往 **flow trace** 注入 additive／subtractive／interactive 三類異常（NetFlow v5 風格結構）；沒有 payload。
- 取得：論文寫 "available under the GNU GPL upon request from the authors"；Cordero 的調查說已停止維護且不公開 `[二手]`。
- 對我們：沒有 payload、沒有封包，無法用。準則 1 ✗。

#### T3 SAIBERSOC
- 來源：Rosso et al., ACSAC 2020，arXiv:2010.08453；成品在 gitlab.tue.nl。
- 內容：用 MITRE ATT&CK 程序對營運中的 SOC 注入合成攻擊；搜尋摘要稱以 tcpreplay 重播攻擊 pcap、可選擇同時重播背景 `[二手]`。摘要頁沒寫 ground truth 與授權細節，我沒開 repo。
- 對我們：目標是評估 SOC，不是逐封包標籤；層級是 trace，不是 session 內。

#### T4 tcpreplay 套件（tcprewrite、tcpliveplay）
- 來源：<https://github.com/appneta/tcpreplay>（GPL-3.0，2026-08 仍有更新）；<https://tcpreplay.appneta.com/tools/tcpliveplay/>。
- 存在確認：文件頁與 repo 目錄（`tcpliveplay.c`、`tcpedit/`）`[原文]`。
- `tcpliveplay`：把一條已擷取的 TCP session 重播給**真實伺服器**，做真正的三向交握，追蹤 SEQ／ACK 並改寫位址與 port，使客戶端流量成為與目標的活對話；文件寫只適用單一 session 的 pcap。
- 對我們：它是自建「同一條真實 TCP 連線內先送正常請求、再送攻擊請求」的候選零件之一（另一條路是 scapy／自寫 client）；標籤要自己記錄。準則 1 ✓、3 ✓、4 ✓。

#### 其他注入類
- **Payload-Byte**（D7）是標籤工具，不是注入工具。
- **PCAP-Backdoor**（arXiv:2501.15563）：針對 ML 後門投毒的觸發封包產生器，與 IDS 評測目標不同，未深入。

---

### 3.6 IDS 規避資料與測試套件

#### T6 HTTP Evader（App::DubiousHTTP）
- 來源：<https://noxxi.de/research/http-evader.html>；<https://github.com/noxxi/p5-app-dubioushttp>（94 stars、179 commits，最後 push 2023-09-18；GitHub 授權欄空白）。
- 存在確認：文章與 README `[原文]`。
- 內容：用 EICAR 測試檔，經各種怪異 HTTP 回應（HTTP/0.9、deflate、chunked、雙重壓縮、gzip、空白、borderline robustness 等十類技術）測防火牆／IDS 是否漏檢；README 寫 `dubious_http.pl` 可當測試伺服器，也可 "generate pcap-Files containing the dubious HTTP traffic" 供離線分析。NSS Labs 的文章說它在私下的 NGFW 測試中用此工具（EICAR＋各種 HTTP 規避）做了 700 多個案例；公開測試改用自製的 Evader++ 子集，10 家廠商中 6 家至少漏掉 26 個案例中的一個 `[二手]`。
- 與延遲攻擊的關係：它測的是**同一個回應內的編碼歧義**，不是「攻擊出現在連線後段」。但 chunked、gzip、keep-alive 等語意是 Suricata 在 bypass／depth 之後仍要維持的狀態，可作為「信任判定後是否仍能看懂內容」的壓力測試。
- 範圍限制：頁面寫針對**客戶端防火牆**（惡意檔在 HTTP 回應中），不是 WAF。
- 準則：1 △（無授權）；2 —；3 ✓；4 ✓。

#### T7 PYROLYSE 與重疊資料論文
- 來源：Aubard et al., RAID 2025，arXiv:2508.00735；<https://github.com/ANSSI-FR/pyrolyse>（Apache-2.0／MIT 雙授權）。另有 arXiv:2504.21618（OS 與 NIDS 的重組差異；預印本）。
- 內容：窮舉最多三個重疊 chunk 的 IPv4／IPv6／TCP 測試案例，測 23 種實作，含 Snort、Suricata、Zeek；摘要稱所有受測 NIDS 仍易受重疊式規避與插入攻擊。
- 我沒確認：repo 是否直接釋出 pcap（README 只提到 `test_data`、`ws` 目錄）、Suricata 7.0.x 的具體結果。
- 與延遲攻擊的關係：測重組層面的規避，不是時間位置。可用來確認 Suricata stream 引擎在重疊資料下的行為。準則 1 ✓；3 ✓；4 △。

#### T8 suricata-verify（OISF）
- 來源：<https://github.com/OISF/suricata-verify>（MIT，2026-10-19 仍在更新）。
- 存在確認：repo tree（11,481 個檔案，約 1,632 個含 `.pcap` 的路徑）與 `bypass-depth-enabled/test.yaml` `[原文]`。
- 與我們直接相關的測試目錄：`bypass-depth-enabled`／`-disabled`、`stream-depth-reached-event`、`stream-depth-ack-tracking`、`bypass-tls-*`、`bypass-ssh-enabled`、`live/tests/ips-local-bypass-nfq`、`live/tests/nfq-ips-bypass`、`alert-testmyids-midstream*`、`http-pipeline-files-with-gap`、`bug-3286-*-evasion`。
  - 例：`bypass-depth-enabled` 設定 `stream.reassembly.depth=1`、`stream.bypass=true`，檢查 `flow_bypassed.local_pkts: 11`。
- 性質：**行為驗證用**，每個測試是 pcap＋預期輸出的檢查，不是帶 ground truth 的 IDS 資料集。用途是確認「Suricata 在 depth 或 bypass 之後對同一條 flow 做什麼」，與我們使用 Suricata 的實作假設對應。
- 準則：全 ✓。

#### L1 Grashöfer et al. 2020（DPD 規避）
- arXiv:1912.03962（IEEE CNS 2020）。已在 `SYNTHESIS.md` 與 `pdfs/search/` 內。這次搜尋沒有找到它釋出 pcap 或 PoC 程式（搜尋結果只有論文本身）。未能確認。

#### L2 NIDS 規避經典論文
- Handley, Paxson, Kreibich, USENIX Security 2001 與 Ptacek & Newsham 1998：這次只由搜尋結果確認論文存在與討論範圍（"closing a session the target never closes" 等 `[二手]`），沒有逐篇精讀。它們是方法論，不是資料集。

---

### 3.7 「attack position within flow」專門研究

**沒有找到。** 嘗試過的查詢見最後一節。

最接近但不夠的：
- Kučera 2018、Papadogiannakis 2010（`SYNTHESIS.md` §0 第 2 點）：只量「告警保留比例」，不是攻擊位置分布。
- 2025 年 IoT 早期偵測（arXiv:2506.18114）：標題與摘要談 early detection，沒有攻擊位置的實驗，只讀到搜尋摘要 `[二手]`。
- TRUST Lab（2026）：明確論述 bi-flow 內混合 benign 與 malicious 封包會使單一標籤語意模糊，並因此在資料設計上排除混合 `[原文]`。這等於說明為什麼現有 flow 資料集裡缺這類樣本。

---

### 3.8 其他曾打開、但與需求距離較遠的

| 名稱 | 來源 | pcap | 標籤粒度 | 取得 | 備註 |
|---|---|---|---|---|---|
| CICIoT2023 | <https://www.unb.ca/cic/datasets/iotdataset-2023.html> | 有 PCAP 目錄（未取得） | 官網未寫 | 填表；授權未寫 | 33 種攻擊，Web-based 6 種；官網沒說 benign 是否獨立擷取。`[原文]` |
| TII-SSRC-23 | arXiv:2310.10661；Kaggle | PCAP＋CSV | flow，三層標籤 | Kaggle | 論文說 CSV 有 Label／Traffic Type／Subtype。`[原文：論文片段]` |
| Edge-IIoTset | IEEE DataPort | 有 | 每攻擊一檔 | 需 DataPort 訂閱；學術免費、商用需許可 | 14 種攻擊。`[摘要]` |
| ISCX-IDS-2012 | <https://www.unb.ca/cic/datasets/ids.html> | 有 | 官網未寫 | 填表 | 含 Infiltrating the network from inside、HTTP DoS、DDoS IRC botnet、SSH brute force。`[摘要]` |
| ISCX Botnet 2014 | <https://www.unb.ca/cic/datasets/botnet.html> | — | flow | 頁面稱 "no longer available" | ✗ |
| HIKARI-2021 | doi:10.5281/zenodo.6463389；論文 doi:10.3390/app11177868 | 有（單檔 0.27–7.6 GB） | flow，5-tuple 規則；背景流量經匿名化 | CC BY 4.0，Zenodo | 加密 HTTPS 暴力破解、探測；提供產生攻擊與標籤的腳本。同 flow 延遲：否。`[原文：論文＋Zenodo API]` |
| DARPA 1999 | <https://www.ll.mit.edu/r-d/datasets/1999-darpa-intrusion-detection-evaluation-dataset> | 有（inside／outside tcpdump） | 攻擊實例：`StartTime`、`Duration`、`Destination`（秒級）；同一受害者重疊的 session 被彙總成一筆 | 直接下載，授權未見 | 真值列表 `master-listfile-condensed.txt`（約 2,000 行，含欄位說明），欄位含 `Insider`、`Manual`、`Success`。流量為 1999 年環境，與現代 TLS 為主的流量差距大。是否含 telnet 登入後才攻擊的 session 未能確認 `[原文：真值列表]` |
| Bot-IoT | 搜尋結果 | 有 | flow；封包級為他人重標 | — | `[二手]`，未打開官網 |
| CPTC 2018 | 搜尋結果（Pelletier et al., HICSS 2019） | VM 映像＋約 200 GB JSON 警報 | 事件級 | 未確認 | `[二手]`，未打開 |

---

## 4. 結論：要不要自建

### 4.1 結論

**要自建延遲攻擊資料，但不必從零開始。** 理由：

1. 現成資料沒有同時具備「同 flow 先正常後攻擊」與「封包／byte 級標籤」（§0）。
2. 主流資料集的標籤單位是 flow，且常刻意避免混合；封包級標籤多半從 IP 或 flow 規則繼承（D7、D9），無法當作 offset 的 ground truth。
3. 注入工具現況：ID2T 只能注入新流；沒有找到能把攻擊接進既有 TCP session 並輸出封包級標籤的工具。
4. 自建的好處：切點由生成器記錄，**標籤在構造上就是封包／byte 精確的**，準則 2、3、4 可以直接做到 ✓；缺點是流量不是真實攻擊，要承認合成 artifact（ID2T 論文也有同樣的警告）。

### 4.2 建議的做法（選項，待與你討論後再動手）

| 選項 | 做法 | 取捨 |
|---|---|---|
| A | 以 live server 為對象，用自寫 client（scapy／socket）在**同一條真實 TCP 連線**中先送 k 個正常請求，再送攻擊請求；記錄第 k 個請求的封包編號與 byte offset。`tcpliveplay` 只會重播一條既有 session pcap，不會自己組合「正常＋攻擊」，所以只適合重播已組好的 pcap | 流量是真實 TCP 狀態，Suricata 看到的與實機一致；要自己維護測試伺服器與攻擊 payload 來源 |
| B | 離線 pcap 改寫：取一條正常 keep-alive session pcap，把攻擊 request 接在後面並重算 SEQ／ACK／checksum（可參考 ID2T Gen 2 的 SEQ／ACK 同步做法） | 不需要 live server，可大量批次；細節（TCP 時序、window）容易出錯，需用 tshark／Suricata 驗證流量有效 |
| C | 沿用 CIC-IDS2017 的 Heartbleed 單連線（若 pcap 驗證成立）作為「自然樣本」的 sanity check | 零自建成本但只有一個樣本；需填表取 pcap；標籤是 flow 級，切點要靠 TLS record 手動找 |
| D | 用 suricata-verify 的 depth／bypass／midstream 測試確認 Suricata 對同一 flow 的實際行為，再決定自建資料需要覆蓋哪些情境 | 驗證的是 IDS 行為，不產生資料集 |

[推測] 最小可行路線是 A 或 B 為主、D 先做、C 作交叉檢查。

### 4.3 需要你決定的問題
1. 「攻擊段」的來源：真實 exploit PoC、Metasploit 擷取，還是 CIC／ET 規則附的樣本？
2. 位置參數化單位：第 k 個封包、第 k 個請求、第 k bytes，還是第 k 秒（SYNTHESIS §6 寫「第 k 個封包或第 k 秒」）？
3. 正常 session 的底：自己擷取、IoT-23／CICIDS2018 的真實 HTTP session，還是純合成？
4. 是否需要加密情境（Heartbleed、C2 over TLS）：這會讓 Suricata 看不到 payload，影響要測的 IDS 能力是什麼。

### 4.4 若要把自建資料當論文貢獻，建議附上
- 生成器腳本與參數（準則 4）、每條 session 的切點 manifest（準則 2）、環境版本（Suricata 7.0.10、nftables 版本，準則 3）。
- 公開在有 DOI 的封存庫（準則 1，例如 Zenodo）。

---

## 5. 搜尋了什麼但沒找到

> 「沒找到」只代表在這次搜尋與可存取的頁面裡沒有出現，不代表不存在。

### 5.1 沒找到的東西
- **專門研究「attack position within flow」或「攻擊落在連線哪個位置」的論文。** 查詢包括：attack position／offset within flow、truncated flows first packets miss late attacks、partially malicious flows、delayed attack long-lived connection IDS bypass、prepend benign packets before malicious payload early flow classification evade。回傳的是 NIDS 規避經典（Ptacek–Newsham、Paxson）、TANTRA（時序重塑）、PLAA、Deep PackGen（對抗樣本），沒有針對位置的實驗。
- **公開、有 pcap、同時有 byte offset 或逐封包標籤、且含「同 flow 內先正常後攻擊」的資料集。**
- **HTTP request smuggling／keep-alive 內 exploit 的有標籤 pcap。** 找到的是：Splunk attack_data（日誌，非 pcap）、CSIC 2010／Torpeda（請求級 XML，無 pcap，官網在我這邊連不上，`[二手]`）、ModSecurity 稽核日誌資料、WAFFLED（論文，未確認是否釋出資料）。
- **C2 長連線「先 heartbeat 後下指令」的有標籤公開 pcap。** 只找到 Gotham Merlin（IP 規則標籤）、MCFP（感染主機流量整體標惡意）、arXiv:2609.27311（內文未讀）。
- **能把攻擊接進既有 TCP 連線的注入工具。** ID2T、FLAME、SAIBERSOC、PCAP-Backdoor 都不是這種用法。
- **FLAME 的公開版本。**（需向作者申請，且被調查稱已停止維護。）
- **CIC DoS 2017、ISCX Botnet 2014**：官網寫已下架。
- **LYCOS-IDS2017 的實際下載點與 LycoSTand 的 repo。**
- **Grashöfer 等人（DPD 規避）的 PoC 或 pcap。**
- **PYROLYSE 的現成 pcap 測試集**：README 沒說。
- **Gotham 的 `raw/metadata/`**：README 與論文說有，zip 目錄裡沒有（GitHub 上有）。

### 5.2 搜到但沒有打開全文或本體
- Lanvin et al. 2022 全文；LYCOS-IDS2017 資料本體；UNSW-NB15 的 GT 檔欄位；CIC-IDS2017、CIC Modbus、CICIoT2023、ISCX-IDS-2012 的 pcap（表單）。
- DAPT 2020、SCVIC-APT-2021、cAPTure、S-DAPT-2026、Unraveled（APT 多階段資料集）：只有搜尋摘要或二手頁面，沒有逐項確認 pcap 與標籤粒度。
- Bot-IoT、TON_IoT、CPTC 2018、MAWILab 官網（憑證錯誤）。
- Kitsune 的 pcap 內容（17.7 GB，沒下載）。
- CIC-IDS2017 的 Heartbleed 是否為單一 TCP 連線（需 pcap）。

### 5.3 本次未做
- 沒有填 CIC 的下載表單，也沒有使用鏡像。
- 沒有對任何 pcap 跑 Suricata；只用 tshark 看過 `CTU-Manual-Capture-Attack-1`。
- 沒有檢查資料集授權的法律效力，只記錄頁面或 repo 上寫的文字。
