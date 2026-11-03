# HorusEye（補讀：框架角度）

> 頁碼為 USENIX 論文集頁碼（pdf 第 n 頁 = p.569+n）。`[App. p.N]` = Artifact Appendix 頁碼。
> `[repo]` = 我讀 GitHub `victorkdwu/HorusEye`（原 vicTorKd，帳號已改名；API 顯示 license 為 null）tag v1.0.1 的檔案。該 tag 的 `.p4`、`control_plane.py`、`iForest_detect.py` 與 main 逐位元組相同。只讀、未編譯、未執行；這是 artifact 實際做了什麼，不是論文的說法。

## A. 書目

Yutao Dong 等，*HorusEye: A Realtime IoT Malicious Traffic Detection Framework using Programmable Switches*，USENIX Security 2023，pp.571–588。全文與附錄：https://www.usenix.org/system/files/usenixsecurity23-dong-yutao.pdf 、https://www.usenix.org/system/files/usenixsecurity23-appendix-dong-yutao.pdf 。PDF 已存於 `research/literature/framework/pdfs/horuseye/`。
既有報告：`research/literature/papers/horuseye.md`。書目（標題、作者、年份、頁碼）經重讀全文確認無誤。取得程度：全文 + artifact appendix + 公開 repo 檔案。

## G. 框架專屬欄位

**G1 抽象。** HorusEye 是固定的兩階段偵測系統，不是通用框架：沒有 API、描述語言或設定格式。只有兩個介面：資料平面的白名單 range/exact 表（Algorithm 1 從 iForest 產生，p.574），以及資料平面上報「flow ID + burst 大小與封包數」[p.576]。作者說 Gulliver Tunnel 可搭配別的控制平面方案，例如 Kitsune [p.582]。

**G2 生命週期。** 論文只有兩句：控制平面「有新流量時更新 iForest 與深度模型」[p.573]；新增白名單項目存 TCAM，「without interrupting the functioning of the switch」[p.580]。更新觸發條件、下發通道、是否原子、切換期間的封包、重配置時間，論文都未說明、未量測。
[repo] 兩處與論文說法有落差：(1) `.p4` 的白名單 `detect_abnormal_stream` 與埠表 `deny_stream` 都是 `const entries`，依 P4_16 規格，控制平面無法在執行期修改 [推測：未在 Tofino 上驗證]，則公開版換模型需重生 P4 並重新載入；(2) 論文 §3 說 Magnifier 把惡意 flow 寫回 blacklist 以封鎖或限速 [p.573]，但 `.p4` 沒有以 flow 為 key 的表，也沒有 meter，`control_plane.py` 沒有任何交換器 API 呼叫。回寫迴路沒有實作，也沒有量延遲。

**G3 分工。** 資料平面（Tofino ingress）：bi-hash 找 flow，把 burst 的封包數、位元組、時間戳存在 double hash table，burst 結束才用白名單比對；register 一次只能讀或寫，所以用 resubmit [p.575]。原封包照常轉發，鏡射封包非同步處理：正常 burst 去 payload 只上傳 header 存到 server，可疑 burst 封裝 header + burst 資訊送控制平面 [p.576]。控制平面：suspicious flow table，異常 burst 比例（Eq.3）超過門檻才取歷史封包跑 Magnifier [p.573, p.579]。交換器到 server 與 server 回寫交換器的通道（CPU port、PCIe 或一般網卡），論文未說明。[repo] 鏡射封包用自訂 ethertype 0xDEAF，egress 控制區塊是空的。

**G4 外部依賴。** 論文未討論控制平面斷線或失效。[推測] 原封包轉發不依賴控制平面 [p.576]，所以大概是 fail-open，只失去複查與回寫。[repo] `deny_stream` 預設動作是 drop（port 不在表上直接丟），這是資料平面自己的 fail-closed 政策。

**G5 價值怎麼證明。**
- 做了：HorusEye vs 只用 Magnifier vs Kitsune，同資料比 TPR@FPR≤5e-5/5e-4 與 PRAUC（Table 5, 10）；有無 Gulliver Tunnel 對 TPR 的影響（Fig.8b）；contamination 與異常頻率門檻對「偵測 vs 卸載」的取捨曲線（Fig.6c,d, p.578–579）；交換器資源、100 Gbps 無丟包與延遲（Table 3, 4）；對抗測試 [p.582]。
- 沒有：端到端延遲或 time-to-detection、控制平面 CPU/RAM/能耗、交換器到 server 的頻寬、與規則式 IDS 的比較、即時完整系統測試。開發成本只有「超過 2000 行 LOC」[p.577]。
- [repo] 76% 與 4.13x 是離線算出來的：偵測流程在 pandas 內用規則 CSV 模擬資料平面，`Flow Gain Ratio` 是 unique flow 數相除；artifact appendix 自己說 `control_plane.py` 產出「除硬體效能外的所有結果」[App. p.20]。單位（flow 或封包）論文未說明。
- [推測，算術] Fig.8(a) 的 6514/1575 與 12056569/2915116 都等於 4.1359，即「加 Gulliver Tunnel」的吞吐很可能是模型吞吐乘以過濾比，不是量到的整體吞吐。[repo] `test_throughput` 只對已抽好的特徵張量單次計時，無 warm-up，不含特徵計算與封包 I/O。

**G6 量測方法。** 交換器：SPIRENT N11U，單埠 100 Gbps，封包 256/512/1024/1500 B 與廠商預設 IMIX，量 #Transmit、#Loss、延遲 [p.580]。持續時間論文未寫；[推測，由 Table 4 的 #Transmit 反推] 四個尺寸都等於 100 Gbps ÷ ((size+20 B)×8) × 900 s，即每組跑 900 秒滿線速。時間戳方式、warm-up、重複次數、信賴區間、是否依 RFC 2544，論文未說明，表中皆為單一數值。[repo] `.p4` 把封包送回 ingress port（`ucast_egress_port = ingress_port`），無 L2/L3 轉送表，[推測] 即單埠迴路測試，不是雙埠轉送。照這份描述無法完整重做，缺 SPIRENT 設定與延遲量測方式。

**G7 安全模型。** 威脅模型是被攻陷的 IoT 裝置 [p.572]。對框架自身只測了 black-box 對抗：低速率 DDoS、混入 benign TLS/QUIC 的 evasion、1/2/10% 訓練投毒；白名單可解釋所以防不了 white-box [p.582]。誰能改規則、規則是否驗證，論文未說明。

**G8 對照我們。**
- 不能宣稱是新的：fast path 放行正常流量、只讓可疑流量進 slow path；用「異常頻率」門檻決定送不送 [p.573, Eq.3]；slow path 確認後回寫 fast path 阻擋（概念）[p.573]；正常流量只留 header 供事後取證 [p.576]。
- 它有、我們沒有 [推測]：非監督模型自動轉成可解讀白名單（規模 77 條 range + 3585 條 exact，ψ=5000, t=200 [p.579]）；burst 分段（15 封包）限制狀態存留 [p.575]；對 fast path 本身做對抗測試。
- 我們有、它沒有 [推測]：規則式 IDS 當第二層、每層 µs/packet 的實測成本；雲端不在封包路徑上且回應受限；外掛簽章與安全邊界。
- 取捨不同：ASIC 的 fast path 近乎免費（延遲 1065.6 ns [p.580]），所以能全量鏡射 header；Pi 4 每層都要付 CPU（bridge+nft 約 10.7 µs、NFQ→Suricata 約 27–29 µs，見 SPEC_ADDENDUM 第 2 節）。[推測] 先濾再檢只在「濾的成本 < 省下比例 × 後段成本」時划算，76% 的條件不同，不能直接搬。

| HorusEye | 我們 [推測] | 差異 |
|---|---|---|
| `deny_stream`（proto+dst port）+ bi-hash register | tc eBPF hash map | Pi 的 map 可原子讀改寫，不需要 resubmit 與 double hash |
| 白名單 range 表，命中即放行 | nft interval/concat set + ct mark 信任 flow | 同構；nft 寫入成本見 Pi nft 實測 |
| Magnifier 吃 Kitsune 特徵與歷史 header | NFQ→Suricata 吃即時完整封包 | slow path 輸入不同，payload 規則的成本無法對應 |

**G9 用途。**
1. 引用為 selective analysis 前例，支撐「信任 flow 繞過 NFQ」的設計 [p.573, Eq.3]。
2. 評估指標：TPR@極低 FPR + PRAUC [p.580]，與「偵測 vs 卸載」取捨曲線 [Fig.6c,d]。
3. 反面教材：我們要量 time-to-verdict、逐層 µs/packet、控制平面成本與傳輸量，這些它都沒量。
4. 對 ct mark 信任機制做 low-rate、evasion、poison 測試 [p.582]。
5. 規則規模 77 + 3585 可當 nft/eBPF map 壓測的現實量級 [p.579]。

## D5 補充

隨機種子固定（`random_state=114514`）[repo]，偵測結果為單一 seed；throughput 單次計時 [repo]。其餘見既有報告。

## D6（Pi 4 部分）

- Tofino/P4 資料平面無法在 Pi 4 執行 [推測，由硬體需求]。Magnifier 依賴 GPU + TensorRT 8.2.1.8 [App. p.20]，Pi 4 沒有；模型小（輸入 5@21 的 Conv1D autoencoder [p.576–577]），CPU 推論是否可行論文未評估，[推測] 可行但須實測。
- 狀態量不是障礙：[repo] `HASH_KEY_SIZE=16`，兩個 bucket 各 2^16 筆，每筆約 11 B / 7 B，合計約 1.2 MB（我自行加總）。
- 兩個 port 都沒有 native XDP，而論文不依賴 XDP，不受影響。

## E. 新增數字

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| 控制平面 pps（補） | G+K 6514；M int8 2,915,116；兩個 G 比值皆 4.1359 | RTX 2080 SUPER | Fig.8(a)；比值為我的算術 |
| 交換器測試時長 | 900 s（反推） | 100 Gbps，4 種封包大小 | Table 4 反推 [推測] |
| 規則數對應參數 | 77 = TCP 29 + UDP 48；3585 = 3460 + 125 | ψ=5000, t=200 | Table 1, p.579 |
| 公開 P4 表容量 | `detect_abnormal_stream` size 128；`deny_stream` size 10240，const entries 約 6978 | grep 粗略計數 | [repo] |

## F. 自評

**既有報告的疑點**（不改既有報告）：
- 第 C.2 節「更新 iForest 與深度模型 [p.572]」與 Magnifier 段落：原文在 p.573。
- 第 E 表與 D6「burst 77、port 3585 [p.580]」：原文在 p.579 §6.4，對應 ψ=5000, t=200。
- 第 E 表「一致率 ψ=400, t=10…5000」：Table 1 實為 ψ=400 配 t=10/50/100/200，與 t=200 配 ψ=1000/2000/5000。
- 第 E 表「HorusEye(G+M int8) 12M pps」未註明可能是推算值（見 G5）。

**最不確定的三件事：**
1. `const entries` 是否代表論文實際用的版本也不能執行期更新。公開版可能不同於實驗版；p.580 說的「不中斷」可能指別種做法。
2. 12M pps 為縮放推算的判斷是由兩組相同比值推得，論文沒明說計算方式。
3. 900 s 與單埠迴路測試是從數字與程式碼反推，論文沒寫。
