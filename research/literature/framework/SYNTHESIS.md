# 子題整合：可擴充 Security Gateway Framework —— 文獻、證明方式與論文方向

> 2026-10-27。依據：`../unread_paper_list.md` 的 12 篇，各一份報告在 `papers/<slug>.md`。
> 讀法照 `SPEC_ADDENDUM.md`：Sonnet subagent 逐篇讀全文、每個事實標出處。其中 4 篇已用舊規格（雲端卸載角度）精讀過，這次用「補讀模式」只補框架角度。
> 主 agent 對原文抽查了以下數字，全部吻合：
> - Polycube Table III（渲染原頁）、firewall 倍率 p.145
> - HorusEye Fig.8(a) 的兩組比值
> - GALETTE ×25.7（P=0.5），以及 galette-paper repo 的 `pktgen-measure.lua`
> - PASS 的 65%、97 ms、82%/65%
> - PALANTIR Table 5
> - MiddleNet 的 3.2×
> - OT 論文只用 Mininet
> - Simioni 的 RabbitMQ broker 位置
> - SLR 的 3735 筆
> - ECIS（10-27 補讀）：全文沒有 NFQUEUE 等字眼；206.08 = 198.95 + 7.13 ms；CPU 0.775%；baseline 比較寫在 future work
> - Wang & Chang（10-27 補讀）：鏡像副本、Xeon E-2134 + ConnectX-3；「3×」是自己的 8 核對單核 Snort 2.9.15.1
>
> 其餘數字以各報告的出處標記為準。[推測] 是判斷，不是論文寫的。「12 篇都沒有」只代表這 12 篇，不代表整個領域。

---

## 0. 先講結論

1. **框架的「機制」幾乎都有前例，不能拿來當主要貢獻。**
   - 執行中載入、原子替換 eBPF：Polycube、GALETTE。
   - 使用者的 eBPF 決定行為、框架只定 loader 與 map API：BPFabric 2017。
   - 依處理深度分 kernel／user 路徑：MiddleNet。
   - 偵測→決策→執行的閉環：PALANTIR。
   - Pi 4 上 kernel 抽特徵、user space 判斷：eBPF/XDP-DL。
   - Pi 4B 上同時跑 Suricata、加密、雲端上傳：ECIS。只能證明「跑得起來」，Suricata 怎麼接進封包路徑全文沒寫。
   - Pi 與雲端以佇列非同步連接：Simioni。
   - eBPF 前置過濾＋user space 規則式 IDS：
     - Wang & Chang 2022（`papers/wang-chang.md`）：x86 Xeon、10 GbE、被動鏡像、自寫引擎、Snort 規則子集、逐封包。
     - SAPO-BOI 2026（`../papers/sapo-boi.md`）：x86 10G、被動、修改過的規則子集。
   - 以 flow 為單位讓 IDS 略過：Suricata 本身就有 XDP-based flow bypass（Wang & Chang p.2 提到）。
2. **這 12 篇共同缺的，正好是我們的設計已經在處理的東西：**
   - (a) 低資源 ARM 上，**未修改的 IDS 串在 inline 轉送路徑上**的逐層成本：
     - GALETTE 沒有 IDS，eBPF/XDP-DL 沒量轉送。
     - ECIS 的 Pi 是終結連線的應用層節點，不是轉送 gateway（依圖文推論），而且沒有逐層成本。
     - Wang & Chang、SAPO-BOI 是 x86、被動、用改過的規則。
     - SLR 全文沒有出現 tc、netfilter、NFQUEUE。
   - (b) controller 或雲端**斷線、關閉時的行為有定義而且驗證過**：12 篇都沒有。
   - (c) **執行中替換造成的中斷**：只有 Polycube 一句文字，沒有圖表。
   - (d) 擴充機制的**安全模型**：
     - BPFabric、GALETTE、PASS 都由遠端下發可執行碼；PALANTIR 由中央執行安全動作；其他沒談。
     - SLR 自己統計 52/54 篇沒處理 eBPF 本身的安全。這個彙總數字的算法沒公開，引用要加但書。
3. **框架論文證明價值的方式只有五、六種（§3）**，最完整的是 Polycube：
   - 對手寫 eBPF 的 overhead
   - 對原生 Linux 元件的效能
   - LoC
   - 多個 NF 案例
4. **一個共通的實驗形狀，最適合當我們評估的主軸**：「送進 slow path 的比例」對吞吐的影響。
   - Polycube Fig.12：0%→10% 時，吞吐約 4.9→1.3 Mpps（目視）。
   - GALETTE 的 P 掃描：Pi 在 P=0.5 時吞吐 ×25.7。
   - HorusEye 的卸載 76%。
   - 三篇都沒有用規則式 IDS 量，也沒有量 bypass 造成的偵測損失（§6）。
5. **有幾條對我們不利的證據，論文裡要正面回應（§5.2）**：
   - Polycube 的 TC 路徑比 XDP 慢約 4.5 倍。
   - MiddleNet 批評 in-kernel eBPF NF。
   - GALETTE 發現便宜的 NF 在 Pi 上分流沒有好處。
6. **很多摘要數字有條件（§7）**，引用前要看條件。

---

## 1. 閱讀狀態

| # | 論文 | 取得程度 | 報告 | 備註 |
|---:|---|---|---|---|
| 1 | GALETTE（IFIP Networking 2023） | 全文（作者版） | `papers/galette.md`（補讀）＋ `../papers/galette.md` | 公開原型沒有完整的動態重配置（README） |
| 2 | Polycube（TNSM 2021） | 全文 | `papers/polycube.md` | 最接近的前例 |
| 3 | eBPF OT Resilience（ISCC 2025） | 全文（accepted manuscript） | `papers/ebpf-ot-resilience.md` | BPFabric 的延續，不是 GALETTE 的；只有 Mininet |
| 4 | MiddleNet（TNSM 2023） | 全文（arXiv v2 延伸版） | `papers/middlenet.md` | TNSM 正式版沒讀，Appendix B 可能只在 arXiv 版 |
| 5 | PASS（Electronics 2025） | 全文 | `papers/pass.md` | 綁 FPGA SmartNIC |
| 6 | ECIS（ICOIACT 2025） | 全文（IEEE 版，使用者經學校下載） | `papers/ecis-ipond.md` | 摘要的「>99% accuracy」和「相對 baseline CPU <1%」在結果章找不到支撐，baseline 比較寫在 future work |
| 7 | BPFabric（ANCS 2017） | 全文（accepted version） | `papers/bpfabric.md` | 原 repo 已 404，程式碼結論來自第三方複本，未執行 |
| 8 | eBPF/XDP-DL（IEEE IC 2026） | 全文 | `papers/ebpf-xdp-dl.md`（補讀）＋ `../papers/ebpf-xdp-dl.md` | 論文沒說 Pi 4 上是 native 還是 generic XDP |
| 9 | HorusEye（USENIX Sec 2023） | 全文＋附錄＋repo | `papers/horuseye.md`（補讀）＋ `../papers/horuseye.md` | 76%、4.13x 是離線算的 |
| 10 | Simioni（IoT-J 2025） | 全文（出版版） | `papers/simioni-offload.md`（補讀）＋ `../papers/simioni-offload.md` | 沒有驗證雲端不可用的情況 |
| 11 | PALANTIR（Sensors 2023） | 全文 | `papers/palantir.md` | 只量管理平面 |
| 12 | eBPF Security SLR（IJIS 2026） | 全文（arXiv 版＋期刊 CC BY 版，兩版逐詞比對一致） | `papers/ebpf-security-slr.md` | PRISMA：3735 筆 → 54 篇、七類。分類法可用，**彙總數字不要引**：有內部不一致、引用編號錯位，抽查 2 篇原始論文有 1 篇被轉述錯（Scholz 2018 的「XDP +45%」其實是 JIT 開 vs 關）。搜尋式只用 "eBPF"、沒有 "XDP"，可能漏掉 gateway 類研究 |

---

## 2. 比較矩陣

| 論文 | 平台 | 框架定義什麼 | 執行中替換 | 外部斷線時 | 安全模型 | 怎麼證明價值 | 重複／CI |
|---|---|---|---|---|---|---|---|
| GALETTE | Pi 3B、Intel NUC | Rust NF API（同一份原始碼編成 eBPF 與 dylib）、TOML chain | tail call 換根（有設計，沒量中斷；公開原型不完整） | 未說明 | 遠端編譯後推送、TLS；README 允許明文 ws | 轉送效能＋P 掃描 | **n=10、95% CI** |
| Polycube | 14 核 Xeon、40G | Cube（fast／slow／control path）、YANG→REST | PROG_ARRAY 原子替換、保留 map；只有一句「<1% loss」 | 未說明 | 只靠 verifier；未談認證 | 對手寫 eBPF、對 Linux 元件、LoC、18 個 NF | 10 次、standard error |
| OT Resilience | Mininet | pipeline `NEXT`、function／map API、REST | controller 安裝／移除 function；未說明語意 | 未說明 | 未談 | 4 個 OT 服務展示＋1 項延遲對比 | 未報告 |
| MiddleNet | 40 核 x86、10G、SR-IOV | L2/L3 走 DPDK、L4/L7 走 kernel stack＋eBPF | 依 VF 靜態分流 | n/a | 未談 | 對 OVS-DPDK／OVS-AF_XDP／bridge／NGINX；解析式 overhead 表 | L2/L3 5×60 s，無變異量 |
| PASS | CPU＋FPGA SmartNIC、1 GE | 三個 callback API、per-packet metadata | controller 推 policy | 未說明 | 遠端載入 executable；無簽章 | LoC −65%（對 Strawman）、硬體加速、控制面延遲 97 ms | 未報告 |
| BPFabric | x86、DPDK／raw socket | loader＋通用 table API＋notify | 整個 pipeline 重建；未量 | 沿用最後的函式（讀程式碼推得，未執行） | **無**（verifier out-of-scope） | L2 switch 對 bmv／OVS；複雜度表 | 未報告 |
| eBPF/XDP-DL | Pi 4B | 離線選特徵＋固定 pipeline | 未說明 | n/a（無雲端） | 未談 | 準確率、Pi profiling | 單次 100 s 重播 |
| HorusEye | Tofino＋x86/GPU | 資料平面白名單＋控制平面 autoencoder | 論文稱「不中斷」；公開 .p4 是 `const entries` | n/a | 未談 | 偵測力、交換器資源、離線卸載比 | 單一 seed |
| Simioni | Pi 3B＋IBM Cloud | early-exit DNN、RabbitMQ | 部署後可調卸載比例 | **未驗證**（0% 卸載是設計模式，不是故障測試） | 未談 | 相對全本地的時間與能耗、bytes、RTT、batch、裝置數 | 未報告 |
| PALANTIR | K8s 1+2 節點、i7 | SecaaS 元件、FSM、Kafka／REST | 容器部署與重配置（約 1.8 s） | 本地 CPE 可獨立（文字），未驗證 | 套件附 integrity；中央可執行動作 | SM 規模掃描（50 次）、SO 生命週期（100 次） | 有次數，無 CI |
| ECIS | Pi 4 Model B（Wi-Fi AP，ESP32 以 HTTP POST 送資料） | 固定流程：Suricata→AES-256-CBC→Firebase | 未說明 | 未說明（Firebase 只存密文，沒有雲端分析） | AES-256-CBC 加密送雲端；ESP32 到 Pi 是明文 | 5 種攻擊的阻擋與否表、DDoS 206.08 ms、CPU 0.775%、10–50 client QoS | 未寫 |

---

## 3. 問題一：框架類研究怎麼證明自己的價值？

| 證據類型 | 誰做了（出處見各報告） | 我們能怎麼做 [建議] |
|---|---|---|
| **對手寫版本的 overhead** | Polycube Table III：XDP 6.86 vs 6.97 Mpps、TC 1.55 vs 1.60 Mpps，latency 約 6 µs。其他 11 篇都沒有。PASS 的 Strawman 只比 LoC，沒比效能 | wnc-gw 管理的設定 vs 手寫等價設定（手寫 nft 規則＋直接啟動 Suricata＋手動 attach 的 tc 程式），比每封包成本 |
| **對原生系統的效能** | Polycube（bridge、iptables、nftables、OVS、ipvs、Katran、K8s CNI）、MiddleNet（OVS-DPDK、OVS-AF_XDP、bridge）、BPFabric（bmv、OVS） | 我們本來就保留 Linux 元件，所以比的是「加上框架之後多花多少」：bridge → +nft → +tc 核心程式 → +NFQ→Suricata |
| **空程式基準** | BPFabric 的 `wire.o`、PASS 扣除 direct forwarding | 我們的 bridge-only（Pi 4、veth 上 3.1 µs）就是這個基準，實體網卡上要重量 |
| **開發成本（LoC）** | Polycube（17 vs 64+176 行）、PASS（−65%）、BPFabric Table 3（10–37 行、25–99 條指令） | 外掛案例的 LoC 與設定行數。要註明框架本身的行數，PASS 就漏了這一項 |
| **擴充案例數** | Polycube 18 個 NF（Table II 只列 11 個）、OT 4 個服務、BPFabric 5 個程式、PASS 3 種功能 | 2–3 個 eBPF 外掛、2 組送雲端欄位設定、2 種雲端回應對應、「雲端關閉」設定 |
| **控制面延遲** | PASS 分項 S1/S2/S3（97 ms）、PALANTIR 生命週期（instantiation 47–67 s、configuration 約 1.8 s） | 「雲端判定 → nft set／ct mark 生效」的延遲，依規則數掃描 |
| **解析式 overhead 拆解** | MiddleNet（拷貝、interrupt、context switch 次數表） | 把 tc 路徑和 NFQ 路徑的成本來源列成表 |

**12 篇幾乎都沒做的**：
- 重配置的中斷量測（封包遺失、延遲尖峰）
- 外部依賴失效的行為
- RAM 與能耗（只有 GALETTE 量功耗、Simioni 量能耗）
- 第三方開發者或使用者研究
- 安全評估

[推測] 前四項我們有條件補上，可以當差異化的實驗。

---

## 4. 問題二：低階硬體的網路處理效能怎麼量？

### 4.1 前例的做法

| 論文 | 做了什麼 | 缺什麼 |
|---|---|---|
| GALETTE | Pktgen-DPDK、7 種封包大小、0.1–100 Mbit/s、每組 10 trials、95% CI、`/proc/stat` 量 CPU、UM24C USB 電表每 0.25 s 取樣 | `pktgen-measure.lua`（主 agent 讀過）有三個問題：(1) 每次 11 s、**沒有暖機**；(2) 吞吐取自停止後一次 dump 的 `portStats`，起停時間被算進去，所以 NUC 在 64 B、1 Gbit/s 只有 744.8 Mbit/s；(3) 延遲用 `latsampler` simple 模式，單向或來回沒寫明。另外沒有丟包判定、沒扣 idle |
| Polycube | 10 次＋standard error、硬體時間戳、CPU 對 offered rate 的曲線 | x86/40G，絕對數字不能比 |
| eBPF/XDP-DL | Pi 4B 上分開報 kernel 與 user space 時間（avg／peak）、CPU、RSS | 沒有轉送吞吐、延遲、丟包；單次 |
| Simioni | 插座電表、先量 idle 再扣、卸載動作也算進去；RTT 分雲端 zone | 電表型號與取樣率、重複次數都沒寫 |
| HorusEye | SPIRENT 100G、900 s 滿線速（由 #Transmit 反推） | 只有交換器部分 |
| ECIS | 5 種攻擊的阻擋與否、DDoS 的偵測加緩解時間（198.95＋7.13 ms）、CPU 0.775%、10–50 client 的 latency／throughput、TIPHON QoS 評等 | 規則來源與條數、攻擊工具、重複次數、Suricata 版本與模式都沒寫；206 ms 的起訖點未定義（作者用 VPN／網路路徑解釋差異，[推測] 包含網路延遲）；Fig.9 和 Table VII 的單位互相衝突 |

### 4.2 建議的量測規格 [建議]

整合前例與我們已有的做法：10/05 簡報的 RFC 9411、10/24 的每封包成本相減法。

- **流程**：RFC 9411 的 Init → Ramp up → Sustain ≥ 300 s，只在 Sustain 段量。前例都沒有暖機，這一項就是差異。
- **基準**：同一台 Pi、同樣兩個 port 的 bridge-only，算出每封包成本（扣掉基準）。各層依序疊加：+br_netfilter → +nft/conntrack → +tc 核心程式 → +NFQ→Suricata。
- **重複**：n≥10、報平均與 95% CI，加上 p50/p99 延遲與丟包率（RFC 9411 的 NDR）。
- **控制變因**：
  - 鎖頻，開跑前用 vcgencmd 確認（見 memory「Pi 剛開機時脈沒鎖住」）。
  - 記錄 GRO 狀態。
  - 註明哪個 port 是 USB 網卡：GALETTE 在 Pi 3B 上的延遲被 USB 1 ms 輪詢主導；Pi 4 的內建網卡不經 USB，但第二個 port 仍是 USB。
- **資源**：CPU（`/proc/stat`）、RSS；功耗可選，要扣 idle。
- **P 掃描**：改變「需要 Suricata 的 flow 比例」，畫出吞吐和 CPU 的曲線。這是 Polycube Fig.12 和 GALETTE Fig.6–8 的形狀，換成真實 Suricata。

---

## 5. 問題三：哪些已有前例、哪些要說明取捨

### 5.1 不能宣稱是新的（寫 related work 時直接承認）

| 設計 | 前例 |
|---|---|
| 框架管理 eBPF 的執行期載入與原子替換 | Polycube（PROG_ARRAY／PatchPanel）、GALETTE（tail call 換根） |
| 框架不定義功能，使用者的 eBPF 決定行為；框架只定 loader 與 map API | BPFabric 2017、OT Resilience |
| fast／slow path 分工，便宜的留在 kernel、昂貴的隔離 | GALETTE、Polycube、HorusEye、PASS |
| 依處理深度分路徑，兩條路徑共存 | MiddleNet |
| 偵測→決策→執行的政策閉環、元件化 | PALANTIR |
| 以描述欄位宣告元件的資料型別或 schema | PALANTIR Table 1、Polycube YANG |
| Pi 4 上 kernel 抽 flow 特徵、經 BPF map 交給 user space | eBPF/XDP-DL |
| Pi 4 上 Suricata 當 edge IPS、偵測後自動加黑名單 | ECIS（接入方式不明，Pi 不是轉送節點） |
| eBPF 在 kernel 先濾、只把可疑封包交給 user space 的規則式 IDS | Wang & Chang 2022（XDP 上做 AC 掃描＋port group，perf event 交給 user space）、SAPO-BOI 2026。兩篇都是 x86、被動、規則子集、沒量漏檢 |
| kernel 內以 flow 為單位讓 IDS 略過 | Suricata 的 XDP flow bypass（Wang & Chang p.2 提到）；`../trust-bypass/` 的 Shunting、SciPass 等 |
| 自適應、可重配置的 eBPF 監控；模組化 eBPF 安全框架 | SLR 的 Tools & Frameworks 類（例如 Magnani 2022、LBM） |
| Pi 與雲端非同步佇列、卸載比例可調 | Simioni |

### 5.2 要說明理由的取捨（含不利證據）

| 取捨 | 對方 | 我們要寫的理由 [推測] |
|---|---|---|
| **TC 而不是 XDP** | Polycube Table III：x86 上 TC 1.60 vs XDP 6.97 Mpps；Fig.5 的 TC 版 bridge 和 Linux bridge 差不多 | Pi 4 兩個 port 都沒有 native XDP，generic XDP 不會比 TC 早到哪裡。這點要在 Pi 4 上**實測** generic XDP vs TC，不能只講 |
| **保留 netfilter／conntrack，不自己做轉送** | Polycube 自己做 bridge、router、firewall；OT／BPFabric 自帶 switch | 複用成熟功能（conntrack、flowtable、OpenWrt fw4）、攻擊面小、低資源。代價是 bridge+br_netfilter+nft 比 routed 多約 35%（Pi 4 實測） |
| **in-kernel eBPF NF 被批評** | MiddleNet：只能做 L2–L4、L7 要付 kernel→user 成本、過載表現差 | 我們的 eBPF 不做 L7，L7 交給 Suricata。過載行為要量（NFQ 的 `fail-open`、queue 滿時的行為） |
| **便宜 NF 分流沒好處** | GALETTE：便宜的 NF 鏈在 Pi 上分流沒有收益 | 我們分流的對象是很貴的 Suricata（約 27–29 µs/封包），不是便宜 NF；划算的條件是「濾的成本 < 省下的比例 × 後段成本」，要用 P 掃描證明 |
| **雲端不在封包路徑上** | Simioni：約 10% 事件由雲端判決 | 斷線時行為可預測；代價是雲端的判定只影響之後的封包 |
| **插件只能本機簽章安裝，雲端不能下發可執行物** | BPFabric、GALETTE、PASS 遠端推送；Rose et al. CNS 2025 研究竄改 ELF 的攻擊（只讀到摘要） | 安全底線 1、2（gateway-architecture skill §5） |
| **揭露而不是限制外掛能力** | Polycube 有 Transparent cube（限制能力） | doctor 揭露。這是設計選擇，要說明管理者責任與風險 |
| **NFQUEUE（event-driven）而不是 polling** | MiddleNet：concurrency 1 時 37% vs 404% CPU、平均省 3.2× | Pi 4 只有 4 核，養不起 polling |

---

## 6. 可以宣稱的缺口（to the best of our knowledge）

| # | 缺口 | 證據 | 強度 |
|---|---|---|---|
| F1 | 在 Pi 級 ARM gateway 上，把 kernel eBPF、netfilter／conntrack、NFQUEUE→**未修改的** Suricata（完整規則、inline 轉送）整合在同一個可擴充框架，並逐層量出每封包成本 | 「eBPF 前置＋規則式 IDS」的概念有前例：Wang & Chang、SAPO-BOI。我們的組合有四個要素，Wang & Chang 每個都沒做：(1) Pi 級 ARM（它是 Xeon）；(2) inline（它丟的是鏡像副本）；(3) 原版 Suricata 全規則（它自寫引擎，排除 flow、flowbits 等選項）；(4) 以 flow 為單位決定（它逐封包）。另外 GALETTE 沒有 IDS、eBPF/XDP-DL 沒量轉送；ECIS 的 Pi 不是轉送節點、接入方式不明 | 中。差異在條件組合，不在概念，論文要用「在這些條件下沒人量過」的措辭 |
| F2 | 外部分析（雲端）可選，**斷線或關閉時的行為有定義並經實驗驗證** | 12 篇都沒驗證 | 中高 |
| F3 | fast path 的效益與**偵測代價**一起量：送 Suricata 的比例 vs 吞吐／CPU vs 偵測率 | Polycube Fig.12、GALETTE P 掃描只量效能；HorusEye 量偵測力但在 ASIC、離線計算；SAPO-BOI 明說不量偵測力；Wang & Chang 沒報任何告警數或偵測力。注意：它們的預過濾在規則子集內是無損的（依設計推論），我們的 ct mark 信任 flow 是**有損**的，所以偵測代價一定要量，不能借它們的論述 | 中高 |
| F4 | 擴充機制的**中斷與失效**量測：外掛載入／卸載、規則 reload、Suricata 重啟時的封包遺失與延遲 | Polycube 只有一句；GALETTE、BPFabric、OT 沒量 | 中 |
| F5 | 擴充機制的**安全模型**（本機簽章、封閉的回應詞彙、揭露） | 前例框架大多沒有安全模型。SLR 稱 52/54 沒處理 eBPF 自身安全（算法未公開）。安全研究已注意到這個問題（Rose 2025、He et al. USENIX Sec 2023 的 CapBits） | 中低。設計論述可以寫，「量」比較難 |

[推測] F1、F4、F5 單獨拿出來，容易被評為「整合工作」。要和 F2、F3 這種有實驗結果的問題一起，論文才站得住（見 §8）。

---

## 7. 摘要數字的條件（引用前看這裡）

- **HorusEye**：76% 和 4.13x 是公開程式碼在 pandas 離線算的。「加 Gulliver Tunnel」的 12M pps 和 Magnifier 的吞吐比值都是 4.1359，[推測] 是模型吞吐乘以過濾比，不是量到的系統吞吐。
- **Polycube**：firewall 對 nftables 31.8x、iptables 7.5x、OVS 1.4x（1000 條規則），混了「演算法 vs 線性掃描」和「動態 reload 特化」兩個因素，沒有 ablation。nftables 那組沒說有沒有用 set。另外，論文說 18 個 NF 約 54k LoC，但 Table II 只列 11 個，加總約 61k。
- **PASS**：摘要的 76%、90% 是範圍最大值，不是平均；「from scratch」其實是同作者寫的 Strawman；LoC 沒算框架本身。
- **OT Resilience**：摘要寫 "minimum performance overhead"，但全文沒有 overhead 量測。
- **GALETTE**：×25.7 是 Pi 在 P=0.5、合成的 100k 運算 NF 下的值；吞吐包含起停時間。
- **Simioni**：Table III／IV、Fig.10 的時間數字互相對不上（Fig.10 的 0.9% 和 Table IV 算出的約 2.0%）。
- **eBPF/XDP-DL**：沒說 Pi 4 上是 native 還是 generic XDP；bcmgenet 的 XDP 補丁到 2026-05 還在 review。

---

## 8. 對論文方向的意涵 [建議，待開發者與老師決定]

repo 裡現在有兩條論文方向：

| | 方向 A：框架論文 | 方向 B：信任式 fast path |
|---|---|---|
| 出處 | `../unread_paper_list.md` | `../trust-bypass/SYNTHESIS.md` §3、§5、§7 |
| 主要貢獻 | 框架的設計、實作、擴充性與效能評估 | 放行後稽核、撤銷、「放行後才攻擊」的漏報量測 |
| 和 WNC 的交付物 | 幾乎完全重疊（產品本身就是框架） | 是框架上的一個功能（階段 3） |
| 新穎性 | 機制多半有前例（§5.1），要靠 F1–F5 | 缺口明確（trust-bypass G1–G5） |
| 風險 | 被評為「整合工作」 | 要做完階段 3、自建延遲攻擊資料集 |

**建議做法 C：以框架為系統貢獻，評估以「成本與偵測的取捨」為主軸。**

- **理由一：這是文獻共通的實驗形狀。** Polycube Fig.12、GALETTE 的 P 掃描、HorusEye 都證明：fast／slow path 系統的效能由「送進 slow path 的比例」決定。但沒有人用真實規則式 IDS、在 ARM 上量，也沒有人同時量 bypass 的偵測代價（F3）。
- **理由二：同時對上三方的需求。**
  - 這正是 CLAUDE.md「當前研究目標」寫的：降低地端成本，同時維持轉送效能與資料完整性。
  - 也是老師 10/19 要的「流量送進去偵測得到嗎」。
  - 也是 WNC 需要的產品證據。
- **理由三：方向 B 最貴的部分可以列為延伸或 future work**，例如 RQ4 的稽核與自建延遲攻擊資料集，不會卡住畢業。

建議的評估章節（E1–E4 是核心，E5、E6 視時間）：

| 實驗 | 回答什麼 | 借自哪裡 | 狀態 |
|---|---|---|---|
| E1 逐層成本 | 每一層在 Pi 4 實體 port 上多花多少 µs/封包、kpps 上限 | MiddleNet 的解析表、BPFabric `wire`、GALETTE 量測矩陣 | veth 已量（10/24），實體網卡未量 |
| E2 框架 overhead | wnc-gw 管理 vs 手寫等價設定 | Polycube Table III | 未做 |
| E3 偵測能力與 P 掃描 | 全量檢查時 IoT-23 usable scenario 偵測得到多少；送 Suricata 的比例 vs 吞吐、CPU、偵測率 | Polycube Fig.12、GALETTE Fig.6–8、HorusEye Fig.6 | 偵測端是老師要的；P 掃描要等 ct mark 信任（階段 1）可用 |
| E4 失效與生命週期 | 雲端斷線、Suricata 掛掉、外掛載入／卸載、規則 reload 時，封包和 log 的行為 | 12 篇都沒有（F2、F4） | `when_unavailable` 已有設計 |
| E5 擴充性案例 | 外掛、欄位設定、雲端回應對應各 2–3 個；LoC 與設定行數 | Polycube、PASS、BPFabric | 未做 |
| E6 雲端迴路成本 | 上傳 bytes、判定延遲、對 RTT 的敏感度 | Simioni Fig.10–13、PASS Table 7 | 要等最小雲端迴路 |

---

## 9. 這輪補讀發現的既有報告問題（沒有改既有報告）

| 既有報告 | 問題 | 原文 |
|---|---|---|
| `../papers/simioni-offload.md` C.2 | 把 RabbitMQ broker 放在 Edge | 「At the Cloud Infrastructure, we deploy the RabbitMQ broker」（主 agent 已核對） |
| `../papers/horuseye.md` | 頁碼：iForest 更新與深度模型應為 p.573，規則數 77/3585 應為 p.579；12M pps 沒註明可能是推算值 | 見 `papers/horuseye.md` F 節 |
| `../papers/ebpf-xdp-dl.md` D7、Q1 | 「線上不會動態改特徵」「map key 為 five-tuple」是推論，應標 [推測] | 見 `papers/ebpf-xdp-dl.md` F 節 |
| `../papers/galette.md` | 無錯；可補「Pi OS 11 kernel 預設關閉 XDP、JIT、BTF」 | 見 `papers/galette.md` |
| `../papers/sapo-boi.md` | 把「否定 content／否定埠」歸給 Wang & Chang 的排除準則，但 Wang & Chang §6.2 沒列這兩項 | 見 `papers/wang-chang.md` F 節 |
| `papers/ebpf-security-slr.md` D9 #1 | 轉述 SLR 的「user space 做完整規則分析」「最高 3×」：原文只支援規則子集；3× 是 8 核對單核 | 見 `papers/wang-chang.md` |

---

## 10. 還沒做的事

- **需要經學校下載的全文**：
  - ~~ECIS~~、~~Wang & Chang 2022~~：2026-10-27 使用者已下載，讀完，見 §1、§6。
  - MiddleNet 的 TNSM 正式版（還沒下載）：要引用 Appendix B 的數字前才需要。
- MiddleNet 的 TNSM 正式版：要引用 Appendix B 的數字前，先核對正式版有沒有。
- 各報告 D9 建議追加閱讀、較值得讀的：

| 論文 | 為什麼 | 來源報告 |
|---|---|---|
| NetEdit（SIGCOMM 2024） | 大規模 eBPF NF 的部署與生命週期 | polycube |
| Rose et al.（CNS 2025） | 竄改 eBPF ELF 的攻擊，支撐 F5 | bpfabric、galette |
| bpf-iptables（CCR 2019） | 和 iptables／nftables 的比較方法 | polycube |
| Morpheus（ASPLOS 2022） | 執行期特化，有可重現 artifact | polycube |
| Honey for the Ice Bear（2024） | 更新時避免服務降級，對應 F4 | bpfabric |
| Pi 3B+ 上的 Snort IDS/IPS（IJACSA 2019） | Pi 級 IDS 前例 | ecis-ipond |
| Scholz et al.（ITC 2018） | eBPF／XDP 封包過濾的量測方法（MoonGen、硬體時間戳），可對照我們的 nft 基準 | ebpf-security-slr |
| He et al.（USENIX Sec 2023，CapBits） | eBPF 本身是攻擊面、權限模型，對應 F5 | ebpf-security-slr |
| Serror et al.（ARES 2018） | 家用路由器上規則過濾＋異常偵測的設計空間 | ebpf-security-slr |

  - mOS、Rubik：LoC 加 overhead 雙證據的評估寫法（來源報告：pass）。
  - 以上都只確認了書目，沒讀全文。
- 方向 C 是建議，要和老師確認。如果採用，CLAUDE.md 的「當前研究目標」和 `../unread_paper_list.md` 的題目要一起改。
