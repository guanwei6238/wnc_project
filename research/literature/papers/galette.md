# Galette
（精讀版。頁碼規則：`[原文 p.N]` 的 N 一律是 PDF 實際頁碼；PDF p.1 是 Enlighten 機構庫封面，論文正文從 p.2 起，所以「論文印刷頁碼 = PDF 頁碼 − 1」。內文以 `pdftotext -layout` 逐頁抽出後閱讀。表格由文字層抽出，欄位對齊已逐列人工核對。）

## A. 書目與取得狀況
- 標題：GALETTE: a Lightweight XDP Dataplane on your Raspberry Pi
- 作者：Kyle A. Simpson, Chris Williamson, Douglas J. Paul, Dimitrios P. Pezaros（University of Glasgow）[原文 p.2]
- 年份 / 出處：2023；22nd IFIP TC6 Networking Conference (IFIP Networking 2023), Barcelona, 12–15 June 2023 [原文 p.1–2]
- DOI：10.23919/IFIPNetworking57963.2023.10186412 [原文 p.1]
- URL：https://eprints.gla.ac.uk/296605/（PDF：https://eprints.gla.ac.uk/296605/1/296605.pdf）；程式碼 https://github.com/FelixMcFelix/galette [原文 p.10 ref 25]
- 與給定資訊的差異：書目全部吻合。補充：(1) 取得的是作者版（accepted manuscript），封面聲明「與出版版可能有差異」[原文 p.1]，表格數字未與 IEEE 出版版比對；(2) 測試機是 Raspberry Pi **Model 3B**（非 3B+）[原文 p.6]；(3) 前一輪 candidates.md 寫「對比 AF_PACKET 省 7.4% 功耗」，原文是「XDP 相對 userland (AF_XDP)」省 7.4%，且該數字我重算對不上同列（見 Q3/E）。
- 取得程度：**全文**（作者版，10 頁 PDF 含封面）

## B. 核心貢獻
1. 指出 SBC 與資料中心硬體的差異（USB 2.0 網卡、GbE 以下 NIC 只暴露單一 Rx/Tx queue → XDP 只有單一執行緒），並據此設計「XDP fast path + AF_XDP userland slow path」兩層架構 [原文 p.3–4, p.6]。
2. 提供讓同一個 Rust NF 同時編成 eBPF 與 native dylib 的 API，加上 TOML chain 格式與遠端編譯/動態重配置的 control plane [原文 p.4–6]。
3. 在 Pi 3B 與 Intel NUC 上用 Macswap NF 量測 XDP / AF_XDP / AF_PACKET 的吞吐、延遲、CPU、功耗（10 trials、95% CI），並證明把昂貴 NF 移到 userland 可保護一般流量 [原文 p.7–9]。

## C. 指定的 9 項
1. **Research Problem**：在 IoT 閘道這類低功耗、低成本 SBC 上，如何用現代 Linux 核心功能做出 CPU 效率高、延遲低的 service function chain (SFC) 資料平面 [原文 p.3]。動機是 IoT 流量僅 100–1000 kbit/s 等級，但資安功能需要本地低延遲反應 [原文 p.2–3]。
2. **Architecture**：
   ```
   RX → [XDP fast path: ACL(LPM trie) → weak-classifier] ─TX/DROP→ 
                         └─ 可疑封包 upcall(AF_XDP, 單一共享 UMEM, N 個 userland 執行緒) → DPI 等昂貴 NF → TX/DROP
   Compile server(WSL2 Ryzen) → eBPF .elf + dylib .so → TLS 雙向認證 → SBC control plane（定期輪詢、同步 BPF map、tail-call 原子切換）
   ```
   無 Flow 收集、無 Cloud；「Edge」就是這台 SBC [原文 p.4–6]。upcall 時在 metadata 加 8 B 記錄 NF ID 與 action index [原文 p.5]。
3. **Processing Location**：Kernel（XDP/eBPF，含 tail call 上限 32）+ User space（AF_XDP socket、run-to-completion 的 dylib）；Cloud 與交換器資料平面皆無 [原文 p.4–6]。
4. **Hardware**：DUT = Raspberry Pi Model 3B（4×1.2 GHz、1 GiB、Pi OS 11 AArch64、kernel 5.15.74-v8+，自編以啟用 XDP、eBPF JIT、BTF）；NIC = SMSC LAN9514（USB 2.0，100BASE-T）。次要 DUT = Intel NUC8i7BEK（4×4.5 GHz、16 GiB、Intel I219-V PCIe）；TrafGen = 另一台 NUC（Ubuntu 22.04 5.15.0-56-lowlatency）；Compile = Ryzen 9 5900X；中間為 TP-Link TL-SG108S GbE 交換器 [原文 p.6–7]。
5. **Dataset**：無資料集。流量為 Pktgen-DPDK 合成流量，每次 11 s burst [原文 p.7]。非 IoT-23 / CICIoT2023 / 真實流量。
6. **Baseline**：DPDK testpmd 的 Macswap（Pi 上為 AF_PACKET PMD；NUC 上另有 e1000e PMD），同硬體重跑；內部比較 Pure XDP vs AF_XDP [原文 p.7]。**沒有** NFQUEUE、iptables/nftables、Linux bridge、Suricata 作基準。
7. **Metrics**：throughput、latency（中位與百分位）、CPU（/proc/stat）、功耗（USB 電表）[原文 p.7]。無 RAM、無偵測準確率。
8. **Limitations（作者承認）**：XDP tail call 上限 32，超過強制 upcall；fast path NF 需要原始碼（未來想用 TEE）；control plane 在 IoT 長期離線/無 ECC 記憶體下的金鑰完整性；redbpf 尚不支援 CO-RE，需回傳 vmlinux；多個 AF_XDP socket 讀取有爭用，限制「用 userland 平衡便宜 NF」的適用性；單一 UMEM 迫使回收工作集中在第一個 userland 執行緒 [原文 p.5–6, p.9]。
9. **Research Gap**：
   - 作者自述：未來擴充 TEE 編譯、PUF 重新認證金鑰、Morpheus 式 runtime profiling 但需評估網路成本、P4Pi 可借 AF_XDP 降功耗 [原文 p.6, p.9]。
   - [推測] 沒有任何真實偵測 NF；沒有 NFQUEUE/Suricata 對照；無 Flow/雲端；無 time-to-detection；功耗未扣除 idle 基線；無 Pi 3B+。

## D. 補充欄位
**D1 對照**
- C1 ○（XDP/AF_XDP 封包處理）；C2 ×；C3 ×（僅在 §I 提到 XDP 可做「本地縮減遙測資料」[原文 p.3]，未實作未量測）；C4 △（量了 CPU 與功耗，無傳輸成本）。
- K1 ○（throughput、latency 都量）；K2 ×；K3 △（量封包轉送延遲，非偵測延遲）。

**D2 卸載與資料**：無雲端卸載。類比的是 fast path → userland 的「內部卸載」：由 NF 回傳 Upcall action 決定；Listing 1 例子是 weak-classifier 認為可疑才送 DPI [原文 p.4]。實驗中則以機率 P 隨機指定封包需要昂貴 NF [原文 p.7]。資料縮減比與偵測力損失：論文未說明。

**D3 成本記帳**：地端 CPU ○、功耗 ○（整機 USB 供電）、RAM ×、傳輸 bytes ×、雲端運算 ×、time-to-detection ×。control plane 傳輸 NF 二進位的時間只在腳註提到「增加初始傳輸時間」，無數字 [原文 p.6]。

**D4 偵測方法與威脅模型**：無偵測方法。NF = Macswap 與「100k 次運算」的合成昂貴 NF，作者稱類比 ML 推論或 DPI [原文 p.7]。威脅模型僅假設「exploit 類攻擊而非 volumetric DDoS，多數封包正常」[原文 p.4]。[推測] 兩層成本模型的概念（便宜篩選留在 fast path、昂貴分析隔離）可借用；但 Suricata 走 NFQUEUE 的 kernel↔user 複製成本結構不同，數值不能直接套。

**D5 實驗可信度**：流量為合成、速率 0.1–100 Mbit/s（NUC 到 1000）、7 種封包大小、每組 10 trials、表格給 95% CI、boxplot 為 {1,25,50,75,99}th 百分位 [原文 p.7]；ablation 有 IRQ vs Poll、Pure XDP vs AF_XDP；程式碼公開，README 說明實驗腳本在另一個 repo（galette-paper）[來源：GitHub README，WebFetch 摘要]。CI 計算方式、括號記法、每 trial 封包數、latency 如何打時間戳：論文未說明。

**D6 移植障礙**：見 Q1/Q2。能否在 Pi 3B+ 跑：論文未測。已驗證的事實（我查 Raspberry Pi kernel rpi-5.15.y 原始碼）：`smsc95xx.c` 與 `lan78xx.c` 兩檔皆無 `xdp` / `bpf` / `ndo_bpf` 字樣（grep 0 筆）→ 兩個驅動都沒有 native XDP，只能 generic（skb）。其他依賴：自編 kernel（XDP、JIT、BTF）、redbpf + Rust 1.59、遠端編譯機、TLS control plane [原文 p.7, p.6]。Pi OS 現行 kernel 是否已預設啟用這些選項：未查。

**D7 六個方向（只回報本論文）**
- Edge–Cloud IDS 分工：無關（無雲端）；僅有 edge 內兩層分工的證據。
- Flow Feature Compression：無關。
- Dynamic Flow Monitoring：無關（有動態 chain 重配置，無 flow 監測）[原文 p.6]。
- XDP-eBPF 真正省多少：**支持但有條件**——見 Q3/Q4；Pi 上 IRQ 模式、大封包、中高速率才明顯，輕量 NF 下絕對瓶頸是核心封包處理 [原文 p.9]。
- Cloud Data Offloading 成本-時效：無關；作者僅主張本地處理可避免導向雲端造成延遲，無量測 [原文 p.3]。
- 不同硬體限制下是否有效：支持（部分）——Pi 與 NUC 趨勢不同：NUC 上昂貴 NF 在低速率才無害，Pi 在 0.5–1 Mbit/s 就受影響 [原文 p.9]；但只有兩種硬體。

**D8 可借用與可改進**
- 可借用：測試台拓撲與量測流程（Q7）；IRQ vs Poll 作為功耗/CPU 的獨立變因 [原文 p.7]；fast path 只做便宜分類、重分析隔離到其他核心的設計 [原文 p.4, p.9]；`/proc/stat` 0.5 s、UM24C 0.25 s 取樣 [原文 p.7]；以 DPDK testpmd 當上限基準 [原文 p.7]。
- 改進方向（全部 [推測]）：(1) 在同一 Pi 重做量測並加入 nftables+NFQUEUE 與 Suricata 基準——基於「baseline 無 NFQUEUE」；(2) 補 idle 功耗基線與以 energy-per-packet 表達——基於「功耗未扣基線」；(3) 在 Pi 3B+ (lan78xx) 重測並明確記錄 attach 模式——基於「僅測 3B 且未說明模式」；(4) 以真實規則比對（或 IoT-23 重播）取代 100k-ops 合成 NF——基於 Q6；(5) 量測 USB polling 對延遲的獨立貢獻（例如以另一張 PCIe/不同介面的 NIC 對照）——基於 Q5。

**D9 建議追加閱讀（≤5）**
1. Yao et al., "Generic XDP Under Embedded SoC Constraints: A Lightweight L2 Data Plane with Cost Decomposition Analysis", Electronics 15(6):1281, 2026, DOI 10.3390/electronics15061281。為何：Galette 的 cited-by；摘要稱多數嵌入式舊網卡只支援 generic XDP，並做 CPU/頻寬雙上限的成本分解（RK3588，非 Pi）。存在確認：OpenAlex 已確認 DOI 與摘要；全文未讀（MDPI 403）。
2. Miano et al., "A Framework for eBPF-Based Network Functions in an Era of Microservices", IEEE TNSM 18(1):133–151, 2021（Polycube）。為何：被 Galette 比較的設計（hybrid XDP-userland）[原文 p.9–10 ref 13]。存在確認：僅見於 Galette 參考文獻，DOI 未驗證。
3. Simpson et al., "Seiðr: Dataplane Assisted Flow Classification Using ML", IEEE GLOBECOM 2020。為何：同作者，Galette 稱可用於「本地縮減遙測資料」[原文 p.3 ref 26]，較貼近 C2/C3。存在確認：僅見於參考文獻，DOI 未驗證。
4. "An eBPF-Based Programmable Network Architecture for OT Digital Resilience Use-Cases", IEEE ISCC 2025, DOI 10.1109/iscc65549.2025.11325939。為何：OpenAlex 列為 Galette 的 citing work，可能是後續應用。存在確認：OpenAlex 已確認；內容與相關度未讀。
5. Laki et al., "P4Pi: P4 on Raspberry Pi for networking education", ACM CCR 51(3):17–21, 2021。為何：Galette 提到的另一個 Pi 資料平面（DPDK + tap bridge）[原文 p.9]。存在確認：僅見於參考文獻，DOI 未驗證。

---
## 指定問題 Q1–Q7

**Q1 XDP 模式（native / generic / offload）**
- 論文**未明說** Pi 上使用哪種模式。全文無 "generic"、"native 模式"、attach flag 或 skb-mode 字樣（逐頁 grep）。
- 論文內的間接線索：(a) 背景說 XDP 對所有 NIC 預設把 eBPF 放在 SKB 配置之後，驅動支援越好越能提前到 SKB 之前或 zero-copy [原文 p.3]；(b) SBC 缺乏 DPDK 等所需的驅動支援 [原文 p.2]；(c) GbE 以下 SBC NIC 只暴露單一 Rx/Tx queue，XDP 只有一個執行緒 [原文 p.4, p.6]；(d) 1518 B 時 AF_XDP CPU 偏高，作者歸因於「把封包內容複製進 UMEM」[原文 p.8]，表示是 copy 模式；(e) 重編 kernel 只提到加入 XDP、eBPF JIT、BTF，沒有提到驅動修改或 patch [原文 p.7]。這些都與 generic 一致，但都不構成直接證明。
- 論文外的證據：Galette 原始碼 `pulley/src/lib.rs` 以 libbpf 的 `attach_xdp(iface)` 掛載，沒有指定模式 flag；建立 XSK 時註解「no pref over (zero)copy mode, or native/drv」[來源：GitHub 原始碼]。我查 Pi kernel rpi-5.15.y 的 `smsc95xx.c` 與 `lan78xx.c` 均無 XDP 相關程式碼。
- **[推測]** 結論：實際為 generic（skb）模式。理由是未指定 flag 時，核心會在驅動沒有 `ndo_bpf` 時退回 SKB 模式（此核心行為來自我的記憶，未在本輪查證原始碼）。Offload 不可能（需 SmartNIC 之類）。

**Q2 Pi 3B+ / 其他網卡 / 可否推廣**
- 論文只測 Pi 3B（LAN9514）與 NUC（I219-V）；**未提 3B+、LAN7515、lan78xx**（grep 無）。
- 推廣性：論文主張「device-portable」「portable across heterogeneous SBCs」[原文 p.2]，但可攜指的是 NF 程式碼（跨 CPU 架構編譯），不是效能結果。對其他 SBC/網卡的效能是否成立：論文未說明。唯一的推廣性論述是「GbE 以下 NIC 常見只有單一 queue」[原文 p.4]，並以 I219-V 為例。

**Q3 量測方法與主要數字**
- 方法：TrafGen 以 Pktgen-DPDK 產生並接收流量，同時量吞吐與延遲，每次 burst 11 s；CPU 讀 /proc/stat，每 0.5 s；Pi 功耗用 RDTech UM24C USB 電表，每 0.25 s 經藍牙由 TrafGen 輪詢；10 trials；表中不確定度為 95% CI，延遲 boxplot 為 1/25/50/75/99 百分位；userland 單執行緒綁 core 1 [原文 p.7]。
- 誤差棒樣本數：**n = 10 trials**（以 trial 為單位）[原文 p.7]。每 trial 內的取樣數：論文未說明；[推測] 11 s 約 22 筆 CPU 樣本與 44 筆功耗樣本（由取樣間隔推算）。CI 計算法（t 分布 / bootstrap）、延遲百分位是否跨 trial 合併：論文未說明。括號記法如 `1.8(24)`：論文未說明，[推測] 為「最後位數的 ±」即 1.8±2.4。
- 注意：CPU% 的分母論文未說明。[推測] Poll 模式下 Pi 恆為約 25%（≈4 核中 1 核滿載），NUC 恆為 12.5%（≈8 執行緒中 1 個），故應是全核平均。「Pure XDP」在 Poll 欄也有 25% 的原因論文未解釋。
- 主要數字見 E 表。補充：Pi 能維持的速率為 64 B→10、512 B→50、1518 B→100 Mbit/s；AF_PACKET 在 512 B 無法達到 50 Mbit/s（表格省略）[原文 p.8]。Pi 64 B 在 50 Mbit/s 過載，吞吐崩到 2.9–5.2 Mbit/s（Table I）。
- 延遲：文字只給相對數字——Pi（64 B，IRQ）XDP 比 AF_PACKET 中位數低 29–41%（0.1 與 10 Mbit/s），99th 低 36.1–95.4%；過載（≥50 Mbit/s）中位延遲增 100 倍（圖省略）[原文 p.8]。絕對延遲只在圖（Fig.4，y 軸 100 µs–100 ms 對數）上，**文字未給數值**。NUC 1 Gbit/s 時 XDP 中位–99th 為 1978.2–2008.7 µs，AF_XDP 差 1.44 倍；polling 時 Galette 約為 DPDK 的 2 倍延遲 [原文 p.8]。
- 數字核對：Table II 1518 B、100 Mbit/s 列 CPU 32.4/10.4 = 3.12，吻合「3.1×」；但同列功耗 1885.1→1824.5 僅省 3.2%，而 7.4% 要用 XDP@50 Mbit/s (1745.1) 對 AF_XDP@100 Mbit/s (1885.1) 才算得出 → [推測] 論文的 7.4% 是跨列比較，非同條件。

**Q4 XDP / AF_XDP / AF_PACKET 的 CPU 成本與優勢消失點**（全部取自 Table I–III，Pi 為 IRQ 與 Poll 兩欄）
- Pi 1518 B（IRQ）CPU：XDP vs AF_XDP = 1.8 vs 1.8（0.1）、1.7 vs 2.1（1）、2.1 vs 3.6（10）、5.3 vs 14.0（50）、10.4 vs 32.4（100 Mbit/s）；AF_PACKET（僅 Poll）= 53.6–74.3%。
- Pi 64 B（IRQ）：XDP vs AF_XDP = 1.8 vs 2.1（0.1）、3.0 vs 3.9（1）、20.0 vs 35.6（10 Mbit/s）；AF_PACKET（Poll）= 64.4 / 54.7 / 75.9%。
- **優勢消失或反轉的條件**：(1) ≤1 Mbit/s，XDP 與 AF_XDP 的 CPU 差異小於 CI（如 1518 B 於 0.1 Mbit/s 皆為 1.8%）；(2) **Poll 模式**下兩者 CPU 都被輪詢執行緒主導：1518 B 於 100 Mbit/s 為 36.9 vs 36.5，64 B 於 10 Mbit/s 為 41.3(53) vs 38.6(96)，名目上 XDP 反而較高但 CI 重疊；(3) 功耗：作者承認 polling 時 XDP 資料平面功耗比 AF_PACKET 約高 5% [原文 p.8]；我由表重算，64 B 於 0.1 Mbit/s 為 2230.3 vs 2107.5 mW（+5.8%），1518 B 於 0.1 Mbit/s 為 2259.8 vs 2069.1 mW（+9.2%），100 Mbit/s 則持平（2253.6 vs 2253.9）；(4) NUC 1 Gbit/s Poll：XDP 23.0% vs AF_XDP 22.7%，優勢消失；與 DPDK 比 XDP 延遲約 2 倍，作者稱「XDP 輸給 DPDK 是已知的」[原文 p.8–9]。
- 限制：AF_PACKET 只有 Poll 欄，所以「IRQ 的 XDP vs Poll 的 AF_PACKET」是跨模式比較；作者稱其為 like-for-like [原文 p.8]，我認為 [推測] 這會放大 XDP 的 CPU/功耗優勢。

**Q5 USB 2.0 1 ms polling**
- 論文承認：Pi 封包到達受 LAN9514 的最小 USB polling 間隔 1 ms 影響 [原文 p.7，引 datasheet p.32]；說延遲「主要由 USB polling 間隔決定」，且更高速率只讓 XDP 中位延遲改善 5.5% [原文 p.8]；Fig.4 caption 提到低速率靠 polling 改善 [原文 p.7]。
- 處理方式：沒有。沒有量化 1 ms 的貢獻，沒有用其他介面的 NIC 做對照，也沒有說明 latency 如何打時間戳、是單向還是來回（來回的話含兩次 USB 傳輸 [推測]）、交換器 store-and-forward 延遲。NUC/TrafGen 關閉 IRQ throttling，Pi 端未提及 [原文 p.7]。結果：Pi 上的延遲差異（相對值）可信度尚可，但絕對值不應拿來外推到非 USB 網卡。

**Q6 Macswap 與真實偵測的距離**
- 很遠：唯一量化的轉送 NF 是 Macswap（交換 12 B 的 MAC）加一個計數器 [原文 p.5 Listing 2, p.7]。Listing 1 的 ACL → 統計分類 → DPI chain 只是範例，**沒有被量測**。
- 作者的處理：用「100k 次運算」的合成 NF，機率 P ∈ {0, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0}，64 B、Pi 10 Mbit/s、NUC 100 Mbit/s [原文 p.7]。結論：即使 1% 封包要昂貴 NF，也會顯著拉高中位/99th 延遲並降低吞吐；移到 userland 後 Pi（P=0.5）吞吐增加 25.7 倍，99th 延遲改善 1–2 個數量級 [原文 p.9]。
- 對輕量 NF：作者承認 Pi 上分流設計不會讓便宜 NF chain 超越純 XDP（瓶頸在核心封包處理），且多 socket 讀取有爭用 [原文 p.9]。
- **[推測]** 對 Suricata：NF 成本比 XDP 省下的固定 per-packet 成本大一到多個數量級，XDP 的節省會被淹沒；有價值的是「哪些封包必須進入昂貴分析」的分流邏輯，而不是 XDP 本身。

**Q7 [推測] 對 nftables + NFQUEUE + Suricata 可沿用的方法學**
- 可直接沿用：(1) 三機測試台（流量產生器 / DUT / 交換器；或直連）；(2) Pktgen-DPDK 的「速率 × 封包大小」矩陣與固定長度 burst；(3) /proc/stat 0.5 s、USB 電表 0.25 s 取樣；(4) 每格重複 10 trials 並報 95% CI；(5) 把 IRQ/Poll（對應我們的 NAPI/busy-poll 設定）當變因；(6) 以接近上限的基準（testpmd）定位天花板；(7) 重編 kernel 時明列所開選項。
- 需要改的：基準換成 nftables 單純轉送、NFQUEUE（含不同 queue 數、fail-open）、NFQUEUE + Suricata；流量要加入 IoT-23 重播（tcpreplay 或 Pktgen 的 pcap 模式），因為 Macswap 的合成流量沒有 flow/payload 結構；功耗要扣 idle 基線；CPU 要區分每核與總和；latency 要說明時間戳方式。
- 論文沒有、需自建：continuous integration——論文未說明；GitHub repo 目錄中也未見 `.github`（查看 tree），README 未描述 CI 或測試。CI（信賴區間）的算法細節論文未說明，需自行定義。

---
## E. 關鍵數字表
（Pi = Raspberry Pi 3B，Macswap NF，Pktgen-DPDK 11 s burst，10 trials，括號為論文的 95% CI 記法，[推測] 為最後位數的 ±。）

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| Pi CPU，Pure XDP | 1.8(24) / 3.0(39) / 20.0(61)% | 64 B；0.1 / 1 / 10 Mbit/s；IRQ | [原文 Table I, p.7] |
| Pi CPU，AF_XDP | 2.1(25) / 3.9(26) / 35.6(57)% | 同上 | [原文 Table I] |
| Pi CPU，AF_PACKET | 64.4(342) / 54.7(75) / 75.9(86)% | 同上；僅 Poll | [原文 Table I] |
| Pi CPU，Pure XDP | 41.3(53)% @10；52.8(221)% @50 | 64 B；Poll | [原文 Table I] |
| Pi 吞吐 | 9.4 Mbit/s @10；Pure XDP 2.9(3) IRQ / 3.9(22) Poll @50 | 64 B；過載 | [原文 Table I] |
| Pi 吞吐，AF_XDP / AF_PACKET @50 | 3.7(2) / 5.2(16)；3.4(6) | 64 B | [原文 Table I] |
| Pi 功耗，Pure XDP | 1675.7(23) / 1664.3(30) / 1802.8(75) mW | 64 B；0.1 / 1 / 10；IRQ | [原文 Table I] |
| Pi 功耗，Pure XDP Poll | 2230.3(104) / 2097.0(104) / 2186.3(85) mW | 同上；Poll | [原文 Table I] |
| Pi 功耗，AF_PACKET | 2107.5(45) / 2068.2(36) / 2198.6(77) mW | 同上；Poll | [原文 Table I] |
| Pi 吞吐 | 97.6 Mbit/s @100 | 1518 B；XDP 與 AF_XDP；AF_PACKET 97.7(1) | [原文 Table II, p.8] |
| Pi CPU，XDP vs AF_XDP | 10.4(66) vs 32.4(78)% | 1518 B；100 Mbit/s；IRQ（比值 3.12） | [原文 Table II] |
| Pi CPU，XDP vs AF_XDP | 5.3(44) vs 14.0(45)% | 1518 B；50 Mbit/s；IRQ | [原文 Table II] |
| Pi CPU，AF_PACKET | 53.6(63) … 74.3(75)% | 1518 B；0.1–100 Mbit/s；Poll | [原文 Table II] |
| Pi 功耗，XDP vs AF_XDP | 1824.5(84) vs 1885.1(104) mW | 1518 B；100 Mbit/s；IRQ（差 3.2%） | [原文 Table II] |
| Pi 功耗，Poll 比 IRQ | 約 +500 mW（例 1675.7→2230.3，+33%） | 64 B；0.1 Mbit/s；Pure XDP；我重算 | [原文 Table I；推算] |
| 作者宣稱 | CPU 最多減 3.1×、功耗少 7.4% | Pi；1518 B；IRQ；XDP vs userland | [原文 p.8]（7.4% 見上註） |
| Pi 延遲 | 中位低 29–41%；99th 低 36.1–95.4% | 64 B；0.1 與 10 Mbit/s；XDP vs AF_PACKET；無 polling | [原文 p.8] |
| Pi 延遲 | 過載 ≥50 Mbit/s 時中位延遲增 100× | 64 B | [原文 p.8] |
| Pi 延遲，XDP 隨速率 | 中位僅改善 5.5% | 提高 ingest | [原文 p.8] |
| NUC 吞吐 | 744.8(1) Mbit/s | 64 B；1000 Mbit/s 目標；XDP / AF_XDP；AF_PACKET 433.7(92)；DPDK 745.1 | [原文 Table III, p.8] |
| NUC CPU @1 Gbit/s | XDP 10.5(5)% IRQ / 23.0(4)% Poll；AF_XDP 21.6(7) / 22.7(9)；AF_PACKET 25.0(2)；DPDK 12.5(1) | 64 B；1000 Mbit/s | [原文 Table III] |
| NUC 延遲 | XDP 中位 vs 第 99 百分位 1978.2–2008.7 µs；AF_XDP 差 1.44× | 1 Gbit/s | [原文 p.8] |
| NUC 延遲 | XDP 比 userland 中位好 100–150 µs；Poll 時約為 DPDK 的 2× | 64 B | [原文 p.8, Fig.5] |
| 昂貴 NF 分流 | Pi 吞吐 ×25.7 | P=0.5；64 B；10 Mbit/s | [原文 p.9, Fig.6] |
| 昂貴 NF 分流 | 99th 延遲改善 1–2 個數量級 | Pi；64 B | [原文 Fig.7, p.9] |
| 取樣設定 | 10 trials；11 s burst；/proc/stat 0.5 s；電表 0.25 s | — | [原文 p.7] |
| 平台功耗背景 | Pi 約 1.4–3.7 W | 作者引述 | [原文 p.6] |

## F. 自評
- 「未能確認」：(1) Pi 上 XDP 的實際 attach 模式（論文未寫，結論為 [推測]，其中「無 ndo_bpf 時預設退回 SKB」是我的核心行為記憶，未在本輪查證）；(2) 延遲絕對值（只在圖上，圖為對數軸）；(3) CI 算法與括號記法；(4) 出版版（IEEE）與作者版是否一致；(5) D9 第 2、3、5 篇的 DOI。
- 最不確定的三件事：(1) 表格的括號記法與 CPU% 分母（推測為最後位數的 ± 與全核平均），若不是，Q3/Q4 的 CI 比較與「消失點」判斷要重做；(2) 「Poll」欄對 Pure XDP 的意義——Pure XDP 理應不輪詢，卻有約 25% 的 CPU 與 +500 mW，作者未解釋，我的解讀（userland 輪詢執行緒仍在跑）是 [推測]；(3) 7.4% 功耗數字是否為作者筆誤或跨列比較，以及 AF_PACKET 僅有 Poll 欄使跨模式比較是否公平。
