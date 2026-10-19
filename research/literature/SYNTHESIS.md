# 跨論文整理與 Research Gap 判斷

> 依據：10 篇精讀報告（`papers/*.md`）。精讀報告由 subagent 撰寫；我（主 agent）只對**關鍵數字與書目**抽查過原文，
> 沒有逐項驗證。所有「[推測]」是我的判斷，不是論文寫的。
> 「搜尋沒找到」只是弱證據，不等於沒人做過。

## 1. 比較矩陣

| 論文 | 硬體 | 偵測方法 | 有卸載到雲端/控制平面 | 量轉送效能 | 量上傳 bytes | 量 time-to-detection | 重複次數 / CI |
|---|---|---|---|---|---|---|---|
| FlowLens (NDSS'21) | Tofino P4 | RF（交換器控制平面） | 否（卸載量只有紙上估算） | 否 | 估算，非實測 | 否 | 單次 50/50 切分，無 CI |
| HorusEye (Sec'23) | Tofino + x86/GPU | iForest 白名單 + autoencoder | **是**（卸載 76%） | 系統吞吐增益 4.13x | 否（正常流量 header 仍上傳） | 否 | 未確認 |
| Edge Multi-agent (ICPS'24) | 無 | RF/SVM/LR 投票 | 否（future work） | 否 | 否 | 否 | 單次切分 |
| eBPF/XDP-DL (IC'26) | Pi 4B | GRU | 否 | 否 | n/a | 部分（每 flow 推論 10.38 ms） | 單次 100 s 重播 |
| Host-Aggregation (Access'25) | Pi 3B+（僅時間）+ Xeon（記憶體） | XGBoost | 否 | 否 | 否 | 否（時間不含特徵產生） | 10-fold CV（僅準確率） |
| Alikhanov (Access'22) | Xeon | DT/RF/CNN | 否 | 否 | 否 | 否 | 未報告 |
| Simioni (稿件) | Pi 3B + 雲端 VM | early-exit DNN | **是**（約 10% 事件） | 否 | 每事件 7.2 / 14.5 KB | 每事件處理時間（Table IV） | 未報告 |
| Galette (Networking'23) | Pi 3B | XDP/AF_XDP（Macswap，無偵測） | 否 | **是** | n/a | n/a | **n=10，95% CI** |
| Sapo-boi (JBCS'26) | x86 10G | **規則式（Snort/Suricata 規則）** | 否 | 丟包率有；轉送無（被動鏡像） | 否 | 否 | 有 ± 值 |
| Kitsune (NDSS'18) | Pi 3B（僅 KitNET 計算） | 自編碼器集成 | 否 | 否（pps 為計算速率） | 否 | 否 | 否 |

## 2. 對六個假說方向的證據

| 方向 | 論文提供的證據 | 判斷 |
|---|---|---|
| **Edge–Cloud IDS 分工** | Simioni 給出「卸載比例 vs 能耗 vs 錯誤率」的框架，HorusEye 給出交換器上的白名單前置過濾。**卸載依據全部是 ML 的信心值或異常分數**。 | 概念已有；**以規則命中為依據的沒找到**（Sapo-boi 是規則式但沒有卸載） |
| **Flow Feature Compression** | FlowLens（32–150x，損失 ≤3%，在 ASIC）；eBPF/XDP-DL（77→5 特徵，93.30%→92.73%，Pi 4B kernel 內抽取）；Host-Aggregation（source IP、10 s 窗） | **比我原先想的少 gap**：eBPF/XDP-DL 已在 Pi 4B 上做 kernel 內抽取。剩下的缺口是「含特徵產生與壓縮的端到端成本」，Host-Agg 與 Simioni 都沒算進去 |
| **Dynamic Flow Monitoring** | Alikhanov：靜態取樣會傷偵測，取樣率 1/10、1/100、1/1000 時 RF 的 Majority DR 由 98.31% 降到約 80%/37%/15%（**讀圖**），短 flow 攻擊先消失。依負載自適應的做法只在候選清單（Braun 2013、XNET 2026 預印本），**未精讀** | 「靜態取樣不夠」有證據；自適應方法在 gateway 上的成本**未驗證** |
| **XDP/eBPF 真正省多少** | Galette：優勢只在 IRQ 模式、中高速率（1518 B、100 Mbit/s 時 CPU 10.4% 對 32.4%），Poll 模式或 ≤1 Mbit/s 消失。Sapo-boi：載入 8000 條規則時 Snort 丟包 53.55%（2 Gbps）/90.81%（8 Gbps），Sapo-boi 約 2.2%，但在 x86 10G。**Pi 3B/3B+ 的 USB 網卡驅動無 XDP 支援（我 grep 過原始碼）→ 只能 generic 模式** | **最清楚的缺口**：ARM + generic XDP + 真實偵測成本，沒有人量過 |
| **Cloud Data Offloading** | Simioni 有每事件 bytes 與處理時間；HorusEye 的 76% 卸載**沒有降低上傳 bytes**（header 仍鏡射）；FlowLens 只有估算 | 「只上傳可疑 flow 省多少頻寬」搜尋未找到實測；**flow 級（非 DNN event）的上傳成本沒人量** |
| **不同硬體限制** | 論文用 Pi 3B、3B+、4B、Tofino、Xeon，每篇只在一種硬體上做一種方法 | 沒有同一方法跨硬體的敏感度分析 |

## 3. 跨論文的方法學觀察（對我們「不被問倒」最有用）

1. **摘要數字幾乎都有條件，單看摘要會被誤導：**
   - Simioni「能耗降到 1%」= 只對 AlexNet、且**容忍約 10% 錯誤率**；MobileNetV2 版是 41%
   - Host-Aggregation「記憶體降 86.4%」= 在 Xeon 伺服器量的、對最大類別；「時間降 99.7%」= 在 Pi 上、對最慢 baseline、不含特徵產生
   - eBPF/XDP-DL「93.30% 對 92.73%」= 77 特徵 vs 5 特徵，縮減掉 0.57 個百分點
   - Kitsune 的 Pi 數字 = 只有 KitNET 計算速率，不含特徵抽取
   - HorusEye 的卸載 76% 與 96.0% 實驗條件不同
2. **可重複性普遍薄弱：** 只有 Galette 做到 n=10 + 95% CI。其餘多為單次量測或未報告。
3. **轉送效能與偵測成本很少同時量：** Galette 量了轉送但沒有偵測；其餘量偵測但沒量轉送。
4. **規則式 IDS 幾乎缺席：** 十篇裡只有 Sapo-boi 使用 Snort/Suricata 規則，而且不在 ARM 上。ML 的成本模型不能直接套到 Suricata。
5. **Pi 3B ≠ Pi 3B+：** Galette、Kitsune、Simioni 用 3B，Host-Aggregation 用 3B+。網卡驅動不同（3B 的 smsc95xx、3B+ 的 lan78xx）。兩者都沒有 XDP 支援。

## 4. 我認為可行的貢獻方向（全部 [推測]，依風險由低到高）

- **A. 規則式 IDS 在 Pi 級 gateway 上的成本量測。** 以 RFC 9411 流程量 Suricata（ET Open 全量 vs 挑選子集）的 throughput / latency / loss / CPU / RAM，並加上偵測一致性。填補：Sapo-boi 無 ARM 資料、Pi 上 Suricata + NFQUEUE 無同行審查實測。**這正是我們目前在規劃的實驗。**
- **B. 完整的成本記帳。** 把 flow 收集／特徵產生、壓縮、上傳都算進端到端成本。Host-Aggregation、Simioni 都沒算特徵產生。
- **C. 以規則命中為依據的卸載決策。** 把 Simioni 的信心值換成 Suricata 的規則命中／未命中等本地訊號，量上傳 bytes 與 time-to-detection。新穎性最高，風險也最高。

## 5. 還沒做、會影響上面判斷的事

- Braun 2013、XNET、LocKedge、A-THENA、Palmese、CECN-DNN 只讀到摘要或二手描述，沒有精讀。
- Coşar & Kıran (IDAP 2018, Snort vs Suricata on two Pis) 是唯一找到的 Pi 上 IDS 對比，全文封閉，未讀。
- 搜尋的引用網路（cited-by）覆蓋不完整，Semantic Scholar 曾被限流。
