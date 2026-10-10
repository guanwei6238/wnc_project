# 報告製作規劃
## 報告時間
2026/10/05

## 標題
security gateway 調查進度

## 內容主題
### 測試方法
介紹 **RFC 9411**，因為對於後面實做 gateway 的時候可以與目前已有的 gateway 用同樣的設定測試
要提及採用原因以及比較其他方法為什麼沒被採用

### datasets
這個主要是根據上次其他人報告的內容去抓的，主要是說明我們可以用這些當benchmark來做測試
`reference/`有更多內容請先看完在製作

### 測試工具
有哪些工具也是可以讓我們測試規則的，如果有其他補充可以加入
`reference/`有更多內容請先看完在製作

---
## 與 Claude 討論後的決定（2026-10-03）
- 三個主題（測試方法、datasets、測試工具）篇幅均等
- 測試方法：RFC 9411 只說「後續會依此方法測試」，不提實作
  - （2026-10-04 修正）RFC 9411 Appendix A 安全有效性測試的攻擊流量可改用 dataset 重播（與原文不同，需註明）；§7 效能測試不適用 dataset
  - 比較對象：上次報告的開源引擎 Suricata、Snort 3（inline），同硬體同設定
  - 現階段無法在 Pi 上做可與市售報告比較的完整測試（缺 TLS 流量工具、gateway 缺建議安全功能）
- 測試工具：定位為「實作時快速測試規則」，搭配規則測試迴圈
- datasets：主軸是「上次報告的四個資料集可不可以復現」
  - 可復現 = 原始封包 + 標籤 + 對應鍵（五元組、時間）三者齊全
  - IoT-23 已實測（tests/dataset/：雜湊、對齊 100%、tcpreplay 重播 3 次一致）
  - CIC 三份不下載，以標籤欄位做文件層級檢查；CICIoT2023 為反例（CSV 無 timestamp）
  - IoT-23 light 不另列，併入 IoT-23 注意事項
- 不宣稱 dataset 可當 benchmark；C&C 標籤僅 SYN，只能測 IP/port 封鎖
- 截圖：02_align.py（Hakai）、03_replay.sh

## 2026-10-04 再修正
- dataset 可復現性的由來：上次報告提到可用於 ML training；RFC 9411 原文沒有規定用 dataset
- 測試規劃改為兩層：第一層 RFC 9411 基準（本地、CVE、對照 Suricata／Snort 3）；第二層自行設計延伸實驗（gateway + 雲端、dataset、送雲端比例 vs 吞吐量／延遲）
- 理由：RFC 9411 排除 ML、流量沒有「未知」類、快取命中率偏高、KPI 不含雲端相關指標
- References 只列參考網頁
- 「規則沒命中時送雲端或放行、雲端判定的快取（類似 SDN reactive flow installation）」是下一階段的設計問題，不放進本次報告

- （2026-10-04 再修正）後續測試分兩項：一、RFC 9411 基準；二、整體測試——用同一份 dataset 測「只有本地」與「本地 + 雲端」

## 2026-10-04 Datasets 段改版
- 撤除自行推導的「三個條件」；改為兩個有出處的需求：① 拿得到同一份原始資料（ACM、Ring 2019）② 標籤能對回原始流量（Engelen 2021、Ring 2019）
- 不綁 tcpreplay；tcpreplay 只是測 gateway 時用的工具
- 結論：IoT-23 已驗證可復現；CIC-IDS2017 用修正版；CIC-DDoS2019 以資料內時間為準；CICIoT2023 對不到 flow
- 「能不能拿來測 gateway」與可復現性分開講

## 2026-10-04 老師 comment 與決定
1. 500 個 CVE：RFC §4.2.1 只給條件（≥ 500 個 should、近 10 年、CVSS 7–10、企業常用軟體），不給清單與流量；決定：照精神挑較小、與 IoT 相關的集合，註明偏離 RFC；樣本來源留待實作時討論
2. p9 結論改為「dataset 可以拿來測 gateway」，限制放第二條
3. 樣本直接寫「CVE（近 10 年、CVSS 7–10）」
4/7. 效能寫清楚：Inspected Throughput、CPS、Concurrent Connections、TTFB／TTLB（HTTP）；HTTPS 系列等有 TLS inspection 再測；整體測試量 detection（擋對／擋錯／漏掉）、throughput、latency、送雲端比例
5. 比較對象皆自行架設：測試一 = 單獨 Suricata／Snort 3（同硬體同規則）；測試二 = 同 gateway 雲端關／開
6. 定位：本地規則比對直接用 Suricata／Snort（Tier 1），貢獻是本地／雲端分流；Suricata 已有 flow bypass（官方文件），快路徑不是新貢獻；Pi 上完整 ET Open 吃記憶體為社群經驗、非官方規格

## 2026-10-05 老師 comment（範圍收斂）與決定
- 老師：完全照 RFC 9411 範圍太大；計畫目標是「依 dataset 有的 feature 做本地或雲端偵測」，不擴大到 anti-XXX 安全功能。先說明效能測試，重點放 dataset。
- 決定：
  - RFC 9411 只「參考效能測試流程」（Reference test → Sustain），簡單帶過
  - 第 2 頁刪「前提」（安全功能、CVE）；量測寫「效能（Throughput、Latency 等）」
  - 第 3 頁（DUT 的要求、Table 3）整頁刪除
  - 第 4（測試流程）、第 5（為什麼選）保留
  - 第 6 頁：一、效能測試（整個 gateway 含雲端；可復現 dataset；throughput、latency、packet loss；比較 Suricata、Snort 3）／二、偵測測試（本地 vs 本地 + 雲端；同一份 dataset；detection、送雲端比例；雲端關／開）
  - 效能指標只列 dataset 重播量得到的；CPS、Concurrent Connections、TTFB 需建立連線，不列
  - References 移除 NetSecOPEN 兩筆
- CLAUDE.md 新規則：專有／技術名詞一律用英文
- （2026-10-05 再修正）效能與偵測合併成同一次測試：同一份 dataset 跑 4 種設定（Suricata、Snort 3、Gateway 本地、Gateway 本地 + 雲端），同時量效能（throughput、latency、packet loss）與偵測（detection rate、false positive rate、送雲端比例）。第 5 頁排版：流程圖＋兩個指標框。
