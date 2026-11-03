# 新穎性查核：篩選規格（標題＋摘要）

輸入：`screen_candidates.jsonl`（每行一篇：n、title、year、venue、abstract、doi、src）。來源是 2026-11-03 在 Web of Science（9 組查詢）、IEEE Xplore（6 組）的匯出，搜尋紀錄在 `wos/search_log.tsv`、`ieee/search_log.tsv`、`acm/search_log.tsv`。

## 我們想宣稱的貢獻（判斷基準）

- **C1 放行後的稽核與撤銷**：IDS／IPS 把判定安全（或已信任）的 flow 放行、不再檢查之後，再用抽樣或稽核窗把它拉回來檢查，有問題就撤銷信任；並量化「放行後才攻擊」的漏報與成本。
- **C2 inline 的部分檢查**：在資源受限（ARM、Raspberry Pi 等級）的 inline gateway 上，只把每段對話或每個應用層訊息的開頭送給有狀態的 IDS（Suricata／Snort），其餘放行；包含有狀態 IDS 能不能接受「部分封包」（中途接手、缺口、ACK 視窗）的分析，以及對「先塞資料再攻擊」規避的處理。
- **C3 同一台 edge 設備上 rule IDS 與 ML 推論的資源分配**：同機執行規則式 IDS（或封包處理）和 ML／DNN 推論，量測互相干擾（特別是記憶體頻寬、快取），並依負載調整 ML 的工作量或核心分配。
- **C4 kernel 的 IDS fast path**：用 conntrack mark、tc eBPF、XDP、flowtable 等 kernel 機制讓已信任的 flow 跳過 user space 的 IDS（NFQUEUE 等），在 ARM／嵌入式 Linux 上量測每封包成本。

## 標記

每篇標一個：
- **overlap**：做了和某個 Cx 本質上相同的事（同樣的機制＋同樣的問題），會讓我們不能宣稱新穎。要寫清楚撞到哪一點。
- **related**：做了相近的事、應該在論文裡引用或比較，但缺了我們的關鍵要素（例如：有 bypass 但沒有放行後稽核；有部分檢查但不是 inline、不是 ARM、沒有處理有狀態 IDS；有 IDS＋ML 但沒有量同機干擾）。
- **none**：無關（例如只是對 ML IDS 的對抗攻擊、與 fast path／部分檢查／同機資源無關的偵測模型）。

只根據標題與摘要判斷；摘要說不清楚但可能 overlap 的，標 related 並寫「需讀全文」。不要上網查。

## 輸出

寫成 TSV：`n<TAB>label<TAB>claims<TAB>理由（繁體中文一句，related／overlap 要寫出缺了哪個要素或撞到哪一點）`。
none 也要列（理由可以只寫「無關」），每個 n 都要有一行。
