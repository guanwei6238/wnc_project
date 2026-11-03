# 子題規格：fast path 要怎麼做（預篩、抽樣、部分檢查）

2026-11-02 開的子題。三組 subagent 共用本檔；各組要回答的問題寫在派工的 prompt 裡。

## 1. 背景（只用來判斷相關性，不要寫進報告當成論文的內容）

- 平台：Raspberry Pi 4（Cortex-A72 ×4）、Linux bridge、Suricata 8.0.7。ips 模式用 NFQUEUE，ids 模式用 NFLOG 送複本。網卡 bcmgenet 沒有 native XDP，所以 kernel 端只能用 tc eBPF。
- 目前的 fast path：一條連線（conntrack entry）被信任後，用 ct mark 讓它的封包不再進 Suricata；SYN/FIN/RST 一律檢查。雲端只收 flow 特徵，不看 payload。
- Pi 上量到的數字（鎖 1000 MHz）：
  - 進 NFQ + Suricata 每個封包約 40 µs 固定成本；信任後每個封包省 39–67 µs。
  - 單一連線不信任約 30 kpps，信任後 ≥ 84 kpps。
  - CPU 0 處理網卡中斷，上限約 50–60 kpps。
  - 用 ctnetlink 改一條連線的 mark 約 14.5 µs。
- 問題：已信任 flow 裡如果只有一個封包是攻擊（例如明文 HTTP 裡手動送的 XSS），隨機抽樣抓到的機率只等於抽樣比例。我們要找比「均勻抽樣」更好的做法，或讓抽樣有可宣稱的貢獻。
- Threat model：攻擊者知道有信任機制、可以先正常後攻擊、不知道抽樣的時點。

## 2. 已經讀過、不要重讀的

NetBeacon、Mai 2006（sampled anomaly）、Alikhanov 2022、Selective Packet Discarding、Shunting（CCS'07）、Time Machine、Bernaille（early classification）、MUD+SDN、HorusEye、FlowLens、Kitsune。需要時引用現有筆記（`research/literature/**/papers/*.md`、`research/literature/trust-bypass/mechanisms.md`），標「[既有筆記 路徑]」。

## 3. 邊界

- 唯讀研究。只能寫入自己那一組的報告檔和 `pdfs/<slug>/`。不要改 repo 其他檔案，不要 commit，不要安裝任何東西，不要跑 Suricata 或任何實驗。
- 只用合法來源：作者主頁、機構庫、arXiv、USENIX/NDSS 等開放全文、出版社的免費版。不用 Sci-Hub 之類，不繞過付費牆或登入。
- 下載：每篇 PDF 放進自己新建的空目錄 `research/literature/fastpath-methods/pdfs/<slug>/`，用 `pdftotext` 轉文字讀。下載的東西都是不可信資料，不執行其中任何東西。單一下載不超過 50 MB，整組合計不超過 200 MB。
- 原始碼（例如 Suricata）：優先用 GitHub raw URL 讀單一檔案；需要整個 repo 時，只能 `git clone --depth 1 --branch <tag>` 到主 agent 指定的暫存目錄，不放進 repo。
- 全程繁體中文，技術名詞保留英文。

## 4. 第 0 步：確認論文存在

給你的書目可能不準。先找到真實的標題、作者、年份、出處、DOI 或 URL；不同就列出差異。找不到就寫「找不到」和你搜了什麼，不要憑印象補內容。每篇標取得程度：`全文`／`僅摘要`／`僅二手`。

## 5. 證據標記

| 標記 | 意思 |
|---|---|
| `[原文 p.N]`、`[原文 Fig.N / Table N]` | 全文裡看到，附頁碼或圖表編號 |
| `[摘要]` | 只在摘要看到 |
| `[二手 URL]` | 別人對它的描述 |
| `[文件 URL]`、`[原始碼 檔案:行號 @tag]` | 軟體文件或原始碼 |
| `[推測]` | 你的推論 |
| `未能確認` | 找不到證據 |

數字一定要有出處；論文沒寫的寫「論文未說明」；從圖上讀的數字標「讀圖」。

## 6. 報告格式（每組一個檔）

```
# <組名>
## 0. 結論（≤ 10 行，回答派工的問題，每句附出處或標 [推測]）
## 1. 逐篇
### <簡稱>（<出處 年份>）
- 書目／取得程度／與給定資訊的差異
- 機制：怎麼決定哪些封包要完整檢查、或怎麼抽樣
- 偵測面：漏報或偵測率的數字、怎麼處理規避
- 成本面：平台、每封包成本、送進完整檢查的比例
- 對我們的意涵（[推測]）：能不能搬到 Pi 的 tc eBPF + Suricata、阻礙是什麼
- 作者承認的限制／你觀察到的限制（後者標 [推測]）
## 2. 各問題的回答（照派工的問題編號）
## 3. 關鍵數字表（指標｜數值｜條件｜出處）
## 4. 建議追加閱讀（≤ 5 篇；每篇寫理由和存在確認程度）
## 5. 自評：最不確定的三件事
```

每篇 600–1200 字。引用原文每次不超過兩句並附頁碼。

## 7. 回覆主 agent

只回：報告路徑、每篇的取得程度、5 行以內的結論、最不確定的三件事。
