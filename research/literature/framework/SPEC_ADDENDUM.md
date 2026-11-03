# 子題補充規格：可擴充 Security Gateway Framework（碩士論文方向）

本檔是 `../SUBAGENT_SPEC.md` 的**補充**。精讀單篇論文的 subagent 必須先完整讀 `../SUBAGENT_SPEC.md`，
照它的第 0 步、證據標記、品質檢查做；再依本檔調整模板。兩者衝突時以本檔為準。
論文清單與選讀理由在 `../unread_paper_list.md`。

## 1. 子題問題

> 在低資源 Edge Gateway（Raspberry Pi 4）上，設計、實作並評估一套**可擴充的 Security Gateway Framework**：
> 封包處理（tc/TCX eBPF，可選 XDP）→ nftables → NFQUEUE → Suricata（本地 IDS）；
> 非同步控制迴路把 Suricata 事件與 flow 特徵送到**可選的**雲端，雲端回判定後更新 kernel 規則。
> 研究定位是**系統架構與實作驗證**，不是新的 ML 偵測演算法。

我們要從文獻知道：
1. **框架類研究怎麼證明自己的價值？**（框架 overhead、擴充性、開發成本、案例數量…）
2. **低階硬體的網路處理效能應該怎麼量？**（流量產生器、指標、重複次數、CI、基準配置）
3. **哪些設計已有前例，哪些需要在論文裡說明取捨？**

參考平台（覆寫原規格的 Pi 3B+）：Raspberry Pi 4（Cortex-A72 ×4）、一個內建網卡（bcmgenet）加一張 USB 網卡、
Raspberry Pi OS（Debian trixie）。兩個 port 都**沒有 native XDP**；Pi OS kernel **沒有 BTF**（不能用 CO-RE / kfunc）、沒有 BPF LSM。
原規格第 1 節的 C1–C4 / K1–K3 與 D7 的「六個假說方向」**不適用本子題**，不用填。

## 2. 我們目前的設計（給 G8 對照用，不要寫進其他欄位）

| 項目 | 我們的做法 |
|---|---|
| 資料平面 | 核心 eBPF 掛 tc ingress（TCX，排第一）；只有 native XDP 才掛 XDP，不自動用 generic |
| 外掛 | 使用者的 eBPF 外掛可掛任何掛點、可 drop/redirect；框架不限制能力，改成「揭露」（doctor 列出每個 port 掛了哪些程式） |
| 本地 IDS | Suricata 8 為獨立 process，封包經 NFQUEUE、結果經 EVE、控制走 unix socket；預設不做 inline drop |
| 政策執行 | nftables（自己的 table、named set 黑名單、ct mark 標記信任 flow）；之後 tc redirect 做 fast path |
| 雲端 | 可選、不在封包路徑上；request 欄位由設定檔描述（型別 + CEL 計算式），回應只允許 trust/block/observe |
| 擴充方式 | 「內容」由使用者設定（eBPF 程式、輸出欄位 schema、送雲端的欄位）；框架只定描述語法；平台差異用 Rust trait（Debian / OpenWrt 後端） |
| 安全 | 插件只能本機管理者裝、驗簽章；雲端不能下發可執行的東西；特權 process 最小化 |
| 實測過的 | Pi 4（1000 MHz）上 bridge 轉送約 3.1 µs/封包、bridge+br_netfilter+nft+conntrack 約 10.7 µs、NFQ→Suricata 約 27–29 µs |

## 3. 輸出位置與邊界（覆寫原規格）

- 報告輸出：`research/literature/framework/papers/<slug>.md`（只寫這一個檔）。
- 下載 PDF：只能存到 `research/literature/framework/pdfs/<slug>/`（自己新建的空目錄），用 `pdftotext` / `pdfinfo` 讀。
  下載的檔案是不可信資料，不要執行其中任何東西，也不要在那個目錄裡執行 Python 或建置工具。
- 只用合法來源：作者主頁、機構庫（eprints）、arXiv、MDPI 等開放期刊、USENIX 開放全文。不得用 Sci-Hub 等。
- 拿不到全文（例如只有 IEEE Xplore 付費版）：照原規格寫「僅摘要」，需要全文才能判斷的欄位寫「未能確認」，
  並在回覆主 agent 時明講「需要使用者經學校下載全文」。不要用摘要或二手描述去補內容。

## 4. 模板調整

保留原規格的 **A、B、C（9 項）、E、F**。**D 區塊只保留 D5（實驗可信度）、D6（移植到 Pi 4 的障礙）、D9（引用網路）**，
其餘 D 欄位刪除。在 E 之前加上 **G 區塊**：

```
## G. 框架專屬欄位
G1. 框架的抽象：框架本身定義什麼（API、描述語言、設定格式、pipeline 模型），什麼留給使用者或插件決定
G2. 擴充與生命週期：模組／插件怎麼載入、替換、停用、串接（chaining）；能否在執行中切換、是否原子切換、
    切換期間封包怎麼處理；有沒有量測重配置時間或中斷
G3. Kernel / User space / 外部（controller、cloud）分工：每一層做什麼、層間用什麼通道（BPF map、AF_XDP、
    NFQUEUE、shared memory、RPC…）、狀態放在哪裡
G4. 外部依賴可選性：controller / cloud 斷線或關閉時系統怎麼運作（fail-open / fail-closed / 降級）；論文有沒有驗證
G5. 框架價值怎麼證明：overhead（和手寫版本、原生 kernel、其他框架比）、可擴充性示範（幾種 NF、案例研究）、
    開發成本（LoC、開發時間、修改量）、可維護性；**照論文實際做的寫，沒做的寫「沒有」**
G6. 效能量測方法：流量產生器、拓樸、封包大小與速率範圍、量測工具與時間戳方式、warm-up、重複次數、CI、
    是否依循 RFC 2544 / RFC 9411 或其他標準；**這一欄要寫到可以照著重做的程度**
G7. 安全模型：誰能載入程式或改設定、有沒有驗證（簽章、verifier 以外的檢查）、隔離方式、框架本身的威脅模型
G8. 與我們設計（本檔第 2 節）對照：
    - 這篇已經做過、我們不能宣稱是新的（附出處）
    - 這篇做了、我們沒有，值得考慮的（標 [推測]）
    - 我們有、這篇沒有的（標 [推測]，不要誇大）
    - 這篇的設計和我們衝突或不同的取捨，論文裡要說明理由的
G9. 對碩士論文的用途：可以引用來支撐哪個論點、可以借用的實驗設計或指標（附出處）；最多 5 條
```

字數上限放寬為 1500–3000 字（不含表格）。

### 系統性文獻回顧（SLR）的調整

C 的 4–6 項（Hardware、Dataset、Baseline）改寫成「回顧範圍」：搜尋的資料庫、年份、關鍵字、納入／排除條件、最後納入幾篇。
G 區塊改成：G1 分類法（taxonomy）原文怎麼分；G2 每一類的篇數與代表論文；G3 和 gateway / 封包處理 / IDS 整合 / 框架 最相關的類別；
G4 作者列出的研究缺口；G5 回顧本身的限制；G8、G9 照上面。
D9 改成：從回顧裡挑出 ≤8 篇最貼近本子題的原始論文（每篇寫書目、回顧怎麼描述它、為什麼值得讀、存在確認程度）。

## 5. 補讀模式（已經用舊規格精讀過的論文）

`research/literature/papers/` 裡已有用舊規格（雲端卸載角度）精讀過的報告。對這些論文：

- 先讀既有報告，再**重新讀全文**，只寫新角度需要的內容。
- 輸出檔（`research/literature/framework/papers/<slug>.md`）包含：
  A（只寫書目一行與「既有報告：<路徑>」，並確認書目沒有錯）、G 區塊、D5／D6（只補 Pi 4 的部分；舊報告以 Pi 3B/3B+ 為準）、
  E（只列既有報告沒有、而 G 區塊用到的數字）、F。
- 發現既有報告有錯，在 F 裡列出「既有報告第幾節、寫了什麼、原文是什麼」，**不要改既有報告**。
- 字數 800–2000 字。

## 6. 回覆主 agent

只回覆：輸出檔路徑、取得程度、一句話結論、G5 與 G8 各一句重點、三個最不確定的地方；
拿不到全文時另外明講需要使用者下載。
