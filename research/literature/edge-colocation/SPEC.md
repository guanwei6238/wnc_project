# 子題規格：同一台 gateway 上 rule、edge AI、轉送怎麼分資源

2026-11-02 開的子題。邊界、第 0 步、證據標記、報告格式、回覆方式都照 `../fastpath-methods/SPEC.md` 的 §3–§7，只有下面不同。

## 1. 背景（只用來判斷相關性）

- `../fastpath-methods/SPEC.md` §1 的平台和數字都適用：Pi 4（Cortex-A72 ×4）、bridge、Suricata 8.0.7 走 NFQUEUE（ips）或 NFLOG（ids）、ct mark 信任、tc eBPF。
- 2026-11-02 新條件：地端有 rule（Suricata）和 edge AI，再加上雲端。edge AI 是合作方的模型，輸入、任務、模型都還不確定，**跑在 gateway 同一台機器上**。正式設備之後不是 Pi，但研究在 Pi 4 上做。
- 所以網卡中斷、Suricata worker、轉送、edge AI 要搶同樣的 4 顆核心。Pi 4 的網卡中斷全在 CPU 0，上限約 50–60 kpps；信任每個封包省 39–67 µs。
- 我們想知道：有沒有類似的框架，它們怎麼分資源；有沒有能讓我們「依負載調整稽核量、edge AI 推論量」的方法；哪裡是空缺。

## 2. 已經讀過、不要重讀的

`../fastpath-methods/SPEC.md` §2 那份清單，加上：`research/literature/papers/` 和 `research/literature/framework/papers/` 底下所有筆記（Simioni offload、SAPO-BOI、edge multi-agent IDS、eBPF/XDP-DL、Galette、PASS、Polycube、MiddleNet、Palantir 等），以及 `../fastpath-methods/` 的三份報告。需要時引用，標「[既有筆記 路徑]」。

## 3. 輸出

- 報告：`research/literature/edge-colocation/<組>.md`（只寫自己那一組的檔）。
- 下載：`research/literature/edge-colocation/pdfs/<slug>/`（每篇自己新建的空目錄）。只放 PDF 和轉出來的文字；**不要把原始碼 repo 或規則檔放進 repo**，需要看程式碼就用 raw URL。
