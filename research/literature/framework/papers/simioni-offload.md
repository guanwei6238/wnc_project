# simioni-offload（補讀：框架子題角度）

頁碼約定：[原文 p.N] 為出版版 PDF 頁碼（共 17 頁，期刊頁碼 = PDF + 20325，例如 Table IV 在 PDF p.14 = 期刊 20339）。本次用 pdftotext 重讀全文，並渲染 p.7、8、10、12–15 目視 Table III–IV、Fig.5–6、Fig.10–13。圖上的數字若是自己從長條圖目測，一律標「目測」。GitHub 只看 README 與目錄（WebFetch，未執行、未讀程式碼），標 [二手 README]。

## A. 書目
Simioni, Viegas, Santin, de Matos, "An Energy-Efficient Intrusion Detection Offloading Based on DNN for Edge Computing", IEEE Internet of Things Journal 12(12), pp. 20326–20342, 15 June 2025, DOI 10.1109/JIOT.2025.3544060 [原文 p.1；pdfinfo Subject]。書目與既有報告一致，無誤。取得程度：全文（出版版）。
既有報告：`/home/sixsquare/wnc_project/research/literature/papers/simioni-offload.md`

## G. 框架專屬欄位

**G1. 框架的抽象**
- 這不是軟體框架論文。固定的是：early-exit DNN 切成分支、每分支一組接受門檻 tc_i = (t_n, t_a)、最後分支的 reject 函數、兩條 RabbitMQ 佇列 [原文 p.8–9, p.11]。留給使用者（operator）的：operating point（門檻）、DNN 架構與出口位置 [原文 p.9, p.12]。沒有描述語言、設定檔格式、外掛介面。
- Fig.3 畫了 End Device / Edge / Cloud 三個位置，但原型只實作兩個出口：Branch 1 在 End Device、Branch 2 在 Cloud [原文 Fig.3 p.8；p.11]。

**G2. 擴充與生命週期**
- 沒有模組載入、替換、串接機制。唯一的「執行中調整」是 operator 不重訓模型、只改門檻就能改變卸載比例 [原文 p.9；Fig.13 p.15]。切換過程中事件怎麼處理、切換要多久：論文未說明、未量。

**G3. Kernel / User space / 外部分工**

| 位置 | 做什麼 | 通道與狀態 |
|---|---|---|
| End Device（Pi 3B，全 Python user space） | Scapy 收包 → numpy 算 15 秒窗 flow 特徵 → Branch 1 → 信心 > 門檻則把標籤交給 Alert；否則把 Branch 1 的中間層輸出 x1 送出 [原文 p.10–11, Fig.5] | Pika 發佈到 Offload 佇列；另有 Consumer 讀 Result 佇列後轉給 Alert |
| Cloud（IBM VM） | **RabbitMQ broker 與 Cloud Processor 同在雲端**：Consumer 取 Offload 佇列 → Branch 2（含 reject）→ Producer 把 Label 發到 Result 佇列 [原文 p.11, Fig.5] | 兩條佇列、單一 broker；狀態只在 broker 與各自 process 內 |
| 決策者 | End Device 用 Branch 1 信心與 (t_n1, t_a1) 比較；雲端只回標籤，被 reject 時為 ∅ [原文 p.9, p.11] | — |

- 送出的內容：只有 x1（Branch 1 的中間層激活）。不送原始封包、不送 58 維特徵向量 [原文 p.9]。每個被卸載事件約 7.2 KB（AlexNet）/ 14.5 KB（MobileNetV2）[原文 Fig.11a, p.14]。[推測] AlexNet 的 Branch 1 分類器輸入是 1600 個值 [原文 p.11]，float32 為 6.4 KB，加上序列化與 AMQP 標頭後接近 7.2 KB；MobileNetV2 的分類器輸入是 1280 個值 [原文 p.11]（約 5.1 KB），與 14.5 KB 對不上，所以 x1 不一定等於分類器輸入。論文沒說訊息格式。
- 論文**沒寫**的佇列設計：序列化格式、事件如何對應回結果（correlation id）、多台 End Device 共用還是各自佇列、發佈是否等待 ack、佇列是否 durable、prefetch、佇列上限或 TTL。README 的範例只有一個 `--mq-queue ee-alexnet` 參數，看不出 Result 佇列怎麼命名 [二手 README]。
- 雲端回的是「標籤」，End Device 只送到 Alert module [原文 Fig.5]。沒有「雲端判定回來後更新本地阻擋規則」的路徑。

**G4. 外部依賴可選性**
- **論文沒有驗證「雲端不可用時本地仍可運作」。** 全文搜尋 timeout、fail、unavailable、outage、backlog 等詞，沒有任何相關段落；唯一提到不穩網路的是 p.15 一句：operator 可以調 batch size 來應付 "high latency or intermittent packet loss"。這是主張，Fig.11(b) 只量了不同 RTT zone 下的 batch 效果，沒有注入掉包或斷線。
- 最接近的兩個東西都是**設計上的運作模式，不是故障測試**：(1) Fig.10 的 "Ours (No offload)"：兩個出口都在 Pi 上跑，處理時間 AlexNet 11.4% / MobileNetV2 37.8%、能耗 12.1% / 47.1%（相對完整 DNN 在 Pi 上跑）[原文 Fig.10 p.13]；(2) Fig.13 掃 offload rate 0–100%，0% 即全本地 [原文 p.15]。p.15 寫 End Device 在資源足夠時「可以兩個分支都在本地執行」，需要時全部卸載，由 operator 決定。沒有自動切換、沒有偵測雲端失聯的機制。
- 為什麼這不等於我們的目標：這個設計裡，信心不足的事件（約 10%）**本地沒有判決**，只有完整 DNN 能給；退回本地就是在 Pi 上跑完整分支，Table IV 的 Local Device 每事件 1385.94 ms（Branch 2 部分 1365.70 ms）[原文 Table IV p.14]。雲端不可用時 Result 佇列永遠等不到的事件怎麼處理（Alert 等不等、是否有預設判決）論文未說明。
- 佇列堆積：唯一相關的是 Fig.12。1–30 台 End Device 全部事件上雲（batch 10），Brazil 約 8 台、US 約 10 台以內平均回應時間不變，超過後近似線性上升，到 30 台約 140 ms（目測）[原文 p.15]。作者把它當擴展性證據，對策是「多開 VM」；沒有量佇列長度、沒有丟棄、反壓、逾時或本地降級。

**G5. 框架價值怎麼證明（照論文實際做的）**
- 做了：相對 baseline（完整 AlexNet / MobileNetV2 在 Pi 上跑，稱 Traditional）的每事件時間與能耗（Fig.10）、兩個雲端 zone 的延遲（Table IV）、每事件傳輸 bytes（Fig.11a）、batch 1/5/10（Fig.11b）、1–30 台裝置（Fig.12）、offload rate 0–100%（Fig.13）[原文 p.13–15]。
- **沒有**：與其他卸載方案比（只比 Traditional）、與「全部卸載」實測比（只用「每個 flow 約 11.6 個封包」文字論述，沒有 bytes）[原文 p.15]、開發成本（LoC、時間）、可維護性、任何轉送 throughput/latency。可擴充性示範只有 2 個 DNN 各 1 個出口位置、2 個雲端 zone。
- 成本記帳的範圍：能耗只算 Pi 端「推論＋卸載動作」[原文 p.11]；雲端算力只量事件處理時間，沒有雲端能耗或費用；傳輸只量每事件 bytes，沒有總頻寬。

**G6. 效能量測方法（寫到可照做；缺的參數另列）**

| 項目 | 論文寫了什麼 | 論文沒寫（照做前要自己決定） |
|---|---|---|
| 能耗 | 接在供電插座的 "current-voltage power ratio consumption meter"；先量 idle，再算執行推論時的差值；推論能耗**包含卸載動作** [原文 p.11]。Fig.10 縱軸單位是 µAh/事件 [原文 Fig.10] | 電表型號、取樣頻率與平均窗、每次跑幾個事件、重複幾次、Pi 的 CPU 頻率/governor、網路介面（有線或 WiFi）、µAh 如何換算 |
| 處理時間 | End Device 端每事件平均時間，含 Branch 1 與必要時的卸載 [原文 p.14]。Table IV 分 Branch 1 / Branch 2 / Total | 計時點（發佈前後？收到 Result 時？）、warm-up、事件數 |
| RTT | 兩個 zone 的「平均 RTT」：Brazil 23.51 ms、US 157.48 ms，「during the experiments」[原文 p.14] | 量法（ICMP ping 或 AMQP 應用層）、次數、封包大小、跳數（只說 "fewer" 與 "higher number of network hops" [原文 p.13]） |
| 地端位置 | End Device 在巴西 Paraná 州南部 [原文 p.13] | 接入網路類型（校園網？ISP？） |
| 雲端設定 | IBM Cloud VM，2 vCPU、8 GB、Ubuntu 24.04；「multiple zones」：Brazil South 與 Central US；每個 zone 上跑 RabbitMQ broker + Cloud Processor [原文 p.11, p.13] | 實例規格名、有無 GPU（未提）、broker 版本與設定、TLS/VPN、兩個 zone 的 VM 是否完全相同 |
| 流量與輸入 | MAWIFlow 的預算特徵（見 D5）；每事件 bytes 是 Fig.11a 的單一長條 | bytes 是應用層 payload 還是含 AMQP/TCP/IP 標頭 |
| 規模與 batch | batch 1、5、10；裝置 1–30 台、batch 10、全部事件卸載 [原文 Fig.11b, Fig.12] | 多台 End Device 是實體 Pi 還是同一台模擬（未說） |
| 統計 | 單次長條/曲線 | 重複次數、標準差、CI：全都沒有 |

- 「Brazil 與另一地區」的實際設定：[推測] IBM Cloud VPC 的區域代碼是 us-south（Dallas）、br-sao（São Paulo）[二手 https://www.ibm.com/docs/en/SS6QJ7/cloud-regions.html 搜尋摘要]，沒有 "Central US" 這個名稱（那是 Azure 風格的命名），所以論文的「Central US」對應哪個 IBM 區域無法確定。
- 能耗量測要重做的最小版本 [推測，依論文描述]：同一台 Pi、固定頻率、同樣的網路介面，先量 idle，再量連續處理 N 個事件的平均功率差，除以事件數。論文描述不足以重現數值，只足以重現方法。
- README 的雲端部署步驟：`apt install rabbitmq-server`、`rabbitmqctl add_user`、`set_permissions -p "/" ... ".*" ".*" ".*"`、開 security group；雲端跑 `offload/ee-processor-server.py`，裝置端跑 `offload/ee-processor-client.py --dataset <csv> --batch-size ...` 並給四個最小信心門檻 [二手 README]。README 沒有電表腳本、RTT 量測、逾時設定。

**G7. 安全模型**
- 論文沒有威脅模型。README 範例的 RabbitMQ 帳號是 remote / remote、對 vhost "/" 有 configure/write/read 全權限，只提醒開 security group，沒提 TLS [二手 README]。AMQP 連線是否加密、雲端回傳是否驗證：論文未說明。

**G8. 與我們設計對照**
- 這篇已做過、不能宣稱是新的：
  - 「Pi 與雲端以非同步佇列（RabbitMQ + Pika）連接」[原文 p.11]。
  - 卸載比例可在部署後由 operator 調整、不必重訓 [原文 p.9, Fig.13]。
  - 卸載的是中間激活，不是封包 [原文 p.9]；我們的決定是雲端不看 payload，兩者方向相同，但這點本身不新。
  - 量 RTT 隨雲端位置的影響 [原文 p.14] 與 batch 攤提 RTT（最多 −70%/−72%）[原文 p.15]。
- 這篇做了、我們沒有，值得考慮 [推測]：
  - 用能耗而不只用 CPU 時間記帳（插座電表、扣 idle、把卸載動作算進去）。
  - 以本地信心值決定卸載，並離線找 Pareto 前緣讓 operator 挑 operating point。我們的 Suricata 輸出沒有連續信心值，這部分不能直接搬。
  - 多裝置對雲端的擴展測試（Fig.12）。
- 我們有、這篇沒有 [推測，不誇大]：
  - 封包路徑：論文只寫 "monitored NIC" [原文 p.10–11]，沒說 inline 或 tap，也沒量任何轉送效能；我們有 bridge/NFQ 的 µs 級實測。
  - 雲端判定回來後更新 kernel 規則；這篇只輸出到 Alert。
  - 雲端不在決策路徑上：這篇的難事件只能由雲端判決。
  - request 欄位由設定檔描述；這篇固定送 DNN 激活張量。
  - 雲端斷線的設計目標；這篇沒有（G4）。
- 取捨不同、論文要說明：他們的雲端在約 10% 事件的判決路徑上，換來本地不需要大模型；我們把雲端放在路徑外，換來斷線時行為可預測，但雲端的判定只能影響之後的封包。

**G9. 對碩士論文的用途（≤5）**
1. 「卸載評估該報哪些軸」的前例：相對全本地的時間與能耗、每事件 bytes、RTT zone、batch、裝置規模、offload rate [原文 Fig.10–13]。
2. 能耗量法（插座電表、idle 基線、含卸載動作）可借用，但我們要補上論文缺的參數（取樣率、頻率鎖定、重複次數）[原文 p.11]。
3. RTT 影響：zone 差 133.97 ms RTT（157.48−23.51，自行相減）使 AlexNet 平均事件時間增加 35 ms、MobileNetV2 增加 26 ms [原文 p.14]，可支持「雲端放近一點」與「不放在封包路徑上」的論點。
4. 本篇沒有驗證雲端不可用時的行為，可當作「卸載設計不一定處理斷線，降級行為需要實測」的一個例子 [推測，僅憑本篇，不代表整個領域]。
5. 反面教材：圖表單位與數字互相不一致、沒有重複次數（見 F）；我們的評估要報 n 與 CI。

## D5／D6（只補 Pi 4）
- D5：README 的 `ee-processor-client.py` 輸入是 `--dataset` CSV [二手 README]，所以 [推測] 卸載量測餵的是預算特徵，Scapy 與特徵抽取不在被量的迴圈內，與舊報告判斷一致，現在有 README 佐證。NSGA-II 的預設參數在 README 是 1000 generations，論文寫 100 [原文 p.12；二手 README]，可能只是腳本預設值，未查。
- D6（Pi 4）：論文的 PyTorch 2.1 + Scapy + Pika 只在 Pi 3B 驗證 [原文 p.10–11]，Pi 4 上能否跑未驗證；我們的框架不跑 DNN，可移植的只有「兩佇列非同步卸載」與「量測方法」。[推測] Pi 4 以 USB-C 供電，同樣可用插座電表，但 idle 基線要在同樣的網卡（bcmgenet + USB 網卡）與連線狀態下量，頻率要鎖定（我們的 Pi 4 量測用 1000 MHz）。論文沒寫 Pi 3B 的頻率設定，兩邊絕對數字不可比。

## E. 關鍵數字表（舊報告沒有、G 區塊用到的）

| 指標 | 數值 | 條件 | 出處 |
|---|---|---|---|
| Table IV：AlexNet 本地 | Branch 1 20.24 / Branch 2 1365.70 / Total 1385.94 ms | Pi 3B，完整 DNN | 原文 Table IV p.14 |
| Table IV：AlexNet 卸載 Brazil | 18.08 / 10.28 / 28.36 ms | 同上，雲端 Brazil | 原文 Table IV p.14 |
| Table IV：AlexNet 卸載 US | 18.08 / 46.18 / 64.26 ms | 雲端 US | 原文 Table IV p.14 |
| Table IV：MobileNetV2 本地 / Brazil / US | 236.89 / 432.56 / 669.45；217.13 / 5.97 / 223.09；217.13 / 32.6 / 249.73 ms | 同上 | 原文 Table IV p.14 |
| Fig.6(b)：operating point 的時間降幅 | AlexNet −86%、MobileNetV2 −44%；error −2.9% / −2.5% | 1 月 validation | 原文 p.12, Fig.6b |
| Fig.10 縱軸 | Traditional 約 5100 ms、約 90 µAh（AlexNet）；約 2500 ms、約 36 µAh（MobileNetV2） | 單事件 | 目測 Fig.10 |
| Fig.11(b) 每事件時間，batch 1 → 10 | Brazil AlexNet 約 33 → 10 ms；US 約 145 → 44 ms | 只算到達 Branch 2 的事件 | 目測 Fig.11b |
| Fig.12 | Brazil 單台約 11 ms、US 單台約 33 ms；30 台時皆約 140 ms | batch 10，全部卸載，AlexNet | 目測 Fig.12 |
| Fig.13（AlexNet）Device / Cloud 時間，offload 0→100% | Device 約 590 → 50 ms；Cloud 約 0 → 540 ms | zone、batch、事件數未說 | 目測 Fig.13a |
| 每被卸載事件的 Branch 2 時間 | Brazil AlexNet 約 103 ms；US 約 462 ms | 10.28 ÷ 0.10、46.18 ÷ 0.10 | [推測] 自行計算，假設 Table IV 的 Branch 2 對所有事件平均、卸載率 ≈10% |

## F. 自評

**既有報告需修正或補充**（不改既有報告）
1. 既有報告 C.2 寫「原型中 Edge 只是 RabbitMQ 通道的中介」。出版版 p.11 與 Fig.5 把 RabbitMQ broker 放在 Cloud Infrastructure，Edge Infrastructure 框裡是 End Device 1..N。（既有報告讀的是稿件版，措辭可能不同，我沒有比對稿件。）
2. 既有報告 Q3 只記 Table III（約 7 events/s，約 136 ms）與 Table IV（本地 AlexNet 1385.94 ms）不一致。補充：Fig.6(b) 目測 Traditional 約 125–135 ms，與 Table III 相符；Fig.10(a) 縱軸目測約 5100 ms，與 Table IV 又不符；Fig.10 標的 0.9% 與 Table IV 算出的 28.36 ÷ 1385.94 ≈ 2.0% 不符（0.9% 的 1385.94 ms 只有約 12.5 ms，比 Branch 1 單獨的 18.08 ms 還小）；p.14 內文同時寫「降到 1%」與「減少 97%」。引用「時間降到 1%」要避免，改引能耗 1.0% 時也要知道沒有第二個來源可核對。
3. 既有報告 Q1 說「nsga2_2variables.py 與 4 變數是否一致未能確認」：README 說該腳本產生 n_1、a_1、n_2、a_2 四個值，檔名的 2 指 2 個出口 [二手 README]，一致。
4. 既有報告 Q4 說 Pi 是「被動監聽 NIC」：論文只寫 "monitored NIC through Scapy"，沒說 inline 或 tap；「被動」是推論。
5. 新觀察 [推測]：Fig.6(b) 的 −86%/−44% 較接近 Fig.10 的 "No offload"（12%/47% 能耗）而不是 "Offload"（1%/41%），NSGA-II 的 σ 可能不含卸載成本，「1%」可能是事後量到的數字，不是最佳化目標。
6. Fig.13 的 Device 與 Cloud 時間加總在各 offload rate 幾乎恆定（AlexNet 約 590 ms、MobileNetV2 約 1020 ms，目測），[推測] 可能是依比例分攤而非各點獨立量測，論文沒說。

**未能確認**：電表型號與取樣；RTT 量法；Fig.13 的 zone 與 batch；多台 End Device 如何實現；RabbitMQ 設定；雲端不可用時的行為（論文未涉及，非未能取得）。

**最不確定的三件事**
1. Table IV 的 Branch 2 是否對所有事件平均（我據此推出每卸載事件約 103/462 ms，屬 [推測]）；若不是，E 表最後一列作廢。
2. Fig.10–13 的目測數字誤差（長條圖無數值標示，我只有座標軸刻度）。
3. 「Central US」對應的實際 IBM 區域，以及該論文的 RTT 是 ICMP 還是應用層量得。
