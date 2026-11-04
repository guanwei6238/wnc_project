# slide_implement.md — Security Gateway 本地 IDS 偵測測試

> 投影片的規格：每一頁放什麼、數據從哪個檔案來、數字的定義、講稿要注意的事。
> 與 `src/main.typ` 同步；兩者不一致時以 `main.typ` 為準。講稿：`逐字稿.md`；草稿：`user_draft.md`。
> 頁碼一律用投影片右下角的顯示頁碼（第八版起：p1 大綱 … p12 References，頁序見「第八版規格」第 1 點；後面各頁的舊規格用的是第七版頁碼）。
> 「講稿注意」和 `>` 引言的內容不印到投影片上。

---

## 改動紀錄（只記在這裡，不寫進講稿）

- 2026-11-02 精簡當場講（使用者：「報告模式我需要每一列都講嗎？」→ 建議每頁講範圍、總結數字、挑 1–2 列；「改」）：第 5–9 頁的當場講各縮成 4–5 句（p5 偵測到 C&C checkin、ELF、SSH port scan，抓不到 Okiru、DDoS；p6 Web、Infiltration、FTP，DoS Hulk 0；p7 MSSQL、NTP 10 條，其他 17 項是 ping、SSH、SNMP public；p8 整檔算攻擊、Web／暴力破解／Recon、flood 與 Spoofing 是 UPnP、ping；p9 只講結論）。原本的當場講整段移到第二部分各頁最前面的「逐列說明」，資訊不變。
- 2026-11-02 逐字稿排版（使用者：「幫我把講稿單純切開或者是單獨放在上方，不然我很難讀」）：重排成兩部分，「一、當場講」（封面到 Q&A 每頁只放要講的話）、「二、補充」（每頁的 `>` 內容，拿掉 `>`）；內容不變（當場講 69 行、補充 483 行，重排前後相同）；章節頁標題寫「（章節頁）」，內文的同一個字拿掉；檔頭「使用方式」改寫。之後新增講稿內容照這兩部分放。
- 2026-11-02「觸發的 rule」欄只寫 rule（使用者：「不用提到背景流量，那只是觸發 rule，只寫 rule」「一起拿掉」）：p8 △ 四列「背景 UPnP、ping」→「UPnP NOTIFY、ICMP PING」，Mirai →「UPnP NOTIFY、ICMP PING、HUNTING port 53」，Benign →「UPnP NOTIFY、ICMP PING」；p5 Attack、p6 SSH-Patator「SSH scan（只數 SYN）」→「SSH scan」；p7 DrDoS_SNMP「SNMP `public`（協定的使用）」→「SNMP `public`」。為什麼對不上改由口頭說明（講稿已有）。p5 Okiru 的「IP 清單（Spamhaus DROP）」保留（括號是哪份清單，屬於 rule 內容）。下面第八版規格裡這幾格的舊寫法以本條為準。p8 的 Mirai 列放不進一行，表格字級 0.78em → 0.74em、左右留白 8pt → 5pt。
- 2026-11-02 rule set（使用者：「設定有寫使用兩個 rule set，但是後面的結果都只有一個值」；選 p3 拿掉 Rule set 那行、p9 有 alert 只留 `full`，「改」）：p3 表只剩 Engine、Rules、讀法；p9「有 alert 的 flow」欄只留 `full`（5.01%、0.39%、0.002%、0.004%）。講稿第 3 頁當場講改說「rule 全部啟用」，`gw_corp` 移到補充；第 9 頁當場講不再提 `gw_corp`，「full 和 gw_corp 差在哪」改成「挑過的 rule set 會不會漏？」（rule 對得上相同、有 alert 與誤報的比較、flowbits 753／3、xbits 46／1、hostbits 0，4 條都沒觸發）。理由：rule set 以完整偵測面為主（10/18），`gw_corp` 只回答挑過會不會漏。直接修改。
- 2026-11-01 第十版（使用者：「照建議做」，Opus 第九版驗證的 M1、M2、L1、L2）：
  - `related_rules.tsv`：Uploading_Attack 回到 /etc/passwd（2002034、2025879）→ ✓（和 Backdoor_Malware 同一對 rule、同樣的流量；passwd 出現在回應代表透過 web 漏洞執行命令成功，CommandInjection、Backdoor、Uploading 一起算）；DrDoS_SNMP 的 `GPL SNMP public access` 和 IRC 同型（認的是協定的使用）→ △；`ET SCAN*` 扣掉 IMAP／POP3「Possible Brute Force」四條（2002992–2002995）；FileDownload 清單拿掉 HUNTING curl UA（2034567，數字不變）。`related_flows.py` 支援「ET SCAN* -SID,…」。第九版清單與結果備份 scratchpad `related_rules.v9.tsv`、`unified_by_label.v9.tsv`。
  - 結果：CIC-IDS2017 Portscan 185 → 175（合計 1,900，0.38%，✓9 不變）；CIC-DDoS2019 ✓2 △17、rule 對得上 10 條（0.00001%）、2／19；CICIoT2023 Web-based（6 種）20,069／410／115、Recon 1,847（HostDiscovery 399、VulnerabilityScan 196）、合計 1,967（0.0002%）、✓11 △22、11／33。IoT-23 不變。只算比對 payload 的：IoT-23 4／15、CIC-IDS2017 8／15、CICIoT2023 9／33。
  - 投影片：p6 Portscan 175、總結 1,900；p7 DrDoS_SNMP 改 △ 列（觸發的 rule 寫 `SNMP public（協定的使用）`），排在 ✓ 之後、其他 16 項之前，總結 ✓2 △17；p8 Web-based（6 種），Uploading_Attack 那一列拿掉；p9 2／19、0.00001%、11／33。
- 2026-11-01 p11 下一步（使用者：下一步是 inline 測試，比較自己開發的框架與直接使用 Suricata 的速度；「現在只需要說預計，而不是把下一步怎麼做都講出來」；確認建議後「可以」）：投影片只留「預計：inline 測試／比較自己開發的框架與直接使用 Suricata 的處理速度」；拿掉 inline 重播做法、HTTP flood profiler、flow 統計偵測、接上 gateway 看 alert 四項；講稿當場講一句，補充只留「inline 是什麼」「框架是什麼」。第 3 頁補充「要等 inline 重播驗證（第 11 頁）」改成「還沒有驗證」。直接修改。
- 2026-11-01 第九版：嚴格的「rule 對得上」（使用者：「好，照你說的改」；三點：只數 SYN 的 SSH scan 不算對得上暴力破解或連線嘗試、IRC 指令的 rule 不算 C&C、Uploading_Attack 靠的 /etc/passwd rule 不算）；「dataset 底下的排版很怪，應該整齊的靠左對齊，分兩邊是可以的」。
  - `related_rules.tsv`：IoT-23 Attack、CIC-IDS2017 SSH-Patator、CICIoT2023 Uploading_Attack 清單清空（→ △）；IoT-23 C&C 只留 Mirai checkin、Muhstik（4,161 → 1,238）；CICIoT2023 DictionaryBruteForce 只留 LibSSH（108 → 5，仍 ✓）。重跑 `related_flows.py`。v8 的清單與結果備份在 scratchpad `related_rules.v8.tsv`、`unified_by_label.v8.tsv`。
  - Opus 第九版驗證（高 0、中 5、低 11；數字全對）：M3–M5、L3–L11 已改（SSH scan 與 LibSSH 用 rule 內容區分、C&C 官方定義含 IRC 類指令、1,238 精確的理由、CIC-DDoS2019 官方分類、SynonymousIP 定義與論文的工具、p6 總結 0.75em、刪 `note`）；M1（`/etc/passwd` rule：Backdoor ✓ 與 Uploading △ 用同一對 rule）、M2（SNMP `public` 和 IRC 同型）、L1（`ET SCAN*` 含 IMAP／POP3 brute force rule）、L2（FileDownload 清單含 HUNTING curl UA）交給使用者決定。
  - 結果：IoT-23 ✓5 △2 ✗8、對得上 14,758,406（5.01%）；CIC-IDS2017 ✓9 △1 ✗5、1,910（0.38%）；CIC-DDoS2019 不變；CICIoT2023 ✓10 △23 ✗0、1,989（0.0002%）。p9 攻擊種類 5／15、9／15、3／19、10／33。只算比對 payload 的：IoT-23 4／15、CIC-IDS2017 8／15、CICIoT2023 8／33（Uploading_Attack 是 payload rule）。
  - 使用者：「這種不一致是可以接受的，因為看得出來差別，但是細節有哪些要在逐字稿寫清楚，讓我知道怎麼回答」→ 合併列的名稱維持（CICIoT2023 用論文分類、其他寫「X 等 N 種」）；講稿第 5–8 頁的被問到時（第 7 頁放在「共用」段）各加一題「包含哪些、差在哪」：IoT-23 FileDownload 類與 DDoS 等 8 種（含官方 label 定義，來源 stratosphereips.org）、CIC-IDS2017 DoS Hulk 等 5 種、CIC-DDoS2019 其他 16 項（逐項 flow）、CICIoT2023 每個類別（逐項 flow、DDoS 與 DoS 差在攻擊者幾台）。逐字稿由 Sonnet 依第九版更新，「包含哪些」由主 agent 加。
  - 投影片：四頁的列順序統一成 ✓ → △ → ✗ → Benign；表與總結包在同一個 block，總結靠左對齊表的左緣，鍵與值都靠左；p5 C&C 的 rule 欄寫 `C&C checkin`；p10 結論表第一列例子「IRC 指令」→「C&C checkin」（IRC 不再算對得上）。
- 2026-11-01 第八版：四個 dataset 用同一個標準（使用者：「4 個 dataset 的數據表示都不一樣，應該要有同一標準」「好，用這個標準做出來，我再來看要怎麼修」；總表位置由使用者選「四個 dataset 之後」）。規格見下面「第八版規格」，它優先於後面各頁的舊規格。
  - 新指標「rule 對得上的 flow」（逐條 flow 版本）與「rule 對得上的攻擊種類」，取代「有攻擊相關特徵的 alert」這個名稱；判斷符號 ✓△✗ 四個 dataset 同一個定義。
  - 每種攻擊算哪些 SID：`tests/detection/results/related_rules.tsv`（新）；計算：`tests/detection/related_flows.py`（新）→ `results/unified_by_label.tsv`。全部是精確值（IoT-23 C&C 在 6 個 scenario 裡沒有混用相關與無關的 SID，所以不用重跑比對）。
  - 頁序：偵測總表移到四個 dataset 之後；原 p7（IoT-23 觸發的 rule）併進 IoT-23 頁的「觸發的 rule」欄；原 p11（Benign）併進各頁的 Benign 列和總表的「誤報」欄。共 12 個編號頁（原 14）。
  - 使用者看過第八版後：「每個 dataset 的底下都有一個數據總結，應該要寫詳細一些，並且分行」「灰色的部份可以移除，那些都是重複的，可以口頭再說」→ p5–p8 表下的一行改成兩欄三行的數據總結（malicious flow、有 alert、rule 對得上、判斷、誤報，都寫條數與比例）；p5–p9 的頁尾 note 全部拿掉，講稿裡「頁尾有寫」「頁尾：」改成指第 4 頁或直接說明。下面各頁規格裡的「表下：」「note 第二行」「頁尾 note」以這條為準。
  - Opus 第八版驗證後（數字、頁碼、資訊搬移都對；高 1、中 6、低 14）：H1 p4 原因不符的例子「CIC-DDoS2019 Syn → ping」是錯的（03-11 Syn 的 227 條沒有 ping、01-12 只有 3／47），換成 DrDoS_DNS（143／162 是 ping）；M1 兩處 ✓ 定義拿掉「rule 在 `gw_corp` 裡」；M2、M3 CICIoT2023 的 Benign 基準判法改稱「三群」，不再用 ✓△✗，`ciciot2023_judgement.tsv` 註明判斷欄是三群；M4、M5 IoT-23 補充的舊頁用語；低：L4–L14 照建議改（p7、p8 表下「攻擊 flow」→「malicious flow」、p8 Mirai 列加 HUNTING、L1 加 C&C IRC rule 的 Q&A）。M6（SSH scan 算不算對得上暴力破解）、L1、L3（Uploading_Attack 靠 passwd rule）留給使用者決定，`related_rules.tsv` 沒改。p10 結論表第二列的 `#no 大多` 先改成 `#partly／#no 大多`，p9 note「見講稿」改成「不等於 false positive rate」（實作後、驗證前由主 agent 修）。
  - 統一定義的結果：CICIoT2023 原本的 ✗ 16 種因為照官方 label 都有背景的 alert，全部變成 △（✓11 △22 ✗0）；CIC-DDoS2019 其他 16 項是 △（✓3 △16 ✗0）。

### 第八版規格（統一標準）

**0. 名詞與定義（全份統一）**
- 判斷一種攻擊（label）時只有四種結果，講稿用這四個詞：
  - **偵測到（✓）**：攻擊流量上有 alert，而且觸發的 rule 描述的就是這種攻擊（rule 對得上）。
  - **原因不符（△）**：攻擊流量上有 alert，但觸發的 rule 都對不上這種攻擊（例：攻擊主機的 ping、背景流量、只因 IP 在黑名單）。
  - **漏報（✗）**：攻擊流量上完全沒有 alert。
  - **誤報**：Benign flow 有 alert。
- **rule 對得上的 flow**：該 label 的 flow 裡，至少有一筆 alert 的 SID 在 `related_rules.tsv` 該 label 的清單裡（`ET SCAN*` = rule 名稱以 ET SCAN 開頭）。「對得上」是看 rule 描述的內容，不是看名稱相同；清單是 Claude 依 rule 名稱與內容判斷的，每條都有理由欄，使用者還沒逐條確認。
- **rule 對得上的攻擊種類**：rule 對得上的 flow > 0 的攻擊種類數 ＝ ✓ 的個數。
- 「有攻擊相關特徵的 alert」這個名稱全份不再使用（投影片與講稿），改說「rule 對得上」。「偵測到」只用在 ✓。
- rule 對得上的 SID 都在 `gw_corp` 裡（IoT-23 下載類的 HUNTING／INFO SID 不在，但這些 flow 都同時有 `gw_corp` 的 2019240），所以 rule 對得上的 flow 在 `full`、`gw_corp` 一樣。
- CICIoT2023 照官方 label：整個檔的 flow 都算該檔的攻擊（含背景流量），flow 是 Suricata 算的。

**1. 頁序（顯示頁碼）**
p1 大綱 → （章）Dataset 對齊 → p2 對齊結果 → （章）偵測測試設定 → p3 實驗設定 → p4 偵測怎麼算 → （章）偵測結果 → p5 IoT-23 → p6 CIC-IDS2017 → p7 CIC-DDoS2019 → p8 CICIoT2023 → p9 偵測總表 → （章）結論與下一步 → p10 結論 → p11 下一步 → p12 References → Q&A。
- 拿掉的頁：原 p7「IoT-23：觸發 alert 的 rule」（內容進 p5 的「觸發的 rule」欄與 p5 講稿補充）、原 p11「Benign 上的 alert」（內容進各頁 Benign 列、p9「誤報」欄、p9 講稿補充）。原 p7、p11 的講稿補充內容要保留，搬到 p5、p9 的補充裡（只改頁碼與指投影片的說法）。
- 舊→新頁碼：p2→p2、p3→p3、p4→p4、p5→p9、p6→p5、p7→p5、p8→p6、p9→p7、p10→p8、p11→p9、p12→p10、p13→p11、p14→p12。講稿與 `main.typ` 裡所有「第 N 頁」都要照這張表換。

**2. 四個 dataset 頁共用的版型（p5–p8）**
- 一張表，6 欄：`攻擊`｜`flows`｜`有 alert 的 flow`｜`rule 對得上的 flow`｜`判斷`｜`觸發的 rule`。數字都寫條數（千分位逗號），靠右；判斷用 `#yes`／`#partly`／`#no`，置中。
- 列：✓ 的每種一列（觸發同一類 rule 的可以併成一列，例：FileDownload 類）；△ 太多時依類別併列；✗ 併成「X 等 N 種」一列；最後一列 Benign（`rule 對得上的 flow`、`判斷` 寫「—」，`觸發的 rule` 寫誤報的主要 rule）。
- 「觸發的 rule」：✓ 列寫對得上的 rule（`related_rules.tsv` 的 `rule_short`）；△ 列寫實際觸發的 rule；✗ 列寫「—」。
- 表下是數據總結（`main.typ` 的 `summary`，兩欄三行，鍵粗體，鍵與值都靠左，和表格包在同一個 block、對齊表的左緣；CIC-IDS2017 頁字級 0.75em，其他 0.85em）：左欄 `malicious flow`（條數與攻擊種類數）、`有 alert`（條數與比例）、`rule 對得上`（條數與比例）；右欄 `判斷`（✓ a 種、△ b 種、✗ c 種）、`誤報`（Benign N 條裡 M 條與比例）。CIC-DDoS2019 用「項」。
- 不放頁尾 note（使用者：灰色的部份是重複的，口頭說）；符號定義在 p4，範圍說明在講稿當場講。

**p5 — IoT-23**
| 攻擊 | flows | 有 alert 的 flow | rule 對得上的 flow | 判斷 | 觸發的 rule |
|---|---|---|---|---|---|
| PartOfAHorizontalPortScan | 213,852,924 | 14,757,108 | 14,757,091 | ✓ | SSH scan |
| C&C | 21,995 | 4,165 | 1,238 | ✓ | C&C checkin |
| FileDownload 類（3 種） | 82 | 77 | 77 | ✓ | ELF 下載 |
| Okiru | 60,990,708 | 34 | 0 | △ | IP 清單（Spamhaus DROP） |
| Attack | 9,398 | 1,389 | 0 | △ | SSH scan（只數 SYN） |
| DDoS 等 8 種 | 19,574,148 | 0 | 0 | ✗ | — |
| Benign | 30,860,691 | 2,837 | — | — | SSH scan、IRC、BitTorrent |
- 表下總結：malicious flow 2.94 億條（15 種攻擊）、有 alert 1,476 萬條（5.01%）、rule 對得上 1,476 萬條（5.01%）、判斷 ✓ 5 種、△ 2 種、✗ 8 種、誤報 Benign 3,086 萬條裡 2,837 條（0.009%）
- note 第二行：`全部 23 個有 label 的 scenario、完整 pcap；rule set 為 full`
- 數字來源（`unified_by_label.tsv` 的 iot23 列）：FileDownload 類 = C&C-FileDownload 53／50／50、FileDownload 18／16／16、C&C-HeartBeat-FileDownload 11／11／11；DDoS 等 8 種 = DDoS 19,538,713、C&C-HeartBeat 33,673、C&C-PartOfAHorizontalPortScan 888、C&C-HeartBeat-Attack 834、C&C-Torii 30、PartOfAHorizontalPortScan-Attack 5、Okiru-Attack 3、C&C-Mirai 2；Benign = Benign 30,858,735／2,834 ＋ 小寫 benign 1,956／3。malicious 合計 294,449,255、有 alert 14,762,773（5.0137%）、rule 對得上 14,758,406（5.0122%）、`gw_corp` 有 alert 14,762,716。
- C&C 的 1,238：3-1 (Muhstik) 6（Muhstik CnC）、49-1 (Mirai) 1,232（Mirai checkin）。IRC 指令的 rule（34-1 (Mirai) 1,767、39-1 (IRCBot) 1,156）認的是有人在用 IRC，不是 C&C，不算；43-1 的 2 條（HUNTING .arm 下載、curl UA）和 52-1 的 2 條（ELF 下載、curl UA）是下載類，也不算。PortScan 少的 17 條是只有 IP 清單。Attack 的 1,389 條是 SSH scan 1,385（只數 SYN，不算）、IP 清單 3、Mirai／VPNFilter UA 1，所以是 △。
- 講稿要保留原 p6、p7 的內容（39-1 (IRCBot) 的 SSH scan、2003068 的 threshold、各 rule 的 scenario、IP 清單、沒有 rule 的 port 等），scenario 一律帶 malware 名稱。

**p6 — CIC-IDS2017**
| 攻擊 | flows | 有 alert 的 flow | rule 對得上的 flow | 判斷 | 觸發的 rule |
|---|---|---|---|---|---|
| Web Attack – XSS | 18 | 18 | 18 | ✓ | XSS |
| Web Attack – SQL Injection | 13 | 9 | 9 | ✓ | SQLi |
| Infiltration | 36 | 15 | 15 | ✓ | cmd.exe、reverse shell |
| FTP-Patator | 3,972 | 1,553 | 1,553 | ✓ | FTP brute force |
| Heartbleed | 11 | 1 | 1 | ✓ | Heartbleed |
| Infiltration – Portscan | 71,767 | 111 | 105 | ✓ | Nmap UA、SCAN |
| Portscan | 159,064 | 185 | 175 | ✓ | SCAN（資料庫 port 等） |
| DoS Slowhttptest | 1,740 | 4 | 4 | ✓ | DoS tool |
| DDoS（LOIC） | 95,144 | 20 | 20 | ✓ | DDoS tool |
| SSH-Patator | 2,961 | 31 | 0 | △ | SSH scan（只數 SYN） |
| DoS Hulk 等 5 種 | 170,703 | 0 | 0 | ✗ | — |
| Benign | 1,581,058 | 10,293 | — | — | JA3 Adware、DNS TLD |
- 表下總結：malicious flow 50.5 萬條（15 種攻擊）、有 alert 1,947 條（0.39%）、rule 對得上 1,900 條（0.38%）、判斷 ✓ 9 種、△ 1 種、✗ 5 種、誤報 Benign 158 萬條裡 10,293 條（0.65%）
- note 第二行：`不含修正版標為 Attempted 的 flow（11,979 條，全部沒有 alert）`
- DoS Hulk 等 5 種 = DoS Hulk 158,468、DoS GoldenEye 7,567、DoS Slowloris 3,859、Botnet（Ares）736、Web Attack – Brute Force 73。Infiltration – Portscan 少的 6 條是 NTLM 的 INFO rule。malicious 合計 505,429、有 alert 1,947（0.3852%）、rule 對得上 1,910（0.3779%）。SSH-Patator 的 31 條是 SSH scan（2001219，只數 SYN），不算對得上，所以是 △。

**p7 — CIC-DDoS2019**
| 攻擊 | flows | 有 alert 的 flow | rule 對得上的 flow | 判斷 | 觸發的 rule |
|---|---|---|---|---|---|
| MSSQL（03-11） | 5,787,453 | 12 | 7 | ✓ | MC-SQLR |
| DrDoS_NTP（01-12） | 1,202,642 | 190 | 3 | ✓ | NTP MON_LIST |
| DrDoS_SNMP（01-12） | 5,159,870 | 210 | 0 | △ | SNMP `public`（協定的使用） |
| 其他 16 項 | 57,685,449 | 1,166 | 0 | △ | ping、SSH scan、資料庫 port scan |
| Benign | 109,424 | 333 | — | — | SSH scan |
- 表下：`malicious flow 6,984 萬條：有 alert 0.002%、rule 對得上 0.00001%；19 項：✓ 2、△ 17、✗ 0`（第九版起是兩欄三行總結：rule 對得上 10 條（0.00001%）、判斷 ✓ 2 項、△ 17 項、✗ 0 項）
- note 第二行：`19 項 = 03-11 的 7 項＋01-12 的 12 項；gw_corp 有 alert 746 條（少的主要是 ping）`
- 沒有「合計」列（四頁一致，合計在表下那一行）。其他 16 項每一項都有 alert（最少的 WebDDoS 2 條，是 Go-http-client 的 INFO rule），所以都是 △，沒有 ✗。攻擊 flow 合計 69,835,414、有 alert 1,578（0.0023%）、rule 對得上 113（0.000162%）。

**p8 — CICIoT2023**
| 攻擊 | flows | 有 alert 的 flow | rule 對得上的 flow | 判斷 | 觸發的 rule |
|---|---|---|---|---|---|
| Web-based（6 種） | 20,069 | 410 | 115 | ✓ | BeEF、SQLi、XSS、/etc/passwd |
| Brute Force | 7,313 | 248 | 5 | ✓ | LibSSH brute force |
| Recon（4 種） | 1,476,827 | 6,822 | 1,847 | ✓ | Nmap OS／NSE、SCAN |
| Recon-PingSweep | 1,829 | 11 | 0 | △ | 背景 UPnP、ping |
| DDoS（12 種） | 746,342,689 | 17,701 | 0 | △ | 背景 UPnP、ping |
| DoS（4 種） | 14,198,947 | 6,515 | 0 | △ | 背景 UPnP、ping |
| Mirai（3 種） | 169,315,173 | 4,935 | 0 | △ | 背景 UPnP、ping；HUNTING |
| Spoofing（2 種） | 160,726 | 1,958 | 0 | △ | 背景 UPnP、ping |
| Benign | 345,984 | 5,157 | — | — | UPnP、ICMP PING |
- 表下總結：malicious flow 9.32 億條（33 種攻擊）、有 alert 38,600 條（0.004%）、rule 對得上 1,967 條（0.0002%）、判斷 ✓ 11 種、△ 22 種、✗ 0 種、誤報 Benign 34.6 萬條裡 5,157 條（1.49%）
- note 第二行：`label 是整個檔（官方：整段擷取都算該攻擊，含背景流量）`
- 每種攻擊（`unified_by_label.tsv` 的 ciciot2023 列）：Web-based ✓（5 種）= Backdoor_Malware 2,642／51／4、BrowserHijacking 2,951／65／16、CommandInjection 3,971／81／3、SqlInjection 5,736／133／88、XSS 3,430／64／2；Uploading_Attack 1,339／16／0 是 △（/etc/passwd rule 抓到的是上傳後執行命令，不是上傳本身）；Brute Force 只算 LibSSH（2006546）5 條，只數 SYN 的 SSH scan 103 條不算；Recon ✓ = HostDiscovery 673,022／1,472／419、OSScan 190,789／1,124／614、PortScan 218,276／1,103／638、VulnerabilityScan 394,740／3,123／200。△ 各類觸發最多的都是背景的 `GPL MISC UPnP malformed advertisement` 與 `GPL ICMP PING`（DDoS 11,314／3,295 條 flow、DoS 3,725／1,262、Mirai 2,069／1,117、Spoofing 1,124／513、PingSweep 6／5）；另外 HTTP flood 有 HUNTING UA、Mirai GRE 有 `ET HUNTING Large non-DNS Packet on Port 53`（1,027 條）、udpplain 有 Edonkey（原 p10 講稿的 △ 理由保留在補充）。
- 原 p10 的 ✗ 16 種在統一定義下都是 △：照官方 label，背景的 alert 也落在「攻擊流量」上。講稿要講清楚這一點，並保留「以 Benign 檔出現過的 SID 為背景」的做法：它現在用來說明 △ 的 alert 是背景，而不是判斷 ✓（✓ 改由 `related_rules.tsv` 的 SID 判斷，結果和原本相同的 11 種）。

**p9 — 偵測總表（原 p5，移到四個 dataset 之後）**
| Dataset | malicious flows | 有 alert 的 flow（`full`／`gw_corp`） | rule 對得上的 flow | rule 對得上的攻擊種類 | 誤報（Benign 有 alert） |
|---|---|---|---|---|---|
| IoT-23 | 2.94 億 | 5.01%／5.01% | 5.01% | 5／15 | 0.009% |
| CIC-IDS2017 | 50.5 萬 | 0.39%／0.38% | 0.38% | 9／15 | 0.65% |
| CIC-DDoS2019 | 6,984 萬 | 0.002%／0.001% | 0.00001% | 2／19 | 0.30% |
| CICIoT2023 | 9.32 億 | 0.004%／0.003% | 0.0002% | 11／33 | 1.49% |
- 表下一行：`rule 對得上的 flow 都很低；rule 對得上的攻擊，大多是有 payload 特徵的`
- 頁尾 note（三行）：`誤報 = Benign flow 有 alert 的比例（Benign label 有標錯的，不等於 false positive rate）` ／ `CIC-DDoS2019 兩天分開算（7＋12 項）；IoT-23 扣掉整個 39-1 (IRCBot) scenario 是 0.02%` ／ `CICIoT2023 照官方 label，整個檔的 flow 都算攻擊（含背景流量）`
- 誤報（`full`）：IoT-23 2,837／30,860,691 ＝ 0.0092%、CIC-IDS2017 10,293／1,581,058 ＝ 0.6510%、CIC-DDoS2019 333／109,424 ＝ 0.3043%、CICIoT2023 5,157／345,984 ＝ 1.4905%；`gw_corp`：2,474（0.0080%）、7,420（0.4693%）、315（0.2879%）、3,676（1.0625%）。
- rule 對得上的 flow：IoT-23 14,758,406／294,449,255、CIC-IDS2017 1,900／505,429、CIC-DDoS2019 10／69,835,414、CICIoT2023 1,967／931,523,573。
- 講稿要保留原 p5 的補充（malicious flows 的精確數字、`full`／`gw_corp` 差異、CICIoT2023 87% 背景、IoT-23 扣掉 39-1 等）和原 p11 的補充（各 dataset Benign 的 rule、「為什麼不直接叫 false positive rate」的理由），並說明「誤報」這個名稱的限制：Benign label 有標錯的（IoT-23 Mirai UA、IRC 換 nick），INFO 類 rule 只是記錄事件；CICIoT2023 攻擊檔裡背景流量的 alert 照官方 label 算在攻擊，不在誤報裡。

**p4 — 偵測怎麼算（改）**
- 上方流程圖不變。下面的表改成 4 列（`指標`｜`定義`）：
  - `有 alert 的 flow`｜`該 label 的 flow 裡，有任何 alert 的`
  - `rule 對得上的 flow`｜`有 alert，且觸發的 rule 描述的就是這種攻擊`
  - `判斷（每種攻擊）`｜`✓ 有 rule 對得上的 flow；△ 有 alert 但都對不上；✗ 沒有 alert`
  - `誤報`｜`Benign flow 裡有 alert 的`
- 講稿：四種結果（偵測到、原因不符、漏報、誤報）用 2×2 的說法講（攻擊／正常 × 有／沒有 alert）；例子：CIC-IDS2017 SQLi → SQLi rule（✓）、CIC-DDoS2019 DrDoS_DNS → ping（△，162 條有 alert 裡 143 條）、IoT-23 DDoS → 沒有 alert（✗）、CIC-IDS2017 Monday → adware JA3（誤報）。「對得上」看內容不看名稱（FTP-Patator ↔ FTP brute force）；判斷單位是一種攻擊，有一條對得上就算 ✓；SID 清單在 `tests/detection/results/related_rules.tsv`。threshold 的說明保留。

**p10 結論、p11 下一步**：投影片只改結論表第二列的「偵測」欄 `#no 大多` → `#partly／#no 大多`（✗ 在統一定義下只指沒有 alert，flood 多數是 △）；其他不變；講稿裡的頁碼照對照表換；「有攻擊相關特徵的 alert」改說「rule 對得上」；結論頁補充「第二種占 malicious flow 的比例」保留。

**講稿共通**
- 只寫最終版；不能出現改動紀錄的字眼（改成、原本、這版、併成、拿掉、新增）。
- 第 2 頁的補充、第 3 頁不動（只換頁碼引用）。
- 每個 dataset 頁的講稿結構照舊：「一、當場講」的那一頁＋「二、補充」的那一頁（怎麼讀、實驗怎麼做、被問到時）；當場講要講表下那一行的三個數字和 ✓△✗。

- 2026-11-01 p2（使用者：「就當做官方說的那樣把那個檔的所有 flow 都標記成他的說明，先不在乎背景 packet」「測試範圍每個 dataset 都不一樣應該要統一」；兩個寫法由使用者選：測試範圍用 pcap 大小、對齊欄維持「—」）：
  - 測試範圍從「23 個 scenario／5 天／2 天／309 個檔」改成 pcap 合計大小 62.9／52.4／192.7／587.3 GB，表頭「測試範圍（pcap）」，該欄靠右。
  - CICIoT2023 的 label 從「只到 pcap 檔」改成「每個檔」；表下第一點改成「逐條 flow 標 label 的三個 dataset」，加一點「CICIoT2023：整個檔的 flow 都算該檔的攻擊，沒有逐條的 label 可對」。
  - 講稿第 2 頁：當場講與補充的「沒有 flow label」改成「label 是整個檔，沒有逐條的 label 可對」；「測試範圍」補充改成四個大小的來源；CICIoT2023 段「為什麼沒有對齊」引用論文 Sec. 4，「被問到時」加「檔裡的 flow 真的都是攻擊嗎？」（SqlInjection 檔 tshark 粗算 4,808 條 flow、攻擊者 `.178` 393 條；arXiv 2412.10738）。tshark 比對的 script 只在 session scratchpad，沒有放進 repo。
  - 直接修改，沒有派 Sonnet／Opus。
- 2026-11-01 照官方 label 同步其他頁（使用者：「其他地方也要跟著改」；p5 要不要填 CICIoT2023 的 flow 比例由使用者選「填進 p5，頁尾註明」）：
  - p5 總表 CICIoT2023 列：malicious flows 9.32 億、有 alert 的 flow 比例 0.004%／0.003%（原本是「—」「—」）；頁尾 note 改成三行，第三行 `CICIoT2023 照官方 label，整個檔的 flow 都算攻擊（含背景流量）`，拿掉「CICIoT2023 沒有 flow label」。
  - p10 頁尾「label 只到 pcap 檔」改成「label 是整個檔」。
  - 講稿：第 4 頁「實驗怎麼做」CICIoT2023 怎麼數有 alert 的 flow；第 5 頁當場講（四個都很低、CICIoT2023 約 0.004%、將近九成是背景的 rule）、malicious flows 與 flow 比例的補充（含 87% 背景、5,188 條、`gw_corp` 少的 13,605 條組成）、讀法、「CICIoT2023 的 flow 比例怎麼算？」、`full`／`gw_corp` 那題；第 10 頁正文與「這是有 alert 的 flow 比例嗎？」；第 11 頁三處「沒有 flow label」；第 12 頁補充「第二種占 malicious flow 的比例」加 CICIoT2023 99.8%。
  - 本檔 0 節 CICIoT2023 偵測率那條、p5 規格、p10 note、舊 p2 補充欄位定義同步。
  - 直接修改，沒有派 Sonnet／Opus。

- 2026-11-01 第六版（Opus 從計畫方角度列出可再刪的數據，使用者同意其中三項）：
  - CIC-DDoS2019 原 p9（03-11）、p10（01-12）共 19 列併成一頁 p9「CIC-DDoS2019」：只列 rule 內容對得上攻擊的 3 項（就是 p5 的 3／19）、其他 16 項一列、合計一列；欄位多一欄「比對到攻擊 protocol 內容的 flow」（7、3、103，合計 113）。兩天逐項的表（含時段與觸發的 rule）移到講稿第 9 頁補充，原兩頁的規格保留成下面兩個「p9 補充」小節。
  - p5 總表的 malicious flows 改寫成億／萬（2.94 億、50.5 萬、6,984 萬），精確數字在講稿。
  - p3 實驗設定：Rule set 只列 `full`、`gw_corp`（`gw_corp` + IP 清單後面沒有一頁用到）；拿掉 HOME_NET 那一列。兩者改在講稿補充說明。
  - 頁碼：原 p11–p15 改成 p10–p14；共 20 頁。
  - Opus 第六版驗證後（數字全對；高 1、中 1、低 8）：SNMP 的 rule（2101411）比對的是送往 161 的 request 裡的 `public`，不是回應（01-12 的 214 筆全部是 `172.16.0.5 → 192.168.50.1:161`），p9 講稿改成「攻擊所用 protocol 的內容」；「有 alert 的 flow 比例 < 0.01%」改成「比對到攻擊內容的 flow 比例 < 0.01%」（DrDoS_NTP 有 alert 的是 0.016%）；p9 頁尾補「主要」（1,578 − 746 = 832 條裡 811 條是 ping）；「其他 16 項是 0」補一句 Syn 的資料庫 port scan 有一部分是 SYN flood 打到、但 rule 認的是 scan；p4 講稿「和 DDoS 無關」→「不是認出 DDoS」；p6 講稿第一次出現 IP 清單時補定義；只在補充裡的內容引用改成「第 N 頁的補充」；規格 HOME_NET 一句改成被問到時才講。L2（第 9 頁補充有重複的段落）不改：都是補充，沒有矛盾。
- 2026-11-01 第五版（使用者：「簡報出現無用數據的地方太多了，像是計畫方會在意 dataset 的實際日期嗎？」；同意後：「並成一頁，詳細數據可以寫進逐字稿，讓我被問到時用補充的」）：
  - 第 1 章原 p2–p5（四個 dataset 各一頁）併成一頁 p2「對齊結果」：每個 dataset 一列（測試範圍、label、flow alignment、packet coverage）；CIC-DDoS2019 兩天合併成一列（99.93%／99.98%，兩天加總）。拿掉的數據（檔案大小、packets、pcap 數與段數、CIC-IDS2017 每天的日期與攻擊、CIC-DDoS2019 的實際日期與 training／testing、IoT-23 的 11 個 usable 那一列、CICIoT2023 每類的大小與 packets）全部移到講稿第 2 頁的補充，原 p2–p5 的規格保留成下面四個「p2 補充」小節。
  - p3 實驗設定：Rules 拿掉「CICIoT2023 載入 52,795 條」；HOME_NET 縮成一行，每個 dataset 怎麼設改在講稿講。
  - p9、p10 CIC-DDoS2019：拿掉「時段（UTC）」欄和只為它存在的頁尾（「時段 = 99% 的 flow 開始的時間」「WebDDoS 和 UDP-lag 同一段時間」），時段移到講稿補充；列的順序仍照時間。
  - 頁碼：原 p6–p18 改成 p3–p15；共 21 頁。
  - Opus 第五版驗證後（數字全對；中 1、低 7）：講稿「時段在第 9、10 頁」「和表上差不到 1 分鐘」改成指補充；只在補充裡的內容引用改成「第 2 頁的補充」；第 2 頁當場講只說「全部的 pcap」（CIC-IDS2017 有 1,510 條 Protocol 0 沒納入、CICIoT2023 沒有 flow label，不能說全部的 flow）；IoT-23 的 23 個 scenario 就是官方全部（28 個 pcap，Honeypot-7-1 底下只有 Somfy-01 有 label）；「資料集狀態綜整表」只在封面用一次；Okiru 改說「算 △，p5 總表不算進 6／15」；0.4、0.6、p2／p9／p10 字級與 `main.typ` 同步；p10 表和標題之間加一點間距。L4（IoT-23 以 scenario 算只有 11／23 usable）已在補充裡，當場不加。
- 2026-11-01 使用者同意 Codex 的建議：總表欄名「偵測得到的攻擊種類」改成「有攻擊相關特徵 alert 的類別」，指標名稱統一為「有攻擊相關特徵的 alert」（label 層級：攻擊流量上有 alert，且 rule 內容對得上這種攻擊）；回答主問題的一般動詞「偵測得到」保留。
- 2026-11-01 Codex 審查後（使用者核對過的修改清單 14 項，`main.typ`、`逐字稿.md`、本檔同步）：
  - 高：
    - Attempted 是修正版作者判定沒有實際送出攻擊內容的攻擊 flow（11,979 條，全部沒有 alert），其中 897 條仍有 TCP payload，不能說「沒有 payload」；p11 頁尾 note 改成 `不含修正版標為 Attempted 的 flow（11,979 條，全部沒有 alert）`。
    - SSH scan 的 threshold：IoT-23 的 2003068 是 `type threshold, count 5, seconds 120`，數的是同一來源「符合條件的 SYN 比對次數」，不是 flow 數；p7 頁尾 note 改成 `每累計 5 次符合的 SYN 才報 1 次`；刪掉「最多就是 20%」「剛好 20%」（一條 flow 只有一個 SYN 時有 alert 的 flow 約 20%，但不是上限，3-1 (Muhstik) 是 31.1%，原因沒有查；39-1 (IRCBot) 照實寫 20.0%）。CIC 的 2001219（`type both`）不動。
    - p7 加第三個指標「有攻擊相關特徵的 alert（label 層級）」，講稿說明三個指標的差別（例：CIC-DDoS2019 19 項都有 alert、偵測得到 3 項）；p16 的 ✓ 大多、✗ 大多指「有攻擊相關特徵的 alert」；講稿不再把有 alert 的 flow 比例等同 detection rate；label 層級的 MSSQL、SNMP、NTP、Heartbleed 也改稱「有攻擊相關特徵的 alert」。
  - 中：
    - p6 HOME_NET 依 dataset 寫（CIC 兩個是受害端網段、IoT-23 用預設、CICIoT2023 是 any），Rules 補 CICIoT2023 載入 52,795 條，講稿照實際設定說。
    - p10 頁尾符號互斥（✗ 沒有 alert）；Okiru 有 34 條 flow 只有 IP 清單的 alert，p8 判成 △，p10 表上 ✗ 那一列是 37215 的 SYN probe 這類流量本身。
    - p8 的 3／19：頁尾補 CIC-DDoS2019 兩天分開算（7＋12 項，Syn 等兩天都有）；講稿說明 19 是「日期 × label」的項目數，不是 19 種不同攻擊，各 dataset 分類粒度不同不能直接比（講稿 CIC-DDoS2019 的「種」改稱「項」）。
    - 講稿 p8：偵測得到不代表認出 flood 或暴力破解的行為（SNMP 的 rule 只比對送往 161 的 `public`；SSH-Patator 靠 SSH scan rule）。
    - 講稿 p8、p16：「沒有內容特徵 → 偵測不到」標推論；原因也可能是 rule set 沒有對應的 rule、threshold 或設定。
    - offline 不再說是偵測能力的「上限」、不再說「alert 只會更少」，改稱「offline 的基準結果」：同一台機器在 flow emergency mode 下也有差異（memcap 調大後 DrDoS_SNMP 210 → 207 條），Pi／線上的差異等 inline 重播驗證。
    - 講稿 p6、p8：`gw_corp` 的數字是從 `full` 的 alert 依 SID 篩出來的，沒有另外跑；有 rule 靠被排除的 rule 先設 flowbits 時會偏高（`tests/detection/README.md`）。
    - 講稿 p14：「以 Benign 檔出現過的 SID 為背景」是啟發式，同一個 SID 也可能同時落在攻擊流量上；✗ 的意思是依這個判準沒有找到相關 alert。
  - 低：p2 講稿補 usable 的定義；p8 頁尾與講稿「扣掉 39-1 (IRCBot) 的 SSH scan」改成「扣掉整個 39-1 (IRCBot) scenario」（49,694／220,887,611）；p16 講稿補速度是 Pi 讀代表性切片（每個最多 20 萬 packets）量的 engine 處理速度、不是 gateway 的線上吞吐量。
- 2026-10-31 初版：20 頁。CIC-DDoS2019 是 03-11 全天 + 01-12 抽 1/8 段落、對齊每 20 條抽 1 條。
- 2026-10-31 第二版（使用者要求「完整測試」與「依 dataset 介紹細節」）：
  - CIC-DDoS2019 兩天都改成全部：01-12 全天 819 段直接從 zip 解壓串流送進 Suricata（不抽樣），兩天都做全部 flow 的對齊（有 packet coverage）。
  - 新增 4 頁 dataset 介紹（p2–p5）：每個 dataset 的原始數據（檔案、大小、packet、flow、label 方式）、這次處理的範圍、對齊結果。原本的「CIC 兩個 dataset 的對齊」頁併進 p3、p4。
  - CIC-DDoS2019 的偵測結果分成兩頁（03-11、01-12），加上每種攻擊的時段。
  - 共 24 頁。
- 2026-10-31 第二版修訂（Opus 驗證後，`驗證報告.md`）：
  - CIC-DDoS2019 的對齊與 alert 比對納入 CSV 的 Protocol 0 flow（原版 CICFlowMeter 把 ICMP、後續 IP fragment 等解不出 TCP/UDP header 的 packet 記成 Protocol 0、port 0/0）。之前只收 TCP/UDP/ICMP：01-12 的 packet coverage 只有 87.24%（被當成未達 usable）、38,510 筆 ICMP ping alert 對不到 flow。納入後兩天都 usable，01-12 有 alert 的 flow（`full`）從 492 變 1,303（多的都是 `GPL ICMP PING`，`gw_corp` 不變）。CIC-IDS2017 修正版不適用（它有 603 條 ICMP flow，加 `--cic` 會讓 ICMP flow 對不上），維持原樣。
  - SCAN alert 的成因改寫：SSH scan 是攻擊主機整天的背景 SSH 連線，不是 flood 打到 22（資料庫 port 的部分見下一輪）。
  - 「真正對應攻擊的 rule」改成「比對到攻擊所用 protocol 內容的 rule，但只比對到極少的 flow」。p12／p13 的時段改成 99% 的 flow 落在的時段。p16 第 2 列改成「沒有內容特徵的大量流量」（HTTP DoS 有 payload）。p5 Benign 2.0 GB。用詞統一成 5-tuple。
  - 01-12 納入 Protocol 0 的對齊跑完後填入：03-11 99.88%／99.94%、01-12 99.95%／99.99%，狀態表 CIC-DDoS2019 改成 ✓ 2／2 usable；memcap 重跑的差異改成 `--cic` 下的 210 → 207 條；01-12 對齊約 65 分鐘。
- 2026-10-31 第二版修訂（第二輪，Opus 第三版驗證後，`驗證報告.md`）：
  - 資料庫 port 的 scan rule（2010935／2010936／2010937／2010939）不是計數型：外部送往該 port 的每個 SYN 都報，同一來源每 60 秒最多 5 筆。成因有兩個來源：Syn flood 亂打 port（03-11 的 219 筆有 154 筆在 Syn 時段；01-12 的 181 筆有 75 筆），和攻擊主機在其他時段零星連資料庫 port（65／106 筆；為什麼連，沒有查）。「計數型」只用在 SSH（2001219：同一來源累積 5 次報 1 次、之後 120 秒內不再報），泛指的地方改成「只看 header 的 scan rule」；p12 頁尾改成 `SCAN = SSH、資料庫 port 等的 scan rule`；各列 rule 的組成照 `top_sids` 寫，刪掉「這些列的 SCAN 都是背景 SSH 連線」（Portmap、NetBIOS、UDP 也有資料庫 port 與 Sipvicious 的 alert）。
  - CIC-IDS2017 的 1,510 條 Protocol 0：1,184 條是 ARP 這類非 IP 的 frame 被當成 IP 解析出的 `8.6.0.1 → 8.0.6.4`，326 條是真的 IP 流量（沒有查是哪一種 protocol）；不加 `--cic` 的主要理由是 603 條 ICMP flow 會對不上（aligned 2,097,247 → 2,096,968）。
  - p13 表下一行與 p16：「都不是認出 DDoS」改成「幾乎都不是認出 DDoS」，加上比對到攻擊 protocol 內容的 113 條（SNMP 103、MC-SQLR 7、NTP 3），並說明和 p14 ✓ 標準的關係（label 層級算有 alert，但有 alert 的 flow 比例 < 0.01%）。
  - p6：「和 Pi 上結果相同」標成推論、沒有量；補充同一台機器 pipe 與讀檔案兩次，有 15 筆 alert 的 flow 紀錄不同（flow emergency mode）。
  - 03-11 的重複列改成 482,799 組（含 Protocol 0 的 117 組）；ping 改成「從 14:36 一直 ping 到 20:59（UTC）」，811 條是 Protocol 0 flow（合計 packet 幾乎都是 flood 的 IP fragment 後續片段，其中 287 條只有 ping）；講稿拿掉「納入 Protocol 0 之前／前後」這類像改動紀錄的說法；頁尾 note 裡的等寬字縮小；規格與 `main.typ` 文字同步（p3、p4、p10、p11、p12、p13）。
- 2026-11-01 第三版（使用者 10/31：「CICIoT2023 要把檔案全跑、3 個 dataset 要量速度、DDOS2019 要去重」；狀態表每一欄都要和 IoT-23 一樣有；11/01：速度頁「跟 10/19 的 dataset 使用相同的敘述方式，這樣大家可以更直觀」）：
  - 新增第 4 章「Pi 處理速度」（章節頁 + p16–p21），寫法照 10/19：實驗設定表 → 切片表（scenario／流量型態／packets／平均 packet）→ 點圖（kpps 對數刻度、右側 full time），圖用 `assets/make_figs.py` 產生，樣式和 10/19 的 fig_full14 相同。結論與下一步順延成 p22、p23，References p24；共 31 頁。
  - p2 狀態表：Pi 速度四個 dataset 都 ✓；CICIoT2023 取得與偵測改成全部 309 個檔。
  - CIC-DDoS2019 03-11 去重（482,799 組重複列）：p4、p12、p13、p15、p22 的 03-11 與兩天合計數字更新；拿掉「沒有去重」的 ❌ 條目與講稿。
  - CICIoT2023 全部 309 個檔：p5 改成全部；p14 判斷結果不變，例子與頁尾更新；p15 Benign 改用 4 個 Benign 檔。
  - p23 下一步拿掉已完成的三項。
- 2026-11-01 第四版 Opus 驗證後：SSH scan 2001219（CIC 兩個 dataset）是 `type both`：累積 5 次才報 1 次、之後 120 秒內不再報（IoT-23 的 2003068 是 `type threshold`：每累計 5 次符合的 SYN 才報 1 次，2026-11-01 Codex 審查後更正）；p8 表下一行改成「偵測得到的攻擊，大多是有 payload 特徵的」並說明有幾種靠只看 header 的 scan rule；「< 0.01%」指的是比對到攻擊內容的 flow，不是有 alert 的 flow（DrDoS_NTP 有 alert 的是 0.016%）；p2 的欄位說明改成前三頁一樣；p7 講稿 IoT-23 23 個 scenario 有 138 筆對不上。
- 2026-11-01 第四版（使用者：「IoT23 應該要全部測過才能知道真的 alert」；「p2 可以刪掉…老師要的表應該是針對 security gateway 的重要數據，像是 alert 比率等等的」）：
  - IoT-23 偵測從 11 個 usable 擴到全部 23 個有 label 的 scenario（另 Somfy-02～06 沒有 label，Suricata 跑過都是 0 筆 alert）；p9、p10、p15、p16 與 0.1 的 IoT-23 數字更新（malicious 294,449,255 條、有 alert 5.01%）。
  - 刪掉流程進度表（原 p2）；在「偵測結果」章開頭新增 p8「偵測總表」（每個 dataset 的 malicious flows、有 alert 的 flow 比例、有攻擊相關特徵 alert 的類別、Benign 有 alert）。原 p3–p8 往前一號（p2–p7）；第一章改名「Dataset 與對齊」。總頁數仍是 24。
  - 原 p2 講稿裡「取得」的說明（md5、Hugging Face 鏡像、和官方核對）移到各 dataset 介紹頁（p2–p5）的補充。
  - 2026-11-01 使用者決定刪掉第 4 章（「速度主要是讓大家知道 Pi 大概能處理多少封包；主要在 dataset 的對齊程度和 Suricata 可以偵測到哪些」）：主線回到 24 頁、大綱四項；保留 p2 狀態表的 Pi 速度欄和結論頁一行；第 4 章的規格移到文末「已刪除：第 4 章」備查，圖留在 `assets/`。
  - Opus 第三版驗證後：切片挑選的說法改成「依流量型態歸類」（不是特徵相同）；不畫 empty 的理由改成 6 個切片 empty 比 full 慢；03-11 NetBIOS 和 DrDoS_NetBIOS 不同型態；CICIoT2023 56 個檔進入 emergency mode、4 GiB 只重跑 3 個；p17 百分比用未四捨五入的值。
  - Sonnet 實作時更正規格的錯：p7 重複列去掉後 03-11 也是 0 筆；「每個切片 20 萬」改成「最多 20 萬」（IoT-23 有 4 個小檔）；p21「小 packet 的」ICMP／UDP flood（Mirai-udpplain 只有 68.6）；結論句「四個 dataset 最慢都是 HTTP flood」不成立，改成分開寫；p22「正常流量」改成「CIC 的 Benign」；p17 標題「重量」改成「重測」。圖的長寬比改成和 10/19 相同，三張圖都 100% 寬。

---

## 0. 全域規範

### 0.1 報告定位
- **進度報告**，回應老師 10/19 報告後的兩個建議：
  1. **資料集狀態綜整表**：使用者 11/01 的解讀：表要放 security gateway 的重要數據（alert 比率等），不是流程進度。所以做成 p5「偵測總表」：每個 dataset 一列，之後每次更新。對象是 10/05 選的 4 個 dataset：IoT-23、CIC-IDS2017（修正版）、CIC-DDoS2019、CICIoT2023。
  2. **偵測能力**：「這些流量送進去之後，偵測得出來嗎？」＝ 把 alert 對回 label，不是「rule 能偵測哪些種類」。
- 主軸問題：**流量送進本地 IDS（Suricata 8.0.7 + ET Open），偵測得出來嗎？** 答案看攻擊型態：
  - **有 payload 特徵的攻擊偵測得到**：Web 攻擊（XSS 18/18、SQL injection 9/13）、exploit（Heartbleed）、惡意程式下載（ELF，IoT-23 77/82 條）、C&C 指令（IRC，39-1 的 C&C 75.6%；Muhstik、Mirai 的 C&C checkin）、暴力破解（FTP 的回應 39%）、BeEF 瀏覽器劫持（CICIoT2023）。
  - **scan、flood、DoS 大多偵測不到**：只有 SYN、沒有 payload 的 scan（Telnet 23／2323、52869、80、8081 等）、Okiru（37215 的 SYN）、TCP／UDP flood、反射式 DDoS、HTTP DoS（Hulk、GoldenEye、Slowloris）。例外是 SSH（22）、VNC、資料庫等少數 port 有只看 header 的 scan rule（CIC 的 SSH scan 2001219 是 `type both`：同一來源累積 5 次才報 1 次、之後 120 秒內不再報；IoT-23 的 2003068 是 `type threshold`：同一來源 120 秒內每累計 5 次符合的 SYN 報 1 次；兩者數的都是符合條件的 SYN 比對次數、不是 flow 數，才是「計數型」；資料庫 port 是外部送往該 port 的每個 SYN 都報、同一來源每分鐘最多 5 筆），例如 39-1 (IRCBot) 的 SSH scan。**「沒有內容特徵 → 偵測不到」是推論**：觀察到的是這些流量沒有對得上的 alert，原因除了沒有內容特徵，也可能是 rule set 沒有對應的 rule、threshold 或設定。
  - 這類流量占 malicious flow 的絕大多數：IoT-23 的 malicious flow 有 99.98% 是 PortScan／Okiru／DDoS（其中只有 39-1、3-1 的 SSH scan 有 rule）；CIC-IDS2017 有 98.5% 是 DoS／DDoS／Portscan；CIC-DDoS2019 全部是 DDoS。IoT-23 的 malicious flow 有 94.99% 沒有任何 alert。
  - 所以「有 alert 的 flow 比例」整體很低：IoT-23 5.01%（而且幾乎全部來自 39-1 的 SSH scan；扣掉整個 39-1 (IRCBot) scenario 是 0.02%）、CIC-IDS2017 0.39%、CIC-DDoS2019 約 0.002%（1,578／69,835,414；`gw_corp` 746 條）。
- 意涵（結論頁）：本地 IDS 的 rule 主要抓得到有內容特徵的攻擊（另有少數 port 只看 header 的 scan rule）；其他 scan／flood 要靠 flow 層級的統計（速率、連線對象數），這和研究目標「Flow 資料收集與雲端卸載」接得上。**這是推論，這輪沒有實作或量測 flow 統計偵測。**
- **承接前幾次報告**：
  - 10/05：選了 4 個 dataset 與對齊方法（5-tuple + 時間 + packet 數）。對齊方法這次不再整頁介紹。
  - 10/19：IoT-23 全 dataset 對齊（23 個 scenario、98.87%、11 個 usable）；Pi 上的處理速度（14 個 scenario 的切片、點圖；這次用同樣的量法重測並擴到 CIC，只在結論頁一行呈現）；`gw_corp`（本地要掛的 rule）；結論「以 Suricata 為 base」。這輪偵測用的就是 Suricata，`gw_corp` 沿用 10/19 的定義。p2 對齊表的 IoT-23 只放整體數字，細節講「見 10/19」。
- ❌ 不可說「老師建議用 flow 統計／ML」。老師只問了「偵測得出來嗎」與要狀態表。
- ❌ 不可把「有 alert 的 flow 比例」叫 detection rate，也不可說它代表「辨識出攻擊」：它只是逐條 flow 的比例（有 alert 的 flow ÷ 該 label 的 flow），alert 可能和攻擊無關；每次出現都要講清楚定義。「這個攻擊有沒有被偵測到」看第三個指標「有攻擊相關特徵的 alert」（p4）。
- ❌ 不可說 Attempted 是「沒有 payload 的攻擊 flow」：它是修正版作者判定沒有實際送出攻擊內容的攻擊 flow（11,979 條），其中 897 條仍有 TCP payload。
- ❌ 不可說 SSH scan「每 5 條 flow 報 1 次」或「有 alert 的 flow 最多就是 20%」：2003068 數的是符合條件的 SYN 比對次數（每累計 5 次報 1 次），一條 flow 只有一個 SYN 時約 20%，但不是上限（3-1 (Muhstik) 是 31.1%，原因沒有查）；39-1 (IRCBot) 的 20.0% 照實寫，不寫「剛好」。
- ❌ 不可說 offline 是偵測能力的「上限」或「alert 只會更少」：offline 是基準結果；同一台機器在 flow emergency mode 下也會有差異（memcap 調大後 DrDoS_SNMP 210 → 207 條）；Pi 和線上的差異要等 inline 重播驗證。
- ❌ 不可說 `gw_corp` 的數字是另外跑的：它是從 `full` 的 alert 依 SID 篩出來的；有 rule 靠被排除的 rule 先設 flowbits 時，篩出來的數字會偏高（`tests/detection/README.md`）。
- ❌ 不可說「有攻擊相關特徵的 alert」＝ 認出 flood 或暴力破解的行為：它只表示有 alert 對得上攻擊內容（例如 SNMP 的 rule 只比對送往 161 的 `public`、沒有速率條件；SSH-Patator 靠的是 SSH scan rule）。
- ❌ 不可說偵測是在 Pi 上跑的。偵測在工作站的 Docker 跑 **Suricata 8.0.7**（和 Pi 上同一個 Debian 套件版本），結果由 engine 版本、設定、rule、pcap 決定（設定和 Pi 相同），所以 Pi 上同版本應該得到一樣的結果；**這是推論，沒有量**（沒有在 Pi 上跑偵測驗證；同一台機器重跑，flood 期間仍有少量 alert 的 flow 紀錄不同，見 p3）。
- ❌ 不可說 CICIoT2023 的偵測率。p5 的 flow 比例是照官方 label（整個檔的 flow 都算攻擊）算的，含背景流量；攻擊有沒有偵測到只能說「這個攻擊的檔有沒有出現跟攻擊有關的 alert」（p10）。
- ❌ 不可再說 CIC-DDoS2019 是抽樣。兩天的偵測與對齊都是全部的 packet、全部的 flow。
- ❌ 不可說 CIC-DDoS2019 有 alert 的 flow 是認出 DDoS（在 flow 層級）：01-12 有 811 條攻擊 flow 只因為攻擊主機的 ICMP ping（`GPL ICMP PING`，不在 `gw_corp`）；SSH scan 是攻擊主機整天的背景 SSH 連線；資料庫 port 的 scan rule 一部分是 SYN flood 亂打 port 打到、一部分是攻擊主機在其他時段零星連資料庫 port；比對到攻擊 protocol 內容的 SNMP、NTP、MC-SQLR 三條 rule 共 113 條 flow，只占各 label 極少的 flow（< 0.01%）。只能說「幾乎都不是認出 DDoS」；在 label 層級（偵測得到，和 p10 同一個標準），01-12 的 DrDoS_SNMP、DrDoS_NTP 和 03-11 的 MSSQL 算偵測得到。
- CIC-DDoS2019 的 flows 包含 CSV 的 Protocol 0 flow（見 p2）；CIC-IDS2017 只算 TCP／UDP／ICMP（它有 603 條 ICMP flow，加 `--cic` 會讓 ICMP flow 對不上；它的 1,510 條 Protocol 0 有 1,184 條是 ARP 這類非 IP 的 frame 被當成 IP 解析，另 326 條是真的 IP 流量，見 p2、p2 講稿）。
- CIC-DDoS2019 03-11 已去重：官方 CSV 有 482,799 組重複列（每組 2 條，除了 uid 以外每個欄位都相同、label 也相同：Syn 478,395 組、Benign 4,404 組；其中 117 組是 Protocol 0），對齊與比對都用去重後的 label（每組留一條）；01-12 沒有重複列。講稿要提（p2）。
- ❌ 不可把 Pi 處理速度說成 gateway 的線上速率：這是 engine 直接讀 tmpfs 上的 pcap 的處理上限（同 10/19），沒有走網卡、NFQUEUE。
- ❌ 不可把 CIC 的切片說成「每種攻擊都量了」或「特徵相同才合併」：CIC 三個 dataset 是依流量型態歸類、同一類只量一個（比 10/19「特徵幾乎相同才只取一個」粗；同一類的 packet 大小、protocol 比例可能不同），共 27 個切片；切片表最後一欄寫同型態、沒有另外量的攻擊。
- ❌ 不可說 Benign 上的 alert 是 false positive rate。Benign label 本身有疑點（IoT-23 33-1 有 208 條、17-1 有 3 條 Benign 觸發 Mirai User-Agent rule）。
- ❌ 和 10/19 的 alert 數不能直接比：10/19 是 Suricata 7.0.10 + 2026-10-11 rule、只跑前 20 萬個 packet；這次是 8.0.7 + 2026-10-30 rule、完整 pcap。

### 0.2 敘述深度
**投影片只放重點，說明、理由、舉例一律放講稿。**
- 表格只留關鍵欄位，每格盡量 ≤ 12 個字；每頁要點 ≤ 3 條，盡量每條一行。
- 投影片上的內容以表格、數字為主；理由與解釋寫進講稿。
- **每張表都要在講稿寫「怎麼讀」**：欄位定義、符號（✓／△／✗）、百分比的分母。
- 只給比率不夠：表格同時寫 flow 數（或括號註明條數），不要讓聽眾自己推算。
- Dataset 只放一頁（p2 對齊結果）：計畫方要看的是 alert 與 label 可不可信，不是 dataset 的原始規格。檔案大小、packet 數、錄製日期、pcap 段數、training／testing、每天的攻擊這類數據不上投影片，全部寫進講稿第 2 頁的補充，被問到時查（使用者 11/01：「計畫方會在意 dataset 的實際日期嗎？」）。**先定義再放數據**：欄位定義寫進講稿。

### 0.3 用詞
- **全份統一（投影片、講稿都一樣）**，同一個概念只能有一種寫法。
- 專有／技術名詞一律英文：dataset、scenario、label、flow、packet、pcap、payload、rule、rule set、category、alert、engine、scan、flood、benign、C&C、port、usable、HOME_NET、threshold、offline、inline、pipe、training／testing（CIC-DDoS2019 官方對兩天的稱呼）、5-tuple（不寫「五元組」）、Protocol 0（CICFlowMeter 把解不出 TCP/UDP header 的 packet 記成的 flow，port 0/0）。
- **對照表（左欄是唯一寫法）**：

| 統一寫法 | 不可再用 |
|---|---|
| 有 alert 的 flow 比例（定義：有 alert 的 flow ÷ 該 label 的 flow；只是逐條 flow 的比例） | 偵測率、detection rate（被問到時要說「不是 detection rate，不代表認出攻擊」） |
| 有沒有 alert（該 label 至少一條 flow 有 alert，任何 alert 都算） | 偵測到、命中 |
| 有攻擊相關特徵的 alert（label 層級：攻擊流量上有 alert，且 rule 內容對得上這種攻擊；總表欄名「有攻擊相關特徵 alert 的類別」） | 偵測到、命中、辨識出攻擊（講稿可以說「有偵測到」但要指這個定義） |
| flow alignment、packet coverage | 對齊率、涵蓋率 |
| dataset | 資料集（「資料集狀態綜整表」是老師的原話，講稿第一次提到可以用，投影片標題寫 `Dataset 狀態`） |
| alert | 警報、告警 |
| rule、rule set | 規則 |
| scan、flood | 掃描、洪水 |
| packet | 封包 |

- rule set 名稱用等寬字型：`full`（ET Open 全部）、`gw_corp`（10/19 定義的本地 rule）、`gw_corp` + IP 清單。
- **scenario 一律帶 malware 名稱**：`39-1 (IRCBot)`、`17-1 (Kenjiro)`、`42-1 (Trojan)`（名稱見 0.6 的對照）。
- CIC-IDS2017 的攻擊名稱沿用 label：`DoS Hulk`、`Web Attack – XSS` 等；CIC-DDoS2019 寫 label 原名（03-11 是 `UDPLag`，01-12 是 `UDP-lag`，兩天的 CSV 寫法不同，照原樣）；CICIoT2023 寫檔案的攻擊名（`DDoS-SYN_Flood`）。
- CIC-DDoS2019 的兩天一律寫官方名稱 `03-11`、`01-12`（「日-月」；實際日期 2018-11-03、2018-12-01 只在講稿補充出現，不上投影片）。
- 章節標題（大綱與章節頁一字不差）：`Dataset 與對齊`、`偵測測試設定`、`偵測結果`、`結論與下一步`。
- 速度的用詞同 10/19：kpps（每秒處理幾千個 packet）、full time（`full` 處理這個切片的時間，engine 自報）、切片（slice 不用英文）、流量型態。

### 0.4 技術規格
- **Typst** 搭配 `@preview/slydekit:0.4.1`（metropolis 主題），共用 `slides/template.typ`，編譯用 `slides/build.sh`（`cd slides && ./build.sh 20261102_security_gateway_本地_IDS_偵測測試`）。
- 只有 p4 一張流程圖（`diagram`），其他都是表格。`assets/` 裡的速度圖與 `make_figs.py` 是已刪除的第 4 章留下的，投影片沒有用到。
- 字型：Noto Sans CJK TC；比例 16:9。可以沿用 10/19 `main.typ` 開頭的小工具（`note`、`big`、`small-tbl`）。
- **共 20 頁** = 封面 1 + 大綱 1 + 章節頁 4 + 內容 12 + References 1 + Q&A 1。封面、章節頁、Q&A 不顯示頁碼。

| 實體頁 | 顯示頁碼 | 標題 |
|---|---|---|
| 1 | — | 封面：Security Gateway 本地 IDS 偵測測試 |
| 2 | p1 | 大綱 |
| 3 | — | 章節頁：Dataset 與對齊 |
| 4 | p2 | 對齊結果 |
| 5 | — | 章節頁：偵測測試設定 |
| 6 | p3 | 實驗設定 |
| 7 | p4 | 偵測怎麼算 |
| 8 | — | 章節頁：偵測結果 |
| 9 | p5 | 偵測總表 |
| 10 | p6 | IoT-23 |
| 11 | p7 | IoT-23：觸發 alert 的 rule |
| 12 | p8 | CIC-IDS2017 |
| 13 | p9 | CIC-DDoS2019 |
| 14 | p10 | CICIoT2023 |
| 15 | p11 | Benign 上的 alert |
| 16 | — | 章節頁：結論與下一步 |
| 17 | p12 | 結論 |
| 18 | p13 | 下一步 |
| 19 | p14 | References |
| 20 | — | Q&A |


### 0.5 視覺
- 符號：有 `#yes`（✓）、沒有 `#no`（✗）、部分／只有零星或不相關的 alert `#partly`（△）；一般強調用 `#hl`。
- 小表格用 `small-tbl(size: …)` 縮字；頁尾小字用 `note`（`c-muted`、0.65em；note 裡的等寬字 `full`、`gw_corp` 字級跟著縮小）。
- 數字欄靠右對齊；有 alert 的 flow：≥ 1% 寫百分比到小數點後一位，< 1% 寫條數（例如「20 條」）；p11 的百分比 < 0.1% 寫「< 0.1%」。
- 講稿補充裡 dataset 的大小寫到小數點後一位（GB，10^9 bytes）；packets、flows 寫完整數字加千分位。

### 0.6 數據來源（repo 內，`tests/detection/` 底下）

| 檔案 | 內容 | 用在 |
|---|---|---|
| `README.md` | 方法、環境、HOME_NET、rule set、資料來源與核對、各 dataset 的原始數據 | 全部 |
| `../iot23/results/*.json`、`../iot23/report.md` | IoT-23 的對齊（10/19）：每個 pcap 的 `pcap_bytes`、`pcap_packets`、`flows`、`aligned`、`pcap_covered_packets` | p2 |
| `results/iot23_by_label.tsv`、`iot23_by_scenario.tsv`、`iot23_sids.tsv`、`iot23_match/*.json` | IoT-23 全部 23 個有 label 的 scenario 的比對結果（11 個 usable 的彙總另存 `results/iot23_usable11_*.tsv`） | p2、p5、p6、p7、p11 |
| `results/align/cicids2017_*.json` | CIC-IDS2017 5 天的對齊（含每個 label 的 flow 數、`pcap_time_range`） | p2 |
| `results/cicids2017_*.tsv`、`cicids2017_match/*.json` | CIC-IDS2017 5 天的比對 | p8、p11 |
| `results/align/cicddos2019_{0311,0112}.json`、`results/align/cicddos2019_0112.windows.tsv` | CIC-DDoS2019 兩天全部 flow 的對齊；01-12 每一段的時間範圍 | p2 |
| `results/cicddos2019_*.tsv`、`cicddos2019_match/{0311,0112}.json` | CIC-DDoS2019 兩天全天的比對 | p9、p11 |
| `results/ciciot2023_files.tsv` | CICIoT2023 官方 309 個 pcap 的資料夾、檔名、大小、這次有沒有取（Hugging Face 鏡像的檔案清單） | p2 |
| `results/ciciot2023.tsv`、`ciciot2023_by_attack.tsv`、`ciciot2023_judgement.tsv` | CICIoT2023 全部 309 個檔的結果（每個檔、每種攻擊合計）與逐一判斷 | p2、p10、p11 |
| `../ids_throughput/README.md` 實驗 5、`../ids_throughput/results/pi/pi_scen3_*.summary.csv` | Pi 處理速度（Suricata 8.0.7、2026-10-30 rule，41 個切片 × `full`／`gw_corp`） | p12 |
| `../ids_throughput/results/pi/pi_scen2_S.summary.csv` | 10/19 的 IoT-23 速度（Suricata 7.0.10），只用來對照 | p12 講稿 |
| `../ids_throughput/results/cic_slice_features.tsv`、`../ids_throughput/manifest_cic.json` | CIC 71 個候選切片的流量特徵與挑選（`selected`）；27 個切片的 packets、平均大小 | 講稿補充 |
| `../../slides/20261102_*/assets/speed_numbers.tsv` | 每個切片的 `full`／`gw_corp` kpps、full time、RSS（`make_figs.py` 輸出） | 已刪除的第 4 章 |

scenario 名稱（IoT-23 官方表的 malware 名稱，10/19 `assets/make_figs.py` 的 FAMILY）：1-1 Hide and Seek、3-1 Muhstik、7-1 Linux.Mirai、8-1 Hakai、9-1 Linux.Hajime、17-1 Kenjiro、20-1 Torii、21-1 Torii、33-1 Kenjiro、34-1 Mirai、35-1 Mirai、36-1 Okiru、39-1 IRCBot、42-1 Trojan、43-1 Mirai、44-1 Mirai、48-1 Mirai、49-1 Mirai、52-1 Mirai、60-1 Gafgyt；Honeypot 4-1 Philips HUE、5-1 Amazon Echo、7-1 door lock（Somfy）。投影片與講稿出現 scenario 編號時一律帶名稱，例如 `39-1 (IRCBot)`（表格裡可寫成 `39-1 IRCBot`）。

---

## 封面
- 標題：**Security Gateway 本地 IDS 偵測測試**（決定 PDF 檔名 `Security_Gateway_本地_IDS_偵測測試.pdf`）
- 日期：2026-11-02；沒有副標。

> **講稿注意**：開場接上 10/19（效能測試、`gw_corp`、以 Suricata 為 base），帶出老師報告後的兩個建議：狀態表、偵測得出來嗎。

## p1 — 大綱
四項，與章節頁一字不差：1. Dataset 與對齊　2. 偵測測試設定　3. 偵測結果　4. 結論與下一步

---

# 1. Dataset 與對齊（章節頁 + p2）

## p2 — 對齊結果
一張 4 列的表（字級約 1.05em；測試範圍與百分比欄靠右；表頭「測試範圍（pcap）」兩行）：

| Dataset | 測試範圍（pcap） | label | flow alignment | packet coverage |
|---|---|---|---|---|
| IoT-23 | 62.9 GB | 每條 flow | 98.87% | 96.42% |
| CIC-IDS2017 | 52.4 GB | 每條 flow | 99.94% | 99.26% |
| CIC-DDoS2019 | 192.7 GB | 每條 flow | 99.93% | 99.98% |
| CICIoT2023 | 587.3 GB | 每個檔 | — | — |

- 表下三點：
  - `逐條 flow 標 label 的三個 dataset：label 幾乎都對得回 packet`
  - `CICIoT2023：整個檔的 flow 都算該檔的攻擊，沒有逐條的 label 可對`
  - `每個 dataset 都跑全部的 pcap，不抽樣`
- 不放頁尾 note。
- 測試範圍用 pcap 合計大小（GB = 10^9 bytes）統一四個 dataset；檔數不能比（CIC-IDS2017 一天一個檔、CIC-DDoS2019 兩天 965 段、CICIoT2023 每檔最多 2 GB）。
  - IoT-23：28 個 pcap 的 `pcap_bytes` 合計 62,948,814,531。
  - CIC-IDS2017：NAS `/mnt/nas/dataset/cicids2017/pcaps/` 5 個官方原始 pcapng 合計 52,433,389,872（工作站轉成 pcap 後是 51.5 GB，不用這個）。
  - CIC-DDoS2019：03-11 串好的 pcap 29,069,821,199 ＋ 01-12 163,604,181,876（Suricata 讀到的 packet 資料 159,591,649,284 加每個 packet 16 bytes 記錄檔頭，`tests/detection/README.md`）＝ 192,674,003,075。
  - CICIoT2023：`results/ciciot2023_files.tsv` 309 個檔合計 587,291,146,325。
- CICIoT2023 的 label 照官方定義：論文（Sensors 2023, PMC10346235）Sec. 4 "for each attack executed, the entire traffic captured is labeled as belonging to that particular attack"，檔裡每條 flow 都算該檔的攻擊；不另外區分背景流量（背景的事實放講稿第 2 頁 CICIoT2023 段的「被問到時」）。

數字來源：
- IoT-23：`tests/iot23/results/*.json`。23 個有 label 的 scenario：flows 325,309,946、aligned 321,632,849（98.87%）；28 個 pcap：packets 770,313,789、covered 742,702,878（96.42%，分母含沒有 label 的 Somfy-02～06）。
- CIC-IDS2017：`results/align/cicids2017_*.json` 5 天加總：aligned 2,097,247／flows 2,098,466（99.94%）；covered 55,952,190／packets 56,370,702（99.26%）。
- CIC-DDoS2019：`results/align/cicddos2019_{0311,0112}.json` 兩天加總：aligned 19,860,617 + 50,035,937 = 69,896,554／flows 19,881,726 + 50,063,112 = 69,944,838（99.93%）；covered 61,372,112 + 250,748,053 = 312,120,165／packets 61,407,883 + 250,783,287 = 312,191,170（99.98%）。分開是 03-11 99.89%／99.94%、01-12 99.95%／99.99%（講稿補充）。
- CICIoT2023：官方 309 個 pcap（`results/ciciot2023_files.tsv`），label 是整個檔，沒有逐條的 label 可以對，所以兩個對齊欄是「—」。

> **講稿注意（當場講）**
> - 這頁回答「label 可不可信」：label 和 pcap 裡的 packet 對得多完整。當場先講兩個欄位的一句話定義：flow alignment 是 label 的 flow 在 pcap 裡找得到對應 packet 的比例；packet coverage 是 pcap 的 packet 落在某一條 label flow 裡的比例。
> - 逐條 flow 標 label 的三個 dataset，flow alignment 都在 98.8% 以上；最低的 IoT-23 98.87% 是被 60-1 (Gafgyt) 拉低（扣掉是 99.97%），細節 10/19 報告過。
> - CICIoT2023 官方把每次攻擊錄到的流量整段標成那種攻擊，檔裡每條 flow 都算那種攻擊；label 直接來自檔案，沒有逐條的 label 可以對 packet，所以是「—」；每種攻擊偵測得到哪些在第 10 頁。
> - 四個 dataset 都跑全部的 pcap，不抽樣；「測試範圍」是 pcap 合計大小。malicious flow 的數量在第 5 頁總表。
>
> **講稿補充（`>` 行）怎麼組織**
> - 先放共用的完整欄位定義與 usable 條件，再依 dataset 分四段（**IoT-23**、**CIC-IDS2017**、**CIC-DDoS2019**、**CICIoT2023**）。每段開頭放原本投影片上的那張詳細表（markdown 表格，數字照下面四個「p2 補充」小節，一格不少），接著是這個 dataset 的怎麼讀、實驗怎麼做、被問到時。
> - 下面四個「p2 補充」小節的「講稿注意」內容全部保留在講稿裡，只改頁碼（照 0.4）和「這頁」「每列一天」這類指投影片的說法。
> - 被問到時要能直接查到：每個 dataset 的大小、packet 數、flow 數；CIC-IDS2017 每天的日期與攻擊；CIC-DDoS2019 兩天的實際日期、training／testing、pcap 段數、時區換算、分開的對齊數字；CICIoT2023 每類的檔數、大小、packets、flows；IoT-23 的 11 個 usable。

以下四個小節是原 p2–p5 的規格，**不上投影片**，是講稿第 2 頁補充的素材。

### p2 補充：IoT-23
講稿補充的表：

| 範圍 | pcap | 大小 | packets | labeled flows | flow alignment | packet coverage |
|---|---|---|---|---|---|---|
| 全部 | 28 個（23 個有 label） | 62.9 GB | 770,313,789 | 325,309,946 | 98.87% | 96.42% |
| 11 個 usable | 11 個 | 32.1 GB | 413,410,334 | 296,338,640 | 99.97% | 99.96% |

- label：Zeek conn.log，每條 flow 一個 label；10/19 已報告；偵測用全部 23 個有 label 的 scenario 的完整 pcap。

數字來源：`tests/iot23/results/*.json`（28 個）與 `tests/iot23/report.md`。
- 全部：28 個 pcap 的 `pcap_bytes` 合計 62.9 GB、`pcap_packets` 合計 770,313,789；23 個有 `conn.log.labeled` 的 flows 合計 325,309,946、aligned 321,632,849（98.87%）、covered 742,702,878（96.42%）。沒有 label 的 5 個是 Honeypot-7-1 底下的 Somfy-02～06。
- 11 個 usable（1-1、7-1、9-1、17-1、33-1、35-1、36-1、39-1、42-1、43-1、48-1）：`pcap_bytes` 合計 32.1 GB、packets 413,410,334、flows 296,338,640、aligned 296,263,818（99.97%）、covered 413,233,218（99.96%）。

> **講稿注意（怎麼讀）**
> - 這頁 10/19 已經講過，只放數字，讓後面的偵測結果有分母：偵測用的是全部 23 個有 label 的 scenario 的完整 pcap（7.7 億個 packet、3.25 億條 flow）；Somfy-02～06 沒有 label，Suricata 也跑過，都是 0 筆 alert。
> - usable 只代表對齊的品質（label 和 packet 對得多完整）；偵測的比對只看 5-tuple 和時間、不看 packet 數，所以 34-1、60-1 這種 packet 數對不上的 scenario 一樣對得到 alert；52-1、49-1 的 label 只涵蓋 pcap 的前 61%、90%，之後的 alert 沒有 label 可對（52-1 3 筆、49-1 135 筆，見第 4 頁）。11 個 usable 的結果另外算過：malicious flow 有 alert 的 5.54%（全部 23 個是 5.01%）。
> - 欄位定義（CIC-IDS2017、CIC-DDoS2019 兩頁同樣的欄位；CICIoT2023 的 label 是整個檔，只有 packets、flows）：**packets** 是 pcap 裡的 packet 數；**labeled flows** 是 label 檔裡的 flow 數（IoT-23、CIC-IDS2017 算 TCP／UDP／ICMP；CIC-DDoS2019 另含 Protocol 0，見 p2）；**flow alignment** 是 labeled flows 裡，在 pcap 找得到剛好對得上的 packet（5-tuple 相同、時間在 flow 的開始與結束之間、packet 數剛好相等）的比例；**packet coverage** 是 pcap 全部的 packet 裡，落在某一條 labeled flow 範圍內的比例。
> - IoT-23 官方的 tar 是 23 個頂層資料夾，Honeypot-7-1 底下又分 Somfy-01～06，所以是 28 個 pcap；Somfy-02～06 沒有 label 檔。
> - 「全部」的 98.87% 被 60-1 拉低（扣掉 60-1 是 99.97%）；usable 的條件是 flow alignment ≥ 99% 且 packet coverage ≥ 90%。當場講第二列（11 個 usable）時要帶一句這個定義。
> - 11 個 usable 的 malware 名稱見 0.6。10/19 的報告另外提到 7-1 的 Benign 有 86.5% 對不回 packet；7-1 整體符合 usable 的條件，這次偵測有放進去，影響的只有 Benign 的數字（Benign 只列數字，見 p11）。
> - 被問到「資料怎麼取得、有沒有核對」：IoT-23 是 Zenodo 全部 21.5 GB，md5 和 Zenodo 一致，原始壓縮檔存在 NAS。

### p2 補充：CIC-IDS2017
講稿補充的表：

| 日 | 日期 | pcap | packets | flows | 攻擊 | flow alignment | packet coverage |
|---|---|---|---|---|---|---|---|
| Monday | 07-03 | 10.8 GB | 11,709,971 | 371,319 | （只有 Benign） | 100% | 99.28% |
| Tuesday | 07-04 | 11.0 GB | 11,551,954 | 321,767 | FTP／SSH-Patator | 100% | 99.28% |
| Wednesday | 07-05 | 13.4 GB | 13,788,878 | 496,323 | DoS ×4、Heartbleed | 100% | 99.39% |
| Thursday | 07-06 | 8.3 GB | 9,322,025 | 361,795 | Web Attack ×3、Infiltration | 99.66% | 99.11% |
| Friday | 07-07 | 8.8 GB | 9,997,874 | 547,262 | Botnet、Portscan、DDoS | 100% | 99.16% |
| 合計 | | 52.4 GB | 56,370,702 | 2,098,466 | | 99.94% | 99.26% |

- label：CNS 2022 修正版 CSV，時間是 UTC；5 天都 usable。flows 只算 TCP／UDP／ICMP；日期是 2017 年。

數字來源：
- pcap 大小：NAS `cicids2017/pcaps/` 的官方 pcapng（Monday 10,822,507,416、Tuesday 11,048,283,608、Wednesday 13,420,789,612、Thursday 8,302,500,180、Friday 8,839,309,056 bytes；合計 52,433,389,872）。
- packets、flows、aligned、covered：`results/align/cicids2017_{monday..friday}.json`。aligned：Thursday 360,576，其他 4 天等於 flows；合計 2,097,247（99.94%）。covered 合計 55,952,190（99.26%）。日期由 `pcap_time_range`（UTC）換算。
- 攻擊（由各天 `labels`）：Tuesday FTP-Patator、SSH-Patator；Wednesday DoS Hulk、GoldenEye、Slowloris、Slowhttptest、Heartbleed；Thursday Web Attack – Brute Force、XSS、SQL Injection、Infiltration（含 Infiltration – Portscan）；Friday Botnet、Portscan、DDoS。
- 每天的 flow 組成：Monday Benign 371,319；Tuesday Benign 314,795；Wednesday Benign 318,802、DoS Hulk 158,468；Thursday Benign 287,891、Infiltration – Portscan 71,767；Friday Benign 288,251、Portscan 159,064、DDoS 95,144（其餘見 json）。
- CSV 另有 1,510 條其他 protocol 的 flow（不是 TCP／UDP／ICMP），不納入：CSV 共 2,099,976 列。

> **講稿注意（怎麼讀）**
> - 每列一天，攻擊欄是這一天出現的攻擊 label（細節在 p8）。flows 是修正版 label 的 flow 數（TCP／UDP／ICMP）；Benign 占多數（5 天合計 1,581,058 條），malicious 505,429 條、Attempted 11,979 條（修正版作者判定沒有實際送出攻擊內容的攻擊 flow；其中 897 條仍有 TCP payload，所以不能說「沒有 payload」）。
> - 對齊方法和 10/19 的 IoT-23 一樣，CSV 先轉成 Zeek conn.log 的欄位排列，再用同一支程式。修正版 label 的時間是 UTC，和 pcap 同一個時鐘。
> - Thursday 的 99.66%：對不上的 1,219 條，全部是「pcap 裡的 packet 比 label 記的多」。
> - flows 只算 TCP／UDP／ICMP：CSV 另有 1,510 條 Protocol 0 的 flow，不納入。其中 1,184 條是 `8.6.0.1 → 8.0.6.4`（ARP 這類非 IP 的 frame 被當成 IP 解析出的位址，label 都是 Benign，對不回 IP packet）；另外 326 條是真的 IP 流量（大多是 192.168.10.x → 192.168.10.3，以及送往 224.0.0.22 的 multicast；label 是 Benign 324 條、Malicious 2 條），是哪一種 protocol **沒有查**。為什麼不納入見 p2 講稿（CIC-DDoS2019 的 Protocol 0 不一樣）。
> - 官方檔是 pcapng，先用 editcap 轉成 pcap（時間精度不變）再對齊與偵測。

### p2 補充：CIC-DDoS2019
講稿補充的表：

| 日 | 實際日期 | 用途 | pcap | packets | flows | 攻擊 | flow alignment | packet coverage |
|---|---|---|---|---|---|---|---|---|
| 03-11 | 2018-11-03 | testing | 146 段、29.1 GB | 61,407,883 | 19,881,726 | 7 種 | 99.89% | 99.94% |
| 01-12 | 2018-12-01 | training | 819 段、163.6 GB | 250,783,287 | 50,063,112 | 12 種 | 99.95% | 99.99% |

- 兩天各自錄製，攻擊一種接一種，各佔一段時間；全部 packet、全部 flow（不抽樣）。pcap 每段 200 MB，大小是解壓後；flows 含 Protocol 0（ICMP、IP fragment 等，port 0/0）；03-11 已去掉重複列。

數字來源：
- 03-11：`pcap/0311.pcap`（146 段串成一個檔，29,069,821,199 bytes）；`results/align/cicddos2019_0311.json`（去重後）：pcap_packets 61,407,883、flows 19,881,726、aligned 19,860,617（99.89%）、covered 61,372,112（99.94%）。去重前：flows 20,364,525、aligned 20,341,001（99.88%），covered 相同。
- 01-12：819 段（`SAT-01-12-2018_0` 到 `_0818`），Suricata 讀到 250,783,287 個 packet、packet 資料 159,591,649,284 bytes，加上每個 packet 16 bytes 的 pcap 記錄檔頭 ＝ 163.6 GB（等同串成一個 pcap 檔的大小，沒有實際存檔）；`results/align/cicddos2019_0112.json`：flows 50,063,112、aligned 50,035,937（99.95%）、covered 250,748,053（99.99%）。
- flows ＝ CSV 的列數（03-11 去掉重複列後），包含 Protocol 0 的 flow（03-11 去重前 1,452 條、5,314,059 個 packet，其中 117 組是重複列；01-12 2,546 條、31,945,472 個 packet）。
- 攻擊種類：03-11 Portmap、NetBIOS、LDAP、MSSQL、UDP、UDPLag、Syn；01-12 DrDoS_NTP、DrDoS_DNS、DrDoS_LDAP、DrDoS_MSSQL、DrDoS_NetBIOS、DrDoS_SNMP、DrDoS_SSDP、DrDoS_UDP、UDP-lag、WebDDoS、Syn、TFTP。
- zip 大小：`PCAP-03-11.zip` 2.0 GB；01-12 四個 zip（`PCAP-01-12_0-0249`、`_0250-0499`、`_0500-0749`、`_0750-0818`）合計 20.9 GB；兩天 CSV zip 2.3 GB、0.9 GB。
- 03-11 CSV 的重複列：482,799 組（每組 2 條，除了 uid 以外每個欄位都相同、label 也相同；Syn 478,395 組、Benign 4,404 組；其中 117 組是 Protocol 0），去重留一條（`tests/detection/dedup_conn.sh`）；01-12 是 0（含 Protocol 0）。去重前有 95 筆 alert 同時對到一組重複的兩條 flow。
- 只算 TCP／UDP／ICMP 時（不含 Protocol 0）：03-11 flow alignment 99.89%、packet coverage 91.28%；01-12 99.95%、87.24%（`~/datasets/cicddos2019/align/old_tcpudp/`）。

> **講稿注意（怎麼讀）**
> - 每列一天。官方把兩天叫 03-11、01-12，這是「日-月」：pcap 和 CSV 裡實際的日期是 2018-11-03 與 2018-12-01（和官網寫的日期不同，10/05 查證時就發現）。兩天是各自錄的，01-12 不包含 03-11；官方把 01-12 當 training day、03-11 當 testing day。
> - 兩天的攻擊種類有一部分重疊（LDAP、MSSQL、NetBIOS、UDP、UDPLag／UDP-lag、Syn），但流量是另一天另外錄的，所以兩天都要測。Portmap 只在 03-11；NTP、DNS、SNMP、SSDP、TFTP、WebDDoS 只在 01-12。
> - 每種攻擊佔一段時間，一種做完再做下一種（時段寫在 p9 的講稿補充）。官方 pcap 每 200 MB 切一段，flood 時一段通常只有幾秒（819 段的中位數 4.3 秒）。
> - **Protocol 0**：CIC-DDoS2019 用的是原版 CICFlowMeter，它把解不出 TCP／UDP header 的 packet（ICMP、IP fragment 的後續片段、OSPF 等）記成 Protocol 0、port 0／0 的 flow，同一對 IP 的這些 packet 歸成同一條；CSV 裡沒有 Protocol 1（ICMP）的 flow。這些 flow 也有 label（例如攻擊主機 ping 受害主機的 packet，被標成當時的攻擊），所以對齊和 alert 比對都納入：packet 端把「IPv4 非 TCP／UDP、或 fragment offset 不是 0」的 packet 當成 Protocol 0。只算 TCP／UDP／ICMP 的話，01-12 的 packet coverage 只有 87.24%（沒被涵蓋的 32,001,558 個 packet 有 99.4% 是 IP fragment 的後續片段；含 Protocol 0 時只有 35,234 個沒被涵蓋）。
> - **實驗怎麼做**：01-12 解開約 164 GB，不先存成 pcap，而是從 zip 一邊解壓一邊用 pipe 送進 Suricata 和對齊程式（Suricata 19.5 分鐘）。用 03-11 驗證過：從 pipe 讀和讀檔案的 657 筆 alert 完全相同（時間、SID、5-tuple、packet 編號；兩份輸出都保存在工作站；alert 附帶的 flow 紀錄有 15 筆不同，見 p3）。01-12 的對齊把 5,006 萬條 flow 依 5-tuple 分成 3 份，每份各讀一次 pcap 串流（共約 65 分鐘、記憶體峰值約 4 GB），三份的結果直接相加（同一個 5-tuple 一定在同一份）。
> - 時鐘：CSV 是當地時間，03-11 要加 3 小時、01-12 要加 4 小時（11 月 3 日還是當地的夏令時間 UTC−3，12 月 1 日已經是標準時間 UTC−4），是拿 pcap 第一個 packet 和 CSV 第一筆對出來的。
> - 兩天都 usable（flow alignment ≥ 99% 且 packet coverage ≥ 90%）。
> - Benign 對得比較差（03-11 Benign 75.50%、UDPLag 65.19%；01-12 Benign 80.31%、WebDDoS 91.12%），但數量很少（03-11 Benign 52,561 條、UDPLag 1,873 條，攻擊有 1,983 萬條），不影響整體數字。
> - 去重：03-11 的官方 CSV 有 482,799 組重複列（每組 2 條，除了 uid 以外每個欄位都相同、label 也相同；Syn 478,395 組、Benign 4,404 組，其中 117 組是 Protocol 0），每組只留一條，所以 03-11 是 19,881,726 條（CSV 20,364,525 列，少 2.4%）；01-12 沒有重複列。重複的兩條會讓同一筆 alert 算成兩條 flow 有 alert，去重後 03-11 Syn 有 alert 的 flow 從 263 條變 227 條、Benign 從 206 條變 175 條，其他攻擊不變。03-11 CSV 的第一欄（`Unnamed: 0`）編號不連續，官方沒有說明。
> - 被問到「同一個 5-tuple 的 flow 會不會分錯」：同一個 5-tuple 有多條 flow 很常見（重送、port 重用、FIN 後切成新的 flow），時間不重疊就分得開；時間重疊的時候，packet 會算給每一條，通常讓 packet 數對不上而算成對齊失敗，不會變成假的成功。
> - 被問到「CIC-IDS2017 為什麼不算 Protocol 0」：CIC-IDS2017 修正版的 CSV 有 603 條 ICMP flow，ICMP 不在 Protocol 0 裡。它的 1,510 條 Protocol 0 flow，1,184 條是 ARP 這類非 IP 的 frame 被當成 IP 解析出的位址（`8.6.0.1 → 8.0.6.4`），其他 326 條是真的 IP 流量（p2）。如果也用 CIC-DDoS2019 的做法（IPv4 非 TCP／UDP 的 packet 當成 Protocol 0），ICMP 的 packet 也會被歸成 Protocol 0，那 603 條 ICMP flow 就對不上，aligned 從 2,097,247 降到 2,096,968，所以 CIC-IDS2017 只算 TCP／UDP／ICMP。

### p2 補充：CICIoT2023
講稿補充的表：

| 類別 | 攻擊種類 | pcap | 大小 | packets | flows |
|---|---|---|---|---|---|
| DDoS | 12 | 176 個 | 346.9 GB | 3,387,315,242 | 746,342,689 |
| Mirai | 3 | 76 個 | 153.1 GB | 262,877,918 | 169,315,173 |
| DoS | 4 | 38 個 | 74.8 GB | 808,847,158 | 14,198,947 |
| Benign | — | 4 個 | 7.0 GB | 11,102,705 | 345,984 |
| Spoofing | 2 | 3 個 | 3.7 GB | 4,904,322 | 160,726 |
| Recon | 5 | 5 個 | 1.8 GB | 7,020,685 | 1,478,656 |
| Web-based | 6 | 6 個 | 0.1 GB | 255,560 | 20,069 |
| Brute Force | 1 | 1 個 | < 0.1 GB | 133,138 | 7,313 |
| 合計 | 33 | 309 個 | 587.3 GB | 4,482,456,728 | 931,869,557 |

- label 只到 pcap 檔：一個檔一種攻擊，沒有 flow label；309 個檔全部跑完偵測。flows 是 Suricata 算出的 flow 數（沒有 flow label）。

數字來源：`results/ciciot2023_files.tsv`（309 列：資料夾、檔名、大小）；packets、flows 是每個檔 `stats.log` 的 `decoder.pkts`、`flow.total`，依類別加總（`results/ciciot2023_by_attack.tsv` 的 packets、flows 欄；攻擊所屬類別見 `results/ciciot2023_judgement.tsv` 的 category）。
- 類別依 CICIoT2023 論文：DDoS 12 種、DoS 4 種、Mirai 3 種、Recon 5 種（HostDiscovery、OSScan、PingSweep、PortScan、VulnerabilityScan）、Web-based 6 種（BrowserHijacking、CommandInjection、SqlInjection、XSS、Backdoor_Malware、Uploading_Attack）、Brute Force 1 種（DictionaryBruteForce）、Spoofing 2 種（DNS_Spoofing、MITM-ArpSpoofing），共 33 種；Benign 1 個資料夾（4 個檔）。
- 取得：先抽 36 個檔（每種攻擊 1–2 個、Benign 1 個），其餘 273 個（543 GB）10/31–11/01 從 Hugging Face 鏡像下載，每個檔用鏡像記的 sha256 核對、跑 Suricata、寫進 NAS 後用 direct read 讀回再核對一次（`tests/detection/fetch_ciciot2023_all.sh`）。

> **講稿注意（怎麼讀）**
> - 每列一個類別；pcap 是官方的檔案數，大小是官方 pcap 合計；packets、flows 是 Suricata 讀完全部 309 個檔算出來的（沒有 flow label，所以 flows 是 Suricata 自己切的 flow）。
> - 大小幾乎都是 flood：DDoS、Mirai、DoS 合計 575 GB（98%）。除了 HTTP flood 和 SlowLoris（每種 1–2 個檔），其他 16 種 flood 每種切成 8–29 個約 2 GB 的檔；Web、Recon、Brute Force、Spoofing 每種只有 1–2 個檔。
> - DDoS 的 flow 特別多（7.5 億條）：其中 7.3 億條來自 4 種 TCP flood（PSHACK、RSTFIN、SYN、TCP），16.7 億個 packet 切出 7.3 億條 flow，平均每 2–3 個 packet 就是一條新的 flow（Suricata 依 5-tuple 切 flow）。
> - 為什麼沒有對齊：CICIoT2023 的 CSV 是每 10 或 100 個 packet 平均出來的特徵值，沒有 IP、port、時間，找不回 packet。
> - **實驗怎麼做**：273 個檔一邊下載一邊跑：下載到工作站、用 sha256 核對、跑 Suricata（設定和最初 36 個檔相同）、存進 NAS 再讀回核對，最後刪掉工作站上的檔。約 7 小時，瓶頸是工作站的 Wi-Fi（下載與寫 NAS 都走 Wi-Fi）。
> - 被問到「全部跑和只跑 36 個有差嗎」：每種攻擊的判斷都一樣（p10）；多出來的檔只多了背景流量的 alert。

---

# 2. 偵測測試設定（章節頁 + p3–p4）

## p3 — 實驗設定
`punch`：`問題：流量送進本地 IDS，偵測得出來嗎`

一張表：

| 項目 | 設定 |
|---|---|
| Engine | Suricata 8.0.7（和 Pi 同一個套件版本） |
| Rules | ET Open 2026-10-30（52,798 條） |
| Rule set | `full`、`gw_corp` |
| 讀法 | offline，engine 直接讀 pcap |

- 不放其他文字。

> **講稿注意**
> - HOME_NET、IP 清單、CICIoT2023 載入 52,795 條都不上投影片、不當場講，放補充（`>`）。HOME_NET 被問到時照實際設定講：CIC 兩個是受害端網段、IoT-23 用預設、CICIoT2023 是 any（細節在下面）。
> - offline：Suricata 直接讀完整的 pcap，在工作站的 Docker 跑；偵測結果由 engine 版本、設定、rule 與 pcap 決定（設定和 Pi 相同），所以 Pi 上同版本的 Suricata 應該得到一樣的結果（**推論**，**沒有量**：沒有在 Pi 上跑偵測驗證）。設定和 10/19 一樣：Debian 預設的 `suricata.yaml`、single thread、`ac-ks`、`-k none`，只改成只輸出 alert。Pi 上 10/30 已經升級到 Suricata 8.0.7（gateway 實作要求 8.0 以上），所以這次也用 8.0.7、ET Open 給 8.0.7 的版本。CIC-DDoS2019 01-12 是從 zip 解壓後用 pipe 送進 Suricata（見 p2）；用 03-11 驗證過 pipe 和讀檔案的 alert 相同（兩份輸出保存在工作站 `~/datasets/detection/pipe_test/0311/` 與 `cicddos2019/0311/`）。
> - offline 和實際送進 Pi 的差別：offline 不會掉 packet（處理完一個才讀下一個），時間用 pcap 的 timestamp；實際送進 Pi 時如果 CPU 跟不上，NFLOG 會丟、NFQ 會排隊或丟，可能影響收到的 alert。所以這次的結果是 offline 的基準結果，不是偵測能力的上限：同一台機器在 flow emergency mode 下結果也會有差異（`flow.memcap` 調大後 DrDoS_SNMP 有 alert 的 flow 從 210 條變 207 條）；Pi 和線上的差異要等 inline 重播驗證（p13）。
> - **rule set**：`full` 是 ET Open 全部啟用的 rule；`gw_corp` 是 10/19 依公司 gateway 需求挑的本地 rule（38,506 條，10/11 的 SID 清單裡 8.0.7 還有的）；IP 清單是 TOR、CINS、Spamhaus DROP 等長 IP 清單的 1,223 條 rule，10/19 決定改用 nftables 的 IP 集合比對，不放在 IDS 裡，但 gateway 一樣偵測得到；`gw_corp` + IP 清單的數字有算（`results/*_by_label.tsv` 的 `gw_corp+iplist` 欄），投影片不放、講稿放補充；p7 的 △「只有 IP 清單」指的就是這類 rule（它們在 `full` 裡、不在 `gw_corp`）。實際只跑一次 `full`，`gw_corp` 的結果是從 `full` 的 alert 依 SID 篩出來的；已知誤差：`gw_corp` 裡若有 rule 靠被排除的 rule 先設 flowbits，篩出來的數字會偏高（`tests/detection/README.md`）。講稿 p3 與 p5 當場要講這一句。
> - **HOME_NET**（被問到時照實際設定講：CIC-IDS2017、CIC-DDoS2019 是受害端網段，IoT-23 用預設，CICIoT2023 是 any；CICIoT2023 因此有 3 條 rule 載入失敗、載入 52,795 條）：Suricata 預設的 HOME_NET 是 RFC1918 三段（10/8、172.16/12、192.168/16）。CIC-IDS2017 和 CIC-DDoS2019 的攻擊者經過防火牆 NAT 之後，在 pcap 裡是 `172.16.0.1`、`172.16.0.5`，會被預設當成內部主機，「外部打內部」的 rule 就不會觸發。所以 HOME_NET 只放受害端網段：CIC-IDS2017 `192.168.10.0/24`、CIC-DDoS2019 `192.168.50.0/24`，模擬 gateway 放在攻擊者與受害者之間。IoT-23 的被感染設備在 192.168.x，預設剛好正確。CICIoT2023 的攻擊者（實驗網路裡的 Raspberry Pi）和受害設備在同一個區網，官方受害清單只有設備名稱，所以 HOME_NET 和 EXTERNAL_NET 都設成 any（不分內外，所有方向的 rule 都適用（3 條載入失敗））。
> - 被問到「HOME_NET 改了差多少」：CIC-IDS2017 Wednesday 兩種都跑過。DoS Hulk、GoldenEye、Slowloris 兩種設定都是 0；改成受害端網段之後，Slowhttptest 從 0 變 4 條（`Unusually Fast HTTP Requests`），Heartbleed 從 2 條變 1 條（預設設定下另一條 Heartbleed rule 也會觸發）。其他天只跑了受害端網段的設定。第一次用預設 HOME_NET 的輸出沒有保留，這些數字是當時的紀錄。
> - 被問到「Pi 上跑，結果會一樣嗎」：偵測結果由 engine 版本、設定、rule 和 pcap 決定，Pi 只影響處理速度，所以應該一樣。這是**推論**，**沒有量**。同一台工作站上，03-11 從 pipe 讀和讀檔案各跑一次，657 筆 alert 的時間、SID、5-tuple、`pcap_cnt` 完全相同；但有 15 筆 alert 附帶的 flow 欄位（`flow.start`、packet 數）不同，全部在 Syn 時段（14:30 左右），當時 Suricata 處在 flow emergency mode。所以 flood 讓 flow table 滿的時候，結果會受執行時序影響；Pi 的 CPU 比較慢，在 flood 的 pcap 上可能有少量差異（推論）。
> - 被問到「為什麼不用 Snort 3」：10/19 的結論是以 Suricata 為 base 實作 gateway，這次只測 gateway 要用的 engine。
> - 被問到「flood 會不會把 Suricata 塞爆」：flood 時 Suricata 的 flow table 會滿：Debian 預設的 `flow.memcap` 是 128 MiB，IoT-23 43-1 (Mirai)、CIC-DDoS2019 兩天、CICIoT2023 的 DDoS-PSHACK_Flood、RSTFINFlood、TCP_Flood 跑的時候都進入過 flow emergency mode（提早回收 flow）。把 `flow.memcap` 調到 4 GiB 重跑這幾個 pcap，就不再進入 emergency mode；結果幾乎一樣：03-11、PSHACK、TCP_Flood 每個 label 的數字不變，RSTFINFlood、43-1 的 alert 是同樣的 5-tuple 和 rule、只差觸發時間，01-12 只有 DrDoS_SNMP 有 alert 的 flow 從 210 條變 207 條。表上用的是預設設定（和 Pi 上一樣）的結果。DrDoS_SNMP 為什麼差 3 條，**沒有查**。（`tests/detection/memcap_check.sh`、`~/datasets/detection/memcap_test/`）
> - 被問到「rule 都有載入嗎」：CICIoT2023 的 HOME_NET、EXTERNAL_NET 都設成 any 時，有 3 條 rule 的位址取反之後變成空集合，載入失敗（52,795／52,798 條）：`ET DNS DNS Lookup for localhost.DOMAIN.TLD`、`ET INFO Outbound Multiple Non-SMTP Server Emails`、`ET INFO Inbound Frequent Emails - Possible Spambot Inbound`；其他三個 dataset 52,798 條全部載入。

## p4 — 偵測怎麼算
（版面與內容同前一版：上半 `alert (eve.json)` → `flow (5-tuple + time)` → `label` 的流程；下半兩個指標的表；頁尾 note `很多 rule 有 threshold：例如 SSH scan 同一來源每累計 5 次符合的 SYN 才報 1 次`。）

| 指標 | 定義 |
|---|---|
| 有 alert 的 flow 比例 | 有 alert 的 flow ÷ 該 label 的 flow |
| 有沒有 alert | 該 label 至少一條 flow 有 alert |
| 有攻擊相關特徵的 alert（label 層級） | 攻擊流量上有 alert，且 rule 內容對得上這種攻擊 |

> **講稿注意（怎麼讀）**
> - 三個指標問的問題不一樣，講稿第 4 頁當場要講到差別：有 alert 的 flow 比例（只是逐條 flow 的比例）、有沒有 alert（任何 alert 都算）、偵測得到（rule 要對得上攻擊）。例子：CIC-DDoS2019 19 項都有 alert，偵測得到的只有 3 項。偵測得到一定有 alert，但有 alert 不一定偵測得到；判斷標準同 p10 CICIoT2023 的 ✓（依 rule 名稱與內容的人工判斷）。
> - alert 對 flow：同一個 5-tuple（雙向都算，ICMP 不看 port），alert 的 packet 時間落在 flow 的開始和結束之間就對上；落不進任何 flow 的，再看 Suricata 那條 flow 的起始時間和 label 的 flow 起始時間是否相差 1 毫秒以內（有些 alert 要等 flow timeout 才送出，時間會在最後一個 packet 之後）。比對不用 packet 數，所以對齊失敗的 flow，它的 alert 一樣對得到。
> - 有 flow label 的三個 dataset，alert 幾乎都對得上 flow：CIC-IDS2017 5 天、CIC-DDoS2019 兩天都是 0 筆對不上；IoT-23 23 個 scenario 有 138 筆對不上（49-1 (Mirai) 135、52-1 (Mirai) 3），都落在 label 結束之後（label 只涵蓋 pcap 前段）。CIC-DDoS2019 01-12 的 39,472 筆 alert 裡有 38,510 筆是攻擊者 172.16.0.5 → 192.168.50.1 的 `GPL ICMP PING`，對到的是 CSV 的 Protocol 0 flow（原版 CICFlowMeter 把 ICMP 記在 Protocol 0、port 0/0，見 p2）。
> - 同一筆 alert 落在兩條以上 flow（同 5-tuple、時間重疊）時，每條都算：IoT-23、CIC-IDS2017、CIC-DDoS2019 01-12 都是 0 筆；03-11 的 CSV 有重複列，每組只留一條，所以也是 0 筆。
> - **為什麼要分開看**：rule 常設 threshold。例如 IoT-23 的 `ET SCAN Potential SSH Scan OUTBOUND`（SID 2003068）是 `type threshold, track by_src, count 5, seconds 120`：同一個來源 120 秒內每累計 5 次符合條件的 SYN 才報 1 次，數的是 SYN 的比對次數，不是 flow 數；如果一條 flow 只有一個 SYN，有 alert 的 flow 約 20%，但這不是上限（39-1 (IRCBot) 實際是 20.0%，3-1 (Muhstik) 是 31.1%，原因**沒有查**）。Heartbleed 的 rule 120 秒內只報 1 次，11 條攻擊 flow 只有 1 條有 alert。所以 scan／DoS 不能只看比例，要看偵測得到。
> - 以實際輸出的 alert 為準：被 threshold 壓掉的不算，因為 gateway 實際上也只會收到輸出的 alert。
> - 「有 alert」不等於「認出這個攻擊」：例如 CIC-DDoS2019 的攻擊 flow 有 alert，是因為攻擊主機一直在 ping 受害主機，或有背景的 SSH 連線、零星連資料庫 port（見 p9）。表格會把觸發的 rule 類型寫出來，讓人判斷是不是跟攻擊有關。
> - 被問到「這是不是 detection rate」：不是。有 alert 的 flow 比例只是逐條 flow 的比例，不代表認出攻擊（alert 可能和攻擊無關）；「這個攻擊有沒有被偵測到」看第三個指標，偵測得到。
> - 被問到「為什麼不按 flow 一條一條送」：判斷單位是 flow，但送進去的是整個 pcap、照原本順序，因為很多 rule 要看好幾條 flow 才觸發（例如 SSH scan 要同一來源 5 個 SYN），真實的 gateway 看到的流量也是交錯的；送完再用 label 對回 flow。

---

# 3. 偵測結果（章節頁 + p5–p11）

## p5 — 偵測總表
一張 4 列的表（字級約 0.85em）：

| Dataset | malicious flows | 有 alert 的 flow 比例（`full`／`gw_corp`） | 有攻擊相關特徵 alert 的類別 | Benign 有 alert |
|---|---|---|---|---|
| IoT-23 | 2.94 億 | 5.01%／5.01% | 6／15 | < 0.1% |
| CIC-IDS2017 | 50.5 萬 | 0.39%／0.38% | 10／15 | 0.7% |
| CIC-DDoS2019 | 6,984 萬 | 0.002%／0.001% | 3／19 | 0.3% |
| CICIoT2023 | 9.32 億 | 0.004%／0.003% | 11／33 | 1.5% |

- 表下一行：`flow 比例都很低；有相關特徵 alert 的攻擊，大多是有 payload 特徵的`
- 頁尾 `note`（三行）：`有攻擊相關特徵的 alert = 攻擊流量上有 alert，且 rule 內容對得上這種攻擊` ／ `CIC-DDoS2019 兩天分開算（7＋12 項，Syn 等兩天都有）；IoT-23 扣掉整個 39-1 (IRCBot) scenario 是 0.02%` ／ `CICIoT2023 照官方 label，整個檔的 flow 都算攻擊（含背景流量）`

malicious flows 寫成億／萬（精確數字 294,449,255、505,429、69,835,414、931,523,573 在講稿補充）。

數字來源與判斷：
- IoT-23（23 個有 label 的 scenario）：`results/iot23_by_label.tsv` 的 Malicious 列合計 294,449,255 條、有 alert 14,762,773（5.01%）、`gw_corp` 14,762,716（5.01%）；扣掉 39-1（73,561,644 條、有 alert 14,713,079）是 49,694／220,887,611 = 0.02%。攻擊種類 15 種 malicious label：✓ 6（PartOfAHorizontalPortScan、Attack［SSH scan rule］、C&C［IRC、Muhstik、Mirai checkin］、C&C-FileDownload、C&C-HeartBeat-FileDownload、FileDownload［ELF 下載］）；△ 1（Okiru：只有 Spamhaus DROP 的 IP 清單 alert，和 Okiru 內容無關）；✗ 8（DDoS、C&C-HeartBeat、C&C-PartOfAHorizontalPortScan、C&C-HeartBeat-Attack、C&C-Torii、PartOfAHorizontalPortScan-Attack、Okiru-Attack、C&C-Mirai）。Benign（含小寫 `benign` 1,956 條）30,860,691 條、有 alert 2,837（0.009%）。
- CIC-IDS2017：`results/cicids2017_by_label.tsv` 的 Malicious 列（不含 Attempted）合計 505,429、有 alert 1,947（0.385%）、`gw_corp` 1,941（0.384%）。15 種攻擊（p8 的表）有 alert 的 10 種，觸發的 rule 都對得上該攻擊（XSS、SQLi、Infiltration、FTP brute force、Heartbleed、SSH scan、Nmap User-Agent、資料庫 port scan、DoS tool、LOIC DDoS tool），所以 10／15；沒有 alert 的 5 種：DoS Hulk、GoldenEye、Slowloris、Web Attack – Brute Force、Botnet。Benign 10,293／1,581,058（0.65%）。
- CIC-DDoS2019：兩天 19 項（日期 × label：03-11 7 項、01-12 12 項；LDAP、MSSQL、NetBIOS、UDP、UDPLag／UDP-lag、Syn 兩天都有，所以不是 19 種不同攻擊，各 dataset 的分類粒度不同，不能直接比）；69,835,414 條、有 alert 1,578（0.0023%）、`gw_corp` 746（0.0011%）；rule 內容對得上的只有 03-11 MSSQL（MC-SQLR）、01-12 DrDoS_SNMP（SNMP public）、DrDoS_NTP（MON_LIST），所以 3／19（其他項目的 alert 是 ping、背景 SSH、資料庫 port scan，見 p9）。Benign 333／109,424（0.30%）。
- CICIoT2023：照官方 label（論文 Sec. 4：每次攻擊錄到的流量整段標成那種攻擊），305 個攻擊檔裡 Suricata 算出的每條 flow 都算 malicious：`results/ciciot2023.tsv` 攻擊檔的 `flows` 合計 931,523,573；有 alert 的 flow 是每個攻擊檔 eve.json 裡 alert 的 distinct `flow_id` 加總，`full` 38,600（0.0041%，＝ `flows_alert` 合計）、`gw_corp` 24,995（0.0027%，flow 上有任一 alert 的 SID 在 `gw_corp_sids.txt`）。38,600 條裡 33,412 條（87%）的 alert 全是 4 個 Benign 檔出現過的 SID（背景：UPnP 21,702、ICMP PING *NIX 7,774 等），有 Benign 沒出現過的 SID 的 5,188 條；`gw_corp` 少的 13,605 條裡 8,603 條有 ICMP PING、INFO 3,318、HUNTING 1,569。這幾個數字由 session scratchpad 的 `ciciot_flowratio.py`、`ciciot_gwdiff.py` 算出，沒有放進 repo。攻擊種類 33 種，p10 的 ✓ 11。Benign 5,157／345,984（1.49%）。
- 「有攻擊相關特徵的 alert」四個 dataset 統一用 p10 的 ✓ 標準：攻擊流量上有 alert，而且 rule 內容對得上這種攻擊（rule 都在 `gw_corp`）；只有 IP 清單或和攻擊無關的 alert 不算。

> **講稿注意（怎麼讀）**
> - 這是 security gateway 角度的總表，每次報告更新這張。每列一個 dataset；後面幾頁是每個 dataset 的細節。
> - 「有 alert 的 flow 比例」＝ 有 alert 的 malicious flow ÷ malicious flow（定義在第 4 頁）；`full` 是 ET Open 全部、`gw_corp` 是 10/19 挑的本地 rule，兩者幾乎一樣。
> - 「有攻擊相關特徵 alert 的類別」：分母是 label 的種類數（CIC-DDoS2019 是日期 × label 的項目數，19 項）；分子是攻擊流量上有 alert、而且觸發的 rule 對得上這種攻擊的種類（和第 10 頁 CICIoT2023 的 ✓ 同一個標準）。
> - 「有攻擊相關特徵的 alert」只表示有 alert 對得上攻擊內容，不代表認出 flood 或暴力破解的行為：例如 DrDoS_SNMP 靠的 rule 只比對送往 161 的 `public` 字串、沒有速率條件；SSH-Patator 靠的是 SSH scan rule，不是認出密碼嘗試。
> - `gw_corp` 的數字是從 `full` 的 alert 依 SID 篩出來的，沒有另外跑；有 rule 靠被排除的 rule 先設 flowbits 時會偏高（講稿當場講一句）。
> - 讀法：flow 比例四個都很低，因為 malicious flow 大多是 scan、flood（IoT-23 99.98%、CIC-IDS2017 98.5%、CIC-DDoS2019 100%；CICIoT2023 DDoS、DoS、Mirai 三類占 99.8%），沒有內容可以比；以攻擊種類來看，偵測得到的大多是 Web 攻擊、exploit、惡意程式下載、C&C 這些有 payload 特徵的，另外幾種靠只看 header 的 scan rule（IoT-23 PortScan、Attack；CIC-IDS2017 SSH-Patator、Portscan；CICIoT2023 HostDiscovery、PortScan）；只算比對 payload 的 rule 是 IoT-23 4／15、CIC-IDS2017 8／15、CICIoT2023 9／33。「沒有內容特徵 → 偵測不到」是**推論**：原因除了沒有內容特徵，也可能是 rule set 沒有對應的 rule、threshold 或設定。
> - IoT-23 的 5.01% 幾乎都是 39-1 (IRCBot) 的 SSH scan；扣掉整個 39-1 (IRCBot) scenario 只有 0.02%（49,694／220,887,611）。CIC-DDoS2019 的 19 項每一項都有 alert，但對得上攻擊內容的只有 3 項，其他是攻擊主機的 ping、背景 SSH 連線、資料庫 port scan（第 9 頁）。
> - Benign 有 alert 只列數字，不當成 false positive rate（第 11 頁）。


## p6 — IoT-23
一張表（字級約 0.85em）：

| label | flows | 有 alert 的 flow | 有 alert 的 scenario |
|---|---|---|---|
| PartOfAHorizontalPortScan | 213,852,924 | 6.9% | 4／11 |
| Okiru | 60,990,708 | 34 條 | 2／5 |
| DDoS | 19,538,713 | 0 | 0／7 |
| C&C-HeartBeat | 33,673 | 0 | 0／5 |
| C&C | 21,995 | 18.9% | 6／10 |
| Attack | 9,398 | 14.8% | 4／5 |
| FileDownload 類 | 82 | 93.9% | 7／7 |
| 其他 6 種 | 1,762 | 0 | 0／6 |

- 表下一行：`malicious flow 共 2.94 億條，有 alert 的 5.01%`
- 頁尾 `note`：`全部 23 個有 label 的 scenario、完整 pcap；rule set 為 full`

數字來源：`results/iot23_by_label.tsv`、`results/iot23_by_scenario.tsv`、`results/iot23_match/*.json`（23 個；11 個 usable 的彙總另存 `results/iot23_usable11_*.tsv`）。
- FileDownload 類 = `C&C-FileDownload`（53 條，50 條有 alert）＋ `C&C-HeartBeat-FileDownload`（11／11）＋ `FileDownload`（18／16）；有這三種 label 的 scenario 是 35-1、42-1、43-1、44-1、48-1、49-1、52-1，7 個都有 alert。
- 其他 6 種 = `C&C-PartOfAHorizontalPortScan` 888、`C&C-HeartBeat-Attack` 834、`C&C-Torii` 30、`PartOfAHorizontalPortScan-Attack` 5、`Okiru-Attack` 3、`C&C-Mirai` 2，都是 0。
- malicious 合計 294,449,255 條；有 alert 14,762,773 條（5.01%）；其中 14,711,802 條是 39-1 的 SSH scan（PartOfAHorizontalPortScan）、45,289 條是 3-1 (Muhstik) 的 SSH scan。沒有任何 alert 的 malicious flow 占 94.99%。
- C&C 的 4,165 條：34-1 (Mirai) IRC 1,767（6,706 條中）、49-1 (Mirai) `ET MALWARE Mirai Variant Checkin Response` 1,232（1,922 條中）、39-1 (IRCBot) IRC 1,156（1,530 條中，75.6%）、3-1 (Muhstik) `ET MALWARE ELF/Muhstik` 6（8 條中）、43-1、52-1 各 2（HUNTING／ELF）。
- Attack 的 1,389 條：3-1 SSH scan 1,264、39-1 SSH scan 121、48-1 IP 清單 3、17-1 1（`ET USER_AGENTS VPNFilter Related UA (Hakai/2.0)`）。
- 11 個 usable 時是 265,503,156 條、5.54%；多出的 12 個 scenario 有 malicious flow 28,946,099 條、有 alert 49,601 條（主要是 3-1 的 SSH scan 46,553 條、34-1 的 IRC 1,767、49-1 的 1,245［Mirai checkin 1,232、ELF 下載 13］）。60-1 (Gafgyt) 22 GB 的 DDoS 沒有任何 alert（Pi 速度測試的切片也是 0）。

> **講稿注意（怎麼讀）**：讀法同前一版；數字換成 23 個 scenario。另外說明：全部 23 個測完，結論和 11 個 usable 時一樣——比例幾乎都來自 SSH scan；多出來的 12 個 scenario 裡偵測得到的是 3-1 (Muhstik) 的 SSH scan 與 C&C、34-1 (Mirai) 的 IRC C&C、49-1 (Mirai) 的 C&C checkin，60-1 (Gafgyt) 的 DDoS（22 GB）一筆 alert 都沒有。

## p7 — IoT-23：觸發 alert 的 rule
一張表（字級約 0.85em，7 列）：

| | 流量 | 觸發的 rule |
|---|---|---|
| ✓ | SSH scan（39-1 IRCBot、3-1 Muhstik） | `ET SCAN Potential SSH Scan` |
| ✓ | IRC C&C（39-1 IRCBot、34-1 Mirai） | `ET CHAT IRC NICK／USER…` |
| ✓ | C&C checkin（3-1 Muhstik、49-1 Mirai） | `ET MALWARE Muhstik／Mirai Variant` |
| ✓ | ELF 下載（7 個 scenario） | `ET INFO ELF file download` |
| △ | 少數 PortScan、Okiru、Attack | IP 清單（Spamhaus DROP） |
| ✗ | SYN scan（23、52869、80、8081…） | — |
| ✗ | DDoS、C&C-HeartBeat、C&C-Torii、Okiru（37215） | — |

- 頁尾 `note`：`✓ 有對應 rule；△ 只有 IP 清單；✗ 沒有 alert`（三個符號互斥）

數字來源：同 p6。SID：SSH scan 2003068（`ET SCAN Potential SSH Scan OUTBOUND`，被感染的設備往外 scan；`type threshold, count 5, seconds 120`：同一來源每累計 5 次符合條件的 SYN 報 1 次，數的是 SYN 的比對次數、不是 flow 數）；IRC 2002023／2002024 等；Muhstik 2034743、2029319；Mirai checkin 2027366；ELF 2019240。

> **講稿注意**：同前一版；Okiru 有 34 條 flow 只有 IP 清單的 alert，所以算 △、p5 總表不算進 6／15，p7 表上 ✗ 那一列講的是 37215 的 SYN probe 這類流量本身（講稿當場要講這一句）；「計數型」只用在 SSH scan；新增 Muhstik、Mirai 的 C&C checkin 那一列：這兩條是 `ET MALWARE`，比對的是 C&C 通訊的內容。

## p8 — CIC-IDS2017
（投影片與講稿同前一版，頁碼改成第 8 頁。）
- 與 main.typ 同步：頁尾 `note`：`不含修正版標為 Attempted 的 flow（11,979 條，全部沒有 alert）`。Attempted 是修正版作者判定沒有實際送出攻擊內容的攻擊 flow，其中 897 條仍有 TCP payload，所以講稿不說「沒有 payload」。

## p9 — CIC-DDoS2019
一張 5 列的表（字級約 0.95em；數字欄靠右）：

| 項目 | flows | 有 alert 的 flow | 比對到攻擊 protocol 內容的 flow |
|---|---|---|---|
| MSSQL（03-11） | 5,787,453 | 12 條 | 7 條（MC-SQLR 回應） |
| DrDoS_NTP（01-12） | 1,202,642 | 190 條 | 3 條（NTP MON_LIST） |
| DrDoS_SNMP（01-12） | 5,159,870 | 210 條 | 103 條（SNMP `public`） |
| 其他 16 項 | 57,685,449 | 1,166 條 | 0 |
| 合計 19 項 | 69,835,414 | 1,578 條 | 113 條 |

- 表下一行：`比對到攻擊內容的都不到 0.01%；其他 alert 是攻擊主機的 ping、背景 SSH 連線、資料庫 port scan`
- 頁尾 `note`：`19 項 = 03-11 的 7 項＋01-12 的 12 項；gw_corp 有 alert 746 條（少的主要是 ping，它的 rule 不在 gw_corp）`（`gw_corp` 用等寬字）

數字來源：`results/cicddos2019_by_scenario.tsv` 的 19 列 Malicious（`flows`、`full_flows`、`gw_corp_flows`）。三項：0311 MSSQL 5,787,453／12（`gw_corp` 12）、0112 DrDoS_NTP 1,202,642／190（64）、0112 DrDoS_SNMP 5,159,870／210（118）；其他 16 項加總 57,685,449／1,166（`gw_corp` 552）；合計 69,835,414／1,578（`gw_corp` 746）。比對到攻擊 protocol 內容的 flow：MC-SQLR（SID 2020306）7、NTP MON_LIST（2017966）3、SNMP public（2101411）103，合計 113（見下面兩個補充小節）。其他 16 項的 alert 都不是這種攻擊的內容（ping、SSH scan、資料庫 port scan、Sipvicious、LibSSH、INFO 等；03-11 Syn 1 條、01-12 DrDoS_NetBIOS 2 條、DrDoS_SSDP 2 條、DrDoS_UDP 1 條，共 6 條 `GPL SNMP public access` 不是那一項的攻擊內容，不算），所以是 0。三項就是 p5「3／19」的 3 項。比例：MSSQL 有 alert 0.0002%、DrDoS_NTP 0.016%、DrDoS_SNMP 0.004%；比對到攻擊內容的 7／5,787,453、3／1,202,642、103／5,159,870 都 < 0.01%。

> **講稿注意（當場講）**
> - CIC-DDoS2019 兩天 19 項都是 DDoS；表上只列 rule 內容對得上攻擊的 3 項（就是第 5 頁 3／19 的 3 項），其他 16 項合成一列；19 項逐項的表在補充。
> - 三項的 rule 比對的是攻擊所用 protocol 的內容（MSSQL 的 MC-SQLR 回應、NTP 的 MON_LIST 回應、送往 161 的 SNMP request 裡的 `public`），但比對到的 flow 都不到 0.01%，不是認出 flood。
> - 其他 alert 是攻擊主機的 ping、整天的背景 SSH 連線、資料庫 port scan；6,984 萬條攻擊 flow 只有 1,578 條有 alert（`gw_corp` 746 條）。
>
> **講稿補充（`>` 行）怎麼組織**：同第 2 頁的做法，分 **03-11**、**01-12** 兩段，每段開頭放逐項的表（攻擊、時段（UTC）、flows、有 alert 的 flow、主要觸發的 rule；markdown 表格，數字照下面兩個「p9 補充」小節），接著是原本兩頁講稿的全部內容（怎麼讀、實驗怎麼做、被問到時），一條都不少，只改頁碼和指投影片的說法。

以下兩個小節是原 p9、p10 的規格，**不上投影片**，是講稿第 9 頁補充的素材。

### p9 補充：03-11
講稿補充的表（7 列，依時間排序）：

| 攻擊 | flows | 有 alert 的 flow | 主要觸發的 rule |
|---|---|---|---|
| Portmap | 186,960 | 18 條 | SCAN |
| NetBIOS | 3,657,497 | 7 條 | SCAN |
| LDAP | 1,915,122 | 2 條 | SCAN |
| MSSQL | 5,787,453 | 12 條 | DOS MC-SQLR、SCAN |
| UDP | 3,867,155 | 3 條 | SCAN |
| UDPLag | 1,873 | 6 條 | SCAN |
| Syn | 4,413,105 | 227 條 | SCAN |

講稿補充的時段（UTC，99% 的 flow 開始的時間，不上投影片）：Portmap 12:48–13:01、NetBIOS 13:01–13:09、LDAP 13:21–13:29、MSSQL 13:34–13:42、UDP 13:53–14:02、UDPLag 14:13–14:27、Syn 14:29–14:37。

- 03-11 攻擊 flow 1,983 萬條，有 alert 的 275 條；SCAN = SSH、資料庫 port 等的 scan rule。

數字來源：`results/cicddos2019_by_scenario.tsv`（0311 列）、`results/cicddos2019_match/0311.json`（`--cic`，含 Protocol 0，去重後的 label）；時段由 `conn/0311.dedup.conn.log.labeled` 每個 label（全部 flow）開始時間的 0.5%～99.5% 分位（去重前後相同），換成 UTC。label 的完整範圍（第一條開始到最後一條結束）：Portmap 12:18–13:01、NetBIOS 13:01–13:19、LDAP 13:19–13:33、MSSQL 13:32–13:53、UDP 13:52–14:13、UDPLag 14:13–14:29、Syn 14:28–20:36。
- 攻擊 flow 合計 19,829,165，有 alert 275（`gw_corp` 274）。對不到 flow 的 alert 是 0。
- MSSQL 的 12 條中，7 條是 SID 2020306 `ET DOS MC-SQLR Response Inbound Possible DDoS Target`，5 條是 SSH scan rule。
- SCAN 的來源（攻擊者都是 172.16.0.5）：
  - SID 2001219 `ET SCAN Potential SSH Scan`（03-11 全天 116 筆）：目的地全天都是同一台主機 192.168.50.4，每小時 9–17 筆，平均分布，不管當時在打哪種攻擊。這是攻擊主機整天的背景 SSH 連線，CIC 依時段把它標成當時的攻擊。這條 rule 是 `threshold: type both, track by_src, count 5, seconds 120`（同一來源累積 5 次才報 1 次、之後 120 秒內不再報，才是「計數型」）。
  - 資料庫 port 的 2010935（MSSQL 1433）／2010936（Oracle 1521）／2010937（MySQL 3306）／2010939（PostgreSQL 5432）：條件是 `flow:to_server; flags:S; threshold: type limit, count 5, seconds 60, track by_src`，外部送往該 port 的每個 SYN 都報、同一來源每 60 秒最多 5 筆，所以不是計數型。03-11 這類 alert 共 219 筆，全部是 172.16.0.5 → 192.168.50.4：154 筆在 Syn 時段（14:29–14:37），是 Syn（TCP SYN flood，65,522 個不同的目的 port）亂打 port 時打到；65 筆在其他時段，零星出現（例：12:48:06 和 13:03:34，同一個來源 port 63407 在約 6 ms 內依序打 3306、1433、5432，像 port scan）。攻擊主機為什麼在 Syn 以外的時段連資料庫 port，**沒有查**。
  - UDP 的反射攻擊和 UDP flood 本身不會觸發這些 TCP SYN 的 rule；Portmap、NetBIOS、UDP 這幾列的 SCAN alert 是攻擊主機的背景流量（SSH 連線、零星送往資料庫 port 的 SYN、Sipvicious）。
  - 各列 rule 的組成（flow 數，照 `results/cicddos2019_by_scenario.tsv` 的 `top_sids` 與 match JSON 的 `labels.*.sids`；一條 flow 可以有多條 rule 的 alert）：Portmap 18＝SSH scan 9、資料庫 port（2010935 3、2010937 2、2010939 1）、Sipvicious（2008578 3、2011716 1）；NetBIOS 7＝資料庫 port（2010935、2010937、2010939 各 1）、SSH scan 1、2022506（ET EXPLOIT）2、2060252（INFO）1；LDAP 2＝SSH scan 2；MSSQL 12＝2020306 7、SSH scan 5；UDP 3＝SSH scan 2、資料庫 port（2010935）1；UDPLag 6＝SSH scan 5、Sipvicious（2008578、2011716 各 1）；Syn 227＝SSH scan 92、資料庫 port（2010935 35、2010937 25、2010939 21、2010936 19）、Sipvicious（2008578 8、2011716 7）、VNC scan 8、POP3／IMAP brute force 16、2001972 2、2101411 1。
- SID 2020306 的內容：`alert udp $EXTERNAL_NET 1434 -> $HOME_NET any`，比對 MC-SQLR 回應的字串，`threshold: type both, track by_dst, count 30, seconds 60`。03-11 MSSQL 的 5,787,453 條中，任一端是 1434 的只有 217 條、從 1434 送出的 81 條。

> **講稿注意（怎麼讀）**
> - 每列一種攻擊（label 原名），照發生的先後排；時段是 99% 的 flow 開始的時間（UTC）。label 的完整範圍比較長，例如 Syn 的 label 一直到 20:36，但絕大多數的 flow 在開頭 10 分鐘，之後是攻擊主機零星的流量，也被標成 Syn。有 alert 的 flow 直接寫條數；最高的 UDPLag 是 6／1,873（0.32%），其餘都低於 0.1%。
> - 這個 dataset 全部是 DDoS：反射式（攻擊者偽造受害者 IP 向 DNS、LDAP、NTP 等伺服器送 request，回應打到受害者）和直接的 SYN、UDP flood。
> - 有 alert 的大多是 SCAN rule，這些不是認出 DDoS：SSH scan 是攻擊主機整天連同一台主機 22 port 的背景連線（不管當時打哪種攻擊，每小時都有）；資料庫 port 的 scan rule 有兩個來源：Syn flood 亂打 port 時打到 1433、3306（219 筆裡有 154 筆），和攻擊主機在其他時段零星連資料庫 port（65 筆，為什麼連**沒有查**）。SSH 是「計數型」（同一來源累積 5 次才報 1 次，之後 120 秒內不再報）；資料庫 port 的 rule 是每個 SYN 都報、每分鐘最多 5 筆，兩種都只看 header。
> - MSSQL 的 7 條 `ET DOS MC-SQLR Response Inbound` 比對的是 MSSQL 反射攻擊的回應內容，但這個 label 的 578 萬條 flow 裡，用到 1434 port 的只有 217 條，所以這 7 條只占該 label 極少的 flow（7／5,787,453，< 0.01%）。和 p10 的標準的關係：這個攻擊在 label 層級算有 alert（攻擊流量上有 alert、rule 內容對得上、rule 在 `gw_corp` 裡），但有 alert 的 flow 比例極低。為什麼 label 成 MSSQL 的 flow 大多不是 1434，**沒有查**。
> - Benign 見 p11。

### p9 補充：01-12
講稿補充的表（12 列，依時間排序）：

| 攻擊 | flows | 有 alert 的 flow | 主要觸發的 rule |
|---|---|---|---|
| DrDoS_NTP | 1,202,642 | 190 條 | ICMP PING、SCAN、DOS NTP |
| DrDoS_DNS | 5,071,011 | 162 條 | ICMP PING、SCAN |
| DrDoS_LDAP | 2,179,930 | 72 條 | ICMP PING、SCAN |
| DrDoS_MSSQL | 4,522,492 | 40 條 | ICMP PING、SCAN |
| DrDoS_NetBIOS | 4,093,279 | 35 條 | ICMP PING、SCAN |
| DrDoS_SNMP | 5,159,870 | 210 條 | SNMP public、ICMP PING |
| DrDoS_SSDP | 2,610,611 | 30 條 | ICMP PING、SCAN |
| DrDoS_UDP | 3,134,645 | 51 條 | ICMP PING、SCAN |
| UDP-lag | 366,461 | 42 條 | ICMP PING、SCAN |
| WebDDoS | 439 | 2 條 | INFO |
| Syn | 1,582,289 | 47 條 | SCAN |
| TFTP | 20,082,580 | 422 條 | ICMP PING、SCAN |

講稿補充的時段（UTC，99% 的 flow 開始的時間，不上投影片）：DrDoS_NTP 14:36–14:45、DrDoS_DNS 15:06–15:16、DrDoS_LDAP 15:22–15:32、DrDoS_MSSQL 15:32–15:47、DrDoS_NetBIOS 15:47–16:00、DrDoS_SNMP 16:00–16:23、DrDoS_SSDP 16:23–16:36、DrDoS_UDP 16:36–17:04、UDP-lag 17:04–17:30、WebDDoS 17:04–17:30、Syn 17:30–17:34、TFTP 17:34–18:00。

- 兩天合計 6,984 萬條攻擊 flow：有 alert 1,578 條、`gw_corp` 746 條；比對到攻擊 protocol 內容的只有 113 條（SNMP 103［01-12 DrDoS_SNMP］＋ MC-SQLR 7［03-11 MSSQL］＋ NTP MON_LIST 3［01-12 DrDoS_NTP］，三條 rule 都在 `gw_corp`）。
- ICMP PING 不在 `gw_corp`；WebDDoS 在 `UDPLag.csv` 裡、和 UDP-lag 同一段時間。

數字來源：`results/cicddos2019_by_scenario.tsv`（0112 列）、`results/cicddos2019_match/0112.json`（`--cic`，`labels.*.sids`）；時段由 `conn/0112/*.conn.log.labeled` 每個 label（全部 flow）開始時間的 0.5%～99.5% 分位，換成 UTC。label 的完整範圍：DrDoS_NTP 13:17–14:51、DrDoS_DNS 14:51–15:22、TFTP 17:34–21:16，其他和上面的時段差不到 1 分鐘。
- 01-12 攻擊 flow 合計 50,006,249，有 alert 1,303（`gw_corp` 472）。兩天合計 19,829,165 + 50,006,249 = 69,835,414；有 alert 275 + 1,303 = 1,578（約 0.002%）；`gw_corp` 274 + 472 = 746。
- `GPL ICMP PING` 系列（SID 2100366 `*NIX` 等 5 條，都不在 `gw_corp`）：01-12 有 38,510 筆，全部是攻擊者 172.16.0.5 → 192.168.50.1 的 ping，從 14:36 一直持續到 20:59（UTC），每小時約 5,700 筆，flood 結束後還在 ping（18:00 之後的 ping 落在 TFTP 的 Protocol 0 flow 裡：TFTP.csv 的 Protocol 0 flow 一直到 21:15，所以 TFTP 有 271 條 ping flow）。ping 落在同一對 IP 的 Protocol 0 flow 裡，這些 flow 被標成當時的攻擊。有 alert 的 1,303 條攻擊 flow 裡，有 811 條只因為 ping（這 811 條是 Protocol 0 flow，上面的 alert 只有 ping；這 811 條合計 26,760,200 個 packet，幾乎都是 flood 的 IP fragment 後續片段（整份 pcap 的 ICMP packet 只有 129,659 個）：其中 524 條是 IP fragment 為主、ping 因為是同一對 IP 被歸進同一條 flow；另外 287 條只有 ping 的 packet（TFTP 144 條、DrDoS_NTP 119 條等，共 11,416 個 packet）；不算 Protocol 0 時 01-12 有 alert 的攻擊 flow 是 492 條，1,303 − 492 ＝ 811）。
- 各列 `gw_corp` 有 alert 的 flow：DrDoS_NTP 64、DrDoS_DNS 19、DrDoS_LDAP 6、DrDoS_MSSQL 7、DrDoS_NetBIOS 20、DrDoS_SNMP 118、DrDoS_SSDP 7、DrDoS_UDP 14、UDP-lag 29、WebDDoS 0、Syn 44、TFTP 144。
- 各列觸發的 rule（flow 數，`full`）：
  - DrDoS_NTP：2100366（123）、SSH scan 2001219（43）、資料庫 port scan、LibSSH、Sipvicious，**SID 2017966 `ET DOS Likely NTP DDoS In Progress MON_LIST Response to Non-Ephemeral Port IMPL 0x03`（3）**，另有 2072593（HUNTING）2、2100227（GPL SNMP trap Format String）2、2038967（INFO）1。
  - DrDoS_SNMP：**SID 2101411 `GPL SNMP public access udp`（103）**、2100366（91）、SSH scan 11、LibSSH 2、資料庫 port 2、2060252（INFO）1。
  - DrDoS_DNS：2100366（143）、SSH scan 13、LibSSH 2、MSSQL port 2、Sipvicious 2、2027126（`ET MALWARE ELF/Mirai Variant UA Inbound (Yakuza)`）1。
  - DrDoS_LDAP：2100366（64）、SSH scan 5、2072593 2、2101948 1。
  - DrDoS_MSSQL：2100366（33）、SSH scan 6、MySQL port 1。MC-SQLR rule（2020306）在 01-12 沒有觸發。
  - DrDoS_NetBIOS：2100366（14）、SSH scan 6、資料庫 port 9、LibSSH 3、2101411 2、2060252 1。
  - DrDoS_SSDP：2100366（22）、SSH scan 5、2101411 2、2060252 1。
  - DrDoS_UDP：2100366（34）、SSH scan 13、2072593 3、2101411 1。
  - UDP-lag：2100366（13）、SSH scan 12、資料庫 port 14、LibSSH、Sipvicious、VNC scan 各 1。
  - WebDDoS：2060252 `ET INFO Go-http-client User-Agent Observed Inbound`（2），不在 `gw_corp`。
  - Syn：資料庫 port scan 32（MSSQL 10、MySQL 9、PostgreSQL 7、Oracle 6）、VNC scan 4、POP3／IMAP brute force 4、SSH scan 2、2100366（ICMP PING）3 等，主要是 SCAN。
  - TFTP：2100366（271）、SSH scan 101、MSSQL port 13、LibSSH 12、Sipvicious 7、2101948 6、2072593 6、MySQL 4、2038967 2、PostgreSQL 1。
- SSH scan（2001219）在 01-12 全天 217 筆，全部是 172.16.0.5 → 192.168.50.1，UTC 13–20 點每小時 20–28 筆（同一來源 120 秒最多報 1 次），和當時在打哪種攻擊無關。
- 資料庫 port 的 scan rule（2010935／2010936／2010937／2010939）：`flags:S; threshold: type limit, count 5, seconds 60, track by_src`，每個外部送往該 port 的 SYN 都報（每分鐘最多 5 筆），不是計數型。01-12 這類 alert 共 181 筆，全部是 172.16.0.5 → 192.168.50.1：75 筆在 Syn 時段（17:30–17:34），106 筆在其他時段（沒有再逐筆區分）。攻擊主機為什麼在 Syn 以外的時段連資料庫 port，**沒有查**。各列打到資料庫 port 的 flow 數：DrDoS_NTP 8、DrDoS_DNS 2、DrDoS_MSSQL 1、DrDoS_NetBIOS 9、DrDoS_SNMP 2、UDP-lag 14、Syn 32、TFTP 18。
- 反射攻擊的 label 幾乎都沒有用到該 protocol 的 port（任一端是該 port 的 flow／該 label 的 flow）：DrDoS_SNMP 161：215／5,159,870；DrDoS_NTP 123：32／1,202,642（從 123 送出的 21 條）；DrDoS_MSSQL 1434：154／4,522,492（從 1434 送出 57 條）；DrDoS_DNS 53：180／5,071,011；DrDoS_LDAP 389：89／2,179,930；DrDoS_NetBIOS 137：195／4,093,279；DrDoS_SSDP 1900：0／2,610,611。
- SID 2017966 的內容：`alert udp any 123 -> any 0:1023`，比對 NTP mode 7 的 MON_LIST 回應，`threshold: type both, track by_src, count 1, seconds 120`。3 筆 alert 都是 `172.16.0.5:123 → 192.168.50.1`（UTC 14:36:44、14:40:03、14:43:39）。SID 2101411：`alert udp $EXTERNAL_NET any -> $HOME_NET 161`，比對 `public`（SNMP 預設 community）。

> **講稿注意（怎麼讀）**
> - 讀法同 03-11。01-12 的 12 種攻擊從 NTP 開始，一種接一種；WebDDoS 沒有獨立的 CSV 檔，439 條在 `UDPLag.csv` 裡，時間和 UDP-lag 重疊。
> - 有 alert 的 flow 大多來自三種，不是認出 DDoS：
>   - `GPL ICMP PING`：攻擊主機從 14:36 開始一直 ping 受害主機，到 20:59（UTC）還在 ping，連 flood 結束後也沒停。CICFlowMeter 把 ping 和 flood 的 IP fragment 後續片段歸成同一條 Protocol 0 flow（同一對 IP），這些 flow 被標成當時的攻擊，但 alert 來自 ping。01-12 有 811 條攻擊 flow 只因為 ping 才有 alert；這些 rule 不在 `gw_corp`，所以 `gw_corp` 的數字小很多（472 條）。
>   - SSH scan：和 03-11 一樣，是攻擊主機整天連同一台主機 22 port 的背景連線；「計數型」（同一來源累積 5 次才報 1 次，之後 120 秒內不再報）。
>   - 資料庫 port 的 scan rule：每個外部送往該 port 的 SYN 都報（每分鐘最多 5 筆），不是計數型。來源有兩個：Syn flood 亂打 port 時打到（01-12 的 181 筆有 75 筆在 Syn 時段），和攻擊主機在其他時段零星連資料庫 port（106 筆，為什麼連**沒有查**）。
> - 比對到攻擊所用 protocol 內容的 rule 有兩條：SNMP 的 `GPL SNMP public access`（103 條，比對 SNMP 預設 community `public`）、NTP 的 `ET DOS Likely NTP DDoS In Progress MON_LIST Response`（3 條）。但這些 label 的 flow 幾乎都沒有用到該 protocol 的 port（DrDoS_SNMP 516 萬條裡只有 215 條碰到 161、DrDoS_NTP 120 萬條裡只有 32 條碰到 123、DrDoS_SSDP 一條都沒有碰到 1900），所以只占該 label 極少的 flow，比對到攻擊內容的 flow 比例 < 0.01%。為什麼 CIC 標成反射攻擊的 flow 大多不是該 protocol 的 port，**沒有查**。
> - 和 p10 標準的關係：p10 CICIoT2023 的 ✓ 是「攻擊流量上有 alert、rule 內容對得上這種攻擊、rule 在 `gw_corp` 裡」。套用到 label 層級，01-12 的 DrDoS_SNMP、DrDoS_NTP 和 03-11 的 MSSQL 都算有 alert（講稿要講清楚這是「有沒有 alert」），但比對到攻擊內容的 flow 都 < 0.01%（SNMP 103／5,159,870、NTP 3／1,202,642、MSSQL 7／5,787,453），所以說「只比對到極少的 flow」，不說認出 flood。
> - 01-12 的 DrDoS_MSSQL 沒有觸發 MC-SQLR rule：這條 rule 只比對從 udp/1434 送出的回應，01-12 的 DrDoS_MSSQL 452 萬條裡，從 1434 送出的只有 57 條。
> - WebDDoS 的 2 條是 INFO 類的 User-Agent rule（Go 的 HTTP client），不是認出 DDoS。
> - 兩天合計：6,984 萬條攻擊 flow，有 alert 的 1,578 條（約 0.002%），其中只有 113 條（SNMP 103、MC-SQLR 7、NTP 3）比對到攻擊所用 protocol 的內容，其餘幾乎都不是認出 DDoS；`gw_corp` 746 條。

## p10 — CICIoT2023
投影片表格與 `33 種攻擊：✓ 11、△ 6、✗ 16` 那一行同前一版（全部 309 個檔判斷完，結果和只做 36 個檔時相同）。改兩處：
- 表下一行改成 `33 種攻擊（全部 309 個檔）：✓ 11、△ 6、✗ 16`
- 頁尾 `note`：`label 是整個檔；以 4 個 Benign 檔為基準，只看 Benign 沒出現過的 rule`

數字來源：`results/ciciot2023_by_attack.tsv`（每種攻擊合計：檔數、攻擊特有 SID、每個 SID 在幾個檔出現與幾條 flow）、`results/ciciot2023_judgement.tsv`（逐一判斷，`files_done` 欄 = 跑完的檔數／官方檔數，全部相等）。Benign 基準：4 個 Benign 檔出現過的 10 個 SID。

> **講稿注意**：同前一版，加三點：
> - 這次是全部 309 個檔；多檔的 flood（每種 8–29 個檔），其他檔多出來的 rule 都是背景流量（403 Forbidden、Go HTTP client User-Agent、.cc TLD 的 DNS 查詢、External IP Lookup、TLS Handshake Failure、STUN、Jabber），在 ICMP、UDP、TCP 這些不相干的 flood 檔都出現，所以判斷不變。
> - Mirai 的 GRE flood（greeth、greip）多了 `GPL SNMP trap Format String`（2100227，在 `gw_corp`）和 `ET TFTP Outbound TFTP ACK`（2008118）：alert 落在 GRE 封裝的內層 packet 上，內層的 IP 是隨機的，是 flood 的亂數內容碰巧對上打到 162、69 port 的 rule，和 Mirai 無關，所以還是 △。
> - 限制（取代原本「✗ 只代表這一個檔」那句）：判斷是依 rule 名稱與內容的人工判斷；✓ 的攻擊都只有 1 個檔（Web、Recon、Brute Force）。
> - 「以 Benign 檔出現過的 SID 為背景」是啟發式：同一個 SID 也可能同時落在攻擊流量上；✗ 的意思是「依這個判準沒有找到相關 alert」（講稿當場要講）。

## p11 — Benign 上的 alert
一張表：

| Dataset | Benign flows | 有 alert | 主要的 rule |
|---|---|---|---|
| IoT-23 | 30,860,691 | 2,837（< 0.1%） | SSH scan、IRC、BitTorrent |
| CIC-IDS2017 | 1,581,058 | 10,293（0.7%） | JA3 Adware、DNS TLD |
| CIC-DDoS2019 | 109,424 | 333（0.3%） | SSH scan |
| CICIoT2023 | 345,984 | 5,157（1.5%） | UPnP、ICMP PING |

- 頁尾 `note`：`dataset 的 Benign label 本身有疑點，不能直接當成 false positive；CICIoT2023 是 4 個 Benign 檔裡 Suricata 算出的 flow`

數字來源：`results/*_by_label.tsv` 的 Benign 列；IoT-23 是 23 個 scenario（含小寫 `benign` 1,956 條），有 alert 2,837（`gw_corp` 2,474），主要是 SSH scan OUTBOUND、IRC、BitTorrent；CIC-DDoS2019 是 03-11 去重後（52,561／175）＋ 01-12（56,863／158）＝ 109,424／333（`gw_corp` 315；含 Protocol 0 的 Benign flow，它們都沒有 alert）；主要的 rule 是 `ET SCAN Potential SSH Scan OUTBOUND`（311 條）。CICIoT2023 是 4 個 Benign 檔（`BenignTraffic`、`BenignTraffic1`–`3`）的 `flow.total` 合計 345,984、有 alert 的 flow（distinct `flow_id`）5,157（`gw_corp` 3,676），主要是 `GPL MISC UPnP malformed advertisement` 與 `GPL ICMP PING`（`results/ciciot2023.tsv` 的 BenignTraffic 列）。其餘同前一版。

> **講稿注意**：同前一版；CIC-DDoS2019 那句是「CIC-DDoS2019 Benign 的 alert 幾乎都是 SSH scan OUTBOUND（333 條中 311 條）」；CICIoT2023 是 4 個 Benign 檔合計。

---

# 4. 結論與下一步（章節頁 + p12–p13）

## p12 — 結論
投影片同前一版，只改表的第 2 列：攻擊型態 `只有 header 的大量流量` → `沒有內容特徵的大量流量`（例子不變：SYN scan、TCP／UDP flood、反射式 DDoS、HTTP DoS）。HTTP DoS 送的是正常格式的 HTTP request，有 payload，偵測不到是因為 payload 沒有特徵，不是只有 header。

另外在頁面最下方加一行（字級 0.72em）：`Pi 處理速度：Suricata 掛 full 最慢是 HTTP flood（6.2–8.5 kpps）；10/19 最慢的 SSH scan 約 15 kpps`（數字來源 `tests/ids_throughput/README.md` 實驗 5；講稿補充量法：Pi 上 engine 直接讀 pcap、Suricata 8.0.7、41 個切片，IoT-23 14 個重測和 10/19 差 −4% 到 +10%；CIC 27 個依流量型態歸類）。

講稿：表上「偵測」欄的 ✓ 大多、✗ 大多指「有攻擊相關特徵的 alert」這個定義（不是有沒有 alert）；「沒有內容特徵 → 偵測不到」的因果標**推論**（原因也可能是 rule set 沒有對應的 rule、threshold 或設定）；當場講速度那一行時補「這是 Pi 讀代表性切片（每個最多 20 萬 packets）量的 engine 處理速度，不是 gateway 的線上吞吐量；線上的留到下一步」。第二種占 malicious flow 的比例：IoT-23 99.98%（23 個 scenario）、CIC-IDS2017 98.5%、CIC-DDoS2019 100%；IoT-23 39-1 (IRCBot) 的 SSH scan 占 IoT-23 malicious flow 的 25.0%、實際有 20.0% 的 flow 有 alert；IoT-23 的 malicious flow 有 94.99% 沒有任何 alert；CIC-DDoS2019 改成「6,984 萬條攻擊 flow 只有 1,578 條有 alert（`gw_corp` 746 條），而且幾乎都不是認出 DDoS：大多是攻擊主機的 ping、背景 SSH 連線、資料庫 port 的 scan rule；只有 113 條（SNMP 103、MC-SQLR 7、NTP 3）比對到攻擊所用 protocol 的內容，而且只占該 label 極少的 flow（< 0.01%）」。第 1 列的 punch 句不變；「例外」改成「SSH 等少數 port 有只看 header 的 scan rule」（「計數型」只用在 SSH）。

## p13 — 下一步
兩個小標，各 2 點：
- **速度**
  - inline 重播：照原本的時間送整個 pcap，看 Pi 跟不跟得上
  - HTTP flood 為什麼最慢：用 profiler 看時間花在哪
- **偵測**
  - scan／flood 的 flow 統計偵測：先量 Pi 上的成本
  - 把 gateway 接上 inline 重播，看實際收到的 alert

> **講稿注意**
> - 四個 dataset 的偵測都做完了（IoT-23 全部 23 個有 label 的 scenario、CIC 三個全部）；之後加新的 dataset 照同一套流程。
> - inline 重播：照原本的順序和時間送整個 pcap（筆電兩張網卡分別接 Pi 的 LAN／WAN，tcpprep 依 MAC 分方向、tcpreplay 送），回答「Pi 跟不跟得上」；目前的速度是 engine 讀 pcap 的上限，inline 還要加上收封包、NFQUEUE 的成本。加速重播會讓 threshold 的時間窗變短，所以速度測試和偵測測試分開看。
> - 「先量 Pi 上的成本」：專案規則是每個決策都要實際量過效能。
> - inline：10/19 之後 gateway（wnc-gw）已經在 Pi 上跑 Suricata 8.0.7 + NFQUEUE／NFLOG；下一步是把 dataset 重播過 gateway，確認 inline 收到的 alert 和這次 offline 的一致。

## p14 — References
（同前一版。）

## Q&A
`focus-slide[Q&A]`

---

## 講稿（逐字稿.md）規格
- 格式沿用 10/19 的 `逐字稿.md`：每頁一節（`## 第 N 頁　標題`），章節頁一行。
- **逐字稿分兩部分（2026-11-02 起）：「一、當場講」是每頁要講的話，「二、補充」是每頁的怎麼讀、實驗怎麼做、被問到時，不用 `>`。**（被問到或時間夠才講）。檔頭的「使用方式」要寫成這個規則。
- 每頁要有：當場要講的內容（2–6 行）、「怎麼讀」這張表的說明、「**實驗怎麼做**」、「**被問到時**」。標「**推論**」「**沒有量**」「**沒有查**」的要在講稿寫出來。
- 只寫最終版本要講的內容，不寫改動紀錄（不要出現「改成」「原本是抽樣」「這版新增」這類字）。
- 頁碼全部重編：所有「見第 N 頁」都要對照 0.4 的頁碼（結論第 12 頁、下一步第 13 頁、References 第 14 頁）。
- 用詞照 0.3 的對照表。

---

## 已刪除：第 4 章 Pi 處理速度（2026-11-01 使用者決定不放，以下留作備查）

（原規格）

這一章的寫法照 10/19「完整 ET Open rules」那一章：實驗設定表 → 切片表 → 處理速度的點圖，讓聽眾可以直接和 10/19 對照。圖由 `assets/make_figs.py` 產生，樣式（橫向點圖、kpps 對數刻度 0.3–300、右側 full time 欄、分群空半格）和 10/19 的 `fig_full14.svg` 相同；只有 Suricata 一個 panel。

## p16 — 速度測試設定
同 10/19「實驗設定」頁的版面：
- `punch`：`問題：四個 dataset 的流量，Pi 上的 Suricata 處理得多快`
- `callout(kind: "info")`：`同 10/19：engine 直接讀 pcap，量處理上限；沒有走 cli → DUT → srv`
- 一張 2 欄表：

| 項目 | 設定 |
|---|---|
| Hardware | Raspberry Pi 4（4 GB），1000 MHz |
| Engine | Suricata 8.0.7（10/19 是 7.0.10） |
| Rules | ET Open 2026-10-30：`full` 52,798、`gw_corp` 38,506 |
| Traffic | 每個切片最多 20 萬 packets：IoT-23 14 個、CIC 27 個 |

數字來源：`tests/ids_throughput/README.md` 實驗 5；`results/pi/pi_scen3_*.env.json`。

> **講稿注意**
> - 和 10/19 同一套量法：pcap 先複製到記憶體（tmpfs），Suricata 單一 thread 直接讀、綁在 CPU 2、3；Pi 鎖 1000 MHz（1.8 GHz 滿載約 30 秒會撞溫度牆降頻）；每個切片 × rule set 先跑 1 次 warm-up、再跑 3 次取中位數；kpps ＝ packets ÷ engine 自己回報的處理時間（不含載入 rule）。這是 engine 的處理上限，不是 gateway 的線上速率。
> - 和 10/19 不同的地方：engine 換成 Pi 現在裝的 Suricata 8.0.7，rule 換成偵測測試用的同一份（2026-10-30），所以四個 dataset 的速度可以直接比；只量 Suricata（10/18 決定以 Suricata 為 base）。
> - 切片：IoT-23 是 10/19 的 14 個 scenario（同樣的切片，重量）；CIC 三個 dataset 照 10/19 挑 scenario 的原則，先算每種攻擊時段的流量特徵（平均大小、payload 比例、TCP／UDP／ICMP 比例、SYN 比例、目的 port 與目的 IP 的分散程度），依流量型態歸類、同一類只量一個：71 個候選挑出 27 個（10/19 是特徵幾乎相同才只取一個，這次歸得比較粗，同一類的速度可能不同，**沒有量**）。CIC-IDS2017、CIC-DDoS2019 的攻擊是一天裡的一段時間，切片從攻擊開始的時間取 20 萬 packets（含同時段的背景流量）；CICIoT2023 一個檔一種攻擊，取檔案開頭。
> - **實驗怎麼做**：2026-10-31 在同一次開機內跑完，正式量測 498 次、作廢 0（量測前後都檢查有沒有降頻、溫度過高）；開頭和結尾各量一次同一個切片（`C_somfy02` × `full`）當錨點：45.5 → 45.3 kpps，整段期間沒有漂移。
> - 被問到「empty（不掛 rule）為什麼沒畫」：10/19 的圖有 empty。這次 CIC 的 flood 切片 flow 很多，Suricata empty 的速度要用差分法算（含讀完 pcap 後清 flow 的時間），有 6 個 flow 很多的切片 empty 反而比 `full` 慢（例如 CICIoT2023 DDoS-TCP_Flood：empty 27.6、`full` 113.4 kpps；另外 DoS-TCP_Flood、DoS-UDP_Flood、Mirai-greip_flood、DrDoS_SNMP、DrDoS_MSSQL），畫在一起會誤導，所以圖上只放 `full` 和 `gw_corp`（差分法 10/19 也用）；empty 的數字在 `pi_scen3_E.summary.csv`。
> - load time（載入 rule 的時間）：`full` 中位數 39.1 秒、`gw_corp` 27.1 秒（10/19 的 7.0.10 是 34.9、24.7）。RSS：`full` 1,356–1,387 MB，HTTP flood 比較大（CIC-IDS2017 DoS Hulk 1,671 MB、CICIoT2023 DDoS-HTTP_Flood 1,404 MB）。

## p17 — IoT-23：8.0.7 重測
- 圖：`assets/fig_speed_iot23.svg`（寬 100%，長寬比和 10/19 的 `fig_full14` 相近：2.84；cic 3.09、ciciot 2.76）。列＝10/19 的 14 個 scenario（同順序、同分群）；空心方塊 = 10/19 的 `full`（Suricata 7.0.10）、實心方塊 = 8.0.7 `full`、藍點 = 8.0.7 `gw_corp`；右側 full time 是 8.0.7 `full` 處理這個切片的秒數。
- 圖下兩點：
  - `和 10/19 的 7.0.10 差不多：−4% ～ +10%`
  - `最慢仍是 39-1 (IRCBot)：14.9 kpps（10/19 是 15.5）`

數字來源：`assets/speed_numbers.tsv`（`S_` 開頭 14 列：`full_kpps`、`gw_corp_kpps`、`full_time_s`、`full_kpps_7010`）。8.0.7 ÷ 7.0.10：最低 39-1 −4.0%、最高 Honeypot-5-1 +10.4%（用未四捨五入的 kpps 算）。`gw_corp` 比 `full` 快 2–25%（中位數 5%，最多的是 Honeypot-7-1 45.0 → 56.2）。

> **講稿注意（怎麼讀）**
> - 圖的讀法和 10/19 一樣：橫軸是 kpps（對數刻度），越右越快；每列一個 scenario，分三群：20 萬 packets 的 scan／混合、20 萬 packets 的 flood／下載、不足 20 萬的小檔；右邊的 full time 是處理這個切片花的秒數。
> - 這頁是要確認換成 8.0.7 和新 rule 之後，10/19 的結論還成立：每個 scenario 幾乎都和 10/19 重疊，最慢的還是 39-1 (IRCBot) 的 SSH scan。
> - `gw_corp`（藍點）和 10/19 一樣只快一點點：中位數 5%。

## p18 — 速度測試的切片：CIC-IDS2017、CIC-DDoS2019
同 10/19「效能測試的 14 個 scenario」頁的表（字級約 0.74em），兩個 dataset 各一個小標列：

| 切片 | 流量型態 | packets | 平均 packet | 同型態、沒另外量的 |
|---|---|---|---|---|
| **CIC-IDS2017** | | | | |
| Benign | benign | 200,000 | 475 B | 低量攻擊的時段 |
| DoS Hulk | HTTP flood | 200,000 | 901 B | DDoS、DoS GoldenEye |
| Portscan | SYN scan | 200,000 | 150 B | — |
| FTP-Patator | large-packet transfer | 200,000 | 1,257 B | Web Attack – Brute Force |
| **CIC-DDoS2019（01-12）** | | | | |
| Benign | benign | 200,000 | 840 B | 03-11 Benign、Portmap |
| DrDoS_DNS | UDP reflection, large | 200,000 | 1,262 B | 兩天的 LDAP |
| DrDoS_MSSQL | UDP reflection, medium | 200,000 | 632 B | 03-11 MSSQL、DrDoS_SSDP |
| DrDoS_SNMP | UDP reflection, small | 200,000 | 271 B | 03-11 NetBIOS |
| DrDoS_NTP | UDP reflection, few ports | 200,000 | 480 B | — |
| DrDoS_UDP | UDP flood | 200,000 | 412 B | 03-11 UDP、DrDoS_NetBIOS、UDP-lag |
| Syn | SYN flood | 200,000 | 60 B | 03-11 Syn |
| TFTP | SYN + UDP mixed | 200,000 | 236 B | 03-11 UDPLag、WebDDoS |

- 頁尾 `note`：`每種攻擊從攻擊開始的時間取 20 萬 packets（含同時段的背景流量）；依流量型態歸類，同一類只量一個`

數字來源：`tests/ids_throughput/manifest_cic.json`（packets、`avg_pkt_size`）；挑選與特徵 `results/cic_slice_features.tsv`；同型態的對照見 `tests/ids_throughput/README.md` 實驗 5 的表。

> **講稿注意（怎麼讀）**
> - 欄位同 10/19：流量型態是這個切片的主要流量；平均 packet 是 pcap 記錄長度的平均；最後一欄是特徵和它幾乎相同、所以沒有另外量的攻擊（10/19 的 IoT-23 也是這樣從 23 個挑 14 個）。
> - CIC-IDS2017 的低量攻擊（Slowloris、Slowhttptest、Heartbleed、Infiltration、SSH-Patator、Web Attack XSS／SQL Injection、Botnet）在攻擊時段切到的 20 萬 packets 幾乎都是背景流量，特徵和 Benign 一樣，所以用 Benign 代表。FTP-Patator 那段時間的主要流量是一條大量傳輸（平均 1,257 B），不是 FTP 登入本身。
> - CIC-DDoS2019 只用 01-12 的切片：03-11 的每一種攻擊，01-12 都有同型態的切片；同一攻擊名稱在兩天不一定同型態（03-11 NetBIOS 271 B 歸到 DrDoS_SNMP，DrDoS_NetBIOS 385 B 歸到 DrDoS_UDP）。03-11 Benign、Portmap 歸到 01-12 Benign，但 protocol 比例不同（UDP 36–56% 對 9%），**沒有量**。
> - 反射式 DDoS 的回應很大、會分段，IP fragment 的後續片段沒有 L4 header，所以特徵表裡的「目的 port 數」很大，不代表真的打很多 port；依平均大小分成 large／medium／small。

## p19 — CIC-IDS2017、CIC-DDoS2019 的處理速度
- 圖：`assets/fig_speed_cic.svg`（寬 100%）。兩群：CIC-IDS2017 4 列、CIC-DDoS2019 8 列；實心方塊 = `full`、藍點 = `gw_corp`；右側 full time。
- 圖下三點：
  - `CIC-IDS2017 最慢：DoS Hulk 6.2 kpps（HTTP flood）`
  - `CIC-DDoS2019 反射式 DDoS 43–77 kpps，比 Benign（16.0）快`
  - `gw_corp 只快 5–34%`

數字來源：`assets/speed_numbers.tsv`（`C17_`、`D12_` 開頭）。`full` kpps：CIC-IDS2017 Benign 15.5、DoS Hulk 6.2、Portscan 26.1、FTP-Patator 18.2；CIC-DDoS2019 Benign 16.0、DrDoS_DNS 43.0、DrDoS_MSSQL 52.0、DrDoS_SNMP 76.5、DrDoS_NTP 63.3、DrDoS_UDP 55.2、Syn 34.3、TFTP 34.7。`gw_corp` 比 `full` 快：CIC-IDS2017 7–13%、CIC-DDoS2019 5–34%（最多 DrDoS_NTP 63.3 → 85.0）。

> **講稿注意（怎麼讀）**
> - 讀法同上一頁。最慢的是 HTTP flood（DoS Hulk 6.2 kpps，處理 20 萬 packets 要 32 秒），不到 IoT-23 最慢的 39-1 (IRCBot)（14.9 kpps，10/19 是 15.5）的一半；RSS 也最大（1,671 MB，其他 1,356 MB）。原因推測是每個 packet 都要做 HTTP 解析、比對大量看 HTTP 內容的 rule（**推論**，沒有用 profiler 量）。
> - 反射式 DDoS 和 UDP flood 比 Benign 快：UDP 沒有 TCP 的 stream 重組和大部分的 app-layer 解析（**推論**）。
> - 兩個 Benign 都約 16 kpps，和 IoT-23 最慢的 scan 同一個量級；也就是說，Pi 光是處理正常的公司流量，單一 thread 也只有十幾 kpps。
> - `gw_corp` 一樣只快一點；原因推測是拿掉的 rule 大多不常被比對到（**推論**）。講稿要有「實驗怎麼做」「被問到時」。

## p20 — 速度測試的切片：CICIoT2023
同 p18 的表（字級約 0.70em）：

| 切片 | 流量型態 | packets | 平均 packet | 同型態、沒另外量的 |
|---|---|---|---|---|
| Benign | benign | 200,000 | 217 B | Web 類、Brute Force、DNS_Spoofing、PingSweep |
| MITM-ArpSpoofing | large TCP transfer | 200,000 | 1,128 B | — |
| Recon-PortScan | scan | 200,000 | 168 B | HostDiscovery、OSScan、VulnerabilityScan |
| DDoS-HTTP_Flood | HTTP flood | 200,000 | 384 B | DoS-HTTP_Flood、DDoS-SlowLoris |
| DDoS-SYN_Flood | SYN flood | 200,000 | 67 B | SynonymousIP、DoS-SYN_Flood |
| DDoS-TCP_Flood | TCP flood, 1 port | 200,000 | 61 B | PSHACK、RSTFIN |
| DoS-TCP_Flood | TCP flood, many ports | 200,000 | 66 B | — |
| DDoS-UDP_Flood | UDP flood, many ports | 200,000 | 65 B | — |
| DoS-UDP_Flood | UDP flood, 1 port | 200,000 | 62 B | — |
| Mirai-udpplain | UDP flood, medium | 200,000 | 552 B | — |
| DDoS-ICMP_Flood | ICMP flood | 200,000 | 64 B | — |
| Mirai-greip_flood | GRE flood | 200,000 | 570 B | Mirai-greeth_flood |
| DDoS-ACK_Fragmentation | TCP fragments, large | 200,000 | 899 B | — |
| DDoS-UDP_Fragmentation | UDP fragments, large | 200,000 | 913 B | — |
| DDoS-ICMP_Fragmentation | ICMP fragments, large | 200,000 | 985 B | — |

- 頁尾 `note`：`每種攻擊取一個檔的開頭 20 萬 packets；依流量型態歸類，同一類只量一個`

數字來源：同 p18（`I23_` 開頭）。

> **講稿注意（怎麼讀）**
> - 讀法同 p18。CICIoT2023 的 flood 種類多，而且差在 protocol、目的 port 集中或分散、有沒有分段，所以留了 15 個；Web 類、Brute Force、PingSweep 的檔很小（不到 20 萬 packets），DNS_Spoofing 0.97 GB；主要是實驗網路的背景流量，歸到 Benign 這一類（平均 packet 不同，**沒有量**）。
> - 「1 port」「many ports」是目的 port 集中或分散（例如 DoS-TCP_Flood 打了 2.6 萬個不同的 port，DDoS-TCP_Flood 99.7% 打同一個 port）。

## p21 — CICIoT2023 的處理速度
- 圖：`assets/fig_speed_ciciot.svg`（寬 100%）。三群：背景／傳輸／scan／HTTP flood 4 列、flood 8 列、fragment 3 列；實心方塊 = `full`、藍點 = `gw_corp`；右側 full time。
- 圖下三點：
  - `最慢：DDoS-HTTP_Flood 8.5 kpps`
  - `小 packet 的 ICMP／UDP flood 最快：162–275 kpps`
  - `gw_corp 差很多的只有 DDoS-UDP_Fragmentation：23.8 → 52.7`

數字來源：`assets/speed_numbers.tsv`（`I23_` 開頭）。`full` kpps：Benign 22.0、MITM-ArpSpoofing 68.1、Recon-PortScan 23.2、DDoS-HTTP_Flood 8.5、DDoS-SYN_Flood 18.9、DDoS-TCP_Flood 113.4、DoS-TCP_Flood 96.7、DDoS-UDP_Flood 204.7、DoS-UDP_Flood 162.2、Mirai-udpplain 68.6、DDoS-ICMP_Flood 275.1、Mirai-greip_flood 35.1、DDoS-ACK_Fragmentation 17.0、DDoS-UDP_Fragmentation 23.8、DDoS-ICMP_Fragmentation 47.6。`gw_corp` 比 `full` 快 2–122%（中位數 8%；用未四捨五入的 kpps 算）。

> **講稿注意（怎麼讀）**
> - 讀法同上。最慢一樣是 HTTP flood（8.5 kpps），和 CIC-IDS2017 的 DoS Hulk 一致。
> - 小 packet 的 ICMP、UDP flood 最快（160–275 kpps）：每個 packet 很小、沒有 TCP stream；SYN flood（18.9）和 TCP fragment（17.0）就慢很多（**推論**：TCP 的每個新連線、每個 fragment 都要建狀態或重組）。
> - `gw_corp` 只有 DDoS-UDP_Fragmentation 差很多（`full` 23.8、`gw_corp` 52.7 kpps），是哪些 rule 造成的**沒有查**；其他都只快 2–21%。
> - 這一章的結論：四個 dataset 用同一個版本量，Pi 上單一 thread 掛 `full`：有 HTTP flood 的兩個 dataset（CIC-IDS2017、CICIoT2023）最慢都是 HTTP flood（6.2、8.5 kpps）；IoT-23 最慢是 39-1 (IRCBot) 的 SSH scan（14.9）；CIC-DDoS2019 最慢是 Benign（16.0）。CIC 三個 dataset 的 Benign 約 15–22 kpps（IoT-23 的 benign 切片 38–45 kpps）。`gw_corp` 換不回多少速度，和 10/19 的結論一樣。

---

