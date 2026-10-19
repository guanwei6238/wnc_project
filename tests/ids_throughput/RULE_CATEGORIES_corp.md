# ET Open 規則分類：公司內網與外網之間的 security gateway 需要哪些類別（gw_corp）

> 由 `12_gateway_rule_corp.py` 產生；判斷表（`DECISIONS`）是**我的分析判斷，不是偵測價值的驗證**，可直接修改後重跑。
> 規則來源：ET Open 2026-10-11 快照，Suricata 版 52,606 條（類別依 `msg` 的 `ET <類別>` 前綴；舊版 GPL 規則依子類別歸類）。

## 判斷依據

1. **保護對象：** 公司內網（Windows／macOS 桌機、瀏覽器、手機、伺服器、網通與 IoT 設備），不依平台排除。
2. **位置：** 閘道器看得到內網↔外網的流量，所以「被感染主機對外掃描、連 C2」與「外部對內網的攻擊」都看得到。
3. **機制：** 長 IP 清單（TOR、CINS、DROP 等）改用 nftables 的 IP 集合做查詢，不放在 IDS 規則裡（Snort 3 會被它們拖垮，見 README 的 `sel` 實驗）。
4. **雜訊：** 資訊性、獵捕（HUNTING）、動態 DNS 的規則誤報多、與入侵無直接關係，不放本地；INFO、CHAT 只留 IRC 相關（殭屍網路常用 IRC 當 C2）；ET 已退役的規則不用。
5. **政策：** P2P、遊戲、遠端桌面、檔案分享等是公司政策問題，不代表入侵，不放本地。

最後的 IDS 可能自己實作（基於 Snort／Suricata），所以以**偵測面完整**為優先：只排除「放在 IDS 裡會拖垮效能」與「不代表入侵」的規則。

## 結果總覽

| 判斷 | 類別數 | 規則數（全部） | 放進 gw_corp 的規則數 |
|---|---|---|---|
| 本地需要 | 50 | 38,399 | 38,378 |
| 本地部分保留 | 2 | 4,585 | 12 |
| 改用 IP 黑名單（nftables） | 6 | 1,216 | 0 |
| 不放本地（交給雲端或不需要） | 15 | 8,406 | 0 |

- **gw_corp**：判斷為「本地需要」與「本地部分保留」的規則，共 38,511 條（含為了 flowbits 依賴補進來的 121 條）。兩引擎實際寫入檔案的條數：Suricata 38,511、Snort 3 38,086（Snort 版少的是 Snort 規則包沒有的 sid）。
- **改用 IP 黑名單**的 1,216 條規則，header 裡共約 25,924 個 IP／網段項目；建議用 nftables 的 IP 集合（set）在封包轉送路徑上直接比對，單一 IP 查詢約常數時間、CIDR 區間約對數成長（**此做法尚未實作與量測**）。

## 各類別的判斷

### 本地需要

| 類別 | 規則數 | 主要協定 | 長 IP 清單 | 保留 | 偵測什麼 | 理由 |
|---|---|---|---|---|---|---|
| MALWARE | 19,277 | dns 6806, tls 5143, http 4836 | 14 | 19,263 | 惡意程式活動與 C2 指標（DNS 網域、TLS、HTTP、IP） | 公司內網各種平台都可能被感染 |
| WEB_SPECIFIC_APPS | 6,074 | http 6008, http1 35, tcp 28 | 0 | 6,074 | 特定網頁應用程式的攻擊（CMS、企業軟體、設備管理介面） | 公司可能架設這些網頁應用 |
| PHISHING | 2,949 | http 2272, dns 413, tls 252 | 0 | 2,949 | 釣魚網站與憑證竊取 | 員工用瀏覽器上網，是公司常見的入侵起點 |
| EXPLOIT_KIT | 2,671 | dns 1104, tls 1052, http 496 | 0 | 2,671 | 瀏覽器漏洞利用套件 | 員工的瀏覽器 |
| EXPLOIT | 1,667 | http 1216, tcp 237, udp 79 | 5 | 1,662 | 對特定服務或設備的漏洞利用 | 公司有各種服務與設備 |
| MOBILE_MALWARE | 1,146 | dns 697, tls 244, http 185 | 0 | 1,146 | 手機惡意程式（Android／iOS） | 員工手機會連公司網路 |
| WEB_SERVER | 693 | http 661, tcp 18, http1 9 | 0 | 693 | 對網頁伺服器的攻擊 | 公司可能有對外或內部的網頁伺服器 |
| ADWARE_PUP | 679 | http 568, dns 40, tls 35 | 1 | 678 | 廣告軟體與不需要的程式 | 桌機上的不需要程式，常是更嚴重感染的前兆 |
| ATTACK_RESPONSE | 679 | tls 429, http 140, dns 62 | 0 | 679 | 攻擊成功後的回應（指令輸出、C2 框架憑證、下載回應） | 代表主機可能已被入侵 |
| WEB_CLIENT | 475 | http 418, tcp 32, dns 16 | 0 | 475 | 瀏覽器端攻擊 | 員工的瀏覽器 |
| GPL_NETBIOS | 356 | tcp 354, udp 2 | 0 | 356 | 舊版 GPL 規則（NETBIOS） | 比照 ET 的 NETBIOS 類別 |
| USER_AGENTS | 280 | http 277, http1 3 | 0 | 280 | 可疑 HTTP User-Agent | 多屬 Windows 惡意程式；公司有 Windows 桌機（需要明文 HTTP） |
| SCAN | 274 | http 185, tcp 48, udp 24 | 0 | 274 | 掃描與偵察工具（nmap、web scanner、服務探測） | 被感染主機對外掃描、外部對內網的偵察，閘道器都看得到 |
| GPL_SQL | 190 | tcp 188, udp 1, http 1 | 0 | 190 | 舊版 GPL 規則（SQL） | 比照 ET 的 SQL 類別 |
| ACTIVEX | 184 | http 161, tcp 23 | 0 | 184 | Windows ActiveX 元件漏洞 | 公司有 Windows 桌機 |
| JA3 | 102 | tls 102 | 0 | 102 | 惡意程式／工具的 TLS 指紋 | 只看 TLS 握手，加密流量下仍有效 |
| SCADA | 90 | http 33, tcp 21, tls 20 | 1 | 89 | 工控協定與設備（Modbus、S7、DNP3 等） | 公司可能有工控／樓宇設備 |
| GPL_RPC | 82 | tcp 44, udp 38 | 0 | 82 | 舊版 GPL 規則（RPC） | 比照 ET 的 RPC 類別 |
| DOS | 59 | udp 32, http 14, tcp 10 | 0 | 59 | DoS／DDoS 與放大攻擊（NTP、SSDP 等） | 內網主機被拿去發動攻擊，或公司對外服務被攻擊 |
| CURRENT_EVENTS | 54 | http 19, tcp 13, dns 9 | 0 | 54 | 近期事件（多為 Windows 攻擊工具） | 公司有 Windows 桌機 |
| GPL_FTP | 49 | ftp 36, tcp 13 | 0 | 49 | 舊版 GPL 規則（FTP） | 比照 ET 的 FTP 類別 |
| SHELLCODE | 43 | http 37, ip 4, udp 1 | 0 | 43 | shellcode 特徵（多為瀏覽器 heap spray） | 員工的瀏覽器與各種服務（需要明文內容） |
| GPL_EXPLOIT | 38 | http 20, tcp 17, http1 1 | 0 | 38 | 舊版 GPL 規則（EXPLOIT） | 比照 ET 的 EXPLOIT 類別 |
| NETBIOS | 36 | tcp 25, udp 11 | 0 | 36 | Windows SMB／NetBIOS 攻擊 | 公司內網常有 SMB |
| GPL_WEB_SERVER | 26 | http 26 | 0 | 26 | 舊版 GPL 規則（WEB_SERVER） | 比照 ET 的 WEB_SERVER 類別 |
| COINMINER | 25 | tcp 9, http 5, dns 5 | 0 | 25 | 挖礦程式連線（Stratum 協定、礦池網域） | 被入侵的主機常被拿來挖礦 |
| GPL_MISC | 21 | tcp 17, udp 2, http 2 | 0 | 21 | 舊版 GPL 規則（MISC） | 比照 ET 的 MISC 類別 |
| DNS | 20 | dns 18, udp 2 | 0 | 20 | DNS 異常（大量回應、sinkhole、可疑 TLD） | 與作業系統無關；DNS 通常不加密 |
| GPL_IMAP | 17 | tcp 17 | 0 | 17 | 舊版 GPL 規則（IMAP） | 比照 ET 的 IMAP 類別 |
| GPL_SHELLCODE | 14 | ip 13, tcp 1 | 0 | 14 | 舊版 GPL 規則（SHELLCODE） | 比照 ET 的 SHELLCODE 類別 |
| GPL_SCAN | 12 | icmp 7, tcp 3, http 2 | 0 | 12 | 舊版 GPL 規則（SCAN） | 比照 ET 的 SCAN 類別 |
| VOIP | 12 | tcp 6, udp 6 | 0 | 12 | SIP 洪水與探測 | 公司常有 VoIP 電話 |
| GPL_ATTACK_RESPONSE | 11 | http 9, udp 1, ip 1 | 0 | 11 | 舊版 GPL 規則（ATTACK_RESPONSE） | 比照 ET 的 ATTACK_RESPONSE 類別 |
| SMTP | 10 | smtp 7, tcp 3 | 0 | 10 | 郵件相關 | 公司有郵件服務 |
| FTP | 9 | tcp 7, ftp 1, tcp-pkt 1 | 0 | 9 | FTP 服務攻擊 | 公司與 NAS 常開 FTP |
| GPL_POP3 | 9 | tcp 9 | 0 | 9 | 舊版 GPL 規則（POP3） | 比照 ET 的 POP3 類別 |
| SNMP | 8 | udp 7, tcp 1 | 0 | 8 | SNMP 未授權存取 | 網通設備常開 SNMP |
| GPL_SNMP | 8 | udp 6, tcp 2 | 0 | 8 | 舊版 GPL 規則（SNMP） | 比照 ET 的 SNMP 類別 |
| WORM | 8 | http 7, tcp 1 | 0 | 8 | 蠕蟲傳播（含 TheMoon 路由器蠕蟲） | 會在內網主機與設備間擴散 |
| GPL_SMTP | 7 | tcp 7 | 0 | 7 | 舊版 GPL 規則（SMTP） | 比照 ET 的 SMTP 類別 |
| TFTP | 7 | udp 7 | 0 | 7 | 對外 TFTP 傳輸 | 惡意程式常用 TFTP 下載 payload |
| GPL_DNS | 6 | udp 4, tcp 2 | 0 | 6 | 舊版 GPL 規則（DNS） | 比照 ET 的 DNS 類別 |
| GPL_TFTP | 6 | udp 6 | 0 | 6 | 舊版 GPL 規則（TFTP） | 比照 ET 的 TFTP 類別 |
| TELNET | 4 | tcp 4 | 0 | 4 | Telnet 暴力破解、Mirai 類 busybox 登入 | 網通與 IoT 設備最常見的入侵途徑 |
| GPL_TELNET | 4 | tcp 4 | 0 | 4 | 舊版 GPL 規則（TELNET） | 比照 ET 的 TELNET 類別 |
| GPL_VOIP | 4 | ip 3, udp 1 | 0 | 4 | 舊版 GPL 規則（VOIP） | 比照 ET 的 VOIP 類別 |
| RPC | 1 | tcp 1 | 0 | 1 | Windows DCERPC | 公司有 Windows 主機 |
| SQL | 1 | tcp 1 | 0 | 1 | 資料庫攻擊 | 公司可能有資料庫服務 |
| GPL_WEB_SPECIFIC_APPS | 1 | http 1 | 0 | 1 | 舊版 GPL 規則（WEB_SPECIFIC_APPS） | 比照 ET 的 WEB_SPECIFIC_APPS 類別 |
| GPL_WORM | 1 | udp 1 | 0 | 1 | 舊版 GPL 規則（WORM） | 比照 ET 的 WORM 類別 |

### 本地部分保留

| 類別 | 規則數 | 主要協定 | 長 IP 清單 | 保留 | 偵測什麼 | 理由 |
|---|---|---|---|---|---|---|
| INFO | 4,548 | tls 2176, dns 1304, http 779 | 1 | 3 | 資訊性事件（雲端服務、DoH、軟體更新等） | 本身不代表入侵、誤報多；只留 IRC 相關（殭屍網路常用 IRC 當 C2） |
| CHAT | 37 | tcp 30, http 7 | 0 | 9 | 即時通訊軟體 | 政策類；只留 IRC 相關（殭屍網路常用 IRC 當 C2） |

### 改用 IP 黑名單（nftables）

| 類別 | 規則數 | 主要協定 | 長 IP 清單 | 保留 | 偵測什麼 | 理由 |
|---|---|---|---|---|---|---|
| TOR | 803 | tcp 803 | 803 | 0 | 已知 TOR 節點 IP 清單 | 純 IP 比對；放在 IDS 規則會拖垮 Snort 3，改用 nftables IP 集合 |
| CINS | 299 | ip 299 | 298 | 0 | CINS 惡名 IP 清單 | 同上 |
| DROP | 68 | ip 68 | 68 | 0 | Spamhaus DROP 網段清單 | 同上 |
| THREATVIEW | 22 | ip 22 | 21 | 0 | Threatview.io C2 IP 清單 | 同上 |
| COMPROMISED | 19 | ip 19 | 19 | 0 | 已知被入侵主機 IP 清單 | 同上 |
| CNC | 5 | ip 5 | 0 | 0 | Feodo Tracker 回報的 C2 IP（銀行木馬） | 純 IP 比對；放進 IP 黑名單 |

### 不放本地（交給雲端或不需要）

| 類別 | 規則數 | 主要協定 | 長 IP 清單 | 保留 | 偵測什麼 | 理由 |
|---|---|---|---|---|---|---|
| DYN_DNS | 6,096 | dns 3051, http 3042, tls 2 | 0 | 0 | 查詢動態 DNS 網域 | 惡意程式常用，但很多設備也正常使用 DDNS，誤報高；交給雲端關聯分析 |
| HUNTING | 1,351 | http 658, tcp 563, dns 46 | 1 | 0 | 威脅獵捕用的可疑特徵 | ET 定位為獵捕用、雜訊多；適合雲端 |
| RETIRED | 408 | http 167, dns 88, http1 59 | 0 | 0 | ET 已退役的規則 | ET 自己已停用 |
| FILE_SHARING | 190 | dns 96, tls 87, tcp 3 | 0 | 0 | 檔案分享服務的網域 | 政策類，不代表入侵 |
| TA_ABUSED_SERVICES | 120 | dns 62, tls 58 | 0 | 0 | 常被濫用的正常服務網域 | 政策類，誤報多 |
| REMOTE_ACCESS | 86 | tls 32, dns 32, tcp 12 | 0 | 0 | 遠端桌面軟體（TeamViewer 等） | 政策類 |
| P2P | 80 | http 33, udp 25, tcp 20 | 0 | 0 | P2P 檔案分享 | 政策類 |
| GAMES | 23 | http 14, tcp 4, dns 4 | 0 | 0 | 線上遊戲 | 政策類 |
| GPL_CHAT | 17 | tcp 15, http 2 | 0 | 0 | 舊版 GPL 規則（CHAT） | 比照 ET 的雜訊／政策類，或只是 ping 指紋 |
| GPL_ICMP | 14 | icmp 14 | 0 | 0 | 舊版 GPL 規則（ICMP） | 比照 ET 的雜訊／政策類，或只是 ping 指紋 |
| GPL_RETIRED | 9 | tcp 9 | 0 | 0 | 舊版 GPL 規則（RETIRED） | 比照 ET 的雜訊／政策類，或只是 ping 指紋 |
| GPL_INFO | 5 | tcp 2, http1 2, http 1 | 0 | 0 | 舊版 GPL 規則（INFO） | 比照 ET 的雜訊／政策類，或只是 ping 指紋 |
| GPL_P2P | 5 | tcp 4, http 1 | 0 | 0 | 舊版 GPL 規則（P2P） | 比照 ET 的雜訊／政策類，或只是 ping 指紋 |
| INAPPROPRIATE | 1 | http 1 | 0 | 0 | 不當內容 | 政策類 |
| GPL_REMOTE_ACCESS | 1 | udp 1 | 0 | 0 | 舊版 GPL 規則（REMOTE_ACCESS） | 比照 ET 的雜訊／政策類，或只是 ping 指紋 |

## 限制

- 判斷只依 ET 的類別（INFO、CHAT 另用 msg 篩 IRC），沒有用 `attack_target`／`affected_product` 這些標註不完整的 metadata。
- 判斷沒有經過偵測率驗證；需要日後用標籤可靠的場景量偵測率，或請領域專家檢查。
- 「不放本地」不代表沒有價值，而是建議交給雲端 IDS；本實驗沒有量雲端那一側。
