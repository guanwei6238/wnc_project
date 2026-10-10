# 事實查證：RFC 9411 與測試工具（2026-10-03）

## RFC 9411
- 2023/03，Informational，IETF BMWG，Obsoletes RFC 3511；作者 Balarajah、Rossenhoevel（EANTC）、Monkman（NetSecOPEN）；致謝 NetSecOPEN 成員
- 範圍：inline 模式的 next-generation network security devices，原文以 NGFW、NGIPS 為例（Abstract "including"；Scope 寫 network security devices）；但 Table 2／3 安全功能清單只定義 NGFW 與 NGIPS 兩種；**明確排除依賴 ML／行為分析的功能（應停用）**；有 VNF 與 Appendix B 尺寸分級
- 測試架構：Option 1（RECOMMENDED）測試設備兩側分別模擬 client／server；TCP 須符合 RFC 9293（或 QUIC RFC 9000）、真實三向交握、FIN 關閉（MUST NOT RST）
  - 「必須是有狀態模擬、不能用 replay」是推論，不是原文
- 負載：Init(≥5s) → Ramp up → Sustain（RECOMMENDED ≥300s）→ Ramp down → Collection；KPI 只在 Sustain 量
- §4.2 Table 2/3：功能分 RECOMMENDED／OPTIONAL，RECOMMENDED 全部開啟；Inline MUST、Fail-Open MUST 關、logging MUST 開；偏差 MUST 寫進報告；§1 目的是 "fair and reasonable comparisons"
  - NGFW RECOMMENDED：TLS Inspection、IDS/IPS、Anti-Spyware、Anti-Virus、Anti-Botnet、Anti-Evasion、App ID
  - NGFW OPTIONAL：Web Filtering、DLP、DDoS Protection、Certificate Validation
- §4.2.1／Appendix A：≥500 個 CVE、10 年內、CVSS High(7–10)；RECOMMENDED 先做；KPI 為擋下／未擋下比例、背景流量影響（≤5% / 5–10% / >10%）；背景流量為 45% HTTP + 45% HTTPS 最大吞吐
- §7 九項：traffic mix throughput、HTTP CPS、HTTP throughput、HTTP latency、HTTP 併發連線、HTTPS CPS、HTTPS throughput、HTTPS latency、HTTPS 併發連線
- KPI §6.3：併發連線、CPS、TPS、TLS handshake rate、inspected throughput、TTFB、TTLB

## 替代方法
- RFC 2544（1999/03）：網路互連設備，以 frame 為單位（throughput、latency、frame loss、back-to-back）
- RFC 3511（2003/04）：防火牆效能；**不是無狀態**——已有併發 TCP、連線建立速率、HTTP 交易等；缺 TLS、IPS／App-ID 等 L7 功能、CVE 有效性
- RFC 9411 §1 自述：距 3511 已 18 年，防火牆從 ACL 演進到 IDS/IPS 與加密流量分析
- 開源實作：無獨立開源；商用 Spirent CyberFlood、Keysight/Ixia、VIAVI；TRex ASTF 有狀態 TCP/HTTP，但 TLS 尚未支援
- NetSecOPEN 有公開認證報告（Cisco、Fortinet、SonicWall 等），實驗室含 UNH-IOL、SE Labs、SecureIQ Lab；可比較的前提是相同設定

## 工具
- tcpreplay：原速／指定速率／line rate；"Replay is not a network stack"，不開 socket、不協商連線
- tcprewrite：--enet-smac/dmac、--pnat、--srcipmap/dstipmap、--portmap、--fixcsum；tcpprep：分 client/server 側；tcpliveplay：單一 TCP 串流對真實 server 重播（只限 TCP）
- Nping：TCP/UDP/ICMP/ARP、--rate；hping3 最後 commit 2014-12，實質未維護
- SlowHTTPTest：slow headers、slow body(RUDY)、slow read、Range(Apache Killer)
- Scapy：Python 封包產生／解析
- Suricata -r：pcap 離線模式
- ET Open LICENSE：GPLv2 + BSD 混合

## RFC 9411 架構參數（2026-10-04 補查，原文 rfc9411.txt）
- §4 測試必須在隔離環境（RFC 6815）
- §4.1 Testbed：Option 1（RECOMMENDED）兩側 Test Equipment（Clients／Servers + 可選 Emulated Router），盡量不放外部 switch/router；Option 2 用 aggregation switch/router
- §4.2 DUT：Inline MUST；Fail-Open MUST 關；RECOMMENDED 功能全開（沒開 MUST 報告原因）；logging MUST 開、SHOULD 以 flow（五元組）記錄；地理過濾 SHOULD；App ID MUST；所有 §7 測試用同一份設定；設定摘要 MUST 公開
- §4.2 Table 4 ACL（由上而下）：block L7／L4／L3 = XS 5／25／25、S 10／50／50、M 20／100／100、L 50／250／250；之後 allow 規則；ACL MUST NOT 擋測試流量
- Appendix B 分級：XS ≤ 1 Gbit/s、S 1–5、M 5–10、L > 10 Gbit/s
- §4.3.1.1 Client TCP：MSS 1460（v4）／1440（v6）；初始 window 65535；initcwnd ≤ 10 MSS；delayed ACK ≤ 200 ms；重試 ≤ 3；來源 port 1024–65535；三向交握、FIN 關閉
- §4.3.1.3 Client IP 數 = 目標吞吐 ÷ 每 IP 平均吞吐；IPv4／IPv6 五種比例（100/0、80/20、50/50、20/80、0/100）；DSCP = DF
- §4.3.1.4 瀏覽器：HTTP/1.1 以上；TLS ≥ 1.2；每條連線完整 handshake、session reuse／resumption MUST 關；TLS 1.2 建議 4 組 cipher（ECDHE-ECDSA/RSA AES128/256-GCM）
- §4.3.2 Server：TCP 同 client；HTTP 80、HTTPS 443；IPv4/IPv6 比例同 client；cipher 同 client
- §4.3.3 client 掃過 server IP 空間形成 balanced mesh
- §4.3.4 負載：Init（≥ 5 s，不量測）→ Ramp up（不量測）→ Sustain（≥ 300 s RECOMMENDED，取樣 < 2 s，只在此量測）→ Ramp down → Collection
- §5 Reference test（MUST 在 §7 之前）：不放 DUT 或 DUT 只做 fast forwarding，確認 testbed 不是瓶頸、記錄環境本身的 loss／latency
- §7.3 HTTP throughput：每條連線 10 個請求；物件 1／16／64／256 KB + Table 5 混合；初始吞吐 = 目標的 10%
- 專案對應（只放講稿）：docker/gw.nft 的 `queue flags bypass` = 程式沒跑時放行 = Fail-Open → 跑 RFC 9411 時要拿掉；Pi 屬 XS 級

## NetSecOPEN 實際認證報告（2026-10-04 查）
- 標題：NetSecOPEN Certification — Network Security Product Performance Testing — Cisco Secure Firewall 1220CX
- 測試實驗室：University of New Hampshire InterOperability Lab（UNH-IOL），2025 年 8 月，Durham, NH
- 工具：Keysight PerfectStorm One（BreakingPoint 11.0）負責 traffic mix 與安全有效性；Spirent CyberFlood C100-S3 負責 HTTP(S) 效能
- 報告 Created: September 2025（測試在 2025 年 8 月）
- 安全有效性 Detection Rate（"performed without sending legitimate user traffic"）：5,388 個中擋下 5,369 個（約 99.65%）
  - 公開漏洞 1,380/1,380；私有漏洞 180/180；惡意程式 3,809→3,790（99.5%）；規避手法 19/19
- 公開 CVE 清單由 NetSecOPEN 依 RFC 9411 §4.2.1 挑選、廠商事先知道；私有清單廠商事先不知道（用意未寫明，屬推論）
- 負載下：兩輪，Healthcare mix 約 94.5%、Education mix 約 94% 最大 inspected throughput，每輪 50 個公開 CVE，全部擋下
- 與 RFC 的關係（第四輪驗證修正）：做法不同、範圍更廣，**不是全面更嚴格**。範圍更廣：malware、evasion、私有清單。但 5,388 個攻擊在無背景流量下測（RFC A.6.2 要求在背景流量下送），負載下只有 50 個；背景基準不同（traffic mix 94% vs RFC HTTP/HTTPS 64 KB 各 45%），不能比大小；未說明是否送加密版本
- 來源：https://www.netsecopen.org/_files/ugd/914193_96dabf1eec4a42f1935d442d99011004.pdf

## 參考文獻書目（Crossref／DataCite 核對）
- RFC 9411：B. Balarajah, C. Rossenhoevel, B. Monkman, 2023-03, doi:10.17487/RFC9411
- RFC 3511：B. Hickman, D. Newman, S. Tadjudin, T. Martin, 2003-04, doi:10.17487/RFC3511
- RFC 2544：S. Bradner, J. McQuaid, 1999-03, doi:10.17487/RFC2544
- IoT-23：S. Garcia, A. Parmisano, M. J. Erquiaga, Zenodo v1.0.0, 2020, doi:10.5281/zenodo.4743746（DataCite）
- CIC-IDS2017：I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, ICISSP 2018, pp. 108–116, doi:10.5220/0006639801080116
- CIC-DDoS2019：I. Sharafaldin, A. H. Lashkari, S. Hakak, A. A. Ghorbani, ICCST 2019, pp. 1–8, doi:10.1109/CCST.2019.8888419
- CICIoT2023：E. C. P. Neto, S. Dadkhah, R. Ferreira, A. Zohourian, R. Lu, A. A. Ghorbani, Sensors 23(13):5941, 2023, doi:10.3390/s23135941
- Engelen：G. Engelen, V. Rimmer, W. Joosen, IEEE SPW 2021, pp. 7–12, doi:10.1109/SPW53761.2021.00009
- 工具網址（HTTP 200 確認）：tcpreplay.appneta.com、nmap.org（含 /nping/）、github.com/antirez/hping、github.com/shekyan/slowhttptest、scapy.net
