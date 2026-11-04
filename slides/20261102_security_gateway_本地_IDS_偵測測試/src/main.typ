#import "../../template.typ": *

#show: slides.with(
  title: "Security Gateway 本地 IDS 偵測測試",
  date: "2026-11-02",
)

// ---- 本報告用的小工具 ----
#let small-tbl(size: 0.85em, body) = text(size: size, body)
#let summary(size: 0.85em, ..cells) = text(size: size, grid(
  columns: (auto, auto, 3em, auto, auto),
  align: left,
  column-gutter: 0.8em,
  row-gutter: 0.65em,
  ..cells.pos().enumerate().map(((i, c)) => if calc.rem(i, 5) == 0 or calc.rem(i, 5) == 3 { strong(c) } else { c }),
))

#title-slide

== 大綱

#v(1.2em)
#align(left)[
  #block(inset: (left: 12%))[
    #set text(size: 1.2em)
    #set par(leading: 0.6em)
    #set enum(spacing: 1.5em)
    #set align(left)
    + Dataset 與對齊
    + 偵測測試設定
    + 偵測結果
    + 結論與下一步
  ]
]

// =====================================================================
= Dataset 對齊

== 對齊結果

#v(1fr)
#align(center)[
  #small-tbl(size: 1.05em)[
    #set table(inset: (x: 14pt, y: 11pt))
    #tbl(
      columns: (auto, auto, auto, auto, auto),
      align: (left + horizon, right + horizon, left + horizon, right + horizon, right + horizon),
      [Dataset], [測試範圍 \ （pcap）], [label], [flow \ alignment], [packet \ coverage],
      [IoT-23], [62.9 GB], [每條 flow], [98.87%], [96.42%],
      [CIC-IDS2017], [52.4 GB], [每條 flow], [99.94%], [99.26%],
      [CIC-DDoS2019], [192.7 GB], [每條 flow], [99.93%], [99.98%],
      [CICIoT2023], [587.3 GB], [每個檔], [—], [—],
    )
  ]
]

#v(1.4em)
#text(size: 1em)[
  - 逐條 flow 標 label 的三個 dataset：label 幾乎都對得回 packet
  - CICIoT2023：整個檔的 flow 都算該檔的攻擊，沒有逐條的 label 可對
]

#v(1.4fr)

// =====================================================================
= 偵測測試設定

== 實驗設定

#v(0.6em)
#punch[問題：流量送進本地 IDS，是否偵測得出來]

#v(1.2em)
#align(center)[
  #small-tbl(size: 0.95em)[
    #set table(inset: (x: 12pt, y: 9pt))
    #tbl(
      columns: (auto, auto),
      align: (left + horizon, left + horizon),
      [項目], [設定],
      [Engine], [Suricata 8.0.7],
      [Rules], [ET Open 2026-10-30],
      [讀法], [offline，engine 直接讀 pcap],
    )
  ]
]

#v(1fr)

== 偵測怎麼算

#v(1fr)
#align(center)[
  #diagram(
    spacing: (3em, 1em),
    node-stroke: none,
    boxnode((0, 0), [alert (eve.json)], color: c-muted, width: 5.2cm),
    boxnode((1, 0), [flow (5-tuple + time)], color: c-muted, width: 6.2cm),
    boxnode((2, 0), [label], color: c-good, width: 4cm),
    edge((0, 0), (1, 0), "-|>", stroke: 1pt + c-muted),
    edge((1, 0), (2, 0), "-|>", stroke: 1pt + c-muted),
  )
]

#v(1.6em)
#align(center)[
  #small-tbl(size: 0.9em)[
    #set table(inset: (x: 12pt, y: 11pt))
    #tbl(
      columns: (auto, auto),
      align: (left + horizon, left + horizon),
      [指標], [定義],
      [有 alert 的 flow], [該 label 的 flow 裡，有任何 alert 的],
      [rule 對得上的 flow], [有 alert，且觸發的 rule 描述的就是這種攻擊],
      [判斷（每種攻擊）], [#yes 有 rule 對得上的 flow；#partly 有 alert 但都對不上；#no 沒有 alert],
      [誤報], [Benign flow 裡有 alert 的],
    )
  ]
]

#v(1fr)


// =====================================================================
= 偵測結果

== IoT-23

#v(0.2em)
#align(center)[#block[
  #set align(left)
  #small-tbl(size: 0.78em)[
    #set table(inset: (x: 6pt, y: 6.5pt))
    #tbl(
      columns: (auto, auto, auto, auto, auto, auto),
      align: (left + horizon, right + horizon, right + horizon, right + horizon, center + horizon, left + horizon),
      [攻擊], [flows], [有 alert \ 的 flow], [rule 對得上 \ 的 flow], [判斷], [觸發的 rule],
      [PartOfAHorizontalPortScan], [213,852,924], [14,757,108], [14,757,091], [#yes], [SSH scan],
      [C&C], [21,995], [4,165], [1,238], [#yes], [C&C checkin],
      [FileDownload 類（3 種）], [82], [77], [77], [#yes], [ELF 下載],
      [Okiru], [60,990,708], [34], [0], [#partly], [IP 清單（Spamhaus DROP）],
      [Attack], [9,398], [1,389], [0], [#partly], [SSH scan],
      [DDoS 等 8 種], [19,574,148], [0], [0], [#no], [—],
      [Benign], [30,860,691], [2,837], [—], [—], [SSH scan、IRC、BitTorrent],
    )
  ]
  #v(0.9em)
  #summary(
    [malicious flow], [2.94 億條（15 種攻擊）], [], [判斷], [#yes 5 種、#partly 2 種、#no 8 種],
    [有 alert], [1,476 萬條（5.01%）], [], [誤報], [Benign 3,086 萬條裡 2,837 條（0.009%）],
    [rule 對得上], [1,476 萬條（5.01%）], [], [], [],
  )
]]

#v(1fr)

== CIC-IDS2017

#v(-0.3em)
#align(center)[#block[
  #set align(left)
  #small-tbl(size: 0.72em)[
    #set table(inset: (x: 8pt, y: 4pt))
    #tbl(
      columns: (auto, auto, auto, auto, auto, auto),
      align: (left + horizon, right + horizon, right + horizon, right + horizon, center + horizon, left + horizon),
      [攻擊], [flows], [有 alert \ 的 flow], [rule 對得上 \ 的 flow], [判斷], [觸發的 rule],
      [Web Attack – XSS], [18], [18], [18], [#yes], [XSS],
      [Web Attack – SQL Injection], [13], [9], [9], [#yes], [SQLi],
      [Infiltration], [36], [15], [15], [#yes], [cmd.exe、reverse shell],
      [FTP-Patator], [3,972], [1,553], [1,553], [#yes], [FTP brute force],
      [Heartbleed], [11], [1], [1], [#yes], [Heartbleed],
      [Infiltration – Portscan], [71,767], [111], [105], [#yes], [Nmap UA、SCAN],
      [Portscan], [159,064], [185], [175], [#yes], [SCAN（資料庫 port 等）],
      [DoS Slowhttptest], [1,740], [4], [4], [#yes], [DoS tool],
      [DDoS（LOIC）], [95,144], [20], [20], [#yes], [DDoS tool],
      [SSH-Patator], [2,961], [31], [0], [#partly], [SSH scan],
      [DoS Hulk 等 5 種], [170,703], [0], [0], [#no], [—],
      [Benign], [1,581,058], [10,293], [—], [—], [JA3 Adware、DNS TLD],
    )
  ]
  #v(0.6em)
  #summary(size: 0.75em,
    [malicious flow], [50.5 萬條（15 種攻擊）], [], [判斷], [#yes 9 種、#partly 1 種、#no 5 種],
    [有 alert], [1,947 條（0.39%）], [], [誤報], [Benign 158 萬條裡 10,293 條（0.65%）],
    [rule 對得上], [1,900 條（0.38%）], [], [], [],
  )
]]

#v(1fr)

== CIC-DDoS2019

#v(0.5em)
#align(center)[#block[
  #set align(left)
  #small-tbl(size: 0.8em)[
    #set table(inset: (x: 7pt, y: 10pt))
    #tbl(
      columns: (auto, auto, auto, auto, auto, auto),
      align: (left + horizon, right + horizon, right + horizon, right + horizon, center + horizon, left + horizon),
      [攻擊], [flows], [有 alert \ 的 flow], [rule 對得上 \ 的 flow], [判斷], [觸發的 rule],
      [MSSQL（03-11）], [5,787,453], [12], [7], [#yes], [MC-SQLR],
      [DrDoS_NTP（01-12）], [1,202,642], [190], [3], [#yes], [NTP MON_LIST],
      [DrDoS_SNMP（01-12）], [5,159,870], [210], [0], [#partly], [SNMP `public`],
      [其他 16 項], [57,685,449], [1,166], [0], [#partly], [ping、SSH scan、資料庫 port scan],
      [Benign], [109,424], [333], [—], [—], [SSH scan],
    )
  ]
  #v(1.2em)
  #summary(
    [malicious flow], [6,984 萬條（19 項）], [], [判斷], [#yes 2 項、#partly 17 項、#no 0 項],
    [有 alert], [1,578 條（0.002%）], [], [誤報], [Benign 10.9 萬條裡 333 條（0.30%）],
    [rule 對得上], [10 條（0.00001%）], [], [], [],
  )
]]

#v(1fr)

== CICIoT2023

#v(0.2em)
#align(center)[#block[
  #set align(left)
  #small-tbl(size: 0.74em)[
    #set table(inset: (x: 5pt, y: 4.5pt))
    #tbl(
      columns: (auto, auto, auto, auto, auto, auto),
      align: (left + horizon, right + horizon, right + horizon, right + horizon, center + horizon, left + horizon),
      [攻擊], [flows], [有 alert \ 的 flow], [rule 對得上 \ 的 flow], [判斷], [觸發的 rule],
      [Web-based（6 種）], [20,069], [410], [115], [#yes], [BeEF、SQLi、XSS、/etc/passwd],
      [Brute Force], [7,313], [248], [5], [#yes], [LibSSH brute force],
      [Recon（4 種）], [1,476,827], [6,822], [1,847], [#yes], [Nmap OS／NSE、SCAN],
      [Recon-PingSweep], [1,829], [11], [0], [#partly], [UPnP NOTIFY、ICMP PING],
      [DDoS（12 種）], [746,342,689], [17,701], [0], [#partly], [UPnP NOTIFY、ICMP PING],
      [DoS（4 種）], [14,198,947], [6,515], [0], [#partly], [UPnP NOTIFY、ICMP PING],
      [Mirai（3 種）], [169,315,173], [4,935], [0], [#partly], [UPnP NOTIFY、ICMP PING、HUNTING port 53],
      [Spoofing（2 種）], [160,726], [1,958], [0], [#partly], [UPnP NOTIFY、ICMP PING],
      [Benign], [345,984], [5,157], [—], [—], [UPnP NOTIFY、ICMP PING],
    )
  ]
  #v(0.8em)
  #summary(
    [malicious flow], [9.32 億條（33 種攻擊）], [], [判斷], [#yes 11 種、#partly 22 種、#no 0 種],
    [有 alert], [38,600 條（0.004%）], [], [誤報], [Benign 34.6 萬條裡 5,157 條（1.49%）],
    [rule 對得上], [1,967 條（0.0002%）], [], [], [],
  )
]]

#v(1fr)

== 偵測總表

#v(1fr)
#align(center)[
  #small-tbl(size: 0.82em)[
    #set table(inset: (x: 9pt, y: 12pt))
    #tbl(
      columns: (auto, auto, auto, auto, auto, auto),
      align: (left + horizon, right + horizon, right + horizon, right + horizon, right + horizon, right + horizon),
      [Dataset], [malicious \ flows], [有 alert \ 的 flow], [rule 對得上 \ 的 flow], [rule 對得上 \ 的攻擊種類], [誤報],
      [IoT-23], [2.94 億], [5.01%], [5.01%], [5／15], [0.009%],
      [CIC-IDS2017], [50.5 萬], [0.39%], [0.38%], [9／15], [0.65%],
      [CIC-DDoS2019], [6,984 萬], [0.002%], [0.00001%], [2／19], [0.30%],
      [CICIoT2023], [9.32 億], [0.004%], [0.0002%], [11／33], [1.49%],
    )
  ]
]

#v(1.2em)
#text(size: 0.9em)[rule 對得上的 flow 都很低；rule 對得上的攻擊，大多是有 payload 特徵的]

#v(1.4fr)

// =====================================================================
= 結論與下一步

== 結論

#v(0.4em)
#align(center)[
  #small-tbl(size: 0.82em)[
    #set table(inset: (x: 8pt, y: 11pt))
    #tbl(
      columns: (auto, auto, auto),
      align: (left + horizon, left + horizon, center + horizon),
      [攻擊型態], [例子], [偵測],
      [payload 有特徵], [Web 攻擊、exploit、ELF 下載、C&C checkin、FTP 暴力破解], [#yes 大多],
      [沒有內容特徵的大量流量], [SYN scan、TCP／UDP flood、反射式 DDoS、HTTP DoS], [#partly／#no 大多],
    )
  ]
]

#v(0.9em)
#punch[malicious flow 大多屬於第二種 → 本地 rule 大多抓不到]

#v(0.6em)
#align(center)[
  #set par(leading: 0.8em)
  #text(size: 0.85em)[例外：SSH 等少數 port 有只看 header 的 scan rule \
  第二種要靠 flow 層級的統計（速率、連線對象數）]
]

== 下一步

#v(1fr)
#align(center)[
  #text(size: 1.2em)[*預計：inline 測試*]
  #v(0.8em)
  #text(size: 1em)[比較自己開發的框架與直接使用 Suricata 的處理速度]
]
#v(1.4fr)

== References

#set text(size: 0.68em)
#set par(justify: false, leading: 0.45em)
// 每筆兩行：名稱一行、網址一行（避免網址在中間被折斷）
#let webref(name, url) = block(spacing: 0pt)[
  #name \
  #text(font: "Noto Sans Mono CJK TC", size: 0.78em, link(url))
]
#grid(
  columns: (1fr, 1.1fr), column-gutter: 1.5em, align: top,
  stack(spacing: 0.6em,
    webref([IoT-23], "https://www.stratosphereips.org/datasets-iot23"),
    webref([CIC-IDS2017], "https://www.unb.ca/cic/datasets/ids-2017.html"),
    webref([CIC-IDS2017 修正版（CNS 2022）], "https://intrusion-detection.distrinet-research.be/CNS2022/"),
    webref([Engelen et al., WTMC 2021], "https://intrusion-detection.distrinet-research.be/WTMC2021/"),
    webref([CIC-DDoS2019], "https://www.unb.ca/cic/datasets/ddos-2019.html"),
  ),
  stack(spacing: 0.6em,
    webref([CICIoT2023], "https://www.unb.ca/cic/datasets/iotdataset-2023.html"),
    webref([ET Open rules], "https://rules.emergingthreats.net/open/"),
    webref([Suricata 8.0 Rule Thresholding], "https://docs.suricata.io/en/suricata-8.0.7/rules/thresholding.html"),
    webref([Hugging Face 鏡像], "https://huggingface.co/bencorn"),
  ),
)

#focus-slide[Q&A]
