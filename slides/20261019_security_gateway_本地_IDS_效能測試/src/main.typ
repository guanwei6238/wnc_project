#import "../../template.typ": *

#show: slides.with(
  title: "Security Gateway 本地 IDS 效能測試",
  date: "2026-10-19",
)

// ---- 本報告用的小工具 ----
// engine 配色（固定）：Suricata 藍、Snort 3 橘，圖與表格強調一致
#let c-su = rgb("#2a78d6")
#let c-sn = rgb("#eb6834")
#let su(body) = text(fill: c-su, weight: "bold", body)
#let sn(body) = text(fill: c-sn, weight: "bold", body)

#let note(body) = text(size: 0.65em, fill: c-muted, body)
#let big(n, cap) = block(width: 100%, inset: (y: 3pt))[
  #text(size: 1.6em, weight: "bold", fill: c-stage3)[#n]\
  #text(size: 0.8em)[#cap]
]
// 表格縮小字級用
#let small-tbl(size: 0.85em, body) = text(size: size, body)
// 比 boxnode 緊湊的方塊節點（inset 可調），用在內容多的架構圖
#let bnode(pos, body, color: c-muted, width: auto, inset: 6pt, ..args) = node(
  pos,
  align(center, text(size: 0.8em, body)),
  fill: tint(color, amount: 90%),
  stroke: 1pt + color,
  corner-radius: 3pt,
  inset: inset,
  width: width,
  ..args,
)

#title-slide

== 大綱

#v(1.2em)
#align(left)[
  #block(inset: (left: 12%))[
    #set text(size: 1.2em)
    #set par(leading: 0.6em)
    #set enum(spacing: 1.5em)
    #set align(left)
    + IoT-23 dataset 對齊
    + 完整 ET Open rules
    + Rule 篩選
    + 結論與下一步
  ]
]

// =====================================================================
= IoT-23 dataset 對齊

== 資料量與對齊結果

#grid(
  columns: (0.75fr, 1.55fr), column-gutter: 0.5em, align: horizon,
  [
    #big[23][個 scenario]
    #big[7.7 億][packets（770,313,789）]
    #big[3.25 億][labeled flows（325,309,946）]
    #big[98.87%][flow alignment]
  ],
  align(right, image("../assets/fig_align.svg", height: 10.2cm)),
)

== 哪些 scenario 不能直接用

#v(0.1em)
#align(center)[
  #diagram(
    spacing: (3.5em, 1em),
    node-stroke: none,
    boxnode((0, 0), [23 scenarios], color: c-muted, width: 5cm),
    boxnode((1, 0), [11 usable], color: c-good, width: 5cm),
    edge((0, 0), (1, 0), "-|>", stroke: 1pt + c-muted),
  )
]

#v(0.5em)
#small-tbl(size: 0.82em)[
  #tbl(
    columns: (auto, 1fr),
    [問題], [scenario],
    [conn.log 把 DDoS 記成 0 packet], [34-1 (Mirai)、60-1 (Gafgyt)],
    [conn.log 比 pcap 早結束], [52-1、49-1 (Mirai)],
    [非 IP packet 多], [#box[8-1 (Hakai)]、#box[20-1、21-1 (Torii)]、#box[Honeypot-7-1 (door lock)]],
    [flow alignment 低], [#box[Honeypot-4-1 (Philips HUE)]、#box[Honeypot-5-1 (Amazon Echo)]、#box[3-1 (Muhstik)]、#box[44-1 (Mirai)]],
  )
]

#v(1fr)
#note[
  表中只寫編號的（如 34-1）都是 Malware-x-x \
  篩選條件：flow alignment ≥ 99% 且 packet coverage ≥ 90%
]

== usable scenario 的流量組成

#grid(
  columns: (1.55fr, 1fr), column-gutter: 1em, align: horizon,
  image("../assets/fig_labels.svg", width: 100%),
  [
    #set text(size: 0.85em)
    - Malicious flow 幾乎都是內網 IoT 設備對外送 SYN：沒有回應、沒有 payload
    - scan 的 port：23／2323（Telnet）、22（SSH）、80／81／8080／8081、37215、52869
  ],
)

// =====================================================================
= 完整 ET Open rules

== 實驗設定

#punch[問題: 完整 ET Open rules 是否能直接掛在 Pi 上]

#v(0.4em)
#callout(kind: "info")[
  這次只量 IDS engine 的處理上限：engine 直接讀 pcap，*沒有走 cli → DUT → srv*
]

#v(0.9em)
#align(center)[
  #small-tbl(size: 0.9em)[
    #tbl(
      columns: (auto, auto),
      [項目], [設定],
      [Hardware], [Raspberry Pi 4（4 GB），1000 MHz],
      [Engine], [Suricata 7.0.10、Snort 3.12.2.0],
      [Rules], [ET Open 2026-10-11（約 5.2 萬）],
      [Traffic], [IoT-23 的 14 個 scenario],
    )
  ]
]

== 效能測試的 14 個 scenario

#v(0.1em)
#align(center)[
  #small-tbl(size: 0.82em)[
    #set table(inset: (x: 10pt, y: 4.2pt))
    #tbl(
      columns: (auto, auto, auto, auto, auto),
      align: (left, left, right, right, center),
      [scenario], [流量型態], [packets], [平均 packet], [usable],
      [17-1 (Kenjiro)], [SYN scan 8081/80], [200,000], [60 B], [#yes],
      [36-1 (Okiru)], [SYN probe 37215], [200,000], [60 B], [#yes],
      [48-1 (Mirai)], [SYN scan 23], [200,000], [85 B], [#yes],
      [39-1 (IRCBot)], [SYN scan 22], [200,000], [124 B], [#yes],
      [3-1 (Muhstik)], [SSH scan + IRC], [200,000], [98 B], [],
      [1-1 (Hide and Seek)], [multi-port + UDP], [200,000], [71 B], [#yes],
      [34-1 (Mirai)], [TCP/UDP mixed], [200,000], [602 B], [],
      [60-1 (Gafgyt)], [UDP flood, small], [200,000], [61 B], [],
      [44-1 (Mirai)], [UDP flood, large], [200,000], [1,360 B], [],
      [Honeypot-5-1 (Amazon Echo)], [TLS download], [200,000], [990 B], [],
      [Honeypot-7-1 (door lock)], [benign], [119,638], [261 B], [],
      [20-1 (Torii)], [C2 443], [50,156], [65 B], [],
      [42-1 (Trojan)], [file download], [24,484], [103 B], [#yes],
      [Honeypot-4-1 (Philips HUE)], [benign], [21,664], [196 B], [],
    )
  ]
]

== `full` 的處理速度

#v(-1em)
#align(center, image("../assets/fig_full14.svg", width: 100%))

#v(0em)
#text(size: 0.82em)[
  - Suricata：14 個 scenario 都跑得動，最慢 15.5 kpps
  - Snort 3：9 個 scan／flood scenario 不到 1 kpps
  - Snort 3 慢的原因是帶 IP 清單的 rule：\
    拿掉後 0.37 → 64.3 kpps(17-1)
]

== Memory：`full` 在 1／2／4 GB

#v(0.3em)
#align(center)[
  #small-tbl(size: 0.9em)[
    #tbl(
      columns: (auto, auto, auto, auto, auto),
      align: center,
      [Memory], [#su[Suricata] kpps], [#su[Suricata] RSS], [#sn[Snort 3] kpps], [#sn[Snort 3] RSS],
      [4 GB], [15.5], [1,240 MB], [0.39], [376 MB],
      [2 GB], [15.3], [1,240 MB], [0.38], [376 MB],
      [1 GB], [13.4], [719 MB], [0.39], [376 MB],
    )
  ]
]

#v(0.8em)
- 1 GB 時 Suricata 慢約 13%，Snort 3 不受影響

// =====================================================================
= Rule 篩選

== ET Open 的 rule category

#grid(
  columns: (1.5fr, 1fr), column-gutter: 1em, align: horizon,
  image("../assets/fig_etcats.svg", width: 100%),
  [
    #set text(size: 0.85em)
    - 52,606 條 rule、73 個 category
    - 最大的 MALWARE 就有 19,277 條；前 5 個 category 占 74%
    - 其他 58 個 category 合計只有 3,090 條（5.9%）
  ],
)

== `gw_corp`：本地 IDS 掛哪些 rule

#v(0.3em)
#align(center)[
  #small-tbl(size: 0.78em)[
    #set table(inset: (x: 8pt, y: 5.5pt))
    #tbl(
      columns: (auto, 2.4fr, 1fr, auto),
      align: (left + horizon, left + horizon, left + horizon, right + horizon),
      [], [第 9 頁的 category], [為什麼], [rules],
      [#yes 全部保留], [#box[MALWARE]、#box[WEB_SPECIFIC_APPS]、#box[PHISHING]、#box[EXPLOIT_KIT]、#box[EXPLOIT]、#box[MOBILE_MALWARE]、#box[WEB_SERVER]、#box[ADWARE_PUP]、#box[ATTACK_RESPONSE]、#box[WEB_CLIENT] #box[＋ 其他 40 個（SCAN、DOS、TELNET…）]], [和入侵直接相關], [38,399 → 38,399],
      [#partly 只留 IRC], [INFO ＋ CHAT], [IRC 常被當 C2；\ 其餘只是資訊], [4,585 → 12],
      [#no 不保留], [#box[DYN_DNS]、#box[HUNTING] #box[＋ 其他 1 個（TA_ABUSED_SERVICES）]], [官方說明：觸發\ 不代表攻擊], [7,567 → 0],
      [#no 不保留], [#box[RETIRED] #box[＋ 其他 11 個（P2P、REMOTE_ACCESS…）]], [辨識服務使用、\ 過時技術], [839 → 0],
      [#no 不保留], [TOR ＋ 其他 5 個（CINS、DROP…）], [IP blocklist], [1,216 → 0],
    )
  ]
]

== `gw_corp` 的處理速度

#v(-1.0em)
#align(center, image("../assets/fig_corp14.svg", width: 100%))

#v(-0.5em)
#text(size: 0.82em)[
  - Suricata：和 `full` 差不多
  - Snort 3：14 個 scenario 都 ≥ 11 kpps
]

== Memory：`gw_corp` 在 1／2／4 GB

#v(0.3em)
#align(center)[
  #small-tbl(size: 0.9em)[
    #tbl(
      columns: (auto, auto, auto, auto, auto),
      align: center,
      [Memory], [#su[Suricata] kpps], [#su[Suricata] RSS], [#sn[Snort 3] kpps], [#sn[Snort 3] RSS],
      [4 GB], [15.8], [977 MB], [20.0], [302 MB],
      [2 GB], [15.7], [977 MB], [20.0], [302 MB],
      [1 GB], [14.2], [749 MB], [20.0], [302 MB],
    )
  ]
]

#v(0.8em)
- 1 GB 時 Suricata 慢約 10%，Snort 3 不受影響

// =====================================================================
= 結論與下一步

== 結論與下一步

#v(0.3em)
#align(center)[
  #small-tbl(size: 0.9em)[
    #tbl(
      columns: (auto, auto, auto, auto, auto),
      align: (left + horizon, center + horizon, center + horizon, center + horizon, center + horizon),
      [kpps], [Min], [Median], [Mean], [Max],
      [#su[Suricata] `full`], [15.5], [36.4], [56.7], [176],
      [#su[Suricata] `gw_corp`], [15.8], [39.9], [59.8], [178],
      [#sn[Snort 3] `full`], [0.37], [0.81], [8.4], [80.8],
      [#sn[Snort 3] `gw_corp`], [11.4], [31.4], [43.7], [94.5],
    )
  ]
]

#v(0.6em)
→ *以 Suricata 為 base 實作能接雲端的 gateway*
#pad(left: 1.2em)[
  #set list(spacing: 0.6em)
  - 效能不被 rule 綁住，rule 可以照偵測需求挑
  - Suricata 在 10 個 scenario 比 Snort 3 快
]

== References

#set text(size: 0.68em)
#set par(justify: false, leading: 0.45em)
// 每筆兩行：名稱一行、網址一行（避免網址在中間被折斷）
#let webref(name, url) = block(spacing: 0pt)[
  #name \
  #text(font: "Noto Sans Mono CJK TC", size: 0.85em, link(url))
]
#grid(
  columns: (1fr, 1fr), column-gutter: 2em, align: top,
  stack(spacing: 0.6em,
    webref([IoT-23], "https://www.stratosphereips.org/datasets-iot23"),
    webref([IoT-23（Zenodo DOI）], "https://doi.org/10.5281/zenodo.4743746"),
    webref([Zeek：Invoking Zeek（checksum）], "https://docs.zeek.org/en/master/tutorial/invoking-zeek.html"),
    webref([ET Open rules], "https://rules.emergingthreats.net/open/"),
    webref([ET Signature Metadata], "https://community.emergingthreats.net/t/signature-metadata/96"),
    webref([Suricata 7.0.10 Tuning Considerations], "https://docs.suricata.io/en/suricata-7.0.10/performance/tuning-considerations.html"),
    webref([Suricata Rule Types（IP-only）], "https://docs.suricata.io/en/latest/rules/rule-types.html"),
    webref([Snort 3.12.2.0], "https://github.com/snort3/snort3/releases/tag/3.12.2.0"),
    webref([Talos：Snort performance and IP-only rules], "https://blog.talosintelligence.com/snort-performance-and-ip-only-rules/"),
  ),
  stack(spacing: 0.6em,
    webref([Raspberry Pi：Frequency management], "https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/computers/raspberry-pi/frequency-management.adoc"),
    webref([Raspberry Pi：total_mem], "https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/computers/config_txt/memory.adoc"),
    webref([CVE-2017-17215], "https://nvd.nist.gov/vuln/detail/CVE-2017-17215"),
    webref([CVE-2014-8361], "https://nvd.nist.gov/vuln/detail/CVE-2014-8361"),
    webref([Check Point：Okiru／Satori], "https://research.checkpoint.com/2017/good-zero-day-skiddie/"),
  ),
)

#focus-slide[Q&A]
