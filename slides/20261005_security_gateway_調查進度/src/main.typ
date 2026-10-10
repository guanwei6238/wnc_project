#import "../../template.typ": *

// 截圖開關：把使用者提供的 assets/align.png、assets/replay.png 放好之後改成 true。
// Typst 沒有「檔案是否存在」的檢查，所以用手動開關；false 時顯示灰色虛線佔位框。
#let has-shots = true

#show: slides.with(
  title: "Security Gateway 調查進度",
  date: "2026-10-05",
)

// ---- 本報告用的小工具 ----
// w 有給就用寬度縮放（圖比較寬時用，避免超出欄位被裁掉），否則用高度
#let shot(path, label, h: 7cm, w: none) = {
  if has-shots {
    align(center, if w == none { image(path, height: h) } else { image(path, width: w) })
  } else {
    align(center, block(
      width: 100%, height: h, radius: 4pt,
      stroke: (paint: c-line, dash: "dashed", thickness: 1.2pt),
      fill: luma(245),
      align(center + horizon, text(fill: c-muted, size: 0.9em)[#label]),
    ))
  }
}
#let note(body) = text(size: 0.65em, fill: c-muted, body)
#let pbox(body, color: c-muted) = block(
  inset: (x: 10pt, y: 7pt), radius: 3pt,
  fill: tint(color, amount: 90%), stroke: 1pt + color,
  text(size: 0.85em, body),
)
// 等寬的指標框（第 5 頁用）
#let mbox(color, body) = block(
  width: 100%, inset: (x: 10pt, y: 8pt), radius: 3pt,
  fill: tint(color, amount: 90%), stroke: 1pt + color,
  align(center, text(size: 0.85em, body)),
)
#let big(n, cap) = block(width: 100%, inset: (y: 4pt))[
  #text(size: 1.7em, weight: "bold", fill: c-stage3)[#n]\
  #text(size: 0.8em)[#cap]
]

#title-slide

== 大綱

#v(1.2em)
#align(left)[
  #block(inset: (left: 12%))[
    #set text(size: 1.2em)
    #set par(leading: 1.4em)
    #set align(left)
    + 測試方法
    + Datasets 可復現性
    + 測試工具
  ]
]

= 測試方法

== RFC 9411

#v(0.3em)
#align(center)[
  #diagram(
    spacing: (4em, 2.4em),
    node-stroke: none,
    boxnode((0, 0), [Client Emulator], color: c-muted, width: 4cm),
    boxnode((1, 0), [DUT\ (Security Gateway)], color: c-stage3, width: 4.4cm),
    boxnode((2, 0), [Server Emulator], color: c-muted, width: 4cm),
    edge((0, 0), (1, 0), "-|>", stroke: 1pt + c-muted),
    edge((1, 0), (2, 0), "-|>", stroke: 1pt + c-muted),
    // RFC 9411 Figure 1：兩側各一台 Test Equipment，DUT 在兩框之間、不在框內
    groupnode((0, 0), [], enclose: ((0, 0),), color: c-line),
    groupnode((2, 0), [], enclose: ((2, 0),), color: c-line),
    node((0, 0.62), text(size: 0.7em, fill: c-muted)[Test Equipment], inset: 0pt),
    node((2, 0.62), text(size: 0.7em, fill: c-muted)[Test Equipment], inset: 0pt),
  )
]

#v(0.6em)
#align(center)[
  #block(width: 78%)[
    #tbl(
      columns: (auto, 1fr),
      [項目], [內容],
      [發布], [IETF，2023],
      [對象], [Inline network security device（例：NGFW／NGIPS）],
      [量測], [效能（Throughput、Latency 等）],
    )
  ]
]

== RFC 9411：測試流程

#v(0.2em)
#align(center)[
  #diagram(
    spacing: (4em, 1em),
    node-stroke: none,
    boxnode((0, 0), [1\. Reference test\ (no DUT)], color: c-muted, width: 8cm),
    boxnode((1, 0), [2\. Benchmark\ with DUT], color: c-stage3, width: 6cm),
    edge((0, 0), (1, 0), "-|>", stroke: 1pt + c-muted),
  )
]

#v(0.4em)
#align(center)[
  #cetz.canvas(length: 1cm, {
    import cetz.draw: *
    let ly = 3.2 // Sustain 高度
    let lw = 2.4pt
    // 座標軸
    line((0, 0), (0, ly + 0.8), stroke: 1pt + c-muted, mark: (end: "stealth", fill: c-muted))
    line((0, 0), (25, 0), stroke: 1pt + c-muted, mark: (end: "stealth", fill: c-muted))
    content((-0.2, ly + 0.8), text(size: 0.7em, fill: c-muted)[load], anchor: "east")
    content((25.1, 0.0), text(size: 0.7em, fill: c-muted)[time], anchor: "west")
    // 各階段折線（Init / Ramp up / Sustain / Ramp down / Collection）
    line((0.5, 0.0), (3.5, 0.0), stroke: lw + c-muted)
    line((3.5, 0.0), (7.5, ly), stroke: lw + c-muted)
    line((7.5, ly), (16.5, ly), stroke: (paint: c-stage3, thickness: 3.6pt))
    line((16.5, ly), (20.5, 0.0), stroke: lw + c-muted)
    line((20.5, 0.0), (24.5, 0.0), stroke: lw + c-muted)
    // Sustain 標註
    content((12, ly + 0.6), text(size: 0.85em, weight: "bold", fill: c-stage3)[Sustain ≥ 300 s], anchor: "south")
    content((12, ly - 0.25), text(size: 0.75em, fill: c-stage3)[measure here], anchor: "north")
    // 階段名稱
    content((2.0, -0.2), text(size: 0.75em, fill: c-muted)[Init], anchor: "north")
    content((2.0, -0.85), text(size: 0.6em, fill: c-muted)[≥ 5 s], anchor: "north")
    content((5.5, -0.2), text(size: 0.75em, fill: c-muted)[Ramp up], anchor: "north")
    content((12, -0.2), text(size: 0.75em, weight: "bold", fill: c-stage3)[Sustain], anchor: "north")
    content((18.5, -0.2), text(size: 0.75em, fill: c-muted)[Ramp down], anchor: "north")
    content((22.8, -0.2), text(size: 0.75em, fill: c-muted)[Collection], anchor: "north")
  })
]

#v(1fr)
- 只在 #hl[Sustain] 段量測（取樣間隔 < 2 秒）
#v(0.3em)

== 為什麼選 RFC 9411

#v(0.3em)
#align(center)[
  #tbl(
    columns: (auto, auto, auto, auto, auto),
    align: center,
    [方法], [年份], [有狀態流量], [L7 安全功能], [適用對象],
    [RFC 2544], [1999], [#no], [#no], [Router／Switch],
    [RFC 3511], [2003], [#yes], [#no], [Firewall],
    [*RFC 9411*], [*2023*], [#yes], [#yes], [*Network security device*],
  )
]

== 後續測試規劃

#v(0.2em)
#align(center)[
  #diagram(
    spacing: (5em, 0.55em),
    node-stroke: none,
    boxnode((0, 1.5), [Dataset\ #text(size: 0.7em)[同一份、可復現]], color: c-stage3, width: 3.6cm),
    boxnode((1, 0), [Suricata], color: c-muted, width: 8cm),
    boxnode((1, 1), [Snort 3], color: c-muted, width: 8cm),
    boxnode((1, 2), [Gateway（本地）], color: c-lan, width: 8cm),
    boxnode((1, 3), [Gateway（本地 + 雲端）], color: c-cloud, width: 8cm),
    edge((0, 1.5), (1, 0), "-|>", stroke: 1pt + c-muted),
    edge((0, 1.5), (1, 1), "-|>", stroke: 1pt + c-muted),
    edge((0, 1.5), (1, 2), "-|>", stroke: 1pt + c-muted),
    edge((0, 1.5), (1, 3), "-|>", stroke: 1pt + c-muted),
  )
]

#v(0.5em)
#align(center)[
  #grid(
    columns: (6.5cm, 6.5cm), column-gutter: 1.5em,
    mbox(c-stage1)[*效能*\ Throughput\ Latency\ Packet loss],
    mbox(c-stage2)[*偵測*\ Detection rate\ False positive rate\ 送雲端比例],
  )
]

#v(1fr)
- 效能測試流程參考 RFC 9411（Reference test → Sustain）

= Datasets 可復現性

== 要復現需要什麼、做不做得到

#v(0.1em)
#align(center, text(size: 0.85em)[
  #tbl(
    columns: (auto, auto),
    [需要什麼], [出處],
    [1\. 拿得到同一份原始資料], [ACM Artifacts Available、Ring 2019],
    [2\. Label 能與原始流量對齊], [Engelen 2021],
  )
])

#v(0.7em)
#align(center, text(size: 0.82em)[
  #tbl(
    columns: (auto, auto, auto, auto),
    align: (left, left, left, left),
    [Dataset], [1\. 拿得到], [2\. 時間維度], [能復現嗎],
    [IoT-23], [#yes 有 DOI], [#yes 微秒], [#yes #hl[已驗證]],
    [CIC-IDS2017], [#partly 需登記、無 DOI], [#partly 分], [#partly 修正版、未實測],
    [CIC-DDoS2019], [#partly 需登記、無 DOI], [#yes 微秒], [#partly 未實測],
    [CICIoT2023], [#partly 需登記、無 DOI], [#no 無], [#no 對不到 flow],
  )
])

== IoT-23 實測：Label 對齊

#v(0.2em)
#grid(
  columns: (1.9fr, 1fr), gutter: 1.5em, align: horizon,
  shot("../assets/align.png", "截圖：02_align.py 輸出", h: 7.2cm, w: 100%),
  [
    #big[10,403][條 flow，#hl[100%] 對齊]
    #big[8,222][條 C&C，全部是 S0]
    #big[0][C&C packet 有 payload]
  ],
)

== IoT-23：能不能拿來測 gateway

#v(0.1em)
#align(center)[
  #diagram(
    spacing: (3em, 1em),
    node-stroke: none,
    boxnode((0, 0), [cli (tcpreplay)], color: c-lan, width: 4cm),
    boxnode((1, 0), [gw #text(size: 0.85em)[nft counter + tcpdump ×2]], color: c-muted, width: 7.4cm),
    boxnode((2, 0), [srv], color: c-wan, width: 2.4cm),
    edge((0, 0), (1, 0), "-|>", [LAN], label-size: 0.75em, stroke: 1pt + c-lan),
    edge((1, 0), (2, 0), "-|>", [WAN], label-size: 0.75em, stroke: 1pt + c-wan),
  )
]

#v(0.2em)
// 只放 C&C 案例的段落（從 assets/replay.png 裁切），完整輸出字太小；NTP 案例用講的
#shot("../assets/replay_cc.png", "截圖：03_replay.sh 輸出", h: 4.6cm, w: 50%)

#v(0.3em)
- Dataset 的 packet 改位址後可#hl[重播穿過 gateway]，處置結果可觀察、可重複
- 限制：這筆 C&C 樣本只有 SYN，目前只驗證到 IP／port 層級的處置

= 測試工具

== 六種候選工具

#v(0.2em)
#text(size: 0.85em)[
  #tbl(
    columns: (auto, auto, 1fr),
    [工具], [產生的流量], [可以測哪類規則],
    [Nping], [TCP／UDP／ICMP], [標頭欄位、TCP flags、速率門檻],
    [hping3], [自訂 TCP/IP], [同上（Nping 的備選）],
    [Scapy], [Python 自訂 packet], [規則邊界（只差一個欄位的命中／不命中）],
    [Nmap], [Port scan], [Scan detection],
    [SlowHTTPTest], [慢速 HTTP], [慢速連線、逾時],
    [Tcpreplay], [Replay PCAP], [已知攻擊樣本（dataset）],
  )
]

#v(1fr)
#note[都有 Debian trixie 官方套件，Docker lab 與 Pi 都能直接安裝]

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
    webref([RFC 9411], "https://www.rfc-editor.org/info/rfc9411/"),
    webref([RFC 3511], "https://www.rfc-editor.org/info/rfc3511/"),
    webref([RFC 2544], "https://www.rfc-editor.org/info/rfc2544/"),
    webref([IoT-23], "https://www.stratosphereips.org/datasets-iot23"),
    webref([CIC-IDS2017], "https://www.unb.ca/cic/datasets/ids-2017.html"),
    webref([CIC-DDoS2019], "https://www.unb.ca/cic/datasets/ddos-2019.html"),
    webref([CICIoT2023], "https://www.unb.ca/cic/datasets/iotdataset-2023.html"),
    webref([ACM Artifact Review and Badging], "https://www.acm.org/publications/policies/artifact-review-and-badging-current"),
    webref([Ring et al. 2019（NIDS dataset survey）], "https://arxiv.org/abs/1903.02460"),
  ),
  stack(spacing: 0.6em,
    webref([CIC-IDS2017 修正版（Engelen et al.）], "https://intrusion-detection.distrinet-research.be/WTMC2021/"),
    webref([CIC-IDS2017 修正版（Liu et al. 2022）], "https://intrusion-detection.distrinet-research.be/CNS2022/"),
    webref([CICFlowMeter issue \#69], "https://github.com/ahlashkari/CICFlowMeter/issues/69"),
    webref([Tcpreplay], "https://tcpreplay.appneta.com/"),
    webref([Nping], "https://nmap.org/nping/"),
    webref([hping3], "https://github.com/antirez/hping"),
    webref([SlowHTTPTest], "https://github.com/shekyan/slowhttptest"),
    webref([Scapy], "https://scapy.net/"),
  ),
)

#focus-slide[Q & A]
