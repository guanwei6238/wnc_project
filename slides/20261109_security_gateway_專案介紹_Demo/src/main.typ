#import "../../template.typ": *

#show: slides.with(
  title: "Security Gateway 專案介紹 & Demo",
  date: "2026-11-09",
)

// template 的 show raw 把 inline code 固定成 0.82 × 全域字級（縮小字級的表格、圖的
// 節點裡也一樣），所以 inline code 一律用 m("...")，字級跟著所在位置走
#let m(s) = text(font: font-mono, size: 1em, s)

// ---- 本報告用的小工具 ----
#let small-tbl(size: 0.85em, body) = text(size: size, body)
#let note(body) = text(size: 0.65em, fill: c-muted, body)

// 實作狀態用框線表示：實線＝已實作、虛線＝還沒實作（planned: true）
#let sn(pos, body, color: c-muted, planned: false, size: 0.8em, width: auto, inset: 8pt, ..args) = node(
  pos,
  align(center, text(size: size, body)),
  fill: tint(color, amount: 90%),
  stroke: if planned { (paint: color, dash: "dashed", thickness: 1.2pt) } else { 1.2pt + color },
  corner-radius: 3pt,
  inset: inset,
  width: width,
  ..args,
)

// 容器框：只表示「在裡面」，用實線淡灰（虛線留給「還沒實作」）
#let frame(pos, body, enclose: (), color: c-line, inset: 10pt, ..args) = node(
  pos,
  body,
  enclose: enclose,
  stroke: 0.8pt + color,
  corner-radius: 4pt,
  inset: inset,
  fill: none,
  snap: -1,
  ..args,
)

// 箭頭樣式
#let ln(c) = 1pt + c
#let dln(c) = (paint: c, dash: "dashed", thickness: 1pt)
#let lbl(body, c: c-muted) = text(fill: c, body)

// 圖例的線段範例
#let sample(planned: false) = box(
  width: 1.1em, height: 0.7em, baseline: 0.1em, radius: 1.5pt,
  stroke: if planned { (paint: c-muted, dash: "dashed", thickness: 1pt) } else { 1pt + c-muted },
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
    + 架構
    + Trust
    + 設定與 doctor
    + Demo
  ]
]

== 整體架構

#v(0.2em)
#align(center)[
  #diagram(
    spacing: (2.6cm, 1.8cm),
    node-stroke: none,
    sn((0, 1.5), [LAN], color: c-lan, width: 1.6cm),
    sn((4.3, 1.5), [WAN], color: c-wan, width: 1.6cm),
    frame((2.15, 1.5), [], enclose: ((1, 1), (2, 1), (3.3, 1), (2, 2), (3.3, 2), (1, 0.45)), inset: 12pt),
    node((1, 0.45), text(size: 0.62em, fill: c-muted)[gateway], inset: 0pt),

    sn((1, 1), [eBPF \ （XDP／TC）], color: c-stage1, planned: true, width: 3.8cm),
    sn((2, 1), [netfilter], color: c-stage2, width: 3.6cm),
    sn((3.3, 1), [Suricata 8], color: c-stage3, width: 3.4cm),
    sn((2, 2), [edge AI], color: c-stage3, planned: true, width: 3.2cm),
    sn((3.3, 2), [wnc-gw], color: c-stage3, width: 3.4cm),
    sn((4.3, 0), [cloud], color: c-cloud, planned: true, width: 1.8cm),

    edge((0, 1.5), (2.15, 1.5), "<|-|>", stroke: ln(c-lan)),
    edge((2.15, 1.5), (4.3, 1.5), "<|-|>", stroke: ln(c-wan)),
    edge((1, 1), (2, 1), "-|>", stroke: dln(c-muted)),
    edge((2, 1), (3.3, 1), "-|>", lbl[copy／queue], label-side: left, label-size: 0.65em, stroke: ln(c-stage2)),
    edge((3.3, 1), (3.3, 2), "-|>", lbl[alert], label-side: right, label-size: 0.65em, stroke: ln(c-stage3)),
    edge((3.3, 2), (2, 1), "-|>", lbl[ct mark], label-side: center, label-pos: 62%, label-size: 0.65em, stroke: ln(c-stage3)),
    edge((2, 2), (3.3, 2), "<|-|>", stroke: dln(c-stage3)),
    edge((3.3, 2), (4.3, 0), "<|-|>", lbl[trust／block／observe], label-side: right, label-pos: 82%, label-size: 0.65em, stroke: dln(c-cloud)),
  )
]

#v(0.1em)
#align(center)[#text(size: 0.65em, fill: c-muted)[#sample()  實線：已實作　　#sample(planned: true)  虛線：規劃中]]

== wnc-gw 的 subcommand

#v(0.3em)
#align(center)[
  #small-tbl(size: 0.85em)[
    #set table(inset: (x: 10pt, y: 8pt))
    #tbl(
      columns: (auto, auto),
      [subcommand], [做什麼],
      [#m("doctor")], [檢查設定與環境],
      [#m("run")], [執行 gateway],
      [#m("trust add／del／list")], [把 connection 設成 trusted、取消、列出],
    )
  ]
]

#v(0.4em)
#align(center)[
  #diagram(
    spacing: (0.7cm, 1.1cm),
    node-stroke: none,
    frame((2, 0.5), [], enclose: ((0, 0), (4, 0), (4, 1), (0, -0.6)), inset: 8pt),
    node((0, -0.6), text(size: 0.65em, fill: c-muted)[#m("run") 的生命週期（目前）], inset: 0pt),
    sn((0, 0), [#m("doctor")], color: c-stage3, width: 3.3cm, size: 0.78em),
    sn((1, 0), [裝 \ nft table], color: c-stage3, width: 3.3cm, size: 0.78em),
    sn((2, 0), [啟動 \ Suricata], color: c-stage3, width: 3.3cm, size: 0.78em),
    sn((3, 0), [收到 #m("READY=1") \ 開始 inspection], color: c-stage3, width: 5cm, size: 0.78em),
    sn((4, 0), [讀 alert、 \ auto trust], color: c-stage3, width: 3.3cm, size: 0.78em),
    sn((4, 1), [停止： \ 移除 table], color: c-stage3, width: 3.3cm, size: 0.78em),
    edge((0, 0), (1, 0), "-|>", stroke: ln(c-stage3)),
    edge((1, 0), (2, 0), "-|>", stroke: ln(c-stage3)),
    edge((2, 0), (3, 0), "-|>", stroke: ln(c-stage3)),
    edge((3, 0), (4, 0), "-|>", stroke: ln(c-stage3)),
    edge((4, 0), (4, 1), "-|>", stroke: ln(c-stage3)),
  )
]

== packet 怎麼走

#v(0.1em)
#align(center)[
  #diagram(
    spacing: (1.8cm, 1.4cm),
    node-stroke: none,
    frame((0, 1), [], enclose: ((0, 0), (0, 2), (0, -0.75)), inset: 10pt),
    node((0, -0.75), text(size: 0.65em, fill: c-muted)[forward chain], inset: 0pt),
    frame((2, 1), [], enclose: ((1, 0.5), (1, 2), (2, 0.5), (3, 0), (3, 1), (2, -0.75)), inset: 10pt),
    node((2, -0.75), text(size: 0.65em, fill: c-muted)[#m("ids") chain], inset: 0pt),

    sn((0, 0), [SYN／FIN／RST？], color: c-stage2, width: 5.6cm, size: 0.76em, inset: 7pt),
    sn((0, 1), [trusted？], color: c-stage2, width: 5.6cm, size: 0.76em, inset: 7pt),
    sn((0, 2), text(fill: c-good)[#m("accept")], color: c-good, width: 5.6cm, size: 0.76em, inset: 7pt),

    sn((1, 0.5), [Suricata ready？], color: c-stage2, width: 5cm, size: 0.76em, inset: 7pt),
    sn((1, 2), [#m("when_unavailable") \ （#m("accept")／#m("drop")）], color: c-muted, width: 5cm, size: 0.76em, inset: 7pt),
    sn((2, 0.5), [#m("protection")？], color: c-stage2, width: 3.6cm, size: 0.76em, inset: 7pt),
    sn((3, 0), [NFLOG copy， \ 立刻轉送], color: c-stage3, width: 4.4cm, size: 0.76em, inset: 7pt),
    sn((3, 1), [NFQUEUE， \ 等 verdict], color: c-stage3, width: 4.4cm, size: 0.76em, inset: 7pt),

    edge((0, 0), (1, 0.5), "-|>", lbl[是], label-pos: 50%, label-side: left, label-size: 0.8em, stroke: ln(c-stage3)),
    edge((0, 0), (0, 1), "-|>", lbl[否], label-side: right, label-size: 0.8em, stroke: ln(c-stage2)),
    edge((0, 1), (0, 2), "-|>", lbl[是], label-side: right, label-size: 0.8em, stroke: ln(c-good)),
    edge((0, 1), (1, 0.5), "-|>", lbl[否], label-pos: 50%, label-side: right, label-size: 0.8em, stroke: ln(c-stage3)),
    edge((1, 0.5), (1, 2), "-|>", lbl[否], label-side: left, label-size: 0.8em, stroke: ln(c-muted)),
    edge((1, 0.5), (2, 0.5), "-|>", lbl[是], label-side: left, label-size: 0.8em, stroke: ln(c-stage3)),
    edge((2, 0.5), (3, 0), "-|>", lbl[#m("ids")], label-side: left, label-size: 0.8em, stroke: ln(c-stage3)),
    edge((2, 0.5), (3, 1), "-|>", lbl[#m("ips")], label-side: right, label-size: 0.8em, stroke: ln(c-stage3)),
  )
]

== trust 以 connection 為單位

#v(0.4em)
#align(center)[
  #block(width: 88%)[
    #set align(left)
    #set text(size: 0.95em)
    - 在 conntrack 的 connection 上設 ct mark
    - 不用 5-tuple：會被 port 重用、偽造的 packet 繞過
  ]
]

#v(0.4em)
#align(center)[#text(size: 0.75em)[整台機器 CPU µs／packet]]
#v(0.1em)
#align(center)[
  #small-tbl(size: 0.85em)[
    #set table(inset: (x: 10pt, y: 8pt))
    #tbl(
      columns: (auto, auto, auto, auto),
      align: (left + horizon, right + horizon, right + horizon, right + horizon),
      [scenario], [全部進 Suricata], [trusted], [只轉送],
      [Honeypot-7-1 (Somfy door lock)], [106.0], [40.0], [39.6],
      [1-1 (Hide and Seek)], [79.6], [59.7], [36.7],
      [39-1 (IRCBot)], [106.2], [97.1], [37.3],
    )
  ]
]

== auto trust

#align(center)[
  #diagram(
    spacing: (11.6cm, 1cm),
    node-stroke: none,
    sn((0, 0), [watching], color: c-stage3, width: 3.2cm),
    sn((1, 0), [trusted], color: c-stage3, width: 3.2cm),
    sn((0.5, 2), [refused], color: c-bad, width: 3.2cm),
    edge((0, 0), (1, 0), "-|>", lbl[兩個方向各 ≥ #m("min_packets")、≥ #m("min_age")、沒有 alert], bend: 18deg, label-side: left, label-size: 0.68em, stroke: ln(c-stage3)),
    edge((1, 0), (0, 0), "-|>", lbl[#m("ttl") 到期], bend: 18deg, label-side: right, label-size: 0.68em, stroke: ln(c-stage3)),
    edge((0, 0), (0.5, 2), "-|>", lbl(c: c-bad)[alert], label-side: right, label-size: 0.68em, stroke: ln(c-bad)),
    edge((1, 0), (0.5, 2), "-|>", lbl(c: c-bad)[alert（revoke）], label-side: left, label-size: 0.68em, stroke: ln(c-bad)),
  )
]

#v(0.1em)
#grid(
  columns: (1fr, 1.1fr), column-gutter: 1.2em, align: top,
  align(center, small-tbl(size: 0.75em)[
    #set table(inset: (x: 7pt, y: 4.5pt))
    #tbl(
      columns: (auto, auto),
      align: (left + horizon, right + horizon),
      [#m("[trust]")], [default],
      [#m("auto")], [#m("false")],
      [#m("min_packets")], [10],
      [#m("min_age")], [5 s],
      [#m("ttl")], [900 s],
      [#m("check_interval")], [5 s],
    )
  ]),
  align(center)[
    #small-tbl(size: 0.75em)[
      #set table(inset: (x: 7pt, y: 4.5pt))
      #tbl(
        columns: (auto, auto, auto),
        align: (left + horizon, right + horizon, right + horizon),
        [CPU ms／s], [#m("auto = false")], [#m("auto = true")],
        [Suricata], [100.5], [13.6],
        [wnc-gw], [0.5], [1.9],
      )
    ]
    #v(0.2em)
    #text(size: 0.75em)[每秒省 85 ms]
  ],
)

== Suricata 沒在 inspection 時

#v(1.2em)
#align(center)[
  #small-tbl(size: 0.88em)[
    #set table(inset: (x: 12pt, y: 10pt))
    #tbl(
      columns: (auto, auto, auto),
      align: (left + horizon, left + horizon, left + horizon),
      [case], [#m("accept")（default）], [#m("drop")],
      [Suricata 啟動中、重啟中], [放行，沒有 inspection], [丟掉],
      [#m("ips")：NFQUEUE 滿了], [放行，沒有 inspection], [丟掉],
      [#m("ids")：NFLOG socket 滿了], [packet 照樣轉送，copy 被丟掉], [同左],
    )
  ]
]

#v(0.9em)
#align(center)[
  #block(width: 94%)[
    #set align(left)
    #set text(size: 0.9em)
    - log 會紀錄：何時沒有 inspection、持續多久（#m("uninspected_ms")）、漏掉多少 copy
  ]
]

== #m("setting.toml")

#v(0.5em)
#align(center)[
  #small-tbl(size: 0.85em)[
    #set table(inset: (x: 11pt, y: 9pt))
    #tbl(
      columns: (auto, auto, auto),
      align: (left + horizon, left + horizon, left + horizon),
      [setting], [default], [options],
      [#m("[ports] lan")、#m("wan")], [（required）], [網卡名稱或 MAC],
      [#m("mode")], [#m("bridge")], [#m("routed")],
      [#m("protection")], [#m("ids")], [#m("ips")],
      [#m("xdp")], [#m("auto")], [#m("off")、#m("generic")],
      [#m("[suricata] when_unavailable")], [#m("accept")], [#m("drop")],
      [#m("[suricata] queue")／#m("group")], [#m("0")／#m("10")], [範圍(#m("\"0-2\"")／#m("\"10-12\""))],
      [#m("[trust] auto")], [#m("false")], [#m("true")],
    )
  ]
]

== #m("mode") 與 #m("protection")

#v(0.4em)
#align(center)[
  #small-tbl(size: 0.82em)[
    #set table(inset: (x: 9pt, y: 8pt))
    #tbl(
      columns: (auto, auto, auto),
      align: (left + horizon, left + horizon, left + horizon),
      [], [#m("bridge")（default）], [#m("routed")],
      [部署], [不用改網段], [不做 NAT，上游 router 要加 route],
      [只轉送：整台機器 \ CPU µs／packet], [9.97], [8.02],
    )
  ]
]

#v(0.8em)
#align(center)[
  #small-tbl(size: 0.82em)[
    #set table(inset: (x: 9pt, y: 8pt))
    #tbl(
      columns: (auto, auto, auto),
      align: (left + horizon, left + horizon, left + horizon),
      [], [#m("ids")（default）], [#m("ips")],
      [Suricata \ CPU µs／packet], [21–24], [38–48],
      [capacity：丟掉的 packet \ ≤ 0.1% 的最高速率], [50,000–80,000 packet／s], [60,000 packet／s],
    )
  ]
]

== #m("doctor")

#v(0.1em)
#align(center)[
  #small-tbl(size: 0.72em)[
    #set table(inset: (x: 8pt, y: 5pt))
    #tbl(
      columns: (auto, 1.1fr, 1fr),
      align: (left + horizon, left + horizon, left + horizon),
      [], [檢查什麼], [沒過會怎樣],
      [網路], [port 對到哪張網卡；#m("mode") 需要的 bridge、sysctl、位址和 route], [找不到網卡，或 packet 繞過 nft table],
      [kernel、#m("nft")], [需要的模組；#m("nft") 有沒有 JSON 支援], [table 裝不上，或寫不了 ct mark],
      [Suricata], [NFQUEUE／NFLOG、#m("READY=1")；設定載入得了；有 rule；queue／group 沒被別的 Suricata 佔住], [收不到 packet、起不來，或沒有偵測],
      [auto trust], [Suricata 有輸出 alert；#m("nf_conntrack_acct") 有開], [有 alert 的 connection 也被 trust；算不了 packet 數],
      [權限], [設定檔、執行檔和上層目錄，非 root 能不能改], [非 root 能讓 gateway 用 root 權限跑任意程式],
    )
  ]
]

#v(0.4em)
#align(center)[
  #small-tbl(size: 0.72em)[
    #set table(inset: (x: 8pt, y: 5pt))
    #tbl(
      columns: (auto, auto, auto),
      align: (left + horizon, left + horizon, left + horizon),
      [severity], [意思], [#m("run")],
      [error], [無法正確運作], [不啟動],
      [warning], [暫時狀態、已知風險], [照常啟動],
      [note], [資訊], [照常啟動],
    )
  ]
]

== #m("doctor") 的輸出：Pi 4 與 Docker

// 終端機截圖：原圖 assets/{pi,docker}_xdp.png，_crop 只裁掉上面幾行（留 MODE CHECK 和 XDP 兩張表）；
// 兩張用同一個比例（px × k），字一樣大
#let shot(path, w, k: 0.0205cm) = image(path, width: w * k)

#v(0.6em)
#align(center)[
  #grid(
    columns: (auto, auto), column-gutter: 0.8em, row-gutter: 1.1em, align: (right + horizon, left + horizon),
    text(size: 0.75em)[Pi 4 \ #m("bridge") \ #m("xdp = auto")],
    shot("../assets/pi_xdp_crop.png", 958),
    text(size: 0.75em)[Docker \ #m("routed") \ #m("xdp = auto")],
    shot("../assets/docker_xdp_crop.png", 948),
  )
]

== Demo 架構

#v(0.6em)
#align(center)[
  #diagram(
    spacing: (5.2cm, 2.2cm),
    node-stroke: none,
    frame((1, 0.6), [], enclose: ((0, 1), (2, 1), (1, 0), (0, -0.45)), inset: 14pt),
    node((0, -0.45), text(size: 0.62em, fill: c-muted)[筆電的 Docker], inset: 0pt),
    sn((0, 1), [#m("wnc-cli") \ #text(size: 0.85em)[iperf3 client]], color: c-lan, width: 3.8cm),
    sn((1, 1), [#m("wnc-gw") \ #text(size: 0.85em)[wnc-gw ＋ Suricata 8.0.7 \ #m("routed")、#m("ids")]], color: c-stage3, width: 6.2cm),
    sn((2, 1), [#m("wnc-srv") \ #text(size: 0.85em)[iperf3 server]], color: c-wan, width: 3.8cm),
    sn((1, 0), [#m("wnc-rep") \ #text(size: 0.85em)[重播 IoT-23 pcap]], color: c-muted, width: 4.2cm),
    node((0.5, 1), [], inset: 0pt),
    node((1.5, 1), [], inset: 0pt),
    edge((0, 1), (1, 1), "<|-|>", lbl(c: c-lan)[LAN 10.0.1.0/24], label-side: right, label-sep: 6pt, label-size: 0.7em, stroke: ln(c-lan)),
    edge((1, 1), (2, 1), "<|-|>", lbl(c: c-wan)[WAN 10.0.2.0/24], label-side: right, label-sep: 6pt, label-size: 0.7em, stroke: ln(c-wan)),
    edge((1, 0), (0.5, 1), "-|>", stroke: ln(c-muted)),
    edge((1, 0), (1.5, 1), "-|>", stroke: ln(c-muted)),
  )
]

#focus-slide[Demo]

#focus-slide[Q&A]
