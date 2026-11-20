#import "../../template.typ": *

#show: slides.with(
  title: "Security Gateway 專案進度",
  date: "2026-11-23",
)

// template 的 show raw 把 inline code 固定成 0.82 × 全域字級（縮小字級的表格、圖的
// 節點裡也一樣），所以 inline code 一律用 m("...")，字級跟著所在位置走
#let m(s) = text(font: font-mono, size: 1em, s)

// ---- 本報告用的小工具 ----
#let small-tbl(size: 0.85em, body) = text(size: size, body)
#let note(body) = text(size: 0.65em, fill: c-muted, body)
#let bad(body) = text(fill: c-bad, weight: "bold", body)

// 實作狀態用框線表示：實線＝已實作、虛線＝還沒實作（planned: true）
#let sn(pos, body, color: c-muted, planned: false, size: 0.8em, width: auto, inset: 8pt, ..args) = node(
  pos,
  align(center, text(size: size, body)),
  shape: rect,
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

// 框內的小標籤（例如 core eBPF program 裡的 trust map）
#let inner(body, c: c-stage1) = box(
  stroke: 0.8pt + c, inset: (x: 4pt, y: 2pt), radius: 2pt, fill: white, body,
)

#title-slide

== 11/09 之後做了什麼

#v(0em)
#align(center)[
  #diagram(
    spacing: (2.9cm, 1.75cm),
    node-stroke: none,
    sn((0, 1.5), [LAN], color: c-lan, width: 1.6cm, size: 0.85em, height: 1.3cm),
    sn((4, 1.5), [WAN], color: c-wan, width: 1.6cm, size: 0.85em, height: 1.3cm),
    frame((2, 1.5), [], enclose: ((1, 1), (3, 1), (1, 2), (3, 2), (2, 0)), inset: 12pt),
    node((2, 0), [], inset: 0pt),
    node((3, 1.5), text(size: 0.7em, fill: c-muted)[gateway], inset: 0pt),

    sn((1, 1), [core eBPF program \ #inner[trust map]], color: c-stage1, width: 5.4cm, size: 0.76em, inset: 6pt, height: 1.9cm),
    sn((2, 1), [netfilter \ #text(size: 0.85em)[ct mark（#m("ctmark") 時）]], color: c-stage2, width: 5.4cm, size: 0.76em, inset: 6pt, height: 1.9cm),
    sn((3, 1), [Suricata 8], color: c-stage3, width: 3.2cm, size: 0.76em, inset: 6pt, height: 1.9cm),
    sn((1, 2), [feature program \ #text(size: 0.85em)[使用者提供]], color: c-stage1, width: 5.4cm, size: 0.76em, inset: 6pt, height: 1.6cm),
    sn((2, 2), [wnc-gw], color: c-stage3, width: 5.4cm, size: 0.76em, inset: 6pt, height: 1.6cm),
    sn((3, 2), [edge AI], color: c-stage3, planned: true, width: 3.2cm, size: 0.76em, inset: 6pt, height: 1.6cm),
    sn((2, 3.4), [cloud], color: c-cloud, planned: true, width: 2.4cm, size: 0.76em, inset: 6pt, height: 1.3cm),

    edge((0, 1.5), (2, 1.5), "<|-|>", stroke: ln(c-lan)),
    edge((2, 1.5), (4, 1.5), "<|-|>", stroke: ln(c-wan)),
    edge((1, 1), (1, 0), (4, 0), (4, 1.5), "-|>", stroke: 1.8pt + c-stage1, label: lbl(c: c-stage1)[*fast path*], label-pos: 50%, label-side: center, label-fill: true, label-size: 0.85em),
    edge((1, 1), (2, 1), "-|>", stroke: ln(c-stage1)),
    edge((2, 1), (3, 1), "-|>", lbl[copy／queue], label-side: left, label-size: 0.64em, stroke: ln(c-stage2)),
    edge((3, 1), (2, 2), "-|>", lbl[alert], label-side: right, label-size: 0.7em, stroke: ln(c-stage3)),
    edge((2, 2), (2, 1), "-|>", lbl[trust], label-side: right, label-size: 0.7em, stroke: ln(c-stage3)),
    edge((2, 2), (1, 1), "-|>", lbl[trust], label-side: right, label-pos: 50%, label-size: 0.7em, stroke: ln(c-stage3)),
    edge((1, 2), (2, 2), "-|>", lbl[讀 map], label-side: right, label-size: 0.7em, stroke: ln(c-stage1)),
    edge((2, 2), (3, 2), "<|-|>", lbl[特徵], label-side: left, label-size: 0.7em, stroke: dln(c-stage3)),
    edge((2, 2), (2, 3.4), "<|-|>", stroke: dln(c-cloud)),
  )
]

#v(0.1em)
#align(center)[#text(size: 0.72em, fill: c-muted)[#sample()  實線：已實作　　#sample(planned: true)  虛線：還沒實作]]

// =====================================================================
= trust 搬到 TC

== fast path：packet 怎麼走

#v(0.3em)
#align(center)[
  #diagram(
    spacing: (2.0cm, 1.5cm),
    node-stroke: none,
    sn((0, 1), [port A \ TCX ingress], color: c-muted, width: 4.2cm, size: 0.9em),
    sn((1, 1), [core eBPF program], color: c-stage1, width: 6.4cm, size: 0.9em),
    sn((1, 0), [trust map], color: c-stage1, width: 3.2cm, size: 0.85em, inset: 6pt),
    sn((3, 1), [port B], color: c-muted, width: 2.8cm, size: 0.9em),

    sn((1, 2), [bridge／routing], color: c-stage2.lighten(40%), width: 6.4cm, size: 0.9em),
    sn((2, 2), [netfilter], color: c-stage2.lighten(40%), width: 5.6cm, size: 0.9em),
    sn((3, 2), [Suricata], color: c-stage3.lighten(40%), width: 3.2cm, size: 0.9em),
    node((2, 2.7), text(size: 0.78em, fill: c-muted)[11/09 的路徑], inset: 0pt),

    edge((0, 1), (1, 1), "-|>", stroke: ln(c-stage1)),
    edge((1, 1), (1, 0), "<|-|>", stroke: ln(c-stage1)),
    edge((1, 1), (3, 1), "-|>", stroke: 1.8pt + c-stage1, label: lbl(c: c-stage1)[*fast path*：#m("redirect") \ #text(size: 0.78em, weight: "regular", fill: c-muted)[查到 trust map，而且不是 SYN／FIN／RST]], label-side: left, label-size: 0.95em),
    edge((1, 1), (1, 2), "-|>", lbl[其他：#m("TCX_NEXT")], label-side: right, label-size: 0.82em, stroke: ln(c-muted)),
    edge((1, 2), (2, 2), "-|>", stroke: ln(c-muted)),
    edge((2, 2), (3, 2), "-|>", stroke: ln(c-muted)),
  )
]

#v(0.3em)
#align(center)[
  #small-tbl(size: 1.0em)[
    #set table(inset: (x: 14pt, y: 8pt))
    #tbl(
      columns: (auto, auto),
      align: (left + horizon, left + horizon),
      [#m("mode")], [packet 的改動],
      [#m("bridge")], [不改],
      [#m("routed")], [TTL −1、修 checksum],
    )
  ]
]

== 每個 trusted packet 省多少（Pi）

#v(0.1em)
#align(center)[#text(size: 0.65em, fill: c-muted)[Pi 4、1000 MHz、實體網卡、#m("ips")、50 kpps；整台 Pi 的 CPU 時間 ÷ packet 數（µs／packet）；2 輪平均]]

#v(0.2em)
#align(center)[
  #small-tbl(size: 0.9em)[
    #set table(inset: (x: 12pt, y: 6.5pt))
    #tbl(
      columns: (auto, auto, auto),
      align: (left + horizon, center + horizon, center + horizon),
      [切片], [#m("bridge")：ct mark → TC], [#m("routed")：ct mark → TC],
      [IoT-23 60-1 (Gafgyt)], [14.2 → 8.8（−5.4）], [11.1 → 9.2（−1.9）],
      [IoT-23 Honeypot-5-1 (Amazon Echo)], [30.5 → 24.7（−5.7）], [29.4 → 25.2（−4.2）],
      [CIC-IDS2017 Benign], [30.8 → 26.4（−4.5）], [28.6 → 26.9（−1.7）],
      [CIC-IDS2017 FTP-Patator], [30.1 → 22.6（−7.5）], [27.2 → 23.2（−4.0）],
      [CIC-DDoS2019 Benign], [29.5 → 26.6（−2.9）], [27.3 → 25.3（−1.9）],
      [CICIoT2023 Benign], [29.6 → 25.7（−3.9）], [27.3 → 29.5（#bad[+2.3]）],
      [CICIoT2023 DNS Spoofing], [28.3 → 25.7（−2.6）], [26.4 → 25.8（−0.6）],
    )
  ]
]

#v(0.3em)
#align(center)[#text(size: 0.9em)[容量（#m("bridge")，kpps）：ct mark 50–80 → TC 50–197]]

== 套到 dataset

#v(0.1em)
#align(center)[#text(size: 0.75em, fill: c-muted)[照 wnc-gw 的 auto trust 條件離線重演 4 個 dataset 的全部 pcap]]

#v(0.5em)
#align(center)[
  #small-tbl(size: 1.0em)[
    #set table(inset: (x: 14pt, y: 10pt))
    #tbl(
      columns: (auto, auto, auto, auto),
      align: (left + horizon, right + horizon, right + horizon, right + horizon),
      [dataset], [fast path 的 \ packet], [平均每個 packet \ （推算）], [trust 之後才出現 \ 的 alert],
      [IoT-23], [0.14%], [< 0.03 µs], [3／14,770,158],
      [CIC-IDS2017], [43.1%], [−1.9 µs], [5／41,861],
      [CIC-DDoS2019], [0.07%], [< 0.03 µs], [12／39,962],
      [CICIoT2023], [0.39%], [< 0.03 µs], [43／596,012],
      [　其中 Benign], [55.5%], [−2.2 µs], [—],
    )
  ]
]

== idle sweep 與長 connection

#v(0.1em)
#grid(
  columns: (1.15fr, 1fr), column-gutter: 1.4em, align: top,
  [
    #align(center)[#text(size: 0.85em, weight: "bold")[idle sweep（#m("tc") backend）]]
    #v(0.2em)
    #align(center)[#text(size: 0.7em)[每 10 秒看一次，packet 數沒變超過 \ UDP~120~s、TCP~600~s → 刪掉 trust]]
    #v(0.3em)
    #align(center)[
      #small-tbl(size: 0.72em)[
        #set table(inset: (x: 6pt, y: 6pt))
        #tbl(
          columns: (auto, auto, auto, auto),
          align: (left + horizon, right + horizon, right + horizon, right + horizon),
          [dataset], [idle sweep], [之後又 \ 有流量], [多送 inspection \ 的 packet],
          [IoT-23], [1,950], [27], [0.000%],
          [CIC-IDS2017], [100,703], [146], [0.019%],
          [CIC-DDoS2019], [5,351], [23], [0.006%],
          [CICIoT2023], [76,844], [7,541], [0.020%],
        )
      ]
    ]
  ],
  [
    #align(center)[#text(size: 0.85em, weight: "bold")[TLS 長 connection 回到 Suricata 會不會斷]]
    #v(0.2em)
    #align(center)[#text(size: 0.7em)[Docker、Pi；#m("tc")、#m("ctmark") 結果相同]]
    #v(0.3em)
    #align(center)[
      #small-tbl(size: 0.72em)[
        #set table(inset: (x: 6pt, y: 6pt))
        #tbl(
          columns: (auto, auto, auto, auto),
          align: (left + horizon, center + horizon, center + horizon, center + horizon),
          [], [#m("ids")], [#m("ips")＋#m("accept")], [#m("ips")＋#m("drop")],
          [idle：閒置 \ 640 s 後恢復], [不斷], [不斷], [不斷],
          [gap：#m("trust del") \ 後繼續傳], [不斷], [不斷], [#bad[斷]],
        )
      ]
    ]
  ],
)

// =====================================================================
= #m("[trust] backend")

== #m("tc") 與 #m("ctmark")

#v(0.1em)
#align(center)[#text(size: 1.0em)[#m("[trust] backend = \"tc\"")（default）／#m("\"ctmark\"")：二選一，不自動切換]]

#v(0.6em)
#align(center)[
  #small-tbl(size: 0.85em)[
    #set table(inset: (x: 10pt, y: 10pt))
    #tbl(
      columns: (auto, auto, auto),
      align: (left + horizon, left + horizon, left + horizon),
      [], [#m("tc")（default）], [#m("ctmark")],
      [trust 存在], [trust map（5-tuple，每個方向一筆）], [conntrack entry 的 ct mark],
      [port 重用], [純 SYN 刪 trust], [純 SYN 清 mark],
      [偽造同 5-tuple 的 packet], [沒有 TCP 序號檢查], [conntrack 的序號檢查],
      [TCX 不能用], [沒有 trust（全部 inspection）], [不影響],
    )
  ]
]

// =====================================================================
= 特徵

== 特徵框架

#v(0.2em)
#align(center)[
  #diagram(
    spacing: (0.75cm, 1.5cm),
    node-stroke: none,
    frame((0, 0.5), [], enclose: ((0, 0), (0, 1), (0, -0.55)), inset: 6pt),
    node((0, -0.55), text(size: 0.62em, fill: c-muted)[使用者提供], inset: 0pt),
    frame((3.5, 0.5), [], enclose: ((1, 0.5), (2, 0.5), (3, 0.5), (4, 0.5), (5, 0.5), (6, 0.5), (3.5, -0.55)), inset: 6pt),
    node((3.5, -0.55), text(size: 0.62em, fill: c-muted)[wnc-gw], inset: 0pt),

    sn((0, 0), [#m("flows.o") \ feature program], color: c-stage1, size: 0.72em, inset: 6pt),
    sn((0, 1), [#m("flows.json") \ definition], color: c-stage3, size: 0.72em, inset: 6pt),
    sn((1, 0.5), [檢查格式], color: c-stage3, size: 0.72em, inset: 6pt),
    sn((2, 0.5), [掛到 \ hook], color: c-stage1, size: 0.72em, inset: 6pt),
    sn((3, 0.5), [每 #m("interval") 秒讀 map], color: c-stage3, size: 0.72em, inset: 6pt),
    sn((4, 0.5), [解碼], color: c-stage3, size: 0.72em, inset: 6pt),
    sn((5, 0.5), [derived], color: c-stage3, size: 0.72em, inset: 6pt),
    sn((6, 0.5), [#m("features/") \ #m("<name>.jsonl")], color: c-stage3, size: 0.72em, inset: 6pt),
    sn((5.5, 2.4), [edge AI], color: c-stage3, planned: true, size: 0.72em, inset: 6pt),
    sn((6.5, 2.4), [cloud], color: c-cloud, planned: true, size: 0.72em, inset: 6pt),

    edge((0, 0), (1, 0.5), "-|>", stroke: ln(c-stage1)),
    edge((0, 1), (1, 0.5), "-|>", stroke: ln(c-stage3)),
    edge((1, 0.5), (2, 0.5), "-|>", stroke: ln(c-stage3)),
    edge((2, 0.5), (3, 0.5), "-|>", stroke: ln(c-stage3)),
    edge((3, 0.5), (4, 0.5), "-|>", stroke: ln(c-stage3)),
    edge((4, 0.5), (5, 0.5), "-|>", stroke: ln(c-stage3)),
    edge((5, 0.5), (6, 0.5), "-|>", stroke: ln(c-stage3)),
    edge((6, 0.5), (5.5, 2.4), "-|>", stroke: dln(c-stage3)),
    edge((6, 0.5), (6.5, 2.4), "-|>", stroke: dln(c-cloud)),
  )
]

#v(0.2em)
#align(center)[
  #block(width: 80%)[
    #set align(left)
    #set text(size: 1.0em)
    #set list(spacing: 0.9em)
    - 不提供 feature program
    - 不預先定義特徵，只提供運算
  ]
]

== definition

#v(0.1em)
#grid(
  columns: (1.12fr, 1fr), column-gutter: 1.2em, align: top,
  [
    #[
      #show raw: set text(size: 12pt)
      ```json
      {
        "map": "FLOWS",
        "key": [
          {"name": "saddr", "type": "ipv4"},
          {"name": "daddr", "type": "ipv4"},
          {"name": "sport", "type": "u16", "endian": "big"},
          {"name": "dport", "type": "u16", "endian": "big"},
          {"name": "proto", "type": "u8"}],
        "value": [
          {"name": "packets",   "type": "u64"},
          {"name": "bytes",     "type": "u64"},
          {"name": "len_sumsq", "type": "u64"}, …],
        "derived": [
          {"name": "pps", "op": "rate",
           "of": "packets"},
          {"name": "len_mean", "op": "mean",
           "sum": "bytes", "count": "packets"},
          {"name": "len_std", "op": "std",
           "sum": "bytes", "sumsq": "len_sumsq",
           "count": "packets"}]
      }
      ```
    ]
  ],
  [
    #text(size: 1.0em, weight: "bold")[運算：13 種]
    #v(1.2em)
    #text(size: 1.0em, weight: "bold")[載入前的檢查]
    #v(0.4em)
    #small-tbl(size: 0.74em)[
      #set table(inset: (x: 7pt, y: 9pt))
      #tbl(
        columns: (auto, auto),
        align: (left + horizon, left + horizon),
        [檢查], [抓得到],
        [ELF 有這個 map、種類支援], [名稱打錯],
        [key／value 的長度], [漏欄位、型別寫錯],
        [BTF 逐欄比對 offset], [長度一樣但順序寫反],
        [derived 的引用], [欄位不存在、循環],
      )
    ]
  ],
)

== hook：看得到哪些 packet

#v(0.2em)
#align(center)[
  #small-tbl(size: 1.2em)[
    #set table(inset: (x: 16pt, y: 13pt))
    #tbl(
      columns: (auto, auto, auto),
      align: (left + horizon, center + horizon, center + horizon),
      [#m("hook")], [trusted packet（#m("tc")）], [被丟掉的 packet],
      [#m("xdp")], [看得到], [看得到],
      [#m("tc-ingress")], [#bad[看不到]], [看得到],
      [#m("tc-egress")], [看得到], [#bad[看不到]],
    )
  ]
]

== 待決與下一步

#v(0.4em)
#grid(
  columns: (1fr, 1fr), column-gutter: 1.4em, align: top,
  [
    #text(size: 1.15em, weight: "bold")[待決]
    #v(0.4em)
    #set text(size: 0.95em)
    #set list(spacing: 1em)
    - trust 之後的 alert Suricata 看不到
    - #m("tc") 沒有 TCP 序號檢查
    - #m("ips") 從中途接手後 FIN 可能被丟
    - 特徵的成本（Pi）
  ],
  [
    #text(size: 1.15em, weight: "bold")[下一步]
    #v(0.4em)
    #set text(size: 0.95em)
    #set list(spacing: 1em)
    - 特徵送 edge AI、cloud（先做模擬的 cloud）
    - timer 對齊：Suricata 的 #box(m("flow-timeouts"))、TTL、idle sweep、conntrack
  ],
)

#focus-slide[Q&A]
