#import "../../template.typ": *

#show: slides.with(
  title: "NetBeacon 論文報告",
  subtitle: [_An Efficient Design of Intelligent Network Data Plane_],
  author: [
    Guangmeng Zhou, Zhuotao Liu, Chuanpu Fu, Qi Li, Ke Xu \
    #text(size: 0.9em)[Tsinghua University、Zhongguancun Laboratory \ 32nd USENIX Security Symposium, 2023]
  ],
  date: "2026-11-13",
)

// ---- 本報告用的小工具 ----
#let m(s) = text(font: font-mono, size: 1em, s)
#let note(body) = text(size: 0.65em, fill: c-muted, body)
#let small-tbl(size: 0.85em, body) = text(size: size, body)

// 論文原圖下方的出處
#let figsrc(n) = note[#n]

// 論文原圖：置中、下方標出處
#let paperfig(path, n, width: auto, height: auto) = align(center)[
  #image(path, width: width, height: height)
  #v(-0.1em)
  #figsrc(n)
]

// 條列：置中的一塊，內文靠左
#let bullets(width: 90%, size: 1em, body) = align(center)[
  #block(width: width)[
    #set align(left)
    #set text(size: size)
    #body
  ]
]

// fletcher 節點：實線框
#let fnode(pos, body, color: c-lan, size: 0.8em, width: auto, inset: 8pt, ..args) = node(
  pos,
  align(center, text(size: size, body)),
  fill: tint(color, amount: 90%),
  stroke: 1.2pt + color,
  corner-radius: 3pt,
  inset: inset,
  width: width,
  ..args,
)

#let ln(c) = 1pt + c
#let lbl(body, c: c-muted) = text(fill: c, body)

#title-slide

= Introduction

== Intelligent Data Plane（IDP）

#v(0.6em)
#align(center)[
  #diagram(
    spacing: (2.6cm, 2.2cm),
    node-stroke: none,
    node((0, 0), align(left, text(size: 0.8em, weight: "bold")[ML 在 \ control plane]), inset: 0pt, width: 5.6cm),
    fnode((1, 0), [switch], color: c-lan, size: 1em, width: 3.8cm),
    fnode((2, 0), [server（ML）], color: c-warn, size: 1em, width: 4.6cm),
    fnode((3, 0), [約 10 Gbps], color: c-bad, size: 1em, width: 4.4cm),
    edge((1, 0), (2, 0), "-|>", lbl[flow 資訊], bend: 25deg, label-side: left, label-size: 0.72em, stroke: ln(c-lan)),
    edge((2, 0), (1, 0), "-|>", lbl[判定結果 \ #text(fill: c-bad)[多一段反應時間]], bend: 25deg, label-side: left, label-size: 0.72em, stroke: ln(c-warn)),
    edge((2, 0), (3, 0), "-|>", stroke: ln(c-bad)),

    node((0, 1), align(left, text(size: 0.8em, weight: "bold")[ML 在 \ data plane（IDP）]), inset: 0pt, width: 5.6cm),
    fnode((1, 1), [switch \ 直接推論], color: c-good, size: 1em, width: 3.8cm),
    fnode((3, 1), [line-speed], color: c-good, size: 1em, width: 4.4cm),
    edge((1, 1), (3, 1), "-|>", stroke: ln(c-good)),
  )
]

== Programmable Data Plane（PISA）

#paperfig("../assets/fig01_pisa.png", [Fig. 1], width: 13.5cm)

#v(0.2em)
#align(center)[
  #small-tbl(size: 0.85em)[
    #set table(inset: (x: 12pt, y: 6pt))
    #tbl(
      columns: (auto, auto),
      align: (left + horizon, left + horizon),
      [], [PISA 能做的],
      [Match], [exact、ternary、LPM],
      [Computation], [boolean、shift、add、subtract],
      [Match/action stage], [數量有限（Tofino 1：12 個）],
      [Stateful storage], [register：一個 packet 對每個 register 只能存取一次],
    )
  ]
]

= Motivation

== Comparison with prior art in IDP

#v(0.2em)
#align(center)[
  #small-tbl(size: 0.9em)[
    #set table(inset: (x: 14pt, y: 8pt))
    #tbl(
      columns: (auto, auto, auto, auto),
      align: (left + horizon, center + horizon, center + horizon, center + horizon),
      [Prior works], [Line-Speed], [Learning-Based], [Flow-Aware],
      [NetWarden、FlowLens], [#no], [#yes], [#yes],
      [Poseidon、Jaqen], [#yes], [#no], [#yes],
      [Planter、Mousika], [#yes], [#yes], [#no],
      [*NetBeacon*], [#yes], [#yes], [#yes],
    )
  ]
]
#v(0.1em)
#align(center)[#note[Table 1]]

#v(0.5em)
#bullets(width: 86%, size: 0.95em)[
  NetBeacon 要比 Planter、Mousika 更進一步的兩件事
  - Model deployment efficiency：表示模型用更少的 table entry
  - Model accuracy：加入 stateful flow-level features
]

== Flow-level features 的必要性

#v(0.1em)
#grid(
  columns: (auto, 1fr), column-gutter: 1.5em, align: horizon,
  paperfig("../assets/fig02_flow_features.png", [Fig. 2], width: 17cm),
  [
    #text(size: 0.95em)[同樣數量的 feature，加入 flow-level features 後 accuracy]
    #v(0.5em)
    #text(size: 1.15em)[
      #hl(color: c-good)[+11%]　P2P \
      #hl(color: c-good)[+43%]　covert channel \
      #hl(color: c-good)[+21%]　DDoS
    ]
  ],
)

= Design

== The architecture of NetBeacon

#v(0.1em)
#paperfig("../assets/fig03_architecture.png", [Fig. 3], width: 22.5cm)

#v(0.3em)
#bullets(width: 88%, size: 0.95em)[
  #set enum(numbering: "(i)")
  + data plane aware model design：multi-phase sequential model
  + efficient model representation（range marking）
  + stateful storage management
]

== (i) Multi-phase sequential model

#v(0.1em)
#paperfig("../assets/fig05_single_vs_multi.png", [Fig. 5], width: 21cm)

#v(0.4em)
#bullets(width: 90%)[
  - 在 flow 的第 n 個 packet（inference point）各用一個模型推論
  - 其他 packet 沿用最近一次的結果
  - 機率 ≥ determination threshold → 提前判定這條 flow
]

== (ii) Model representation：range marking

#v(-0.3em)
#paperfig("../assets/fig06_range_marking.png", [Fig. 6], height: 10.3cm)

#v(0em)
#align(center)[#text(size: 0.9em)[leaf 5 用 ternary matching 要 #hl[48] 個 entry → NetBeacon 每個 leaf 在 model table 只要 #hl(color: c-good)[1] 個]]

== (iii) Stateful storage management

#v(0.2em)
#pad(x: -1cm)[#align(center)[
  #diagram(
    spacing: (1.5cm, 1.1cm),
    node-stroke: none,
    fnode((0, 0), [new flow], color: c-lan, size: 0.74em),
    fnode((1, 0), [long-short 分類 \ per-packet features], color: c-warn, size: 0.74em),
    fnode((3, 0), [H(5-tuple) % N 對到的 \ register 空的，或舊 flow \ 已判定／逾時？], color: c-warn, size: 0.74em),
    fnode((4, -1), [佔用 register， \ 算 flow-level \ features], color: c-good, size: 0.74em),
    fnode((4, 1), [退回 \ per-packet features], color: c-muted, size: 0.74em),
    fnode((1, 1), [不存 state， \ 只用 per-packet \ features 分類], color: c-muted, size: 0.74em),
    edge((0, 0), (1, 0), "-|>", stroke: ln(c-lan)),
    edge((1, 0), (3, 0), "-|>", lbl[long], label-side: left, label-size: 0.74em, stroke: ln(c-lan)),
    edge((3, 0), (4, -1), "-|>", lbl(c: c-good)[是], label-side: left, label-size: 0.74em, stroke: ln(c-good)),
    edge((3, 0), (4, 1), "-|>", lbl[否], label-side: right, label-size: 0.74em, stroke: ln(c-muted)),
    edge((1, 0), (1, 1), "-|>", lbl[short], label-side: right, label-size: 0.74em, stroke: ln(c-muted)),
  )
]]

== Integrated data plane processing logic（Alg. 1）

#v(0.1em)
#pad(x: -1cm)[#align(center)[
  #diagram(
    spacing: (1.1cm, 1.1cm),
    node-stroke: none,
    fnode((0, 0), [packet], color: c-lan, size: 0.74em),
    fnode((1, 0), [flow class table \ 命中？], color: c-warn, size: 0.74em),
    fnode((2, 0), [有 per-flow \ state？], color: c-warn, size: 0.74em),
    fnode((3, 0), [更新 state； \ inference point 才推論], color: c-lan, size: 0.74em),
    fnode((4, 0), [機率 ≥ \ threshold？], color: c-warn, size: 0.74em),
    fnode((1, -1), [直接用存的 class \ （不再推論）], color: c-good, size: 0.74em),
    fnode((2, 1), [per-packet features \ 推論], color: c-muted, size: 0.74em),
    fnode((4, 1), [標記已判定，通知 \ control plane 寫入 \ flow class table], color: c-good, size: 0.74em),
    edge((0, 0), (1, 0), "-|>", stroke: ln(c-lan)),
    edge((1, 0), (1, -1), "-|>", lbl(c: c-good)[是], label-side: left, label-size: 0.74em, stroke: ln(c-good)),
    edge((1, 0), (2, 0), "-|>", lbl[否], label-side: left, label-size: 0.74em, stroke: ln(c-muted)),
    edge((2, 0), (3, 0), "-|>", lbl[有], label-side: left, label-size: 0.74em, stroke: ln(c-lan)),
    edge((2, 0), (2, 1), "-|>", lbl[沒有], label-side: right, label-size: 0.74em, stroke: ln(c-muted)),
    edge((3, 0), (4, 0), "-|>", stroke: ln(c-lan)),
    edge((4, 0), (4, 1), "-|>", lbl(c: c-good)[是], label-side: right, label-size: 0.74em, stroke: ln(c-good)),
  )
]]

#v(0.4em)
#bullets(width: 90%)[
  - entry 依 FIFO 或 LRU 移除
  - register 在 flow 判定後就能讓給新 flow
]

== Alg. 1 的例子：一條 long flow（P2P 任務）

#v(0.5em)
#align(center)[
  #small-tbl(size: 0.8em)[
    #set table(inset: (x: 12pt, y: 9pt))
    #tbl(
      columns: (6.0cm, 19.6cm),
      align: (left + horizon, left + horizon),
      [packet], [switch 做什麼],
      [第 1 個], [per-packet model 分類；判成 long 且 register 可用 → 佔用 register],
      [第 2 個 \ （inference point）], [更新 register → 算 flow-level features → 查 feature table、model table \ → class 寫回 register],
      [第 3 個], [更新 register，用 register 裡存的 class],
      [第 4、8、32 … 個 \ （inference point）], [同第 2 個，換成該 phase 的 model； \ 機率 ≥ threshold，或到第 2048 個 → 標記已判定，通知 control plane],
      [寫入 flow class \ table 之後], [5-tuple 命中 → 直接用存的 class，不再推論],
    )
  ]
]
#v(0.1em)
#align(center)[#note[依 Alg. 1 整理]]

= Evaluation

== Experiment setup

#v(0.8em)
#align(center)[
  #small-tbl(size: 0.8em)[
    #set table(inset: (x: 10pt, y: 10pt))
    #tbl(
      columns: (6.2cm, 8cm, 4.4cm, 3.3cm),
      align: (left + horizon, left + horizon, left + horizon, right + horizon),
      [任務], [Dataset], [Model], [Testing \ flows],
      [P2P application \ fingerprinting], [PeerRush \ （eMule、uTorrent、Vuze）], [Random Forest], [246,278],
      [Covert channel \ detection], [FacetTraffic \ （＋Univ2 背景）], [XGBoost], [400],
      [DDoS attack \ detection], [8 種 DDoS \ ＋ MAWI 背景], [XGBoost], [191,009],
    )
  ]
]
#v(0.1em)
#align(center)[#note[Table 4 整理]]

#v(1.0em)
#bullets(width: 88%)[
  - Tofino 1；tcpreplay 重播 pcap；指標是 per-packet macro-accuracy
]

== End-to-end system performance

#v(0.1em)
#pad(x: -0.9cm)[#paperfig("../assets/fig13_end_to_end.png", [Fig. 13], width: 27.5cm)]

#v(0.5em)
#bullets(width: 100%, size: 0.93em)[
  - accuracy 比 Mousika 高 #hl(color: c-good)[14%]（P2P）、#hl(color: c-good)[38%]（covert channel）、#hl(color: c-good)[20%]（DDoS）
  - 和 stateful storage 不受限的 Ideal 相當
]

== Model representation performance

#v(0.3em)
#paperfig("../assets/fig14_table_entries.png", [Fig. 14 (a)–(c)], width: 25.5cm)

#v(0.6em)
#bullets(width: 90%)[
  - 同樣的 table entry 數，accuracy 比較高
  - 表現相近的模型，table entry 少很多（covert channel 少 #hl(color: c-good)[75%]）
]

== NetBeacon deep dive

#v(0.1em)
#paperfig("../assets/fig15bc_threshold_indexsize.png", [Fig. 15 (b)(c)], height: 6.6cm)

#v(0.1em)
#bullets(width: 98%, size: 0.84em)[
  - Throughput：#hl(color: c-good)[99.12–99.18 Gbps]（100 Gb port）
  - Determination thresholds（左）：register 少 → 低 threshold 較好；register 多 → 高 threshold 較好
  - Size of stateful storage（右）：storage 越大 accuracy 越高；storage 有限時 storage management 有幫助
]

= Conclusion

== Discussion：security analysis

#v(0.3em)
#align(center)[
  #small-tbl(size: 0.82em)[
    #set table(inset: (x: 12pt, y: 9pt))
    #tbl(
      columns: (auto, auto, auto),
      align: (left + horizon, left + horizon, left + horizon),
      [], [攻擊], [作者提的緩解],
      [Stealth attack], [先送 benign packet， \ 等 flow 被判定後才送 malicious packet], [flow class table 的 entry \ 加 maximum flow length limit],
      [Low-rate-long-flow \ attack], [把 packet 間隔拉長， \ 逼 flow 逾時], [每條 flow 用自己的 timeout \ （例如最大 IPD 的兩倍）],
    )
  ]
]

#v(0.8em)
#align(center)[#punch[報告人的觀察：兩種攻擊與緩解都只有文字討論，沒有實驗]]

#v(0.8em)
#align(center)[
  #note[Table 5　FPR／FNR：covert channel 8.8%／10.9%　DDoS 0.7%／0.05%]
]

== Conclusion 與討論

#v(0.3em)
#grid(
  columns: (1fr, 1.15fr), column-gutter: 2em, align: top,
  [
    #text(weight: "bold", fill: c-stage3)[論文的結論]
    #v(0.3em)
    #set text(size: 1em)
    #set par(leading: 0.6em)
    model accuracy 與 model representation efficiency 都超過 prior art，靠三個設計：
    #set enum(numbering: "(i)")
    + multi-phase sequential model
    + efficient model representation
    + stateful storage management
  ],
  [
    #text(weight: "bold", fill: c-stage3)[討論（報告人的問題）]
    #v(0.3em)
    #set text(size: 1em)
    #set par(leading: 0.6em)
    #set enum(spacing: 0.9em)
    + 判定後不再檢查 → 中途變惡意的 flow 會漏多少？（沒有量）
    + maximum flow length limit 設多少？到期後是重新分析還是直接放行？
    + determination threshold 要依硬體資源決定，能不能依負載動態調整？
    + flow class table 的大小與 FIFO／LRU 對 accuracy 的影響沒有評估
  ],
)

#focus-slide[Q&A]
